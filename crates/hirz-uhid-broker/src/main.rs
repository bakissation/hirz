//! hirz-uhid-broker: the root helper of the hirz virtual security key.
//!
//! It owns `/dev/uhid`. Each client connection on its Unix socket gets exactly one FIDO HID
//! device, created with a fixed report descriptor; the broker relays 64-byte reports both
//! ways and destroys the device when the client disconnects. The uhid descriptor never
//! leaves this process, because whoever holds it can recreate the device as any HID device,
//! a keyboard included.
#![forbid(unsafe_code)]

mod device;
mod relay;
mod slots;

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use slots::Slots;

const DEFAULT_UHID: &str = "/dev/uhid";
const DEFAULT_MIN_UID: u32 = 1000;
const DEFAULT_MAX_CONNECTIONS: usize = 8;
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

const USAGE: &str =
    "usage: hirz-uhid-broker [--listen PATH] [--uhid PATH] [--min-uid N] [--max-connections N]

Without --listen the broker expects a socket from systemd (socket activation).
--listen PATH        bind PATH itself (mode 0666) instead, for manual runs
--uhid PATH          uhid device (default /dev/uhid)
--min-uid N          refuse peers with a lower uid (default 1000)
--max-connections N  devices at the same time, one per uid (default 8)";

#[derive(Debug)]
struct Args {
    listen: Option<PathBuf>,
    uhid: PathBuf,
    min_uid: u32,
    max_connections: usize,
}

fn parse_args(mut it: impl Iterator<Item = OsString>) -> Result<Args, String> {
    let mut args = Args {
        listen: None,
        uhid: PathBuf::from(DEFAULT_UHID),
        min_uid: DEFAULT_MIN_UID,
        max_connections: DEFAULT_MAX_CONNECTIONS,
    };
    while let Some(flag) = it.next() {
        let flag = flag.to_str().ok_or("invalid argument")?.to_owned();
        if flag == "--help" || flag == "-h" {
            return Err(String::new());
        }
        let value = it.next().ok_or(format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--listen" => args.listen = Some(PathBuf::from(value)),
            "--uhid" => args.uhid = PathBuf::from(value),
            "--min-uid" => {
                args.min_uid = value
                    .to_str()
                    .and_then(|v| v.parse().ok())
                    .ok_or("--min-uid needs a number")?;
            }
            "--max-connections" => {
                args.max_connections = value
                    .to_str()
                    .and_then(|v| v.parse().ok())
                    .filter(|n| *n > 0)
                    .ok_or("--max-connections needs a positive number")?;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if args.min_uid == 0 {
        return Err("--min-uid 0 would let root clients in; use 1 or more".into());
    }
    Ok(args)
}

fn log(msg: std::fmt::Arguments<'_>) {
    eprintln!("hirz-uhid-broker: {msg}");
}

fn activated_listener() -> io::Result<UnixListener> {
    let mut fds = hirz_sys::listen_fds()?;
    if fds.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "expected exactly one socket from systemd, got {} (use --listen for manual runs)",
                fds.len()
            ),
        ));
    }
    let Some(fd) = fds.pop() else {
        return Err(io::Error::other("no socket"));
    };
    let info = hirz_sys::socket_info(fd.as_fd())?;
    if !info.is_unix_stream_listener() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "passed socket is not a listening AF_UNIX stream socket",
        ));
    }
    Ok(UnixListener::from(fd))
}

fn manual_listener(path: &Path) -> io::Result<UnixListener> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755))?;
    }
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => fs::remove_file(path)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "listen path exists and is not a socket",
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    // Any local user may connect; the broker itself enforces the uid policy, and the udev
    // rule makes each device node accessible only to the uid that created it.
    fs::set_permissions(path, fs::Permissions::from_mode(0o666))?;
    Ok(listener)
}

fn serve(mut client: UnixStream, uhid_path: &Path, uid: u32, pid: i32) {
    if let Err(e) = client.set_write_timeout(Some(CLIENT_WRITE_TIMEOUT)) {
        log(format_args!(
            "uid {uid} pid {pid}: socket setup failed: {e}"
        ));
        return;
    }
    let mut uhid = match OpenOptions::new().read(true).write(true).open(uhid_path) {
        Ok(f) => f,
        Err(e) => {
            log(format_args!("uid {uid} pid {pid}: cannot open uhid: {e}"));
            return;
        }
    };
    let phys = uid.to_string();
    let mut stats = relay::Stats::default();
    log(format_args!("uid {uid} pid {pid}: creating device"));
    let end = relay::run_device(&mut uhid, &mut client, &phys, &mut stats);
    let summary = format!(
        "{} reports to client, {} to device, {} dropped",
        stats.to_client, stats.to_device, stats.dropped
    );
    match end {
        Ok(end) => log(format_args!(
            "uid {uid} pid {pid}: device destroyed ({end:?}; {summary})"
        )),
        Err(e) => log(format_args!(
            "uid {uid} pid {pid}: relay error: {e} ({summary})"
        )),
    }
}

fn accept_loop(listener: &UnixListener, slots: &Arc<Slots>, uhid_path: &Path) {
    for conn in listener.incoming() {
        let client = match conn {
            Ok(c) => c,
            Err(e) => {
                log(format_args!("accept failed: {e}"));
                // EMFILE and similar persist until a connection ends; do not spin.
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
        };
        let cred = match hirz_sys::peer_credentials(&client) {
            Ok(c) => c,
            Err(e) => {
                log(format_args!("cannot read peer credentials: {e}"));
                continue;
            }
        };
        let guard = match slots.try_acquire(cred.uid) {
            Ok(g) => g,
            Err(refusal) => {
                log(format_args!(
                    "refused uid {} pid {}: {}",
                    cred.uid,
                    cred.pid,
                    refusal.reason()
                ));
                continue;
            }
        };
        let path = uhid_path.to_path_buf();
        let spawned = std::thread::Builder::new()
            .name("relay".into())
            .spawn(move || {
                serve(client, &path, cred.uid, cred.pid);
                drop(guard);
            });
        if let Err(e) = spawned {
            log(format_args!("cannot start relay thread: {e}"));
        }
    }
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args_os().skip(1)) {
        Ok(a) => a,
        Err(msg) => {
            if !msg.is_empty() {
                eprintln!("hirz-uhid-broker: {msg}");
            }
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    let listener = match &args.listen {
        Some(path) => manual_listener(path),
        None => activated_listener(),
    };
    let listener = match listener {
        Ok(l) => l,
        Err(e) => {
            log(format_args!("cannot set up the listening socket: {e}"));
            return ExitCode::FAILURE;
        }
    };

    // From here on the broker needs no capability: as uid 0 it opens the root-owned
    // /dev/uhid through the owner permission bits.
    if let Err(e) = hirz_sys::drop_all_capabilities() {
        log(format_args!("cannot drop capabilities: {e}"));
        return ExitCode::FAILURE;
    }
    if let Err(e) = hirz_sys::harden_process(false) {
        log(format_args!("cannot harden the process: {e}"));
        return ExitCode::FAILURE;
    }
    if let Err(e) = OpenOptions::new().read(true).write(true).open(&args.uhid) {
        log(format_args!(
            "cannot open {}: {e} (is the uhid module available?)",
            args.uhid.display()
        ));
        return ExitCode::FAILURE;
    }

    log(format_args!(
        "ready (min uid {}, max {} devices)",
        args.min_uid, args.max_connections
    ));
    let slots = Slots::new(args.min_uid, args.max_connections);
    accept_loop(&listener, &slots, &args.uhid);
    ExitCode::SUCCESS
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn parse(v: &[&str]) -> Result<Args, String> {
        parse_args(v.iter().map(OsString::from))
    }

    #[test]
    fn parses_flags() {
        let a = parse(&[]).unwrap();
        assert!(a.listen.is_none());
        assert_eq!(a.uhid, PathBuf::from("/dev/uhid"));
        assert_eq!(a.min_uid, 1000);
        let a = parse(&[
            "--listen",
            "/run/hirz/uhid.sock",
            "--min-uid",
            "500",
            "--max-connections",
            "2",
        ])
        .unwrap();
        assert_eq!(a.listen, Some(PathBuf::from("/run/hirz/uhid.sock")));
        assert_eq!(a.min_uid, 500);
        assert_eq!(a.max_connections, 2);
    }

    #[test]
    fn rejects_bad_flags() {
        assert!(parse(&["--min-uid", "0"]).is_err());
        assert!(parse(&["--min-uid", "x"]).is_err());
        assert!(parse(&["--max-connections", "0"]).is_err());
        assert!(parse(&["--listen"]).is_err());
        assert!(parse(&["--bogus", "1"]).is_err());
        assert_eq!(parse(&["--help"]).unwrap_err(), "");
    }

    #[test]
    fn manual_listener_sets_mode_and_replaces_stale_socket() {
        let dir = std::env::temp_dir().join(format!("hirz-broker-test-{}", std::process::id()));
        let path = dir.join("uhid.sock");
        let first = manual_listener(&path).unwrap();
        drop(first);
        let listener = manual_listener(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o666);
        let _client = UnixStream::connect(&path).unwrap();
        let (server_side, _) = listener.accept().unwrap();
        let cred = hirz_sys::peer_credentials(&server_side).unwrap();
        assert_eq!(cred.pid, i32::try_from(std::process::id()).unwrap());
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"x").unwrap();
        assert!(manual_listener(&path).is_err());
        fs::remove_file(&path).unwrap();
        let _ = fs::remove_dir(&dir);
    }
}
