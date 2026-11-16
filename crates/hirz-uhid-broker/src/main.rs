//! hirz-uhid-broker: the root helper of the hirz virtual security key. It owns `/dev/uhid` and gives
//! each client connection one FIDO HID device with a fixed report descriptor, relaying 64-byte
//! reports. The descriptor never leaves this process: whoever holds it can recreate the device as
//! any HID device, a keyboard included (docs/uhid.md).
#![forbid(unsafe_code)]

mod device;
mod policy;
mod relay;
mod slots;

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use policy::HostPolicy;
use slots::{RefusalLog, SlotGuard, Slots};

const DEFAULT_UHID: &str = "/dev/uhid";
const DEFAULT_MIN_UID: u32 = 1000;
/// Regular users (1000 to 60000) and systemd-homed users (60001 to 60513). Everything above stays
/// out: host users mapped into containers (60514 and up), the DynamicUser range (61184 to 65519)
/// and `nobody` (65534).
const DEFAULT_MAX_UID: u32 = 60_513;
const DEFAULT_MAX_CONNECTIONS: usize = 8;
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
/// How often a running device re-checks that its user still has an active session.
const SESSION_RECHECK: Duration = Duration::from_secs(5);

const USAGE: &str =
    "usage: hirz-uhid-broker [--listen PATH] [--uhid PATH] [--min-uid N] [--max-uid N]
                        [--max-connections N] [--sessions-dir DIR] [--udev-rules-dir DIR]

Without --listen the broker expects a socket from systemd (socket activation).
--listen PATH         bind PATH itself (mode 0666) instead, for manual runs; PATH must be
                      absolute, with no symbolic link on the way, and every directory on it
                      root-owned or ours and closed to group and others
--uhid PATH           uhid device (default /dev/uhid)
--min-uid N           refuse peers with a lower uid (default 1000)
--max-uid N           refuse peers with a higher uid (default 60513: regular and systemd-homed
                      users; nobody and DynamicUser ids stay out)
--max-connections N   devices at the same time, one per uid (default 8)
--sessions-dir DIR    logind user state files (default /run/systemd/users); only users with
                      an active session on a seat get a device
--udev-rules-dir DIR  the only directory searched for the hirz udev rules (70-hirz.rules,
                      72-hirz.rules, 99-zzz-hirz.rules); default: the system udev directories
                      in udev's order, where a mask hides a packaged file";

#[derive(Debug)]
struct Args {
    listen: Option<PathBuf>,
    uhid: PathBuf,
    min_uid: u32,
    max_uid: u32,
    max_connections: usize,
    sessions_dir: PathBuf,
    udev_rules_dir: Option<PathBuf>,
}

fn parse_uid(value: &OsString, flag: &str) -> Result<u32, String> {
    value
        .to_str()
        .and_then(|v| v.parse().ok())
        .ok_or(format!("{flag} needs a number"))
}

fn parse_args(mut it: impl Iterator<Item = OsString>) -> Result<Args, String> {
    let mut args = Args {
        listen: None,
        uhid: PathBuf::from(DEFAULT_UHID),
        min_uid: DEFAULT_MIN_UID,
        max_uid: DEFAULT_MAX_UID,
        max_connections: DEFAULT_MAX_CONNECTIONS,
        sessions_dir: PathBuf::from(policy::DEFAULT_SESSIONS_DIR),
        udev_rules_dir: None,
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
            "--min-uid" => args.min_uid = parse_uid(&value, &flag)?,
            "--max-uid" => args.max_uid = parse_uid(&value, &flag)?,
            "--sessions-dir" => args.sessions_dir = PathBuf::from(value),
            "--udev-rules-dir" => args.udev_rules_dir = Some(PathBuf::from(value)),
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
    if args.max_uid < args.min_uid {
        return Err("--max-uid is below --min-uid".into());
    }
    if !args.sessions_dir.is_absolute() {
        return Err("--sessions-dir needs an absolute path".into());
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

/// The directory that holds a manual socket is never changed when it exists: widening its mode
/// could strip the sticky bit from /tmp. It must be a real directory that nobody else can write to.
fn check_socket_dir(meta: &fs::Metadata, trusted_uid: u32) -> io::Result<()> {
    if !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the directory of the listen path is not a directory",
        ));
    }
    if meta.uid() != 0 && meta.uid() != trusted_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the directory of the listen path is owned by another user",
        ));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the directory of the listen path is writable by group or others",
        ));
    }
    Ok(())
}

/// A directory on the way to the socket: a real directory (never a symbolic link) owned by root
/// or the broker, and closed to group and others, except a sticky one such as /tmp, in which
/// nobody can rename or remove an entry that is not theirs.
fn check_ancestor(path: &Path, meta: &fs::Metadata, trusted_uid: u32) -> io::Result<()> {
    let refuse = |kind, why: &str| Err(io::Error::new(kind, format!("{} {why}", path.display())));
    if !meta.is_dir() {
        return refuse(
            io::ErrorKind::InvalidInput,
            "is not a directory or is a symbolic link (give the real path of --listen)",
        );
    }
    if meta.uid() != 0 && meta.uid() != trusted_uid {
        return refuse(io::ErrorKind::PermissionDenied, "is owned by another user");
    }
    if meta.mode() & 0o022 != 0 && meta.mode() & 0o1000 == 0 {
        return refuse(
            io::ErrorKind::PermissionDenied,
            "is writable by group or others and not sticky",
        );
    }
    Ok(())
}

/// Checks every directory from `/` to `dir` with `lstat`, so a link anywhere on the path is
/// refused, and creates `dir` when it is missing. The checks leave nobody but root and the broker
/// able to swap a component later. The directory is made with `mkdir` (which never follows a
/// link) under umask 0, so no `chmod` by path is needed afterwards.
fn prepare_socket_dir(dir: &Path) -> io::Result<()> {
    let trusted_uid = hirz_sys::effective_uid();
    let mut current = PathBuf::new();
    let mut parts = dir.components().peekable();
    while let Some(part) = parts.next() {
        match part {
            Component::RootDir | Component::Normal(_) => current.push(part),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--listen must not contain . or .. components",
                ));
            }
        }
        if parts.peek().is_some() {
            check_ancestor(&current, &fs::symlink_metadata(&current)?, trusted_uid)?;
        }
    }
    let meta = match fs::symlink_metadata(dir) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // The parent must exist; the umask would leave clients unable to traverse it.
            hirz_sys::peercred::with_umask(0, || fs::DirBuilder::new().mode(0o755).create(dir))?;
            fs::symlink_metadata(dir)?
        }
        Err(e) => return Err(e),
    };
    check_socket_dir(&meta, trusted_uid)
}

fn manual_listener(path: &Path) -> io::Result<UnixListener> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--listen needs an absolute path",
        ));
    }
    let Some(dir) = path.parent() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--listen needs a path below a directory",
        ));
    };
    prepare_socket_dir(dir)?;
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
    // Any local user may connect; the broker itself decides who gets a device (uid range,
    // active session on a seat), and the udev rule makes each device node accessible only to
    // the uid that created it. A socket is created with 0777 minus the umask, so 0111 gives 0666
    // without a chmod by path.
    let listener = hirz_sys::peercred::with_umask(0o111, || UnixListener::bind(path))?;
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_socket() || meta.mode() & 0o777 != 0o666 {
        return Err(io::Error::other(
            "the listen socket was not created as expected",
        ));
    }
    Ok(listener)
}

fn open_uhid(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).write(true).open(path)
}

fn serve(mut client: UnixStream, uhid_path: &Path, policy: &HostPolicy, uid: u32, pid: i32) {
    if let Err(e) = client.set_write_timeout(Some(CLIENT_WRITE_TIMEOUT)) {
        log(format_args!(
            "uid {uid} pid {pid}: socket setup failed: {e}"
        ));
        return;
    }
    let mut uhid = match open_uhid(uhid_path) {
        Ok(f) => f,
        Err(e) => {
            log(format_args!("uid {uid} pid {pid}: cannot open uhid: {e}"));
            return;
        }
    };
    let phys = uid.to_string();
    let mut stats = relay::Stats::default();
    log(format_args!("uid {uid} pid {pid}: creating device"));
    let mut still_allowed = || match policy.check(uid) {
        Ok(()) => true,
        Err(denied) => {
            log(format_args!(
                "uid {uid} pid {pid}: ending the device: {}",
                denied.reason()
            ));
            false
        }
    };
    let end = relay::run_device(
        &mut uhid,
        &mut client,
        &phys,
        &mut stats,
        SESSION_RECHECK,
        &mut still_allowed,
    );
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

#[derive(Debug, PartialEq, Eq)]
enum Refused {
    Slot(slots::Refusal),
    Host(policy::Denied),
}

impl Refused {
    fn reason(&self) -> &'static str {
        match self {
            Self::Slot(r) => r.reason(),
            Self::Host(d) => d.reason(),
        }
    }
}

/// The checks every connection passes before a device is created: the uid range, then the
/// host policy (active session on a seat, udev rules present), then the per-uid budget.
fn admit(
    slots: &Arc<Slots>,
    policy: &HostPolicy,
    uid: u32,
    now: Instant,
) -> Result<SlotGuard, Refused> {
    slots.check_range(uid).map_err(Refused::Slot)?;
    policy.check(uid).map_err(Refused::Host)?;
    slots.try_acquire_at(uid, now).map_err(Refused::Slot)
}

fn accept_loop(
    listener: &UnixListener,
    slots: &Arc<Slots>,
    policy: &Arc<HostPolicy>,
    uhid_path: &Path,
) {
    let mut refusals = RefusalLog::default();
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
        let now = Instant::now();
        let guard = match admit(slots, policy, cred.uid, now) {
            Ok(g) => g,
            Err(refused) => {
                if let Some(skipped) = refusals.note(cred.uid, now) {
                    log(format_args!(
                        "refused uid {} pid {}: {} ({skipped} similar refusals not logged)",
                        cred.uid,
                        cred.pid,
                        refused.reason()
                    ));
                }
                continue;
            }
        };
        let path = uhid_path.to_path_buf();
        let policy = Arc::clone(policy);
        let spawned = std::thread::Builder::new()
            .name("relay".into())
            .spawn(move || {
                serve(client, &path, &policy, cred.uid, cred.pid);
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
    if let Err(e) = open_uhid(&args.uhid) {
        log(format_args!(
            "cannot open {}: {e} (is the uhid module available?)",
            args.uhid.display()
        ));
        return ExitCode::FAILURE;
    }

    let policy = Arc::new(HostPolicy::new(args.sessions_dir, args.udev_rules_dir));
    if !policy.sessions_dir().is_dir() {
        log(format_args!(
            "warning: {} does not exist (no systemd-logind or elogind?); every client is refused until it does",
            policy.sessions_dir().display()
        ));
    }
    let missing = policy.missing_rules();
    if !missing.is_empty() {
        log(format_args!(
            "warning: the udev rules {} are not installed or are masked; every client is refused until they are",
            missing.join(", ")
        ));
    }
    log(format_args!(
        "ready (uid {} to {}, max {} devices, active seat sessions only)",
        args.min_uid, args.max_uid, args.max_connections
    ));
    let slots = Slots::new(args.min_uid, args.max_uid, args.max_connections);
    accept_loop(&listener, &slots, &policy, &args.uhid);
    ExitCode::SUCCESS
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    // The umask is process wide and the broker's socket code briefly changes it, so test
    // directories get their mode explicitly instead of from the umask.
    fn make_dir(path: &Path) {
        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            make_dir(parent);
        }
        if !path.exists() {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    fn parse(v: &[&str]) -> Result<Args, String> {
        parse_args(v.iter().map(OsString::from))
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hirz-broker-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        make_dir(&dir);
        dir
    }

    fn mkdir(path: &Path, mode: u32) {
        make_dir(path);
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn mode_of(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn parses_flags() {
        let a = parse(&[]).unwrap();
        assert!(a.listen.is_none());
        assert_eq!(a.uhid, PathBuf::from("/dev/uhid"));
        assert_eq!(a.min_uid, 1000);
        assert_eq!(a.max_uid, 60_513);
        assert_eq!(a.sessions_dir, PathBuf::from("/run/systemd/users"));
        assert!(a.udev_rules_dir.is_none());
        let a = parse(&[
            "--listen",
            "/run/hirz/uhid.sock",
            "--min-uid",
            "500",
            "--max-uid",
            "2000",
            "--max-connections",
            "2",
            "--sessions-dir",
            "/tmp/users",
            "--udev-rules-dir",
            "/tmp/rules",
        ])
        .unwrap();
        assert_eq!(a.listen, Some(PathBuf::from("/run/hirz/uhid.sock")));
        assert_eq!(a.min_uid, 500);
        assert_eq!(a.max_uid, 2000);
        assert_eq!(a.max_connections, 2);
        assert_eq!(a.sessions_dir, PathBuf::from("/tmp/users"));
        assert_eq!(a.udev_rules_dir, Some(PathBuf::from("/tmp/rules")));
    }

    #[test]
    fn rejects_bad_flags() {
        assert!(parse(&["--min-uid", "0"]).is_err());
        assert!(parse(&["--min-uid", "x"]).is_err());
        assert!(parse(&["--max-uid", "x"]).is_err());
        assert!(parse(&["--min-uid", "2000", "--max-uid", "1999"]).is_err());
        assert!(parse(&["--sessions-dir", "users"]).is_err());
        assert!(parse(&["--max-connections", "0"]).is_err());
        assert!(parse(&["--listen"]).is_err());
        assert!(parse(&["--bogus", "1"]).is_err());
        assert_eq!(parse(&["--help"]).unwrap_err(), "");
    }

    #[test]
    fn manual_listener_sets_mode_and_replaces_stale_socket() {
        let dir = std::env::temp_dir().join(format!("hirz-broker-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("uhid.sock");
        let first = manual_listener(&path).unwrap();
        drop(first);
        let dir_mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o7777;
        assert_eq!(dir_mode, 0o755);
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

    #[test]
    fn manual_listener_never_changes_an_existing_directory() {
        let base = scratch("keepmode");
        for mode in [0o1777, 0o770, 0o757] {
            let dir = base.join(format!("m{mode:o}"));
            mkdir(&dir, mode);
            let err = manual_listener(&dir.join("x.sock")).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "mode {mode:o}");
            let after = fs::metadata(&dir).unwrap().permissions().mode() & 0o7777;
            assert_eq!(after, mode, "mode {mode:o} was changed");
            assert!(!dir.join("x.sock").exists());
        }
        let ok = base.join("ok");
        mkdir(&ok, 0o750);
        drop(manual_listener(&ok.join("x.sock")).unwrap());
        let after = fs::metadata(&ok).unwrap().permissions().mode() & 0o7777;
        assert_eq!(after, 0o750);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn manual_listener_needs_an_absolute_path_and_a_real_directory() {
        assert!(manual_listener(Path::new("x.sock")).is_err());
        assert!(manual_listener(Path::new("/")).is_err());
        let base = scratch("kinds");
        let file = base.join("file");
        fs::write(&file, b"x").unwrap();
        assert!(manual_listener(&file.join("x.sock")).is_err());
        let real = base.join("real");
        mkdir(&real, 0o755);
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(manual_listener(&link.join("x.sock")).is_err());
        let _ = fs::remove_dir_all(&base);
    }

    // A user who owns the grandparent could swap a link in under a running broker, and root then
    // created and chmod'ed whatever the link pointed to.
    #[test]
    fn a_link_anywhere_on_the_path_is_refused_and_nothing_is_made_through_it() {
        let base = scratch("ancestors");
        let real = base.join("real");
        mkdir(&real, 0o700);
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        for tail in ["sub/x.sock", "sub/deeper/x.sock"] {
            let err = manual_listener(&link.join(tail)).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{tail}: {err}");
            assert!(err.to_string().contains("symbolic link"), "{err}");
            assert!(
                !real.join("sub").exists(),
                "{tail}: created through the link"
            );
            assert_eq!(mode_of(&real), 0o700);
        }
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn a_directory_on_the_path_that_others_can_write_is_refused() {
        let base = scratch("open-ancestor");
        let open = base.join("open");
        mkdir(&open, 0o777);
        let group = base.join("group");
        mkdir(&group, 0o775);
        for dir in [&open, &group] {
            let err = manual_listener(&dir.join("sub").join("x.sock")).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
            assert!(!dir.join("sub").exists());
        }
        // A sticky directory such as /tmp is fine: entries that are not theirs cannot be
        // renamed or removed by others.
        let sticky = base.join("sticky");
        mkdir(&sticky, 0o1777);
        drop(manual_listener(&sticky.join("sub").join("x.sock")).unwrap());
        assert_eq!(mode_of(&sticky.join("sub")), 0o755);
        assert_eq!(mode_of(&sticky), 0o1777);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn dots_and_an_owner_that_is_not_trusted_are_refused() {
        let base = scratch("dots");
        mkdir(&base.join("a"), 0o755);
        mkdir(&base.join("b"), 0o755);
        for path in [base.join("a/../b/x.sock"), base.join("./b/../b/x.sock")] {
            assert!(manual_listener(&path).is_err(), "{}", path.display());
        }
        let meta = fs::symlink_metadata(base.join("a")).unwrap();
        let me = meta.uid();
        assert!(check_ancestor(&base, &meta, me).is_ok());
        assert_eq!(
            check_ancestor(&base, &meta, me.wrapping_add(1)).is_err(),
            me != 0
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn modes_do_not_depend_on_the_umask() {
        let base = scratch("umask");
        let path = base.join("sock-dir").join("uhid.sock");
        let listener = hirz_sys::peercred::with_umask(0o077, || manual_listener(&path)).unwrap();
        assert_eq!(mode_of(path.parent().unwrap()), 0o755);
        assert_eq!(mode_of(&path), 0o666);
        drop(listener);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn socket_dir_owner_must_be_root_or_the_broker() {
        let base = scratch("owner");
        fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).unwrap();
        let meta = fs::metadata(&base).unwrap();
        let me = meta.uid();
        assert!(check_socket_dir(&meta, me).is_ok());
        assert_eq!(
            check_socket_dir(&meta, me.wrapping_add(1)).is_err(),
            me != 0
        );
        let _ = fs::remove_dir_all(&base);
    }

    struct Host {
        root: PathBuf,
        policy: Arc<HostPolicy>,
    }

    fn host(name: &str) -> Host {
        let root = scratch(name);
        make_dir(&root.join("users"));
        make_dir(&root.join("udev"));
        for name in policy::UDEV_RULES_FILES {
            fs::write(root.join("udev").join(name), b"TAG-=\"uaccess\"\n").unwrap();
        }
        let policy = Arc::new(HostPolicy::new(root.join("users"), Some(root.join("udev"))));
        Host { root, policy }
    }

    fn login(host: &Host, uid: u32, state: &str, seats: &str) {
        fs::write(
            host.root.join("users").join(uid.to_string()),
            format!("STATE={state}\nACTIVE_SEATS={seats}\n"),
        )
        .unwrap();
    }

    #[test]
    fn only_users_with_an_active_seat_session_get_a_device() {
        let host = host("admit");
        let slots = Slots::new(DEFAULT_MIN_UID, DEFAULT_MAX_UID, 8);
        let now = Instant::now() + Duration::from_secs(60);
        login(&host, 1000, "active", "seat0");
        login(&host, 1001, "online", "");
        login(&host, 1002, "active", "");
        login(&host, 65534, "active", "seat0");
        login(&host, 61184, "active", "seat0");
        login(&host, 999, "active", "seat0");

        let alice = admit(&slots, &host.policy, 1000, now).unwrap();
        assert_eq!(
            admit(&slots, &host.policy, 1001, now).unwrap_err(),
            Refused::Host(policy::Denied::SessionNotActive)
        );
        assert_eq!(
            admit(&slots, &host.policy, 1002, now).unwrap_err(),
            Refused::Host(policy::Denied::NoSeat)
        );
        assert_eq!(
            admit(&slots, &host.policy, 1003, now).unwrap_err(),
            Refused::Host(policy::Denied::NoSession)
        );
        for uid in [60_514, 61_184, 65_519, 65_534] {
            assert_eq!(
                admit(&slots, &host.policy, uid, now).unwrap_err(),
                Refused::Slot(slots::Refusal::AboveMaxUid),
                "uid {uid}"
            );
        }
        assert_eq!(
            admit(&slots, &host.policy, 999, now).unwrap_err(),
            Refused::Slot(slots::Refusal::BelowMinUid)
        );
        assert_eq!(
            admit(&slots, &host.policy, 1000, now).unwrap_err(),
            Refused::Slot(slots::Refusal::UidBusy)
        );
        drop(alice);
        let _ = fs::remove_dir_all(&host.root);
    }

    #[test]
    fn systemd_homed_users_are_admitted_and_the_ranges_above_them_are_not() {
        let host = host("homed");
        let slots = Slots::new(DEFAULT_MIN_UID, DEFAULT_MAX_UID, 16);
        let now = Instant::now() + Duration::from_secs(60);
        for uid in [60_000, 60_001, 60_257, 60_513] {
            login(&host, uid, "active", "seat0");
            let guard = admit(&slots, &host.policy, uid, now);
            assert!(guard.is_ok(), "uid {uid}: {:?}", guard.err());
        }
        for uid in [
            0, 1, 999, 60_514, 60_577, 61_183, 61_184, 65_519, 65_534, 65_535,
        ] {
            login(&host, uid, "active", "seat0");
            assert!(
                matches!(
                    admit(&slots, &host.policy, uid, now),
                    Err(Refused::Slot(
                        slots::Refusal::AboveMaxUid | slots::Refusal::BelowMinUid
                    ))
                ),
                "uid {uid}"
            );
        }
        let _ = fs::remove_dir_all(&host.root);
    }

    #[test]
    fn a_running_device_is_revoked_when_the_session_ends() {
        let host = host("revoke");
        login(&host, 1000, "active", "seat0");
        assert!(host.policy.check(1000).is_ok());
        login(&host, 1000, "closing", "");
        assert_eq!(
            host.policy.check(1000),
            Err(policy::Denied::SessionNotActive)
        );
        let _ = fs::remove_dir_all(&host.root);
    }
}
