//! The first-run setup window (`hirz init --gui`). Its lock and the note of a cancelled setup live
//! in `$XDG_RUNTIME_DIR/hirz`, shared by the CLI that shows the window and by hirzd and hirz-nmh,
//! which start it (docs/approval.md, "Setting up hirz").

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

const SUBDIR: &str = "hirz";
pub const LOCK_FILE: &str = "setup.lock";
pub const CANCELLED_FILE: &str = "setup-cancelled";
/// Which quiet period a notification was already shown for.
pub const QUIET_NOTICE_FILE: &str = "setup-quiet-noticed";
/// After the user cancels the setup window, no request opens it again for this long.
pub const QUIET_AFTER_CANCEL: Duration = Duration::from_secs(60);
pub const ADDON_ID: &str = "hirz@berkati.xyz";
pub const ADDON_PAGE: &str = "https://addons.mozilla.org/firefox/addon/hirz/";
const MAX_STAMP_LEN: u64 = 32;

pub fn setup_dir(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join(SUBDIR)
}

/// Held by the open setup window for as long as it runs; the lock ends with the process.
#[derive(Debug)]
pub struct SetupLock {
    _file: File,
}

/// `None` while another setup window holds the lock.
pub fn try_lock(runtime_dir: &Path) -> io::Result<Option<SetupLock>> {
    let dir = setup_dir(runtime_dir);
    crate::pin::ensure_private_dir(&dir)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(dir.join(LOCK_FILE))?;
    Ok(hirz_sys::try_lock_exclusive(&file)?.then_some(SetupLock { _file: file }))
}

/// True while a setup window is open, and when that cannot be told.
pub fn window_open(runtime_dir: &Path) -> bool {
    !matches!(try_lock(runtime_dir), Ok(Some(_)))
}

/// After a setup that completed: an earlier cancel no longer keeps requests quiet.
pub fn clear_cancelled(runtime_dir: &Path) {
    let dir = setup_dir(runtime_dir);
    let _ = std::fs::remove_file(dir.join(CANCELLED_FILE));
    let _ = std::fs::remove_file(dir.join(QUIET_NOTICE_FILE));
}

pub fn mark_cancelled(runtime_dir: &Path, unix_now: u64) -> io::Result<()> {
    let dir = setup_dir(runtime_dir);
    crate::pin::ensure_private_dir(&dir)?;
    crate::pin::write_atomic(&dir, CANCELLED_FILE, &unix_now.to_string())
}

fn read_stamp(path: &Path) -> Option<u64> {
    let file = File::open(path).ok()?;
    let mut text = String::new();
    file.take(MAX_STAMP_LEN.saturating_add(1))
        .read_to_string(&mut text)
        .ok()?;
    if u64::try_from(text.len()).map_or(true, |n| n > MAX_STAMP_LEN) {
        return None;
    }
    text.trim().parse().ok()
}

/// When the user cancelled a setup, if that was less than [`QUIET_AFTER_CANCEL`] ago. A clock
/// that went back keeps the quiet time; a note far in the future is ignored.
pub fn cancelled_at(runtime_dir: &Path, unix_now: u64) -> Option<u64> {
    read_stamp(&setup_dir(runtime_dir).join(CANCELLED_FILE))
        .filter(|at| unix_now.abs_diff(*at) < QUIET_AFTER_CANCEL.as_secs())
}

pub fn cancelled_recently(runtime_dir: &Path, unix_now: u64) -> bool {
    cancelled_at(runtime_dir, unix_now).is_some()
}

/// True once per quiet period (`cancelled_at`), for every process of the user: the caller then
/// shows its one notification for that period.
pub fn claim_quiet_notice(runtime_dir: &Path, cancelled_at: u64) -> bool {
    let dir = setup_dir(runtime_dir);
    if read_stamp(&dir.join(QUIET_NOTICE_FILE)) == Some(cancelled_at) {
        return false;
    }
    crate::pin::write_atomic(&dir, QUIET_NOTICE_FILE, &cancelled_at.to_string()).is_ok()
}

/// Written by a request that stopped waiting for the setup window (it was cancelled or ran out of
/// time) while the window was still open; the window then says when hirz is ready.
pub const WAITER_GONE_FILE: &str = "setup-waiter-gone";
pub const READY_NOTICE: &str = "hirz is ready. Go back to the site and try again.";
const NO_PASSKEY_DIR: &str = "no-passkey";
/// One "no passkey" notice per site in this time, across hirzd and every hirz-nmh.
pub const NO_PASSKEY_EVERY: Duration = Duration::from_secs(60);
const MAX_NO_PASSKEY_SITES: usize = 256;

pub fn mark_waiter_gone(runtime_dir: &Path) {
    let dir = setup_dir(runtime_dir);
    let _ = crate::pin::ensure_private_dir(&dir)
        .and_then(|()| crate::pin::write_atomic(&dir, WAITER_GONE_FILE, "1"));
}

/// True when a request stopped waiting since the last call; the note is removed.
pub fn take_waiter_gone(runtime_dir: &Path) -> bool {
    std::fs::remove_file(setup_dir(runtime_dir).join(WAITER_GONE_FILE)).is_ok()
}

/// True at most once per site every [`NO_PASSKEY_EVERY`], for all processes of the user. Sites are
/// kept as hashes of their id, and old entries are dropped once there are many.
pub fn claim_no_passkey_notice(runtime_dir: &Path, rp_id: &str, unix_now: u64) -> bool {
    let dir = setup_dir(runtime_dir).join(NO_PASSKEY_DIR);
    if crate::pin::ensure_private_dir(&dir).is_err() {
        return false;
    }
    let digest = hirz_crypto::sha256(rp_id.as_bytes());
    let name = hirz_proto::hex::encode(digest.get(..16).unwrap_or(&digest));
    let recent = |at: u64| unix_now.abs_diff(at) < NO_PASSKEY_EVERY.as_secs();
    if read_stamp(&dir.join(&name)).is_some_and(recent) {
        return false;
    }
    if let Ok(entries) = std::fs::read_dir(&dir) {
        let names: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        if names.len() >= MAX_NO_PASSKEY_SITES {
            for p in names {
                if !read_stamp(&p).is_some_and(recent) {
                    let _ = std::fs::remove_file(p);
                }
            }
            if std::fs::read_dir(&dir).map_or(0, Iterator::count) >= MAX_NO_PASSKEY_SITES {
                return false;
            }
        }
    }
    crate::pin::write_atomic(&dir, &name, &unix_now.to_string()).is_ok()
}

/// How long a notification stays up, in milliseconds.
pub const NOTICE_EXPIRE_MS: u32 = 10_000;
const NOTICE_CHARS: usize = 200;
const GDBUS_TIMEOUT: Duration = Duration::from_secs(5);

/// `text` as a GVariant text string literal: gdbus parses each argument as GVariant text, so the
/// value is quoted and escaped and always stays one string.
fn gvariant_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len().saturating_add(2));
    out.push('"');
    for c in text.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `gdbus call` for org.freedesktop.Notifications.Notify with the app name "hirz", the hirz icon
/// when installed, `text` as the summary (cleaned like every text in a hirz window), no body, no
/// actions and an explicit expiry.
pub fn notify_args(text: &str, icon: Option<&str>) -> Vec<String> {
    let summary = crate::display::sanitize(text, NOTICE_CHARS);
    vec![
        "call".to_owned(),
        "--session".to_owned(),
        "--dest=org.freedesktop.Notifications".to_owned(),
        "--object-path=/org/freedesktop/Notifications".to_owned(),
        "--method=org.freedesktop.Notifications.Notify".to_owned(),
        "--".to_owned(),
        gvariant_string("hirz"),
        "uint32 0".to_owned(),
        gvariant_string(icon.unwrap_or("")),
        gvariant_string(&summary),
        gvariant_string(""),
        "@as []".to_owned(),
        "@a{sv} {}".to_owned(),
        format!("int32 {NOTICE_EXPIRE_MS}"),
    ]
}

/// A desktop notification, best effort and in the background: through the notification service
/// with gdbus (it then shows as hirz, with the hirz icon), else `zenity --notification`. Both come
/// from a trusted system directory; no shell, no `PATH`.
pub fn notify_desktop(text: &str) {
    notify_with(&crate::runner::SystemRunner, text);
}

pub fn notify_with<R: crate::runner::CommandRunner + Clone + Send + 'static>(
    runner: &R,
    text: &str,
) {
    let runner = runner.clone();
    let text = text.to_owned();
    let _ = std::thread::Builder::new()
        .name("notice".into())
        .spawn(move || notify_now(&runner, &text));
}

/// What [`notify_desktop`] does, waiting for it. True when gdbus delivered the notification.
pub fn notify_now<R: crate::runner::CommandRunner>(runner: &R, text: &str) -> bool {
    use crate::runner::{CommandSpec, EnvPolicy, RunResult, Tool};
    let icon = runner
        .window_icon()
        .and_then(|p| p.to_str().map(str::to_owned));
    let sent = runner.tool_available(Tool::Gdbus)
        && matches!(
            runner.run(&CommandSpec {
                tool: Tool::Gdbus,
                args: notify_args(text, icon.as_deref()),
                env: EnvPolicy::Desktop,
                timeout: GDBUS_TIMEOUT,
            }),
            RunResult::Exited { code: Some(0), .. }
        );
    if !sent {
        let _ = runner.run(&CommandSpec {
            tool: Tool::Zenity,
            args: vec![
                "--notification".to_owned(),
                format!("--text={}", crate::display::sanitize(text, NOTICE_CHARS)),
            ],
            env: EnvPolicy::Desktop,
            timeout: GDBUS_TIMEOUT,
        });
    }
    sent
}

/// Starts `program` with `args` in a session of its own, with standard input and output on
/// `/dev/null` and the caller's environment, and reaps it in the background. No shell is involved.
pub fn spawn_detached<S: AsRef<std::ffi::OsStr>>(program: &Path, args: &[S]) -> io::Result<()> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = hirz_sys::new_session(&mut cmd).spawn()?;
    let _ = std::thread::Builder::new()
        .name("reap".into())
        .spawn(move || child.wait());
    Ok(())
}

/// Opens `url` in the user's browser with `xdg-open`, else `gio open`, both from a trusted system
/// directory. False when neither could be started.
pub fn open_url(url: &str) -> bool {
    if let Some(p) = crate::runner::resolve_tool("xdg-open")
        && spawn_detached(&p, &[url]).is_ok()
    {
        return true;
    }
    crate::runner::resolve_tool("gio").is_some_and(|p| spawn_detached(&p, &["open", url]).is_ok())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let mut r = [0u8; 8];
            hirz_crypto::random_fill(&mut r).unwrap();
            let p = std::env::temp_dir().join(format!(
                "hirz-uv-first-run-{tag}-{}",
                hirz_proto::hex::encode(&r)
            ));
            std::fs::create_dir_all(&p).unwrap();
            Scratch(p)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn one_setup_window_at_a_time() {
        let d = Scratch::new("lock");
        assert!(!window_open(&d.0));
        let held = try_lock(&d.0).unwrap().expect("free");
        assert!(window_open(&d.0));
        assert!(try_lock(&d.0).unwrap().is_none());
        drop(held);
        assert!(!window_open(&d.0));
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(setup_dir(&d.0))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn a_cancelled_setup_stays_quiet_for_a_minute() {
        let d = Scratch::new("cancel");
        let now = 1_700_000_000;
        assert!(!cancelled_recently(&d.0, now));
        mark_cancelled(&d.0, now).unwrap();
        assert!(cancelled_recently(&d.0, now));
        assert!(cancelled_recently(&d.0, now + 59));
        assert!(!cancelled_recently(&d.0, now + 60));
        assert_eq!(cancelled_at(&d.0, now + 10), Some(now));
        assert!(cancelled_recently(&d.0, now - 30), "clock went back");
        assert!(!cancelled_recently(&d.0, now - 3600));
        let file = setup_dir(&d.0).join(CANCELLED_FILE);
        std::fs::write(&file, "not a time").unwrap();
        assert!(!cancelled_recently(&d.0, now));
        std::fs::write(&file, "1".repeat(64)).unwrap();
        assert!(!cancelled_recently(&d.0, now));
    }

    #[test]
    fn a_completed_setup_clears_the_quiet_period() {
        let d = Scratch::new("clear");
        mark_cancelled(&d.0, 100).unwrap();
        assert!(claim_quiet_notice(&d.0, 100));
        clear_cancelled(&d.0);
        assert!(!cancelled_recently(&d.0, 100));
        assert!(!setup_dir(&d.0).join(QUIET_NOTICE_FILE).exists());
        clear_cancelled(&d.0);
    }

    #[test]
    fn one_quiet_notice_per_cancelled_setup() {
        let d = Scratch::new("quiet");
        mark_cancelled(&d.0, 100).unwrap();
        assert!(claim_quiet_notice(&d.0, 100));
        assert!(!claim_quiet_notice(&d.0, 100), "another process asks too");
        mark_cancelled(&d.0, 500).unwrap();
        assert!(claim_quiet_notice(&d.0, 500), "a new cancel, a new period");
        assert!(!claim_quiet_notice(&d.0, 500));
    }

    #[test]
    fn a_no_passkey_notice_once_per_site_and_minute() {
        let d = Scratch::new("no-passkey");
        let now = 1_700_000_000;
        assert!(claim_no_passkey_notice(&d.0, "example.com", now));
        assert!(!claim_no_passkey_notice(&d.0, "example.com", now + 59));
        assert!(claim_no_passkey_notice(&d.0, "acme.example", now + 1));
        assert!(claim_no_passkey_notice(&d.0, "example.com", now + 60));
        for i in 0..300 {
            claim_no_passkey_notice(&d.0, &format!("s{i}.example"), now + 100);
        }
        let count = std::fs::read_dir(setup_dir(&d.0).join(NO_PASSKEY_DIR))
            .unwrap()
            .count();
        assert!(count <= MAX_NO_PASSKEY_SITES, "{count}");
        assert!(claim_no_passkey_notice(&d.0, "late.example", now + 1000));
    }

    #[test]
    fn a_waiter_that_gave_up_is_told_once() {
        let d = Scratch::new("waiter");
        assert!(!take_waiter_gone(&d.0));
        mark_waiter_gone(&d.0);
        assert!(take_waiter_gone(&d.0));
        assert!(!take_waiter_gone(&d.0));
    }

    #[test]
    fn notifications_go_to_the_notification_service_as_hirz() {
        let a = notify_args(
            r#"hirz has no passkey for "x" \ y."#,
            Some("/usr/share/hirz.svg"),
        );
        assert_eq!(
            a,
            [
                "call",
                "--session",
                "--dest=org.freedesktop.Notifications",
                "--object-path=/org/freedesktop/Notifications",
                "--method=org.freedesktop.Notifications.Notify",
                "--",
                r#""hirz""#,
                "uint32 0",
                r#""/usr/share/hirz.svg""#,
                "\"hirz has no passkey for \\\"x\\\" \u{ff3c} y.\"",
                r#""""#,
                "@as []",
                "@a{sv} {}",
                "int32 10000",
            ]
        );
        let tricky = notify_args("a\"\nb<i>\u{202e}", None);
        assert_eq!(tricky[8], r#""""#);
        assert_eq!(tricky[9], "\"a\\\" b\u{ff1c}i\u{ff1e}\"");
    }

    #[derive(Clone)]
    struct Recorder {
        calls: std::sync::Arc<std::sync::Mutex<Vec<crate::runner::CommandSpec>>>,
        gdbus: bool,
        gdbus_ok: bool,
    }

    impl crate::runner::CommandRunner for Recorder {
        fn run(&self, spec: &crate::runner::CommandSpec) -> crate::runner::RunResult {
            self.calls.lock().unwrap().push(spec.clone());
            crate::runner::RunResult::Exited {
                code: Some(if self.gdbus_ok { 0 } else { 1 }),
                stdout: hirz_crypto::Zeroizing::new(Vec::new()),
                stderr: Vec::new(),
                elapsed: Duration::ZERO,
            }
        }
        fn run_with_dialog(
            &self,
            _: &crate::runner::CommandSpec,
            _: &crate::runner::CommandSpec,
        ) -> crate::runner::Race {
            crate::runner::Race::Main(crate::runner::RunResult::NotFound)
        }
        fn tool_available(&self, tool: crate::runner::Tool) -> bool {
            tool != crate::runner::Tool::Gdbus || self.gdbus
        }
        fn polkit_action_installed(&self) -> bool {
            false
        }
        fn process_identity(&self) -> Option<crate::polkit::ProcessIdentity> {
            None
        }
        fn username(&self) -> Option<String> {
            None
        }
    }

    #[test]
    fn zenity_shows_the_notice_when_gdbus_cannot() {
        use crate::runner::Tool;
        for (gdbus, gdbus_ok, tools) in [
            (true, true, vec![Tool::Gdbus]),
            (true, false, vec![Tool::Gdbus, Tool::Zenity]),
            (false, false, vec![Tool::Zenity]),
        ] {
            let r = Recorder {
                calls: Default::default(),
                gdbus,
                gdbus_ok,
            };
            assert_eq!(notify_now(&r, "hirz is ready."), gdbus && gdbus_ok);
            let calls = r.calls.lock().unwrap();
            let used: Vec<Tool> = calls.iter().map(|c| c.tool).collect();
            assert_eq!(used, tools);
            if let Some(z) = calls.iter().find(|c| c.tool == Tool::Zenity) {
                assert_eq!(z.args, ["--notification", "--text=hirz is ready."]);
            }
        }
    }

    #[test]
    fn a_detached_program_runs_in_a_session_of_its_own() {
        let Some(sh) = crate::runner::resolve_tool("sh") else {
            return;
        };
        let d = Scratch::new("spawn");
        let out = d.0.join("out");
        let script = format!(
            "cat /proc/$$/stat > '{}.tmp' && mv '{0}.tmp' '{0}'",
            out.display()
        );
        spawn_detached(&sh, &["-c", &script]).unwrap();
        let mut stat = String::new();
        for _ in 0..200 {
            if let Ok(s) = std::fs::read_to_string(&out) {
                stat = s;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let pid = stat.split_whitespace().next().expect("written");
        let after = stat.rsplit_once(')').unwrap().1;
        let session = after.split_whitespace().nth(3).unwrap();
        assert_eq!(session, pid);
    }
}
