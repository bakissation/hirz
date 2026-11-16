//! Running helper programs (zenity, pkcheck, fprintd) and reading the few system facts the
//! approval flow needs. The flow only talks to the [`CommandRunner`] trait so the decision
//! logic can be tested with a scripted fake.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use hirz_crypto::Secret;

use crate::polkit::{self, ProcessIdentity};

/// The helper programs hirz-uv runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Zenity,
    Pkcheck,
    FprintdVerify,
    FprintdList,
}

impl Tool {
    pub fn binary_name(self) -> &'static str {
        match self {
            Tool::Zenity => "zenity",
            Tool::Pkcheck => "pkcheck",
            Tool::FprintdVerify => "fprintd-verify",
            Tool::FprintdList => "fprintd-list",
        }
    }
}

/// Which environment a child process gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvPolicy {
    /// Cleared environment with a fixed PATH and the C locale. Used for helpers that talk to
    /// the system bus, so a tampered `DBUS_SYSTEM_BUS_ADDRESS` cannot redirect them.
    System,
    /// Only the variables a desktop dialog needs to reach the user's display.
    Desktop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub tool: Tool,
    /// Passed as an argument vector, never through a shell.
    pub args: Vec<String>,
    pub env: EnvPolicy,
    /// The child is killed when it runs longer than this.
    pub timeout: Duration,
}

pub enum RunResult {
    Exited {
        /// `None` when the child was terminated by a signal.
        code: Option<i32>,
        /// Wiped on drop: zenity prints the typed PIN here.
        stdout: Secret,
        stderr: Vec<u8>,
    },
    /// Killed after `CommandSpec::timeout`.
    TimedOut,
    /// The program is not installed in a trusted system directory.
    NotFound,
    Failed(String),
}

impl core::fmt::Debug for RunResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RunResult::Exited {
                code,
                stdout,
                stderr,
            } => f
                .debug_struct("Exited")
                .field("code", code)
                .field("stdout_len", &stdout.len())
                .field("stderr_len", &stderr.len())
                .finish(),
            RunResult::TimedOut => f.write_str("TimedOut"),
            RunResult::NotFound => f.write_str("NotFound"),
            RunResult::Failed(m) => f.debug_tuple("Failed").field(m).finish(),
        }
    }
}

/// Which of two processes run side by side ended first; the other one was killed.
#[derive(Debug)]
pub enum Race {
    Main(RunResult),
    Dialog(RunResult),
}

/// Everything the approval flow needs from the operating system.
pub trait CommandRunner {
    fn run(&self, spec: &CommandSpec) -> RunResult;
    /// Runs `main` (for example `fprintd-verify`) while `dialog` is shown, and returns as soon
    /// as either ends, after killing the other.
    fn run_with_dialog(&self, main: &CommandSpec, dialog: &CommandSpec) -> Race;
    /// An icon for hirz's windows, from a fixed list of system paths.
    fn window_icon(&self) -> Option<PathBuf> {
        None
    }
    /// True when the program exists in a trusted system directory.
    fn tool_available(&self, tool: Tool) -> bool;
    /// True when the hirz polkit action file is installed.
    fn polkit_action_installed(&self) -> bool;
    /// pid, start time and uid of the current process, for `pkcheck --process`.
    fn process_identity(&self) -> Option<ProcessIdentity>;
    /// Login name of the current user, for `fprintd-list`.
    fn username(&self) -> Option<String>;
}

/// Directories searched for helper programs. PATH is ignored on purpose: a same-user process
/// could otherwise point it at a fake `pkcheck` that always exits 0.
pub const TRUSTED_DIRS: &[&str] = &[
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/run/current-system/sw/bin",
];

/// Where packages install the hirz icon. Never taken from the environment.
pub const WINDOW_ICONS: &[&str] = &[
    "/usr/share/icons/hicolor/scalable/apps/hirz.svg",
    "/usr/local/share/icons/hicolor/scalable/apps/hirz.svg",
];

const CHILD_PATH: &str = "/usr/bin:/bin";
const OUTPUT_CAP: usize = 16 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const DESKTOP_ENV: &[&str] = &[
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_TYPE",
    "XDG_CURRENT_DESKTOP",
    "XDG_DATA_DIRS",
    "DBUS_SESSION_BUS_ADDRESS",
    "HOME",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_MESSAGES",
    "LC_CTYPE",
];

/// Finds `name` in [`TRUSTED_DIRS`]; the file must be a root-owned executable that neither
/// group nor others can write.
pub fn resolve_tool(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    TRUSTED_DIRS.iter().find_map(|dir| {
        let path = Path::new(dir).join(name);
        let md = std::fs::metadata(&path).ok()?;
        let mode = md.mode();
        (md.is_file() && md.uid() == 0 && mode & 0o022 == 0 && mode & 0o111 != 0).then_some(path)
    })
}

/// The real runner.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemRunner;

struct Running {
    child: Child,
    out: mpsc::Receiver<Option<Secret>>,
    err: mpsc::Receiver<Option<Secret>>,
}

impl Running {
    fn start(spec: &CommandSpec) -> Result<Running, RunResult> {
        let Some(path) = resolve_tool(spec.tool.binary_name()) else {
            return Err(RunResult::NotFound);
        };
        let mut cmd = Command::new(path);
        cmd.args(&spec.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear()
            .env("PATH", CHILD_PATH);
        match spec.env {
            EnvPolicy::System => {
                cmd.env("LC_ALL", "C");
            }
            EnvPolicy::Desktop => {
                for key in DESKTOP_ENV {
                    if let Some(v) = std::env::var_os(key) {
                        cmd.env(key, v);
                    }
                }
            }
        }
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(RunResult::NotFound),
            Err(e) => return Err(RunResult::Failed(format!("spawn failed: {}", e.kind()))),
        };
        let out = spawn_reader(child.stdout.take());
        let err = spawn_reader(child.stderr.take());
        Ok(Running { child, out, err })
    }

    /// `Ok(Some)` once the child exited.
    fn poll(&mut self) -> Result<Option<ExitStatus>, RunResult> {
        self.child.try_wait().map_err(|e| {
            self.kill();
            RunResult::Failed(format!("wait failed: {}", e.kind()))
        })
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn finish(self, status: ExitStatus) -> RunResult {
        let stdout = self.out.recv_timeout(DRAIN_TIMEOUT).ok().flatten();
        let stderr = self.err.recv_timeout(DRAIN_TIMEOUT).ok().flatten();
        match (stdout, stderr) {
            (Some(stdout), Some(stderr)) => RunResult::Exited {
                code: status.code(),
                stdout,
                stderr: stderr.to_vec(),
            },
            _ => RunResult::Failed("output missing or over the size limit".into()),
        }
    }
}

fn past(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|d| Instant::now() >= d)
}

impl CommandRunner for SystemRunner {
    fn run(&self, spec: &CommandSpec) -> RunResult {
        let mut child = match Running::start(spec) {
            Ok(c) => c,
            Err(r) => return r,
        };
        let deadline = Instant::now().checked_add(spec.timeout);
        loop {
            match child.poll() {
                Ok(Some(status)) => return child.finish(status),
                Ok(None) => {}
                Err(r) => return r,
            }
            if past(deadline) {
                child.kill();
                return RunResult::TimedOut;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    fn run_with_dialog(&self, main: &CommandSpec, dialog: &CommandSpec) -> Race {
        let mut m = match Running::start(main) {
            Ok(c) => c,
            Err(r) => return Race::Main(r),
        };
        let mut d = match Running::start(dialog) {
            Ok(c) => c,
            Err(r) => {
                m.kill();
                return Race::Dialog(r);
            }
        };
        let now = Instant::now();
        let main_end = now.checked_add(main.timeout);
        let dialog_end = now.checked_add(dialog.timeout);
        loop {
            match m.poll() {
                Ok(Some(status)) => {
                    d.kill();
                    return Race::Main(m.finish(status));
                }
                Ok(None) => {}
                Err(r) => {
                    d.kill();
                    return Race::Main(r);
                }
            }
            match d.poll() {
                Ok(Some(status)) => {
                    m.kill();
                    return Race::Dialog(d.finish(status));
                }
                Ok(None) => {}
                Err(r) => {
                    m.kill();
                    return Race::Dialog(r);
                }
            }
            if past(main_end) {
                m.kill();
                d.kill();
                return Race::Main(RunResult::TimedOut);
            }
            if past(dialog_end) {
                m.kill();
                d.kill();
                return Race::Dialog(RunResult::TimedOut);
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    fn window_icon(&self) -> Option<PathBuf> {
        WINDOW_ICONS.iter().map(PathBuf::from).find(|p| p.is_file())
    }

    fn tool_available(&self, tool: Tool) -> bool {
        resolve_tool(tool.binary_name()).is_some()
    }

    fn polkit_action_installed(&self) -> bool {
        polkit::POLICY_DIRS
            .iter()
            .any(|dir| Path::new(dir).join(polkit::POLICY_FILE_NAME).is_file())
    }

    fn process_identity(&self) -> Option<ProcessIdentity> {
        let stat = read_capped_file(Path::new("/proc/self/stat"), 4096)?;
        let status = read_capped_file(Path::new("/proc/self/status"), 64 * 1024)?;
        Some(ProcessIdentity {
            pid: std::process::id(),
            start_time: polkit::parse_stat_start_time(&stat)?,
            uid: polkit::parse_status_uid(&status)?,
        })
    }

    fn username(&self) -> Option<String> {
        let status = read_capped_file(Path::new("/proc/self/status"), 64 * 1024)?;
        let uid = polkit::parse_status_uid(&status)?;
        read_capped_file(Path::new("/etc/passwd"), 4 * 1024 * 1024)
            .and_then(|p| passwd_name_for_uid(&p, uid))
            .or_else(|| std::env::var("USER").ok().filter(|u| valid_username(u)))
    }
}

fn spawn_reader<R: Read + Send + 'static>(src: Option<R>) -> mpsc::Receiver<Option<Secret>> {
    let (tx, rx) = mpsc::channel();
    match src {
        None => {
            let _ = tx.send(Some(Secret::new(Vec::new())));
        }
        Some(mut r) => {
            // If the thread cannot start, the sender is dropped and the caller sees no output.
            let _ = std::thread::Builder::new()
                .name("hirz-uv-reader".into())
                .spawn(move || {
                    let _ = tx.send(read_capped(&mut r));
                });
        }
    }
    rx
}

/// Reads at most [`OUTPUT_CAP`] bytes into a preallocated secret buffer so that no
/// reallocation leaves unwiped copies behind. Returns `None` on error or overflow.
fn read_capped(r: &mut impl Read) -> Option<Secret> {
    let mut buf = Secret::new(vec![0u8; OUTPUT_CAP]);
    let mut len = 0usize;
    let mut overflow = false;
    let mut sink = [0u8; 512];
    loop {
        let (dst, full): (&mut [u8], bool) = match buf.get_mut(len..) {
            Some(d) if !d.is_empty() => (d, false),
            _ => (sink.as_mut_slice(), true),
        };
        match r.read(dst) {
            Ok(0) => break,
            Ok(_) if full => overflow = true,
            Ok(n) => len = len.saturating_add(n).min(OUTPUT_CAP),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    if overflow {
        return None;
    }
    buf.truncate(len);
    Some(buf)
}

fn read_capped_file(path: &Path, cap: u64) -> Option<Vec<u8>> {
    let f = std::fs::File::open(path).ok()?;
    let mut out = Vec::new();
    f.take(cap.saturating_add(1)).read_to_end(&mut out).ok()?;
    (u64::try_from(out.len()).ok()? <= cap).then_some(out)
}

/// Login names passed to `fprintd-list` as an argument; reject anything that could be read as
/// an option or that a shell-free argv still should not carry.
pub fn valid_username(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Finds the login name for `uid` in `/etc/passwd` content.
pub fn passwd_name_for_uid(passwd: &[u8], uid: u32) -> Option<String> {
    let text = core::str::from_utf8(passwd).ok()?;
    text.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let _password = fields.next()?;
        let line_uid: u32 = fields.next()?.parse().ok()?;
        (line_uid == uid && valid_username(name)).then(|| name.to_owned())
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn passwd_lookup() {
        let p = b"root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice,,,:/u/alice:/bin/bash\n";
        assert_eq!(passwd_name_for_uid(p, 1000).as_deref(), Some("alice"));
        assert_eq!(passwd_name_for_uid(p, 0).as_deref(), Some("root"));
        assert_eq!(passwd_name_for_uid(p, 1001), None);
        assert_eq!(passwd_name_for_uid(b"broken line\n::x\n", 0), None);
        assert_eq!(passwd_name_for_uid(b"-evil:x:5:5::/:/bin/sh\n", 5), None);
    }

    #[test]
    fn usernames() {
        assert!(valid_username("alice"));
        assert!(valid_username("a.b_c-d"));
        assert!(!valid_username(""));
        assert!(!valid_username("--help"));
        assert!(!valid_username("a b"));
        assert!(!valid_username(&"a".repeat(65)));
    }

    #[test]
    fn capped_reader() {
        let data = vec![7u8; 100];
        let out = read_capped(&mut data.as_slice()).unwrap();
        assert_eq!(&out[..], &data[..]);
        let big = vec![1u8; OUTPUT_CAP + 1];
        assert!(read_capped(&mut big.as_slice()).is_none());
        let exact = vec![1u8; OUTPUT_CAP];
        assert_eq!(
            read_capped(&mut exact.as_slice()).unwrap().len(),
            OUTPUT_CAP
        );
    }

    #[test]
    fn debug_hides_output() {
        let r = RunResult::Exited {
            code: Some(0),
            stdout: Secret::new(b"1234".to_vec()),
            stderr: vec![],
        };
        let s = format!("{r:?}");
        assert!(!s.contains("49"), "{s}");
        assert!(s.contains("stdout_len: 4"));
    }

    #[test]
    fn system_runner_real_process() {
        // Smoke test against a binary that exists on every Linux system; skipped otherwise.
        if resolve_tool("pkcheck").is_none() {
            return;
        }
        let r = SystemRunner.run(&CommandSpec {
            tool: Tool::Pkcheck,
            args: vec!["--version".into()],
            env: EnvPolicy::System,
            timeout: Duration::from_secs(10),
        });
        match r {
            RunResult::Exited { code, stdout, .. } => {
                assert_eq!(code, Some(0));
                assert!(stdout.starts_with(b"pkcheck"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn race_returns_the_first_to_end() {
        if resolve_tool("pkcheck").is_none() {
            return;
        }
        let quick = CommandSpec {
            tool: Tool::Pkcheck,
            args: vec!["--version".into()],
            env: EnvPolicy::System,
            timeout: Duration::from_secs(10),
        };
        let missing = CommandSpec {
            tool: Tool::FprintdList,
            ..quick.clone()
        };
        match SystemRunner.run_with_dialog(&quick, &quick) {
            Race::Main(RunResult::Exited { code, .. })
            | Race::Dialog(RunResult::Exited { code, .. }) => {
                assert_eq!(code, Some(0));
            }
            other => panic!("unexpected {other:?}"),
        }
        if resolve_tool("fprintd-list").is_none() {
            assert!(matches!(
                SystemRunner.run_with_dialog(&quick, &missing),
                Race::Dialog(RunResult::NotFound)
            ));
            assert!(matches!(
                SystemRunner.run_with_dialog(&missing, &quick),
                Race::Main(RunResult::NotFound)
            ));
        }
    }

    #[test]
    fn icons_come_from_fixed_system_paths() {
        assert!(
            WINDOW_ICONS
                .iter()
                .all(|p| p.starts_with("/usr/") && p.ends_with("/hirz.svg"))
        );
        if let Some(p) = SystemRunner.window_icon() {
            assert!(WINDOW_ICONS.iter().any(|w| p == Path::new(w)));
        }
    }

    #[test]
    fn own_identity() {
        let id = SystemRunner.process_identity().unwrap();
        assert_eq!(id.pid, std::process::id());
        assert!(id.start_time > 0);
    }
}
