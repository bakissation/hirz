//! Where the vault lives, and one opened vault with its approver, shared by hirzd and hirz-nmh.
//! Locations are in docs/architecture.md, "Local state". The variables are read once at start; the
//! recorded folder is re-read while no vault is open.
#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use hirz_core::{Approval, ApprovalContext, ApprovalError, Approver, CoreError, Engine};
use hirz_vault::{VAULT_POINTER_FILE, Vault, VaultError, VaultPointerError};

pub const VAULT_ENV: &str = "HIRZ_VAULT";
pub const STATE_ENV: &str = "HIRZ_STATE";
const VARS: [&str; 6] = [
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    VAULT_ENV,
    STATE_ENV,
];

#[derive(Debug, Clone, Default)]
pub struct Settings {
    vars: Vec<(&'static str, OsString)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    pub vault_dir: PathBuf,
    pub state_dir: PathBuf,
}

impl Settings {
    pub fn from_process() -> Settings {
        Settings::from_vars(|k| std::env::var_os(k))
    }

    pub fn from_vars(get: impl Fn(&str) -> Option<OsString>) -> Settings {
        Settings {
            vars: VARS
                .iter()
                .filter_map(|k| get(k).map(|v| (*k, v)))
                .collect(),
        }
    }

    fn var(&self, key: &str) -> Option<&OsString> {
        self.vars.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    /// Relative and empty values are ignored, as the XDG base directory spec requires.
    fn abs(&self, key: &str) -> Option<PathBuf> {
        self.var(key).map(PathBuf::from).filter(|p| p.is_absolute())
    }

    pub fn state_dir(&self) -> Result<PathBuf, &'static str> {
        self.abs(STATE_ENV)
            .or_else(|| self.abs("XDG_STATE_HOME").map(|p| p.join("hirz")))
            .or_else(|| {
                self.abs("HOME")
                    .map(|h| h.join(".local").join("state").join("hirz"))
            })
            .ok_or("HOME is not set")
    }

    pub fn location(&self) -> Result<Location, String> {
        let state_dir = self.state_dir()?;
        let vault_dir = match self.abs(VAULT_ENV) {
            Some(p) => p,
            None => match read_pointer(&state_dir.join(VAULT_POINTER_FILE))? {
                Some(p) => p,
                None => self
                    .abs("XDG_DATA_HOME")
                    .or_else(|| self.abs("HOME").map(|h| h.join(".local").join("share")))
                    .ok_or("HOME is not set")?
                    .join("hirz")
                    .join("vault"),
            },
        };
        Ok(Location {
            vault_dir,
            state_dir,
        })
    }

    pub fn uv_paths(&self) -> Result<hirz_uv::Paths, &'static str> {
        let mut paths = hirz_uv::Paths::from_vars(|k| self.var(k).cloned())?;
        paths.state_dir = self.state_dir()?;
        Ok(paths)
    }
}

fn read_pointer(path: &Path) -> Result<Option<PathBuf>, String> {
    hirz_vault::read_vault_pointer(path).map_err(|e| match e {
        VaultPointerError::Io(e) => format!("cannot read {}: {e}", path.display()),
        VaultPointerError::Invalid => format!("{} does not hold a valid folder", path.display()),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultStatus {
    Ready,
    Missing,
    Broken(String),
    /// Another device removed this one from the vault. Its passkeys are no longer used here.
    Removed,
}

/// How old the last look at the vault folder may be for the requests that only read and never ask
/// the user: account lists, capability checks and silent probes. Every look scans the whole folder
/// and runs the maintenance that belongs to it (migration, key rotation, garbage collection), so a
/// page or a client that repeats such a request must not make each one do that work.
pub const READ_ONLY_MAX_AGE: Duration = Duration::from_secs(3);

pub const REMOVED_NOTICE: &str =
    "This computer was removed from your hirz vault; its passkeys are no longer used here";

/// Said when `Session::take_fork_change` reports `Some(true)`.
pub const FORK_NOTICE: &str = "the vault folder no longer holds the key changes this computer \
     followed, so someone with access to it may have changed it; existing passkeys still work, \
     new passkeys are refused until it is settled (run `hirz status`, then `hirz repair`)";

/// Said when `Session::take_fork_change` reports `Some(false)`.
pub const FORK_ENDED_NOTICE: &str =
    "the vault folder is consistent again; new passkeys can be saved";

/// After the setup window was started, the same process does not start it again for this long,
/// whatever happened to it: a page that sends request after request starts at most one window per
/// interval, and the window's own lock keeps a second one from opening.
pub const SETUP_RETRY: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupOffer {
    /// `hirz init --gui` was started.
    Opened,
    /// A setup window is open already (started by this or another process).
    AlreadyOpen,
    /// The user cancelled the window a moment ago; [`QUIET_NOTICE`] was shown instead, once for
    /// that quiet period.
    QuietNotice,
    NotOffered,
}

/// How long a request that would ask the user waits for the setup window
/// ([`FirstRun::wait_for_setup`]), and how often it looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hold {
    pub limit: Duration,
    pub poll: Duration,
}

pub const HOLD_POLL: Duration = Duration::from_millis(500);
/// A window that was just started counts as open this long, before it has taken its lock.
pub const SETUP_START_GRACE: Duration = Duration::from_secs(10);

/// Shown, once, to a request that comes while a cancelled setup keeps quiet.
pub const QUIET_NOTICE: &str =
    "hirz is not set up. Try again in a minute, or run hirz init in a terminal.";

/// How [`FirstRun`] starts the setup window; tests count the starts instead.
pub trait SetupLauncher {
    /// The window can be drawn (zenity is installed in a trusted directory).
    fn can_draw(&self) -> bool;
    fn launch(&self, program: &Path, runtime_dir: &Path) -> std::io::Result<()>;
    /// A desktop notification, best effort.
    fn notify(&self, text: &str);
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemLauncher;

impl SetupLauncher for SystemLauncher {
    fn can_draw(&self) -> bool {
        hirz_uv::runner::resolve_tool("zenity").is_some()
    }

    fn notify(&self, text: &str) {
        hirz_uv::first_run::notify_desktop(text);
    }

    fn launch(&self, program: &Path, runtime_dir: &Path) -> std::io::Result<()> {
        let (exe, args) = setup_command(
            program,
            runtime_dir,
            hirz_uv::runner::resolve_tool("systemd-run").as_deref(),
            |k| std::env::var_os(k),
        );
        hirz_uv::first_run::spawn_detached(&exe, &args)
    }
}

/// The transient user unit the setup window runs in. A fixed name: while one runs, starting a
/// second one fails.
pub const SETUP_UNIT: &str = "hirz-setup.service";

/// Passed on to the setup window when they are set here: where the vault and state live, and the
/// display. A transient unit otherwise gets the user manager's environment, not ours.
const SETUP_ENV: [&str; 8] = [
    VAULT_ENV,
    STATE_ENV,
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_CONFIG_HOME",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
];

/// What starts `hirz init --gui`: `systemd-run --user` when there is a user service manager (its
/// socket `$XDG_RUNTIME_DIR/systemd/private`) and `systemd_run` was found in a trusted system
/// directory, so the window runs in a unit of its own, outside the daemon's cgroup and sandbox,
/// and outlives a daemon restart. Otherwise `program` itself, started detached. Never a shell.
pub fn setup_command(
    program: &Path,
    runtime_dir: &Path,
    systemd_run: Option<&Path>,
    env: impl Fn(&str) -> Option<OsString>,
) -> (PathBuf, Vec<OsString>) {
    let manager = runtime_dir.join("systemd").join("private");
    let direct = || {
        (
            program.to_path_buf(),
            vec![OsString::from("init"), OsString::from("--gui")],
        )
    };
    let Some(run) = systemd_run.filter(|_| manager.exists()) else {
        return direct();
    };
    let mut args: Vec<OsString> = [
        "--user",
        "--quiet",
        "--collect",
        "--no-block",
        "--description=hirz setup",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    args.insert(4, OsString::from(format!("--unit={SETUP_UNIT}")));
    for key in SETUP_ENV {
        if let Some(value) = env(key).filter(|v| !v.is_empty()) {
            let mut arg = OsString::from(format!("--setenv={key}="));
            arg.push(value);
            args.push(arg);
        }
    }
    args.push(OsString::from("--"));
    args.push(program.as_os_str().to_owned());
    args.push(OsString::from("init"));
    args.push(OsString::from("--gui"));
    (run.to_path_buf(), args)
}

/// Opens the graphical first-run setup (`hirz init --gui`) when a request that would ask the user
/// finds no vault (docs/approval.md, "Setting up hirz"). Silent probes must not call it.
#[derive(Debug)]
pub struct FirstRun<L = SystemLauncher> {
    runtime_dir: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    graphical: bool,
    program: Option<PathBuf>,
    launcher: L,
    last_launch: Option<Instant>,
}

/// The `hirz` program to start: the one next to the running program, else `/usr/bin/hirz`. `PATH`
/// is never searched.
pub fn setup_program(current_exe: Option<&Path>) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let executable = |p: &Path| {
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    current_exe
        .and_then(Path::parent)
        .map(|d| d.join("hirz"))
        .filter(|p| executable(p))
        .or_else(|| Some(PathBuf::from("/usr/bin/hirz")).filter(|p| executable(p)))
}

impl FirstRun<SystemLauncher> {
    /// Never opens anything.
    pub fn disabled() -> Self {
        FirstRun::new(None, None, false, None, SystemLauncher)
    }

    /// Reads `XDG_RUNTIME_DIR`, `WAYLAND_DISPLAY` and `DISPLAY` once.
    pub fn from_process(settings: &Settings) -> Self {
        let set = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
        FirstRun::new(
            std::env::var_os("XDG_RUNTIME_DIR")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute()),
            settings.state_dir().ok(),
            set("WAYLAND_DISPLAY") || set("DISPLAY"),
            setup_program(std::env::current_exe().ok().as_deref()),
            SystemLauncher,
        )
    }
}

impl<L: SetupLauncher> FirstRun<L> {
    pub fn new(
        runtime_dir: Option<PathBuf>,
        state_dir: Option<PathBuf>,
        graphical: bool,
        program: Option<PathBuf>,
        launcher: L,
    ) -> Self {
        FirstRun {
            runtime_dir,
            state_dir,
            graphical,
            program,
            launcher,
            last_launch: None,
        }
    }

    pub fn offer(&mut self) -> SetupOffer {
        let unix_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.offer_at(Instant::now(), unix_now)
    }

    /// Nothing is started without a graphical session, while a setup window is open, within
    /// [`SETUP_RETRY`] of the last start by this process, within a minute of a setup the user
    /// cancelled, or on a computer that is set up and only misses its vault folder (a sync tool
    /// that has not copied it yet).
    pub fn offer_at(&mut self, now: Instant, unix_now: u64) -> SetupOffer {
        let (true, Some(runtime), Some(program)) = (
            self.graphical,
            self.runtime_dir.as_deref(),
            self.program.as_deref(),
        ) else {
            return SetupOffer::NotOffered;
        };
        if self
            .state_dir
            .as_deref()
            .is_none_or(hirz_vault::Vault::is_set_up)
        {
            return SetupOffer::NotOffered;
        }
        if hirz_uv::first_run::window_open(runtime) {
            return SetupOffer::AlreadyOpen;
        }
        if let Some(at) = hirz_uv::first_run::cancelled_at(runtime, unix_now) {
            if hirz_uv::first_run::claim_quiet_notice(runtime, at) {
                self.launcher.notify(QUIET_NOTICE);
                return SetupOffer::QuietNotice;
            }
            return SetupOffer::NotOffered;
        }
        if self
            .last_launch
            .is_some_and(|t| now.saturating_duration_since(t) < SETUP_RETRY)
            || !self.launcher.can_draw()
        {
            return SetupOffer::NotOffered;
        }
        self.last_launch = Some(now);
        match self.launcher.launch(program, runtime) {
            Ok(()) => SetupOffer::Opened,
            Err(_) => SetupOffer::NotOffered,
        }
    }
}

impl<L: SetupLauncher> FirstRun<L> {
    fn setup_running(&self, runtime: &Path, now: Instant) -> bool {
        hirz_uv::first_run::window_open(runtime)
            || self
                .last_launch
                .is_some_and(|t| now.saturating_duration_since(t) < SETUP_START_GRACE)
    }

    /// After [`FirstRun::offer`] said `Opened` or `AlreadyOpen`: waits while the setup window
    /// runs, then looks at the vault folder. The vault is not used while the window is still
    /// open (it exists before its phrase was checked). A request that is cancelled or runs out of
    /// `hold.limit` first gets `Missing`, and the window says when hirz is ready.
    pub fn wait_for_setup<A: Approver>(
        &mut self,
        session: &mut Session<A>,
        cancelled: &dyn Fn() -> bool,
        hold: Hold,
    ) -> VaultStatus {
        let Some(runtime) = self.runtime_dir.clone() else {
            return VaultStatus::Missing;
        };
        let started = Instant::now();
        loop {
            let now = Instant::now();
            if !self.setup_running(&runtime, now) {
                return session.ensure_vault();
            }
            let waited = now.saturating_duration_since(started);
            if cancelled() || waited >= hold.limit {
                hirz_uv::first_run::mark_waiter_gone(&runtime);
                return VaultStatus::Missing;
            }
            std::thread::sleep(hold.poll.min(hold.limit.saturating_sub(waited)));
        }
    }

    /// "hirz has no passkey for SITE." on the desktop, at most once per site and minute for all
    /// processes of the user. For requests that asked for the user's presence and found nothing.
    pub fn no_passkey_notice(&self, rp_id: &str) {
        let unix_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.no_passkey_notice_at(rp_id, unix_now);
    }

    pub fn no_passkey_notice_at(&self, rp_id: &str, unix_now: u64) -> bool {
        let (true, Some(runtime)) = (self.graphical, self.runtime_dir.as_deref()) else {
            return false;
        };
        if !hirz_uv::first_run::claim_no_passkey_notice(runtime, rp_id, unix_now) {
            return false;
        }
        self.launcher.notify(&format!(
            "hirz has no passkey for {}.",
            hirz_uv::display::site_label(rp_id)
        ));
        true
    }
}

pub struct Session<A> {
    settings: Settings,
    vault: Option<Vault>,
    approver: A,
    /// The vault was reloaded by `ensure_vault` and no engine has used it since.
    loaded: bool,
    /// What the vault last reported about a fork, and whether that changed since the front end
    /// last asked (`take_fork_change`).
    fork: bool,
    fork_changed: bool,
    /// When and how the folder was last looked at, for [`Session::ensure_vault_recent`].
    last_look: Option<(Instant, VaultStatus)>,
    looks: u64,
}

impl<A> core::fmt::Debug for Session<A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("vault", &self.vault)
            .finish_non_exhaustive()
    }
}

impl<A: Approver> Session<A> {
    pub fn new(settings: Settings, approver: A) -> Self {
        Session {
            settings,
            vault: None,
            approver,
            loaded: false,
            fork: false,
            fork_changed: false,
            last_look: None,
            looks: 0,
        }
    }

    pub fn approver(&self) -> &A {
        &self.approver
    }

    /// Looks at the vault folder once for a request: opens the vault, or reloads it. The engine
    /// that serves the request does not look again before it asks the user, only after.
    ///
    /// A removed device keeps no vault open, so nothing is served from it; joining again later is picked up by the next call.
    pub fn ensure_vault(&mut self) -> VaultStatus {
        self.loaded = false;
        self.looks = self.looks.saturating_add(1);
        let status = self.load_vault();
        self.observe_fork();
        if status == VaultStatus::Ready {
            self.loaded = true;
        } else {
            self.vault = None;
        }
        self.last_look = Some((Instant::now(), status.clone()));
        status
    }

    /// Like [`Session::ensure_vault`] for a request that only reads and never asks the user: when
    /// the folder was looked at less than `max_age` ago, that look is used again and nothing is
    /// scanned or maintained. Anything that signs, registers or prompts calls `ensure_vault`.
    pub fn ensure_vault_recent(&mut self, max_age: Duration) -> VaultStatus {
        if let Some((at, status)) = &self.last_look
            && at.elapsed() < max_age
            && (*status != VaultStatus::Ready || self.vault.is_some())
        {
            self.loaded = *status == VaultStatus::Ready;
            return status.clone();
        }
        self.ensure_vault()
    }

    /// How many times the vault folder was looked at (opened or reloaded).
    pub fn looks(&self) -> u64 {
        self.looks
    }

    fn load_vault(&mut self) -> VaultStatus {
        if let Some(vault) = self.vault.as_mut() {
            match vault.reload() {
                Ok(r) if r.this_device_removed => return VaultStatus::Removed,
                Ok(_) => return VaultStatus::Ready,
                Err(_) => self.vault = None,
            }
        }
        let loc = match self.settings.location() {
            Ok(l) => l,
            Err(e) => return VaultStatus::Broken(e),
        };
        match Vault::open(&loc.vault_dir, &loc.state_dir) {
            Ok(v) if v.report().this_device_removed => {
                self.vault = Some(v);
                VaultStatus::Removed
            }
            Ok(v) => {
                self.vault = Some(v);
                VaultStatus::Ready
            }
            Err(VaultError::NotFound) => VaultStatus::Missing,
            Err(e) => VaultStatus::Broken(format!("{}: {e}", loc.vault_dir.display())),
        }
    }

    fn observe_fork(&mut self) {
        let Some(now) = self.vault.as_ref().map(|v| v.report().fork_detected) else {
            return;
        };
        if now != self.fork {
            self.fork = now;
            self.fork_changed = true;
        }
    }

    /// `Some(true)` once when the vault starts to report a fork (key changes this computer
    /// followed are missing or were rewritten in the folder), `Some(false)` once when it stops, so
    /// a front end logs it once per change and not once per request.
    pub fn take_fork_change(&mut self) -> Option<bool> {
        core::mem::take(&mut self.fork_changed).then_some(self.fork)
    }

    /// True while the open vault serves the passkeys it has but cannot save new ones (a fork, a
    /// rotation conflict, or a key change this computer holds no key for).
    pub fn read_only(&self) -> bool {
        self.vault
            .as_ref()
            .is_some_and(|v| hirz_core::engine::is_read_only(v.report()))
    }

    /// Once `cancelled` returns true approvals count as refused, so a cancelled request creates and
    /// signs nothing. A vault error closes the vault; the next request reopens it from disk.
    pub fn with_engine<T>(
        &mut self,
        cancelled: &dyn Fn() -> bool,
        f: impl FnOnce(&mut Engine<'_>) -> Result<T, CoreError>,
    ) -> Result<T, CoreError> {
        self.with_engine_observed(cancelled, None, f).0
    }

    /// Like [`Session::with_engine`], and also says whether something may have been shown to the
    /// user: false when the approver was never asked or refused before any window
    /// (`ApprovalError::NothingShown`). `commit` is the engine's last word before a registration
    /// becomes final (`Engine::with_commit`).
    pub fn with_engine_observed<T>(
        &mut self,
        cancelled: &dyn Fn() -> bool,
        commit: Option<&dyn Fn() -> bool>,
        f: impl FnOnce(&mut Engine<'_>) -> Result<T, CoreError>,
    ) -> (Result<T, CoreError>, bool) {
        let Some(vault) = self.vault.as_mut() else {
            return (Err(CoreError::Vault("no vault is open".into())), false);
        };
        let guard = CancelGuard {
            inner: &self.approver,
            cancelled,
            asked: AtomicBool::new(false),
        };
        let mut engine = Engine::new(vault, &guard).with_cancel(cancelled);
        if let Some(commit) = commit {
            engine = engine.with_commit(commit);
        }
        if core::mem::take(&mut self.loaded) {
            engine = engine.with_loaded_vault();
        }
        let result = f(&mut engine);
        let asked = guard.asked.load(Ordering::Relaxed);
        if matches!(result, Err(CoreError::Vault(_))) {
            self.vault = None;
            self.last_look = None;
        }
        self.observe_fork();
        (result, asked)
    }
}

struct CancelGuard<'a, A> {
    inner: &'a A,
    cancelled: &'a dyn Fn() -> bool,
    asked: AtomicBool,
}

impl<A: Approver> CancelGuard<'_, A> {
    fn checked(
        &self,
        ask: impl FnOnce() -> Result<Approval, ApprovalError>,
    ) -> Result<Approval, ApprovalError> {
        if (self.cancelled)() {
            return Err(ApprovalError::Denied);
        }
        let asked = ask();
        if !matches!(asked, Err(ApprovalError::NothingShown)) {
            self.asked.store(true, Ordering::Relaxed);
        }
        let approval = asked?;
        if (self.cancelled)() {
            return Err(ApprovalError::Denied);
        }
        Ok(approval)
    }
}

impl<A: Approver> Approver for CancelGuard<'_, A> {
    fn approve(&self, ctx: &ApprovalContext<'_>) -> Result<Approval, ApprovalError> {
        self.checked(|| self.inner.approve(ctx))
    }

    fn confirm_selection(&self) -> Result<Approval, ApprovalError> {
        self.checked(|| self.inner.confirm_selection())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod location_tests {
    use super::*;

    fn settings(pairs: &[(&str, &str)]) -> Settings {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Settings::from_vars(|k| {
            pairs
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| OsString::from(v))
        })
    }

    #[test]
    fn defaults_follow_xdg() {
        let s = settings(&[("HOME", "/home/alice")]);
        let loc = s.location().unwrap();
        assert_eq!(loc.state_dir, Path::new("/home/alice/.local/state/hirz"));
        assert_eq!(
            loc.vault_dir,
            Path::new("/home/alice/.local/share/hirz/vault")
        );

        let s = settings(&[
            ("HOME", "/home/alice"),
            ("XDG_DATA_HOME", "/data"),
            ("XDG_STATE_HOME", "relative/ignored"),
        ]);
        let loc = s.location().unwrap();
        assert_eq!(loc.state_dir, Path::new("/home/alice/.local/state/hirz"));
        assert_eq!(loc.vault_dir, Path::new("/data/hirz/vault"));

        assert!(settings(&[]).location().is_err());
    }

    #[test]
    fn overrides_win() {
        let s = settings(&[
            ("HOME", "/home/alice"),
            (VAULT_ENV, "/tmp/v"),
            (STATE_ENV, "/tmp/s"),
        ]);
        let loc = s.location().unwrap();
        assert_eq!(loc.vault_dir, Path::new("/tmp/v"));
        assert_eq!(loc.state_dir, Path::new("/tmp/s"));
        assert_eq!(s.uv_paths().unwrap().state_dir, Path::new("/tmp/s"));
    }

    #[test]
    fn recorded_vault_folder() {
        let mut r = [0u8; 8];
        hirz_crypto::random_fill(&mut r).unwrap();
        let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("hirz-location-test-{hex}"));
        std::fs::create_dir_all(&dir).unwrap();
        let state = dir.to_str().unwrap().to_owned();
        let s = settings(&[("HOME", "/home/alice"), (STATE_ENV, &state)]);

        std::fs::write(dir.join(VAULT_POINTER_FILE), b"/srv/sync/hirz").unwrap();
        assert_eq!(s.location().unwrap().vault_dir, Path::new("/srv/sync/hirz"));
        std::fs::write(dir.join(VAULT_POINTER_FILE), b"relative/path").unwrap();
        assert!(s.location().is_err());
        std::fs::write(dir.join(VAULT_POINTER_FILE), b"").unwrap();
        assert!(s.location().is_err());
        std::fs::write(dir.join(VAULT_POINTER_FILE), vec![b'/'; 5000]).unwrap();
        assert!(s.location().is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod session_tests {
    use super::*;
    use hirz_core::{
        GetAssertionRequest, GetExtensions, MakeCredentialRequest, MakeExtensions, RpEntity,
        UserEntity, UvRequirement,
    };

    struct Allow;

    impl Approver for Allow {
        fn approve(&self, _: &ApprovalContext<'_>) -> Result<Approval, ApprovalError> {
            Ok(Approval {
                user_present: true,
                user_verified: false,
                selected: None,
            })
        }
    }

    struct Folders(PathBuf);

    impl Folders {
        fn new() -> Folders {
            let mut r = [0u8; 8];
            hirz_crypto::random_fill(&mut r).unwrap();
            let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
            let p = std::env::temp_dir().join(format!("hirz-session-test-{hex}"));
            std::fs::create_dir_all(&p).unwrap();
            Folders(p)
        }
        fn path(&self, sub: &str) -> PathBuf {
            self.0.join(sub)
        }
        fn settings(&self) -> Settings {
            let vault = self.path("vault").into_os_string();
            let state = self.path("state").into_os_string();
            Settings::from_vars(|k| match k {
                VAULT_ENV => Some(vault.clone()),
                STATE_ENV => Some(state.clone()),
                _ => None,
            })
        }
    }

    impl Drop for Folders {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn make(user: &str) -> MakeCredentialRequest {
        MakeCredentialRequest {
            client_data_hash: [7; 32],
            rp: RpEntity {
                id: "example.com".into(),
                name: None,
            },
            user: UserEntity {
                id: user.as_bytes().to_vec(),
                name: Some(user.into()),
                display_name: None,
            },
            algorithms: vec![hirz_core::COSE_ALG_ES256],
            exclude_list: Vec::new(),
            resident_key: true,
            uv: UvRequirement::Preferred,
            extensions: MakeExtensions::default(),
        }
    }

    fn get(id: &[u8]) -> GetAssertionRequest {
        GetAssertionRequest {
            client_data_hash: [7; 32],
            rp_id: "example.com".into(),
            allow_list: vec![id.to_vec()],
            uv: UvRequirement::Preferred,
            up: true,
            extensions: GetExtensions::default(),
        }
    }

    fn create(vault: &mut Vault, user: &str) -> Vec<u8> {
        Engine::new(vault, &Allow)
            .make_credential(&make(user), None)
            .unwrap()
            .credential_id
    }

    const NEVER: &dyn Fn() -> bool = &|| false;

    #[test]
    fn a_request_looks_at_the_vault_folder_once_before_the_prompt() {
        let f = Folders::new();
        let (mut other, _) = Vault::create(&f.path("vault"), &f.path("state"), "laptop").unwrap();
        let mut session = Session::new(f.settings(), Allow);
        assert_eq!(session.ensure_vault(), VaultStatus::Ready);

        let first = create(&mut other, "alice");
        let r = session.with_engine(NEVER, |e| e.get_assertion(&get(&first), None, None));
        assert_eq!(
            r.unwrap_err(),
            CoreError::NoCredentials,
            "ensure_vault already looked; the engine does not look again before asking"
        );

        assert_eq!(session.ensure_vault(), VaultStatus::Ready);
        let r = session.with_engine(NEVER, |e| e.get_assertion(&get(&first), None, None));
        assert!(r.is_ok());

        let second = create(&mut other, "bob");
        let r = session.with_engine(NEVER, |e| e.get_assertion(&get(&second), None, None));
        assert!(
            r.is_ok(),
            "a request that was not preceded by ensure_vault gets its own look"
        );
    }

    #[test]
    fn a_fork_is_reported_once_per_change_and_blocks_only_new_passkeys() {
        let f = Folders::new();
        let vault_dir = f.path("vault");
        let (mut a, phrase) = Vault::create(&vault_dir, &f.path("state"), "laptop").unwrap();
        let b =
            Vault::join_with_recovery(&vault_dir, &f.path("state-b"), &phrase, "phone").unwrap();
        let existing = create(&mut a, "alice");
        a.remove_device(&b.device_id()).unwrap();
        let hidden = std::fs::read_dir(vault_dir.join("keys"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .find(|n| n.starts_with("0000000002-"))
            .unwrap();
        let from = vault_dir.join("keys").join(&hidden);
        let to = vault_dir.join(format!(".hidden-{hidden}"));
        std::fs::rename(&from, &to).unwrap();

        let mut session = Session::new(f.settings(), Allow);
        assert_eq!(session.take_fork_change(), None);
        assert_eq!(session.ensure_vault(), VaultStatus::Ready);
        assert_eq!(session.take_fork_change(), Some(true));
        assert!(session.read_only());
        for _ in 0..3 {
            assert_eq!(session.ensure_vault(), VaultStatus::Ready);
            assert_eq!(session.take_fork_change(), None, "reported once");
        }

        let r = session.with_engine(NEVER, |e| e.make_credential(&make("bob"), None));
        assert_eq!(
            r.unwrap_err(),
            CoreError::Approval(ApprovalError::Unavailable)
        );
        assert_eq!(session.ensure_vault(), VaultStatus::Ready);
        let r = session.with_engine(NEVER, |e| e.get_assertion(&get(&existing), None, None));
        assert!(r.is_ok(), "existing passkeys keep working");

        std::fs::rename(&to, &from).unwrap();
        assert_eq!(session.ensure_vault(), VaultStatus::Ready);
        assert_eq!(session.take_fork_change(), Some(false));
        assert!(!session.read_only());
        assert_eq!(session.take_fork_change(), None);
    }

    #[test]
    fn a_removed_device_is_not_served() {
        let f = Folders::new();
        let (mut a, phrase) = Vault::create(&f.path("vault"), &f.path("state"), "laptop").unwrap();
        let b = Vault::join_with_recovery(&f.path("vault"), &f.path("state-b"), &phrase, "phone")
            .unwrap();
        let mut session = Session::new(
            Settings::from_vars(|k| match k {
                VAULT_ENV => Some(f.path("vault").into_os_string()),
                STATE_ENV => Some(f.path("state-b").into_os_string()),
                _ => None,
            }),
            Allow,
        );
        assert_eq!(session.ensure_vault(), VaultStatus::Ready);
        a.remove_device(&b.device_id()).unwrap();
        assert_eq!(session.ensure_vault(), VaultStatus::Removed);
        assert_eq!(session.take_fork_change(), None);
        let r = session.with_engine(NEVER, |e| e.make_credential(&make("bob"), None));
        assert!(matches!(r, Err(CoreError::Vault(_))), "no vault is open");
    }

    #[test]
    fn requests_that_only_read_do_not_rescan_the_folder_every_time() {
        let f = Folders::new();
        let (mut other, _) = Vault::create(&f.path("vault"), &f.path("state"), "laptop").unwrap();
        let mut session = Session::new(f.settings(), Allow);
        assert_eq!(
            session.ensure_vault_recent(READ_ONLY_MAX_AGE),
            VaultStatus::Ready
        );
        assert_eq!(session.looks(), 1);
        for _ in 0..100 {
            assert_eq!(
                session.ensure_vault_recent(READ_ONLY_MAX_AGE),
                VaultStatus::Ready
            );
        }
        assert_eq!(
            session.looks(),
            1,
            "100 list requests looked at the folder once"
        );

        let id = create(&mut other, "alice");
        let mut probe = get(&id);
        probe.up = false;
        let r = session.with_engine(NEVER, |e| e.get_assertion(&probe, None, None));
        assert_eq!(
            r.unwrap_err(),
            CoreError::NoCredentials,
            "a silent probe in the window does not scan for what another device just wrote"
        );
        assert_eq!(session.looks(), 1);

        assert_eq!(session.ensure_vault(), VaultStatus::Ready);
        assert_eq!(
            session.looks(),
            2,
            "a request that signs or asks always looks"
        );
        let r = session.with_engine(NEVER, |e| e.get_assertion(&probe, None, None));
        assert!(r.is_ok());

        assert_eq!(
            session.ensure_vault_recent(Duration::ZERO),
            VaultStatus::Ready
        );
        assert_eq!(session.looks(), 3, "an old look is not reused");
    }

    #[test]
    fn a_missing_vault_is_not_looked_for_again_within_the_window() {
        let f = Folders::new();
        let mut session = Session::new(f.settings(), Allow);
        for _ in 0..20 {
            assert_eq!(
                session.ensure_vault_recent(READ_ONLY_MAX_AGE),
                VaultStatus::Missing
            );
        }
        assert_eq!(session.looks(), 1);
        Vault::create(&f.path("vault"), &f.path("state"), "laptop").unwrap();
        assert_eq!(session.ensure_vault(), VaultStatus::Ready);
    }

    struct Refuses(ApprovalError);

    impl Approver for Refuses {
        fn approve(&self, _: &ApprovalContext<'_>) -> Result<Approval, ApprovalError> {
            Err(self.0.clone())
        }
    }

    #[test]
    fn a_refusal_before_any_window_does_not_count_as_asking_the_user() {
        let f = Folders::new();
        let (mut other, _) = Vault::create(&f.path("vault"), &f.path("state"), "laptop").unwrap();
        let id = create(&mut other, "alice");
        for (error, asked) in [
            (ApprovalError::NothingShown, false),
            (ApprovalError::Denied, true),
            (ApprovalError::Timeout, true),
            (ApprovalError::Unavailable, true),
        ] {
            let mut session = Session::new(f.settings(), Refuses(error.clone()));
            assert_eq!(session.ensure_vault(), VaultStatus::Ready);
            let (r, was_asked) = session
                .with_engine_observed(NEVER, None, |e| e.get_assertion(&get(&id), None, None));
            assert!(r.is_err(), "{error:?}");
            assert_eq!(was_asked, asked, "{error:?}");
        }
    }

    #[test]
    fn the_last_word_before_a_registration_is_final_reaches_the_engine() {
        let f = Folders::new();
        Vault::create(&f.path("vault"), &f.path("state"), "laptop").unwrap();
        let mut session = Session::new(f.settings(), Allow);
        assert_eq!(session.ensure_vault(), VaultStatus::Ready);
        let refuse: &dyn Fn() -> bool = &|| false;
        let (r, _) = session.with_engine_observed(NEVER, Some(refuse), |e| {
            e.make_credential(&make("alice"), None)
        });
        assert_eq!(r.unwrap_err(), CoreError::Approval(ApprovalError::Denied));
        assert!(session.vault.as_ref().unwrap().list_all().is_empty());
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
mod first_run_tests {
    use super::*;
    use std::cell::Cell;

    #[derive(Debug, Default)]
    struct Counting {
        launches: Cell<u32>,
        notices: std::cell::RefCell<Vec<String>>,
        cannot_draw: bool,
    }

    impl SetupLauncher for &Counting {
        fn can_draw(&self) -> bool {
            !self.cannot_draw
        }
        fn launch(&self, _: &Path, _: &Path) -> std::io::Result<()> {
            self.launches.set(self.launches.get() + 1);
            Ok(())
        }
        fn notify(&self, text: &str) {
            self.notices.borrow_mut().push(text.to_owned());
        }
    }

    #[test]
    fn the_setup_runs_in_a_user_unit_of_its_own_when_systemd_is_there() {
        let d = Dir::new();
        let runtime = d.0.join("run");
        let program = Path::new("/usr/bin/hirz");
        let run = Path::new("/usr/bin/systemd-run");
        let env = |k: &str| match k {
            VAULT_ENV => Some(OsString::from("/srv/sync/hirz")),
            "DISPLAY" => Some(OsString::from(":0")),
            "WAYLAND_DISPLAY" => Some(OsString::new()),
            "PATH" => Some(OsString::from("/tmp/evil")),
            _ => None,
        };

        let (exe, args) = setup_command(program, &runtime, Some(run), env);
        assert_eq!(exe, program, "no user manager: started directly");
        assert_eq!(args, ["init", "--gui"]);

        std::fs::create_dir_all(runtime.join("systemd")).unwrap();
        std::fs::write(runtime.join("systemd").join("private"), b"").unwrap();
        let (exe, args) = setup_command(program, &runtime, None, env);
        assert_eq!(exe, program, "no systemd-run: started directly");
        assert_eq!(args, ["init", "--gui"]);

        let (exe, args) = setup_command(program, &runtime, Some(run), env);
        assert_eq!(exe, run);
        let args: Vec<String> = args.into_iter().map(|a| a.into_string().unwrap()).collect();
        assert_eq!(
            args,
            [
                "--user",
                "--quiet",
                "--collect",
                "--no-block",
                "--unit=hirz-setup.service",
                "--description=hirz setup",
                "--setenv=HIRZ_VAULT=/srv/sync/hirz",
                "--setenv=DISPLAY=:0",
                "--",
                "/usr/bin/hirz",
                "init",
                "--gui",
            ]
        );
        assert!(args.iter().any(|a| a == &format!("--unit={SETUP_UNIT}")));
    }

    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Dir {
            let mut r = [0u8; 8];
            hirz_crypto::random_fill(&mut r).unwrap();
            let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
            let p = std::env::temp_dir().join(format!("hirz-first-run-test-{hex}"));
            std::fs::create_dir_all(&p).unwrap();
            Dir(p)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const NOW: u64 = 1_700_000_000;

    fn first_run<'a>(d: &Dir, l: &'a Counting) -> FirstRun<&'a Counting> {
        FirstRun::new(
            Some(d.0.join("run")),
            Some(d.0.join("state")),
            true,
            Some(PathBuf::from("/usr/bin/hirz")),
            l,
        )
    }

    #[test]
    fn a_burst_of_requests_starts_one_window() {
        let d = Dir::new();
        let l = Counting::default();
        let mut f = first_run(&d, &l);
        let t0 = Instant::now();
        assert_eq!(f.offer_at(t0, NOW), SetupOffer::Opened);
        for i in 1..1000 {
            let at = t0 + Duration::from_millis(i * 25);
            assert_eq!(f.offer_at(at, NOW), SetupOffer::NotOffered);
        }
        assert_eq!(l.launches.get(), 1);
        assert_eq!(f.offer_at(t0 + SETUP_RETRY, NOW), SetupOffer::Opened);
        assert_eq!(l.launches.get(), 2);
    }

    #[test]
    fn nothing_starts_while_a_setup_window_is_open() {
        let d = Dir::new();
        let l = Counting::default();
        let runtime = d.0.join("run");
        let held = hirz_uv::first_run::try_lock(&runtime).unwrap().unwrap();
        let mut f = first_run(&d, &l);
        let t0 = Instant::now();
        assert_eq!(f.offer_at(t0, NOW), SetupOffer::AlreadyOpen);
        assert_eq!(
            first_run(&d, &l).offer_at(t0, NOW),
            SetupOffer::AlreadyOpen,
            "another process sees the same lock"
        );
        drop(held);
        assert_eq!(f.offer_at(t0, NOW), SetupOffer::Opened);
        assert_eq!(l.launches.get(), 1);
    }

    #[test]
    fn a_cancelled_setup_keeps_quiet_for_a_minute_with_one_notice() {
        let d = Dir::new();
        let l = Counting::default();
        let runtime = d.0.join("run");
        hirz_uv::first_run::mark_cancelled(&runtime, NOW).unwrap();
        let t0 = Instant::now();
        let mut f = first_run(&d, &l);
        let mut other = first_run(&d, &l);
        assert_eq!(f.offer_at(t0, NOW + 1), SetupOffer::QuietNotice);
        assert_eq!(f.offer_at(t0, NOW + 2), SetupOffer::NotOffered);
        assert_eq!(
            other.offer_at(t0, NOW + 3),
            SetupOffer::NotOffered,
            "one notice per quiet period, whichever process asks"
        );
        assert_eq!(f.offer_at(t0, NOW + 59), SetupOffer::NotOffered);
        assert_eq!(l.launches.get(), 0);
        assert_eq!(l.notices.borrow().as_slice(), [QUIET_NOTICE]);
        assert_eq!(f.offer_at(t0, NOW + 60), SetupOffer::Opened);

        hirz_uv::first_run::mark_cancelled(&runtime, NOW + 100).unwrap();
        assert_eq!(other.offer_at(t0, NOW + 101), SetupOffer::QuietNotice);
        assert_eq!(l.notices.borrow().len(), 2, "a new cancel, a new notice");
    }

    #[test]
    fn only_a_visible_graphical_session_without_hirz_gets_a_window() {
        let d = Dir::new();
        let l = Counting::default();
        let t0 = Instant::now();
        let runtime = Some(d.0.join("run"));
        let state = Some(d.0.join("state"));
        let program = Some(PathBuf::from("/usr/bin/hirz"));
        let cases: [FirstRun<&Counting>; 4] = [
            FirstRun::new(runtime.clone(), state.clone(), false, program.clone(), &l),
            FirstRun::new(None, state.clone(), true, program.clone(), &l),
            FirstRun::new(runtime.clone(), state.clone(), true, None, &l),
            FirstRun::new(runtime.clone(), None, true, program.clone(), &l),
        ];
        for mut f in cases {
            assert_eq!(f.offer_at(t0, NOW), SetupOffer::NotOffered);
        }
        let no_zenity = Counting {
            cannot_draw: true,
            ..Counting::default()
        };
        let mut f = FirstRun::new(
            runtime.clone(),
            state.clone(),
            true,
            program.clone(),
            &no_zenity,
        );
        assert_eq!(f.offer_at(t0, NOW), SetupOffer::NotOffered);

        Vault::create(&d.0.join("elsewhere"), &d.0.join("state"), "laptop").unwrap();
        let mut f = first_run(&d, &l);
        assert_eq!(
            f.offer_at(t0, NOW),
            SetupOffer::NotOffered,
            "set up, waiting for the sync tool"
        );
        assert_eq!(l.launches.get(), 0);
        assert_eq!(
            FirstRun::disabled().offer_at(t0, NOW),
            SetupOffer::NotOffered
        );
    }

    const FAST: Hold = Hold {
        limit: Duration::from_secs(5),
        poll: Duration::from_millis(10),
    };

    fn session(d: &Dir) -> Session<Allow> {
        Session::new(
            Settings::from_vars(|k| match k {
                VAULT_ENV => Some(d.0.join("vault").into_os_string()),
                STATE_ENV => Some(d.0.join("state").into_os_string()),
                _ => None,
            }),
            Allow,
        )
    }

    struct Allow;

    impl Approver for Allow {
        fn approve(&self, _: &ApprovalContext<'_>) -> Result<Approval, ApprovalError> {
            Ok(Approval {
                user_present: true,
                user_verified: false,
                selected: None,
            })
        }
    }

    #[test]
    fn a_held_request_gets_the_vault_once_the_window_closes() {
        let d = Dir::new();
        let l = Counting::default();
        let runtime = d.0.join("run");
        let lock = hirz_uv::first_run::try_lock(&runtime).unwrap().unwrap();
        let mut f = first_run(&d, &l);
        assert_eq!(f.offer(), SetupOffer::AlreadyOpen);
        let mut s = session(&d);
        let vault = d.0.join("vault");
        let state = d.0.join("state");
        let window = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            Vault::create(&vault, &state, "laptop").unwrap();
            std::thread::sleep(Duration::from_millis(200));
            drop(lock);
        });
        let started = Instant::now();
        assert_eq!(
            f.wait_for_setup(&mut s, &|| false, FAST),
            VaultStatus::Ready
        );
        assert!(
            started.elapsed() >= Duration::from_millis(300),
            "not before the window closed"
        );
        window.join().unwrap();
        assert!(!hirz_uv::first_run::take_waiter_gone(&runtime));
    }

    #[test]
    fn a_held_request_ends_on_cancel_on_time_or_when_setup_ends_empty() {
        let d = Dir::new();
        let l = Counting::default();
        let runtime = d.0.join("run");
        let lock = hirz_uv::first_run::try_lock(&runtime).unwrap().unwrap();
        let mut f = first_run(&d, &l);
        let mut s = session(&d);
        assert_eq!(
            f.wait_for_setup(&mut s, &|| true, FAST),
            VaultStatus::Missing
        );
        assert!(hirz_uv::first_run::take_waiter_gone(&runtime), "cancelled");
        let short = Hold {
            limit: Duration::from_millis(100),
            ..FAST
        };
        let started = Instant::now();
        assert_eq!(
            f.wait_for_setup(&mut s, &|| false, short),
            VaultStatus::Missing
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(hirz_uv::first_run::take_waiter_gone(&runtime), "timed out");
        drop(lock);
        assert_eq!(
            f.wait_for_setup(&mut s, &|| false, FAST),
            VaultStatus::Missing
        );
        assert!(
            !hirz_uv::first_run::take_waiter_gone(&runtime),
            "the window closed without a vault: nothing to announce"
        );
    }

    #[test]
    fn no_passkey_notices_are_rate_limited_per_site() {
        let d = Dir::new();
        let l = Counting::default();
        let a = first_run(&d, &l);
        let b = first_run(&d, &l);
        assert!(a.no_passkey_notice_at("example.com", NOW));
        assert!(
            !b.no_passkey_notice_at("example.com", NOW + 30),
            "other process"
        );
        assert!(a.no_passkey_notice_at("acme.example", NOW + 30));
        assert!(b.no_passkey_notice_at("example.com", NOW + 60));
        assert_eq!(
            l.notices.borrow().as_slice(),
            [
                "hirz has no passkey for example.com.",
                "hirz has no passkey for acme.example.",
                "hirz has no passkey for example.com."
            ]
        );
        let hidden = FirstRun::new(None, None, false, None, &l);
        assert!(!hidden.no_passkey_notice_at("example.org", NOW));
    }

    #[test]
    fn the_program_is_never_looked_up_in_path() {
        let d = Dir::new();
        let bin = d.0.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let me = bin.join("hirzd");
        std::fs::write(&me, b"").unwrap();
        let next = bin.join("hirz");
        std::fs::write(&next, b"#!/bin/sh\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&next, std::fs::Permissions::from_mode(0o600)).unwrap();
        let fallback = Path::new("/usr/bin/hirz")
            .is_file()
            .then(|| PathBuf::from("/usr/bin/hirz"));
        assert_eq!(setup_program(Some(&me)), fallback, "not executable");
        std::fs::set_permissions(&next, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(setup_program(Some(&me)), Some(next));
        assert_eq!(setup_program(None), fallback);
    }
}
