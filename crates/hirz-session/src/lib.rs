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
