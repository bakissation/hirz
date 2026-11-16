//! Where the vault lives, and one opened vault with its approver. Shared by hirzd and
//! hirz-nmh (included there with `#[path]`), so both frontends find the same vault.
//!
//! Locations:
//! - state: `$HIRZ_STATE`, else `$XDG_STATE_HOME/hirz`, else `~/.local/state/hirz`;
//! - vault: `$HIRZ_VAULT`, else the folder recorded by `hirz init` in `<state>/vault-path`,
//!   else `$XDG_DATA_HOME/hirz/vault`, else `~/.local/share/hirz/vault`.
//!
//! The variables are read once at start; the recorded folder is read again whenever no
//! vault is open, so a vault set up while the frontend runs is found without a restart.

use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use hirz_core::{Approval, ApprovalContext, ApprovalError, Approver, CoreError, Engine};
use hirz_vault::{Vault, VaultError};

pub const VAULT_ENV: &str = "HIRZ_VAULT";
pub const STATE_ENV: &str = "HIRZ_STATE";
const VAULT_POINTER: &str = "vault-path";
const MAX_POINTER_LEN: u64 = 4096;
const VARS: [&str; 6] = [
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    VAULT_ENV,
    STATE_ENV,
];

/// The environment variables that decide the locations, captured once.
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

    /// Relative and empty values are ignored, as the XDG base directory spec requires.
    fn abs(&self, key: &str) -> Option<PathBuf> {
        self.vars
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| PathBuf::from(v))
            .filter(|p| p.is_absolute())
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
            None => match read_pointer(&state_dir.join(VAULT_POINTER))? {
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

    /// hirz-uv paths (config file, PIN state) with the same state directory as the vault.
    pub fn uv_paths(&self) -> Result<hirz_uv::Paths, &'static str> {
        let mut paths = hirz_uv::Paths::from_vars(|k| {
            self.vars
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.clone())
        })?;
        paths.state_dir = self.state_dir()?;
        Ok(paths)
    }
}

/// The folder `hirz init --vault` recorded, if any. Same rules as the CLI: at most 4096
/// bytes, absolute, no NUL byte.
fn read_pointer(path: &Path) -> Result<Option<PathBuf>, String> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let mut buf = Vec::new();
    file.take(MAX_POINTER_LEN.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let p = PathBuf::from(OsStr::from_bytes(&buf));
    let too_long = u64::try_from(buf.len()).map_or(true, |n| n > MAX_POINTER_LEN);
    if too_long || buf.is_empty() || buf.contains(&0) || !p.is_absolute() {
        return Err(format!("{} does not hold a valid folder", path.display()));
    }
    Ok(Some(p))
}

/// What opening the vault found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultStatus {
    Ready,
    /// No vault, or no device state for it: `hirz init` (or `hirz join`) has not run.
    Missing,
    /// A vault exists but cannot be opened; the text says why.
    Broken(String),
}

/// An opened vault (kept between requests, reloaded by the engine for every ceremony) and
/// the approver.
pub struct Session<A> {
    settings: Settings,
    vault: Option<Vault>,
    approver: A,
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
        }
    }

    #[allow(dead_code)] // used by hirz-nmh only
    pub fn approver(&self) -> &A {
        &self.approver
    }

    /// Opens the vault unless it is already open.
    pub fn ensure_vault(&mut self) -> VaultStatus {
        if self.vault.is_some() {
            return VaultStatus::Ready;
        }
        let loc = match self.settings.location() {
            Ok(l) => l,
            Err(e) => return VaultStatus::Broken(e),
        };
        match Vault::open(&loc.vault_dir, &loc.state_dir) {
            Ok(v) => {
                self.vault = Some(v);
                VaultStatus::Ready
            }
            Err(VaultError::NotFound) => VaultStatus::Missing,
            Err(e) => VaultStatus::Broken(format!("{}: {e}", loc.vault_dir.display())),
        }
    }

    /// Runs `f` on an engine over the open vault. Call [`Session::ensure_vault`] first.
    /// Once `cancelled` returns true, approvals count as refused, so a request cancelled
    /// while its prompt was open creates and signs nothing. A vault error closes the vault,
    /// so the next request opens it again from disk.
    pub fn with_engine<T>(
        &mut self,
        cancelled: &dyn Fn() -> bool,
        f: impl FnOnce(&mut Engine<'_>) -> Result<T, CoreError>,
    ) -> Result<T, CoreError> {
        let Some(vault) = self.vault.as_mut() else {
            return Err(CoreError::Vault("no vault is open".into()));
        };
        let guard = CancelGuard {
            inner: &self.approver,
            cancelled,
        };
        let mut engine = Engine::new(vault, &guard);
        let result = f(&mut engine);
        if matches!(result, Err(CoreError::Vault(_))) {
            self.vault = None;
        }
        result
    }
}

/// Refuses approvals for requests cancelled before or while the prompt was shown.
struct CancelGuard<'a, A> {
    inner: &'a A,
    cancelled: &'a dyn Fn() -> bool,
}

impl<A: Approver> CancelGuard<'_, A> {
    fn checked(
        &self,
        ask: impl FnOnce() -> Result<Approval, ApprovalError>,
    ) -> Result<Approval, ApprovalError> {
        if (self.cancelled)() {
            return Err(ApprovalError::Denied);
        }
        let approval = ask()?;
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

        std::fs::write(dir.join(VAULT_POINTER), b"/srv/sync/hirz").unwrap();
        assert_eq!(s.location().unwrap().vault_dir, Path::new("/srv/sync/hirz"));
        std::fs::write(dir.join(VAULT_POINTER), b"relative/path").unwrap();
        assert!(s.location().is_err());
        std::fs::write(dir.join(VAULT_POINTER), b"").unwrap();
        assert!(s.location().is_err());
        std::fs::write(dir.join(VAULT_POINTER), vec![b'/'; 5000]).unwrap();
        assert!(s.location().is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
