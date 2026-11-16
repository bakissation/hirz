//! Where hirz keeps things, and probes of the system around it.

use crate::error::{CliError, CliResult};
use hirz_uv::{Paths, UvMethod};
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Name of the file in the state directory that records where this device's vault is.
pub const VAULT_POINTER: &str = "vault-path";
/// Name of the vault header file (`docs/vault-format.md`, section 3).
pub const VAULT_HEADER: &str = "hirz-vault";
/// Name of the device state file (`docs/vault-format.md`, section 7).
pub const STATE_DEVICE: &str = "device";
pub const DEFAULT_BROKER_SOCKET: &str = "/run/hirz/uhid.sock";
const MAX_POINTER_LEN: u64 = 4096;

#[derive(Debug, Clone)]
pub struct Env {
    pub home: Option<PathBuf>,
    /// `$XDG_DATA_HOME`, or `~/.local/share`.
    pub data_home: PathBuf,
    /// `$XDG_CONFIG_HOME`, or `~/.config`.
    pub config_home: PathBuf,
    /// hirz-uv paths: config file and `$XDG_STATE_HOME/hirz`.
    pub uv: Paths,
    /// Prefix for system paths that are probed (`/` outside tests).
    pub root: PathBuf,
    pub broker_socket: PathBuf,
    /// Directory of the running `hirz` binary.
    pub exe_dir: Option<PathBuf>,
    pub cwd: Option<PathBuf>,
}

impl Env {
    pub fn from_process() -> CliResult<Env> {
        let mut env = Env::from_vars(|k| std::env::var_os(k))?;
        env.exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf));
        env.cwd = std::env::current_dir().ok();
        Ok(env)
    }

    pub fn from_vars(get: impl Fn(&str) -> Option<OsString>) -> CliResult<Env> {
        let abs = |k: &str| get(k).map(PathBuf::from).filter(|p| p.is_absolute());
        let uv = Paths::from_vars(&get).map_err(|_| {
            CliError::failed("HOME is not set, so hirz cannot tell where to keep its files.")
        })?;
        let home = abs("HOME");
        let data_home = abs("XDG_DATA_HOME")
            .or_else(|| home.as_ref().map(|h| h.join(".local").join("share")))
            .ok_or_else(|| CliError::failed("HOME is not set."))?;
        let config_home = abs("XDG_CONFIG_HOME")
            .or_else(|| home.as_ref().map(|h| h.join(".config")))
            .ok_or_else(|| CliError::failed("HOME is not set."))?;
        let broker_socket =
            abs("HIRZ_BROKER_SOCKET").unwrap_or_else(|| PathBuf::from(DEFAULT_BROKER_SOCKET));
        Ok(Env {
            home,
            data_home,
            config_home,
            uv,
            root: PathBuf::from("/"),
            broker_socket,
            exe_dir: None,
            cwd: None,
        })
    }

    pub fn state_dir(&self) -> &Path {
        &self.uv.state_dir
    }

    pub fn default_vault(&self) -> PathBuf {
        self.data_home.join("hirz").join("vault")
    }

    /// A system path under the probe root.
    pub fn sys_path(&self, abs: &str) -> PathBuf {
        self.root.join(abs.trim_start_matches('/'))
    }

    pub fn absolute(&self, p: &Path) -> CliResult<PathBuf> {
        if p.is_absolute() {
            return Ok(p.to_path_buf());
        }
        self.cwd
            .as_ref()
            .map(|c| c.join(p))
            .ok_or_else(|| CliError::failed("Could not find the current folder; give a full path."))
    }

    /// Vault location: `--vault`, else the recorded location, else the default.
    pub fn vault_dir(&self, flag: Option<&Path>) -> CliResult<PathBuf> {
        if let Some(p) = flag {
            return self.absolute(p);
        }
        if let Some(p) = read_pointer(&self.state_dir().join(VAULT_POINTER))? {
            return Ok(p);
        }
        Ok(self.default_vault())
    }

    pub fn device_state_exists(&self) -> bool {
        self.state_dir().join(STATE_DEVICE).exists()
    }

    pub fn record_vault_dir(&self, vault: &Path) -> CliResult<()> {
        write_private(
            self.state_dir(),
            VAULT_POINTER,
            vault.as_os_str().as_bytes(),
        )
        .map_err(|e| CliError::io("Could not record the vault location", &e))
    }
}

fn read_pointer(path: &Path) -> CliResult<Option<PathBuf>> {
    let f = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(CliError::io(
                "Could not read the recorded vault location",
                &e,
            ));
        }
    };
    let mut buf = Vec::new();
    f.take(MAX_POINTER_LEN.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| CliError::io("Could not read the recorded vault location", &e))?;
    let p = PathBuf::from(std::ffi::OsStr::from_bytes(&buf));
    if u64::try_from(buf.len()).unwrap_or(u64::MAX) > MAX_POINTER_LEN
        || buf.is_empty()
        || buf.contains(&0)
        || !p.is_absolute()
    {
        return Err(CliError::failed(format!(
            "The recorded vault location in {} is not valid. Give the folder with --vault.",
            path.display()
        )));
    }
    Ok(Some(p))
}

/// Writes `dir/name` with mode 0600 through a temp file and a rename, in a 0700 directory.
pub fn write_private(dir: &Path, name: &str, data: &[u8]) -> std::io::Result<()> {
    hirz_uv::pin::ensure_private_dir(dir)?;
    write_atomic(dir, name, data, 0o600)
}

/// Writes `dir/name` through a temp file and a rename. The directory must exist.
pub fn write_atomic(dir: &Path, name: &str, data: &[u8], mode: u32) -> std::io::Result<()> {
    let mut rnd = [0u8; 8];
    hirz_crypto::random_fill(&mut rnd).map_err(|_| std::io::Error::other("random"))?;
    let tmp = dir.join(format!(".{name}.tmp-{}", crate::ui::hex(&rnd)));
    let result = (|| {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&tmp, dir.join(name))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Creates a new file that must not exist yet, mode 0600.
pub fn create_new_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    let r = f.write_all(data).and_then(|()| f.sync_all());
    if r.is_err() {
        drop(f);
        let _ = fs::remove_file(path);
    }
    r
}

pub fn is_executable_file(p: &Path) -> bool {
    fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// The parts of the system that tests replace.
pub trait System {
    /// Approval methods hirz-uv can use right now, or why that could not be determined.
    fn uv_methods(&self, env: &Env) -> Result<Vec<UvMethod>, String>;
    /// Whether `zenity` (needed for every approval prompt) is installed.
    fn zenity(&self) -> bool;
    /// This computer's name, for the device name.
    fn hostname(&self) -> Option<String>;
}

#[derive(Debug, Default)]
pub struct RealSystem;

impl System for RealSystem {
    fn uv_methods(&self, env: &Env) -> Result<Vec<UvMethod>, String> {
        hirz_uv::config::load_config(&env.uv.config_file).map_err(|e| e.to_string())?;
        let approver = hirz_uv::HirzApprover::new(hirz_uv::SystemRunner, &env.uv);
        approver
            .available_uv_methods()
            .map_err(|e| format!("{e:?}"))
    }

    fn zenity(&self) -> bool {
        hirz_uv::runner::resolve_tool("zenity").is_some()
    }

    fn hostname(&self) -> Option<String> {
        let mut buf = Vec::new();
        fs::File::open("/proc/sys/kernel/hostname")
            .ok()?
            .take(256)
            .read_to_end(&mut buf)
            .ok()?;
        let s = String::from_utf8(buf).ok()?;
        let s = s.trim();
        (!s.is_empty()).then(|| s.to_string())
    }
}
