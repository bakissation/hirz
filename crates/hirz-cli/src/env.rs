//! Where hirz keeps things, and probes of the system around it.

use crate::error::{CliError, CliResult};
use hirz_uv::{Paths, UvMethod};
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const DEFAULT_BROKER_SOCKET: &str = "/run/hirz/uhid.sock";

#[derive(Debug, Clone)]
pub struct Env {
    pub home: Option<PathBuf>,
    pub data_home: PathBuf,
    pub config_home: PathBuf,
    pub uv: Paths,
    /// Prefix for system paths that are probed (`/` outside tests).
    pub root: PathBuf,
    pub broker_socket: PathBuf,
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

    pub fn vault_dir(&self, flag: Option<&Path>) -> CliResult<PathBuf> {
        if let Some(p) = flag {
            return self.absolute(p);
        }
        if let Some(p) = read_pointer(&self.state_dir().join(hirz_vault::VAULT_POINTER_FILE))? {
            return Ok(p);
        }
        Ok(self.default_vault())
    }

    pub fn device_state_exists(&self) -> bool {
        hirz_vault::Vault::is_set_up(self.state_dir())
    }

    pub fn record_vault_dir(&self, vault: &Path) -> CliResult<()> {
        write_private(
            self.state_dir(),
            hirz_vault::VAULT_POINTER_FILE,
            vault.as_os_str().as_bytes(),
        )
        .map_err(|e| CliError::io("Could not record the vault location", &e))
    }
}

fn read_pointer(path: &Path) -> CliResult<Option<PathBuf>> {
    hirz_vault::read_vault_pointer(path).map_err(|e| match e {
        hirz_vault::VaultPointerError::Io(e) => {
            CliError::io("Could not read the recorded vault location", &e)
        }
        hirz_vault::VaultPointerError::Invalid => CliError::failed(format!(
            "The recorded vault location in {} is not valid. Give the folder with --vault.",
            path.display()
        )),
    })
}

/// Writes `dir/name` with mode 0600 through a temp file and a rename, in a 0700 directory.
pub fn write_private(dir: &Path, name: &str, data: &[u8]) -> std::io::Result<()> {
    hirz_uv::pin::ensure_private_dir(dir)?;
    write_atomic(dir, name, data, 0o600)
}

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

/// How to write this program in commands printed for the user: `hirz` when it was started
/// by name or a `hirz` is on `PATH`, otherwise the path it was started with (`argv[0]`),
/// quoted for a POSIX shell when needed.
pub fn command_name(
    argv0: Option<&std::ffi::OsStr>,
    path_var: Option<&std::ffi::OsStr>,
    is_executable: &dyn Fn(&Path) -> bool,
) -> String {
    const NAME: &str = "hirz";
    let Some(arg) = argv0.and_then(|a| a.to_str()) else {
        return NAME.to_string();
    };
    if !arg.contains('/') || arg.len() > 4096 || arg.chars().any(char::is_control) {
        return NAME.to_string();
    }
    let on_path = path_var.is_some_and(|p| {
        std::env::split_paths(p).any(|d| d.is_absolute() && is_executable(&d.join(NAME)))
    });
    if on_path {
        return NAME.to_string();
    }
    shell_quote(arg)
}

fn shell_quote(s: &str) -> String {
    let plain = s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"/._-+,:@%=".contains(&b));
    if plain {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

pub fn is_executable_file(p: &Path) -> bool {
    fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

pub trait System {
    fn uv_methods(&self, env: &Env) -> Result<Vec<UvMethod>, String>;
    fn zenity(&self) -> bool;
    fn hostname(&self) -> Option<String>;
    fn pairing_approver<'s>(&'s self, env: &Env) -> Box<dyn hirz_core::Approver + 's>;
    fn now(&self) -> u64 {
        crate::ui::now()
    }
    fn sleep(&self, d: std::time::Duration) {
        std::thread::sleep(d);
    }
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

    fn pairing_approver<'s>(&'s self, env: &Env) -> Box<dyn hirz_core::Approver + 's> {
        Box::new(hirz_uv::HirzApprover::new(hirz_uv::SystemRunner, &env.uv))
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
