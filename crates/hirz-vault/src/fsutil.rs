//! File helpers: atomic immutable writes, capped reads, private directories, state lock.

use crate::codec::hex;
use crate::error::{VaultError, io};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Records are a few hundred bytes; backups hold many.
pub(crate) const MAX_FILE_LEN: u64 = 1 << 20;
pub(crate) const MAX_BACKUP_LEN: u64 = 64 << 20;

const LOCK_NAME: &str = "lock";
const LOCK_STALE_AFTER: Duration = Duration::from_secs(60);
const LOCK_ATTEMPTS: u32 = 1000;
const LOCK_SLEEP: Duration = Duration::from_millis(10);

pub(crate) fn private_dir(path: &Path) -> Result<(), VaultError> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true).mode(0o700);
    b.create(path).map_err(io("create directory"))?;
    Ok(())
}

/// Forces mode 0700 even if the directory already existed.
pub(crate) fn state_dir(path: &Path) -> Result<(), VaultError> {
    private_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(io("set state directory permissions"))
}

fn sync_dir(dir: &Path) -> Result<(), VaultError> {
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(io("sync directory"))
}

fn random_suffix() -> Result<String, VaultError> {
    let mut r = [0u8; 8];
    hirz_crypto::random_fill(&mut r)?;
    Ok(hex(&r))
}

/// Temp file in the same directory (a dot-name that readers skip), fsync, rename, fsync the
/// directory. Files are created with mode 0600.
pub(crate) fn write_atomic(dir: &Path, name: &str, data: &[u8]) -> Result<(), VaultError> {
    private_dir(dir)?;
    let tmp = dir.join(format!(".{name}.tmp-{}", random_suffix()?));
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(io("create temp file"))?;
        f.write_all(data).map_err(io("write temp file"))?;
        f.sync_all().map_err(io("sync temp file"))?;
        fs::rename(&tmp, dir.join(name)).map_err(io("rename temp file"))?;
        sync_dir(dir)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Never allocates more than `max + 1`.
pub(crate) fn read_capped(path: &Path, max: u64) -> Result<Vec<u8>, VaultError> {
    let f = File::open(path).map_err(io("open file"))?;
    let meta = f.metadata().map_err(io("stat file"))?;
    if !meta.is_file() {
        return Err(VaultError::Corrupt("not a regular file"));
    }
    if meta.len() > max {
        return Err(VaultError::Corrupt("file too large"));
    }
    let mut out = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    f.take(max.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(io("read file"))?;
    if u64::try_from(out.len()).unwrap_or(u64::MAX) > max {
        return Err(VaultError::Corrupt("file too large"));
    }
    Ok(out)
}

pub(crate) fn remove_file(path: &Path) -> Result<(), VaultError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(VaultError::Io(e.kind(), "remove file")),
    }
}

/// Lists directory entry names that are valid UTF-8; a missing directory is empty.
pub(crate) fn list(dir: &Path) -> Result<Vec<String>, VaultError> {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(VaultError::Io(e.kind(), "list directory")),
    };
    let mut names = Vec::new();
    for entry in rd {
        let entry = entry.map_err(io("list directory"))?;
        if let Ok(name) = entry.file_name().into_string() {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

pub const VAULT_POINTER_FILE: &str = "vault-path";
const MAX_VAULT_POINTER_LEN: u64 = 4096;

#[derive(Debug)]
pub enum VaultPointerError {
    Io(std::io::Error),
    /// Empty, longer than 4096 bytes, relative, or containing a NUL byte.
    Invalid,
}

pub fn read_vault_pointer(path: &Path) -> Result<Option<PathBuf>, VaultPointerError> {
    use std::os::unix::ffi::OsStrExt;
    let f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(VaultPointerError::Io(e)),
    };
    let mut buf = Vec::new();
    f.take(MAX_VAULT_POINTER_LEN.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(VaultPointerError::Io)?;
    let p = PathBuf::from(std::ffi::OsStr::from_bytes(&buf));
    let too_long = u64::try_from(buf.len()).map_or(true, |n| n > MAX_VAULT_POINTER_LEN);
    if too_long || buf.is_empty() || buf.contains(&0) || !p.is_absolute() {
        return Err(VaultPointerError::Invalid);
    }
    Ok(Some(p))
}

/// Cross-process lock on the local state directory. A `create_new` file, because `File::lock`
/// is newer than the MSRV; stale when its owner process is gone or it is older than a minute.
#[derive(Debug)]
pub(crate) struct StateLock {
    path: PathBuf,
}

impl StateLock {
    pub(crate) fn acquire(state: &Path) -> Result<StateLock, VaultError> {
        let path = state.join(LOCK_NAME);
        for _ in 0..LOCK_ATTEMPTS {
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(mut f) => {
                    let _ = writeln!(f, "{}", std::process::id());
                    return Ok(StateLock { path });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if lock_is_stale(&path) {
                        break_stale(&path)?;
                        continue;
                    }
                    std::thread::sleep(LOCK_SLEEP);
                }
                Err(e) => return Err(VaultError::Io(e.kind(), "create lock file")),
            }
        }
        Err(VaultError::LockTimeout)
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Moves the lock aside before deleting it, so a lock a live process re-created meanwhile is put back.
fn break_stale(path: &Path) -> Result<(), VaultError> {
    let aside = path.with_file_name(format!("{LOCK_NAME}.stale-{}", random_suffix()?));
    if fs::rename(path, &aside).is_err() {
        return Ok(());
    }
    if !lock_is_stale(&aside) {
        let _ = fs::hard_link(&aside, path);
    }
    let _ = fs::remove_file(&aside);
    Ok(())
}

fn lock_is_stale(path: &Path) -> bool {
    let age = fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok());
    if age.is_some_and(|a| a > LOCK_STALE_AFTER) {
        return true;
    }
    let owner = fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok());
    match owner {
        Some(pid) => !Path::new("/proc").join(pid.to_string()).exists(),
        // Written but not yet filled by its owner: give it time.
        None => false,
    }
}
