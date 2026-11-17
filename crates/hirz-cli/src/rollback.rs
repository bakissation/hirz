//! Taking back a vault that `hirz init --gui` created when its recovery phrase was never
//! confirmed. Only what that run created is removed, and only while it is exactly as the run left
//! it: no symbolic link is ever followed, and anything else in the way stops the rollback.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const MAX_ENTRIES: usize = 4096;
const MAX_DEPTH: usize = 8;
const MAX_POINTER: u64 = 8192;

/// A file or folder below the vault folder: whether it is a folder, its size and when it changed.
type Entry = (bool, u64, Option<SystemTime>);

/// What a folder held before the vault was created.
#[derive(Debug)]
pub struct Before {
    vault_existed: bool,
    state_existed: bool,
    state_names: BTreeSet<OsString>,
    pointer: Option<Vec<u8>>,
}

/// What this run created.
#[derive(Debug)]
pub struct Created {
    vault_dir: PathBuf,
    state_dir: PathBuf,
    vault: Option<BTreeMap<PathBuf, Entry>>,
    state_new: BTreeSet<OsString>,
    before: Before,
}

fn names(dir: &Path) -> io::Result<BTreeSet<OsString>> {
    match fs::read_dir(dir) {
        Ok(rd) => rd.map(|e| e.map(|e| e.file_name())).collect(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeSet::new()),
        Err(e) => Err(e),
    }
}

fn read_small(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let md = fs::symlink_metadata(path).ok()?;
    if !md.is_file() || md.len() > MAX_POINTER {
        return None;
    }
    let mut out = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(MAX_POINTER)
        .read_to_end(&mut out)
        .ok()?;
    Some(out)
}

/// Every entry below `dir`, without following links. A link, a device or anything that is neither
/// a file nor a folder is an error.
pub fn tree(dir: &Path) -> io::Result<BTreeMap<PathBuf, Entry>> {
    let mut out = BTreeMap::new();
    let mut todo = vec![(PathBuf::new(), 0usize)];
    while let Some((rel, depth)) = todo.pop() {
        if depth > MAX_DEPTH {
            return Err(io::Error::other("too deep"));
        }
        for e in fs::read_dir(dir.join(&rel))? {
            let e = e?;
            let path = rel.join(e.file_name());
            let md = fs::symlink_metadata(dir.join(&path))?;
            if md.is_dir() {
                todo.push((path.clone(), depth.saturating_add(1)));
            } else if !md.is_file() {
                return Err(io::Error::other("not a file or folder"));
            }
            out.insert(path, (md.is_dir(), md.len(), md.modified().ok()));
            if out.len() > MAX_ENTRIES {
                return Err(io::Error::other("too many entries"));
            }
        }
    }
    Ok(out)
}

pub fn before(vault_dir: &Path, state_dir: &Path) -> io::Result<Before> {
    Ok(Before {
        vault_existed: fs::symlink_metadata(vault_dir).is_ok(),
        state_existed: fs::symlink_metadata(state_dir).is_ok(),
        state_names: names(state_dir)?,
        pointer: read_small(&state_dir.join(hirz_vault::VAULT_POINTER_FILE)),
    })
}

/// Right after the vault was created. A vault folder that cannot be listed, or that holds a link,
/// is never removed.
pub fn created(vault_dir: &Path, state_dir: &Path, before: Before) -> io::Result<Created> {
    let state_new = names(state_dir)?
        .difference(&before.state_names)
        .cloned()
        .collect();
    let vault = if fs::symlink_metadata(vault_dir).is_ok_and(|m| m.is_dir()) {
        tree(vault_dir).ok()
    } else {
        None
    };
    Ok(Created {
        vault_dir: vault_dir.to_path_buf(),
        state_dir: state_dir.to_path_buf(),
        vault,
        state_new,
        before,
    })
}

fn remove_tree(root: &Path, entries: &BTreeMap<PathBuf, Entry>) -> io::Result<()> {
    let mut order: Vec<(&PathBuf, &Entry)> = entries.iter().collect();
    order.sort_by_key(|(p, _)| std::cmp::Reverse(p.components().count()));
    for (rel, (is_dir, _, _)) in order {
        let path = root.join(rel);
        let md = fs::symlink_metadata(&path)?;
        match (*is_dir, md.is_dir(), md.is_file()) {
            (true, true, _) => fs::remove_dir(&path)?,
            (false, _, true) => fs::remove_file(&path)?,
            _ => return Err(io::Error::other("an entry changed")),
        }
    }
    Ok(())
}

impl Created {
    /// Removes the vault folder and the device state this run created. `Err` says why nothing
    /// (or not everything) was removed.
    pub fn roll_back(&self) -> Result<(), String> {
        if self.before.vault_existed {
            return Err(format!(
                "{} existed before, so hirz leaves it",
                self.vault_dir.display()
            ));
        }
        let Some(made) = &self.vault else {
            return Err("the new vault folder could not be listed".into());
        };
        let md = fs::symlink_metadata(&self.vault_dir).map_err(|e| e.to_string())?;
        if !md.is_dir() {
            return Err("the vault folder is not a folder any more".into());
        }
        let now = tree(&self.vault_dir).map_err(|e| format!("the vault folder: {e}"))?;
        if &now != made {
            return Err("the vault folder changed since it was created".into());
        }
        let mut state = BTreeMap::new();
        for name in &self.state_new {
            let path = PathBuf::from(name);
            let md = fs::symlink_metadata(self.state_dir.join(&path)).map_err(|e| e.to_string())?;
            if md.is_dir() {
                for (rel, entry) in tree(&self.state_dir.join(&path))
                    .map_err(|e| format!("the device state: {e}"))?
                {
                    state.insert(path.join(rel), entry);
                }
            } else if !md.is_file() {
                return Err("the device state holds something that is not a file".into());
            }
            state.insert(path, (md.is_dir(), md.len(), md.modified().ok()));
        }
        remove_tree(&self.vault_dir, made).map_err(|e| e.to_string())?;
        fs::remove_dir(&self.vault_dir).map_err(|e| e.to_string())?;
        remove_tree(&self.state_dir, &state).map_err(|e| e.to_string())?;
        let pointer = self.state_dir.join(hirz_vault::VAULT_POINTER_FILE);
        match &self.before.pointer {
            Some(old) => {
                crate::env::write_private(&self.state_dir, hirz_vault::VAULT_POINTER_FILE, old)
                    .map_err(|e| e.to_string())?;
            }
            None => {
                use std::os::unix::ffi::OsStrExt;
                if read_small(&pointer).as_deref() == Some(self.vault_dir.as_os_str().as_bytes()) {
                    fs::remove_file(&pointer).map_err(|e| e.to_string())?;
                }
            }
        }
        if !self.before.state_existed {
            let _ = fs::remove_dir(&self.state_dir);
        }
        Ok(())
    }
}
