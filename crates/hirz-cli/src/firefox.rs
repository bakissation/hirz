//! Whether Firefox is here and has the hirz extension, read from the profiles' `extensions.json`
//! through `profiles.ini`. Every read is bounded; anything unreadable counts as "not installed", so
//! the extension's page is offered.

use crate::env::Env;
use hirz_proto::json::{self, Json, Limits};
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_PROFILES_INI: u64 = 64 * 1024;
const MAX_EXTENSIONS_JSON: usize = 16 * 1024 * 1024;
const MAX_PROFILES: usize = 32;
const JSON_LIMITS: Limits = Limits {
    max_len: MAX_EXTENSIONS_JSON,
    max_depth: 64,
    max_items: 4_000_000,
};
/// Where Firefox builds keep their programs; only their presence is checked.
const PROGRAMS: &[&str] = &[
    "/usr/bin/firefox",
    "/usr/bin/firefox-esr",
    "/usr/lib/firefox/firefox",
    "/usr/lib64/firefox/firefox",
    "/usr/lib/firefox-esr/firefox-esr",
    "/opt/firefox/firefox",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddonState {
    NoFirefox,
    Installed,
    /// Not in any profile Firefox lists, or that could not be told.
    Missing,
}

/// Folders that hold `profiles.ini`: deb and rpm builds (the old and the XDG location), Snap and
/// Flatpak.
pub fn profile_roots(env: &Env) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(home) = &env.home {
        v.push(home.join(".mozilla/firefox"));
    }
    v.push(env.config_home.join("mozilla/firefox"));
    if let Some(home) = &env.home {
        v.push(home.join("snap/firefox/common/.mozilla/firefox"));
        v.push(home.join(".var/app/org.mozilla.firefox/.mozilla/firefox"));
    }
    v
}

pub fn addon_state(env: &Env) -> AddonState {
    let mut profiles = Vec::new();
    let mut found_ini = false;
    for root in profile_roots(env) {
        let Some(ini) = read_capped(&root.join("profiles.ini"), MAX_PROFILES_INI) else {
            continue;
        };
        found_ini = true;
        for p in profile_dirs(&root, &String::from_utf8_lossy(&ini)) {
            if profiles.len() < MAX_PROFILES && !profiles.contains(&p) {
                profiles.push(p);
            }
        }
    }
    let program = PROGRAMS.iter().any(|p| env.sys_path(p).is_file())
        || crate::cmd_setup::snap_firefox(env)
        || crate::cmd_setup::flatpak_firefox(env);
    if !found_ini && !program {
        return AddonState::NoFirefox;
    }
    let installed = profiles.iter().any(|dir| {
        read_capped(&dir.join("extensions.json"), MAX_EXTENSIONS_JSON as u64)
            .is_some_and(|bytes| lists_addon(&bytes, hirz_uv::first_run::ADDON_ID))
    });
    if installed {
        AddonState::Installed
    } else {
        AddonState::Missing
    }
}

/// The profile folders a `profiles.ini` names in its `[Profile...]` sections. `IsRelative=1`, the
/// default, puts the path below `root`.
pub fn profile_dirs(root: &Path, ini: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut in_profile = false;
    let mut path: Option<&str> = None;
    let mut relative = true;
    let mut flush = |path: &mut Option<&str>, relative: &mut bool| {
        if let Some(p) = path.take().filter(|p| !p.is_empty()) {
            out.push(if *relative {
                root.join(p)
            } else {
                PathBuf::from(p)
            });
        }
        *relative = true;
    };
    for line in ini.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            if in_profile {
                flush(&mut path, &mut relative);
            }
            path = None;
            relative = true;
            in_profile = line.starts_with("[Profile");
            continue;
        }
        if !in_profile {
            continue;
        }
        match line.split_once('=') {
            Some(("Path", v)) => path = Some(v.trim()),
            Some(("IsRelative", v)) => relative = v.trim() != "0",
            _ => {}
        }
    }
    if in_profile {
        flush(&mut path, &mut relative);
    }
    out.retain(|p| p.is_absolute());
    out
}

/// `extensions.json` lists an add-on with this id.
pub fn lists_addon(bytes: &[u8], id: &str) -> bool {
    let Ok(doc) = json::parse(bytes, &JSON_LIMITS) else {
        return false;
    };
    doc.get("addons")
        .and_then(Json::as_array)
        .is_some_and(|addons| {
            addons
                .iter()
                .any(|a| a.get("id").and_then(Json::as_str) == Some(id))
        })
}

fn read_capped(path: &Path, cap: u64) -> Option<Vec<u8>> {
    let f = std::fs::File::open(path).ok()?;
    if !f.metadata().ok()?.is_file() {
        return None;
    }
    let mut out = Vec::new();
    f.take(cap.saturating_add(1)).read_to_end(&mut out).ok()?;
    (u64::try_from(out.len()).ok()? <= cap).then_some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn profiles_ini_sections() {
        let ini = "[Install4F96D1932A9F858E]\nDefault=elsewhere\nLocked=1\n\n\
                   [Profile1]\nName=work\nIsRelative=0\nPath=/data/ff/work\n\n\
                   [Profile0]\nName=default\nIsRelative=1\nPath=abc.default-release\nDefault=1\n\n\
                   [Profile2]\nName=bare\nPath=bare.profile\n\n\
                   [General]\nStartWithLastProfile=1\nVersion=2\n";
        let dirs = profile_dirs(Path::new("/h/.mozilla/firefox"), ini);
        assert_eq!(
            dirs,
            vec![
                PathBuf::from("/data/ff/work"),
                PathBuf::from("/h/.mozilla/firefox/abc.default-release"),
                PathBuf::from("/h/.mozilla/firefox/bare.profile"),
            ]
        );
        assert!(profile_dirs(Path::new("/r"), "[Profile0]\nIsRelative=0\nPath=rel\n").is_empty());
        assert!(profile_dirs(Path::new("/r"), "garbage\n=\n[Profile0\n").is_empty());
    }

    #[test]
    fn extensions_json() {
        let id = hirz_uv::first_run::ADDON_ID;
        let with = format!(
            r#"{{"schemaVersion":36,"addons":[{{"id":"other@example.com","version":"1.0","installDate":1700000000000,"active":true}},{{"id":"{id}","active":false,"rating":4.5,"name":"hïrz"}}]}}"#
        );
        assert!(lists_addon(with.as_bytes(), id));
        assert!(!lists_addon(
            br#"{"addons":[{"id":"other@example.com"}]}"#,
            id
        ));
        assert!(!lists_addon(br#"{"addons":{}}"#, id));
        assert!(!lists_addon(b"{\"addons\":[", id));
        assert!(!lists_addon(b"", id));
    }
}
