//! `hirz setup firefox`: the per-user native messaging manifest.

use crate::app::Ctx;
use crate::env::{Env, is_executable_file};
use crate::error::{CliError, CliResult, Exit};
use crate::prompt::confirm;
use serde_json::Value;
use std::path::{Path, PathBuf};

const TEMPLATE: &str = include_str!("../../../packaging/native-messaging/hirz.json");
const PLACEHOLDER: &str = "\"@HIRZ_NMH_PATH@\"";
pub const MANIFEST_NAME: &str = "hirz.json";
const NMH_BINARY: &str = "hirz-nmh";
const MAX_MANIFEST_LEN: u64 = 64 * 1024;

/// Where Firefox, the WebExtensions portal and the native messaging proxy look for host
/// manifests (see docs/extension.md). The first entry is the one `setup firefox` writes.
pub fn manifest_locations(env: &Env) -> Vec<(PathBuf, &'static str)> {
    let mut v = Vec::new();
    if let Some(home) = &env.home {
        v.push((
            home.join(".mozilla/native-messaging-hosts")
                .join(MANIFEST_NAME),
            "your user",
        ));
    }
    v.push((
        env.config_home
            .join("mozilla/native-messaging-hosts")
            .join(MANIFEST_NAME),
        "your user (portal and proxy only)",
    ));
    for sys in [
        "/usr/lib/mozilla/native-messaging-hosts",
        "/usr/lib64/mozilla/native-messaging-hosts",
        "/usr/lib/x86_64-linux-gnu/mozilla/native-messaging-hosts",
        "/usr/lib/aarch64-linux-gnu/mozilla/native-messaging-hosts",
    ] {
        v.push((env.sys_path(sys).join(MANIFEST_NAME), "system"));
    }
    v
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestState {
    Missing,
    /// Present and points to an executable program.
    Ok(PathBuf),
    /// Present but its `path` is missing, relative or not executable.
    BrokenTarget(String),
    Invalid,
}

pub fn manifest_state(path: &Path) -> ManifestState {
    use std::io::Read;
    let Ok(f) = std::fs::File::open(path) else {
        return ManifestState::Missing;
    };
    let mut buf = Vec::new();
    if f.take(MAX_MANIFEST_LEN).read_to_end(&mut buf).is_err() {
        return ManifestState::Invalid;
    }
    let Ok(Value::Object(m)) = serde_json::from_slice::<Value>(&buf) else {
        return ManifestState::Invalid;
    };
    if m.get("name").and_then(Value::as_str) != Some("hirz") {
        return ManifestState::Invalid;
    }
    match m.get("path").and_then(Value::as_str) {
        Some(p) if Path::new(p).is_absolute() && is_executable_file(Path::new(p)) => {
            ManifestState::Ok(PathBuf::from(p))
        }
        Some(p) => ManifestState::BrokenTarget(p.to_string()),
        None => ManifestState::Invalid,
    }
}

/// Fills the template with the absolute path of hirz-nmh.
pub fn render_manifest(nmh: &Path) -> CliResult<String> {
    let path = nmh
        .to_str()
        .ok_or_else(|| CliError::failed("The hirz-nmh path must be valid UTF-8."))?;
    let quoted = serde_json::to_string(path).map_err(|e| CliError::failed(e.to_string()))?;
    if !TEMPLATE.contains(PLACEHOLDER) {
        return Err(CliError::failed("Internal error: manifest template."));
    }
    let text = TEMPLATE.replace(PLACEHOLDER, &quoted);
    let check: Value = serde_json::from_str(&text)
        .map_err(|_| CliError::failed("Internal error: manifest template."))?;
    if check.get("path").and_then(Value::as_str) != Some(path) {
        return Err(CliError::failed("Internal error: manifest template."));
    }
    Ok(text)
}

pub fn snap_firefox(env: &Env) -> bool {
    env.sys_path("/snap/bin/firefox").exists() || env.sys_path("/snap/firefox").is_dir()
}

pub fn flatpak_firefox(env: &Env) -> bool {
    env.sys_path("/var/lib/flatpak/app/org.mozilla.firefox")
        .is_dir()
        || env
            .data_home
            .join("flatpak/app/org.mozilla.firefox")
            .is_dir()
}

pub fn firefox(ctx: &mut Ctx<'_>, nmh_path: Option<PathBuf>, force: bool) -> CliResult<Exit> {
    let nmh = match nmh_path {
        Some(p) => ctx.env.absolute(&p)?,
        None => ctx
            .env
            .exe_dir
            .as_ref()
            .map(|d| d.join(NMH_BINARY))
            .ok_or_else(|| {
                CliError::failed("Could not find hirz-nmh. Give its path with --nmh-path PATH.")
            })?,
    };
    let nmh = std::fs::canonicalize(&nmh).map_err(|_| {
        CliError::failed(format!(
            "hirz-nmh was not found at {}. Install it, or give its path with --nmh-path PATH.",
            nmh.display()
        ))
    })?;
    if !is_executable_file(&nmh) {
        return Err(CliError::failed(format!(
            "{} is not an executable program.",
            nmh.display()
        )));
    }
    let text = render_manifest(&nmh)?;
    let target = manifest_locations(ctx.env)
        .into_iter()
        .next()
        .map(|(p, _)| p)
        .ok_or_else(|| CliError::failed("HOME is not set."))?;
    let dir = target
        .parent()
        .ok_or_else(|| CliError::failed("Internal error: manifest folder."))?
        .to_path_buf();

    let mut changed = true;
    match std::fs::read_to_string(&target) {
        Ok(existing) if existing == text => {
            ctx.say(&format!(
                "Firefox is already set up ({}).",
                target.display()
            ))?;
            changed = false;
        }
        Ok(_) => {
            let what = match manifest_state(&target) {
                ManifestState::Ok(p) => p.display().to_string(),
                ManifestState::BrokenTarget(p) => crate::ui::clean(&p, 200),
                _ => "something else".to_string(),
            };
            ctx.say(&format!(
                "{} already exists and points to {what}.",
                target.display()
            ))?;
            if !force
                && !confirm(
                    ctx.prompt,
                    &format!("Point it to {} instead?", nmh.display()),
                )?
            {
                return Err(CliError::cancelled("Nothing was changed."));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(CliError::io(
                &format!("Could not read {}", target.display()),
                &e,
            ));
        }
    }
    if changed {
        std::fs::create_dir_all(&dir)
            .map_err(|e| CliError::io(&format!("Could not create {}", dir.display()), &e))?;
        crate::env::write_atomic(&dir, MANIFEST_NAME, text.as_bytes(), 0o644)
            .map_err(|e| CliError::io(&format!("Could not write {}", target.display()), &e))?;
        ctx.say(&format!(
            "Installed {} for your user.\nIt starts {}.",
            target.display(),
            nmh.display()
        ))?;
    }
    ctx.say(
        "\nNext:\n\
         1. Install the hirz extension in Firefox.\n\
         2. Restart Firefox.\n\
         3. Run `hirz status` to check that everything is found.",
    )?;
    if snap_firefox(ctx.env) {
        ctx.say(
            "\nYour Firefox is a Snap. It reaches hirz through the desktop's WebExtensions portal,\n\
             which reads the same file. The first time, Firefox asks \"Allow Firefox to start\n\
             WebExtension backend?\": answer Allow while Firefox is the focused window. To allow\n\
             it in advance, run:\n  flatpak permission-set webextensions hirz snap.firefox yes",
        )?;
    }
    if flatpak_firefox(ctx.env) {
        ctx.say(
            "\nYour Firefox is a Flatpak. This is experimental: it needs the\n\
             xdg-native-messaging-proxy package and permission to use it:\n  \
             flatpak override --user --talk-name=org.freedesktop.NativeMessagingProxy org.mozilla.firefox",
        )?;
    }
    Ok(Exit::Ok)
}
