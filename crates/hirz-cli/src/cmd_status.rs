//! `hirz status`.

use crate::app::Ctx;
use crate::cmd_setup::{
    ManifestState, SYSTEM_SCOPE, flatpak_firefox, manifest_locations, manifest_state, snap_firefox,
};
use crate::error::{CliResult, Exit};
use crate::ui::{clean, count, hex, path_text};
use hirz_uv::PinStore;
use hirz_vault::Vault;
use serde_json::{Value, json};
use std::os::unix::fs::FileTypeExt;
use std::path::PathBuf;

const MAX_LISTED_SKIPPED: usize = 10;
const BROKER_ANSWER_TIME: std::time::Duration = std::time::Duration::from_secs(1);

/// What a connection to the broker socket found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Broker {
    Missing,
    /// Something accepted the connection: the broker, or systemd holding its socket.
    Answers,
    /// The socket file is there but nobody listens on it.
    Stale,
    NoAnswer,
    Error(String),
}

impl Broker {
    fn name(&self) -> &'static str {
        match self {
            Broker::Missing => "missing",
            Broker::Answers => "answers",
            Broker::Stale => "stale",
            Broker::NoAnswer => "no_answer",
            Broker::Error(_) => "error",
        }
    }
}

/// Sends the broker's probe hello and waits for its answer; the broker creates no device for it.
/// Runs on its own thread so a socket whose backlog is full cannot hold `hirz status` up for more
/// than `wait`.
pub fn probe_broker(path: &std::path::Path, wait: std::time::Duration) -> Broker {
    if !std::fs::metadata(path).is_ok_and(|m| m.file_type().is_socket()) {
        return Broker::Missing;
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let target = path.to_path_buf();
    let started = std::thread::Builder::new()
        .name("broker-probe".into())
        .spawn(move || {
            let _ = tx.send(ask_broker(&target, wait));
        });
    if started.is_err() {
        return Broker::Error("cannot start a thread".into());
    }
    match rx.recv_timeout(wait) {
        Ok(Ok(true)) => Broker::Answers,
        Ok(Ok(false)) => Broker::Error("it did not answer like the hirz broker".into()),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => Broker::Stale,
        Ok(Err(e))
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            Broker::NoAnswer
        }
        Ok(Err(e)) => Broker::Error(crate::error::describe_io(e.kind())),
        Err(_) => Broker::NoAnswer,
    }
}

/// True when the answer is the broker's `ALIVE`; reads at most that many bytes.
fn ask_broker(path: &std::path::Path, wait: std::time::Duration) -> std::io::Result<bool> {
    use hirz_sys::broker::{ALIVE, HELLO_PROBE};
    use std::io::{Read, Write};
    let mut s = std::os::unix::net::UnixStream::connect(path)?;
    s.set_write_timeout(Some(wait))?;
    s.set_read_timeout(Some(wait))?;
    s.write_all(&HELLO_PROBE)?;
    let mut answer = [0u8; ALIVE.len()];
    match s.read_exact(&mut answer) {
        Ok(()) => Ok(answer == ALIVE),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e),
    }
}

#[derive(Debug, Default)]
struct VaultInfo {
    device_name: String,
    device_id: String,
    passkeys: usize,
    devices_active: usize,
    devices_removed: usize,
    backed_up: bool,
    generation: u32,
    skipped: Vec<(String, &'static str)>,
    ignored_files: usize,
    locked_out: bool,
    removed: bool,
    rotation_conflict: bool,
    fork_detected: bool,
    rollback_suspected: bool,
    maintenance_error: Option<String>,
}

#[derive(Debug)]
struct Manifest {
    path: PathBuf,
    scope: &'static str,
    state: ManifestState,
}

#[derive(Debug)]
struct Report {
    vault_dir: PathBuf,
    state_dir: PathBuf,
    set_up: bool,
    vault_found: bool,
    vault: Option<VaultInfo>,
    vault_error: Option<String>,
    methods: Result<Vec<&'static str>, String>,
    zenity: bool,
    pin_set: bool,
    pin_locked: bool,
    polkit_action: Option<PathBuf>,
    manifests: Vec<Manifest>,
    snap: bool,
    flatpak: bool,
    broker_socket: PathBuf,
    broker: Broker,
    hirzd: Option<bool>,
}

fn gather(ctx: &Ctx<'_>) -> CliResult<Report> {
    let env = ctx.env;
    let vault_dir = ctx.vault_dir()?;
    let set_up = env.device_state_exists();
    let vault_found = Vault::exists(&vault_dir);
    let mut vault = None;
    let mut vault_error = None;
    if set_up && vault_found {
        match ctx.open_vault() {
            Ok((v, _)) => {
                let devices = v.devices();
                let me = devices.iter().find(|d| d.this_device);
                let r = v.report();
                vault = Some(VaultInfo {
                    device_name: me.map(|d| clean(&d.name, 64)).unwrap_or_default(),
                    device_id: hex(&v.device_id()),
                    passkeys: v.list_all().len(),
                    devices_active: devices.iter().filter(|d| !d.removed).count(),
                    devices_removed: devices.iter().filter(|d| d.removed).count(),
                    backed_up: v.backup_state(),
                    generation: r.generation,
                    skipped: r
                        .skipped
                        .iter()
                        .map(|s| (clean(&s.path, 200), s.reason))
                        .collect(),
                    ignored_files: r.ignored_files,
                    locked_out: r.locked_out,
                    removed: r.this_device_removed,
                    rotation_conflict: r.rotation_conflict,
                    fork_detected: r.fork_detected,
                    rollback_suspected: r.rollback_suspected,
                    maintenance_error: r.maintenance_error.as_ref().map(|e| e.to_string()),
                });
            }
            Err(e) => vault_error = Some(e.message),
        }
    }
    let pins = PinStore::with_params(env.state_dir(), ctx.kdf);
    let (pin_set, pin_locked) = match pins.status() {
        Ok(Some(s)) => (true, s.locked),
        Ok(None) => (false, false),
        Err(_) => (true, true),
    };
    let polkit_action = hirz_uv::polkit::POLICY_DIRS
        .iter()
        .map(|d| env.sys_path(d).join(hirz_uv::polkit::POLICY_FILE_NAME))
        .find(|p| p.is_file());
    let manifests = manifest_locations(env)
        .into_iter()
        .map(|(path, scope)| {
            let state = manifest_state(&path);
            Manifest { path, scope, state }
        })
        .collect();
    let broker_socket = env.broker_socket.clone();
    let broker = probe_broker(&broker_socket, BROKER_ANSWER_TIME);
    Ok(Report {
        vault_dir,
        state_dir: env.state_dir().to_path_buf(),
        set_up,
        vault_found,
        vault,
        vault_error,
        methods: ctx
            .sys
            .uv_methods(env)
            .map(|v| v.into_iter().map(|m| m.name()).collect()),
        zenity: ctx.sys.zenity(),
        pin_set,
        pin_locked,
        polkit_action,
        manifests,
        snap: snap_firefox(env),
        flatpak: flatpak_firefox(env),
        broker_socket,
        broker,
        hirzd: ctx.sys.hirzd_running(),
    })
}

/// Per-user manifests that Firefox, the portal and the proxy read before an installed system
/// manifest, so they take precedence over the packaged one.
fn overriding_user_manifests(manifests: &[Manifest]) -> Vec<&Manifest> {
    let system_installed = manifests
        .iter()
        .any(|m| m.scope == SYSTEM_SCOPE && m.state != ManifestState::Missing);
    if !system_installed {
        return Vec::new();
    }
    manifests
        .iter()
        .filter(|m| m.scope != SYSTEM_SCOPE && m.state != ManifestState::Missing)
        .collect()
}

fn to_json(r: &Report) -> Value {
    let vault = r.vault.as_ref().map(|v| {
        json!({
            "device_name": v.device_name,
            "device_id": v.device_id,
            "passkeys": v.passkeys,
            "devices_active": v.devices_active,
            "devices_removed": v.devices_removed,
            "backed_up": v.backed_up,
            "key_generation": v.generation,
            "this_device_removed": v.removed,
            "sync": {
                "skipped_files": v.skipped.iter().map(|(p, why)| json!({"path": p, "reason": why})).collect::<Vec<_>>(),
                "ignored_files": v.ignored_files,
                "locked_out": v.locked_out,
                "rotation_conflict": v.rotation_conflict,
                "fork_detected": v.fork_detected,
                "rollback_suspected": v.rollback_suspected,
                "maintenance_error": v.maintenance_error,
            }
        })
    });
    let overriding = overriding_user_manifests(&r.manifests);
    let (methods, methods_error) = match &r.methods {
        Ok(m) => (Some(m.clone()), None),
        Err(e) => (None, Some(e.clone())),
    };
    json!({
        "vault_dir": r.vault_dir.display().to_string(),
        "state_dir": r.state_dir.display().to_string(),
        "set_up": r.set_up,
        "vault_found": r.vault_found,
        "vault": vault,
        "vault_error": r.vault_error,
        "approval": {
            "methods": methods,
            "error": methods_error,
            "zenity": r.zenity,
            "pin_set": r.pin_set,
            "pin_locked": r.pin_locked,
            "polkit_action": r.polkit_action.as_ref().map(|p| p.display().to_string()),
        },
        "firefox": {
            "manifests": r.manifests.iter().map(|m| {
                let (state, target) = match &m.state {
                    ManifestState::Missing => ("missing", None),
                    ManifestState::Ok(p) => ("ok", Some(p.display().to_string())),
                    ManifestState::BrokenTarget(p) => ("program_missing", Some(p.clone())),
                    ManifestState::Invalid => ("invalid", None),
                };
                let overrides_system = overriding.iter().any(|o| o.path == m.path);
                json!({"path": m.path.display().to_string(), "scope": m.scope, "state": state, "program": target, "overrides_system": overrides_system})
            }).collect::<Vec<_>>(),
            "snap": r.snap,
            "flatpak": r.flatpak,
        },
        "uhid_broker": {
            "socket": r.broker_socket.display().to_string(),
            "present": r.broker != Broker::Missing,
            "state": r.broker.name(),
        },
        "hirzd": { "running": r.hirzd },
    })
}

fn print_text(ctx: &mut Ctx<'_>, r: &Report) -> CliResult {
    ctx.say(&format!("Vault folder:   {}", r.vault_dir.display()))?;
    ctx.say(&format!("Device state:   {}", r.state_dir.display()))?;
    if !r.set_up {
        ctx.say(
            "Setup:          not set up. Run `hirz init` for a new vault, or\n                \
             `hirz join --vault DIR` to use one from another device.",
        )?;
    } else if !r.vault_found {
        ctx.say(
            "Setup:          this computer is set up, but the vault folder is missing.\n                \
             Check your sync tool, or give the folder with --vault DIR.",
        )?;
    }
    if let Some(e) = &r.vault_error {
        ctx.say(&format!("Problem:        {e}"))?;
    }
    if let Some(v) = &r.vault {
        ctx.say(&format!(
            "This device:    \"{}\" (id {})",
            v.device_name,
            v.device_id.get(..12).unwrap_or(&v.device_id)
        ))?;
        ctx.say(&format!("Passkeys:       {}", v.passkeys))?;
        let removed = if v.devices_removed > 0 {
            format!(", {} removed", v.devices_removed)
        } else {
            String::new()
        };
        ctx.say(&format!(
            "Devices:        {} in use{removed}",
            v.devices_active
        ))?;
        if v.backed_up {
            ctx.say("Backed up:      yes (sites see your passkeys as backed up)")?;
        } else {
            ctx.say(
                "Backed up:      no. Your passkeys are only on this computer. Add a device with\n                \
                 `hirz join`, or sync or export the vault and run `hirz backup confirm`.",
            )?;
        }
        let mut sync_ok = true;
        let disputed = v.fork_detected || v.rotation_conflict;
        if v.removed && disputed {
            sync_ok = false;
            ctx.say(
                "Sync:           the vault folder says this computer was removed, but it also holds\n                \
                 conflicting key changes. Do not run `hirz forget-local` yet: check the vault\n                \
                 on a device you trust first.",
            )?;
        } else if v.removed {
            sync_ok = false;
            ctx.say(&format!(
                "Sync:           {}\n                \
                 Delete its keys with `{} forget-local`, or join again if that was a mistake.",
                crate::app::REMOVED,
                ctx.program
            ))?;
        } else if v.locked_out {
            sync_ok = false;
            ctx.say(
                "Sync:           this device was removed from the vault (or missed a key change)\n                \
                 and cannot write. Join again with the recovery phrase if that is a mistake.",
            )?;
        }
        if v.fork_detected {
            sync_ok = false;
            ctx.say(
                "Sync:           the vault folder no longer holds the key changes this computer\n                \
                 followed. Someone with access to the folder may have changed it. Passkeys still\n                \
                 work, but nothing new is saved. Restore the folder from your sync tool's\n                \
                 history, or run `hirz repair` to see what to do (it can also delete a key\n                \
                 change you do not trust, or follow the folder as it is).",
            )?;
        }
        if v.rotation_conflict {
            sync_ok = false;
            ctx.say(
                "Sync:           two devices removed each other. Stop sharing the folder with the\n                \
                 one you do not trust, then run `hirz remove-device` for it again, or run\n                \
                 `hirz repair` to delete a key change it made.",
            )?;
        }
        if v.rollback_suspected {
            sync_ok = false;
            ctx.say(
                "Sync:           files seem to be missing or older than before. Check your sync\n                \
                 tool and its trash or version history.",
            )?;
        }
        if !v.skipped.is_empty() {
            sync_ok = false;
            ctx.say(&format!(
                "Sync:           {} could not be read and were skipped (often a sync still in\n                \
                 progress; if it stays, the file is damaged):",
                count(v.skipped.len(), "file")
            ))?;
            for (p, why) in v.skipped.iter().take(MAX_LISTED_SKIPPED) {
                ctx.say(&format!("                  {p}: {why}"))?;
            }
            if v.skipped.len() > MAX_LISTED_SKIPPED {
                ctx.say(&format!(
                    "                  and {} more",
                    v.skipped.len().saturating_sub(MAX_LISTED_SKIPPED)
                ))?;
            }
        }
        if let Some(e) = &v.maintenance_error {
            sync_ok = false;
            ctx.say(&format!(
                "Sync:           hirz could not write to the vault folder ({e})."
            ))?;
        }
        if sync_ok {
            ctx.say("Sync:           all vault files read correctly")?;
        }
    }

    ctx.say("")?;
    match &r.methods {
        Ok(m) if m.is_empty() => ctx.say(
            "Approval:       no approval method works yet, so passkeys cannot be used.\n                \
             Install the polkit action or set a PIN (hirz pin set). See docs/approval.md.",
        )?,
        Ok(m) => ctx.say(&format!("Approval:       {}", m.join(", ")))?,
        Err(e) => ctx.say(&format!(
            "Approval:       the config file has a problem: {}",
            clean(e, 200)
        ))?,
    }
    if !r.zenity {
        ctx.say("                zenity is not installed; hirz needs it to show prompts.")?;
    }
    ctx.say(&format!(
        "Polkit action:  {}",
        match &r.polkit_action {
            Some(p) => format!("installed ({})", p.display()),
            None => "not installed (see docs/approval.md)".into(),
        }
    ))?;
    ctx.say(&format!(
        "hirz PIN:       {}",
        match (r.pin_set, r.pin_locked) {
            (false, _) => "not set",
            (true, false) => "set",
            (true, true) => "locked or damaged (hirz pin reset)",
        }
    ))?;

    ctx.say("")?;
    let installed: Vec<&Manifest> = r
        .manifests
        .iter()
        .filter(|m| m.state != ManifestState::Missing)
        .collect();
    if installed.is_empty() {
        ctx.say("Firefox:        not set up. Run `hirz setup firefox`.")?;
    }
    for m in installed {
        let state = match &m.state {
            ManifestState::Ok(p) => format!("ok, starts {}", path_text(p)),
            ManifestState::BrokenTarget(p) => {
                format!("points to {}, which is missing", clean(p, 200))
            }
            ManifestState::Invalid => "not a valid hirz manifest".into(),
            ManifestState::Missing => continue,
        };
        ctx.say(&format!(
            "Firefox:        {} ({}): {state}",
            m.path.display(),
            m.scope
        ))?;
    }
    for m in overriding_user_manifests(&r.manifests) {
        let program = match &m.state {
            ManifestState::Ok(p) => path_text(p),
            ManifestState::BrokenTarget(p) => clean(p, 200),
            ManifestState::Invalid | ManifestState::Missing => "no valid program".into(),
        };
        ctx.say(&format!(
            "Warning:        {} takes precedence over the system manifest, so Firefox\n                \
             starts {program} instead of the packaged host.\n                \
             Remove it unless you run a development build: rm {}",
            m.path.display(),
            m.path.display()
        ))?;
    }
    if r.snap {
        ctx.say(
            "Firefox Snap:   found; it reads the manifest through the desktop portal and asks\n                \
             once to allow hirz (see docs/extension.md)",
        )?;
    }
    if r.flatpak {
        ctx.say("Firefox Flatpak: found; support is experimental (docs/extension.md)")?;
    }
    ctx.say(&format!(
        "Security key:   {}",
        match &r.broker {
            Broker::Answers => format!("the broker answers ({})", r.broker_socket.display()),
            Broker::Missing => format!(
                "broker socket {} not found (only needed for the virtual security key; see docs/uhid.md)",
                r.broker_socket.display()
            ),
            Broker::Stale => format!(
                "broker socket {} is stale: nothing answers on it. Restart the broker\n                \
                 (systemctl restart hirz-uhid-broker.socket; see docs/uhid.md)",
                r.broker_socket.display()
            ),
            Broker::NoAnswer => format!(
                "the broker socket {} did not answer within {} s",
                r.broker_socket.display(),
                BROKER_ANSWER_TIME.as_secs()
            ),
            Broker::Error(why) => format!(
                "cannot connect to the broker socket {}: {why}",
                r.broker_socket.display()
            ),
        }
    ))?;
    ctx.say(match (r.hirzd, &r.broker) {
        (Some(true), _) => "hirzd:          running",
        (Some(false), Broker::Missing) => {
            "hirzd:          not running (only needed for the virtual security key; see docs/uhid.md)"
        }
        (Some(false), _) => {
            "hirzd:          not running, so browsers cannot see the hirz security key.\n                \
             Start it: systemctl --user start hirzd (or log out and back in)"
        }
        (None, _) => "hirzd:          could not check whether it runs",
    })?;
    Ok(())
}

pub fn status(ctx: &mut Ctx<'_>, json_out: bool) -> CliResult<Exit> {
    let report = gather(ctx)?;
    if json_out {
        ctx.say_json(&to_json(&report))?;
    } else {
        print_text(ctx, &report)?;
    }
    if !report.set_up || !report.vault_found {
        return Ok(Exit::NotSetUp);
    }
    match &report.vault {
        None => return Ok(Exit::Failed),
        Some(v) if v.removed || v.locked_out || v.rotation_conflict || v.fork_detected => {
            return Ok(Exit::Failed);
        }
        Some(_) => {}
    }
    Ok(Exit::Ok)
}

#[cfg(test)]
mod manifest_override_tests {
    use super::*;

    fn manifest(path: &str, scope: &'static str, state: ManifestState) -> Manifest {
        Manifest {
            path: PathBuf::from(path),
            scope,
            state,
        }
    }

    #[test]
    fn user_manifest_overrides_only_an_installed_system_manifest() {
        let user = || manifest("/h/user.json", "your user", ManifestState::Invalid);
        let portal = || {
            manifest(
                "/h/portal.json",
                "your user (portal)",
                ManifestState::Missing,
            )
        };
        let sys = |state| manifest("/usr/lib/hirz.json", SYSTEM_SCOPE, state);

        let none = [user(), portal(), sys(ManifestState::Missing)];
        assert!(overriding_user_manifests(&none).is_empty());

        let both = [
            user(),
            portal(),
            sys(ManifestState::Ok(PathBuf::from("/usr/lib/hirz/hirz-nmh"))),
        ];
        let found = overriding_user_manifests(&both);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found.first().map(|m| m.path.as_path()),
            Some(PathBuf::from("/h/user.json").as_path())
        );

        let only_system = [sys(ManifestState::Invalid)];
        assert!(overriding_user_manifests(&only_system).is_empty());
    }
}
