//! Dispatch, shared context and help texts.

use crate::args::{Command, Invocation};
use crate::env::{Env, System};
use crate::error::{CliError, CliResult, Exit};
use crate::prompt::Prompter;
use hirz_crypto::kdf::Argon2Params;
use hirz_vault::{Vault, VaultError};
use std::io::Write;
use std::path::PathBuf;

pub struct Ctx<'a> {
    pub out: &'a mut dyn Write,
    pub prompt: &'a mut dyn Prompter,
    pub env: &'a Env,
    pub sys: &'a dyn System,
    /// Argon2id cost for new export envelopes and PINs (the RFC 9106 default outside tests).
    pub kdf: Argon2Params,
    pub vault_flag: Option<PathBuf>,
    pub program: String,
    pub out_is_terminal: bool,
}

impl core::fmt::Debug for Ctx<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ctx")
            .field("env", self.env)
            .field("vault_flag", &self.vault_flag)
            .finish_non_exhaustive()
    }
}

impl Ctx<'_> {
    pub fn say(&mut self, text: &str) -> CliResult {
        self.out
            .write_all(text.as_bytes())
            .and_then(|()| self.out.write_all(b"\n"))
            .map_err(|e| CliError::io("Could not write the output", &e))
    }

    pub fn write_raw(&mut self, text: &str) -> CliResult {
        self.out
            .write_all(text.as_bytes())
            .and_then(|()| self.out.flush())
            .map_err(|e| CliError::io("Could not write the output", &e))
    }

    pub fn say_json(&mut self, value: &serde_json::Value) -> CliResult {
        let text =
            serde_json::to_string_pretty(value).map_err(|e| CliError::failed(e.to_string()))?;
        self.say(&crate::ui::escape_json_controls(&text))
    }

    pub fn vault_dir(&self) -> CliResult<PathBuf> {
        self.env.vault_dir(self.vault_flag.as_deref())
    }

    pub fn open_vault(&self) -> CliResult<(Vault, PathBuf)> {
        let dir = self.vault_dir()?;
        if !self.env.device_state_exists() {
            return Err(not_set_up());
        }
        if !Vault::exists(&dir) {
            return Err(CliError::not_set_up(format!(
                "No vault found in {}. If this folder is synced, check that your sync tool is \
                 running and has copied it. Otherwise give the right folder with --vault DIR.",
                dir.display()
            )));
        }
        let vault = Vault::open(&dir, self.env.state_dir())?;
        Ok((vault, dir))
    }

    /// Like [`Ctx::open_vault`], but refuses when another device removed this one or a newer
    /// key generation exists that this computer holds no key for.
    pub fn open_active_vault(&self) -> CliResult<(Vault, PathBuf)> {
        let (vault, dir) = self.open_vault()?;
        let report = vault.report();
        let removed_here = matches!(vault.ensure_active(), Err(VaultError::Removed));
        if (removed_here || report.locked_out) && (report.fork_detected || report.rotation_conflict)
        {
            return Err(disputed_removal(&self.program));
        }
        if removed_here {
            return Err(removed(&self.program));
        }
        if report.locked_out {
            return Err(locked_out(&self.program));
        }
        Ok((vault, dir))
    }
}

pub const REMOVED: &str =
    "This computer was removed from your hirz vault; its passkeys are no longer used here.";

pub fn removed(program: &str) -> CliError {
    CliError::failed(format!(
        "{REMOVED}\nTo delete this computer's hirz keys, run `{program} forget-local`. If the \
         removal was a mistake, run that and then join again with `{program} join --vault DIR \
         --request`."
    ))
}

/// Removal reported together with a fork or rotation conflict: the removal may be forged, so
/// deleting this computer's keys is not recommended.
pub fn disputed_removal(program: &str) -> CliError {
    CliError::failed(format!(
        "The vault folder says this computer can no longer use the vault, but it also holds \
         conflicting key changes, so that may not be true. Do not run `{program} forget-local` \
         yet. Run `{program} status` and `{program} repair` to see what the folder holds, and \
         check it on a device you trust; if a device you removed still has access to the folder, \
         stop sharing the folder with it and run `{program} remove-device` for it again."
    ))
}

pub fn locked_out(program: &str) -> CliError {
    CliError::failed(format!(
        "This computer cannot read the newest version of your hirz vault: another device \
         changed the vault key and this computer has not received it. If your sync tool is \
         still copying files, wait and try again. If this computer was removed from the \
         vault, run `{program} forget-local`; `{program} status` shows more."
    ))
}

pub fn not_set_up() -> CliError {
    CliError::not_set_up(
        "hirz is not set up on this computer. Run `hirz init` to start a new vault, or \
         `hirz join --vault DIR --request` to use a vault you already have on another device.",
    )
}

pub fn run(inv: Invocation, ctx: &mut Ctx<'_>) -> CliResult<Exit> {
    ctx.vault_flag = inv.vault;
    match inv.command {
        Command::Help(topic) => {
            let text = help(topic.as_deref())?;
            ctx.write_raw(text)?;
            Ok(Exit::Ok)
        }
        Command::Version => {
            ctx.say(&format!("hirz {}", env!("CARGO_PKG_VERSION")))?;
            Ok(Exit::Ok)
        }
        Command::Init { name, saved } => crate::cmd_vault::init(ctx, name, saved),
        Command::InitGui { name } => {
            crate::cmd_gui::init_gui(ctx, name, &mut crate::cmd_gui::ZenityWindows::new())
        }
        Command::Join { name, request } => crate::cmd_vault::join(ctx, name, request),
        Command::Status { json } => crate::cmd_status::status(ctx, json),
        Command::List { site, json } => crate::cmd_vault::list(ctx, site, json),
        Command::Delete { target, yes } => crate::cmd_vault::delete(ctx, target, yes),
        Command::Devices { json } => crate::cmd_vault::devices(ctx, json),
        Command::DevicesApprove { request } => crate::cmd_pair::approve(ctx, request),
        Command::DevicesDeny { request } => crate::cmd_pair::deny(ctx, &request),
        Command::RemoveDevice { prefix, yes } => crate::cmd_vault::remove_device(ctx, &prefix, yes),
        Command::ForgetLocal => crate::cmd_vault::forget_local(ctx),
        Command::Repair { action, yes } => crate::cmd_repair::repair(ctx, action, yes),
        Command::BackupConfirm { yes } => crate::cmd_vault::backup_confirm(ctx, yes),
        Command::Pin(action) => crate::cmd_pin::pin(ctx, action),
        Command::Export { file, plain } => crate::cmd_cxf::export(ctx, &file, plain),
        Command::Import { format, file, yes } => crate::cmd_cxf::import(ctx, format, &file, yes),
        Command::SetupFirefox { nmh_path, force } => {
            crate::cmd_setup::firefox(ctx, nmh_path, force)
        }
    }
}

const HELP: &str = "\
hirz keeps your passkeys in an encrypted folder that you can sync between computers.

Usage: hirz [--vault DIR] COMMAND [OPTIONS]

Getting started:
  init                 Create a new vault on this computer (--gui: in windows)
  join --vault DIR     Use an existing (synced) vault on this computer
                       (--request: get approval from another device)
  setup firefox        Connect hirz to Firefox

Everyday:
  status               Show how hirz is set up and whether everything works
  list                 List your passkeys
  delete               Delete a passkey
  pin                  Set, change or reset the hirz PIN

Devices and backups:
  devices              List the devices that use this vault
  devices approve      Let a new device join (compare four words first)
  devices deny ID      Refuse a device that asked to join
  remove-device ID     Stop a lost or old device from reading new passkeys
  repair               Show and settle a vault folder that was changed behind your back
  forget-local         Delete this computer's hirz keys (after it was removed)
  backup confirm       Tell hirz that your passkeys are backed up
  export --cxf FILE    Save all passkeys to a file (encrypted by default)
  import --cxf FILE    Add passkeys from an export file
                       (or --bitwarden FILE, --keepassxc PATH)

Options for every command:
  --vault DIR          Use the vault in DIR instead of the one this computer uses
  -h, --help           Show help for a command, for example: hirz help init
  -V, --version        Show the version

Exit status: 0 done, 1 failed, 2 wrong arguments, 3 not set up, 4 cancelled,
5 wrong phrase, PIN or passphrase, 6 import finished but skipped some passkeys.
";

const HELP_INIT: &str = "\
Usage: hirz init [--vault DIR] [--name NAME] [--yes-i-saved-it]
       hirz init --gui [--vault DIR] [--name NAME]

Creates a new, empty vault and sets up this computer to use it.

  --vault DIR         Folder for the vault (default: ~/.local/share/hirz/vault).
                      Pick an empty folder inside your sync folder to sync it.
  --name NAME         Name of this computer as other devices see it
                      (default: the computer's host name)
  --yes-i-saved-it    Do not ask to retype words of the recovery phrase (scripts)
  --gui               Do the same in windows instead of the terminal. hirz starts this
                      itself the first time an app asks it for a passkey and there is
                      no vault yet.

hirz shows a 24-word recovery phrase once, on the terminal's alternate screen so it
does not stay in scrollback. Write it down: it is the only way to get your passkeys
back if you lose every device, and you need it to add a computer.

When Firefox is installed without the hirz extension, hirz offers at the end to open
the extension's page on addons.mozilla.org.
";

const HELP_JOIN: &str = "\
Usage: hirz join --vault DIR --request [--name NAME]
       hirz join --vault DIR [--name NAME]

Sets up this computer to use a vault that already exists, for example one that your
sync tool copied here.

With --request, this computer shows four words and waits (up to 15 minutes) until you
approve it on a device that already uses the vault: run `hirz devices approve` there
and check that it shows the same four words. Without --request, you type the 24-word
recovery phrase of the vault instead.

  --vault DIR    The synced vault folder (required)
  --request      Ask another device for approval instead of typing the phrase
  --name NAME    Name of this computer (default: the computer's host name)
";

const HELP_STATUS: &str = "\
Usage: hirz status [--json]

Shows the vault, this device, how many passkeys and devices there are, whether your
passkeys count as backed up, files the sync tool may have damaged, which approval
methods work, and whether Firefox and the virtual security key are set up.

  --json    Print the same information as JSON
";

const HELP_LIST: &str = "\
Usage: hirz list [--site SITE] [--json]

Lists your passkeys: site, account, date created and the start of the passkey id.
Private keys are never shown.

  --site SITE    Only passkeys for this site, for example example.com
  --json         Print JSON
";

const HELP_DELETE: &str = "\
Usage: hirz delete ID-PREFIX [--yes]
       hirz delete SITE ACCOUNT [--yes]

Deletes one passkey from the vault, on every device. ID-PREFIX is the start of the id
shown by `hirz list` (at least 4 characters). The site still lists the passkey in your
account settings; remove it there too.

  --yes    Do not ask for confirmation
";

const HELP_DEVICES: &str = "\
Usage: hirz devices [--json]
       hirz devices approve [REQUEST]
       hirz devices deny REQUEST

Lists the devices (computers) that use this vault.

  approve    Shows the devices waiting to join (after `hirz join --request` on them)
             and four words for the one you pick. Approve only if the new device shows
             exactly the same words. Only then hirz shows the name that device gave
             itself, and you confirm with your password, fingerprint or hirz PIN.
             REQUEST (the start of its id) picks one directly.
  deny       Deletes the request of a device waiting to join.
";

const HELP_REMOVE: &str = "\
Usage: hirz remove-device ID-PREFIX [--yes]

Removes a device from the vault and changes the vault key, so the device cannot read
passkeys added or changed from now on. It keeps whatever it could already read: hirz
lists the sites whose passkeys you should replace. You confirm in a hirz window with
your password, fingerprint or hirz PIN.

  --yes    Do not ask the yes/no question in the terminal (the window still asks)
";

const HELP_REPAIR: &str = "\
Usage: hirz repair
       hirz repair --discard NAME [--yes]
       hirz repair --accept-fork [--yes]

Without options, shows whether the vault folder reports a fork (key changes this computer
followed are gone or were rewritten) or a rotation conflict (two devices removed each other),
and lists the key changes this computer does not follow, by the folder name that --discard
takes. Passkeys keep working in all these cases, but nothing new is saved until it is settled.

  --discard NAME   Delete that key change and everything built on it, after you confirm.
                   Use it for a key change a device you do not trust made.
  --accept-fork    Follow the vault folder as it is now, going on from the newest key change
                   this computer followed that is still there; removed devices stay removed.
                   Only after you restored the folder from your sync tool's history if you
                   could, and stopped sharing it with every device you do not trust.
  --yes            Do not ask the yes/no question in the terminal (the window still asks)

Both changes need your password, fingerprint or hirz PIN in a hirz window.
";

const HELP_FORGET: &str = "\
Usage: hirz forget-local

Deletes this computer's hirz keys (its device key, key ring and counter) from the state
folder, after you confirm. Use it on a computer that was removed from the vault, or to
stop using hirz here. The vault folder is never touched, and the hirz PIN is kept.
Join again later with `hirz join`.
";

const HELP_PIN: &str = "\
Usage: hirz pin set | change | reset | status

The hirz PIN is one way to approve passkey requests (see docs/approval.md).

  set       Choose a PIN (at least 4 characters)
  change    Change the PIN (asks for the current one)
  reset     Remove the PIN, for example after too many wrong tries
            (asks for the recovery phrase when a vault is set up, and is
            refused on a computer that was removed from the vault)
  status    Show whether a PIN is set and how many wrong tries were made
";

const HELP_EXPORT: &str = "\
Usage: hirz export --cxf FILE [--plain]

Saves every passkey to FILE in the FIDO Credential Exchange Format (CXF 1.0). By
default the file is encrypted with a passphrase you choose. Keep it somewhere other
than this computer, for example on a USB drive.

Like approving or removing a device, an export needs your password, fingerprint or
hirz PIN in a hirz window, and it is refused on a computer that was removed from the
vault.

  --cxf FILE    File to create (it must not exist yet)
  --plain       Write an unencrypted CXF file, for importing into another passkey
                manager. Anyone who gets the file can use your passkeys.
";

const HELP_IMPORT: &str = "\
Usage: hirz import --cxf FILE | --bitwarden FILE | --keepassxc PATH [--yes]

Adds passkeys from an export file. hirz first lists the sites and accounts it would
add and asks before it adds them: an imported passkey signs in to the account it
names. Existing passkeys are never replaced. Passkeys hirz cannot use are skipped and
listed. Passwords, notes and everything else in the file are ignored.

  --yes               Add the passkeys without asking (the list is still shown)
  --cxf FILE          An encrypted hirz export or a plain CXF export from another
                      passkey manager
  --bitwarden FILE    A Bitwarden .json export, unencrypted or password protected
                      (asks for the file password). Account restricted exports cannot
                      be read; export again as password protected.
  --keepassxc PATH    A KeePassXC .passkey file, or a folder of them
";

const HELP_BACKUP: &str = "\
Usage: hirz backup confirm [--yes]

Tells hirz that your passkeys exist somewhere other than this computer (another
device that uses the vault, a synced copy of the vault folder, or an export file you
moved elsewhere). Sites can then see that your passkeys are backed up.

  --yes    Do not ask
";

const HELP_SETUP: &str = "\
Usage: hirz setup firefox [--nmh-path PATH] [--force]

Installs the file that lets the hirz Firefox extension start hirz-nmh, for your user
only (~/.mozilla/native-messaging-hosts/hirz.json). System folders are never touched.

  --nmh-path PATH    The hirz-nmh program (default: next to this hirz program)
  --force            Replace an existing file that points elsewhere, and write it even
                     when a package already installed the system-wide manifest (which
                     the new file would override)

Installed from a package? Do not run this: the package already connected Firefox.
";

pub fn help(topic: Option<&str>) -> CliResult<&'static str> {
    Ok(match topic {
        None => HELP,
        Some("init") => HELP_INIT,
        Some("join") => HELP_JOIN,
        Some("status") => HELP_STATUS,
        Some("list") => HELP_LIST,
        Some("delete") => HELP_DELETE,
        Some("devices") => HELP_DEVICES,
        Some("remove-device") => HELP_REMOVE,
        Some("forget-local") => HELP_FORGET,
        Some("repair") => HELP_REPAIR,
        Some("pin") => HELP_PIN,
        Some("export") => HELP_EXPORT,
        Some("import") => HELP_IMPORT,
        Some("backup") => HELP_BACKUP,
        Some("setup") => HELP_SETUP,
        Some("help") | Some("version") => HELP,
        Some(other) => {
            return Err(CliError::usage(format!(
                "No help for `{}`. Run `hirz help` to see the commands.",
                crate::ui::clean(other, 40)
            )));
        }
    })
}
