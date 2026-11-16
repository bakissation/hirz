//! Dispatch, shared context and help texts.

use crate::args::{Command, Invocation};
use crate::env::{Env, STATE_DEVICE, System, VAULT_HEADER};
use crate::error::{CliError, CliResult, Exit};
use crate::prompt::Prompter;
use hirz_crypto::kdf::Argon2Params;
use hirz_vault::Vault;
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

    /// The vault folder for commands that use an existing vault.
    pub fn vault_dir(&self) -> CliResult<PathBuf> {
        self.env.vault_dir(self.vault_flag.as_deref())
    }

    pub fn open_vault(&self) -> CliResult<(Vault, PathBuf)> {
        let dir = self.vault_dir()?;
        if !self.env.state_dir().join(STATE_DEVICE).exists() {
            return Err(not_set_up());
        }
        if !dir.join(VAULT_HEADER).exists() {
            return Err(CliError::not_set_up(format!(
                "No vault found in {}. If this folder is synced, check that your sync tool is \
                 running and has copied it. Otherwise give the right folder with --vault DIR.",
                dir.display()
            )));
        }
        let vault = Vault::open(&dir, self.env.state_dir())?;
        Ok((vault, dir))
    }
}

pub fn not_set_up() -> CliError {
    CliError::not_set_up(
        "hirz is not set up on this computer. Run `hirz init` to start a new vault, or \
         `hirz join --vault DIR` to use a vault you already have on another device.",
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
        Command::Join { name } => crate::cmd_vault::join(ctx, name),
        Command::Status { json } => crate::cmd_status::status(ctx, json),
        Command::List { site, json } => crate::cmd_vault::list(ctx, site, json),
        Command::Delete { target, yes } => crate::cmd_vault::delete(ctx, target, yes),
        Command::Devices { json } => crate::cmd_vault::devices(ctx, json),
        Command::RemoveDevice { prefix, yes } => crate::cmd_vault::remove_device(ctx, &prefix, yes),
        Command::BackupConfirm { yes } => crate::cmd_vault::backup_confirm(ctx, yes),
        Command::Pin(action) => crate::cmd_pin::pin(ctx, action),
        Command::Export { file, plain } => crate::cmd_cxf::export(ctx, &file, plain),
        Command::Import { file } => crate::cmd_cxf::import(ctx, &file),
        Command::SetupFirefox { nmh_path, force } => {
            crate::cmd_setup::firefox(ctx, nmh_path, force)
        }
    }
}

const HELP: &str = "\
hirz keeps your passkeys in an encrypted folder that you can sync between computers.

Usage: hirz [--vault DIR] COMMAND [OPTIONS]

Getting started:
  init                 Create a new vault on this computer
  join --vault DIR     Use an existing (synced) vault on this computer
  setup firefox        Connect hirz to Firefox

Everyday:
  status               Show how hirz is set up and whether everything works
  list                 List your passkeys
  delete               Delete a passkey
  pin                  Set, change or reset the hirz PIN

Devices and backups:
  devices              List the devices that use this vault
  remove-device ID     Stop a lost or old device from reading new passkeys
  backup confirm       Tell hirz that your passkeys are backed up
  export --cxf FILE    Save all passkeys to a file (encrypted by default)
  import --cxf FILE    Add passkeys from an export file

Options for every command:
  --vault DIR          Use the vault in DIR instead of the one this computer uses
  -h, --help           Show help for a command, for example: hirz help init
  -V, --version        Show the version

Exit status: 0 done, 1 failed, 2 wrong arguments, 3 not set up, 4 cancelled,
5 wrong phrase, PIN or passphrase, 6 import finished but skipped some passkeys.
";

const HELP_INIT: &str = "\
Usage: hirz init [--vault DIR] [--name NAME] [--yes-i-saved-it]

Creates a new, empty vault and sets up this computer to use it.

  --vault DIR         Folder for the vault (default: ~/.local/share/hirz/vault).
                      Pick an empty folder inside your sync folder to sync it.
  --name NAME         Name of this computer as other devices see it
                      (default: the computer's host name)
  --yes-i-saved-it    Do not ask to retype words of the recovery phrase (scripts)

hirz shows a 24-word recovery phrase once. Write it down: it is the only way to get
your passkeys back if you lose every device, and you need it to add a computer.
";

const HELP_JOIN: &str = "\
Usage: hirz join --vault DIR [--name NAME]

Sets up this computer to use a vault that already exists, for example one that your
sync tool copied here. You type the 24-word recovery phrase of the vault.

  --vault DIR    The synced vault folder (required)
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

Lists the devices (computers) that use this vault.
";

const HELP_REMOVE: &str = "\
Usage: hirz remove-device ID-PREFIX [--yes]

Removes a device from the vault and changes the vault key, so the device cannot read
passkeys added or changed from now on. It keeps whatever it could already read: hirz
lists the sites whose passkeys you should replace.

  --yes    Do not ask for confirmation
";

const HELP_PIN: &str = "\
Usage: hirz pin set | change | reset | status

The hirz PIN is one way to approve passkey requests (see docs/approval.md).

  set       Choose a PIN (at least 4 characters)
  change    Change the PIN (asks for the current one)
  reset     Remove the PIN, for example after too many wrong tries
            (asks for the recovery phrase when a vault is set up)
  status    Show whether a PIN is set and how many wrong tries were made
";

const HELP_EXPORT: &str = "\
Usage: hirz export --cxf FILE [--plain]

Saves every passkey to FILE in the FIDO Credential Exchange Format (CXF 1.0). By
default the file is encrypted with a passphrase you choose. Keep it somewhere other
than this computer, for example on a USB drive.

  --cxf FILE    File to create (it must not exist yet)
  --plain       Write an unencrypted CXF file, for importing into another passkey
                manager. Anyone who gets the file can use your passkeys.
";

const HELP_IMPORT: &str = "\
Usage: hirz import --cxf FILE

Adds passkeys from a CXF file: an encrypted hirz export or a plain CXF export from
another passkey manager. Existing passkeys are never replaced. Passkeys hirz cannot
use are skipped and listed.
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
  --force            Replace an existing file that points elsewhere
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
