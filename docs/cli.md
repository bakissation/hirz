# hirz command line reference

`hirz` sets up and manages the vault that holds your passkeys. It never talks to the
network. Approving passkey requests is done by `hirzd` and `hirz-nmh` through `hirz-uv`
(see [approval.md](approval.md)); `hirz` only manages the vault and the setup around it. Manual pages: `docs/man/`.

```
hirz [--vault DIR] COMMAND [OPTIONS]
```

Options take their value as `--opt value` or `--opt=value`. `--` ends the options, so an
account name that starts with `-` can still be given. `hirz help COMMAND` or
`hirz COMMAND --help` shows the help of one command.

Messages are short and plain. Questions are written to standard error, so standard output
stays clean when it is redirected. `status`, `list` and `devices` accept `--json`.

Commands that hirz suggests for this computer start with `hirz`. When hirz was started by
a path (for example `./target/release/hirz`) and no `hirz` is on `PATH`, they start with
that path instead, quoted for the shell when needed.

## Where hirz keeps things

| What | Default | Synced |
|---|---|---|
| Vault folder | `$XDG_DATA_HOME/hirz/vault` (`~/.local/share/hirz/vault`), or the folder given to `init` / `join` | yes, by your sync tool ([sync.md](sync.md)) |
| Device state | `$XDG_STATE_HOME/hirz` (`~/.local/state/hirz`): device key, keyring, counter, PIN verifier, `vault-path` | never |
| Approval config | `$XDG_CONFIG_HOME/hirz/config` | never |
| Firefox manifest | `~/.mozilla/native-messaging-hosts/hirz.json` | never |

**Finding the vault.** Every command that uses the vault looks for it in this order:

1. the `--vault DIR` option;
2. the file `vault-path` in the device state directory, which `init` and `join` write. It
   holds the absolute path of the vault folder as raw bytes, without a trailing newline
   (mode 0600, at most 4096 bytes). `hirzd` and `hirz-nmh` should resolve the vault the
   same way;
3. the default `$XDG_DATA_HOME/hirz/vault`.

hirz uses one vault per user and device state directory.

Environment variables: `HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`, `XDG_CONFIG_HOME`
(relative values are ignored, as the XDG specification requires) and
`HIRZ_BROKER_SOCKET` (checked by `status`, default `/run/hirz/uhid.sock`).

## Typing secrets

The recovery phrase, PINs and passphrases are read without showing them on screen. The
standard library has no terminal API and hirz allows `unsafe` code only in `hirz-sys`, so
hirz turns off echo by running `stty -echo` (and restores the saved settings with
`stty <saved>` afterwards). `stty` is only taken from root-owned system directories
(`/usr/bin`, `/bin`, ...), never from `PATH`. When the input cannot be hidden, hirz reads it
normally and prints one note on standard error before the first secret:

- standard input is a terminal but `stty` is not available:
  "Note: this terminal cannot hide what you type, so it will be visible."
- standard input is not a terminal (a pipe or a file, for example `hirz pin set` in a
  script):
  "Note: standard input is not a terminal, so hirz cannot hide this input."

If hirz is killed while echo is off, type `reset` and press Enter.

## Commands

### `hirz init [--vault DIR] [--name NAME] [--yes-i-saved-it]`

Creates a new vault and sets up this computer to use it.

- `--vault DIR`: the vault folder. It must be empty or not exist yet. To sync the vault,
  make it a new folder inside your sync folder, for example `~/Sync/hirz`.
- `--name NAME`: this computer's name as other devices see it (1 to 64 characters,
  default: the host name).
- Shows the 24-word recovery phrase once, with instructions to write it down and not to
  copy, paste or screenshot it, then asks you to retype three words chosen at random. When
  standard output is a terminal and the check succeeds, hirz clears the screen and the
  scrollback so the phrase does not stay visible. After three failed rounds the command stops with
  exit status 4; the vault exists but the phrase was not confirmed.
- `--yes-i-saved-it` skips the check (for scripts that store the phrase themselves).
- Refuses when this computer is already set up, when DIR already holds a vault (use
  `join`), or when DIR is not empty.

### `hirz join --vault DIR --request [--name NAME]`

Sets up this computer to use an existing vault that your sync tool copied to DIR, approved
from a device that already uses it ([vault-format.md](vault-format.md), section 11). hirz
writes a request into the vault folder, shows four verification words and waits, polling
the folder every two seconds. On the other device, run `hirz devices approve` and check
the words. The request expires after 15 minutes; hirz keeps waiting two more minutes for
an approval that is still being copied, then deletes the request and exits with status 1.
Nothing is written to this computer's state until a valid approval arrives. An approval
file that does not open this vault is reported once and ignored. After joining, hirz lists
the other devices of the vault so you can check that it is yours. Pressing Ctrl-C stops
waiting; the request then expires on its own.

### `hirz join --vault DIR [--name NAME]`

The same without another device: you type the recovery phrase (case does not matter; the first four letters of each word are enough).
A phrase with a wrong word count, an unknown word or a bad checksum is explained and asked
again, up to three times. A valid phrase of another vault exits with status 5 and changes
nothing.

### `hirz status [--json]`

Shows:

- the vault folder and the device state directory, and whether this computer is set up;
- this device's name and id, the number of passkeys, devices in use and removed;
- whether your passkeys count as backed up (the WebAuthn BS flag: set once the vault has
  a second device or a confirmed backup);
- sync health: files that could not be read (usually a sync still in progress, otherwise
  damaged files), whether another device removed this one (or this one missed a key
  change), a key rotation conflict, files that seem rolled back, and maintenance writes
  that failed;
- the approval methods that work now (from `hirz-uv`), whether `zenity` is installed,
  whether the polkit action is installed and whether a hirz PIN is set;
- the Firefox native messaging manifests found in the per-user, `$XDG_CONFIG_HOME` and
  system locations, and whether the program each one starts exists; whether Firefox is a
  Snap or a Flatpak;
- whether the uhid broker socket exists.

Exit status 3 when this computer is not set up or the vault folder is missing, 1 when the
vault cannot be read or this device was removed from it.

`--json` prints one object:

```json
{
  "vault_dir": "...", "state_dir": "...", "set_up": true, "vault_found": true,
  "vault": {
    "device_name": "...", "device_id": "<hex>", "passkeys": 3,
    "devices_active": 2, "devices_removed": 0, "backed_up": true, "key_generation": 1,
    "this_device_removed": false,
    "sync": { "skipped_files": [{"path": "...", "reason": "..."}], "ignored_files": 0,
              "locked_out": false, "rotation_conflict": false,
              "rollback_suspected": false, "maintenance_error": null }
  },
  "vault_error": null,
  "approval": { "methods": ["polkit", "pin"], "error": null, "zenity": true,
                "pin_set": true, "pin_locked": false, "polkit_action": "/usr/share/..." },
  "firefox": { "manifests": [{"path": "...", "scope": "your user", "state": "ok",
                              "program": "/usr/lib/hirz/hirz-nmh"}],
               "snap": false, "flatpak": false },
  "uhid_broker": { "socket": "/run/hirz/uhid.sock", "present": false }
}
```

Manifest `state` is `ok`, `missing`, `program_missing` or `invalid`.

### When another device removed this one

When the vault says that this computer was removed (another device ran `hirz
remove-device` for it), `hirz list`, `hirz delete`, `hirz devices`, `hirz devices approve`,
`hirz devices deny`, `hirz remove-device` and `hirz backup confirm` print "This computer
was removed from your hirz vault; its passkeys are no longer used here." with what to do
next, and exit with status 1. `hirz status` reports it too. hirzd and hirz-nmh stop using
the vault at the same time. Run `hirz forget-local` to delete this computer's keys.

### `hirz list [--site SITE] [--json]`

A table of passkeys: site (relying party id), account (user name, or display name), date
created (UTC) and the first 12 hex digits of the credential id. `--site` keeps one site
(exact match, case-insensitive). Names come from websites and are cleaned of control and
invisible characters before display. Private keys are never printed. Keys that OpenSSH made
on hirz (RP id `ssh:` or `ssh:NAME`) are shown as "SSH key" or "SSH key (NAME)"; `--site`
and `--json` use the raw RP id.

`--json` prints an array of objects with `site`, `site_name`, `user_name`,
`user_display_name`, `created_at` (unix seconds), `credential_id` (base64url),
`credential_id_hex`, `algorithm` (`ES256` or `EdDSA`), `discoverable` and `prf`.

### `hirz delete ID-PREFIX [--yes]`, `hirz delete SITE ACCOUNT [--yes]`

Deletes one passkey on all devices, after showing it and asking. ID-PREFIX is at least
four hex digits of the credential id. Imported passkeys keep their original credential id,
which can be shorter or longer than the 32 bytes hirz creates; a whole id typed in full
selects that passkey even when it is also the start of a longer id. SITE ACCOUNT matches the
user name or display name exactly. When several passkeys match, they are listed and nothing
is deleted. The site still
lists the passkey in your account; hirz reminds you to remove it there.

### `hirz devices [--json]`

Lists the devices of the vault: name, id prefix, date added, status (this computer,
active, removed).

The text output also says when devices are waiting for approval.

### `hirz devices approve [REQUEST]`

Lists the devices waiting to join (requests made with `join --request` that have not
expired) and, for the chosen one, shows its name, how long ago it asked (in the same words
as the hirz window: "less than a minute ago", "1 minute ago", "N minutes ago") and the four
verification words computed on this device. With one request it is chosen directly; with
several hirz lists them, warns that unexpected ones may be planted, and asks for a number.
REQUEST, at least four hex digits of the request id, picks one directly.

You must type `yes` to approve, and only if the new device shows exactly the same words.
There is no option to skip this question. Any other answer deletes the request (exit
status 4).

After `yes`, hirz requires user verification, as for a passkey: a hirz window shows the
device name and the four words again (Cancel has the focus), and then the first available
method of your approval config asks for your system password (polkit), your fingerprint or
your hirz PIN. Click-to-allow never counts here. The request stays waiting when the window is
cancelled or the check fails (exit status 4), or the window times out or the PIN is locked
(exit status 1). When no
verifying method is available, hirz refuses before showing the words (exit status 1) and
explains how to set a PIN with `hirz pin set` or install the polkit action; see
[approval.md](approval.md).

On approval hirz gives the new device the vault key, its key slot and a `device added`
entry. If the request changed or expired while you were checking, nothing is approved (exit
status 1). Exit status 1 also when no device is waiting.

### `hirz devices deny REQUEST`

Deletes the request whose id starts with REQUEST (at least four hex digits), so that device
cannot join with it.

### `hirz remove-device ID-PREFIX [--yes]`

Removes another device and rotates the vault key ([vault-format.md](vault-format.md),
section 9). Before asking, hirz explains that the device cannot read anything added or
changed afterwards, that it keeps whatever it already read, and that you should stop
sharing the folder with it in your sync tool. It then lists every site with a passkey in
the vault, since the removed device could have copied all of them, and advises replacing
those passkeys. This computer cannot remove itself.

After the yes/no question, hirz requires user verification, as for approving a device: a
hirz window shows the device name and id (Cancel has the focus), and then the first
available method of your approval config asks for your system password, your fingerprint
or your hirz PIN. Click-to-allow never counts. `--yes` skips only the yes/no question in the
terminal, never the window. Nothing is removed when the window is cancelled or the check
fails (exit status 4), or the window times out or the PIN is locked (exit status 1). When no
verifying method is available, hirz refuses before asking anything (exit status 1) and
explains how to set a PIN or install the polkit action.

### `hirz forget-local`

Deletes this computer's hirz keys from the state directory: the device secret, the key ring
and the event counter, and the recorded vault location. The vault folder is never touched,
nor are other devices or the hirz PIN. Use it on a computer that another device removed, or
to stop using hirz here. When the vault says this computer was removed, hirz asks a yes/no
question; otherwise it warns that this computer will lose access until it joins again and
you must type `forget`. Anything else changes nothing (exit status 4). Without keys there is
nothing to do (exit status 0).

This only makes an honest computer stop. Someone who copied the files before (see
[threat-model.md](threat-model.md)) keeps what they copied.

### `hirz pin set | change | reset | status`

Manages the hirz PIN through `hirz-uv`'s `PinStore` (Argon2id verifier in the device
state directory; rules in [approval.md](approval.md)).

- `set`: asks for a new PIN twice. Fails if a PIN exists.
- `change`: asks for the current PIN (a wrong one counts as a failed try), then the new
  one twice.
- `reset`: removes the PIN, which also clears a lock. When this computer is set up with a
  vault, you must type the vault's recovery phrase first.
- `status`: whether a PIN is set, the number of wrong tries, whether it is locked.

### `hirz export --cxf FILE [--plain]`

Writes every passkey as a FIDO Credential Exchange Format 1.0 document
([sync.md](sync.md#exporting-and-importing-passkeys)). FILE must not exist; it is created
with mode 0600.

- By default the document is encrypted with a passphrase you choose (at least 12
  characters, typed twice) in the envelope described in [sync.md](sync.md#encrypted-export-file).
- `--plain` writes the bare JSON document, for importing into another passkey manager.
  hirz explains the risk and asks you to type `yes` first.
- An export is a backup only once it is stored somewhere else, so hirz asks whether it is.
  Only a yes marks the backup as done (as `hirz backup confirm` does).

### `hirz import --cxf FILE`

Reads an encrypted hirz export (asks for the passphrase, three tries) or a plain CXF
document from any provider, checks every passkey, and adds the valid ones. It never
replaces a passkey that hirz already has: an identical one is reported as already present,
a different one with the same credential id is skipped. Credential ids of any length from 1
to 1023 bytes (the WebAuthn limit) are kept as they are. Exit status 6 when at least one
passkey was skipped; each one is listed with the reason.

### `hirz import --bitwarden FILE`

Reads the passkeys of a Bitwarden `.json` export, unencrypted or password protected (asks
for the file password, three tries). Account restricted exports, encrypted with the
Bitwarden account key, cannot be read; hirz explains how to export again. Only
`login.fido2Credentials` entries are read, and only P-256 passkeys are imported; passwords,
notes and other items are counted and ignored. Duplicates, skipped passkeys and the exit
status work as for `--cxf`. Details: [sync.md](sync.md#importing-from-bitwarden-and-keepassxc).

### `hirz import --keepassxc PATH`

Reads a KeePassXC `.passkey` file, or every `*.passkey` file in the folder PATH. P-256 and
Ed25519 passkeys are imported. KeePass XML exports are not supported. Duplicates, skipped
passkeys and the exit status work as for `--cxf`.

### `hirz backup confirm [--yes]`

Records that your passkeys exist somewhere other than this computer (a synced copy of the
vault folder, another device, or an export file stored elsewhere). From then on new
assertions carry the BS (backed up) flag on every device. hirz asks first unless `--yes`.

### `hirz setup firefox [--nmh-path PATH] [--force]`

Writes `~/.mozilla/native-messaging-hosts/hirz.json` from
`packaging/native-messaging/hirz.json`, with `path` set to the absolute, resolved path of
`hirz-nmh`: by default the `hirz-nmh` next to the running `hirz`, or `--nmh-path`. The file
is replaced atomically (mode 0644). An existing file that points elsewhere is only
replaced after a question, or with `--force`. System locations are never written. For a
Snap Firefox it explains the WebExtensions portal question and how to allow hirz in
advance; for a Flatpak Firefox it shows the experimental proxy setup
([extension.md](extension.md)).

## Exit status

| Status | Meaning |
|---|---|
| 0 | Done |
| 1 | The operation failed (file access, damaged vault, nothing matched, already set up) |
| 2 | Wrong arguments, or an ambiguous id prefix |
| 3 | hirz is not set up on this computer, or the vault folder is missing |
| 4 | Cancelled: you answered no, input ended, or the recovery phrase check failed |
| 5 | A wrong recovery phrase, PIN or passphrase, or a locked PIN |
| 6 | Import finished, but some passkeys were skipped |

Errors are printed on standard error as `hirz: <message>`.
