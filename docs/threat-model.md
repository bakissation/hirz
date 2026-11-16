# Threat model

hirz is a software authenticator. It keeps passkeys on your computer, encrypted, and it can
sync them between your devices. This page says plainly what it protects against and what it
does not.

## What hirz protects against

- **Phishing.** A passkey only works for the site it was created for.
  - Virtual security key: the browser binds the site, exactly as for a hardware key.
  - Extension: hirz takes the origin from Firefox's report for the requesting page, and the
    native host checks the relying party id against the public suffix list (the extension
    only compares the id with the page's host name as a shortcut). A page cannot claim
    another site or a whole public suffix such as `com`.
- **Silent use by a web page.** Every signature with the user-present flag needs a prompt
  drawn by hirz, outside the page. A page cannot draw, hide or click it. Browsers check
  silently whether a key holds one of a site's credentials before they ask the user
  (getAssertion with `up: false`); hirz answers these checks like a hardware security key,
  with a signature whose user-present flag is not set. Relying parties reject such
  signatures for sign-in. The check reveals to local processes whether a credential exists
  for a site, which processes running as you can learn from the vault anyway.
- **A stolen or copied sync folder.** Records are encrypted with a random 256-bit vault key.
  The folder does not contain anything derived from a password, so it cannot be attacked
  offline by guessing passwords. It does reveal metadata: how many records and devices exist,
  file sizes and timestamps.
- **A stolen laptop that is powered off**, when the disk is encrypted (full-disk encryption
  is assumed; hirz's local device secret is a file protected by your account).
- **Tampering with synced files.** Every record is authenticated, and every vault key change is
  signed by a device of the vault. Damaged or forged files are skipped and reported, and
  symlinks in the folder are never followed. Files can still be deleted or held back by
  whoever controls the folder: hirz reports it when the newest files disappear or a key
  change it already followed is deleted or rewritten, but not when a single older file is
  held back, so a passkey you deleted can come back (`docs/vault-format.md`, section 10). A
  removed device that can still write to the folder is covered under "Remote revocation" below.

## What hirz does not protect against

- **Malware running as your user.** While you are logged in, a program running as you can
  read hirz's local device secret, decrypt the vault and copy your passkeys. A hardware key
  (or a TPM-bound credential) is the answer if this matters to you. hirz still requires an
  approval prompt for every signature with the user-present flag it makes itself, but it
  cannot stop a program that reads the files directly.
- **A compromised browser or a compromised hirz extension update.** It could show you one
  site and ask hirz to sign for another site that it claims is the page's origin. The native
  host re-validates origin and relying party id, but it cannot detect a browser that lies.
- **Other programs that can start the native host.** `hirz-nmh` cannot tell Firefox from
  another process: anything that can run it as you, or reach it through the WebExtensions
  portal or `xdg-native-messaging-proxy` from a sandbox that has no access to your home
  folder, can claim any origin. A signature still needs the approval prompt, which shows
  the claimed origin. The account list the host gives for conditional mediation needs no
  prompt and contains credential ids and user names (not credProtect level 3 ones).
- **Other FIDO clients that run as root.** Root-run clients (pam-u2f in `sudo`, `login` or a
  screen locker, `systemd-cryptsetup` with `fido2-device=auto`, `systemd-homed`, `fido2-token`
  under `sudo`) list every FIDO device whoever owns its node, so they also reach a device
  created by a program running as the user at the console. The broker only gives a device
  to users with an active session on a seat, but that user's programs can still stand in
  for hirz with their own authenticator toward those clients. See `docs/uhid.md`
  ("What this does not cover") for the group-restricted socket that closes this on shared
  computers.
- **Fingerprint prompts started by other programs.** fprintd lets any of your processes start
  a fingerprint check. A fingerprint approval proves a finger was presented, not which
  program asked. Use the system password method if this matters to you.
- **A hirz PIN that someone else set.** The PIN is a verifier file in your state directory:
  with a shell in your unlocked session, a person (or a program) can set a PIN of its own, put
  `pin` first in the `methods` line of the approval config and then pass the user verification
  that approving or removing a device and exporting passkeys ask for. A PIN protects against
  a person at your keyboard who does not know it, not against one who can run commands as you.
  The system password and the fingerprint cannot be set up that way (`docs/approval.md`).
- **Other programs on an X11 desktop.** Every X client can read and click the approval
  windows and read the PIN as it is typed, a sandboxed one that has the X11 socket included;
  programs using the accessibility interfaces can do much the same. Wayland keeps clients
  apart. On X11 use the system password method and do not enable click-to-allow for sites you
  care about (`docs/approval.md`, "Limits").
- **Remote revocation.** Removing a lost device rotates the vault key, so the lost device
  cannot read passkeys that a device which saw the removal creates afterwards. Key changes the
  lost device makes afterwards with the old keys, under its own name or a made-up one, are
  ignored by every device that has seen the removal and rejected by every other device while
  the removal is in the folder; a device that saw the removal keeps it in force even when the
  removal is deleted from the folder or a fork is accepted. Limits, while the lost device can
  still change the synced folder:
  - It can delete the removal before a device that has not seen it yet syncs; that device then
    still trusts it, and the devices that did see the removal report a fork (`hirz repair`
    shows it and settles it after user verification).
  - Until a device has seen the removal, it trusts the lost device: the lost device can show
    it changed passkeys and read what that device writes before it catches up. Nothing of that
    lasts: once the removal is known, every change the lost device made after it, and every
    device removal it caused, is void on every device, since changes are signed by the device
    that made them and the removal lists what that device had made before. Devices that saw
    the removal never write under a key the lost device holds.
  - Devices the lost device approved while it was trusted keep their access when it is
    removed. Someone holding it can approve a device of their own before you remove it, and
    name it like one of yours. `hirz remove-device` lists every device approved through the
    one you remove and warns before it asks, and `hirz devices` marks devices in use that
    share a name; remove the ones you did not approve.

  Stop sharing the folder with a lost device as part of removing it. Passkeys the lost device
  already decrypted stay usable by whoever holds it: hirz lists the affected sites so you can
  replace those passkeys.
  A removed device that runs hirz and syncs the change stops serving passkeys and says so,
  and `hirz forget-local` deletes its keys. That only makes an honest device stop: a thief
  who copied the device secret, the key ring and the vault folder (or who runs a modified
  hirz) is not stopped by it and keeps every passkey the device could read before the
  removal. Replacing those passkeys at each site is the only remedy.
- **A recovery phrase that someone else learned.** Every vault key, including those created
  after removing a device, is also sealed to the recovery key, and the recovery key cannot be
  changed yet. Whoever has the 24 words and a copy of the folder can read every passkey, now
  and later. If the phrase was typed on a computer you no longer trust, or the paper was seen,
  create a new vault, export your passkeys from the old one and import them.
- **Secrets in memory.** While hirzd, the native host or a `hirz` command runs, the vault is
  decrypted in its memory, and the keys stay there until the process ends. Only hirzd can lock
  its memory against swapping, and only with `HIRZ_MLOCK=1`; the native host and the command
  line tool never do, so use encrypted swap (or none) and turn off core dumps. Secrets are
  wiped from memory when hirz is done with them where the code controls the buffer. The files
  that hold passkeys (an import, an export) are read and built in buffers sized beforehand, so
  they never grow and leave no copy behind; a typed secret is read from the terminal without
  the standard library's input buffer; and terminal echo is switched back on when Ctrl-C ends
  a hidden prompt. The JSON and CBOR readers wipe the text and bytes they have built when a
  parse fails, and the values they return when those are dropped. Copies can still remain in
  freed memory (the buffers of the cryptographic libraries, text a program builds from a value
  or a document it writes out) and in swap, so this is a best effort, not a guarantee.
- **Logging in to the computer hirz runs on.** hirz passkeys are synced software keys:
  whoever can read the vault on any of your devices holds them, so they must not unlock the
  machine itself. hirz refuses every request whose RP id starts with `pam://` (pam-u2f, used
  for login, sudo and screen unlock) or is `io.systemd.home` (systemd-homed) or
  `io.systemd.cryptsetup` (`systemd-cryptenroll`, LUKS unlock) with `CTAP2_ERR_NOT_ALLOWED`,
  without a prompt. This also avoids an unlock screen or initrd that waits for a hirz approval
  it cannot show. The list is fixed (`hirz-core`, `machine_login`): pam-u2f accepts any
  `origin=` and `appid=` an administrator sets, and a custom value that looks like a host name
  cannot be told from a web site, so keep hirz out of such a setup yourself. Use a hardware
  security key for machine login.
- **Sites that refuse software authenticators.** Some relying parties require hardware
  attestation or allow only certain authenticators. hirz uses `none` attestation and will be
  refused there.

## Trust boundaries

See `docs/architecture.md`. In short: the page is hostile, the extension background is
trusted only for the origin Firefox attaches to messages, the native host and daemon own all
policy, approval and signing, and the root broker only relays 64-byte HID reports for a device
it created itself.

## Reporting

See `SECURITY.md`.
