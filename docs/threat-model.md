# Threat model

hirz is a software authenticator. It keeps passkeys on your computer, encrypted, and it can
sync them between your devices. This page says plainly what it protects against and what it
does not.

## What hirz protects against

- **Phishing.** A passkey only works for the site it was created for.
  - Virtual security key: the browser binds the site, exactly as for a hardware key.
  - Extension: hirz checks the origin Firefox reports for the requesting page, and checks
    the relying party id against the public suffix list again in the native host. A page
    cannot claim another site or a whole public suffix such as `com`.
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
- **Tampering with synced files.** Every record is authenticated. Damaged or forged files are
  skipped and reported.

## What hirz does not protect against

- **Malware running as your user.** While you are logged in, a program running as you can
  read hirz's local device secret, decrypt the vault and copy your passkeys. A hardware key
  (or a TPM-bound credential) is the answer if this matters to you. hirz still requires an
  approval prompt for every signature with the user-present flag it makes itself, but it
  cannot stop a program that reads the files directly.
- **A compromised browser or a compromised hirz extension update.** It could show you one
  site and ask hirz to sign for another site that it claims is the page's origin. The native
  host re-validates origin and relying party id, but it cannot detect a browser that lies.
- **Fingerprint prompts started by other programs.** fprintd lets any of your processes start
  a fingerprint check. A fingerprint approval proves a finger was presented, not which
  program asked. Use the system password method if this matters to you.
- **Remote revocation.** Removing a lost device rotates the vault key, so the lost device
  cannot read passkeys created afterwards. Passkeys the lost device already decrypted stay
  usable by whoever holds it: hirz lists the affected sites so you can replace those passkeys.
  A removed device that runs hirz and syncs the change stops serving passkeys and says so,
  and `hirz forget-local` deletes its keys. That only makes an honest device stop: a thief
  who copied the device secret, the key ring and the vault folder (or who runs a modified
  hirz) is not stopped by it and keeps every passkey the device could read before the
  removal. Replacing those passkeys at each site is the only remedy.
- **Logging in to the computer hirz runs on.** hirz passkeys are synced software keys:
  whoever can read the vault on any of your devices holds them, so they must not unlock the
  machine itself. hirz refuses every request whose RP id starts with `pam://` (pam-u2f, used
  for login, sudo and screen unlock) with `CTAP2_ERR_NOT_ALLOWED`, without a prompt. This
  also avoids an unlock screen that waits for a hirz approval it cannot show. Use a hardware
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
