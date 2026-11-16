# Approving passkey requests

hirz never signs a request with the user-present flag without a fresh approval from you (silent existence checks from the browser are answered with that flag unset, like a hardware key; see `docs/threat-model.md`). The `hirz-uv` crate asks for
that approval. There are four ways to give it. Three of them verify that it is you and set
the UV (user verified) flag; one only shows that someone clicked and sets UP (user present)
alone.

| Method | Flags | Default | What proves it is you |
|---|---|---|---|
| System password (polkit) | UP + UV | on when the polkit action is installed | Your login password, asked by your desktop's polkit agent |
| Fingerprint (fprintd) | UP + UV | on when a finger is enrolled | A finger on the reader |
| hirz PIN | UP + UV | on once you set a PIN | A PIN that hirz checks itself |
| Click-to-allow | UP only | off, opt-in per site | Nothing: someone clicked Allow |

Every approval needs a prompt drawn by hirz itself (with zenity) that shows the site. A web
page cannot draw, hide or click it.

## What the prompt shows

- The relying party id (the site, such as `example.com`) in the title and as the first line
  of the dialog. On the Firefox extension path, the origin of the requesting page is shown
  too ("Requested by").
- For OpenSSH security keys (`ssh-keygen -t ecdsa-sk` or `-t ed25519-sk`), whose RP id is
  `ssh:` or `ssh:NAME`, "SSH key" or "SSH key (NAME)" instead of the raw id. Logs keep the
  raw id. RP ids starting with `pam://` (pam-u2f) never reach a prompt: hirz refuses them
  (see [threat-model.md](threat-model.md)).
- The account: the one being created, or the one being used to sign in. When several
  accounts exist for the site, a list asks you to choose first ("Choose an account, then
  confirm it is you."; the method that follows depends on what is available).
- The name the site gives itself, labelled as such. Sites choose this name freely, so it is
  never shown in place of the site id.

Names come from the site and are treated as hostile. hirz passes `--no-markup` to zenity,
removes control characters, bidirectional overrides and invisible characters, collapses
whitespace, replaces `< > & \` with look-alike characters, and shortens long values.

When the hirz icon is installed (`/usr/share/icons/hicolor/scalable/apps/hirz.svg`, or the
same path under `/usr/local`), hirz passes it with `--window-icon`. The path comes from that
fixed list, never from the environment. zenity 4 accepts the option with a deprecation
warning and shows the icon in the dialog; older versions use it as the window icon.

If a prompt is not answered within the ceremony timeout (120 seconds by default), hirz
closes it and the request fails with a timeout. Cancel or closing the window refuses the
request. Only one prompt is open at a time; a request that arrives meanwhile is refused.
At most 5 prompts per site per minute are shown (in memory, per running hirz process);
further requests are refused without a prompt.

## System password (polkit)

After you confirm the site in hirz's dialog, hirz runs:

```
pkcheck --action-id dev.hirz.authenticate --process <pid>,<start time>,<uid> --allow-user-interaction
```

for its own process, with the start time read from `/proc/self/stat` (the three-part form
avoids the process id reuse races described in pkcheck(1)). Your desktop's polkit agent then
asks for your login password. The action uses `auth_self`, not `auth_self_keep`, so polkit
asks every time and remembers nothing.

| pkcheck exit status | hirz result |
|---|---|
| 0, authorized | approved, UV set |
| 1, not authorized | refused |
| 3, dialog dismissed | refused |
| 2, no polkit agent in the session | method unavailable, next method tried |
| 127, check failed (for example, action not installed) | method unavailable, next method tried |
| 126 or anything else | internal error |

The polkit dialog text is fixed ("Confirm it is you to use hirz"); polkit does not
show which site is asking. That is why hirz shows its own dialog with the site first.

This method is the strongest against other programs running as you: the password is typed
into the polkit agent, which other programs cannot read, and polkitd decides the result,
not hirz.

hirz only runs helper programs from root-owned system directories (`/usr/bin`, `/bin` and
similar), never from `PATH`, and runs `pkcheck` and `fprintd-verify` with an empty
environment, so a changed `PATH` or `DBUS_SYSTEM_BUS_ADDRESS` cannot fake the answer.

### Installing the polkit action

The action file is `packaging/polkit/dev.hirz.authenticate.policy`. Distribution packages
install it. For a manual or development install:

```
sudo install -o root -g root -m 0644 packaging/polkit/dev.hirz.authenticate.policy /usr/share/polkit-1/actions/
pkaction --action-id dev.hirz.authenticate --verbose
```

polkitd picks up new action files on its own. If `pkaction` does not list the action, run
`sudo systemctl restart polkit`. hirz offers this method only when the file is present in
`/usr/share/polkit-1/actions/` (or `/usr/local/share/polkit-1/actions/`) and `pkcheck` is
installed.

The polkit agent must be able to find the session of the hirz process. Recent polkit
versions fall back to your graphical session for processes started by a user service
manager; if `pkcheck` exits with status 2 in your setup, polkit is skipped and the next
method is used.

## Fingerprint (fprintd)

hirz uses the fprintd command line tools, not a D-Bus library. To decide whether the method
is available it runs `fprintd-list <your user>` and looks for an enrolled finger. To verify,
it runs `fprintd-verify` with the ceremony timeout and, while it runs, shows a window with
the site and account (or the device, when approving or removing one) and "Touch the
fingerprint reader." The window has a Cancel button and, when another method is configured
and usable, a "Use password instead" (or "Use PIN instead") button. Cancel stops
`fprintd-verify` and refuses the request; the other button stops it and goes straight to
that method without counting as a failure. A match closes the window.

A verification counts only when all of the following hold: `fprintd-verify` exited by itself
with status 0, its output is valid UTF-8, and the only final result line is
`Verify result: verify-match (done)`. Partial output, a killed process or any other result
never counts as a match.

When the finger is not recognised the window comes back with "Not recognised. Try again
(N left)."; after 3 misses in one request hirz moves on to the next configured method with a
short note ("Your fingerprint was not recognised."), or refuses when there is none. Scans
the reader could not use (`verify-retry-scan`, `verify-swipe-too-short`,
`verify-finger-not-centered`, `verify-remove-and-retry`) show a short hint and do not count
as misses, up to 5 per request. A reader error (`verify-unknown-error`,
`verify-disconnected` or unexpected output) also moves on to the next method with a note.
When no finger is enrolled (`fprintd-list` says so, or `fprintd-verify` reports
`NoEnrolledPrints`), fingerprint is unavailable and hirz says once: "Set up your fingerprint
in Settings > Users, or run fprintd-enroll." (in the next window and on standard error).

**Weakness.** fprintd's own policy lets any program in your active session start a
fingerprint check without authentication. A fingerprint approval therefore proves that a
finger was presented, not which program asked for it: a program running as you could start
its own check at the moment you touch the reader for hirz. Prefer the system password when
other programs running as you are a concern.

## hirz PIN

The PIN is checked by hirz itself, so it works without polkit or a fingerprint reader. hirz
asks for it with a hidden-text zenity entry that also shows the site and account.

- Length: at least 4 characters (Unicode code points) and at most 63 bytes, as in CTAP.
- Storage: `$XDG_STATE_HOME/hirz/pin` (by default `~/.local/state/hirz/pin`), directory mode
  0700, file mode 0600. It holds a random 16-byte salt, the Argon2id output for the PIN
  (64 MiB, 3 passes, 4 lanes by default) and the failure counter. It never holds the PIN.
  Comparison is constant time.
- Retries: each attempt is counted on disk before the PIN is checked, so stopping hirz in the
  middle of a check does not give a free guess. Once 3 failures are recorded, hirz waits
  1, 2, 4, 8, 16 seconds (at most 30) before each further check. After 8 wrong PINs in a
  row the PIN is locked until it is reset with the hirz CLI. A correct PIN resets the counter.
  Malformed input (too short or too long) is rejected without counting.
- Within one request you may try again after a wrong PIN; the dialog shows how many
  attempts are left. When the PIN is locked, hirz moves on to the next configured method.

The verifier file is rewritten atomically and has this layout:

```
hirz-pin 1
kdf argon2id <m_cost_kib> <t_cost> <p_cost>
salt <hex>
hash <hex>
failures <n>
```

Argon2id parameters that are out of range, or below the ones hirz would use for a new PIN,
make the file corrupt, so a replaced file cannot weaken the check.

The PIN protects against someone at your keyboard who does not know it. It does not protect
against a program running as you: such a program can read the verifier file and guess
offline (Argon2id makes this slow, not impossible), or replace the file.

Two hirz processes checking a PIN at the very same moment can each count only one of the
two attempts. This allows at most one extra guess per concurrent process.

## Click-to-allow

A zenity question showing the site and account, with Allow and Cancel; the focus starts on
Cancel so a stray Enter does not approve. On a sign-in with several accounts, choosing the
account in the list is the click. This sets UP and leaves UV unset: hirz reports honestly that
it did not verify you.

Click-to-allow is off by default and is enabled per site in the config file. It is refused
(the method is unavailable) whenever the site requires user verification, so such sites fall
back to a verifying method or fail.

## Removing a device

`hirz remove-device` also always requires user verification. After the yes/no question in
the terminal (which `--yes` skips), hirz shows a zenity question with the device's name
(sanitized like site names) and the start of its id, Remove and Cancel, with the focus on
Cancel. Then the configured verifying methods run in order, as for pairing; the PIN and
fingerprint windows repeat the device. Click-to-allow never counts, and when no verifying
method is available no window is shown and the CLI explains how to set one up. Removal
prompts are counted under their own key for the prompt limit.

## Approving a new device

`hirz devices approve` lets a new device join the vault and gives it every passkey, so it
always requires user verification. After the typed confirmation in the terminal, hirz shows
a zenity question with the name of the new device (from the request, so it is sanitized
like site names), how long ago it asked and the four verification words in capitals, and
asks: "Do these 4 words match the ones on the new device? Only approve a device you are
setting up yourself right now." The focus starts on Cancel. How long ago it asked uses the
same words as the terminal ("less than a minute ago", "1 minute ago", "N minutes ago").

Then the configured verifying methods run in order: system password, fingerprint or hirz
PIN (the PIN and fingerprint windows repeat the device name and words). Pairing is
approved only when one of them succeeds. Click-to-allow is never used for pairing, whatever
the `click_to_allow` list holds, and when no verifying method is available no window is shown
and the CLI explains how to set a PIN or install the polkit action. Cancel or a failed check
leaves the request waiting. The busy rule and the prompt limit apply as for sites, with all
pairing prompts counted under one shared key.

## Configuration

`$XDG_CONFIG_HOME/hirz/config` (by default `~/.config/hirz/config`). One `key = value` per
line; lines starting with `#` are comments. Unknown keys, repeated keys and malformed values
are errors, and every approval fails until the file is fixed.

```
# Verifying methods in order of preference. Methods that are not available are skipped.
methods = polkit, fingerprint, pin
# Sites where a click is enough when the site does not require verification.
click_to_allow = example.com, other.example
# Seconds for the whole request, all dialogs included (10 to 600).
timeout = 120
# Prompts per site per minute (1 to 60).
prompts_per_minute = 5
```

Site ids are host names in lowercase ASCII (internationalized names in their `xn--` form)
and match exactly: `example.com` does not cover `login.example.com`.

When no method is available (no polkit action, no enrolled finger, no PIN, and the site not
listed for click-to-allow), the request fails as unavailable. Approving a new device ignores
`click_to_allow` and needs one of the verifying methods.

## Requirements

- `zenity` (hirz-uv was tested against zenity 4.2). Without it no prompt can be shown and
  every request fails as unavailable, with a message on standard error.
- For the system password: polkit (`pkcheck`), a polkit authentication agent in your
  desktop session, and the hirz polkit action installed.
- For fingerprints: `fprintd` and an enrolled finger (`fprintd-enroll`).

## Limits

These methods protect against web pages and against people at your computer. They do not
protect against malware running as your user, which can read the unlocked vault directly
(see [threat-model.md](threat-model.md)). Within that limit:

- The system password is the hardest to fake: the decision is made by polkitd, outside
  your user.
- A fingerprint shows that a finger touched the reader, not which program asked.
- A PIN verifier file can be read or replaced by programs running as you.
- Programs running as you can draw look-alike dialogs. hirz's dialog shows the site so you
  can notice requests you did not start.

## zenity 4 behaviour hirz relies on

Found on a real GNOME desktop with zenity 4.2.1; the unit tests use a scripted runner, so
these are the facts the scripts encode:

- `--list` does not treat `--` as the end of options: it becomes the first table cell and
  shifts every column. hirz passes no `--`; instead no table cell may start with `-` (a
  leading dash in a site-supplied name becomes U+2010 HYPHEN, empty fields show `(none)`).
- A hidden print column is not reliable. The account number column stays visible and is
  printed with `--print-column=1`; hirz reads the first `|`-separated field.
- Every value that comes from a site is passed with `--no-markup` and as `--option=value`,
  never as a separate argument that could be read as an option.
- `--progress` does not accept `--no-markup`, so the fingerprint window is a `--question`
  (or `--info` when there is no other method) whose OK button is "Use password instead"
  (or Cancel), not a progress bar.
- `--window-icon` prints a deprecation warning on standard error and is treated as `--icon`.
  It is accepted by every dialog type hirz uses.
