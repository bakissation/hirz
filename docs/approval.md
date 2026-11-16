# Approving passkey requests

hirz never signs a request without a fresh approval from you. The `hirz-uv` crate asks for
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
- The account: the one being created, or the one being used to sign in. When several
  accounts exist for the site, a list asks you to choose first.
- The name the site gives itself, labelled as such. Sites choose this name freely, so it is
  never shown in place of the site id.

Names come from the site and are treated as hostile. hirz passes `--no-markup` to zenity,
removes control characters, bidirectional overrides and invisible characters, collapses
whitespace, replaces `< > & \` with look-alike characters, and shortens long values.

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

The polkit dialog text is fixed ("Confirm it is you to use a passkey"); polkit does not
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
after you confirm the site in hirz's dialog, it runs `fprintd-verify` with the ceremony
timeout and kills it when the time is up.

A verification counts only when all of the following hold: `fprintd-verify` exited by itself
with status 0, its output is valid UTF-8, and the only final result line is
`Verify result: verify-match (done)`. Partial output, a killed process or any other result
never counts as a match. A non-matching finger may be retried up to 3 times within one
request; device errors and missing enrolment make the method unavailable.

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
listed for click-to-allow), the request fails as unavailable.

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
