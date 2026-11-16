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
  too ("Requested by"). A site id or origin that is too long for the window loses its left
  part and keeps its right end, behind an ellipsis, because the right end holds the domain the
  site really belongs to (an id such as `accounts.example.com.` followed by 80 filler
  characters and `.evil.example` shows the end `.evil.example`, not the start).
- For OpenSSH security keys (`ssh-keygen -t ecdsa-sk` or `-t ed25519-sk`), whose RP id is
  `ssh:` or `ssh:NAME`, "SSH key" or "SSH key (NAME)" instead of the raw id. Logs keep the
  raw id. RP ids starting with `pam://` (pam-u2f), `io.systemd.home` and `io.systemd.cryptsetup` never reach a prompt: hirz refuses them
  (see [threat-model.md](threat-model.md)).
- The account: the one being created, or the one being used to sign in. When several
  accounts exist for the site, a list asks you to choose first ("Choose an account, then
  confirm it is you."; the method that follows depends on what is available).
- The name the site gives itself, labelled as such. Sites choose this name freely, so it is
  never shown in place of the site id.

Names come from the site and are treated as hostile. Before a name reaches a window, hirz
removes control characters, bidirectional overrides and every invisible character (the Unicode
default-ignorable code points, plus glyphs that draw nothing, such as U+2800), collapses
whitespace, keeps at most two combining marks after a character (every nonspacing and enclosing
mark of Unicode, so a letter followed by sixty marks of any script ends up with two),
replaces `< > & \` with look-alike characters and shortens long values. Question and information windows also get
`--no-markup`. zenity 4 does not apply `--no-markup` to the text of the account list (it reads
that text as markup) or to the text of the PIN entry (it reads it with mnemonics, so a single
`_` would vanish and underline the next character); for those two the cleaning above is the
protection, and hirz doubles `_` in entry text so that `my_bank.example` stays readable. A
test checks that no string in a list or entry window contains `< > & \` or a single `_`.

When the hirz icon is installed (`/usr/share/icons/hicolor/scalable/apps/hirz.svg`, or the
same path under `/usr/local`), hirz passes it with `--window-icon`. The path comes from that
fixed list, never from the environment. zenity 4 accepts the option with a deprecation
warning and shows the icon in the dialog; older versions use it as the window icon.

If a prompt is not answered within the ceremony timeout (120 seconds by default), hirz
closes it and the request fails with a timeout. Cancel or closing the window refuses the
request. A window that fails within a second and says on standard error that it cannot open
the display makes the method unavailable (the next one is tried); Cancel, which also exits
with status 1, never does, whatever zenity prints on standard error. `hirzd` caps the timeout
at 115 seconds even when the config file allows more, because the browser ends a CTAPHID
transaction after 120 seconds and the prompt must be gone before that; the Firefox extension and
the CLI use the configured value (up to 600).

Only one prompt is open at a time in a hirz process. `hirzd`, each `hirz-nmh` and each run of
the `hirz` CLI are separate processes that do not know about each other, so prompts of several
of them can be open at once. What happens to a request that arrives while a prompt is open in
its own process depends on the process. `hirz-nmh` answers requests one at a time and keeps up to
64 of them waiting behind the open prompt, in order; a request that finds the queue full gets a
busy answer (the page sees `NotAllowedError`). A request that waits is answered when its turn
comes, unless the page cancels it first. In `hirzd` the browser's transport carries one request
at a time (another request gets CTAPHID_ERR_CHANNEL_BUSY), and so does a new request that
arrives while an earlier one, which the browser already cancelled, still holds its window: the
window cannot be closed from outside and stays until it is answered or times out, and hirz does
not start another thread behind it. The approver itself also refuses a second prompt while one is
open, as a last line behind those two.

Prompts are counted when the first window of a request is about to open, so a request that ends
before that (no method available, polkit deciding by itself, a missing helper, a budget that is
already used up) costs nothing. At most `prompts_per_minute` (5 by default)
prompts per relying party id are shown per minute, and three times that many in total across all
ids, so a page that moves between host names does not get a fresh budget each time. Prompts for
choosing a security key ("Use hirz?", see below), for approving a device, for removing one, for
exporting and for repairing the vault folder have a key of their own and share the total. Further requests are refused without a
prompt. The counters are in memory, per running process: they limit a page or a local client that
keeps talking to one daemon. Every run of the `hirz` CLI is a new process, so the limit does not
apply there; its prompts follow a command you typed.

A request that ends before any window was shown, whatever the reason (no usable verification
method, the budget above, zenity or another helper missing, polkit answering by itself, an
unreadable config file), is reported by the approver as "nothing was shown". On the Firefox
extension path that is answered like "no credential for this site": the request goes back to
Firefox and its own sign-in interface, so a page cannot tell, from how fast or how a request
failed, whether hirz holds a passkey for it. Only a window the user saw can end in a refusal
(Cancel, a timeout, a wrong PIN too often). For `hirzd` the answer is the CTAP "not allowed"
status in both cases. The CLI does not use this path: its commands say which method is missing
and how to set it up.

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

Before it shows anything for this method, hirz runs the same check once without
`--allow-user-interaction`, which never asks anyone, to see what polkit would do on its own:

| preflight exit status | meaning | hirz result |
|---|---|---|
| 2 | a password is needed | the dialog and the check above follow |
| 0 | polkit grants the action without a password (a rule such as `return polkit.Result.YES` for administrators) | not a verification: the method is skipped with a note, and the next one is tried |
| 1 | polkit refuses without asking (a remote or inactive session, a rule) | the method is skipped with a note and the next one is tried; the request is not refused |
| 127 | check failed, for example the action is not installed | method unavailable, next method tried |

The polkit dialog text is fixed ("Confirm it is you to use hirz"); polkit does not
show which site is asking. That is why hirz shows its own dialog with the site first.

This method is the strongest against other programs running as you: the password is typed
into the polkit agent, which other programs cannot read, and polkitd decides the result,
not hirz.

hirz looks for helper programs in `/usr/bin`, `/bin`, `/usr/sbin`, `/usr/local/bin` and
`/run/current-system/sw/bin`, never in `PATH`. A helper is used only when it is a root-owned
executable that group and others cannot write, and every directory above it, both where hirz
looked and where a symbolic link ends, is owned by root and closed to group and others (a
directory with the sticky bit is accepted). A symbolic link in a directory that members of a
group can write, such as `/usr/local/bin` on Debian (group `staff`), is therefore never used.
`pkcheck` and `fprintd-verify` run with an empty environment except `PATH=/usr/bin:/bin` and
`LC_ALL=C`, so a changed `PATH` or `DBUS_SYSTEM_BUS_ADDRESS` cannot fake the answer; zenity
gets only `DISPLAY`, `WAYLAND_DISPLAY`, `XAUTHORITY`, `XDG_RUNTIME_DIR`, `XDG_SESSION_TYPE`,
`XDG_CURRENT_DESKTOP`, `XDG_DATA_DIRS`, `DBUS_SESSION_BUS_ADDRESS`, `HOME`, `LANG`, `LANGUAGE`,
`LC_ALL`, `LC_MESSAGES` and `LC_CTYPE` from its environment, so `LD_*` and `GTK_*` variables
never reach it.

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
short note ("Your fingerprint was not recognised."), or refuses when there is none. Misses are
also counted across requests, in `$XDG_STATE_HOME/hirz/fingerprint-misses`: after 9 in a row
the reader is not offered for 15 minutes, or until a verification by any method succeeds (a
match clears the count, too), so repeated tries by someone else do not start afresh with every
request. A damaged counter file counts as paused until a verified approval removes it. Scans
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

- Length: 4 to 63 characters, printable ASCII only (letters, digits, spaces and the punctuation
  of a US keyboard, no accents). A PIN typed into the zenity window and a PIN typed into a
  terminal must be the same bytes, and hirz does not normalise Unicode, so other characters are
  refused with a message instead of failing later. Before this rule was added, `hirz pin set`
  accepted other characters. A PIN made of them is refused as a format error at the prompt and
  does not match, so it has to be replaced with `hirz pin reset` (it asks for the recovery
  phrase) and a new PIN of printable ASCII.
- Storage: `$XDG_STATE_HOME/hirz/pin` (by default `~/.local/state/hirz/pin`), directory mode
  0700, file mode 0600. It holds a random 16-byte salt, the Argon2id output for the PIN
  (64 MiB, 3 passes, 4 lanes by default) and the failure counter. It never holds the PIN.
  Comparison is constant time.
- Retries: each attempt is counted on disk before the PIN is checked, so stopping hirz in the
  middle of a check does not give a free guess. Once 3 failures are recorded, hirz waits
  1, 2, 4, 8, 16 seconds (at most 30) before each further check. After 8 wrong PINs in a
  row the PIN is locked until it is reset with the hirz CLI. A correct PIN resets the counter.
  Malformed input (too short, too long, not printable ASCII) is rejected without counting.
- Within one request you may try again after a wrong PIN; the dialog shows how many
  attempts are left, and the window is shown at most 5 times per request. When the PIN is
  locked, hirz moves on to the next configured method. A PIN checked after the ceremony timeout
  (the back-off and the key derivation run after the window closed) does not approve.
- A PIN file that is damaged, or was replaced by one that hirz would not write (a weaker
  Argon2id setting), does not stop the request: the PIN method is skipped with the note "The
  hirz PIN file is damaged", before any PIN is asked for, and the next method runs. Without
  another method the request fails as unavailable.

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

Every change goes through a freshly named file (`O_EXCL`, mode 0600) and a rename, and is taken
under an exclusive lock on `pin.lock` in the same directory. `hirzd`, `hirz-nmh` and `hirz pin`
therefore never see a half-written file and never lose a failure count to each other: two
processes checking at the same moment each count their attempt. The key derivation and the
back-off wait run outside the lock.

The PIN protects against someone at your keyboard who does not know it. It does not protect
against a program running as you: such a program can read the verifier file and guess
offline (Argon2id makes this slow, not impossible), or replace the file. It does not stop
someone with a shell in your unlocked session either: when no PIN is set, `hirz pin set` asks
for nothing, the `methods` line of the config file is writable by you, and deleting the file
does the same as `hirz pin reset`. Such a person can set a PIN, list `pin` first in `methods`,
and then pass the user verification that approving a device or removing one asks for. User
verification by PIN means "someone who knows this PIN", not "the owner of the vault". The
system password and the fingerprint do not have this weakness; choose them for the strongest
guarantee (see [vault-format.md](vault-format.md), section 11).

## Click-to-allow

A zenity question showing the site and account, with Allow and Cancel; the focus starts on
Cancel so a stray Enter does not approve. On a sign-in with several accounts the question
comes after the account list: choosing an account in the list (its Continue button, or a stray
Enter on the list, which starts with the first row selected) never approves anything alone.
Click-to-allow still asks "Allow?" for the chosen account, with the focus on Cancel; the other
methods then ask for a password, a finger or the PIN. This sets UP and leaves UV unset: hirz
reports honestly that it did not verify you.

Click-to-allow is off by default and is enabled per site in the config file. It is refused
(the method is unavailable) whenever the site requires user verification, so such sites fall
back to a verifying method or fail.

## Choosing a security key

Browsers that look for an authenticator send a throwaway request (Firefox uses the RP id
`make.me.blink`, Chromium one that starts with a dot) to every security key they find. hirz
answers it with a question "Your browser is asking which security key to use. Use hirz?" with
Cancel focused. It creates nothing, and its approval is never reused for a real request. These
questions are rate limited like any other prompt (see above).

## Removing a device

`hirz remove-device` also always requires user verification. After the yes/no question in
the terminal (which `--yes` skips), hirz shows a zenity question with the device's name
(sanitized like site names) and the start of its id, Remove and Cancel, with the focus on
Cancel. Then the configured verifying methods run in order, as for pairing; the PIN and
fingerprint windows repeat the device. Click-to-allow never counts, and when no verifying
method is available no window is shown and the CLI explains how to set one up. Removal
prompts are counted under their own key for the prompt limit.

## Exporting passkeys

`hirz export` hands out every private key, so it always requires user verification, like
removing a device. After the plain-file warning and the passphrase (when the file is
encrypted), hirz shows a zenity question that gives the number of passkeys and says whether
the file is encrypted, with Export and Cancel and the focus on Cancel. Then the configured
verifying methods run in order, as for pairing; the PIN and fingerprint windows repeat the
number of passkeys. Click-to-allow never counts, `--yes` does not exist for this command, and
when no verifying method is available no window is shown and the CLI explains how to set one
up. The file is built and written only after the check passed. Export prompts are counted
under their own key for the prompt limit.

## Repairing the vault folder

`hirz repair --discard NAME` and `hirz repair --accept-fork` change which key changes the
vault follows, so both always require user verification, like removing a device. After the
question in the terminal (a yes/no for `--discard`, the typed word `follow` for
`--accept-fork`; `--yes` skips it), hirz shows a zenity question with Discard or Follow
folder and Cancel and the focus on Cancel. For a discard it names the key change (its folder name,
sanitized like site names) and says that everything built on it is deleted; for the other it
says that hirz goes on from the newest key change this computer followed that is still in the
folder, as the folder holds it now, and that devices it saw removed stay removed.
Then the configured verifying methods run in order, as for pairing; the PIN and fingerprint
windows repeat the action. Click-to-allow never counts, and when no verifying method is
available no window is shown and the CLI explains how to set one up. The vault is changed only
after the check passed. Repair prompts are counted under their own key for the prompt limit.
The approver trait refuses by default (`Approver::confirm_repair`), like the other device
changes.

## Approving a new device

`hirz devices approve` lets a new device join the vault and gives it every passkey, so it
always requires user verification. The comparison and the confirmation come in two steps, in
the terminal and again in the hirz window, so that nothing the other device chose can stand next
to the words while they are being compared.

The name is chosen by the device that asks, so anyone who can write to the synced folder can
make one up, and the words are public to anyone who can read it. A request called
`laptop MAPLE ORBIT ...`, planted next to the real one, would put the genuine words of the real
request on the first line of a prompt that showed the name first. So:

1. **Words only.** The terminal prints how long ago the request was made and the four words, and
   asks "Do all four words match?" (answer `yes`). After that, hirz shows a zenity question with
   how long ago it asked, the four verification words in capitals, and nothing else the other
   device sent, not even its name: "Do these 4 words match the ones on the new device? Only
   approve a device you are setting up yourself right now." (button "They match", focus on
   Cancel). How long ago it asked uses the same words in both ("less than a minute ago", "1
   minute ago", "N minutes ago"). When several requests wait, the list the terminal prints to
   choose from has a number, the four words, the age and the start of the request id of each,
   and no name.
2. **Name, after the words matched.** Only then does the terminal print the name, labelled
   "That device calls itself (hirz cannot check the name)" and put in brackets, and ask "Is that
   the name of the device you are setting up?" (`yes`). The window does the same in a second
   question, "The words matched. Approve this device?", with the name labelled "Name chosen by
   that device (hirz cannot check it)" in brackets, a reminder that approving gives it every
   passkey, and the buttons Approve and Cancel (focus on Cancel). hirz-uv lowercases a word in
   capitals inside the name and turns brackets in it into look-alikes, so the capitals stay the
   words' own and the name cannot close its brackets. A "no" at either step in the terminal
   deletes the request; Cancel in the window leaves it waiting.

A request is listed only when its name is 1 to 32 characters of ASCII letters, digits, spaces and
`- _ .`, with further rules that keep a name from reading as the verification words (the exact
rules are in [vault-format.md](vault-format.md), section 11). A request with any other name is
not shown and is deleted after 20 minutes. A new device names itself with the host name or
`--name`, reduced to those rules (other characters become `-`, words in capitals are lowercased,
the result is cut to 32 characters, and `hirz join --request` says which name it used); a name
that cannot be repaired becomes `new-device`. These rules are a second line: the order of the
steps is what keeps the name out of the comparison.

Then the configured verifying methods run in order: system password, fingerprint or hirz
PIN (the PIN and fingerprint windows repeat the device's name, labelled the same way, and no
words: they come after the comparison). Pairing is approved only when one of them succeeds.
Click-to-allow is never used for pairing, whatever the `click_to_allow` list holds, and when no
verifying method is available no window is shown and the CLI explains how to set a PIN or install
the polkit action. Cancel or a failed check leaves the request waiting. The busy rule and the
prompt limit apply as for sites, with all pairing prompts counted under one shared key (the two
questions of one approval count once).

## Configuration

`$XDG_CONFIG_HOME/hirz/config` (by default `~/.config/hirz/config`). One `key = value` per
line; lines starting with `#` are comments. Unknown keys, repeated keys and malformed values
are errors, and every approval fails until the file is fixed.

```
# Verifying methods in order of preference. Methods that are not available are skipped.
methods = polkit, fingerprint, pin
# Sites where a click is enough when the site does not require verification.
click_to_allow = example.com, other.example
# Seconds for the whole request, all dialogs included (10 to 600; hirzd caps it at 115).
timeout = 120
# Prompts per site per minute (1 to 60); three times as many are allowed in total.
prompts_per_minute = 5
```

Site ids are host names in lowercase ASCII (internationalized names in their `xn--` form)
and match exactly: `example.com` does not cover `login.example.com`.

When no method is available (no polkit action, no enrolled finger, no PIN, and the site not
listed for click-to-allow), the request fails as unavailable. Approving a new device ignores
`click_to_allow` and needs one of the verifying methods. The `uv` option that `hirzd` reports in
CTAP2 getInfo follows this: it is false when none of the configured verifying methods can be
used right now (checked every few seconds), so a browser does not ask for user verification that
hirz cannot give and click-to-allow sites keep working.

## Requirements

- `zenity` 4 or newer (hirz-uv was tested against zenity 4.2). hirz runs `zenity --version`
  once and refuses to show prompts with an older one, because the options below behave
  differently in zenity 3; a version that cannot be read does not block. Without zenity no
  prompt can be shown and every request fails as unavailable, with a message on standard error
  that names the directories searched.
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
- A PIN verifier file can be read or replaced by programs running as you, and a PIN can be
  set by anyone at a shell of your session (see "hirz PIN").
- Programs running as you can draw look-alike dialogs. hirz's dialog shows the site so you
  can notice requests you did not start.
- On an X11 session every X client, a sandboxed application with access to the X11 socket
  included, can read and click the windows of other clients, take their keyboard input (the
  PIN as you type it) and read the screen, and programs that use the accessibility interfaces
  (AT-SPI) of your desktop can do much the same. Wayland compositors keep clients apart by
  default. On X11 prefer the system password, whose dialog belongs to the polkit agent, over
  the hirz PIN, and do not enable click-to-allow for sites you care about.
- The windows are drawn by zenity and the desktop: hirz cannot tell whether another window sits
  on top of one of them.

## zenity 4 behaviour hirz relies on

Found on a real GNOME desktop with zenity 4.2.1; the unit tests use a scripted runner, so
these are the facts the scripts encode:

- `--list` does not treat `--` as the end of options: it becomes the first table cell and
  shifts every column. hirz passes no `--`; instead no table cell may start with `-` (a
  leading dash in a site-supplied name becomes U+2010 HYPHEN, empty fields show `(none)`).
- A hidden print column is not reliable. The account number column stays visible and is
  printed with `--print-column=1`; hirz reads the first `|`-separated field.
- Every value that comes from a site is passed as `--option=value` (or as a table cell that
  cannot start with `-`), never as a separate argument that could be read as an option.
  Question and information windows also get `--no-markup`. The text of `--list` is read as
  markup and the text of `--entry` with mnemonics whatever `--no-markup` says, so those two rely
  on the cleaning described under "What the prompt shows".
- `--progress` does not accept `--no-markup`, so the fingerprint window is a `--question`
  (or `--info` when there is no other method) whose OK button is "Use password instead"
  (or Cancel), not a progress bar.
- `--window-icon` prints a deprecation warning on standard error and is treated as `--icon`.
  It is accepted by every dialog type hirz uses.
