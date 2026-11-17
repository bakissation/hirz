# The uhid frontend

hirz presents itself to browsers as a USB security key. The kernel's uhid driver lets a
process create a HID device from user space; browsers then find a `/dev/hidrawN` node with
the FIDO report descriptor and speak CTAP2 over CTAPHID to it, exactly as they would with a
hardware key. The browser performs the WebAuthn client role (origin checks, RP ID
validation), and hirz only ever sees CTAP requests.

```
browser --hidraw--> kernel HID core --uhid--> hirz-uhid-broker (root) --64-byte reports--> hirzd (user)
                                               owns /dev/uhid               Unix socket      CTAPHID + CTAP2
```

## Components

- `hirz-sys::uhid`: the `struct uhid_event` ABI from `include/uapi/linux/uhid.h` as safe,
  byte-level encode and decode functions. uhid needs no ioctls: one event per `write(2)`
  and one per `read(2)` on `/dev/uhid`. Events are packed, in host byte order, and 4376
  bytes long.
- `hirz-uhid-broker`: a small root process that owns `/dev/uhid`.
- `hirz-ctap::hid`: the CTAPHID transport (CTAP 2.2 section 11.2), a pure state machine
  plus a thin I/O loop.
- `hirzd`: the user daemon. It connects to the broker, hardens itself, and runs CTAPHID and
  the authenticator.

## How the broker works

The broker is started by systemd socket activation (`hirz-uhid-broker.socket`, socket
`/run/hirz/uhid.sock`) or by hand with `--listen PATH`. The unit in `packaging/systemd/` runs
`/usr/libexec/hirz/hirz-uhid-broker`, the path of the deb and rpm packages; a package with
another layout rewrites that line (the Arch package uses `/usr/lib/hirz`). For each
connection it:

1. Reads the peer credentials with `SO_PEERCRED`. The kernel records them at `connect`
   time, so the client cannot forge them.
2. Reads the client's hello: exactly 8 bytes, within 2 seconds in total. `hirzdev1` asks for
   a device and goes on below. `hirzprb1` is a probe (what `hirz status` sends): the broker
   answers `hirzok01` and closes the connection, without the checks below, without creating a
   device, without spending the uid's creation budget and without a log line. Anything else,
   end of input or the time running out closes the connection. At most 16 connections, and 2
   per uid, may wait for their hello at the same time; further ones are closed at once.
3. For a device, admits the peer only if every check in "Who may connect" below passes: the uid is
   between `--min-uid` (default 1000, never 0) and `--max-uid` (default 60513), the uid owns
   an active login session on a seat, the three hirz udev rule files are in effect, the uid has no
   device yet, fewer than `--max-connections` (default 8) devices exist and the uid has
   not created devices too fast. Refusal closes the socket. Refusals are logged at most
   once per uid every 30 seconds, with a count of the lines left out.
4. Opens `/dev/uhid` and writes `UHID_CREATE2` with fixed values: name
   `hirz virtual authenticator`, bus `BUS_USB`, vendor `0x1209`, product `0x0007`, the
   client's decimal uid in the `phys` field, and the FIDO report descriptor (usage page
   `0xF1D0`, usage `0x01`, one 64-byte input and one 64-byte output report, no report ids).
   Nothing in the request comes from the client.
5. Relays reports. Output reports (`UHID_OUTPUT`) go to the client as exactly 64 bytes;
   hidraw writers prefix the report number 0, so the kernel delivers 65 bytes and the
   broker strips the first byte. Every 64 bytes the client sends become one `UHID_INPUT2`.
   Anything else is dropped. Feature report requests (`UHID_GET_REPORT`,
   `UHID_SET_REPORT`) are answered with `EIO`, since the descriptor declares none.
6. When the client disconnects, or the uid stops passing the session check (re-checked every
   5 seconds), writes `UHID_DESTROY` and closes the descriptor and the client socket. The
   device disappears; the uid's slot is freed.

After the hello there is no other message type: the framing is 64 bytes per message in
each direction. Writes to a client time out after 2 seconds, so a stuck client cannot block
the broker. The broker logs uids, pids and report counts, never report contents.

### Why the uhid descriptor never leaves the broker

Whoever holds a `/dev/uhid` descriptor can destroy its device and create a new one with any
report descriptor, for example a keyboard that types commands into the active session. Passing
the descriptor to the user daemon (`SCM_RIGHTS`) would hand that power to any process able to
impersonate or compromise the daemon. The broker therefore keeps the descriptor and relays
fixed-size reports only. It also never accepts a descriptor: the client socket is read with
plain `read`, so file descriptors sent as ancillary data are discarded by the kernel and never
installed in the broker.

### Hardening

- The unit runs as uid 0 with an empty capability bounding set. `/dev/uhid` is
  `root:root 0600`, so uid 0 opens it through the owner permission bits; no capability is
  needed. When started by hand with `sudo`, the broker drops every capability itself right
  after binding the socket (`hirz_sys::drop_all_capabilities`).
- `PR_SET_NO_NEW_PRIVS`, `PR_SET_DUMPABLE 0` and `RLIMIT_CORE 0` (`hirz_sys::harden_process`).
- `DevicePolicy=closed` with `DeviceAllow=/dev/uhid rw`, `ProtectSystem=strict`,
  `PrivateNetwork`, `RestrictAddressFamilies=AF_UNIX`, a `SystemCallFilter` allow list and
  the usual `Protect*` and `Restrict*` options. `systemd-analyze security` rates the unit
  1.0 ("OK").
- `PrivateUsers=` is deliberately not set: inside a user namespace `SO_PEERCRED` reports
  unmapped client uids as the overflow uid, which would break the per-uid policy.
- The `uhid` module loads on first open of `/dev/uhid` (the static node comes from
  `modules.devname`). Distributions that disable module autoloading can add `uhid` to
  `/etc/modules-load.d/`.

## Socket permissions

The socket is mode 0666, so the kernel does not decide who may connect: the broker does,
from the uid the kernel recorded for the peer (`SO_PEERCRED`).

### Who may connect

A peer gets a device only when all of these hold, checked at connect time and, for the
session, every 5 seconds while the device exists:

- **Uid range.** The uid is at least `--min-uid` (default 1000) and at most `--max-uid`
  (default 60513). That admits regular users (1000 to 60000) and systemd-homed users (60001
  to 60513), and keeps out system accounts, host users mapped into containers (60514 and up),
  systemd `DynamicUser` ids (61184 to 65519) and `nobody` (65534). A distribution with other
  ranges sets the two options.
- **Active session on a seat.** `/run/systemd/users/<uid>`, the state file of systemd-logind
  (elogind writes the same files), has `STATE=active` and a non-empty `ACTIVE_SEATS`: the
  user has the foreground session on a seat. Refused: a user who is only logged in over ssh
  (logind calls such a user active, but without a seat), a lingering user, a user whose
  session is in the background after a fast user switch, and a user without any session.
  A remote desktop session that logind does not attach to a seat (xrdp or VNC servers
  usually have none) is refused too; use the Firefox extension path there, which needs no
  broker. Only root can write these files, and libsystemd reads the same keys for
  `sd_uid_get_state` and `sd_uid_get_seats`; the broker also refuses files that are not
  regular files or larger than 256 KiB. When the session ends or goes to the background the
  device is destroyed within 5 seconds, and `hirzd` reconnects (with its backoff, up to 60
  seconds) once the session is active again. `--sessions-dir DIR` replaces the directory.
  Without systemd-logind or elogind the broker refuses every client and says so at start.
- **Udev rules in effect.** All three files `70-hirz.rules`, `72-hirz.rules` and
  `99-zzz-hirz.rules` must be what udev would apply. The broker looks for each name in udev's
  order (`/etc`, `/run`, `/usr/local/lib`, `/usr/lib`, `/lib`, each below `udev/rules.d`;
  `--udev-rules-dir DIR` replaces the list by one directory) and takes the first entry it
  finds, as udev does. That entry must be a regular file (or a link to one) with at least
  one line that is neither blank nor a comment. A link to `/dev/null` or an empty file in
  an earlier directory masks the packaged file of the same name, and counts as missing. The
  broker checks that a rule is present, not what it says: an administrator's own copy with
  other content passes. Without the rules the hidraw node would get the seat ACL of whoever
  owns the seat, so the broker serves nobody until all three are in effect, and it names the
  missing ones in its log at start.
- **Budget.** One device per uid at a time, at most `--max-connections` devices overall, at
  most 6 devices created per uid in a burst (one more every 10 seconds), and at least 250 ms
  between a destroyed device and the next one of the same uid, so one account cannot churn
  kernel HID devices, udev events and logs.

A client can only get a device for its own uid, with a descriptor it cannot choose. With the
udev rule below, the hidraw node belongs to that uid only, so a user cannot place an
authenticator in front of another user's browser.

### What this does not cover

A user who holds the foreground session on a seat can still create a hirz device, and FIDO
clients that run as root list every FIDO hidraw node whoever owns it: pam-u2f inside `sudo`,
`login`, a display manager or a screen locker, `systemd-cryptsetup` and
`systemd-cryptenroll` with `fido2-device=auto`, `systemd-homed`, and an administrator running
`fido2-token` or `ykman` under `sudo`. Such a client can talk to a device that a program
running as the seat user created, with a rogue CTAP2 implementation instead of hirzd: it
sees the key handles and relying party the client asks about, may receive the PIN hash of a
PIN verification, and can stall the client. This needs a program running as the user at the
console, which already has everything hirz holds for that user (see
`docs/threat-model.md`), but it reaches root-run clients that the user could not otherwise
touch. On a computer where the console user is not the administrator, or on which several
people hold sessions on different seats, restrict the socket as well: create a `hirz` group,
set `SocketGroup=hirz` and `SocketMode=0660` in `hirz-uhid-broker.socket`, and add only
trusted users to the group (a re-login is needed for group membership to apply). Do not use
pam-u2f or `fido2-device=auto` for anything that matters on a computer where this exposure
is not acceptable; hirz itself refuses `pam://` requests (see "OpenSSH and pam-u2f").

Without the udev rule, mode 0666 would be a problem on multi-user machines: the node would
get the ACL of whoever owns the active seat, so another local user could plant a device that
answers the seat user's browser and approve registrations without them. That is why the
broker refuses to serve while one of the hirz rule files is missing or masked, and why
packagers who ship the socket without the udev rules must restrict it as above.

## hidraw access

The default path in systemd (`60-fido-id.rules` and `70-uaccess.rules`):

1. `fido_id` reads the report descriptor of every new hidraw node. The FIDO usage page sets
   `ID_SECURITY_TOKEN=1` and the tag `security-device`. This works for uhid devices too,
   because their HID device exposes `report_descriptor` like any other.
2. `70-uaccess.rules` tags nodes with `ID_SECURITY_TOKEN` as `uaccess`, and
   `73-seat-late.rules` gives the user of the active session on the seat an ACL. The node
   itself stays `root:root 0600`.

So without any hirz rule the device is reachable by the seat user, which is the creator on a
single-user laptop. The three hirz rule files make the binding exact:

- `packaging/udev/70-hirz.rules` matches only hidraw nodes under `/devices/virtual/misc/uhid/`
  with ids `1209:0007` and `ID_SECURITY_TOKEN=1`, so real hardware is never affected. It
  imports `HID_PHYS` (the creator's uid, written by the broker) from the parent HID device and,
  only when it is one to ten decimal digits without a leading zero (never `0`, never a user
  name), sets `OWNER:=` to it, `GROUP:="root"` and `MODE:="0600"`. The `:=` form makes the
  values final, so no later rule file can widen them. Any other `HID_PHYS` leaves the node
  `root:root 0600`. It also adds the snap tags described below.
- `packaging/udev/72-hirz.rules` removes the `uaccess` tag from every uhid node with the
  hirz ids with `TAG-="uaccess"`, so `73-seat-late.rules` adds no seat ACL and logind never
  moves one to another user on a seat switch.
- `packaging/udev/99-zzz-hirz.rules` removes `uaccess` once more late in the run, in case a
  rule of another package tags all hidraw nodes `uaccess` after `72-hirz.rules` ran (some
  keyboard configuration tools do). Udev runs the files in file name order and no name can
  sort after every other: a file whose name sorts later (`99-zzzz.rules`, or any name that
  starts with a letter) runs after it and could add the tag again. The check below
  shows whether that happened on a given computer.

The binding trusts `HID_PHYS` of every uhid device with the ids `1209:0007`, which are not
secret. It therefore assumes that `/dev/uhid` is root only (the default: `root:root 0600`).
A system where another rule or tool opens `/dev/uhid` to seat users or a group (some game
streaming tools do) lets those users create a device with a `phys` of their choice, owned by
any user; do not combine the two.

`ID_SECURITY_TOKEN` itself stays set, because snapd uses it to let snap browsers reach the
node (next section). Earlier versions of the rule cleared it instead, which also stopped the
`uaccess` tag but hid the device from every snap that hirz did not tag by name.

Ordering, by file name across `/usr/lib/udev/rules.d` and `/etc/udev/rules.d`:

| File | What it does to a hirz node |
|---|---|
| `60-fido-id.rules` (systemd) | `fido_id` sets `ID_SECURITY_TOKEN=1` and the tag `security-device` |
| `70-hirz.rules` | owner, group and mode (final); snap tags for older snapd |
| `70-snap.<snap>.rules` (snapd) | tags the node for each snap with `u2f-devices` connected and runs `snap-device-helper` on the tag |
| `70-uaccess.rules` (systemd) | `ENV{ID_SECURITY_TOKEN}=="?*"` adds `uaccess` |
| `71-seat.rules` (systemd) | tags every hidraw node `seat` (unchanged by hirz) |
| `72-hirz.rules` | removes `uaccess` |
| `73-seat-late.rules` (systemd) | `TAG=="uaccess"` would apply the seat ACL; no longer matches |
| `99-zzz-hirz.rules` | removes `uaccess` again, late in the run (only names that sort later can still add it) |

`70-hirz.rules` must sort after `60-fido-id.rules` and before `70-snap.*.rules`, and
`72-hirz.rules` after `71-seat.rules` and before `73-seat-late.rules`, and `99-zzz-hirz.rules`
after every rule file that tags hidraw nodes. Removing a tag within
the event that added it is safe with sticky tags (systemd 247 and newer): a tag is only
remembered once the event's database entry is written, and the entry never contains
`uaccess`.

To check on a running system, while `hirzd` runs:

```sh
dev=$(ls /sys/devices/virtual/misc/uhid/0003:1209:0007.*/hidraw | head -1)
udevadm info --query=property --name="/dev/$dev" | grep -E 'ID_SECURITY_TOKEN|HID_PHYS|TAGS'
getfacl "/dev/$dev"    # owner only, no user: entry for the seat user
```

`TAGS` must not contain `:uaccess:`; `ID_SECURITY_TOKEN=1` must be present.

Every process of the same user can still open the node and speak CTAP to it, as with a
hardware key. That is inherent to the design; every signature with the user-present flag
requires an approval prompt from hirzd (see `docs/threat-model.md` and "Silent probes"
below).

## Snap and Flatpak

- **Snap.** Strictly confined browsers reach hidraw nodes only through the `u2f-devices`
  interface. Its AppArmor rule allows `/dev/hidraw*`, and the device cgroup decides: snapd
  writes `/etc/udev/rules.d/70-snap.<snap>.rules`, and `snap-device-helper` adds every node
  tagged `snap_<snap>_<app>` to that snap's device cgroup.
  - snapd 2.78 and newer on systemd 244 and newer tag every hidraw node with
    `ENV{ID_SECURITY_TOKEN}=="1"`. Because `70-hirz.rules` keeps that property, every snap
    with `u2f-devices` connected gets the hirz node: Firefox, Chromium, Brave, Opera,
    Vivaldi, Discord and others.
  - Older snapd tags only a fixed list of USB vendor and product ids, matched with
    `ATTRS{idVendor}`; a uhid device has no USB parent, so it never matches. For those
    versions `70-hirz.rules` adds `snap_firefox_firefox` and `snap_chromium_chromium`
    itself, which is why it must sort before the snap rule files, whose `RUN` line fires on
    the tag. Other snaps need snapd 2.78.

  The node is still owned by its creator with mode 0600, so a snap of another user cannot
  open it even though it is in that snap's device cgroup. Check with
  `snap connections <snap>` that `u2f-devices` is connected, and with `snap version` which
  snapd runs. The AppArmor profile allows reading `report_descriptor` in sysfs only below
  `usb*` and `i2c*` paths, not below `virtual/misc/uhid`; a browser that reads the
  descriptor from sysfs (Chromium does) instead of with the `HIDIOCGRDESC` ioctl (Firefox
  does) does not recognize the device inside a snap unless `hardware-observe` is also
  connected. Chromium as a snap is untested.
- **Flatpak.** Firefox and Chromium on Flathub have `--device=all` and run as the same
  uid, so the owner-only node is reachable without further setup.

## Device identity

Vendor `0x1209` is the pid.codes vendor id for open source projects. Product `0x0007` is
in the pid.codes test range (`0x0001` to `0x0010`), which must not be used in released
products. A dedicated product id has to be registered with pid.codes before a release; the
broker constant and the udev rule then change together.

## CTAPHID transport

`hirz_ctap::hid::Transport` implements channel allocation with CTAPHID_INIT on the
broadcast channel (nonce echo, protocol version 2, capabilities WINK, CBOR and NMSG since
U2F is not supported), PING, WINK, CBOR dispatch, CANCEL, KEEPALIVE every 100 ms with
status PROCESSING or UPNEEDED, error codes, reassembly of messages up to 7609 bytes with
sequence checks, a 1 second timeout between packets, and a processing timeout of 120 seconds
(the prompt of hirzd is capped below it, see "Cancellation"). One transaction runs at a time;
other channels get CHANNEL_BUSY meanwhile. Channel identifiers are random 32-bit numbers (never 0
or the broadcast id), so a client that did not see the INIT answer has to guess one; at most 64
are remembered, the oldest one that is not in use is forgotten first. This does not hide the
identifier from another process that has the hidraw node open: it can read every report the
device sends, as the browser does, and the node is owned by the user it was made for.

`hirz_ctap::hid::run` executes each CBOR request on a worker thread through the
`CborHandler` trait, so the handler can block on a user prompt while the loop keeps sending
keepalives and listening for CANCEL. The handler polls `RequestContext::is_cancelled` and
sets `KeepaliveStatus::UpNeeded` while it waits for the user. At most four request threads are
alive at once, a thread of a cancelled request included (see "Cancellation").

## CTAP2 command policy

Policy of `hirz_ctap::ctap2` for an authenticator with built-in user verification and no
clientPin. Requests are decoded with the strict canonical CBOR decoder into `hirz_core`
types, handed to an `Authenticator` (the engine adapter) and the results are encoded as
canonical CBOR.

- The `uv` option maps to `UvRequirement::Required` when true and to `Discouraged` when
  false or absent. Discouraged does not forbid UV: when the approval method verifies the
  user anyway, the UV flag is set.
- hirz shows its own account picker during approval, so a discoverable getAssertion returns
  exactly one credential with `userSelected`, and authenticatorGetNextAssertion is never
  needed. The `user` entity carries only the id; the platform never needs name or
  displayName for its own picker. With an allow list the platform chose the credential and
  `userSelected` is not set.
- authenticatorReset is refused: credentials are managed with the hirz CLI.
- hmac-secret: the handler decrypts the salts and passes an `HmacSecretWrap` to the engine,
  which encrypts its output through it and embeds the result in authData before signing.
- Parameter decoding does not enforce map key order: Firefox sends getAssertion options as
  `{"uv": .., "up": ..}`, which is not canonical, and hardware keys accept it. Everything
  else stays strict (shortest-form integers, definite lengths, no duplicate keys, no floats
  or tags).
- Allow and exclude list ids of any length up to the WebAuthn limit (1023) are kept, since
  imported credentials keep the id their original authenticator chose. Longer ids are
  refused rather than dropped, so a list never turns into an empty (discoverable) one.
  `maxCredentialCountInList` is 16 so that platforms' silent pre-flight probes need few
  round trips.
- hirz never issues a pinUvAuthToken, so a non-empty pinUvAuthParam with a supported
  protocol can never verify. The zero-length pinUvAuthParam probe waits for a gesture and
  then reports that no PIN is set.
- makeCredential step 7 (`CTAP2_ERR_PUAT_REQUIRED` when uv is false on a UV-protected
  authenticator) is not applied: the approval method decides, and click-to-allow without UV
  stays possible when the platform does not ask for UV.
- authenticatorClientPIN supports only getKeyAgreement. Every other subcommand needs
  clientPin or a pinUvAuthToken, neither of which getInfo advertises, so it answers
  `CTAP2_ERR_INVALID_SUBCOMMAND`.
- Status mapping: a user who declines, or an approval window that times out, gives
  `CTAP2_ERR_OPERATION_DENIED`; an approval that is unavailable or showed nothing gives
  `CTAP2_ERR_NOT_ALLOWED`; a lock is `UV_BLOCKED` rather than `PIN_BLOCKED`, because hirz has no
  clientPin and platforms retry built-in UV in a loop on `UV_INVALID` (see "Refusals end the
  ceremony").

## hirzd

hirzd connects to the broker, runs `hirz_ctap::Ctap2Handler` on the CTAPHID transport and
answers with the engine of `hirz-core` over the user's vault, asking `hirz-uv`
(`HirzApprover`) for every approval.

- **Vault.** Resolved like the CLI does: `HIRZ_VAULT`, else the folder recorded in
  `$XDG_STATE_HOME/hirz/vault-path`, else `$XDG_DATA_HOME/hirz/vault`; state in
  `HIRZ_STATE`, else `$XDG_STATE_HOME/hirz`. The vault is opened on the first request and
  reloaded by the engine for every ceremony, so credentials created by the extension path
  or synced from another device are seen at once. Without a vault, makeCredential,
  authenticatorSelection and silent probes return `CTAP2_ERR_NOT_ALLOWED` (a sign-in gets
  `CTAP2_ERR_NO_CREDENTIALS`, see below), hirzd logs
  "run `hirz init` first" and shows a desktop notification ([approval.md](approval.md),
  "Notifications", at
  most once every 10 minutes). A request that would ask the user (not a silent probe) also
  opens the setup window, `hirz init --gui`, within the limits described in
  [approval.md](approval.md), "Setting up hirz". A sign-in or touch request is then answered
  at once with `CTAP2_ERR_NO_CREDENTIALS`. A registration waits for the window like for an
  approval (keepalives keep flowing, at most 115 seconds, a CTAPHID_CANCEL ends it); when the
  window leaves a vault behind, it goes on with the normal approval, otherwise it is refused
  as above. A sign-in that finds no passkey for the site shows "hirz has no passkey for SITE."
  at most once per site and minute ([approval.md](approval.md), "No passkey for the site").
- **getInfo** comes from `hirz_ctap::ctap2::get_info_response_with()`: versions `FIDO_2_0` and
  `FIDO_2_1`, extensions `credProtect` and `hmac-secret`, the hirz AAGUID, options `rk`,
  `up`, `uv` and `plat` false, maxMsgSize 7609, PIN/UV auth protocols 2 and 1,
  maxCredentialCountInList 16, maxCredentialIdLength 1023 (hirz creates 32-byte ids; imported passkeys keep their
  original ids of up to 1023 bytes, and browsers drop allow-list ids longer than this value), transports `usb`, algorithms
  ES256 and EdDSA, and firmwareVersion `0x000100` (a fixed value, not the release version). The `uv` option is true when at
  least one verifying method of the approval config (system password, fingerprint, PIN) can be
  used right now and false otherwise; hirzd re-checks it at most every 10 seconds and never
  waits for a request in progress to answer. A platform that reads `uv: false` does not ask for
  user verification, so click-to-allow sites keep working and a site that needs verification
  fails with a clear refusal instead of after a prompt. The key agreement key behind
  clientPIN getKeyAgreement (used for hmac-secret) is replaced on every reconnect to the broker
  and when a platform asks for it ten minutes after the last one.
- **Cancellation.** The approval prompt cannot be interrupted. On CTAPHID_CANCEL the
  transport answers `CTAP2_ERR_KEEPALIVE_CANCEL` at once; the open prompt stays until it is
  answered or times out, and its approval then counts as refused, so a cancelled request
  creates and signs nothing (the engine checks the cancel again after the approval, right
  before it stores or signs, and takes a just-stored credential back). A request that may wait
  for the user (makeCredential, getAssertion, authenticatorSelection) and arrives meanwhile is
  refused with CTAPHID_ERR_CHANNEL_BUSY, so a page that starts and aborts requests cannot pile
  up threads behind the open prompt; getInfo and the other requests that answer at once are
  still served. The transport ends a request after 120 seconds with
  `CTAP2_ERR_USER_ACTION_TIMEOUT`, so hirzd caps the ceremony timeout of the approval config
  (up to 600 s for the extension and the CLI) at 115 seconds: the prompt is gone before the
  browser is told it timed out.
- **Debug trace.** `HIRZ_DEBUG_CTAP=1` prints every CTAP2 request and response in hex to
  standard error, only when standard error is a terminal. Started by a service manager
  (journal) or with output redirected to a file, hirzd logs that the variable is ignored and
  prints no trace. The trace leaves out the `user` entity of makeCredential requests and
  getAssertion responses (account and display names); relying party ids, credential ids,
  client data hashes and signatures remain in it, so keep it for a terminal you control.
- **Reconnects.** When the broker closes the connection or cannot be reached, hirzd
  retries after 1 second, doubling up to 60 seconds; a connection that lasted 30 seconds
  resets the delay.
- **Hardening.** At start: `RLIMIT_CORE 0`, `PR_SET_DUMPABLE 0`, `PR_SET_NO_NEW_PRIVS`
  (`hirz_sys::harden_process`), and `mlockall` when `HIRZ_MLOCK=1`. None of the helpers
  hirz-uv starts (zenity, pkcheck, fprintd-verify, fprintd-list) is setuid or has file
  capabilities, so NO_NEW_PRIVS does not affect them. polkitd identifies the hirzd process
  by pid, start time and uid from `/proc/<pid>/stat` and `/proc/<pid>/status`, which stay
  readable when the process is not dumpable; pkcheck gives the same answer for a hardened
  and an unhardened process.

### hirzd user unit

`packaging/systemd/hirzd.service` is a user unit ordered after `graphical-session.target`:
the approval prompts (zenity) need the session's display and polkit needs its agent, and
both exist only while a graphical session runs. The desktop imports `DISPLAY`,
`WAYLAND_DISPLAY` and the session bus address into the user manager before that target.
hirzd retries the broker itself, so it only exits on a fatal error.

The sandbox options are chosen so that the helpers hirzd starts keep working. `SystemCallFilter`
is a deny list, not an allow list, because the filter also applies to zenity (GTK) and its GPU
drivers, whose needs are broad and change with the desktop. `RestrictAddressFamilies` allows
`AF_UNIX` (broker, session bus, Wayland, X11) and `AF_NETLINK` (GLib inside zenity); hirzd
itself never uses the network. None of the helpers carries setuid bits or file capabilities,
so `NoNewPrivileges=yes` does not break approval.

Deliberately not set:

- `ProtectSystem=`, `ProtectHome=`, `PrivateTmp=`, `PrivateDevices=`, `ProtectKernel*=`,
  `ProtectControlGroups=`, `ProtectClock=`, `ProtectHostname=`, `ReadOnlyPaths=` and similar:
  in a user unit they imply `PrivateUsers=yes`. In a user namespace root-owned files appear
  owned by the overflow uid, so hirz-uv no longer finds zenity, pkcheck and fprintd in
  root-owned system directories and refuses every approval. `ProtectHome` would also hide
  the vault.
- `PrivateNetwork=`, `IPAddressDeny=`: they need a network namespace (and with it a user
  namespace), and X11 over TCP would break too.
- `MemoryDenyWriteExecute=`: zenity's GTK renderer may JIT shaders (Mesa llvmpipe).
- `CapabilityBoundingSet=`, `AmbientCapabilities=`: a user service holds no capabilities, and
  `NoNewPrivileges=yes` keeps it from gaining any.

hirzd also sets `PR_SET_DUMPABLE 0`, `NO_NEW_PRIVS` and `RLIMIT_CORE 0` at start.

## OpenSSH and pam-u2f

OpenSSH security keys (`ssh-keygen -t ecdsa-sk` or `-t ed25519-sk`) work with hirz. Their RP
id is `ssh:` or `ssh:NAME` (`-O application=`); prompts and `hirz list` show it as "SSH key"
or "SSH key (NAME)", logs and `--json` output keep the raw value.

pam-u2f is refused. Requests whose RP id starts with `pam://` (its default origin is
`pam://HOSTNAME`) or is `io.systemd.home` or `io.systemd.cryptsetup` (systemd-homed and
systemd-cryptenroll) get `CTAP2_ERR_NOT_ALLOWED` for makeCredential and getAssertion, silent
probes included, before the vault is opened and without a prompt; hirzd logs one line naming
the RP id. A synced software key must not be a login factor for the machine it runs on, and
a screen unlock that needs a hirz approval could deadlock. The engine enforces the same rule,
so the extension path refuses it too. See `docs/threat-model.md`.

## Silent probes

Before the real request, platforms check which entries of an allow list (getAssertion) or
exclude list (makeCredential) a key holds, by sending authenticatorGetAssertion with the
option `up: false` (CTAP 2.2 section 6.2.2 calls this pre-flight). Firefox does this for
every CTAP2 device: in authenticator-rs, now vendored at
`dom/webauthn/authenticator/src/ctap2/preflight.rs` in the Firefox tree
(<https://searchfox.org/firefox-main/source/dom/webauthn/authenticator/src/ctap2/preflight.rs>),
`do_credential_list_filtering_ctap2` sends getAssertion with `user_presence: Some(false)`
for each chunk of `maxCredentialCountInList` entries (1 when the device does not say), keeps
the chunk that succeeds, and drops ids longer than `maxCredentialIdLength`. `register` and
`sign` in `src/ctap2/mod.rs` of the same crate run it on the exclude and allow lists. When
the filtered allow list comes back empty, `sign` asks for a touch and fails with
`NoCredentials` without ever sending the real request, so a key that refuses probes can
never be used to sign in with an allow list. Chromium probes the same way
(`MakeCredentialTask::NextSilentRequest` and `GetAssertionTask` in `device/fido/`, with
`user_presence_required = false` and UV discouraged), but only when a list does not fit in
one request of `maxCredentialCountInList` entries.

hirz therefore answers probes as hardware keys do. With `up: false` and a non-empty allow
list, the engine signs for the first credential of the list that belongs to the RP, without
a prompt, with flags UP=0 and UV=0 (BE and BS as usual), no hmac-secret output and no user
name. Credentials with credProtect level 3 are skipped (they need UV). An empty allow list
gives `CTAP2_ERR_NO_CREDENTIALS`, and a probe that also asks for UV gives
`CTAP2_ERR_NOT_ALLOWED`. Relying parties reject assertions without UP for sign-in, so a
probe result cannot log anyone in. A probe reveals to local processes whether a credential
exists for a site, which processes of the same user can learn from the vault anyway.

When none of the allowed credentials is found, Firefox sends a throwaway makeCredential
for the RP id `make.me.blink` (`dummy_make_credentials_cmd` in
`src/ctap2/commands/make_credentials.rs`) only to wait for a touch before it reports
`NoCredentials`; Chromium does the same with the RP id `.dummy` (`kDummyRpID`,
`MakeCredentialTask::GetTouchRequest`). hirzd answers such
requests with a presence-only prompt, as for authenticatorSelection, and then
`CTAP2_ERR_NOT_ALLOWED`; it never stores a credential for them.

## Running hirzd

```
cargo build --release -p hirz-uhid-broker -p hirzd
sudo ./target/release/hirz-uhid-broker --listen /run/hirz/uhid.sock   # terminal 1
./target/release/hirzd                                                # terminal 2, as the user
```

The broker needs the udev rules installed (`scripts/dev-run.sh` does that) and you need an
active session on a seat, that is, a login at the computer's own screen or console. A
`--listen` path must be absolute and contain no symbolic link, `.` or `..`. Every directory
on it must be owned by root (or by the user running the broker) and closed to group and
others; only a sticky directory such as `/tmp` may be open to others, and the directory that
holds the socket may not be. Nobody else can then swap a directory on the path for a link
while the broker starts. The broker creates the last directory with mode 0755 when it is
missing (with `mkdir` under a zero umask, not by changing a mode afterwards, which would
follow a link) and never changes the mode of an existing one; it creates the socket with
mode 0666 the same way. Give the real path (`/run/hirz/uhid.sock`, not through `/var/run`).

`HIRZ_BROKER_SOCKET` overrides the socket path. As a service, install
`packaging/systemd/hirzd.service` as a user unit (the comments in the file explain each
hardening option, and why the namespace-based ones are not used):

```
install -D -m 0644 packaging/systemd/hirzd.service ~/.config/systemd/user/hirzd.service
# edit ExecStart if the binary is not at /usr/bin/hirzd
systemctl --user daemon-reload
systemctl --user enable --now hirzd.service
journalctl --user -u hirzd -f
```

`hirzd --self-test` needs neither root nor `/dev/uhid` nor a desktop. It creates a vault in
a temporary folder and plays the browser over an in-process socketpair: getInfo,
makeCredential, getAssertion with an allow list, a discoverable getAssertion and a silent
probe, verifying every signature, and then makeCredential without a vault, which must be
denied. Its approver approves everything and exists only inside the self-test; no option
or variable puts it in front of the real vault.

## Manual test checklist

Needs the broker running (root), the udev rule installed, a vault (`hirz init`), and an
approval method (for example the polkit action).

1. `hirzd --self-test` passes.
2. Start hirzd; the log shows "connected to the broker". `fido2-token -L` lists
   `hirz virtual authenticator`; `fido2-token -I <device>` shows the getInfo above.
3. Firefox, https://webauthn.io, register with "Security key": one hirz prompt shows the
   site; after approval the registration succeeds.
4. Authenticate with the same username (allow list): the silent probe produces no prompt,
   then one hirz prompt; the assertion succeeds with UP set.
5. Authenticate without a username (discoverable): the account list appears when several
   accounts exist.
6. Register again with the same username (exclude list): one hirz prompt, then Firefox
   reports that the key is already registered.
7. Cancel in Firefox while the hirz prompt is open: Firefox stops at once; approving the
   still open prompt afterwards creates nothing (`hirz list` is unchanged).
8. Stop the broker: hirzd logs the reconnect delays; start it again: hirzd reconnects.
9. Move the vault away (or use a fresh account): a ceremony is refused and a desktop
   notification asks to run `hirz init`.
10. Repeat 3 and 4 in Chromium.
11. As a user who has no session at the computer's own screen, log in over `ssh` and start
    `hirzd`: the broker refuses it ("active session is not on a seat") and no device appears.
12. With two accounts, switch users from the lock screen: within 5 seconds the broker logs
    "ending the device" for the account that went to the background and its device
    disappears; switching back brings it back after `hirzd` reconnects.
13. Mask a rule file: `sudo ln -s /dev/null /etc/udev/rules.d/70-hirz.rules`. Within 5 seconds
    the broker logs "ending the device: the hirz udev rules are not installed or are masked"
    and the device disappears, and new connections are refused. Remove the link again and
    `hirzd` reconnects. The same happens for `72-hirz.rules` and `99-zzz-hirz.rules`, and for
    an empty file of that name.

### Refusals end the ceremony

When the user clicks Cancel, or the approval window times out, hirzd answers
`CTAP2_ERR_OPERATION_DENIED`, as CTAP 2.2 asks for makeCredential and getAssertion (sections 6.1
and 6.2: "If the user declines permission, or the operation times out"). Browsers treat it
differently:

- Chromium (`device/fido/fido_device_authenticator.cc`, the functions that convert a device
  response code) ends the request on `OPERATION_DENIED` (user consent denied). Any other code
  except a few PIN errors, `CTAP2_ERR_NOT_ALLOWED` and `CTAP2_ERR_USER_ACTION_TIMEOUT`
  included, only drops the key, and the browser's dialog then waits until its own timeout.
  Chromium's rule that a denial faster than 300 ms means a locked key applies only to
  authenticators that also offer a clientPin, which hirz does not.
- Firefox (authenticator-rs, `src/ctap2/mod.rs`, `register` and `sign` with the
  `handle_errors!` macro) treats `OPERATION_DENIED` from an authenticator with built-in user
  verification, which hirz reports while a verifying method works, as a failed verification:
  it repeats its silent pre-flight probes and resends the same command at once (same client data
  hash, RP id and lists), with no delay or limit, until the request ends. Any other error ends
  it.

So hirzd remembers each declined makeCredential and getAssertion with user presence for 5
seconds: its command, RP id and client data hash, nothing else, at most four of them, in the
running process only. The same request again within that time is answered
`CTAP2_ERR_NOT_ALLOWED` at once, without a window, a notification or the prompt budget, which ends
Firefox's ceremony; the entry is then forgotten. A page that asks again gets a new challenge,
so a new client data hash, and is asked as usual; silent probes are never remembered. An
approval that was unavailable or showed nothing stays `CTAP2_ERR_NOT_ALLOWED`. Both browsers then
reject the page's call with `NotAllowedError`.
