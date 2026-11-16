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
`/run/hirz/uhid.sock`) or by hand with `--listen PATH`. For each connection it:

1. Reads the peer credentials with `SO_PEERCRED`. The kernel records them at `connect`
   time, so the client cannot forge them.
2. Refuses uids below `--min-uid` (default 1000, never 0), a uid that already has a device,
   and connections beyond `--max-connections` (default 8). Refusal closes the socket.
3. Opens `/dev/uhid` and writes `UHID_CREATE2` with fixed values: name
   `hirz virtual authenticator`, bus `BUS_USB`, vendor `0x1209`, product `0x0007`, the
   client's decimal uid in the `phys` field, and the FIDO report descriptor (usage page
   `0xF1D0`, usage `0x01`, one 64-byte input and one 64-byte output report, no report ids).
   Nothing in the request comes from the client.
4. Relays reports. Output reports (`UHID_OUTPUT`) go to the client as exactly 64 bytes;
   hidraw writers prefix the report number 0, so the kernel delivers 65 bytes and the
   broker strips the first byte. Every 64 bytes the client sends become one `UHID_INPUT2`.
   Anything else is dropped. Feature report requests (`UHID_GET_REPORT`,
   `UHID_SET_REPORT`) are answered with `EIO`, since the descriptor declares none.
5. When the client disconnects, writes `UHID_DESTROY` and closes the descriptor. The device
   disappears; the uid's slot is freed.

There is no handshake and no other message type: the framing is 64 bytes per message in
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

The socket is mode 0666. Any local user can connect, and that is acceptable because:

- a client can only get one FIDO device for its own uid, with a descriptor it cannot
  choose, and cannot influence anything else in the broker;
- with the udev rule below, the hidraw node belongs to that uid only, so a user cannot place
  an authenticator in front of another user's browser.

Without the udev rule, mode 0666 would be a problem on multi-user machines: the node would get
the ACL of whoever owns the active seat, so another local user (for example one logged in over
SSH) could plant a device that answers the seat user's browser and approve registrations
without them. Packagers who ship the socket without the udev rule must restrict it instead:
create a `hirz` group, set `SocketGroup=hirz` and `SocketMode=0660`, and add only the seat users
to the group (a re-login is needed for group membership to apply).

## hidraw access

The default path in systemd (`60-fido-id.rules` and `70-uaccess.rules`):

1. `fido_id` reads the report descriptor of every new hidraw node. The FIDO usage page sets
   `ID_SECURITY_TOKEN=1` and the tag `security-device`. This works for uhid devices too,
   because their HID device exposes `report_descriptor` like any other.
2. `70-uaccess.rules` tags nodes with `ID_SECURITY_TOKEN` as `uaccess`, and
   `73-seat-late.rules` gives the user of the active session on the seat an ACL. The node
   itself stays `root:root 0600`.

So without any hirz rule the device is reachable by the seat user, which is the creator on a
single-user laptop. The two hirz rule files make the binding exact:

- `packaging/udev/70-hirz.rules` matches only hidraw nodes under `/devices/virtual/misc/uhid/`
  with ids `1209:0007` and `ID_SECURITY_TOKEN=1`, so real hardware is never affected. It
  imports `HID_PHYS` (the creator's uid, written by the broker) from the parent HID device and
  sets `OWNER:=` to it, `GROUP:="root"` and `MODE:="0600"`. The `:=` form makes the values
  final, so no later rule file can widen them. It also adds the snap tags described below.
- `packaging/udev/72-hirz.rules` removes the `uaccess` tag from the same nodes with
  `TAG-="uaccess"`, so `73-seat-late.rules` adds no seat ACL and logind never moves one to
  another user on a seat switch.

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

`70-hirz.rules` must sort after `60-fido-id.rules` and before `70-snap.*.rules`, and
`72-hirz.rules` after `71-seat.rules` and before `73-seat-late.rules`. Removing a tag within
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
sequence checks, a 1 second timeout between packets, and a processing timeout. One
transaction runs at a time; other channels get CHANNEL_BUSY meanwhile.

`hirz_ctap::hid::run` executes each CBOR request on a worker thread through the
`CborHandler` trait, so the handler can block on a user prompt while the loop keeps sending
keepalives and listening for CANCEL. The handler polls `RequestContext::is_cancelled` and
sets `KeepaliveStatus::UpNeeded` while it waits for the user.

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
- Status mapping: a refused or unavailable approval is `CTAP2_ERR_NOT_ALLOWED` and a lock is
  `UV_BLOCKED` rather than `PIN_BLOCKED`, because hirz has no clientPin and platforms retry
  built-in UV in a loop on `UV_INVALID` and `OPERATION_DENIED` (see "Refusals end the
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
  getAssertion and authenticatorSelection return `CTAP2_ERR_NOT_ALLOWED`, hirzd logs
  "run `hirz init` first" and shows a desktop notification (`zenity --notification`, at
  most once every 10 minutes).
- **getInfo** comes from `hirz_ctap::ctap2::get_info_response()`: versions `FIDO_2_0` and
  `FIDO_2_1`, extensions `credProtect` and `hmac-secret`, the hirz AAGUID, options `rk`,
  `up`, `uv` true and `plat` false, maxMsgSize 7609, PIN/UV auth protocols 2 and 1,
  maxCredentialCountInList 16, maxCredentialIdLength 1023 (hirz creates 32-byte ids; imported passkeys keep their
  original ids of up to 1023 bytes, and browsers drop allow-list ids longer than this value), transports `usb`, algorithms
  ES256 and EdDSA, and firmwareVersion `0x000100` (0.1.0).
- **Cancellation.** The approval prompt cannot be interrupted. On CTAPHID_CANCEL the
  transport answers `CTAP2_ERR_KEEPALIVE_CANCEL` at once; the open prompt stays until it is
  answered or times out, and its approval then counts as refused, so a cancelled request
  creates and signs nothing. A request that arrives meanwhile waits for that prompt to
  close.
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
`pam://HOSTNAME`) get `CTAP2_ERR_NOT_ALLOWED` for makeCredential and getAssertion, silent
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

`HIRZ_BROKER_SOCKET` overrides the socket path. As a service, install
`packaging/systemd/hirzd.service` as a user unit (the comments in the file explain each
hardening option, and why the namespace-based ones are not used):

```
install -D -m 0644 packaging/systemd/hirzd.service ~/.config/systemd/user/hirzd.service
# edit ExecStart if the binary is not at /usr/local/libexec/hirz/hirzd
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

### Refusals end the ceremony

hirz answers a refused, cancelled or unavailable approval with `CTAP2_ERR_NOT_ALLOWED`, not
`CTAP2_ERR_OPERATION_DENIED`. For an authenticator with built-in user verification, Firefox
(authenticator-rs, `ctap2/mod.rs`, `handle_errors!`) treats `OPERATION_DENIED` and
`PIN_AUTH_INVALID` as a failed verification and resends the request at once; a user who
clicks Cancel would then see the prompt again forever. Timeouts use
`CTAP2_ERR_USER_ACTION_TIMEOUT`. Both end the ceremony with `NotAllowedError` in the page.
