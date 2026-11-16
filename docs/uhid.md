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
single-user laptop. `packaging/udev/70-hirz.rules` makes the binding exact:

- it matches only hidraw nodes under `/devices/virtual/misc/uhid/` with ids `1209:0007`
  and `ID_SECURITY_TOKEN=1`, so real hardware is never affected;
- it imports `HID_PHYS` (the creator's uid, written by the broker) from the parent HID
  device, sets `OWNER` to it with mode 0600, and clears `ID_SECURITY_TOKEN` before
  `70-uaccess.rules` runs, so no seat ACL is added and none follows a seat switch;
- it adds the snap tags described below.

The file name sorts after `60-fido-id.rules` and before `70-snap.*.rules` and
`70-uaccess.rules`; both orderings matter.

Every process of the same user can still open the node and speak CTAP to it, as with a
hardware key. That is inherent to the design; every signature requires an approval prompt
from hirzd (see `docs/threat-model.md`).

## Snap and Flatpak

- **Snap.** Strictly confined browsers reach hidraw nodes only through the `u2f-devices`
  interface. Its AppArmor rule allows `/dev/hidraw*`, and the device cgroup decides: snapd
  writes `/etc/udev/rules.d/70-snap.<snap>.rules`, which tags a fixed list of known security
  key vendor and product ids (the list on snapd 2.77 has no generic `ID_SECURITY_TOKEN`
  match), and `snap-device-helper` adds tagged nodes to the snap's device cgroup. The hirz
  ids are not on that list, so `70-hirz.rules` adds `snap_firefox_firefox` and
  `snap_chromium_chromium` itself. The rule must sort before the snap rule files, whose
  `RUN` line fires on the tag. Check with `snap connections firefox` that `u2f-devices` is
  connected. The AppArmor profile allows reading `report_descriptor` in sysfs only below
  `usb*` and `i2c*` paths, not below `virtual/misc/uhid`; a browser that reads the
  descriptor from sysfs instead of with the `HIDIOCGRDESC` ioctl would not recognize the
  device inside a snap. The spike checks Firefox; Chromium as a snap is untested.
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

## Running the spike by hand

```
cargo build --release -p hirz-uhid-broker -p hirzd
sudo ./target/release/hirz-uhid-broker --listen /run/hirz/uhid.sock   # terminal 1
./target/release/hirzd                                                # terminal 2, as the user
```

`HIRZ_BROKER_SOCKET` overrides the socket path for hirzd. `hirzd --self-test` runs the
transport against an in-process fake broker over a socketpair and needs neither root nor
`/dev/uhid`. hirzd exits when the broker closes the connection; it does not reconnect yet.
