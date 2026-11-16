# hirz as a snap (draft)

This directory holds a draft `snapcraft.yaml` for publishing hirz in the Snap Store. It is
not published. This page records what a snap of hirz can and cannot do, why the draft uses
classic confinement, and what the store review needs.

This is about packaging hirz itself as a snap. Browsers installed as snaps (Ubuntu's
default Firefox, Chromium, Brave and others) already work with the `.deb`, `.rpm` and AUR
packages; see "Snap and Flatpak" in [docs/uhid.md](../../docs/uhid.md).

## What hirz needs from the host

| Piece | Packages install it as | Why it matters |
|---|---|---|
| Root broker with `/dev/uhid` | system service, socket-activated, sandboxed by systemd directives | creates the virtual security key |
| udev rules `70-hirz.rules`, `72-hirz.rules` | `/usr/lib/udev/rules.d` | the hidraw node belongs to the user who created it, no seat ACL |
| polkit action `dev.hirz.authenticate` | `/usr/share/polkit-1/actions` | password approval |
| `zenity`, `pkcheck`, `fprintd-verify` | distribution packages | hirz runs them only from root-owned system directories (`/usr/bin` and similar), never from `PATH` |
| systemd user unit `hirzd.service` | `/usr/lib/systemd/user` | starts the user daemon with the desktop session |
| Firefox native messaging manifest | `/usr/lib/mozilla/native-messaging-hosts`, root-owned | the extension path; a per-user manifest is deliberately not used |

## Strict confinement: possible, but it loses the security properties

Checked against snapd 2.78 (interfaces in `interfaces/builtin/`):

- **The broker can run.** snapd has a `uhid` interface (AppArmor `/dev/uhid rw`), slot on the
  system snap, `deny-auto-connection: true`. A user must run `snap connect hirz:uhid`, or
  the store grants auto-connection. `raw-usb`, `hardware-observe` and `u2f-devices` do not
  grant `/dev/uhid`. A system daemon runs as root; its socket must be below `$SNAP_DATA`,
  `$SNAP_COMMON` or `$XDG_RUNTIME_DIR`.
- **No udev rules.** A strict snap cannot install udev rules. Without them the hidraw node
  stays `root:root 0600` with a seat ACL from `70-uaccess.rules`: the active seat user gets
  the device, whoever created it. On a shared computer another local user could place an
  authenticator in front of the seat user's browser, or reach someone else's device after a
  seat switch. This is the main reason strict confinement is not acceptable (see
  "Socket permissions" in `docs/uhid.md`).
- **polkit.** The `polkit` interface can install action files from `meta/polkit/` and lets
  the snap ask polkitd, but it is super-privileged (`allow-installation: false` in the base
  declaration), so the store must grant it.
- **Helper programs.** Inside a strict snap `/usr/bin` is the base snap's, which has no
  `zenity`, `pkcheck` or `fprintd-verify`. Staged copies would live under `$SNAP`, which
  hirz-uv does not trust by design; changing that is a code change to a security
  boundary. There is no snapd interface for fprintd (`net.reactivated.Fprint`), so
  fingerprint approval would be unavailable.
- **User daemon.** `daemon-scope: user` is still behind `experimental.user-daemons` in
  snapd 2.78 (allowed only for a short list of Canonical snaps), so `hirzd` would have to
  start through a desktop autostart file instead of systemd.
- **Native messaging.** A strict snap cannot write the root-owned system manifest. The only
  way is `personal-files` (super-privileged) for `~/.mozilla/native-messaging-hosts`, a
  per-user manifest that any program of the user can rewrite, which the packages avoid on
  purpose.

Strict confinement would ship a virtual key with weaker multi-user isolation, no
fingerprint approval and a different trust model for helper programs. Not worth it.

## Classic confinement: what the draft does

A classic snap runs unconfined on the host's root file system, so hirz finds the host's
`zenity`, `pkcheck` and `fprintd-verify` and opens `/dev/uhid` as on a package install. snapd
still does not install udev rules, polkit actions, user units or native messaging manifests
for a snap, so the draft adds a command an administrator runs once:

```sh
sudo snap install hirz --classic
sudo snap run hirz.setup-system install
hirz init
systemctl --user enable --now hirzd
```

`setup-system install` writes the same files the packages install, under `/etc` where the
host reads them there (`/etc/udev/rules.d`, `/etc/systemd/user`, `/etc/modules-load.d`, and
`/etc/polkit-1/actions` with polkit 126 or newer), and the polkit action under
`/usr/share/polkit-1/actions` on older polkit. Firefox reads system manifests only below
`/usr/lib/mozilla` (and `/usr/lib64/mozilla`), so the manifest goes there; on a read-only
`/usr` the extension path is unavailable and the virtual key still works. Every written path
is listed in `$SNAP_COMMON/host-files`; `setup-system remove` and the snap's `remove` hook
delete exactly those.

The broker socket is `/var/snap/hirz/common/uhid.sock` (snapd's rule above), and the snap
sets `HIRZ_BROKER_SOCKET` for `hirz` and `hirzd`.

Trade-offs of the classic draft:

- **The broker loses its systemd sandbox.** snapd generates the service unit; the
  `DevicePolicy=`, `ProtectSystem=`, `SystemCallFilter=`, capability and other directives
  in `packaging/systemd/hirz-uhid-broker.service` cannot be expressed in `snapcraft.yaml`.
  The broker still drops to an empty capability set and refuses bad peers itself, but a
  classic snap's root daemon is less contained than the packaged one. This is the strongest
  argument for preferring the distribution packages.
- Setup is a manual root step. A classic snap's `install` hook runs as root and could do it
  automatically; it is kept manual because a hook that writes host configuration outside
  the snap's own directories is the kind of change store reviewers are expected to question.
- Refreshes are automatic. The manifest points to `/snap/hirz/current/bin/hirz-nmh` and the
  user unit to `/snap/bin/hirz.hirzd`, so they follow refreshes without rerunning setup.
- Do not install the snap and a distribution package of hirz at the same time.

## What the store review needs

Nothing below has been requested yet. In order:

1. Register the name: `snapcraft register hirz`.
2. Ask for classic confinement in the "store-requests" category of the Snapcraft forum. The
   request should explain: hirz is a FIDO2 authenticator that creates a kernel HID device
   through `/dev/uhid` from a root broker; it must bind the device node to its creating user
   with udev rules, register a polkit action, run the host's polkit agent, `zenity` and
   fprintd tools from root-owned host paths, and install a root-owned Firefox native
   messaging manifest. Link this page for why strict confinement (with the `uhid`,
   `polkit` and `personal-files` interfaces) loses the per-user device binding and
   fingerprint approval. Classic is granted only to some categories of software, so the
   request may be refused.
3. Until classic is granted, an upload is held for manual review. The release workflow
   uploads to the `edge` channel only, and only when `SNAPCRAFT_STORE_CREDENTIALS` exists
   (see `docs/release.md`). Promotion to `beta`, `candidate` or `stable` is manual:
   `snapcraft release hirz <revision> stable`.
4. When classic is granted, change `grade: devel` to `grade: stable`; a `devel` grade snap
   cannot be released to the stable or candidate channels.

If classic is refused, the honest outcome is no snap: the distribution packages and the own
apt and dnf repositories cover Ubuntu, and snap browsers already work with them.

## Building locally

```sh
mkdir -p snap && cp packaging/snap/snapcraft.yaml snap/ && cp -r packaging/snap/hooks snap/
snapcraft pack                      # LXD; or --destructive-mode on Ubuntu 24.04
sudo snap install --dangerous --classic ./hirz_*.snap
```

Remove the `snap/` copy afterwards; the source of truth is this directory.
