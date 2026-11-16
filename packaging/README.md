# Packaging hirz

Every distribution package installs the same set of files. Only the directory of the root
broker follows the distribution's convention for internal programs; the native messaging
manifest points to the same `hirz-nmh` path everywhere.

| What | Debian / Ubuntu (.deb) | Fedora (.rpm) | Arch (AUR) | Mode |
|---|---|---|---|---|
| CLI | `/usr/bin/hirz` | same | same | 0755 |
| User daemon | `/usr/bin/hirzd` | same | same | 0755 |
| Native messaging host (not on `PATH`) | `/usr/lib/hirz/hirz-nmh` | same | same | 0755 |
| uhid broker (root) | `/usr/libexec/hirz/hirz-uhid-broker` | `/usr/libexec/hirz/hirz-uhid-broker` | `/usr/lib/hirz/hirz-uhid-broker` | 0755 |
| Broker units | `/usr/lib/systemd/system/hirz-uhid-broker.{socket,service}` | same | same | 0644 |
| User unit | `/usr/lib/systemd/user/hirzd.service` | same | same | 0644 |
| udev rules | `/usr/lib/udev/rules.d/70-hirz.rules` and `72-hirz.rules` | same | same | 0644 |
| polkit action | `/usr/share/polkit-1/actions/dev.hirz.authenticate.policy` | same | same | 0644 |
| Module list (`uhid`) | `/usr/lib/modules-load.d/hirz.conf` | same | same | 0644 |
| Firefox native manifest | `/usr/lib/mozilla/native-messaging-hosts/hirz.json` | same, plus `/usr/lib64/mozilla/native-messaging-hosts/hirz.json` (a relative symlink to it) | same as Debian | 0644 |
| Manual pages | `/usr/share/man/man1/hirz.1`, `hirzd.1`, `hirz-nmh.1` and `/usr/share/man/man8/hirz-uhid-broker.8` (compressed by the package tools) | same | same | 0644 |
| Preset enabling the broker socket | none | `/usr/lib/systemd/system-preset/80-hirz.preset` | none | 0644 |

All files and directories are owned by root. Nothing is installed in `/etc` (no conffiles)
and nothing in a home directory.

## Sources of the installed files

| Installed file | Source in this repository | Change at install time |
|---|---|---|
| `hirz-uhid-broker.service` | `packaging/systemd/hirz-uhid-broker.service` | `ExecStart` path set to the distribution's broker path |
| `hirz-uhid-broker.socket` | `packaging/systemd/hirz-uhid-broker.socket` | none |
| `hirzd.service` | `packaging/systemd/hirzd.service` | `ExecStart` path set to `/usr/bin/hirzd` |
| `70-hirz.rules`, `72-hirz.rules` | `packaging/udev/` | none |
| `dev.hirz.authenticate.policy` | `packaging/polkit/dev.hirz.authenticate.policy` | none |
| `hirz.json` | `packaging/native-messaging/hirz.json` | `@HIRZ_NMH_PATH@` replaced by `/usr/lib/hirz/hirz-nmh` |
| `hirz.conf` | written by the build | contains `uhid` |
| Manual pages | `docs/man/` (hand-written roff) | gzip |

Every package script checks that the substitution happened and stops otherwise.

## Why the manifest is system-wide and root-owned

A manifest in the user's home (`~/.mozilla/native-messaging-hosts/hirz.json`) can be
rewritten by any program running as that user, which could point Firefox at a different
program that receives every passkey request. The packaged manifest and the `hirz-nmh` binary
are root-owned, so only an administrator can change them.

Firefox, the WebExtensions portal and xdg-native-messaging-proxy all look in the user's
folders before the system folders. A per-user `hirz.json` therefore wins over the packaged
one. Package users should not run `hirz setup firefox`, which exists for development
builds. `hirz status` lists every manifest it finds; it should warn when a per-user manifest
(`~/.mozilla/native-messaging-hosts/hirz.json` or
`$XDG_CONFIG_HOME/mozilla/native-messaging-hosts/hirz.json`) exists while a system manifest
is installed, say that the per-user file takes precedence, show the program it starts, and
suggest removing it.

## Install and remove scripts

| Step | Debian / Ubuntu | Fedora | Arch |
|---|---|---|---|
| After install | enable `hirz-uhid-broker.socket` with `deb-systemd-helper` (first install, or again if it was enabled before), `daemon-reload`, `udevadm control --reload`, `modprobe uhid`, start the socket | `%systemd_post` with the preset, `%udev_rules_update`, `modprobe uhid`, start the socket | pacman hooks reload systemd and udev; `hirz.install` loads `uhid` and prints the command to enable the socket |
| Upgrade | restart the broker if it runs; an administrator's `disable` is kept | `%systemd_postun_with_restart` | prints a reminder to restart the broker |
| Before removal | stop the broker socket and service | `%systemd_preun` | `systemctl disable --now` the socket and service |
| After removal | mask the socket on `remove` (state kept for a reinstall), forget it on `purge`; `daemon-reload`, `udevadm control --reload` | `%udev_rules_update` | pacman hooks |

The user unit `hirzd.service` is never enabled by a package: each user runs
`systemctl --user enable --now hirzd` after `hirz init`. Arch packages do not enable
services on install, so the Arch package prints the broker command instead of running it.
Removal never touches vaults or device state in home directories (`~/.local/share/hirz`,
`~/.local/state/hirz`, `~/.config/hirz`, or a vault inside a sync folder).

## Building

```sh
scripts/build-release.sh                        # dist/hirz-VERSION-ARCH-linux.tar.gz + .sha256
scripts/build-release.sh --verify-reproducible  # two clean builds, compares the binaries
scripts/package-deb.sh                          # dist/hirz_VERSION_ARCH.deb (needs dpkg-deb)
scripts/package-rpm.sh                          # RPM when rpmbuild exists, otherwise prints what to do
scripts/build-xpi.sh                            # dist/hirz-VERSION.xpi, deterministic zip
scripts/package-debsrc.sh                       # Debian source package, from the two tarballs
scripts/set-version.sh --check                  # every file carries the Cargo.toml version
```

Arch: `cd packaging/arch && makepkg -si` once release `v$pkgver` exists (`makepkg` downloads
its source tarball and vendored crates). To build before a release exists, run
`scripts/package-rpm.sh --sources-only` and copy `dist/rpm/SOURCES/hirz-*.tar.*` next to the
`PKGBUILD`: `makepkg` uses existing source files instead of downloading them (the sums in
the repository are `SKIP`; the AUR copy carries the real ones).

Release builds pass `--locked`, remap the source and Cargo paths
(`--remap-path-prefix`, and `-ffile-prefix-map` for the C code of AWS-LC), take
`SOURCE_DATE_EPOCH` from the last commit and strip symbols. `build-release.sh` warns when a
local path is still found in a binary.

## Directories

- `deb/`: maintainer scripts (`postinst`, `prerm`, `postrm`) used by `scripts/package-deb.sh`
  and by the Debian source package.
- `debian/`: Debian source package for the Ubuntu PPA. It builds offline from the release
  source tarball and the vendored crates tarball with the distribution's Rust compiler;
  `scripts/package-debsrc.sh` assembles and checks it (see `docs/release.md`).
- `rpm/`: `hirz.spec`, and `hirz.rpmlintrc` with the filters for rpmlint's false positives
  (`rpmlint -r packaging/rpm/hirz.rpmlintrc hirz.spec *.rpm`).
- `arch/`: `PKGBUILD` and `hirz.install`.
- `flatpak/`: how hirz works with Firefox installed as a Flatpak. hirz itself is not a
  Flatpak.
- `snap/`: a draft `snapcraft.yaml` and why hirz needs classic confinement as a snap.
- `amo/`: listing metadata for the first submission of the Firefox extension to
  addons.mozilla.org.
- `systemd/`, `udev/`, `polkit/`, `native-messaging/`: the source files above.
