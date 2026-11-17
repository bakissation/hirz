# hirz with Firefox from Flatpak

hirz is installed from your distribution's package (`.deb`, `.rpm` or AUR), not as a
Flatpak. This page is about using it from Firefox installed as a Flatpak
(`org.mozilla.firefox` from Flathub). Both hirz paths can work there, with different setup.

Status: the virtual security key is expected to work with no setup; the extension path is
experimental. Report what you see with `hirz status` output and your Firefox and Flatpak
versions.

## Virtual security key: works without setup

Firefox on Flathub runs with `--device=all`, so it sees `/dev/hidraw*` like a Firefox from
the distribution. The hidraw node of the hirz device belongs to your user with mode 0600
(see `docs/uhid.md`), and the Flatpak runs as your user, so Firefox can open it.

1. Install the hirz package and set up your vault as `docs/install.md` describes (the setup
   window, or `hirz init`).
2. Check the device exists: `hirz status` shows the broker socket, and
   `ls -l /dev/hidraw*` shows one node owned by you.
3. Open a site that supports passkeys and choose "security key" when asked.

Limits:

- Start `hirzd` before Firefox if the key is not found. Firefox learns about new security
  keys from udev, and that may not reach the sandbox in every Flatpak version; a key that
  exists when Firefox starts is always enumerated.
- Firefox, not hirz, checks the site's origin on this path, exactly as with a hardware key.

## Firefox extension: experimental, needs the native messaging proxy

A Flatpak Firefox cannot start programs on the host by itself. Firefox 157 and later can
ask a host service to start the native messaging host for it:

- **xdg-native-messaging-proxy** (D-Bus name `org.freedesktop.NativeMessagingProxy`): a
  small host service that reads native manifests from the usual host folders and starts the
  host outside the sandbox. It does not ask the user anything.
- **The WebExtensions portal** (`org.freedesktop.portal.WebExtensions`): a distribution
  patch to xdg-desktop-portal, shipped by Ubuntu. It asks once per application whether
  Firefox may start the hirz backend. Firefox uses it only when the proxy is not available.

Both read the root-owned manifest the hirz package installs at
`/usr/lib/mozilla/native-messaging-hosts/hirz.json` (and `/usr/lib64/...` on Fedora), which
points to `/usr/lib/hirz/hirz-nmh`. No manifest inside `~/.var/app/org.mozilla.firefox` is
used.

Setup with the proxy:

1. Install the proxy on the host:

   ```sh
   sudo apt install xdg-native-messaging-proxy     # Debian, Ubuntu
   sudo dnf install xdg-native-messaging-proxy     # Fedora
   ```

   On Arch, install `xdg-native-messaging-proxy` from the official repositories or the
   AUR, whichever carries it.
2. Let the Firefox Flatpak talk to it (only needed if your Flathub build does not allow it
   already; the command is harmless otherwise):

   ```sh
   flatpak override --user --talk-name=org.freedesktop.NativeMessagingProxy org.mozilla.firefox
   ```
3. In Firefox, open `about:config` and check that
   `widget.use-xdg-desktop-portal.native-messaging-proxy` is `1` or `2` (`2`, the default
   in a Flatpak, means "when sandboxed"). If it is `0`, set it to `2`.
4. Restart Firefox, install the hirz extension, and open a site that supports passkeys.

On Ubuntu without the proxy, the portal asks "Allow Firefox to start WebExtension
backend?" the first time; answer while Firefox is the focused window. The answer is stored
for the application id `org.mozilla.firefox` and can be checked or reset with:

```sh
flatpak permissions webextensions
flatpak permission-remove webextensions hirz
```

Limits:

- Requires Firefox 157 or later. Check with `flatpak info org.mozilla.firefox`.
- Without the proxy and without the Ubuntu portal patch, the extension cannot reach hirz.
  It then stays out of the way: every ceremony falls back to Firefox's own WebAuthn, and
  the virtual security key above still works.
- A per-user manifest in `~/.mozilla/native-messaging-hosts/` takes precedence over the
  packaged one for the proxy and the portal too. Remove it unless you are developing hirz.

## Undo

```sh
flatpak override --user --reset org.mozilla.firefox     # removes all your overrides for it
flatpak permission-remove webextensions hirz
```
