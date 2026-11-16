# Installing hirz

hirz is pre-release software and has not been audited. Keep another way into your
important accounts (a hardware key, recovery codes) while you try it.

You need a Linux desktop with systemd (Ubuntu 26.04, Debian 13, Fedora or Arch) and Firefox
or Chromium. Commands that start with `sudo` ask for your password.

## 1. Install the package

Pick one route. The package repositories below are available from the first release; until
then, build the package yourself (see
[Building the package yourself](#building-the-package-yourself)).

| Route | Updates | Distributions |
|---|---|---|
| [hirz apt repository](#apt-repository-debian-and-ubuntu) | with `apt upgrade` | Debian 13, Ubuntu 24.04 and newer, amd64 and arm64 |
| [Ubuntu PPA](#ubuntu-ppa) | with `apt upgrade` | Ubuntu 24.04 and 26.04 |
| [hirz dnf repository](#dnf-repository-fedora) | with `dnf upgrade` | Fedora, x86_64 and aarch64 |
| [Fedora COPR](#fedora-copr) | with `dnf upgrade` | the Fedora releases the COPR project builds for |
| [AUR](#arch-linux) | with your AUR helper | Arch Linux |
| [Download from GitHub Releases](#download-from-github-releases) | by hand | Debian, Ubuntu, Fedora |

Every route installs the same files. hirz is not offered as a snap or a Flatpak (see
`packaging/snap/README.md`); browsers installed as snaps or Flatpaks work with the
packages. The release workflow can upload a draft snap to the Snap Store's `edge` channel for
testing; it is not part of the signed checksums and not a supported route.

### Signing keys

Two keys sign what hirz publishes. Compare the fingerprint your tools show with these, with
the ones in the [README](../README.md) and with the notes of the release you install; they are
published in all three places, away from the repository's own site. If one differs, stop and
report it (see [SECURITY.md](../SECURITY.md)).

| Key | Fingerprint | What it signs |
|---|---|---|
| hirz archive key | `5831 16C2 55B8 72AF 888C  A940 E599 5331 0261 779A` | the apt and dnf repository |
| hirz PPA upload key | `4580 9408 7F6D 1BFF 4550  8EEA A5E3 5D5E 1CCF F011` | the source packages uploaded to the Ubuntu PPA (published on keyserver.ubuntu.com) |

### apt repository (Debian and Ubuntu)

Available from the first release. The repository's `Release` file is signed with the hirz
archive key, and apt checks every package against the hashes in it.

```sh
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://bakissation.github.io/hirz/hirz-archive-keyring.gpg |
  sudo tee /etc/apt/keyrings/hirz-archive-keyring.gpg >/dev/null
gpg --show-keys /etc/apt/keyrings/hirz-archive-keyring.gpg   # compare with the fingerprint below
sudo tee /etc/apt/sources.list.d/hirz.sources >/dev/null <<'EOF'
Types: deb
URIs: https://bakissation.github.io/hirz/apt
Suites: stable
Components: main
Signed-By: /etc/apt/keyrings/hirz-archive-keyring.gpg
EOF
sudo apt update
sudo apt install hirz
```

The one-line format works too:
`deb [signed-by=/etc/apt/keyrings/hirz-archive-keyring.gpg] https://bakissation.github.io/hirz/apt stable main`
in `/etc/apt/sources.list.d/hirz.list`.

Archive key fingerprint: `5831 16C2 55B8 72AF 888C  A940 E599 5331 0261 779A`. `gpg --show-keys`
prints it in this form; it must match, and the same fingerprint is in the README and in the
release notes. The repository's metadata has no expiry date, so apt cannot tell an old copy from
a new one: it is served over HTTPS from GitHub Pages only.

### Ubuntu PPA

Available from the first release. Built by Launchpad from the release sources, for Ubuntu
24.04 (noble) and 26.04 (resolute):

```sh
sudo add-apt-repository ppa:bakissation/hirz
sudo apt install hirz
```

Launchpad builds the packages and signs the PPA archive with its own key, which
`add-apt-repository` installs and which the PPA's page shows; apt trusts that key, not ours.
The source packages in the PPA were uploaded signed with the hirz PPA upload key
`4580 9408 7F6D 1BFF 4550  8EEA A5E3 5D5E 1CCF F011`: download the `.dsc` file from the PPA's
page ("View package details") and run `gpg --verify` on it to see which key signed it.

### dnf repository (Fedora)

Available from the first release. The repository metadata and the packages are signed;
dnf checks both.

```sh
sudo curl -fsSL -o /etc/yum.repos.d/hirz.repo https://bakissation.github.io/hirz/hirz.repo
sudo dnf install hirz
```

The file contains:

```ini
[hirz]
name=hirz
baseurl=https://bakissation.github.io/hirz/rpm/$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://bakissation.github.io/hirz/hirz-archive-keyring.asc
```

dnf shows the key fingerprint the first time and asks before importing it; compare it with
the archive key fingerprint above (it is the same key as for apt).

### Fedora COPR

Available from the first release. Built by COPR from the release sources:

```sh
sudo dnf copr enable bakissation/hirz
sudo dnf install hirz
```

### Download from GitHub Releases

Packages are attached to each release on
[github.com/bakissation/hirz/releases](https://github.com/bakissation/hirz/releases),
available from the first release. Each file has a GitHub attestation and a Sigstore
signature; [release.md](release.md#verifying-a-release) shows how to check them.

#### Ubuntu and Debian

1. Download the `.deb` file for your computer (`amd64` on most PCs) into your Downloads
   folder.
2. Install it:

   ```sh
   cd ~/Downloads
   sudo apt install ./hirz_*_amd64.deb
   ```

   apt also installs what hirz needs (polkit and zenity 4 or newer) and suggests fprintd for
   fingerprints.

#### Fedora

1. Download the `.rpm` file (`x86_64` on most PCs) into your Downloads folder.
2. Install it:

   ```sh
   cd ~/Downloads
   sudo dnf install ./hirz-*.x86_64.rpm
   ```

### Arch Linux

1. Install the `hirz` package from the AUR (available from the first release) with your
   AUR helper, or by hand:

   ```sh
   git clone https://aur.archlinux.org/hirz.git
   cd hirz
   makepkg -si
   ```

2. Arch packages do not start services on their own. Start the virtual security key broker:

   ```sh
   sudo systemctl enable --now hirz-uhid-broker.socket
   ```

On Ubuntu, Debian and Fedora the package starts the broker for you.

## 2. Set up hirz for your user

Do this once per user account, without `sudo`.

1. Create your vault. To use your passkeys on several computers, put the vault in a folder
   your sync tool copies (see [sync.md](sync.md)), for example:

   ```sh
   hirz init --vault ~/Sync/hirz
   ```

   Or keep it on this computer only:

   ```sh
   hirz init
   ```

   hirz shows a 24-word recovery phrase. Write it down on paper and keep it safe: it is the
   only way back to your passkeys if you lose your computers. hirz then asks for three of
   the words to check.

   On a second computer, wait until your sync tool has copied the vault folder, then run
   `hirz join --vault ~/Sync/hirz` instead and type the recovery phrase.

2. Start the hirz daemon now and at every login:

   ```sh
   systemctl --user enable --now hirzd
   ```

3. Check that everything is found:

   ```sh
   hirz status
   ```

From now on, sites that ask for a security key or passkey can use hirz in Firefox and
Chromium. Every time a site wants a passkey, hirz shows a window naming the site and asks
for your password, your fingerprint or your hirz PIN (see [approval.md](approval.md)).

## 3. Optional: the Firefox extension

The extension lets Firefox use hirz as a passkey provider instead of a security key, so
sites see a regular passkey prompt. The virtual security key works without it.

Once Mozilla has reviewed it (submitted with each release, available from the first
release), install it from addons.mozilla.org: search for "hirz" in Firefox's add-ons
manager. Check that the developer link points to github.com/bakissation/hirz.

Until then the extension is unsigned, so regular Firefox only loads it until the next
restart:

1. Download `hirz-*.xpi` from the release, or use the `extension` folder of the source.
2. Open `about:debugging#/runtime/this-firefox` in Firefox.
3. Click "Load Temporary Add-on" and choose the `.xpi` file (or `extension/manifest.json`).

Firefox Developer Edition and Nightly can install it permanently: set
`xpinstall.signatures.required` to `false` in `about:config`, then open the `.xpi` file
with Firefox. That setting turns off Firefox's check that add-ons are signed, for every
add-on, so any add-on you or a web page installs afterwards loads unchecked: use it only in a
profile you keep for trying hirz, and set it back to `true` when you are done.

Do not run `hirz setup firefox` when you installed a package: the package already installed
the Firefox connection system-wide, and a copy in your home folder would take precedence.
The command refuses while the packaged manifest exists; `--force` overrides that for a
build from source.

### Firefox from Snap (Ubuntu's default)

The first time a site uses the extension, a window asks "Allow Firefox to start WebExtension
backend?". Click Allow. It only appears while Firefox is the active window; if a request
fails instead, click into Firefox and try again.

### Firefox from Flatpak

See [packaging/flatpak/README.md](../packaging/flatpak/README.md).

## Uninstalling

1. Stop the daemon for your user (each user who enabled it):

   ```sh
   systemctl --user disable --now hirzd
   ```

2. Remove the package:

   ```sh
   sudo apt remove hirz      # Ubuntu, Debian
   sudo dnf remove hirz      # Fedora
   sudo pacman -Rns hirz     # Arch
   ```

3. Remove the extension in Firefox under `about:addons`, if you installed it.

Removing the package never deletes your vault. Your passkeys stay in the vault folder and
in `~/.local/state/hirz` (this computer's keys). Delete those folders only if you are sure
you no longer need the passkeys, for example after `hirz export` (see [cli.md](cli.md)) or
when another computer still has the vault.

## Troubleshooting

Start with `hirz status`. It shows each part and what is missing.

| What `hirz status` says | What to do |
|---|---|
| Not set up | Run `hirz init`, or `hirz join --vault DIR` on a second computer |
| Vault folder missing | Your sync tool has not copied it yet, or it moved. Check the folder |
| Broker socket not present | `sudo systemctl enable --now hirz-uhid-broker.socket` |
| polkit action not installed, or zenity missing or older than 4 | Reinstall the package, or update zenity |
| No approval method works | Make sure you are in a desktop session (polkit needs its agent), or set a PIN with `hirz pin set` |
| A manifest under your home folder (`~/.mozilla/...` or `~/.config/mozilla/...`) | Delete that file unless you develop hirz: it overrides the one from the package |
| Firefox is a Snap or Flatpak | See the sections above |

More checks:

- Is the daemon running? `systemctl --user status hirzd`, and its log:
  `journalctl --user -u hirzd -e`.
- Is the broker running? `systemctl status hirz-uhid-broker.socket hirz-uhid-broker.service`.
- Is the virtual key there? While `hirzd` runs, `ls -l /dev/hidraw*` shows one node owned by
  you. If not, check that the kernel module is loaded: `lsmod | grep uhid` (load it with
  `sudo modprobe uhid`).
- The broker log (`journalctl -u hirz-uhid-broker`) says "refused uid ...": the broker serves
  only a user with an active session on a seat, that is, a login at the computer's own screen
  (not `ssh`, not a session that went to the background after switching users), and only while
  the three hirz udev rule files (`70-hirz.rules`, `72-hirz.rules`, `99-zzz-hirz.rules`) are
  installed and not masked by a link to `/dev/null` or an empty file of the same name in
  `/etc/udev/rules.d`. The broker log names a missing rule at start. Log in at the computer,
  or reinstall the package. After a user switch, the key comes back within a minute of
  switching back.
- Snap Firefox does not see the key: `snap connections firefox` must show `u2f-devices`
  connected.

## Building the package yourself

You need git, a C compiler, cmake and Rust (from [rustup.rs](https://rustup.rs)).

Ubuntu and Debian:

```sh
sudo apt install git build-essential cmake curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
git clone https://github.com/bakissation/hirz.git
cd hirz
scripts/package-deb.sh
sudo apt install ./dist/hirz_*.deb
```

Fedora:

```sh
sudo dnf install git rpm-build cargo rust gcc cmake systemd-rpm-macros
git clone https://github.com/bakissation/hirz.git
cd hirz
scripts/package-rpm.sh
sudo dnf install ./dist/hirz-*.x86_64.rpm
```

Arch: `packaging/arch/PKGBUILD` builds from a release tag with `makepkg -si`.

The Firefox extension: `scripts/build-xpi.sh` writes `dist/hirz-VERSION.xpi`.
