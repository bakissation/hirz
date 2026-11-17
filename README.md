<p align="center">
  <img src="assets/brand/hirz-wordmark-light.svg#gh-light-mode-only" alt="hirz" height="96">
  <img src="assets/brand/hirz-wordmark-dark.svg#gh-dark-mode-only" alt="hirz" height="96">
</p>

<h1 align="center">hirz: passkeys for Linux</h1>

<p align="center"><b>Your keys. Your machine. Your say.</b><br>
Sign in to websites with a passkey on Linux, using your fingerprint or your computer password. No passwords to type, no new account, and your passkeys stay in sync across your computers.</p>

<p align="center">
  <!-- Badges: enable when the repo is public and CI runs. -->
  <!-- <a href="https://github.com/bakissation/hirz/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/bakissation/hirz"></a> -->
  <!-- <a href="https://addons.mozilla.org/firefox/addon/hirz/"><img alt="Firefox add-on" src="https://img.shields.io/amo/v/hirz"></a> -->
  <img alt="License: MIT or Apache 2.0" src="https://img.shields.io/badge/license-MIT%20or%20Apache%202.0-0F766E">
  <img alt="Status: pre-release" src="https://img.shields.io/badge/status-pre--release-F59E0B">
</p>

## Passkeys on Linux, finally

Windows has Windows Hello. Macs have Touch ID and iCloud Keychain. Phones have passkeys built in. On Linux, browsers could only use passkeys stored on a plug-in USB security key, so people moving to Linux lost "Sign in with a passkey" on the sites they use every day.

hirz brings passkeys to Linux. It is a passkey manager for your Linux computer that:

- **Lets you sign in without a password** on sites that support passkeys, such as Google, GitHub, Microsoft accounts and many banks and shops (some sites only accept passkeys from specific devices; see the questions below).
- **Uses your fingerprint or your computer password** to approve every sign-in, like Windows Hello or Touch ID. A hirz PIN works too.
- **Works in Firefox and Google Chrome on Ubuntu, Fedora, Arch and more**, including the Firefox Snap and Flatpak. No USB security key needed.
- **Syncs your passkeys between your computers** through a folder you already sync (Syncthing, Nextcloud, Dropbox or git). No hirz account, no hirz server.
- **Adds a new computer by comparing 4 words**, like pairing a Bluetooth device.
- **Keeps a way back**: 24 recovery words on paper restore everything if you lose all your devices.
- **Protects you from phishing**: a passkey only works on the website it was made for.
- **Imports and exports passkeys** using the FIDO Credential Exchange format, encrypted with a passphrase.

hirz is open source, written in Rust, never connects to the internet, and has a short list of dependencies. Read exactly what it protects against, and what it does not, in the [threat model](docs/threat-model.md).

### Questions people ask

**Can I use passkeys on Linux?**
Yes. With hirz installed, your browser on Linux can create and use passkeys stored on your computer, just like on Windows or a Mac.

**Do I need a YubiKey or another security key?**
No. hirz works on its own. If you have a hardware security key, it keeps working next to hirz.

**Can I use my fingerprint to sign in on Linux?**
Yes, if your computer has a fingerprint reader that works on Linux. Otherwise hirz asks for your computer password or a hirz PIN.

**Does it work with Google, GitHub and other big sites?**
It works with sites that offer "Sign in with a passkey" and accept passkeys from password managers. A few sites only accept passkeys from specific devices or companies and may refuse hirz.

**Does it work in Chrome or Chromium?**
Yes. hirz appears to your browser as a security key, and Firefox and Google Chrome are tested. Other browsers that support security keys, such as Chromium, Brave and Edge, should work too; if one does not, please [tell us](https://github.com/bakissation/hirz/issues/new/choose).

**What happens if I lose my laptop?**
Your passkeys are still on your other computers. On another computer, remove the lost one with `hirz remove-device`; hirz changes the vault key so the lost laptop cannot read anything new, and lists the sites where you should replace the passkey. If you lost every device, your 24 recovery words and a copy of your sync folder bring everything back.

**Is it safe?**
Each passkey is encrypted on disk, every sign-in needs your approval, and a passkey cannot be used on a fake website. hirz is software, so malware running as you on an unlocked computer could copy your passkeys; a hardware security key protects against that. hirz is pre-release and has not had an independent security review yet.

**Where is the name from?**
hirz (حرز, say it like *hearts* without the t) is an old Arabic word for a safe place where something precious is kept.

## Quick setup

These steps are for Ubuntu. Debian, Fedora, Arch and other routes are in [docs/install.md](docs/install.md). Packages are published from the first release, coming soon.

1. Install hirz:
   ```
   sudo add-apt-repository ppa:bakissation/hirz
   sudo apt install hirz
   ```
2. Open a site that offers passkeys and try to register one. The first time, hirz opens a setup window: click Set up, write the 24 recovery words on paper when hirz shows them, and type the two it asks for. Then try the site again. To sync with your other computers, create the vault in a terminal instead, inside a folder you already sync:
   ```
   hirz init --vault ~/Sync/hirz
   ```
3. Optional, for passkey suggestions in sign-in boxes: at the end of setup, hirz offers to open the page of its Firefox add-on. The package already connected Firefox to hirz for every user, so do not run `hirz setup firefox` (that command is for builds from source and would override the packaged connection).
4. Check that everything is ready:
   ```
   hirz status
   ```

That's it. Next time a website offers "Sign in with a passkey", choose it and approve with your fingerprint or password.

### Check the signing keys

The hirz apt and dnf repository is signed with the key `5831 16C2 55B8 72AF 888C  A940 E599 5331 0261 779A`, and the source packages of the Ubuntu PPA are uploaded signed with `4580 9408 7F6D 1BFF 4550  8EEA A5E3 5D5E 1CCF F011` (Launchpad signs the PPA archive itself with its own key). Compare these with what `gpg --show-keys`, `gpg --verify` or dnf shows before you trust a key. The same fingerprints are in [docs/install.md](docs/install.md) and in the notes of every release; if one place differs from the others, do not install and [report it](SECURITY.md).

More: [Sync between computers](docs/sync.md) · [All commands](docs/cli.md) · [Approving sign-ins](docs/approval.md) · [How it works](docs/architecture.md) · [Threat model](docs/threat-model.md) · [Firefox add-on](docs/extension.md) · [Virtual security key](docs/uhid.md) · [Vault format](docs/vault-format.md) · [Dependencies](docs/dependencies.md) · [Releases](docs/release.md) · [Packaging](packaging/README.md)

## Maintainer, sponsor and license

Built and maintained by **Abdelbaki Berkati**: [berkati.xyz](https://berkati.xyz) · [@bakissation](https://github.com/bakissation).

Development is **funded by [IdeaCrafters](https://ideacrafters.com)** ([@IdeaCraftersHQ](https://github.com/IdeaCraftersHQ)), the labelled incubator that powers R&D and pays for this open-source project to exist.

The project is maintainer-led: bug reports are welcome, feature pull requests by prior agreement (see [CONTRIBUTING.md](CONTRIBUTING.md)). **Feedback shapes the roadmap: [open an issue](https://github.com/bakissation/hirz/issues/new/choose) with bugs, sites that refuse hirz, or what you wish it did.** Security reports go to [SECURITY.md](SECURITY.md), never a public issue.

Licensed under either the [MIT license](LICENSE-MIT) or the [Apache License 2.0](LICENSE-APACHE), at your option. The bundled [Public Suffix List](crates/hirz-webauthn/data/public_suffix_list.dat) keeps its own license, the Mozilla Public License 2.0. The hirz name, logo, wordmark and icons are all rights reserved and not covered by it, see [assets/brand/README.md](assets/brand/README.md).

**Status: pre-release, not independently audited.** Keep another way to sign in to important accounts while hirz is young.
