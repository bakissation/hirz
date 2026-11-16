# hirz

**Passkeys for Linux.** hirz is a security-first passkey authenticator written in Rust. It
works in Firefox and Chromium, syncs between your devices through your own folder sync, and
asks for your fingerprint or password before it signs anything.

- **Works where you browse.** hirz appears to browsers as a USB security key, so Firefox,
  Chromium and other FIDO2 tools use it with no plugin. An optional Firefox extension makes
  it a regular passkey provider.
- **Your sync, not ours.** Passkeys live in an encrypted vault folder. Syncthing, Nextcloud
  or any folder sync copies it between your computers; no hirz server exists.
- **Nothing signs without you.** Every request opens a hirz window that names the site and
  asks for your account password (polkit), your fingerprint (fprintd) or a hirz PIN.
- **Small and auditable.** Written in Rust with a handful of dependencies, cryptography only
  from AWS-LC and Argon2, a root helper that does one thing, and a documented threat model.
- **Portable.** Export and import passkeys in the FIDO Credential Exchange Format (CXF), and
  keep a 24-word recovery phrase for when every device is gone.

## Quick setup

1. Install the package for your distribution from the
   [releases page](https://github.com/bakissation/hirz/releases):

   ```sh
   sudo apt install ./hirz_*_amd64.deb       # Ubuntu, Debian
   sudo dnf install ./hirz-*.x86_64.rpm      # Fedora
   ```

   On Arch, install `hirz` from the AUR, then run
   `sudo systemctl enable --now hirz-uhid-broker.socket`.
2. Create your vault, inside your sync folder if you want your passkeys on several
   computers, and write down the recovery phrase it shows:

   ```sh
   hirz init --vault ~/Sync/hirz
   ```

3. Start hirz now and at every login:

   ```sh
   systemctl --user enable --now hirzd
   ```

4. Check everything is in place:

   ```sh
   hirz status
   ```

5. Sign in to a site that supports passkeys and choose "security key". Optionally add the
   Firefox extension.

Step-by-step instructions, Snap and Flatpak Firefox, uninstalling and troubleshooting are in
[docs/install.md](docs/install.md).

Documentation:

- [Install](docs/install.md)
- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Sync between computers](docs/sync.md)
- [Approving requests](docs/approval.md)
- [Command line](docs/cli.md)
- [Firefox extension](docs/extension.md)
- [Virtual security key (uhid)](docs/uhid.md)
- [Vault format](docs/vault-format.md)
- [Dependencies](docs/dependencies.md)
- [Packaging](packaging/README.md)

## Ownership

hirz is written and maintained by Abdelbaki Berkati
(blog: [berkati.xyz](https://berkati.xyz), GitHub: [bakissation](https://github.com/bakissation)).

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your
option (`MIT OR Apache-2.0`). Report vulnerabilities privately as described in the
[security policy](SECURITY.md).

Status: pre-release, not audited. Do not rely on hirz as the only way into an account yet.
