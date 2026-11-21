# Changelog

All notable changes to this project are documented in this file. Entries are written by
release-plz from the Conventional Commits merged since the previous release
(see [docs/release.md](docs/release.md)).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/bakissation/hirz/compare/v0.1.0...v0.1.1) - 2026-11-21

### Added

- *(cli)* show whether hirzd runs in hirz status

## [0.1.0](https://github.com/bakissation/hirz/releases/tag/v0.1.0) - 2026-11-17

### Added

- work right after install, with a graphical first-run setup
- import passkeys from Bitwarden and KeePassXC
- SSH key labels, refuse pam-u2f, man pages, final add-on id
- *(pairing)* approving a new device requires password, fingerprint or PIN
- *(pairing)* add a device by comparing four words, no recovery phrase; safer init phrase display
- *(vault)* variable-length credential ids for imported passkeys, vault helpers
- *(cli)* hirz command line with vault setup, devices, PIN and encrypted CXF export/import

### Changed

- keep only comments that explain the non-obvious
- simplify app crates and extension without behaviour change

### Documentation

- prepare the repository for public release

### Fixed

- verify device removal, stop removed devices, visible fingerprint window

### Other

- *(supply-chain)* cargo-deny and cargo-vet gates, rpm/arch/deb lint fixes, more fuzz targets, status manifest warning, nmh list handler
- workspace skeleton, licences, architecture contracts

### Security

- harden sync, approval, the browser path and releases
