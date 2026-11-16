# Dependencies

hirz keeps its dependency tree small on purpose. Spec-defined formats (CBOR, COSE,
authenticatorData, clientDataJSON, CTAPHID, native messaging, the vault format, JSON for the
native messaging envelope) are written in this repository and fuzzed. Cryptographic primitives
are never written here; they come from the libraries below and are only reachable through
`hirz-crypto`.

Adding a dependency requires a line in this file, a change to `supply-chain/allowed-deps.txt`
(`scripts/check.sh deps` fails when the tree of a shipped program differs from it) and a
passing `cargo deny check`.

## Runtime

The workspace crates (`hirz-proto`, `hirz-crypto`, `hirz-sys`, `hirz-vault`, `hirz-ctap`,
`hirz-webauthn`, `hirz-core`, `hirz-uv`, `hirz-session`, `hirzd`, `hirz-uhid-broker`, `hirz-nmh`,
`hirz-cli`) are path dependencies. They are not covered by `cargo deny` bans or `cargo vet`, and
add nothing to the tables below: a new internal crate that pulls an external one shows up as a
difference in `supply-chain/allowed-deps.txt`.

| Crate | Used by | Why it is needed | Notes |
|---|---|---|---|
| `aws-lc-rs` (+ `aws-lc-sys`) | hirz-crypto | ES256, Ed25519, SHA-256, HMAC, HKDF, AES-GCM, AES-CBC, X25519, P-256 ECDH, RNG | AWS-LC has a FIPS 140-3 validated module and formally verified parts of P-256 and Ed25519. Bundled C library built from source |
| `argon2` (+ `blake2`, `base64ct`, `digest`, `crypto-common`, `block-buffer`, `hybrid-array`, `typenum`, `cpufeatures`, `cmov`, `ctutils`) | hirz-crypto | Argon2id for the PIN verifier and passphrase-protected exports | RustCrypto. Not yet in a cargo-vet import set: exempted without an audit record (see "Supply chain checks"), tested against RFC 9106 vectors |
| `zeroize` | hirz-crypto (re-exported to other crates), hirz-proto | Wipes secrets on drop; hirz-proto uses it to wipe the text and bytes its JSON and CBOR readers build when they fail, and the values they return when dropped | Audited by several cargo-vet import sets |
| `libc` | hirz-sys | prctl, setrlimit, mlockall, SO_PEERCRED, flock, uhid I/O | rust-lang owned |

## Build only

`cc`, `cmake`, `jobserver`, `shlex`, `dunce`, `fs_extra`, `pkg-config`, `find-msvc-tools`:
pulled by `aws-lc-sys` to compile AWS-LC. They do not end up in the binaries.

## Tool only

| Crate | Used by | Why |
|---|---|---|
| `serde_json` (+ `serde_core`, `itoa`, `memchr`, `zmij`) | hirz-cli import/export | Reading and writing FIDO CXF files (JSON). Default features off except `std`; no `serde` derive, no proc macros. Never linked into hirzd or hirz-nmh |

## Build and release tools

Programs used to build, check and publish hirz. None of them is linked into a binary; each
is pinned to a version in the workflow that uses it (see [release.md](release.md)).

| Tool | Version | Used by | Why |
|---|---|---|---|
| `cargo-auditable` | 0.7.7 | `scripts/build-release.sh --auditable`, `build.yml`, the RPM spec (`--with auditable`) | Wraps `cargo build` and embeds the dependency list (names, versions, sources from `Cargo.lock`) in a `.dep-v0` section of each binary, so `cargo audit bin`, Trivy or Syft can check a shipped binary against RustSec without the source. Changes no code |
| `cargo-deny` | 0.20.2 | `scripts/check.sh deny`, CI | Licenses, bans, RustSec advisories, sources (`deny.toml`) |
| `cargo-vet` | 0.10.3 | `scripts/check.sh vet`, CI | Records which crates are covered by imported audits and which are exempted (`supply-chain/`, see below) |
| `cargo-fuzz` | 0.13.2 | `scripts/fuzz.sh`, nightly CI | libFuzzer targets in `fuzz/`, on a nightly pinned by date (`nightly-2026-11-12`) |
| `release-plz` | 0.4.3 | `release-plz.yml` | Release PR, version bump, `CHANGELOG.md`, tags (git-only, nothing published to crates.io). The binary is downloaded and checked against a pinned SHA-256 (`scripts/ci/install-release-plz.sh`), not installed by an action |
| `cosign` | 3.1.4 | `release.yml` | Keyless Sigstore signatures of every release file |
| `actions/attest-build-provenance` | 4.2.2 | `release.yml` | GitHub artifact attestations (SLSA provenance) |
| Node.js | 24.22.2 | `ci.yml` (`actions/setup-node`) | Runs `scripts/extension-test.mjs` with `node --test`; the tests import only Node's own modules, and no npm package is installed |
| `scripts/amo-submit.py` | Python 3 standard library only | `release.yml` | Submits the extension to addons.mozilla.org through the AMO API; no npm or PyPI package |
| `copr-cli` | Fedora 45 package | `release.yml` | Starts the COPR build from the release's source RPM, installed with `dnf` in the digest-pinned Fedora image |
| `reprepro`, `createrepo_c`, `rpmsign`, `gnupg` | Debian 13 packages | `scripts/ci/publish-pkgrepo.sh` | The signed apt and dnf repository |
| `dpkg-dev`, `devscripts`, `dput` | Ubuntu packages | `scripts/package-debsrc.sh`, `release.yml` | Debian source package for the PPA, signing and upload |
| `snapcraft` | 8.14.5 (`8.x/stable`, the job fails on another version) | `release.yml` | The draft snap (`packaging/snap/`) |

Build containers are pinned by digest in `.github/workflows/build.yml` and `release.yml`:
`rust:1.99.1-trixie` (binaries, `.deb`, source tarballs), `fedora:45` (`.rpm` and the COPR
job), `debian:trixie-slim` (package repository) and `archlinux:base` (AUR metadata).
Third-party GitHub Actions are pinned by full commit SHA with the version in a comment, and
Dependabot proposes updates. Dependabot does not read the images in workflows, so their
digests are refreshed by hand; `scripts/check.sh toolchain` fails when an image is not pinned
by digest or when the Rust toolchain and image differ between the workflows, the docs, the
snap draft and `rust-toolchain.toml`.

## Bundled data

Two data files are compiled into the shipped programs with `include_str!`, and one more is used
by tests. They are not crates, so `cargo deny` does not see them. Each keeps its own license:

| File | Used by | License | Source and notes |
|---|---|---|---|
| `crates/hirz-webauthn/data/public_suffix_list.dat` | `hirz-nmh` (RP ID validation) | MPL-2.0 | Public Suffix List, used unmodified; version, commit and update steps in `crates/hirz-webauthn/README.md`. Applies to that file only; the text is in `LICENSES/MPL-2.0.txt` |
| `crates/hirz-vault/data/bip39-english.txt` | `hirz-vault` (recovery words), so every program that links it | MIT | English word list of BIP-39, used unchanged; authors and notice in `crates/hirz-vault/data/LICENSE-BIP39` |
| `crates/hirz-webauthn/data/test_psl.txt` | tests only, not shipped | CC0-1.0 | Test vectors of the Public Suffix List project |

Packages declare these in their license metadata (the RPM `License:` tag, the PKGBUILD, the snap
and `debian/copyright`). `REUSE.toml` maps every path to its license, and `LICENSES/` holds the
texts. The hirz name, logo, wordmark and icons are not under the project license, see
`assets/brand/README.md`.

## Supply chain checks

- `cargo deny` (licenses, bans, RustSec advisories, sources) covers the main workspace. It runs
  on every push and pull request and every night (an advisory can appear after a merge).
  The `fuzz/` workspace is outside it and outside `cargo vet`: it ships nothing and holds no
  secret (see [fuzzing.md](fuzzing.md)).
- `cargo vet` passes with a mix of imported audits and exemptions. Crates covered by an
  audit set that this project imports (Mozilla, Google, Bytecode Alliance, ISRG, Zcash) or by
  a trusted publisher entry in `supply-chain/audits.toml` count as audited. The trusted
  publishers are the ones the imported sets also trust: the rust-lang crates team account
  (`cfg-if`, `cmake`, `jobserver`), the crates.io accounts `BurntSushi` (`memchr`), `cuviper`
  (`find-msvc-tools`) and `dtolnay` (`itoa`, `proc-macro2`, `serde`, `serde_core`,
  `serde_derive`, `serde_json`, `syn`, `unicode-ident`, `zmij`); each entry is in
  `supply-chain/audits.toml`. The rest are exemptions in `supply-chain/config.toml`, 19 of the 39
  crates at the time of writing: `aws-lc-rs` and `aws-lc-sys` (the cryptographic backend),
  the `argon2` and RustCrypto support crates, `libc`, `cc`, `getrandom` and its `r-efi`,
  `typenum` and `fs_extra`. An exemption or a publisher trust entry is a trust decision
  resting on upstream review and on RustSec advisories, not an audit by this project, and
  `supply-chain/audits.toml` records no audit of its own. The cryptographic backend in particular is too large to audit here;
  packagers should not read the exemptions as reviewed code.
- `supply-chain/allowed-deps.txt` lists the external crates of each shipped program; the CI
  fails when a tree differs.

## Not used, on purpose

- No async runtime, no TLS stack, no HTTP client: hirz never talks to the network.
- No D-Bus library: polkit and fprintd are reached through their command-line tools.
- No GUI toolkit: prompts use the desktop's `zenity`.
- No CBOR, COSE, JSON or WebAuthn crates in shipped binaries. `passkey-rs`, `webauthn-rs`,
  `python-fido2` and `libfido2` are used only as test oracles outside the build.
