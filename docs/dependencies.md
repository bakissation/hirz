# Dependencies

hirz keeps its dependency tree small on purpose. Spec-defined formats (CBOR, COSE,
authenticatorData, clientDataJSON, CTAPHID, native messaging, the vault format, JSON for the
native messaging envelope) are written in this repository and fuzzed. Cryptographic primitives
are never written here; they come from the libraries below and are only reachable through
`hirz-crypto`.

Adding a dependency requires a line in this file and a passing `cargo deny check`.

## Runtime

| Crate | Used by | Why it is needed | Notes |
|---|---|---|---|
| `aws-lc-rs` (+ `aws-lc-sys`) | hirz-crypto | ES256, Ed25519, SHA-256, HMAC, HKDF, AES-GCM, AES-CBC, X25519, P-256 ECDH, RNG | AWS-LC has a FIPS 140-3 validated module and formally verified parts of P-256 and Ed25519. Bundled C library built from source |
| `argon2` (+ `blake2`, `base64ct`, `digest`, `crypto-common`, `block-buffer`, `hybrid-array`, `typenum`, `cpufeatures`, `cmov`, `ctutils`) | hirz-crypto | Argon2id for the PIN verifier and passphrase-protected exports | RustCrypto. Not yet in a cargo-vet import set: audited by this project, tested against RFC 9106 vectors |
| `zeroize` | hirz-crypto (re-exported to other crates) | Wipes secrets on drop | Audited by several cargo-vet import sets |
| `libc` | hirz-sys | prctl, setrlimit, mlockall, SO_PEERCRED, uhid I/O | rust-lang owned |

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
| `cargo-vet` | 0.10.3 | `scripts/check.sh vet`, CI | Audit records for every crate (`supply-chain/`) |
| `cargo-fuzz` | 0.13.2 | `scripts/fuzz.sh`, nightly CI | libFuzzer targets in `fuzz/` (nightly toolchain) |
| `release-plz` | 0.4.3 | `release-plz.yml` | Release PR, version bump, `CHANGELOG.md`, tags (git-only, nothing published to crates.io) |
| `cosign` | 3.1.4 | `release.yml` | Keyless Sigstore signatures of every release file |
| `actions/attest-build-provenance` | 4.2.2 | `release.yml` | GitHub artifact attestations (SLSA provenance) |
| `web-ext` | 10.8.0 | `release.yml` | Signs and submits the extension to addons.mozilla.org |
| `copr-cli` | 2.9 | `release.yml` | Starts the COPR build from the release's source RPM |
| `reprepro`, `createrepo_c`, `rpmsign`, `gnupg` | Debian 13 packages | `scripts/ci/publish-pkgrepo.sh` | The signed apt and dnf repository |
| `dpkg-dev`, `devscripts`, `dput` | Ubuntu packages | `scripts/package-debsrc.sh`, `release.yml` | Debian source package for the PPA, signing and upload |
| `snapcraft` | 8.x | `release.yml` | The draft snap (`packaging/snap/`) |

Build containers are pinned by digest in `.github/workflows/build.yml` and `release.yml`:
`rust:1.99.1-trixie` (binaries, `.deb`, source tarballs), `fedora:45` (`.rpm`),
`debian:trixie-slim` (package repository) and `archlinux:base` (AUR metadata). Third-party
GitHub Actions are pinned by full commit SHA with the version in a comment, and Dependabot
proposes updates.

## Not used, on purpose

- No async runtime, no TLS stack, no HTTP client: hirz never talks to the network.
- No D-Bus library: polkit and fprintd are reached through their command-line tools.
- No GUI toolkit: prompts use the desktop's `zenity`.
- No CBOR, COSE, JSON or WebAuthn crates in shipped binaries. `passkey-rs`, `webauthn-rs`,
  `python-fido2` and `libfido2` are used only as test oracles outside the build.
