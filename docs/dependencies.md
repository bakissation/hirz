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

## Not used, on purpose

- No async runtime, no TLS stack, no HTTP client: hirz never talks to the network.
- No D-Bus library: polkit and fprintd are reached through their command-line tools.
- No GUI toolkit: prompts use the desktop's `zenity`.
- No CBOR, COSE, JSON or WebAuthn crates in shipped binaries. `passkey-rs`, `webauthn-rs`,
  `python-fido2` and `libfido2` are used only as test oracles outside the build.
