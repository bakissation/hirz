# Fuzzing

The parsers of untrusted bytes are pure functions over `&[u8]` (or `&str`) with explicit size
limits, so they are libFuzzer targets as they are, and the tables below list every target with
its entry point. The targets live in `fuzz/`, a separate cargo workspace (package
`hirz-fuzz`) that is never built by the main workspace and never shipped. It is the only place
where `libfuzzer-sys` is a dependency. Because it is a separate workspace, `cargo deny` and
`cargo vet` do not cover it; that is acceptable because it holds no secret, nothing from it
is shipped, and CI runs it with a read-only token. Its lock file is `fuzz/Cargo.lock`.

## Setup

cargo-fuzz needs a nightly toolchain (for `-Zsanitizer=address` and SanitizerCoverage):

```sh
rustup toolchain install nightly-2026-11-12 --profile minimal
cargo install cargo-fuzz --locked
```

The repository pins a stable toolchain in `rust-toolchain.toml`, so the script always calls
`cargo +TOOLCHAIN`, where the toolchain is a nightly pinned by date in `scripts/fuzz.sh` and
in `.github/workflows/ci.yml` (`scripts/check.sh toolchain` fails when the two differ). Move the
pin forward in a reviewed change; set `FUZZ_TOOLCHAIN` to try another nightly locally.

## Running

```sh
scripts/fuzz.sh smoke                     # every target for 60 s, two at a time
scripts/fuzz.sh long ctap2_handler 3600   # one target for an hour
scripts/fuzz.sh repro json fuzz/artifacts/json/crash-...
scripts/fuzz.sh tmin json fuzz/artifacts/json/crash-...
scripts/fuzz.sh seeds                     # regenerate fuzz/seeds
scripts/fuzz.sh list
```

`smoke` is meant for local CI: about 12 minutes after the first build, and it exits non-zero
when any target finds a crash, leak or timeout. Logs go to `fuzz/artifacts/smoke-logs/`.
Environment knobs: `FUZZ_SMOKE_SECONDS` (default 60), `FUZZ_JOBS` (parallel targets,
default 2), `FUZZ_RSS_MB` (default 1024), `CARGO_BUILD_JOBS` (default 3).

Every run uses `-rss_limit_mb=1024`, a 10 second per-input timeout and a per-target
`-max_len`: 7609 bytes for CTAP2 inputs (the largest CTAPHID message, 57 + 128 x 59),
262144 for JSON, Bitwarden and CXF exports, 65536 for CBOR, authenticatorData and KeePassXC
files, 16640 for the CTAPHID transport script (256 reports), 8192 otherwise.

Inputs are read from `fuzz/seeds/<target>` (checked in; every target has seeds) and
`fuzz/corpus/<target>` (generated, ignored by git). Crashing inputs land in `fuzz/artifacts/<target>/` (ignored
by git). The build enables debug assertions and overflow checks.

The nightly CI job writes the logs to files, not to the public job log. A crashing input is a
ready denial of service for a public repository, so the job uploads `fuzz/artifacts/` only
encrypted to the OpenPGP key in the repository variable `FUZZ_CRASH_GPG_PUBLIC_KEY`
(`gpg --decrypt fuzz-artifacts.tar.gpg | tar -x`); without the variable nothing is uploaded and
the job log says so.

## Seeds

`fuzz/examples/gen_seeds.rs` builds small valid inputs with the crates' own encoders
(CTAP2 requests, CTAPHID message scripts, COSE keys, authenticatorData, WebAuthn options and
envelopes, a CXF export written by hirz's own exporter, a passphrase envelope, hex strings),
takes the W3C WebAuthn Level 3 test vectors from `crates/hirz-proto/tests/common/vectors.rs`
and a provider's CXF export from `crates/hirz-cli/tests/fixtures/provider-export.json`. The
output is checked in under `fuzz/seeds/` and stays far below 200 KB. Rerun
`scripts/fuzz.sh seeds` after a format change: it deletes `fuzz/seeds/` and writes it again,
so a seed that is not in `gen_seeds.rs` is lost. The envelope seeds are sealed with a random
nonce, so each run writes different bytes for them. A target without a directory under
`fuzz/seeds/` still runs: `scripts/fuzz.sh` creates the empty folders it needs.

## Targets

Properties are checked with `assert!`, so a violated property is reported like a panic.

### hirz-proto

| Target | Entry point | Checks |
|---|---|---|
| `cbor_strict` | `cbor::decode` with default (canonical) limits | accepted input re-encodes byte for byte: `encode(decode(x)) == x` |
| `cbor_lenient` | `cbor::decode` with `require_canonical: false` | `encode` succeeds, is never longer than the input, passes the strict decoder and is a fixed point |
| `cose_key` | `cose::parse_public_key`, `cose::parse_key_agreement` on any decoded item | a parsed key re-encoded by `encode_es256` / `encode_ed25519` / `key_agreement_value` parses back to the same key |
| `auth_data` | `AuthenticatorData::parse` | with valid flags, `encode(parse(x)) == x`; `encode` fails only for reserved bits or BS without BE |
| `attestation` | `attestation::parse_webauthn`, `parse_ctap` | `attStmt` is a map; a `none` statement re-encoded in both forms parses back equal |
| `json` | `json::parse` | `parse(v.to_string()) == v` and the writer is idempotent |
| `base64url` | `base64url::decode`, `encode` | only canonical text decodes (`encode(decode(s)) == s`); `decode(encode(b)) == b` |
| `hex` | `hex::decode`, `decode_array`, `encode` | only lowercase, even-length text decodes (`encode(decode(s)) == s`); `decode(encode(b)) == b` |
| `client_data` | `client_data::serialize` with arbitrary origin, top origin and challenge | output is valid JSON with exactly the given members |

### hirz-ctap

| Target | Entry point | Checks |
|---|---|---|
| `ctaphid_packet` | `hid::parse_packet`, `hid::build_message` | only 64-byte reports parse; `build_message` uses the minimal packet count, numbers continuation packets from 0, pads with zeros and reassembles to the payload; it fails only above 7609 bytes |
| `ctaphid_transport` | `hid::Transport` driven by a script of (control byte, 64-byte report) records with simulated time, `tick` and `job_finished` | one CBOR job at a time, increasing job ids, only the running job is cancelled, `current_job` matches the outputs, every sent report parses, finished jobs are always answered, stale job results are dropped |
| `ctap2_make_credential` | `ctap2::parse_make_credential`, `into_request` | user id 1 to 64 bytes; requests have only supported, distinct algorithms; the touch probe never becomes a request |
| `ctap2_get_assertion` | `ctap2::parse_get_assertion`, `into_request` | `up` defaults to true; hmac-secret input survives validation; salts are never set before decryption |
| `ctap2_client_pin` | `ctap2::parse_client_pin` | no panic |
| `ctap2_handler` | `Ctap2Handler::process` (command byte + CBOR) over an authenticator that approves everything and never signs | every response is a status byte; errors have no body; success bodies are canonical CBOR maps; makeCredential returns a parseable attestation object and getAssertion parseable authenticatorData |

### hirz-webauthn

| Target | Entry point | Checks |
|---|---|---|
| `webauthn_origin` | `Origin::parse`, `validate_rp_id`, `psl::*` (input `origin` or `origin\nrpId`) | origins round-trip; the host is always a valid RP ID; an accepted RP ID equals the host or is a parent domain that is not a public suffix; public suffix and registrable domain are suffixes of the host |
| `webauthn_prepare` | `prepare_create`, `prepare_get` on any JSON (first byte picks ceremony and origin), then `registration_response` / `authentication_response` | clientDataJSON parses and its SHA-256 is the request hash; the RP ID validates for the origin; a fake engine's answer to an accepted plan is always accepted by the response builder |
| `webauthn_handle` | `handle` on any JSON envelope with a fake engine | every reply is a valid envelope (`v`, `id` null or a safe integer, `ok`, and `error`/`message` on failure) that the strict JSON reader accepts |

### hirz-uv

| Target | Entry point | Checks |
|---|---|---|
| `uv_config` | `config::parse_config` | methods non-empty and unique, RP ids valid and lowercase, timeout and rate within bounds |
| `uv_pin_verifier` | `pin::parse_verifier` | the PIN verifier file has one spelling: `serialize(parse(x)) == x` |
| `uv_tool_output` | `fprint::classify_verify`, `fprint::has_enrolled_fingers`, `polkit::parse_stat_start_time`, `polkit::parse_status_uid`, `runner::passwd_name_for_uid` | a fingerprint match needs exit status 0 and a `verify-match (done)` line; listed fingers need exit status 0; a passwd name is always a valid user name |

### hirz-nmh

| Target | Entry point | Checks |
|---|---|---|
| `nmh_framing` | `framing::read_frame` in a loop over a stream (first byte: bytes per `read` call, second: frame size cap), then `write_frame` | every frame is 1 byte to the cap; the bytes consumed are exactly the headers and bodies; a clean end only after the last frame; `TooLarge` only above the cap; a written frame reads back unchanged |

`hirz-nmh` has a library target (`src/lib.rs`) only so that `fuzz/` can link the framing.

### hirz-vault decoders

The record and event decoders are crate-private, and in a vault they only see bytes that
passed AEAD authentication. Two `#[doc(hidden)]` functions expose them for fuzzing:
`fuzz_decode_record_body` and `fuzz_decode_event` decode, then return the re-encoding of
what they decoded.

| Target | Entry point | Checks |
|---|---|---|
| `vault_record` | `CredentialRecord::decode` (version 1 and 2 bodies) | a decoded record always encodes, and the encoding is a fixed point of decode then encode |
| `vault_event` | `Event::decode` (body and author tag, all five event kinds) | same as `vault_record`, for events with their author tag |

### hirz-cli file readers

`hirz` has no library target; `fuzz/src/lib.rs` includes `crates/hirz-cli/src/foreign/`,
`cxf.rs`, `envelope.rs` and `ui.rs` as modules, from the same source files. The import
parsers use only hirz library crates and the strict JSON reader of hirz-proto.

| Target | Entry point | Checks |
|---|---|---|
| `import_bitwarden` | `bitwarden::read`, `Protected::decrypt_with` with a fixed key (no KDF runs), `bitwarden::read_decrypted`, `bitwarden::credential_id` | every imported record validates, is ES256 with a key that parses, a valid RP id (or an OpenSSH key id) and a creation time not in the future; credential ids are 1 to 1023 bytes |
| `import_keepassxc` | `keepassxc::read` | every imported record validates, is ES256 or EdDSA, discoverable and backup eligible, with a valid RP id (or an OpenSSH key id) |
| `cxf_parse` | `cxf::parse` | at most `MAX_PASSKEYS` passkeys; every ready record validates and has a site id that is plain printable text |
| `envelope_open` | `envelope::params`, `open`, `seal` | `is_envelope` is the magic prefix; accepted parameters stay within the import limit; inputs that ask for little Argon2 work are opened without a panic; a sealed input opens with its passphrase and not with another |

## Triage

1. `scripts/fuzz.sh repro <target> <artifact>` prints the panic message and stack.
2. `scripts/fuzz.sh tmin <target> <artifact>` writes a minimised input next to it.
3. Turn the minimised input into a unit test in the crate, fix, and keep the input in
   `fuzz/seeds/<target>/` when it exercises a new path.
