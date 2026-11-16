# Fuzzing

Every parser that reads untrusted bytes is a pure function over `&[u8]` (or `&str`) with
explicit size limits, so each one is a libFuzzer target as is. The targets live in `fuzz/`,
a separate cargo workspace (package `hirz-fuzz`) that is never built by the main workspace
and never shipped. It is the only place where `libfuzzer-sys` is a dependency.

## Setup

cargo-fuzz needs a nightly toolchain (for `-Zsanitizer=address` and SanitizerCoverage):

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
```

The repository pins a stable toolchain in `rust-toolchain.toml`, so the script always calls
`cargo +nightly`. Set `FUZZ_TOOLCHAIN` to use another nightly.

## Running

```sh
scripts/fuzz.sh smoke                     # every target for 60 s, two at a time
scripts/fuzz.sh long ctap2_handler 3600   # one target for an hour
scripts/fuzz.sh repro json fuzz/artifacts/json/crash-...
scripts/fuzz.sh tmin json fuzz/artifacts/json/crash-...
scripts/fuzz.sh seeds                     # regenerate fuzz/seeds
scripts/fuzz.sh list
```

`smoke` is meant for local CI: about 11 minutes after the first build, and it exits non-zero
when any target finds a crash, leak or timeout. Logs go to `fuzz/artifacts/smoke-logs/`.
Environment knobs: `FUZZ_SMOKE_SECONDS` (default 60), `FUZZ_JOBS` (parallel targets,
default 2), `FUZZ_RSS_MB` (default 1024), `CARGO_BUILD_JOBS` (default 3).

Every run uses `-rss_limit_mb=1024`, a 10 second per-input timeout and a per-target
`-max_len`: 7609 bytes for CTAP2 inputs (the largest CTAPHID message, 57 + 128 x 59),
262144 for JSON, 65536 for CBOR and authenticatorData, 16640 for the CTAPHID transport
script (256 reports), 8192 otherwise.

Inputs are read from `fuzz/seeds/<target>` (checked in) and `fuzz/corpus/<target>`
(generated, ignored by git). Crashing inputs land in `fuzz/artifacts/<target>/` (ignored
by git). The build enables debug assertions and overflow checks.

## Seeds

`fuzz/examples/gen_seeds.rs` builds small valid inputs with the crates' own encoders
(CTAP2 requests, CTAPHID message scripts, COSE keys, authenticatorData, WebAuthn options and
envelopes) and takes the W3C WebAuthn Level 3 test vectors from
`crates/hirz-proto/tests/common/vectors.rs`. The output is checked in under `fuzz/seeds/`
and stays far below 200 KB. Rerun `scripts/fuzz.sh seeds` after a format change.

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

### hirz-vault and hirz-uv

| Target | Entry point | Checks |
|---|---|---|
| `vault_backup` | `import_backup` with a fixed recovery phrase and no passphrase | no panic in the header reader and AEAD rejection path (no Argon2 runs) |
| `uv_config` | `config::parse_config` | methods non-empty and unique, RP ids valid and lowercase, timeout and rate within bounds |
| `uv_pin_verifier` | `pin::parse_verifier` | the PIN verifier file has one spelling: `serialize(parse(x)) == x` |
| `uv_tool_output` | `fprint::classify_verify`, `fprint::has_enrolled_fingers`, `polkit::parse_stat_start_time`, `polkit::parse_status_uid`, `runner::passwd_name_for_uid` | a fingerprint match needs exit status 0 and a `verify-match (done)` line; listed fingers need exit status 0; a passwd name is always a valid user name |

## Not covered yet

- `hirz-nmh` framing (`read_frame`, `write_frame`) lives in the binary crate and cannot be
  linked from `fuzz/`. Moving `framing.rs` into a library target (or into `hirz-proto`)
  makes it a target.
- `hirz-vault` record, event and field decoders (`CredentialRecord::decode`,
  `Event::decode`, `codec::Fields`) are crate-private, and in a vault they only see bytes
  that passed AEAD authentication. A `#[doc(hidden)] pub fn` that decodes one record body
  would make them a target.

## Triage

1. `scripts/fuzz.sh repro <target> <artifact>` prints the panic message and stack.
2. `scripts/fuzz.sh tmin <target> <artifact>` writes a minimised input next to it.
3. Turn the minimised input into a unit test in the crate, fix, and keep the input in
   `fuzz/seeds/<target>/` when it exercises a new path.
