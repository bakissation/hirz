# Fuzzing hirz-proto

Every decoder is a pure function over bytes with explicit limits, so each one can be a
cargo-fuzz target as is. Suggested targets (one per entry point):

| Target | Call | Extra property to assert |
|---|---|---|
| `cbor_strict` | `cbor::decode(data, &cbor::Limits::default())` | on `Ok(v)`, `cbor::encode(&v) == data` |
| `cbor_lenient` | `cbor::decode` with `require_canonical: false` | on `Ok(v)`, `cbor::encode(&v)` succeeds |
| `cose_key` | `cbor::decode`, then `cose::parse_public_key` and `cose::parse_key_agreement` | no panic |
| `auth_data` | `auth_data::AuthenticatorData::parse(data, &limits)` | on `Ok(ad)` with valid flags, `parse(encode(ad)) == ad` |
| `attestation` | `attestation::parse_webauthn` and `attestation::parse_ctap` | no panic |
| `json` | `json::parse(data, &json::Limits::default())` | on `Ok(v)`, `parse(v.to_string()) == v` |
| `base64url` | `base64url::decode` on `data` as UTF-8 | on `Ok(b)`, `encode(&b) == input` |

Seed corpora: the W3C WebAuthn test vectors in `tests/common/vectors.rs` and the RFC 8949
Appendix A examples in `tests/rfc8949.rs`. `tests/robustness.rs` runs a deterministic
mutation loop over the same entry points on every `cargo test`.
