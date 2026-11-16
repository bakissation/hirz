# Fuzzing hirz-proto

The fuzz targets for every decoder of this crate (`cbor_strict`, `cbor_lenient`, `cose_key`,
`auth_data`, `attestation`, `json`, `base64url`, `client_data`, `hex`) live in the separate
`fuzz/` workspace at the repository root, with the properties each one asserts. They are
documented, together with how to build, run and triage them, in
[`docs/fuzzing.md`](../../docs/fuzzing.md).

Seed corpora: the W3C WebAuthn test vectors in `tests/common/vectors.rs` and the RFC 8949
Appendix A examples in `tests/rfc8949.rs`. `tests/robustness.rs` runs a deterministic
mutation loop over the same entry points on every `cargo test`.
