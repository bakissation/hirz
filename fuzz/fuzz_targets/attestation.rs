#![no_main]

use hirz_proto::attestation::{self, FMT_NONE};
use hirz_proto::auth_data::AuthenticatorData;
use hirz_proto::cbor::Limits;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = Limits::default();
    let roomy = Limits {
        max_len: usize::MAX,
        ..limits
    };
    for parsed in [
        attestation::parse_webauthn(data, &limits),
        attestation::parse_ctap(data, &limits),
    ] {
        let Ok(obj) = parsed else {
            continue;
        };
        assert!(obj.att_stmt.as_map().is_some());
        let _ = AuthenticatorData::parse(&obj.auth_data, &limits);
        if obj.fmt == FMT_NONE && obj.att_stmt.as_map().is_some_and(<[_]>::is_empty) {
            let w = attestation::none_webauthn(&obj.auth_data);
            assert_eq!(attestation::parse_webauthn(&w, &roomy).expect("webauthn form"), obj);
            let c = attestation::none_ctap(&obj.auth_data);
            assert_eq!(attestation::parse_ctap(&c, &roomy).expect("ctap form"), obj);
        }
    }
});
