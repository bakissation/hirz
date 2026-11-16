#![no_main]

use hirz_proto::auth_data::{AuthenticatorData, FLAG_BE, FLAG_BS};
use hirz_proto::cbor::Limits;
use libfuzzer_sys::fuzz_target;

const FLAGS_RESERVED: u8 = 0x22;

fuzz_target!(|data: &[u8]| {
    let Ok(ad) = AuthenticatorData::parse(data, &Limits::default()) else {
        return;
    };
    let flags_valid =
        ad.flags & FLAGS_RESERVED == 0 && (ad.flags & FLAG_BS == 0 || ad.flags & FLAG_BE != 0);
    match ad.encode() {
        Ok(encoded) => {
            assert_eq!(encoded, data, "parse then encode must reproduce the input");
            let again = AuthenticatorData::parse(&encoded, &Limits::default()).expect("re-parse");
            assert_eq!(again, ad);
        }
        Err(_) => assert!(!flags_valid, "valid parsed authenticatorData must encode"),
    }
});
