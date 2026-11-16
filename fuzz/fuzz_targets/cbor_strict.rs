#![no_main]

use hirz_proto::cbor::{self, Limits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = cbor::decode(data, &Limits::default()) else {
        return;
    };
    let encoded = cbor::encode(&value).expect("an accepted item must encode");
    assert_eq!(encoded, data, "canonical input must re-encode byte for byte");
});
