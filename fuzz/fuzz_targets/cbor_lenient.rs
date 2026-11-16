#![no_main]

use hirz_proto::cbor::{self, Limits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let lenient = Limits {
        require_canonical: false,
        ..Limits::default()
    };
    let Ok(value) = cbor::decode(data, &lenient) else {
        return;
    };
    let encoded = cbor::encode(&value).expect("an accepted item must encode");
    assert!(encoded.len() <= data.len(), "canonical form is never longer");
    let strict = cbor::decode(&encoded, &Limits::default())
        .expect("the canonical encoding must pass the strict decoder");
    assert_eq!(
        cbor::encode(&strict).expect("re-encode"),
        encoded,
        "canonical encoding is a fixed point"
    );
});
