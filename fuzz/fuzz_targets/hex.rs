#![no_main]

use hirz_proto::hex;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = core::str::from_utf8(data) {
        if let Ok(bytes) = hex::decode(text) {
            assert_eq!(
                hex::encode(&bytes),
                text,
                "only lowercase, even-length text decodes"
            );
        }
        if let Ok(array) = hex::decode_array::<16>(text) {
            assert_eq!(text.len(), 32);
            assert_eq!(hex::encode(&array), text);
        }
    }
    let encoded = hex::encode(data);
    assert_eq!(hex::decode(&encoded).expect("encoder output decodes"), data);
});
