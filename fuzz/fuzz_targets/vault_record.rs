#![no_main]

//! Credential record body decoder (the plaintext inside a record file's AEAD). A decoded
//! record always encodes again, and the encoding is a fixed point of decode then encode.

use hirz_vault::fuzz_decode_record_body;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(encoded) = fuzz_decode_record_body(data) else {
        return;
    };
    let encoded = encoded.expect("a decoded record encodes");
    let again = fuzz_decode_record_body(&encoded)
        .expect("the encoding decodes")
        .expect("and encodes again");
    assert_eq!(again.as_slice(), encoded.as_slice());
});
