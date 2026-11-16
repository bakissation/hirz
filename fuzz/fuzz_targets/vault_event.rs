#![no_main]

//! Vault event decoder (event body plus author tag, the plaintext inside an event file's
//! AEAD). A decoded event always encodes again, and the encoding is a fixed point of decode
//! then encode.

use hirz_vault::fuzz_decode_event;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(encoded) = fuzz_decode_event(data) else {
        return;
    };
    let encoded = encoded.expect("a decoded event encodes");
    let again = fuzz_decode_event(&encoded)
        .expect("the encoding decodes")
        .expect("and encodes again");
    assert_eq!(again.as_slice(), encoded.as_slice());
});
