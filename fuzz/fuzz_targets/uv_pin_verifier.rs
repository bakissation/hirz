#![no_main]

use hirz_uv::pin;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(v) = pin::parse_verifier(data) else {
        return;
    };
    let text = pin::serialize_verifier(&v);
    assert_eq!(text.as_bytes(), data, "the verifier file has one spelling");
    assert_eq!(pin::parse_verifier(text.as_bytes()), Ok(v));
});
