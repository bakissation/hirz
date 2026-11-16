#![no_main]

use hirz_proto::base64url;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = core::str::from_utf8(data)
        && let Ok(bytes) = base64url::decode(text)
    {
        assert_eq!(base64url::encode(&bytes), text, "only canonical input decodes");
    }
    let encoded = base64url::encode(data);
    assert_eq!(base64url::decode(&encoded).expect("encoder output decodes"), data);
});
