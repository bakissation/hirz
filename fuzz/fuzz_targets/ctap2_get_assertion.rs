#![no_main]

use hirz_ctap::ctap2;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(params) = ctap2::parse_get_assertion(data) else {
        return;
    };
    let probe = params.is_touch_probe();
    let up = params.options.up;
    let has_hmac = params.hmac_secret.is_some();
    if let Ok((req, hmac)) = params.into_request() {
        assert!(!probe, "the touch probe never becomes a request");
        assert_eq!(req.up, up.unwrap_or(true));
        assert_eq!(hmac.is_some(), has_hmac);
        assert!(req.extensions.hmac_secret.is_none(), "salts are added after decryption");
    }
});
