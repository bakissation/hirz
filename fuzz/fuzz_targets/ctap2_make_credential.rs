#![no_main]

use hirz_core::{COSE_ALG_EDDSA, COSE_ALG_ES256};
use hirz_ctap::ctap2::{self, MAX_USER_ID_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(params) = ctap2::parse_make_credential(data) else {
        return;
    };
    assert!(!params.user.id.is_empty() && params.user.id.len() <= MAX_USER_ID_LEN);
    let probe = params.is_touch_probe();
    if let Ok(req) = params.into_request() {
        assert!(!probe, "the touch probe never becomes a request");
        assert!(!req.algorithms.is_empty());
        assert!(
            req.algorithms
                .iter()
                .all(|&a| a == COSE_ALG_ES256 || a == COSE_ALG_EDDSA)
        );
        let mut seen = req.algorithms.clone();
        seen.dedup();
        assert_eq!(seen.len(), req.algorithms.len());
    }
});
