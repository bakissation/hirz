#![no_main]

//! FIDO Credential Exchange Format reader (hirz-cli, `hirz import`).

use hirz_fuzz::cxf::{self, Candidate};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(parsed) = cxf::parse(data, 1_800_000_000) else {
        return;
    };
    assert!(parsed.passkeys.len() <= cxf::MAX_PASSKEYS);
    for candidate in &parsed.passkeys {
        if let Candidate::Ready { record, .. } = candidate {
            assert!(record.validate().is_ok(), "imported records are valid");
            assert!(hirz_fuzz::foreign::exact_site_id(&record.rp_id).is_ok());
        }
    }
});
