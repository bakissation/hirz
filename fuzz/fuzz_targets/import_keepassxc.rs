#![no_main]

//! KeePassXC `.passkey` file reader.

use hirz_core::{COSE_ALG_EDDSA, COSE_ALG_ES256};
use hirz_fuzz::foreign::Found;
use hirz_fuzz::foreign::keepassxc;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(Found::Ready(r)) = keepassxc::read(data, 1_800_000_000) else {
        return;
    };
    assert!(r.validate().is_ok(), "imported records are valid");
    assert!(r.algorithm == COSE_ALG_ES256 || r.algorithm == COSE_ALG_EDDSA);
    assert!(hirz_uv::config::valid_rp_id(&r.rp_id) || r.rp_id.starts_with("ssh:"));
    assert!(r.discoverable && r.backup_eligible);
});
