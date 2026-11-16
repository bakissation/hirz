#![no_main]

use hirz_ctap::ctap2;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ctap2::parse_client_pin(data);
});
