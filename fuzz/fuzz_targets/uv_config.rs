#![no_main]

use hirz_uv::config::{
    self, MAX_PROMPTS_PER_MINUTE, MAX_TIMEOUT_SECS, MIN_TIMEOUT_SECS, valid_rp_id,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(cfg) = config::parse_config(data) else {
        return;
    };
    assert!(!cfg.methods.is_empty());
    for (i, m) in cfg.methods.iter().enumerate() {
        assert!(!cfg.methods[..i].contains(m), "methods are unique");
    }
    for rp in &cfg.click_to_allow {
        assert!(valid_rp_id(rp), "click_to_allow holds only valid RP ids");
        assert_eq!(rp.to_ascii_lowercase(), *rp);
    }
    let secs = cfg.timeout.as_secs();
    assert!((MIN_TIMEOUT_SECS..=MAX_TIMEOUT_SECS).contains(&secs));
    assert!((1..=MAX_PROMPTS_PER_MINUTE).contains(&cfg.prompts_per_minute));
});
