#![no_main]

//! Input: `origin` or `origin\nrpId`.

use hirz_webauthn::{Origin, psl, validate_rp_id};
use libfuzzer_sys::fuzz_target;

fn is_suffix_domain(child: &str, parent: &str) -> bool {
    child == parent
        || child
            .strip_suffix(parent)
            .is_some_and(|head| head.ends_with('.'))
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    let (origin, rp_id) = match text.split_once('\n') {
        Some((o, r)) => (o, Some(r)),
        None => (text, None),
    };
    if let Some(suffix) = psl::public_suffix(origin) {
        assert!(is_suffix_domain(origin, suffix));
    }
    if let Some(reg) = psl::registrable_domain(origin) {
        assert!(is_suffix_domain(origin, reg));
        assert!(!psl::is_public_suffix(reg));
    }
    let Ok(o) = Origin::parse(origin) else {
        return;
    };
    assert_eq!(o.as_str(), origin);
    assert_eq!(Origin::parse(o.as_str()).as_ref(), Ok(&o));
    let host = o.effective_domain();
    assert!(!host.is_empty() && host.len() <= 253);
    assert_eq!(validate_rp_id(None, &o).as_deref(), Ok(host));
    assert_eq!(validate_rp_id(Some(host), &o).as_deref(), Ok(host));
    if let Some(rp) = rp_id
        && let Ok(accepted) = validate_rp_id(Some(rp), &o)
    {
        assert_eq!(accepted, rp);
        assert!(is_suffix_domain(host, rp), "RP ID must be the host or a parent of it");
        if accepted != host {
            assert!(!psl::is_public_suffix(rp), "a parent RP ID is never a public suffix");
        }
    }
});
