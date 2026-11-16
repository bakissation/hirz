#![no_main]

//! Bitwarden JSON export reader: unencrypted exports, the password protected envelope and
//! its EncStrings (with a fixed key, so no KDF runs), and decrypted inner exports.

use hirz_core::COSE_ALG_ES256;
use hirz_fuzz::foreign::bitwarden::{self, Export, StretchedKey};
use hirz_fuzz::foreign::{Found, Parsed};
use libfuzzer_sys::fuzz_target;

const NOW: u64 = 1_800_000_000;

fn check(p: &Parsed) {
    for f in &p.passkeys {
        if let Found::Ready(r) = f {
            assert!(r.validate().is_ok(), "imported records are valid");
            assert_eq!(r.algorithm, COSE_ALG_ES256);
            assert!(hirz_crypto::es256::public_key(&r.private_key_pkcs8).is_ok());
            assert!(hirz_uv::config::valid_rp_id(&r.rp_id) || r.rp_id.starts_with("ssh:"));
            assert!(r.created_at > 0 && r.created_at <= NOW);
            assert!(r.hmac_secret.is_none() && r.cred_protect.is_none());
        }
    }
}

fuzz_target!(|data: &[u8]| {
    match bitwarden::read(data, NOW) {
        Ok(Export::Plain(p)) => check(&p),
        Ok(Export::Protected(p)) => {
            let key = StretchedKey::from_parts([0x11; 32], [0x22; 32]);
            if let Ok(inner) = p.decrypt_with(&key) {
                if let Ok(p) = bitwarden::read_decrypted(&inner, NOW) {
                    check(&p);
                }
            }
        }
        Err(_) => {}
    }
    if let Ok(p) = bitwarden::read_decrypted(data, NOW) {
        check(&p);
    }
    if let Ok(s) = core::str::from_utf8(data)
        && let Some(id) = bitwarden::credential_id(s)
    {
        assert!(!id.is_empty() && id.len() <= hirz_vault::MAX_CREDENTIAL_ID_LEN);
    }
});
