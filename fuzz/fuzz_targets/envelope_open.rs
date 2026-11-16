#![no_main]

//! Passphrase envelope around a CXF export (hirz-cli).

use hirz_crypto::kdf::Argon2Params;
use hirz_fuzz::envelope;
use libfuzzer_sys::fuzz_target;

const FAST: Argon2Params = Argon2Params {
    m_cost_kib: 64,
    t_cost: 1,
    p_cost: 1,
};

fuzz_target!(|data: &[u8]| {
    assert_eq!(
        envelope::is_envelope(data),
        data.starts_with(envelope::MAGIC)
    );
    match envelope::params(data) {
        Ok(p) => {
            let limit = envelope::IMPORT_LIMIT;
            assert!(p.m_cost_kib <= limit.m_cost_kib && p.t_cost <= limit.t_cost);
            assert!(p.p_cost <= limit.p_cost && p.t_cost >= 1 && p.p_cost >= 1);
            // Opening runs Argon2: only inputs that ask for little work are opened here.
            if p.m_cost_kib <= 1024 && p.t_cost <= 2 && p.p_cost <= 2 {
                let _ = envelope::open(b"fuzz passphrase", data);
            }
        }
        Err(_) => assert!(envelope::open(b"fuzz passphrase", data).is_err()),
    }
    if data.first() == Some(&0) {
        let sealed = envelope::seal(b"fuzz passphrase", data, FAST).expect("seal");
        let opened = envelope::open(b"fuzz passphrase", &sealed).expect("open what was sealed");
        assert_eq!(opened.as_slice(), data);
        assert!(envelope::open(b"another passphrase", &sealed).is_err());
    }
});
