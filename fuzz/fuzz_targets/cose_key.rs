#![no_main]

use hirz_proto::cbor::{self, Limits};
use hirz_proto::cose::{self, PublicKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let lenient = Limits {
        require_canonical: false,
        ..Limits::default()
    };
    let Ok(value) = cbor::decode(data, &lenient) else {
        return;
    };
    if let Ok(key) = cose::parse_public_key(&value) {
        let encoded = match &key {
            PublicKey::Es256 { x, y } => cose::encode_es256(x, y),
            PublicKey::Ed25519 { x } => cose::encode_ed25519(x),
        };
        let back = cbor::decode(&encoded, &Limits::default()).expect("encoder output decodes");
        assert_eq!(cose::parse_public_key(&back).expect("re-parse"), key);
    }
    if let Ok(key) = cose::parse_key_agreement(&value) {
        let back = cose::key_agreement_value(&key.x, &key.y);
        assert_eq!(cose::parse_key_agreement(&back).expect("re-parse"), key);
        let encoded = cbor::encode(&back).expect("encode");
        cbor::decode(&encoded, &Limits::default()).expect("canonical key-agreement value");
    }
});
