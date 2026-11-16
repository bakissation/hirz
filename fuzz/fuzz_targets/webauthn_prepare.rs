#![no_main]

//! Input: one byte (bit 0: create or get, bits 1..=2: origin), then the options JSON.
//! Accepted options are answered by an engine that never signs, and the response builder
//! must accept that answer: the plan and the engine contract agree.

use hirz_core::{COSE_ALG_EDDSA, COSE_ALG_ES256};
use hirz_crypto::sha256;
use hirz_fuzz::{NoSignEngine, ORIGINS};
use hirz_proto::json::{self, Json, Limits};
use hirz_webauthn::{
    Origin, authentication_response, prepare_create, prepare_get, registration_response,
    validate_rp_id,
};
use libfuzzer_sys::fuzz_target;

fn check_client_data(text: &str, hash: &[u8; 32], kind: &str, origin: &Origin) {
    assert_eq!(&sha256(text.as_bytes()), hash);
    let v = json::parse(text.as_bytes(), &Limits::default()).expect("clientDataJSON parses");
    assert_eq!(v.get("type").and_then(Json::as_str), Some(kind));
    assert_eq!(v.get("origin").and_then(Json::as_str), Some(origin.as_str()));
}

fuzz_target!(|data: &[u8]| {
    let Some((&ctl, rest)) = data.split_first() else {
        return;
    };
    let origin = Origin::parse(ORIGINS[usize::from(ctl >> 1) % ORIGINS.len()]).expect("origin");
    let Ok(options) = json::parse(rest, &Limits::default()) else {
        return;
    };
    let engine = NoSignEngine;
    if ctl & 1 == 0 {
        let Ok(plan) = prepare_create(&options, &origin) else {
            return;
        };
        let req = &plan.request;
        check_client_data(&plan.client_data_json, &req.client_data_hash, "webauthn.create", &origin);
        assert_eq!(validate_rp_id(Some(&req.rp.id), &origin).as_ref(), Ok(&req.rp.id));
        assert!(!req.user.id.is_empty() && req.user.id.len() <= 64);
        assert!(!req.algorithms.is_empty());
        assert!(
            req.algorithms
                .iter()
                .all(|&a| a == COSE_ALG_ES256 || a == COSE_ALG_EDDSA)
        );
        let resp = engine.make(req).expect("fake engine");
        let reply = registration_response(&plan, &resp).expect("response for a valid plan");
        assert_eq!(json::parse(reply.to_string().as_bytes(), &Limits::default()), Ok(reply));
    } else {
        let Ok(plan) = prepare_get(&options, &origin) else {
            return;
        };
        let req = &plan.request;
        check_client_data(&plan.client_data_json, &req.client_data_hash, "webauthn.get", &origin);
        assert_eq!(validate_rp_id(Some(&req.rp_id), &origin).as_ref(), Ok(&req.rp_id));
        let resp = engine.get(req).expect("fake engine");
        let reply = authentication_response(&plan, &resp).expect("response for a valid plan");
        assert_eq!(json::parse(reply.to_string().as_bytes(), &Limits::default()), Ok(reply));
    }
});
