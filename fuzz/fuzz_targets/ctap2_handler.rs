#![no_main]

//! The full CTAP2 command handler (command byte + CBOR parameters) over an authenticator
//! that approves everything and never signs. Every response must be a status byte, followed
//! on success by one canonical CBOR map.

use std::sync::OnceLock;

use hirz_ctap::Ctap2Handler;
use hirz_ctap::ctap2::command;
use hirz_ctap::hid::RequestContext;
use hirz_fuzz::NoSignAuthenticator;
use hirz_proto::attestation;
use hirz_proto::auth_data::AuthenticatorData;
use hirz_proto::cbor::{self, Limits};
use libfuzzer_sys::fuzz_target;

static HANDLER: OnceLock<Ctap2Handler<NoSignAuthenticator>> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let handler = HANDLER.get_or_init(|| Ctap2Handler::new(NoSignAuthenticator));
    let response = handler.process(data, &RequestContext::new());
    let (&status, body) = response.split_first().expect("a status byte is always sent");
    if status != 0 {
        assert!(body.is_empty(), "errors carry no body");
        return;
    }
    if body.is_empty() {
        return;
    }
    let value = cbor::decode(body, &Limits::default()).expect("responses are canonical CBOR");
    assert!(value.as_map().is_some());
    match data.first().copied() {
        Some(command::MAKE_CREDENTIAL) => {
            let att = attestation::parse_ctap(body, &Limits::default()).expect("attestation");
            AuthenticatorData::parse(&att.auth_data, &Limits::default()).expect("authData");
        }
        Some(command::GET_ASSERTION) => {
            let ad = value.get_int(2).and_then(|v| v.as_bytes()).expect("authData");
            AuthenticatorData::parse(ad, &Limits::default()).expect("authData");
        }
        _ => {}
    }
});
