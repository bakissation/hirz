#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use super::*;
use crate::pin_uv::SharedSecret;
use hirz_core::{ApprovalError, HmacSecretSalts};
use hirz_crypto::ctap_pin_uv;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn hex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| (b as char).to_digit(16).unwrap() as u8)
        .collect();
    digits.chunks(2).map(|c| (c[0] << 4) | c[1]).collect()
}

const FAKE_AUTH_DATA: [u8; 37] = [0xad; 37];

#[derive(Default)]
struct Fake {
    makes: Vec<MakeCredentialRequest>,
    gets: Vec<GetAssertionRequest>,
    selects: usize,
    fail: Option<CoreError>,
    block: bool,
    hmac_output: Option<Vec<u8>>,
    wrapped: Option<Vec<u8>>,
    user: Option<UserEntity>,
    user_handle: Vec<u8>,
}

impl Fake {
    fn wait(&self, ctx: &RequestContext) -> Result<(), CoreError> {
        if self.block {
            let start = Instant::now();
            while !ctx.is_cancelled() && start.elapsed() < Duration::from_secs(10) {
                std::thread::sleep(Duration::from_millis(2));
            }
            return Err(CoreError::Approval(ApprovalError::Denied));
        }
        match &self.fail {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }
}

fn fake_hmac_output(salts: &HmacSecretSalts) -> Vec<u8> {
    let mut out = hirz_crypto::hmac_sha256(b"cred-random", &salts.salt1).to_vec();
    if let Some(s2) = salts.salt2 {
        out.extend_from_slice(&hirz_crypto::hmac_sha256(b"cred-random", &s2));
    }
    out
}

impl Authenticator for Fake {
    fn make_credential(
        &mut self,
        req: &MakeCredentialRequest,
        ctx: &RequestContext,
    ) -> Result<MakeCredentialResponse, CoreError> {
        self.makes.push(req.clone());
        self.wait(ctx)?;
        Ok(MakeCredentialResponse {
            auth_data: FAKE_AUTH_DATA.to_vec(),
            credential_id: vec![1; 32],
            public_key_cose: Vec::new(),
            algorithm: req.algorithms[0],
            hmac_secret: req.extensions.hmac_secret,
            resident_key: true,
        })
    }

    fn get_assertion(
        &mut self,
        req: &GetAssertionRequest,
        hmac: Option<&dyn HmacSecretWrap>,
        ctx: &RequestContext,
    ) -> Result<AssertionResponse, CoreError> {
        self.gets.push(req.clone());
        self.wait(ctx)?;
        let mut auth_data = FAKE_AUTH_DATA.to_vec();
        if let (Some(w), Some(salts)) = (hmac, &req.extensions.hmac_secret) {
            let out = fake_hmac_output(salts);
            let wrapped = w.wrap(&out)?;
            auth_data.extend_from_slice(&wrapped);
            self.hmac_output = Some(out);
            self.wrapped = Some(wrapped);
        }
        Ok(AssertionResponse {
            credential_id: vec![2; 32],
            auth_data,
            signature: vec![0x30, 0x01, 0x02],
            user_handle: self.user_handle.clone(),
            user: self.user.clone(),
            hmac_secret_output: None,
        })
    }

    fn select(&mut self, ctx: &RequestContext) -> Result<(), CoreError> {
        self.selects += 1;
        self.wait(ctx)
    }
}

fn handler() -> Ctap2Handler<Fake> {
    Ctap2Handler::new(Fake::default())
}

fn with_engine<R>(h: &Ctap2Handler<Fake>, f: impl FnOnce(&mut Fake) -> R) -> R {
    f(&mut h.engine.lock().unwrap())
}

fn run(h: &Ctap2Handler<Fake>, cmd: u8, params: &Value) -> Vec<u8> {
    let mut req = vec![cmd];
    req.extend_from_slice(&cbor::encode(params).unwrap());
    h.process(&req, &RequestContext::new())
}

fn status_of(h: &Ctap2Handler<Fake>, cmd: u8, params: &Value) -> u8 {
    run(h, cmd, params)[0]
}

fn body(resp: &[u8]) -> Value {
    assert_eq!(resp[0], 0x00, "status {:#04x}", resp[0]);
    cbor::decode(&resp[1..], &limits()).unwrap()
}

fn rp() -> Value {
    MapBuilder::new()
        .text("id", "example.com")
        .text("name", "Acme")
        .build()
}

fn user() -> Value {
    MapBuilder::new()
        .text("id", [7u8; 16].as_slice())
        .text("name", "alice@example.com")
        .text("displayName", "Alice")
        .build()
}

fn alg_param(alg: i64) -> Value {
    MapBuilder::new()
        .text("alg", alg)
        .text("type", "public-key")
        .build()
}

fn descriptor(id: &[u8]) -> Value {
    MapBuilder::new()
        .text("id", id)
        .text("type", "public-key")
        .build()
}

/// A valid makeCredential parameter map with `edit` applied to its entries.
fn make_params(edit: impl FnOnce(&mut Vec<(i64, Value)>)) -> Value {
    let mut e: Vec<(i64, Value)> = vec![
        (1, Value::from([0x11u8; 32].as_slice())),
        (2, rp()),
        (3, user()),
        (4, Value::Array(vec![alg_param(-7), alg_param(-8)])),
    ];
    edit(&mut e);
    Value::Map(e.into_iter().map(|(k, v)| (Value::int(k), v)).collect())
}

fn get_params(edit: impl FnOnce(&mut Vec<(i64, Value)>)) -> Value {
    let mut e: Vec<(i64, Value)> = vec![
        (1, Value::from("example.com")),
        (2, Value::from([0x22u8; 32].as_slice())),
    ];
    edit(&mut e);
    Value::Map(e.into_iter().map(|(k, v)| (Value::int(k), v)).collect())
}

fn set(e: &mut Vec<(i64, Value)>, key: i64, v: Value) {
    e.retain(|(k, _)| *k != key);
    e.push((key, v));
}

fn remove(e: &mut Vec<(i64, Value)>, key: i64) {
    e.retain(|(k, _)| *k != key);
}

fn text_map(entries: &[(&str, Value)]) -> Value {
    Value::Map(
        entries
            .iter()
            .map(|(k, v)| (Value::from(*k), v.clone()))
            .collect(),
    )
}

// Copy of the hand-written spike bytes in hirzd's getinfo.rs, which this encoder replaces.
fn hand_written_get_info() -> Vec<u8> {
    let mut v = vec![0x00, 0xab, 0x01, 0x82];
    v.extend_from_slice(b"\x68FIDO_2_0\x68FIDO_2_1");
    v.extend_from_slice(b"\x02\x82\x6bcredProtect\x6bhmac-secret");
    v.extend_from_slice(&[0x03, 0x50]);
    v.extend_from_slice(&AAGUID);
    v.extend_from_slice(b"\x04\xa4\x62rk\xf5\x62up\xf5\x62uv\xf5\x64plat\xf4");
    v.extend_from_slice(&[0x05, 0x19, 0x1d, 0xb9, 0x06, 0x82, 0x02, 0x01]);
    // maxCredentialCountInList 16, maxCredentialIdLength 1023.
    v.extend_from_slice(&[0x07, 0x10, 0x08, 0x19, 0x03, 0xff]);
    v.extend_from_slice(b"\x09\x81\x63usb\x0a\x82");
    v.extend_from_slice(b"\xa2\x63alg\x26\x64type\x6apublic-key");
    v.extend_from_slice(b"\xa2\x63alg\x27\x64type\x6apublic-key");
    // firmwareVersion 0x000100.
    v.extend_from_slice(&[0x0e, 0x19, 0x01, 0x00]);
    v
}

#[test]
fn get_info_equals_the_hand_written_bytes() {
    let r = get_info_response();
    assert_eq!(r.len(), 156);
    assert_eq!(r, hand_written_get_info());
    let h = handler();
    assert_eq!(h.process(&[command::GET_INFO], &RequestContext::new()), r);
}

// authenticatorMakeCredential example request from the CTAP specification
// (section "authenticatorMakeCredential", example with ES256 and RS256).
const SPEC_MAKE_CREDENTIAL: &str = "
a5
01 5820 687134968222ec17202e42505f8ed2b16ae22f16bb05b88c25db9e602645f141
02 a2 626964 6b6578616d706c652e636f6d 646e616d65 6441636d65
03 a4 626964 5820 3082019330820138a0030201023082019330820138a003020102308201933082
      6469636f6e 782b 68747470733a2f2f706963732e6578616d706c652e636f6d2f30302f702f61426a6a6a707150622e706e67
      646e616d65 76 6a6f686e70736d697468406578616d706c652e636f6d
      6b646973706c61794e616d65 6d 4a6f686e20502e20536d697468
04 82 a2 63616c67 26 6474797065 6a7075626c69632d6b6579
      a2 63616c67 390100 6474797065 6a7075626c69632d6b6579
07 a1 62726b f5";

// authenticatorGetAssertion example request from the CTAP specification.
const SPEC_GET_ASSERTION: &str = "
a4
01 6b6578616d706c652e636f6d
02 5820 687134968222ec17202e42505f8ed2b16ae22f16bb05b88c25db9e602645f141
03 82 a2 626964 5840 f22006de4f905af68a43942f024f2a5ece603d9c6d4b3df8be08ed01fc442646d034858ac75bed3fd580bf9808d94fcbee82b9b2ef6677af0adcc35852ea6b9e
         6474797065 6a7075626c69632d6b6579
      a2 626964 5832 0303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303
         6474797065 6a7075626c69632d6b6579
05 a1 627576 f5";

#[test]
fn spec_make_credential_example() {
    let params = hex(SPEC_MAKE_CREDENTIAL);
    let p = parse_make_credential(&params).unwrap();
    assert_eq!(p.rp.id, "example.com");
    assert_eq!(p.rp.name.as_deref(), Some("Acme"));
    assert_eq!(p.user.id.len(), 32);
    assert_eq!(p.user.name.as_deref(), Some("johnpsmith@example.com"));
    assert_eq!(p.user.display_name.as_deref(), Some("John P. Smith"));
    assert_eq!(p.algorithms, vec![-7]);
    assert_eq!(p.options.rk, Some(true));
    let req = p.into_request().unwrap();
    assert!(req.resident_key);
    assert_eq!(req.uv, UvRequirement::Discouraged);

    let h = handler();
    let mut msg = vec![command::MAKE_CREDENTIAL];
    msg.extend_from_slice(&params);
    let resp = body(&h.process(&msg, &RequestContext::new()));
    assert_eq!(resp.get_int(1).and_then(Value::as_text), Some("none"));
    assert_eq!(
        resp.get_int(2).and_then(Value::as_bytes),
        Some(FAKE_AUTH_DATA.as_slice())
    );
    assert_eq!(resp.get_int(3), Some(&Value::Map(Vec::new())));
    assert_eq!(resp.as_map().unwrap().len(), 3);
}

#[test]
fn spec_get_assertion_example() {
    let p = parse_get_assertion(&hex(SPEC_GET_ASSERTION)).unwrap();
    assert_eq!(p.rp_id, "example.com");
    assert_eq!(p.allow_list.len(), 2);
    assert_eq!(p.allow_list[0].len(), 64);
    assert_eq!(p.allow_list[1], vec![3u8; 50]);
    let (req, hmac) = p.into_request().unwrap();
    assert!(hmac.is_none());
    assert_eq!(req.uv, UvRequirement::Required);
    assert!(req.up);
}

#[test]
fn make_credential_maps_options_and_extensions() {
    let h = handler();
    let params = make_params(|e| {
        set(
            e,
            4,
            Value::Array(vec![
                alg_param(-257),
                alg_param(-8),
                MapBuilder::new()
                    .text("alg", -7)
                    .text("type", "future-type")
                    .build(),
                alg_param(-7),
            ]),
        );
        set(e, 5, Value::Array(vec![descriptor(&[9; 32])]));
        set(
            e,
            6,
            text_map(&[
                ("credProtect", Value::int(2)),
                ("hmac-secret", Value::Bool(true)),
                ("unknownExt", Value::from("x")),
            ]),
        );
        set(
            e,
            7,
            text_map(&[
                ("uv", Value::Bool(true)),
                ("up", Value::Bool(true)),
                ("other", Value::int(5)),
            ]),
        );
    });
    assert_eq!(status_of(&h, command::MAKE_CREDENTIAL, &params), 0x00);
    let req = with_engine(&h, |f| f.makes.pop().unwrap());
    assert_eq!(req.algorithms, vec![-8, -7]);
    assert_eq!(req.exclude_list, vec![vec![9u8; 32]]);
    assert_eq!(req.uv, UvRequirement::Required);
    assert!(!req.resident_key);
    assert!(req.extensions.hmac_secret);
    assert_eq!(
        req.extensions.cred_protect,
        Some(CredProtect::UserVerificationOptionalWithCredentialIdList)
    );
    assert_eq!(req.user.display_name.as_deref(), Some("Alice"));
}

#[test]
fn make_credential_error_paths() {
    type Edit = Box<dyn FnOnce(&mut Vec<(i64, Value)>)>;
    let cases: Vec<(&str, Edit, Status)> = vec![
        (
            "no hash",
            Box::new(|e| remove(e, 1)),
            Status::MissingParameter,
        ),
        (
            "hash type",
            Box::new(|e| set(e, 1, Value::from("h"))),
            Status::CborUnexpectedType,
        ),
        (
            "hash len",
            Box::new(|e| set(e, 1, Value::from([0u8; 31].as_slice()))),
            Status::InvalidParameter,
        ),
        (
            "no rp",
            Box::new(|e| remove(e, 2)),
            Status::MissingParameter,
        ),
        (
            "rp type",
            Box::new(|e| set(e, 2, Value::from("rp"))),
            Status::CborUnexpectedType,
        ),
        (
            "rp no id",
            Box::new(|e| set(e, 2, text_map(&[("name", Value::from("Acme"))]))),
            Status::MissingParameter,
        ),
        (
            "rp id type",
            Box::new(|e| set(e, 2, text_map(&[("id", Value::int(1))]))),
            Status::CborUnexpectedType,
        ),
        (
            "rp name type",
            Box::new(|e| {
                set(
                    e,
                    2,
                    text_map(&[("id", Value::from("example.com")), ("name", Value::int(1))]),
                )
            }),
            Status::CborUnexpectedType,
        ),
        (
            "no user",
            Box::new(|e| remove(e, 3)),
            Status::MissingParameter,
        ),
        (
            "user type",
            Box::new(|e| set(e, 3, Value::Array(vec![]))),
            Status::CborUnexpectedType,
        ),
        (
            "user no id",
            Box::new(|e| set(e, 3, text_map(&[("name", Value::from("alice"))]))),
            Status::MissingParameter,
        ),
        (
            "user id type",
            Box::new(|e| set(e, 3, text_map(&[("id", Value::from("alice"))]))),
            Status::CborUnexpectedType,
        ),
        (
            "user id long",
            Box::new(|e| set(e, 3, text_map(&[("id", Value::from([1u8; 65].as_slice()))]))),
            Status::InvalidParameter,
        ),
        (
            "user id empty",
            Box::new(|e| set(e, 3, text_map(&[("id", Value::Bytes(Vec::new()))]))),
            Status::InvalidParameter,
        ),
        (
            "user name type",
            Box::new(|e| {
                set(
                    e,
                    3,
                    text_map(&[
                        ("id", Value::from([1u8; 4].as_slice())),
                        ("displayName", Value::int(1)),
                    ]),
                )
            }),
            Status::CborUnexpectedType,
        ),
        (
            "no params",
            Box::new(|e| remove(e, 4)),
            Status::MissingParameter,
        ),
        (
            "params type",
            Box::new(|e| set(e, 4, alg_param(-7))),
            Status::CborUnexpectedType,
        ),
        (
            "param type",
            Box::new(|e| set(e, 4, Value::Array(vec![Value::int(-7)]))),
            Status::CborUnexpectedType,
        ),
        (
            "param no alg",
            Box::new(|e| {
                set(
                    e,
                    4,
                    Value::Array(vec![text_map(&[("type", Value::from("public-key"))])]),
                )
            }),
            Status::MissingParameter,
        ),
        (
            "param no type",
            Box::new(|e| {
                set(
                    e,
                    4,
                    Value::Array(vec![text_map(&[("alg", Value::int(-7))])]),
                )
            }),
            Status::MissingParameter,
        ),
        (
            "param alg type",
            Box::new(|e| {
                set(
                    e,
                    4,
                    Value::Array(vec![text_map(&[
                        ("alg", Value::from("ES256")),
                        ("type", Value::from("public-key")),
                    ])]),
                )
            }),
            Status::CborUnexpectedType,
        ),
        (
            "param type type",
            Box::new(|e| {
                set(
                    e,
                    4,
                    Value::Array(vec![text_map(&[
                        ("alg", Value::int(-7)),
                        ("type", Value::int(1)),
                    ])]),
                )
            }),
            Status::CborUnexpectedType,
        ),
        (
            "only rs256",
            Box::new(|e| set(e, 4, Value::Array(vec![alg_param(-257)]))),
            Status::UnsupportedAlgorithm,
        ),
        (
            "empty params",
            Box::new(|e| set(e, 4, Value::Array(vec![]))),
            Status::UnsupportedAlgorithm,
        ),
        (
            "exclude type",
            Box::new(|e| set(e, 5, descriptor(&[1]))),
            Status::CborUnexpectedType,
        ),
        (
            "exclude no id",
            Box::new(|e| {
                set(
                    e,
                    5,
                    Value::Array(vec![text_map(&[("type", Value::from("public-key"))])]),
                )
            }),
            Status::MissingParameter,
        ),
        (
            "exclude id type",
            Box::new(|e| {
                set(
                    e,
                    5,
                    Value::Array(vec![text_map(&[
                        ("id", Value::from("x")),
                        ("type", Value::from("public-key")),
                    ])]),
                )
            }),
            Status::CborUnexpectedType,
        ),
        (
            "ext type",
            Box::new(|e| set(e, 6, Value::Array(vec![]))),
            Status::CborUnexpectedType,
        ),
        (
            "hmac type",
            Box::new(|e| set(e, 6, text_map(&[("hmac-secret", Value::int(1))]))),
            Status::CborUnexpectedType,
        ),
        (
            "credProtect 0",
            Box::new(|e| set(e, 6, text_map(&[("credProtect", Value::int(0))]))),
            Status::InvalidParameter,
        ),
        (
            "credProtect 4",
            Box::new(|e| set(e, 6, text_map(&[("credProtect", Value::int(4))]))),
            Status::InvalidParameter,
        ),
        (
            "credProtect type",
            Box::new(|e| set(e, 6, text_map(&[("credProtect", Value::from("x"))]))),
            Status::CborUnexpectedType,
        ),
        (
            "options type",
            Box::new(|e| set(e, 7, Value::Bool(true))),
            Status::CborUnexpectedType,
        ),
        (
            "rk type",
            Box::new(|e| set(e, 7, text_map(&[("rk", Value::int(1))]))),
            Status::CborUnexpectedType,
        ),
        (
            "up false",
            Box::new(|e| set(e, 7, text_map(&[("up", Value::Bool(false))]))),
            Status::InvalidOption,
        ),
        (
            "pin param type",
            Box::new(|e| set(e, 8, Value::int(1))),
            Status::CborUnexpectedType,
        ),
        (
            "pin param no protocol",
            Box::new(|e| set(e, 8, Value::from([0u8; 16].as_slice()))),
            Status::MissingParameter,
        ),
        (
            "pin protocol type",
            Box::new(|e| {
                set(e, 8, Value::from([0u8; 16].as_slice()));
                set(e, 9, Value::from("1"));
            }),
            Status::CborUnexpectedType,
        ),
        (
            "pin protocol 3",
            Box::new(|e| {
                set(e, 8, Value::from([0u8; 16].as_slice()));
                set(e, 9, Value::int(3));
            }),
            Status::InvalidParameter,
        ),
        (
            "pin param p1",
            Box::new(|e| {
                set(e, 8, Value::from([0u8; 16].as_slice()));
                set(e, 9, Value::int(1));
            }),
            Status::PinAuthInvalid,
        ),
        (
            "pin param p2",
            Box::new(|e| {
                set(e, 8, Value::from([0u8; 32].as_slice()));
                set(e, 9, Value::int(2));
            }),
            Status::PinAuthInvalid,
        ),
        (
            "enterprise",
            Box::new(|e| set(e, 10, Value::int(1))),
            Status::InvalidParameter,
        ),
        (
            "unknown key ignored",
            Box::new(|e| set(e, 0x20, Value::int(1))),
            Status::Ok,
        ),
        (
            "attestation formats ignored",
            Box::new(|e| set(e, 0x0b, Value::Array(vec![Value::from("packed")]))),
            Status::Ok,
        ),
    ];
    for (name, edit, expected) in cases {
        let h = handler();
        let got = status_of(&h, command::MAKE_CREDENTIAL, &make_params(edit));
        assert_eq!(got, expected.code(), "{name}");
        let called = with_engine(&h, |f| f.makes.len());
        assert_eq!(called, usize::from(expected == Status::Ok), "{name}");
    }
}

#[test]
fn malformed_cbor_is_rejected() {
    let h = handler();
    let ctx = RequestContext::new();
    let valid = cbor::encode(&make_params(|_| {})).unwrap();
    let mut trailing = vec![command::MAKE_CREDENTIAL];
    trailing.extend_from_slice(&valid);
    trailing.push(0x00);
    let mut truncated = vec![command::MAKE_CREDENTIAL];
    truncated.extend_from_slice(&valid[..valid.len() - 1]);
    // {2: 0, 1: 0}: keys out of canonical order.
    let unsorted = vec![command::MAKE_CREDENTIAL, 0xa2, 0x02, 0x00, 0x01, 0x00];
    // 0x18 0x05: non-shortest integer.
    let long_int = vec![command::GET_ASSERTION, 0xa1, 0x18, 0x01, 0x00];
    let float = vec![command::MAKE_CREDENTIAL, 0xa1, 0x01, 0xf9, 0x3c, 0x00];
    let tag = vec![command::GET_ASSERTION, 0xa1, 0x01, 0xc0, 0x60];
    let indefinite = vec![command::CLIENT_PIN, 0xbf, 0x01, 0x01, 0xff];
    let duplicate = vec![command::CLIENT_PIN, 0xa2, 0x01, 0x01, 0x01, 0x02];
    for (name, msg) in [
        ("trailing", trailing),
        ("truncated", truncated),
        ("unsorted", unsorted),
        ("long int", long_int),
        ("float", float),
        ("tag", tag),
        ("indefinite", indefinite),
        ("duplicate", duplicate),
    ] {
        assert_eq!(
            h.process(&msg, &ctx),
            vec![Status::InvalidCbor.code()],
            "{name}"
        );
    }
    for cmd in [
        command::MAKE_CREDENTIAL,
        command::GET_ASSERTION,
        command::CLIENT_PIN,
    ] {
        assert_eq!(
            h.process(&[cmd, 0x80], &ctx),
            vec![Status::CborUnexpectedType.code()]
        );
        assert_eq!(h.process(&[cmd], &ctx), vec![Status::InvalidCbor.code()]);
    }
    let mut deep = vec![command::MAKE_CREDENTIAL, 0xa1, 0x01];
    deep.extend(std::iter::repeat_n(0x81, 20));
    deep.push(0x00);
    assert_eq!(h.process(&deep, &ctx), vec![Status::LimitExceeded.code()]);
    let mut big = vec![command::MAKE_CREDENTIAL, 0xa1, 0x01, 0x59, 0x1d, 0xb9];
    big.extend(std::iter::repeat_n(0u8, 7609));
    assert_eq!(h.process(&big, &ctx), vec![Status::RequestTooLarge.code()]);
    assert_eq!(with_engine(&h, |f| f.makes.len() + f.gets.len()), 0);
}

#[test]
fn touch_probe_waits_for_a_gesture_then_reports_no_pin() {
    let probe_mc = make_params(|e| {
        set(e, 8, Value::Bytes(Vec::new()));
        set(e, 9, Value::int(1));
    });
    let probe_ga = get_params(|e| {
        set(e, 6, Value::Bytes(Vec::new()));
        set(e, 7, Value::int(2));
    });
    for (cmd, params) in [
        (command::MAKE_CREDENTIAL, &probe_mc),
        (command::GET_ASSERTION, &probe_ga),
    ] {
        let h = handler();
        assert_eq!(status_of(&h, cmd, params), Status::PinNotSet.code());
        assert_eq!(
            with_engine(&h, |f| (f.selects, f.makes.len(), f.gets.len())),
            (1, 0, 0)
        );

        for (err, expected) in [
            (ApprovalError::Denied, Status::OperationDenied),
            (ApprovalError::Timeout, Status::UserActionTimeout),
        ] {
            let h = handler();
            with_engine(&h, |f| f.fail = Some(CoreError::Approval(err)));
            assert_eq!(status_of(&h, cmd, params), expected.code());
        }
    }
}

#[test]
fn engine_errors_become_statuses() {
    for (err, expected) in [
        (CoreError::CredentialExcluded, Status::CredentialExcluded),
        (CoreError::NoCredentials, Status::NoCredentials),
        (CoreError::UvRequiredUnavailable, Status::OperationDenied),
        (
            CoreError::Approval(ApprovalError::Locked),
            Status::UvBlocked,
        ),
        (CoreError::Vault("io".into()), Status::Other),
    ] {
        let h = handler();
        with_engine(&h, |f| f.fail = Some(err.clone()));
        assert_eq!(
            status_of(&h, command::MAKE_CREDENTIAL, &make_params(|_| {})),
            expected.code()
        );
        assert_eq!(
            status_of(&h, command::GET_ASSERTION, &get_params(|_| {})),
            expected.code()
        );
    }
}

#[test]
fn get_assertion_options_and_response() {
    let h = handler();
    with_engine(&h, |f| {
        f.user_handle = vec![7; 16];
        f.user = Some(UserEntity {
            id: vec![7; 16],
            name: Some("alice@example.com".into()),
            display_name: Some("Alice".into()),
        });
    });
    let resp = body(&run(&h, command::GET_ASSERTION, &get_params(|_| {})));
    let req = with_engine(&h, |f| f.gets.pop().unwrap());
    assert_eq!(req.uv, UvRequirement::Discouraged);
    assert!(req.up);
    assert!(req.allow_list.is_empty());
    assert_eq!(req.extensions, GetExtensions::default());

    let cred = resp.get_int(1).unwrap();
    assert_eq!(
        cred.get_text("id").and_then(Value::as_bytes),
        Some([2u8; 32].as_slice())
    );
    assert_eq!(
        cred.get_text("type").and_then(Value::as_text),
        Some("public-key")
    );
    assert_eq!(
        resp.get_int(2).and_then(Value::as_bytes),
        Some(FAKE_AUTH_DATA.as_slice())
    );
    assert_eq!(
        resp.get_int(3).and_then(Value::as_bytes),
        Some([0x30, 1, 2].as_slice())
    );
    let user = resp.get_int(4).unwrap();
    assert_eq!(user.as_map().unwrap().len(), 1);
    assert_eq!(
        user.get_text("id").and_then(Value::as_bytes),
        Some([7u8; 16].as_slice())
    );
    assert!(resp.get_int(5).is_none());
    assert_eq!(resp.get_int(6), Some(&Value::Bool(true)));

    // With an allow list the platform chose the credential: no userSelected.
    let params = get_params(|e| {
        set(
            e,
            3,
            Value::Array(vec![descriptor(&[2; 32]), descriptor(&[3; 32])]),
        );
        set(e, 5, text_map(&[("uv", Value::Bool(true))]));
    });
    let resp = body(&run(&h, command::GET_ASSERTION, &params));
    assert!(resp.get_int(6).is_none());
    let req = with_engine(&h, |f| f.gets.pop().unwrap());
    assert_eq!(req.allow_list.len(), 2);
    assert_eq!(req.uv, UvRequirement::Required);

    // Silent probe: up false, no userSelected, no user when the engine has none.
    let h = handler();
    let params = get_params(|e| set(e, 5, text_map(&[("up", Value::Bool(false))])));
    let resp = body(&run(&h, command::GET_ASSERTION, &params));
    assert!(resp.get_int(4).is_none());
    assert!(resp.get_int(6).is_none());
    assert!(!with_engine(&h, |f| f.gets.pop().unwrap()).up);
}

fn hmac_ext(entries: &[(i64, Value)]) -> Value {
    text_map(&[(
        "hmac-secret",
        Value::Map(
            entries
                .iter()
                .map(|(k, v)| (Value::int(*k), v.clone()))
                .collect(),
        ),
    )])
}

fn some_key() -> Value {
    let (_, x, y) = ctap_pin_uv::generate().unwrap();
    cose::key_agreement_value(&x, &y)
}

#[test]
fn get_assertion_error_paths() {
    type Edit = Box<dyn FnOnce(&mut Vec<(i64, Value)>)>;
    let key = some_key();
    let k2 = key.clone();
    let k3 = key.clone();
    let k4 = key.clone();
    let k5 = key.clone();
    let cases: Vec<(&str, Edit, Status)> = vec![
        (
            "no rp id",
            Box::new(|e| remove(e, 1)),
            Status::MissingParameter,
        ),
        (
            "rp id type",
            Box::new(|e| set(e, 1, Value::from([1u8].as_slice()))),
            Status::CborUnexpectedType,
        ),
        (
            "no hash",
            Box::new(|e| remove(e, 2)),
            Status::MissingParameter,
        ),
        (
            "hash len",
            Box::new(|e| set(e, 2, Value::from([0u8; 33].as_slice()))),
            Status::InvalidParameter,
        ),
        (
            "allow type",
            Box::new(|e| set(e, 3, Value::from("x"))),
            Status::CborUnexpectedType,
        ),
        (
            "allow item type",
            Box::new(|e| set(e, 3, Value::Array(vec![Value::int(1)]))),
            Status::CborUnexpectedType,
        ),
        (
            "allow no type",
            Box::new(|e| {
                set(
                    e,
                    3,
                    Value::Array(vec![text_map(&[("id", Value::from([1u8].as_slice()))])]),
                )
            }),
            Status::MissingParameter,
        ),
        (
            "ext type",
            Box::new(|e| set(e, 4, Value::int(1))),
            Status::CborUnexpectedType,
        ),
        (
            "hmac type",
            Box::new(|e| set(e, 4, text_map(&[("hmac-secret", Value::Bool(true))]))),
            Status::CborUnexpectedType,
        ),
        (
            "hmac no key",
            Box::new(|e| {
                set(
                    e,
                    4,
                    hmac_ext(&[
                        (2, Value::from([0u8; 32].as_slice())),
                        (3, Value::from([0u8; 16].as_slice())),
                    ]),
                )
            }),
            Status::MissingParameter,
        ),
        (
            "hmac bad key",
            Box::new(|e| {
                set(
                    e,
                    4,
                    hmac_ext(&[
                        (1, text_map(&[("kty", Value::int(2))])),
                        (2, Value::from([0u8; 32].as_slice())),
                        (3, Value::from([0u8; 16].as_slice())),
                    ]),
                )
            }),
            Status::InvalidParameter,
        ),
        (
            "hmac no saltEnc",
            Box::new(move |e| {
                set(
                    e,
                    4,
                    hmac_ext(&[(1, key), (3, Value::from([0u8; 16].as_slice()))]),
                )
            }),
            Status::MissingParameter,
        ),
        (
            "hmac no saltAuth",
            Box::new(move |e| {
                set(
                    e,
                    4,
                    hmac_ext(&[(1, k2), (2, Value::from([0u8; 32].as_slice()))]),
                )
            }),
            Status::MissingParameter,
        ),
        (
            "hmac saltEnc type",
            Box::new(move |e| {
                set(
                    e,
                    4,
                    hmac_ext(&[
                        (1, k3),
                        (2, Value::from("s")),
                        (3, Value::from([0u8; 16].as_slice())),
                    ]),
                )
            }),
            Status::CborUnexpectedType,
        ),
        (
            "hmac protocol 3",
            Box::new(move |e| {
                set(
                    e,
                    4,
                    hmac_ext(&[
                        (1, k4),
                        (2, Value::from([0u8; 32].as_slice())),
                        (3, Value::from([0u8; 16].as_slice())),
                        (4, Value::int(3)),
                    ]),
                )
            }),
            Status::InvalidParameter,
        ),
        (
            "hmac bad auth",
            Box::new(move |e| {
                set(
                    e,
                    4,
                    hmac_ext(&[
                        (1, k5),
                        (2, Value::from([0u8; 32].as_slice())),
                        (3, Value::from([0u8; 16].as_slice())),
                    ]),
                )
            }),
            Status::PinAuthInvalid,
        ),
        (
            "options type",
            Box::new(|e| set(e, 5, Value::int(1))),
            Status::CborUnexpectedType,
        ),
        (
            "uv type",
            Box::new(|e| set(e, 5, text_map(&[("uv", Value::from("yes"))]))),
            Status::CborUnexpectedType,
        ),
        (
            "rk true",
            Box::new(|e| set(e, 5, text_map(&[("rk", Value::Bool(true))]))),
            Status::UnsupportedOption,
        ),
        (
            "rk false",
            Box::new(|e| set(e, 5, text_map(&[("rk", Value::Bool(false))]))),
            Status::UnsupportedOption,
        ),
        (
            "rk odd type",
            Box::new(|e| set(e, 5, text_map(&[("rk", Value::int(0))]))),
            Status::CborUnexpectedType,
        ),
        (
            "pin param no protocol",
            Box::new(|e| set(e, 6, Value::from([0u8; 16].as_slice()))),
            Status::MissingParameter,
        ),
        (
            "pin protocol 0",
            Box::new(|e| {
                set(e, 6, Value::from([0u8; 16].as_slice()));
                set(e, 7, Value::int(0));
            }),
            Status::InvalidParameter,
        ),
        (
            "pin param",
            Box::new(|e| {
                set(e, 6, Value::from([0u8; 32].as_slice()));
                set(e, 7, Value::int(2));
            }),
            Status::PinAuthInvalid,
        ),
        (
            "unknown ext ignored",
            Box::new(|e| set(e, 4, text_map(&[("credBlob", Value::Bool(true))]))),
            Status::Ok,
        ),
    ];
    for (name, edit, expected) in cases {
        let h = handler();
        let got = status_of(&h, command::GET_ASSERTION, &get_params(edit));
        assert_eq!(got, expected.code(), "{name}");
        assert_eq!(
            with_engine(&h, |f| f.gets.len()),
            usize::from(expected == Status::Ok),
            "{name}"
        );
    }
}

/// Plays the platform side: getKeyAgreement, then ECDH with a fresh platform key.
fn platform(h: &Ctap2Handler<Fake>, protocol: PinUvAuthProtocol) -> (Value, SharedSecret) {
    let params = MapBuilder::new()
        .int(1, protocol.number())
        .int(2, client_pin::GET_KEY_AGREEMENT)
        .build();
    let resp = body(&run(h, command::CLIENT_PIN, &params));
    assert_eq!(resp.as_map().unwrap().len(), 1);
    let key = resp.get_int(1).unwrap();
    assert_eq!(key.get_int(3).and_then(Value::as_i64), Some(-25));
    let authenticator = cose::parse_key_agreement(key).unwrap();
    let (private, x, y) = ctap_pin_uv::generate().unwrap();
    let z = ctap_pin_uv::ecdh(&private, &authenticator.x, &authenticator.y).unwrap();
    (
        cose::key_agreement_value(&x, &y),
        SharedSecret::from_z(protocol, &z).unwrap(),
    )
}

fn hmac_round_trip(protocol: PinUvAuthProtocol, two_salts: bool, explicit_protocol: bool) {
    let h = handler();
    let (key, secret) = platform(&h, protocol);
    let salt1 = [0x5au8; 32];
    let salt2 = [0xa5u8; 32];
    let mut salts = salt1.to_vec();
    if two_salts {
        salts.extend_from_slice(&salt2);
    }
    let salt_enc = secret.encrypt(&salts).unwrap();
    let salt_auth = secret.authenticate(&salt_enc);
    let mut entries = vec![
        (1, key),
        (2, Value::from(salt_enc)),
        (3, Value::from(salt_auth)),
    ];
    if explicit_protocol {
        entries.push((4, Value::int(protocol.number() as i64)));
    }
    let params = get_params(|e| set(e, 4, hmac_ext(&entries)));
    let resp = body(&run(&h, command::GET_ASSERTION, &params));

    let (req, output, wrapped) = with_engine(&h, |f| {
        (
            f.gets.pop().unwrap(),
            f.hmac_output.clone().unwrap(),
            f.wrapped.clone().unwrap(),
        )
    });
    let expected = HmacSecretSalts {
        salt1,
        salt2: two_salts.then_some(salt2),
    };
    assert_eq!(req.extensions.hmac_secret, Some(expected));
    let out_len = if two_salts { 64 } else { 32 };
    assert_eq!(output.len(), out_len);
    let iv_len = if protocol == PinUvAuthProtocol::Two {
        16
    } else {
        0
    };
    assert_eq!(wrapped.len(), out_len + iv_len);
    assert_eq!(*secret.decrypt(&wrapped).unwrap(), output);
    let auth_data = resp.get_int(2).and_then(Value::as_bytes).unwrap();
    assert!(auth_data.ends_with(&wrapped));
}

#[test]
fn hmac_secret_protocol_one() {
    hmac_round_trip(PinUvAuthProtocol::One, false, false);
    hmac_round_trip(PinUvAuthProtocol::One, true, true);
}

#[test]
fn hmac_secret_protocol_two() {
    hmac_round_trip(PinUvAuthProtocol::Two, false, true);
    hmac_round_trip(PinUvAuthProtocol::Two, true, true);
}

#[test]
fn hmac_secret_rejects_wrong_protocol_and_length() {
    let h = handler();
    let (key, secret) = platform(&h, PinUvAuthProtocol::Two);
    // Protocol mismatch: the platform used protocol two, the request claims one.
    let enc = secret.encrypt(&[1u8; 32]).unwrap();
    let auth = secret.authenticate(&enc);
    let params = get_params(|e| {
        set(
            e,
            4,
            hmac_ext(&[
                (1, key.clone()),
                (2, Value::from(enc)),
                (3, Value::from(auth)),
            ]),
        )
    });
    assert_eq!(
        status_of(&h, command::GET_ASSERTION, &params),
        Status::PinAuthInvalid.code()
    );
    // Three salt blocks are not a valid salt length.
    let enc = secret.encrypt(&[1u8; 48]).unwrap();
    let auth = secret.authenticate(&enc);
    let params = get_params(|e| {
        set(
            e,
            4,
            hmac_ext(&[
                (1, key),
                (2, Value::from(enc)),
                (3, Value::from(auth)),
                (4, Value::int(2)),
            ]),
        )
    });
    assert_eq!(
        status_of(&h, command::GET_ASSERTION, &params),
        Status::InvalidLength.code()
    );
    assert_eq!(with_engine(&h, |f| f.gets.len()), 0);
}

#[test]
fn client_pin_subcommands() {
    let h = handler();
    let get = |p: Option<i64>, sub: Option<u64>| {
        let mut m = MapBuilder::new();
        if let Some(p) = p {
            m = m.int(1, p);
        }
        if let Some(s) = sub {
            m = m.int(2, s);
        }
        run(&h, command::CLIENT_PIN, &m.build())
    };
    let a = get(Some(2), Some(client_pin::GET_KEY_AGREEMENT));
    assert_eq!(a, get(Some(2), Some(client_pin::GET_KEY_AGREEMENT)));
    let b = get(Some(1), Some(client_pin::GET_KEY_AGREEMENT));
    assert_eq!(b[0], 0);
    assert_ne!(a, b);
    h.regenerate_key_agreement();
    assert_ne!(a, get(Some(2), Some(client_pin::GET_KEY_AGREEMENT)));

    assert_eq!(get(None, Some(2)), vec![Status::MissingParameter.code()]);
    assert_eq!(get(Some(3), Some(2)), vec![Status::InvalidParameter.code()]);
    assert_eq!(get(Some(1), None), vec![Status::MissingParameter.code()]);
    for sub in [
        client_pin::GET_PIN_RETRIES,
        client_pin::SET_PIN,
        client_pin::CHANGE_PIN,
        client_pin::GET_PIN_TOKEN,
        client_pin::GET_PIN_UV_AUTH_TOKEN_USING_UV_WITH_PERMISSIONS,
        client_pin::GET_UV_RETRIES,
        client_pin::GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS,
        0x08,
        0xff,
    ] {
        assert_eq!(
            get(Some(2), Some(sub)),
            vec![Status::InvalidSubcommand.code()]
        );
    }
    let bad = MapBuilder::new().int(1, 2).int(2, "two").build();
    assert_eq!(
        status_of(&h, command::CLIENT_PIN, &bad),
        Status::CborUnexpectedType.code()
    );
}

#[test]
fn other_commands() {
    let h = handler();
    let ctx = RequestContext::new();
    assert_eq!(h.process(&[], &ctx), vec![Status::InvalidLength.code()]);
    assert_eq!(
        h.process(&[command::RESET], &ctx),
        vec![Status::OperationDenied.code()]
    );
    assert_eq!(
        h.process(&[command::GET_NEXT_ASSERTION], &ctx),
        vec![Status::NotAllowed.code()]
    );
    for cmd in [
        command::BIO_ENROLLMENT,
        command::CREDENTIAL_MANAGEMENT,
        command::LARGE_BLOBS,
        command::CONFIG,
        0x03,
        0x40,
        0x41,
        0xc0,
    ] {
        assert_eq!(
            h.process(&[cmd], &ctx),
            vec![Status::InvalidCommand.code()],
            "{cmd:#x}"
        );
    }
    assert_eq!(h.process(&[command::SELECTION], &ctx), vec![0x00]);
    assert_eq!(with_engine(&h, |f| f.selects), 1);
    with_engine(&h, |f| {
        f.fail = Some(CoreError::Approval(ApprovalError::Denied))
    });
    assert_eq!(
        h.process(&[command::SELECTION], &ctx),
        vec![Status::OperationDenied.code()]
    );
    with_engine(&h, |f| {
        f.fail = Some(CoreError::Approval(ApprovalError::Timeout))
    });
    assert_eq!(
        h.process(&[command::SELECTION], &ctx),
        vec![Status::UserActionTimeout.code()]
    );
}

#[test]
fn cancellation_stops_a_blocked_engine() {
    for msg in [
        vec![command::SELECTION],
        {
            let mut m = vec![command::GET_ASSERTION];
            m.extend_from_slice(&cbor::encode(&get_params(|_| {})).unwrap());
            m
        },
        {
            let mut m = vec![command::MAKE_CREDENTIAL];
            m.extend_from_slice(&cbor::encode(&make_params(|_| {})).unwrap());
            m
        },
    ] {
        let h = Arc::new(handler());
        with_engine(&h, |f| f.block = true);
        let ctx = RequestContext::new();
        let worker = {
            let (h, ctx) = (Arc::clone(&h), ctx.clone());
            std::thread::spawn(move || CborHandler::handle(&*h, &msg, &ctx))
        };
        let start = Instant::now();
        while ctx.status() != KeepaliveStatus::UpNeeded && start.elapsed() < Duration::from_secs(5)
        {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(ctx.status(), KeepaliveStatus::UpNeeded);
        ctx.cancel();
        let resp = worker.join().unwrap();
        assert_eq!(resp, vec![Status::KeepaliveCancel.code()]);
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}

#[test]
fn descriptor_ids_of_any_length_up_to_1023() {
    let ids = [vec![1u8; 1], vec![2u8; 16], vec![3u8; 32], vec![4u8; 1023]];
    let list = Value::Array(ids.iter().map(|id| descriptor(id)).collect());
    let enc = cbor::encode(&get_params(|e| set(e, 3, list.clone()))).unwrap();
    assert_eq!(parse_get_assertion(&enc).unwrap().allow_list, ids.to_vec());
    let enc = cbor::encode(&make_params(|e| set(e, 5, list))).unwrap();
    assert_eq!(
        parse_make_credential(&enc).unwrap().exclude_list,
        ids.to_vec()
    );

    let too_long = Value::Array(vec![descriptor(&[2; 16]), descriptor(&[5; 1024])]);
    let enc = cbor::encode(&get_params(|e| set(e, 3, too_long.clone()))).unwrap();
    assert_eq!(
        parse_get_assertion(&enc).unwrap_err(),
        Status::InvalidParameter
    );
    let enc = cbor::encode(&make_params(|e| set(e, 5, too_long))).unwrap();
    assert_eq!(
        parse_make_credential(&enc).unwrap_err(),
        Status::InvalidParameter
    );

    // Descriptors of other types are skipped whatever their id.
    let other = Value::Array(vec![
        MapBuilder::new()
            .text("id", [6u8; 1024].as_slice())
            .text("type", "future-type")
            .build(),
        descriptor(&[2; 16]),
    ]);
    let enc = cbor::encode(&get_params(|e| set(e, 3, other))).unwrap();
    assert_eq!(
        parse_get_assertion(&enc).unwrap().allow_list,
        vec![vec![2u8; 16]]
    );
}
