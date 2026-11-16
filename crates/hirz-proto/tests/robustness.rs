//! Deterministic pseudo-random round trips and mutation tests for every decoder.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

mod common;

use common::vectors::*;
use common::{XorShift, hex};
use hirz_proto::attestation;
use hirz_proto::auth_data::AuthenticatorData;
use hirz_proto::base64url;
use hirz_proto::cbor::{self, Limits, Value};
use hirz_proto::cose;
use hirz_proto::json::{self, Json, Number};

const CHARS: [char; 14] = [
    'a',
    'Z',
    '0',
    ' ',
    '"',
    '\\',
    '/',
    '\u{0}',
    '\u{1f}',
    '\u{7f}',
    '\u{e9}',
    '\u{20ac}',
    '\u{1f600}',
    '\u{2028}',
];

const INTS: [u64; 12] = [
    0,
    1,
    23,
    24,
    255,
    256,
    65_535,
    65_536,
    4_294_967_295,
    4_294_967_296,
    u64::MAX - 1,
    u64::MAX,
];

fn random_text(rng: &mut XorShift) -> String {
    let len = rng.below(12);
    (0..len).map(|_| *rng.pick(&CHARS)).collect()
}

fn random_int(rng: &mut XorShift) -> u64 {
    if rng.below(2) == 0 {
        *rng.pick(&INTS)
    } else {
        rng.next_u64() >> rng.below(64)
    }
}

fn random_key(rng: &mut XorShift) -> Value {
    match rng.below(3) {
        0 => Value::Unsigned(random_int(rng)),
        1 => Value::Negative(random_int(rng)),
        _ => Value::Text(random_text(rng)),
    }
}

fn random_cbor(rng: &mut XorShift, depth: usize) -> Value {
    let kinds = if depth >= 6 { 6 } else { 8 };
    match rng.below(kinds) {
        0 => Value::Unsigned(random_int(rng)),
        1 => Value::Negative(random_int(rng)),
        2 => {
            let len = rng.below(40);
            Value::Bytes(rng.bytes(len))
        }
        3 => Value::Text(random_text(rng)),
        4 => Value::Bool(rng.below(2) == 0),
        5 => Value::Null,
        6 => Value::Array(
            (0..rng.below(5))
                .map(|_| random_cbor(rng, depth + 1))
                .collect(),
        ),
        _ => {
            let mut entries: Vec<(Value, Value)> = Vec::new();
            for _ in 0..rng.below(5) {
                let key = random_key(rng);
                if entries.iter().all(|(k, _)| *k != key) {
                    entries.push((key, random_cbor(rng, depth + 1)));
                }
            }
            Value::Map(entries)
        }
    }
}

fn mutate(rng: &mut XorShift, input: &[u8]) -> Vec<u8> {
    let mut out = input.to_vec();
    for _ in 0..=rng.below(3) {
        match rng.below(5) {
            0 if !out.is_empty() => {
                let i = rng.below(out.len());
                out[i] ^= 1 << rng.below(8);
            }
            1 if !out.is_empty() => {
                let i = rng.below(out.len());
                out[i] = rng.next_u64() as u8;
            }
            2 => {
                let i = rng.below(out.len() + 1);
                out.insert(i, rng.next_u64() as u8);
            }
            3 if !out.is_empty() => {
                let i = rng.below(out.len());
                out.remove(i);
            }
            _ => {
                let len = rng.below(out.len() + 1);
                out.truncate(len);
            }
        }
    }
    out
}

#[test]
fn cbor_random_round_trip() {
    let mut rng = XorShift::new(0x6869_727a_0001);
    let lenient = Limits {
        require_canonical: false,
        ..Limits::default()
    };
    for _ in 0..3000 {
        let value = random_cbor(&mut rng, 0);
        let encoded = cbor::encode(&value).unwrap();
        let decoded = cbor::decode(&encoded, &Limits::default()).unwrap();
        assert_eq!(cbor::encode(&decoded).unwrap(), encoded);
        assert_eq!(cbor::decode(&encoded, &lenient).unwrap(), decoded);
        for (k, v) in value.as_map().unwrap_or_default() {
            let found = decoded.get(k).unwrap();
            assert_eq!(cbor::encode(found).unwrap(), cbor::encode(v).unwrap());
        }
    }
}

#[test]
fn cbor_mutations_never_panic_and_strict_is_bijective() {
    let mut rng = XorShift::new(0x6869_727a_0002);
    let mut corpus: Vec<Vec<u8>> = [
        NONE_ES256_REG_ATTESTATIONOBJECT,
        SELF_ES256_REG_ATTESTATIONOBJECT,
        TOP_REG_ATTESTATIONOBJECT,
        PACKED_ED25519_REG_ATTESTATIONOBJECT,
    ]
    .iter()
    .map(|h| hex(h))
    .collect();
    corpus.push(cose::encode_es256(&[7; 32], &[9; 32]));
    corpus.push(attestation::none_ctap(&[1; 37]));
    for _ in 0..64 {
        corpus.push(cbor::encode(&random_cbor(&mut rng, 0)).unwrap());
    }
    let lenient = Limits {
        require_canonical: false,
        ..Limits::default()
    };
    let mut accepted = 0;
    for i in 0..30_000 {
        let seed = &corpus[i % corpus.len()];
        let input = mutate(&mut rng, seed);
        if let Ok(v) = cbor::decode(&input, &Limits::default()) {
            accepted += 1;
            assert_eq!(cbor::encode(&v).unwrap(), input);
            let _ = cose::parse_public_key(&v);
            let _ = cose::parse_key_agreement(&v);
        }
        if let Ok(v) = cbor::decode(&input, &lenient) {
            let re = cbor::encode(&v).unwrap();
            let canonical = cbor::decode(&re, &Limits::default()).unwrap();
            assert_eq!(cbor::encode(&canonical).unwrap(), re);
        }
        if let Ok(obj) = attestation::parse_webauthn(&input, &Limits::default()) {
            let _ = AuthenticatorData::parse(&obj.auth_data, &Limits::default());
        }
        let _ = attestation::parse_ctap(&input, &Limits::default());
    }
    assert!(accepted > 1000, "{accepted}");
}

#[test]
fn auth_data_mutations_never_panic() {
    let mut rng = XorShift::new(0x6869_727a_0003);
    let seeds: Vec<Vec<u8>> = [
        NONE_ES256_REG_ATTESTATIONOBJECT,
        LONGID_REG_ATTESTATIONOBJECT,
        PACKED_ED25519_REG_ATTESTATIONOBJECT,
    ]
    .iter()
    .map(|h| {
        attestation::parse_webauthn(&hex(h), &Limits::default())
            .unwrap()
            .auth_data
    })
    .collect();
    let mut accepted = 0;
    for i in 0..20_000 {
        let input = mutate(&mut rng, &seeds[i % seeds.len()]);
        if let Ok(ad) = AuthenticatorData::parse(&input, &Limits::default())
            && let Ok(re) = ad.encode()
        {
            assert_eq!(re, input);
            accepted += 1;
        }
    }
    assert!(accepted > 1000, "{accepted}");
}

fn random_json(rng: &mut XorShift, depth: usize) -> Json {
    let kinds = if depth >= 10 { 6 } else { 8 };
    match rng.below(kinds) {
        0 => Json::Null,
        1 => Json::Bool(rng.below(2) == 0),
        2 => Json::from(rng.next_u64() >> rng.below(64)),
        3 => Json::from(rng.next_u64() as i64 >> rng.below(64)),
        4 => {
            let f = f64::from_bits(rng.next_u64());
            // "-0" parses back as the exact integer 0, which is written as "0".
            let f = if f == 0.0 { 0.0 } else { f };
            match Number::from_f64(f) {
                Some(n) => Json::Number(n),
                None => {
                    Json::Number(Number::from_f64(f64::from(rng.next_u64() as i32) / 8.0).unwrap())
                }
            }
        }
        5 => Json::String(random_text(rng)),
        6 => Json::Array(
            (0..rng.below(5))
                .map(|_| random_json(rng, depth + 1))
                .collect(),
        ),
        _ => {
            let mut members: Vec<(String, Json)> = Vec::new();
            for _ in 0..rng.below(5) {
                let key = random_text(rng);
                if members.iter().all(|(k, _)| *k != key) {
                    members.push((key, random_json(rng, depth + 1)));
                }
            }
            Json::Object(members)
        }
    }
}

#[test]
fn json_random_round_trip_and_mutations() {
    let mut rng = XorShift::new(0x6869_727a_0004);
    let mut corpus = Vec::new();
    for _ in 0..2000 {
        let value = random_json(&mut rng, 0);
        let text = value.to_string();
        let parsed = json::parse(text.as_bytes(), &json::Limits::default()).unwrap();
        assert_eq!(parsed, value, "{text}");
        assert_eq!(parsed.to_string(), text);
        if corpus.len() < 64 {
            corpus.push(text.into_bytes());
        }
    }
    corpus.push(hex(NONE_ES256_REG_CLIENTDATAJSON));
    corpus.push(hex(TOP_AUTH_CLIENTDATAJSON));
    corpus.push(br#"{"a":"\ud83d\ude00","b":[1,2.5e-3,-0,true,null]}"#.to_vec());
    let mut accepted = 0;
    for i in 0..30_000 {
        let input = mutate(&mut rng, &corpus[i % corpus.len()]);
        if let Ok(v) = json::parse(&input, &json::Limits::default()) {
            accepted += 1;
            let text = v.to_string();
            assert_eq!(
                json::parse(text.as_bytes(), &json::Limits::default()).unwrap(),
                v
            );
        }
    }
    assert!(accepted > 1000, "{accepted}");
}

#[test]
fn base64url_random_round_trip_and_strictness() {
    let mut rng = XorShift::new(0x6869_727a_0005);
    for _ in 0..2000 {
        let len = rng.below(70);
        let data = rng.bytes(len);
        let enc = base64url::encode(&data);
        assert_eq!(base64url::decode(&enc).unwrap(), data);
    }
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=+/ .";
    for _ in 0..20_000 {
        let len = rng.below(12);
        let s: String = (0..len).map(|_| char::from(*rng.pick(alphabet))).collect();
        if let Ok(bytes) = base64url::decode(&s) {
            assert_eq!(base64url::encode(&bytes), s);
        }
    }
}
