//! Checks against the W3C Web Authentication Level 3 test vectors (section 16).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::vectors::*;
use common::{RP_ID_HASH, hex, hex32};
use hirz_proto::attestation::{self, FMT_NONE};
use hirz_proto::auth_data::{
    AttestedCredentialData, AuthenticatorData, FLAG_AT, FLAG_BE, FLAG_BS, FLAG_UP, FLAG_UV,
};
use hirz_proto::cbor::{self, Limits, Value};
use hirz_proto::client_data::{self, CeremonyType};
use hirz_proto::cose::{self, PublicKey};
use hirz_proto::{base64url, json};

const USER_FLAGS: u8 = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS;

struct Registration {
    name: &'static str,
    attestation_object: &'static str,
    aaguid: &'static str,
    credential_id: &'static str,
    expected_flags: u8,
}

const NONE_REGISTRATIONS: [Registration; 4] = [
    Registration {
        name: "none.ES256",
        attestation_object: NONE_ES256_REG_ATTESTATIONOBJECT,
        aaguid: NONE_ES256_REG_AAGUID,
        credential_id: NONE_ES256_REG_CREDENTIAL_ID,
        expected_flags: FLAG_UP | FLAG_BE | FLAG_BS | FLAG_AT,
    },
    Registration {
        name: "none.ES256.crossOrigin",
        attestation_object: CROSS_REG_ATTESTATIONOBJECT,
        aaguid: CROSS_REG_AAGUID,
        credential_id: CROSS_REG_CREDENTIAL_ID,
        expected_flags: FLAG_UP | FLAG_UV | FLAG_AT,
    },
    Registration {
        name: "none.ES256.topOrigin",
        attestation_object: TOP_REG_ATTESTATIONOBJECT,
        aaguid: TOP_REG_AAGUID,
        credential_id: TOP_REG_CREDENTIAL_ID,
        expected_flags: FLAG_UP | FLAG_AT,
    },
    Registration {
        name: "none.ES256.long-credential-id",
        attestation_object: LONGID_REG_ATTESTATIONOBJECT,
        aaguid: LONGID_REG_AAGUID,
        credential_id: LONGID_REG_CREDENTIAL_ID,
        expected_flags: FLAG_UP | FLAG_BE | FLAG_AT,
    },
];

#[test]
fn none_attestation_objects_are_reproduced() {
    for reg in &NONE_REGISTRATIONS {
        let att = hex(reg.attestation_object);
        let obj = attestation::parse_webauthn(&att, &Limits::default()).unwrap();
        assert_eq!(obj.fmt, FMT_NONE, "{}", reg.name);
        assert_eq!(obj.att_stmt, Value::Map(vec![]), "{}", reg.name);

        let ad = AuthenticatorData::parse(&obj.auth_data, &Limits::default()).unwrap();
        assert_eq!(ad.rp_id_hash, hex32(RP_ID_HASH), "{}", reg.name);
        assert_eq!(ad.flags, reg.expected_flags, "{}", reg.name);
        assert_eq!(ad.sign_count, 0);
        assert!(ad.extensions.is_none());
        let cred = ad.attested_credential.clone().unwrap();
        assert_eq!(cred.aaguid.to_vec(), hex(reg.aaguid), "{}", reg.name);
        assert_eq!(cred.credential_id, hex(reg.credential_id), "{}", reg.name);

        let key = cbor::decode(&cred.public_key, &Limits::default()).unwrap();
        let PublicKey::Es256 { x, y } = cose::parse_public_key(&key).unwrap() else {
            panic!("{}: expected an ES256 key", reg.name);
        };
        let public_key = cose::encode_es256(&x, &y);
        assert_eq!(public_key, cred.public_key, "{}", reg.name);

        let rebuilt = AuthenticatorData {
            rp_id_hash: hex32(RP_ID_HASH),
            flags: reg.expected_flags & USER_FLAGS,
            sign_count: 0,
            attested_credential: Some(AttestedCredentialData {
                aaguid: cred.aaguid,
                credential_id: hex(reg.credential_id),
                public_key,
            }),
            extensions: None,
        }
        .encode()
        .unwrap();
        assert_eq!(rebuilt, obj.auth_data, "{}", reg.name);
        assert_eq!(attestation::none_webauthn(&rebuilt), att, "{}", reg.name);

        let ctap = attestation::none_ctap(&rebuilt);
        let ctap_obj = attestation::parse_ctap(&ctap, &Limits::default()).unwrap();
        assert_eq!(ctap_obj, obj, "{}", reg.name);
    }
}

#[test]
fn long_credential_id_uses_the_maximum_length() {
    let obj = attestation::parse_webauthn(&hex(LONGID_REG_ATTESTATIONOBJECT), &Limits::default())
        .unwrap();
    assert_eq!(&obj.auth_data[53..55], &[0x03, 0xff]);
    let ad = AuthenticatorData::parse(&obj.auth_data, &Limits::default()).unwrap();
    assert_eq!(ad.attested_credential.unwrap().credential_id.len(), 1023);
}

#[test]
fn packed_attestation_objects_parse() {
    for (att_hex, credential_id) in [
        (
            SELF_ES256_REG_ATTESTATIONOBJECT,
            SELF_ES256_REG_CREDENTIAL_ID,
        ),
        (
            PACKED_ED25519_REG_ATTESTATIONOBJECT,
            PACKED_ED25519_REG_CREDENTIAL_ID,
        ),
    ] {
        let att = hex(att_hex);
        let obj = attestation::parse_webauthn(&att, &Limits::default()).unwrap();
        assert_eq!(obj.fmt, "packed");
        assert_eq!(
            obj.att_stmt.get_text("alg").and_then(Value::as_i64),
            Some(-7)
        );
        assert!(
            obj.att_stmt
                .get_text("sig")
                .and_then(Value::as_bytes)
                .is_some()
        );
        let ad = AuthenticatorData::parse(&obj.auth_data, &Limits::default()).unwrap();
        let cred = ad.attested_credential.unwrap();
        assert_eq!(cred.credential_id, hex(credential_id));
        let key = cbor::decode(&cred.public_key, &Limits::default()).unwrap();
        let reencoded = match cose::parse_public_key(&key).unwrap() {
            PublicKey::Es256 { x, y } => cose::encode_es256(&x, &y),
            PublicKey::Ed25519 { x } => cose::encode_ed25519(&x),
        };
        assert_eq!(reencoded, cred.public_key);
    }
    let ed = attestation::parse_webauthn(
        &hex(PACKED_ED25519_REG_ATTESTATIONOBJECT),
        &Limits::default(),
    )
    .unwrap();
    let ad = AuthenticatorData::parse(&ed.auth_data, &Limits::default()).unwrap();
    let key = cbor::decode(
        &ad.attested_credential.unwrap().public_key,
        &Limits::default(),
    )
    .unwrap();
    assert!(matches!(
        cose::parse_public_key(&key).unwrap(),
        PublicKey::Ed25519 { .. }
    ));
}

#[test]
fn assertion_authenticator_data_is_reproduced() {
    let cases = [
        (
            NONE_ES256_AUTH_AUTHENTICATORDATA,
            FLAG_UP | FLAG_BE | FLAG_BS,
        ),
        (SELF_ES256_AUTH_AUTHENTICATORDATA, FLAG_UP | FLAG_BE),
        (CROSS_AUTH_AUTHENTICATORDATA, FLAG_UP | FLAG_UV),
        (TOP_AUTH_AUTHENTICATORDATA, FLAG_UP | FLAG_UV),
        (LONGID_AUTH_AUTHENTICATORDATA, FLAG_UP | FLAG_UV | FLAG_BE),
        (PACKED_ED25519_AUTH_AUTHENTICATORDATA, FLAG_UP),
    ];
    for (ad_hex, flags) in cases {
        let bytes = hex(ad_hex);
        let parsed = AuthenticatorData::parse(&bytes, &Limits::default()).unwrap();
        assert_eq!(parsed.flags, flags, "{ad_hex}");
        assert!(parsed.attested_credential.is_none());
        let rebuilt = AuthenticatorData {
            rp_id_hash: hex32(RP_ID_HASH),
            flags,
            sign_count: 0,
            attested_credential: None,
            extensions: None,
        }
        .encode()
        .unwrap();
        assert_eq!(rebuilt, bytes);
    }
}

struct ClientData {
    json: &'static str,
    ceremony: CeremonyType,
    challenge: &'static str,
    gen_flags: &'static str,
    cross_origin: bool,
    top_origin: Option<&'static str>,
}

const fn cd(
    json: &'static str,
    ceremony: CeremonyType,
    challenge: &'static str,
    gen_flags: &'static str,
    cross_origin: bool,
    top_origin: Option<&'static str>,
) -> ClientData {
    ClientData {
        json,
        ceremony,
        challenge,
        gen_flags,
        cross_origin,
        top_origin,
    }
}

const CREATE: CeremonyType = CeremonyType::Create;
const GET: CeremonyType = CeremonyType::Get;
const TOP: Option<&str> = Some("https://example.com");

const CLIENT_DATA: [ClientData; 12] = [
    cd(
        NONE_ES256_REG_CLIENTDATAJSON,
        CREATE,
        NONE_ES256_REG_CHALLENGE,
        NONE_ES256_REG_CLIENT_DATA_GEN_FLAGS,
        false,
        None,
    ),
    cd(
        NONE_ES256_AUTH_CLIENTDATAJSON,
        GET,
        NONE_ES256_AUTH_CHALLENGE,
        NONE_ES256_AUTH_CLIENT_DATA_GEN_FLAGS,
        false,
        None,
    ),
    cd(
        SELF_ES256_REG_CLIENTDATAJSON,
        CREATE,
        SELF_ES256_REG_CHALLENGE,
        SELF_ES256_REG_CLIENT_DATA_GEN_FLAGS,
        false,
        None,
    ),
    cd(
        SELF_ES256_AUTH_CLIENTDATAJSON,
        GET,
        SELF_ES256_AUTH_CHALLENGE,
        SELF_ES256_AUTH_CLIENT_DATA_GEN_FLAGS,
        false,
        None,
    ),
    cd(
        CROSS_REG_CLIENTDATAJSON,
        CREATE,
        CROSS_REG_CHALLENGE,
        CROSS_REG_CLIENT_DATA_GEN_FLAGS,
        true,
        None,
    ),
    cd(
        CROSS_AUTH_CLIENTDATAJSON,
        GET,
        CROSS_AUTH_CHALLENGE,
        CROSS_AUTH_CLIENT_DATA_GEN_FLAGS,
        true,
        None,
    ),
    cd(
        TOP_REG_CLIENTDATAJSON,
        CREATE,
        TOP_REG_CHALLENGE,
        TOP_REG_CLIENT_DATA_GEN_FLAGS,
        true,
        TOP,
    ),
    cd(
        TOP_AUTH_CLIENTDATAJSON,
        GET,
        TOP_AUTH_CHALLENGE,
        TOP_AUTH_CLIENT_DATA_GEN_FLAGS,
        true,
        TOP,
    ),
    cd(
        LONGID_REG_CLIENTDATAJSON,
        CREATE,
        LONGID_REG_CHALLENGE,
        LONGID_REG_CLIENT_DATA_GEN_FLAGS,
        false,
        None,
    ),
    cd(
        LONGID_AUTH_CLIENTDATAJSON,
        GET,
        LONGID_AUTH_CHALLENGE,
        LONGID_AUTH_CLIENT_DATA_GEN_FLAGS,
        false,
        None,
    ),
    cd(
        PACKED_ED25519_REG_CLIENTDATAJSON,
        CREATE,
        PACKED_ED25519_REG_CHALLENGE,
        PACKED_ED25519_REG_CLIENT_DATA_GEN_FLAGS,
        false,
        None,
    ),
    cd(
        PACKED_ED25519_AUTH_CLIENTDATAJSON,
        GET,
        PACKED_ED25519_AUTH_CHALLENGE,
        PACKED_ED25519_AUTH_CLIENT_DATA_GEN_FLAGS,
        false,
        None,
    ),
];

#[test]
fn client_data_json_is_reproduced() {
    let mut exact = 0;
    for c in &CLIENT_DATA {
        let vector = hex(c.json);
        let challenge = hex(c.challenge);
        let ours = client_data::serialize(
            c.ceremony,
            &challenge,
            "https://example.org",
            c.cross_origin,
            c.top_origin,
        );
        let has_extra_data = hex(c.gen_flags)[0] & 0x01 != 0;
        if has_extra_data {
            // The vector appends an extraData member after the fields we produce.
            let prefix = &ours.as_bytes()[..ours.len() - 1];
            assert!(vector.starts_with(prefix), "{ours}");
            assert_eq!(vector[prefix.len()], b',');
        } else {
            assert_eq!(ours.as_bytes(), vector.as_slice());
            exact += 1;
        }

        let parsed = json::parse(&vector, &json::Limits::default()).unwrap();
        assert_eq!(
            parsed.get("type").and_then(json::Json::as_str),
            Some(c.ceremony.as_str())
        );
        let challenge_b64 = parsed
            .get("challenge")
            .and_then(json::Json::as_str)
            .unwrap();
        assert_eq!(base64url::decode(challenge_b64).unwrap(), challenge);
        assert_eq!(
            parsed.get("origin").and_then(json::Json::as_str),
            Some("https://example.org")
        );
        assert_eq!(
            parsed.get("crossOrigin").and_then(json::Json::as_bool),
            Some(c.cross_origin)
        );
        assert_eq!(
            parsed.get("topOrigin").and_then(json::Json::as_str),
            c.top_origin
        );
        assert_eq!(parsed.to_string().as_bytes(), vector.as_slice());
    }
    assert_eq!(exact, 5);
}

#[test]
fn truncated_vectors_are_rejected() {
    let all = [
        NONE_ES256_REG_ATTESTATIONOBJECT,
        SELF_ES256_REG_ATTESTATIONOBJECT,
        CROSS_REG_ATTESTATIONOBJECT,
        TOP_REG_ATTESTATIONOBJECT,
        LONGID_REG_ATTESTATIONOBJECT,
        PACKED_ED25519_REG_ATTESTATIONOBJECT,
    ];
    for att_hex in all {
        let att = hex(att_hex);
        for len in 0..att.len() {
            assert!(cbor::decode(&att[..len], &Limits::default()).is_err());
            assert!(attestation::parse_webauthn(&att[..len], &Limits::default()).is_err());
        }
        let obj = attestation::parse_webauthn(&att, &Limits::default()).unwrap();
        for len in 0..obj.auth_data.len() {
            assert!(AuthenticatorData::parse(&obj.auth_data[..len], &Limits::default()).is_err());
        }
        let mut trailing = att.clone();
        trailing.push(0x00);
        assert!(attestation::parse_webauthn(&trailing, &Limits::default()).is_err());
    }
    for c in &CLIENT_DATA {
        let vector = hex(c.json);
        for len in 0..vector.len() {
            assert!(json::parse(&vector[..len], &json::Limits::default()).is_err());
        }
    }
}
