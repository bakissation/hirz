#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use crate::envelope::{Engine, handle};
use crate::{ErrorName, Origin, prepare_create, prepare_get, prepare_list, prf_salt};
use hirz_core::{
    AAGUID, ApprovalError, AssertionResponse, CandidateAccount, CoreError, CredProtect,
    GetAssertionRequest, HmacSecretSalts, MakeCredentialRequest, MakeCredentialResponse,
    UvRequirement,
};
use hirz_crypto::sha256;
use hirz_proto::auth_data::{AttestedCredentialData, AuthenticatorData, FLAG_BE, FLAG_UP, FLAG_UV};
use hirz_proto::json::{self, Json, Limits};
use hirz_proto::{attestation, base64url, cbor, cose};

const ORIGIN: &str = "https://login.example.com";
const CRED_ID: [u8; 32] = [0x11; 32];
const OTHER_ID: [u8; 32] = [0x22; 32];

fn j(s: &str) -> Json {
    json::parse(s.as_bytes(), &Limits::default()).unwrap()
}

fn b64(b: &[u8]) -> String {
    base64url::encode(b)
}

fn unb64(v: &Json) -> Vec<u8> {
    base64url::decode(v.as_str().unwrap()).unwrap()
}

fn at<'a>(v: &'a Json, path: &[&str]) -> &'a Json {
    path.iter()
        .fold(v, |v, k| v.get(k).unwrap_or_else(|| panic!("missing {k}")))
}

fn set(v: &mut Json, path: &[&str], new: Option<Json>) {
    let Json::Object(members) = v else {
        panic!("not an object")
    };
    let (head, rest) = path.split_first().unwrap();
    if rest.is_empty() {
        members.retain(|(k, _)| k != head);
        if let Some(n) = new {
            members.push(((*head).to_owned(), n));
        }
        return;
    }
    let child = members
        .iter_mut()
        .find(|(k, _)| k == head)
        .map(|(_, v)| v)
        .unwrap();
    set(child, rest, new);
}

fn create_options() -> Json {
    j(&format!(
        r#"{{
        "rp": {{"id": "example.com", "name": "Example"}},
        "user": {{"id": "{uid}", "name": "alice", "displayName": "Alice"}},
        "challenge": "{ch}",
        "pubKeyCredParams": [
            {{"type": "public-key", "alg": -257}},
            {{"type": "public-key", "alg": -8}},
            {{"type": "other", "alg": -7}},
            {{"type": "public-key", "alg": -7}}
        ],
        "timeout": 60000,
        "excludeCredentials": [
            {{"type": "public-key", "id": "{ex}", "transports": ["internal"]}},
            {{"type": "future-type", "id": "{ex2}"}}
        ],
        "authenticatorSelection": {{
            "residentKey": "required", "requireResidentKey": true,
            "userVerification": "required", "authenticatorAttachment": "platform"
        }},
        "attestation": "direct",
        "attestationFormats": ["packed"],
        "hints": ["client-device", "security-key"],
        "extensions": {{
            "credProps": true,
            "prf": {{"eval": {{"first": "{p1}"}}}},
            "credentialProtectionPolicy": "userVerificationRequired",
            "enforceCredentialProtectionPolicy": true,
            "appidExclude": "https://example.com/appid",
            "unknownExtension": {{"x": 1}}
        }},
        "unknownMember": [1, 2, 3]
    }}"#,
        uid = b64(b"user-0001"),
        ch = b64(&[7u8; 32]),
        ex = b64(&OTHER_ID),
        ex2 = b64(&[0x33; 16]),
        p1 = b64(b"salt input"),
    ))
}

fn get_options() -> Json {
    j(&format!(
        r#"{{
        "challenge": "{ch}",
        "timeout": 30000,
        "rpId": "example.com",
        "allowCredentials": [{{"type": "public-key", "id": "{id}", "transports": ["internal", "hybrid"]}}],
        "userVerification": "discouraged",
        "hints": [],
        "extensions": {{"prf": {{"eval": {{"first": "{p1}", "second": "{p2}"}}}}}}
    }}"#,
        ch = b64(&[9u8; 16]),
        id = b64(&CRED_ID),
        p1 = b64(b"first input"),
        p2 = b64(b"second input"),
    ))
}

fn envelope(kind: &str, origin: &str, options: Json) -> Json {
    Json::Object(vec![
        ("v".to_owned(), Json::from(1u64)),
        ("id".to_owned(), Json::from(7u64)),
        ("type".to_owned(), Json::from(kind)),
        ("origin".to_owned(), Json::from(origin)),
        ("options".to_owned(), options),
    ])
}

#[derive(Debug)]
struct Fake {
    alg: i64,
    fail: Option<CoreError>,
    rp_override: Option<String>,
    cred_id: Vec<u8>,
    hmac_out: Option<Vec<u8>>,
    flags: u8,
    user_handle: Vec<u8>,
    made: Option<(MakeCredentialRequest, String)>,
    got: Option<(GetAssertionRequest, String)>,
    accounts: Vec<CandidateAccount>,
    listed: Option<(String, Vec<Vec<u8>>)>,
}

impl Default for Fake {
    fn default() -> Self {
        Fake {
            alg: -7,
            fail: None,
            rp_override: None,
            cred_id: CRED_ID.to_vec(),
            hmac_out: None,
            flags: FLAG_UP | FLAG_UV | FLAG_BE,
            user_handle: b"user-0001".to_vec(),
            made: None,
            got: None,
            accounts: Vec::new(),
            listed: None,
        }
    }
}

impl Fake {
    fn public_key(&self) -> Vec<u8> {
        if self.alg == -8 {
            cose::encode_ed25519(&[3; 32])
        } else {
            cose::encode_es256(&[1; 32], &[2; 32])
        }
    }

    fn auth_data(&self, rp_id: &str, attested: bool) -> Vec<u8> {
        let rp = self.rp_override.as_deref().unwrap_or(rp_id);
        AuthenticatorData {
            rp_id_hash: sha256(rp.as_bytes()),
            flags: self.flags,
            sign_count: 0,
            attested_credential: attested.then(|| AttestedCredentialData {
                aaguid: AAGUID,
                credential_id: self.cred_id.clone(),
                public_key: self.public_key(),
            }),
            extensions: None,
        }
        .encode()
        .unwrap()
    }
}

impl Engine for Fake {
    fn make_credential(
        &mut self,
        request: &MakeCredentialRequest,
        origin_for_display: &str,
    ) -> Result<MakeCredentialResponse, CoreError> {
        self.made = Some((request.clone(), origin_for_display.to_owned()));
        if let Some(e) = self.fail.clone() {
            return Err(e);
        }
        Ok(MakeCredentialResponse {
            auth_data: self.auth_data(&request.rp.id, true),
            credential_id: self.cred_id.clone(),
            public_key_cose: self.public_key(),
            algorithm: self.alg,
            hmac_secret: request.extensions.hmac_secret,
            resident_key: true,
        })
    }

    fn get_assertion(
        &mut self,
        request: &GetAssertionRequest,
        origin_for_display: &str,
    ) -> Result<AssertionResponse, CoreError> {
        self.got = Some((request.clone(), origin_for_display.to_owned()));
        if let Some(e) = self.fail.clone() {
            return Err(e);
        }
        Ok(AssertionResponse {
            credential_id: self.cred_id.clone(),
            auth_data: self.auth_data(&request.rp_id, false),
            signature: vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
            user_handle: self.user_handle.clone(),
            user: None,
            hmac_secret_output: self.hmac_out.clone(),
        })
    }

    fn user_verification_available(&self) -> bool {
        true
    }

    fn list_accounts(
        &mut self,
        rp_id: &str,
        allow_list: &[Vec<u8>],
    ) -> Result<Vec<CandidateAccount>, CoreError> {
        self.listed = Some((rp_id.to_owned(), allow_list.to_vec()));
        if let Some(e) = self.fail.clone() {
            return Err(e);
        }
        Ok(self.accounts.clone())
    }
}

fn run(req: &Json, engine: &mut Fake) -> Json {
    let reply = handle(req, engine);
    // Every reply must serialize to JSON the strict reader accepts.
    assert_eq!(j(&reply.to_string()), reply);
    reply
}

fn error_of(reply: &Json) -> &str {
    assert_eq!(reply.get("ok"), Some(&Json::Bool(false)), "{reply}");
    reply.get("error").and_then(Json::as_str).unwrap()
}

fn create_error(options: Json) -> String {
    let mut fake = Fake::default();
    let reply = run(&envelope("create", ORIGIN, options), &mut fake);
    error_of(&reply).to_owned()
}

fn get_error(options: Json) -> String {
    let mut fake = Fake::default();
    let reply = run(&envelope("get", ORIGIN, options), &mut fake);
    error_of(&reply).to_owned()
}

#[test]
fn create_round_trip() {
    let mut fake = Fake::default();
    let reply = run(&envelope("create", ORIGIN, create_options()), &mut fake);
    assert_eq!(reply.get("ok"), Some(&Json::Bool(true)), "{reply}");
    assert_eq!(reply.get("v").and_then(Json::as_u64), Some(1));
    assert_eq!(reply.get("id").and_then(Json::as_u64), Some(7));

    let (req, origin) = fake.made.clone().unwrap();
    assert_eq!(origin, ORIGIN);
    assert_eq!(req.rp.id, "example.com");
    assert_eq!(req.rp.name.as_deref(), Some("Example"));
    assert_eq!(req.user.id, b"user-0001");
    assert_eq!(req.user.name.as_deref(), Some("alice"));
    assert_eq!(req.user.display_name.as_deref(), Some("Alice"));
    assert_eq!(req.algorithms, vec![-8, -7]);
    assert_eq!(req.exclude_list, vec![OTHER_ID.to_vec()]);
    assert!(req.resident_key);
    assert_eq!(req.uv, UvRequirement::Required);
    assert!(req.extensions.cred_props);
    assert!(req.extensions.hmac_secret);
    assert_eq!(
        req.extensions.cred_protect,
        Some(CredProtect::UserVerificationRequired)
    );

    let cred = reply.get("credential").unwrap();
    let client_data = unb64(at(cred, &["response", "clientDataJSON"]));
    let expected = format!(
        r#"{{"type":"webauthn.create","challenge":"{}","origin":"{ORIGIN}","crossOrigin":false}}"#,
        b64(&[7u8; 32])
    );
    assert_eq!(String::from_utf8(client_data.clone()).unwrap(), expected);
    assert_eq!(req.client_data_hash, sha256(&client_data));

    assert_eq!(
        cred.get("id").unwrap().as_str(),
        Some(b64(&CRED_ID).as_str())
    );
    assert_eq!(cred.get("rawId"), cred.get("id"));
    assert_eq!(cred.get("type").unwrap().as_str(), Some("public-key"));
    assert_eq!(
        cred.get("authenticatorAttachment").unwrap().as_str(),
        Some("platform")
    );
    let auth_data = unb64(at(cred, &["response", "authenticatorData"]));
    assert_eq!(auth_data, fake.auth_data("example.com", true));
    assert_eq!(at(cred, &["response", "transports"]), &j(r#"["internal"]"#));
    assert_eq!(
        at(cred, &["response", "publicKeyAlgorithm"]).as_i64(),
        Some(-7)
    );
    let spki = unb64(at(cred, &["response", "publicKey"]));
    assert_eq!(spki, hirz_crypto::es256::spki_der(&[1; 32], &[2; 32]));
    assert_eq!(spki.len(), 91);
    let att = unb64(at(cred, &["response", "attestationObject"]));
    let parsed = attestation::parse_webauthn(&att, &cbor::Limits::default()).unwrap();
    assert_eq!(parsed.fmt, "none");
    assert_eq!(parsed.auth_data, auth_data);
    assert_eq!(
        cred.get("clientExtensionResults").unwrap(),
        &j(r#"{"credProps":{"rk":true},"prf":{"enabled":true}}"#)
    );
}

#[test]
fn create_ed25519_and_defaults() {
    let mut options = create_options();
    set(
        &mut options,
        &["pubKeyCredParams"],
        Some(j(r#"[{"type":"public-key","alg":-8}]"#)),
    );
    set(&mut options, &["authenticatorSelection"], None);
    set(&mut options, &["extensions"], None);
    set(&mut options, &["excludeCredentials"], None);
    set(&mut options, &["hints"], None);
    set(&mut options, &["attestation"], None);
    set(&mut options, &["rp", "id"], None);
    let mut fake = Fake {
        alg: -8,
        ..Fake::default()
    };
    let reply = run(&envelope("create", ORIGIN, options), &mut fake);
    let cred = reply.get("credential").unwrap();
    let (req, _) = fake.made.clone().unwrap();
    assert_eq!(req.rp.id, "login.example.com");
    assert_eq!(req.algorithms, vec![-8]);
    assert!(!req.resident_key);
    assert_eq!(req.uv, UvRequirement::Preferred);
    assert_eq!(req.extensions, Default::default());
    assert!(req.exclude_list.is_empty());
    assert_eq!(
        unb64(at(cred, &["response", "publicKey"])),
        hirz_crypto::ed25519::spki_der(&[3; 32])
    );
    assert_eq!(
        at(cred, &["response", "publicKeyAlgorithm"]).as_i64(),
        Some(-8)
    );
    assert_eq!(cred.get("clientExtensionResults").unwrap(), &j("{}"));
}

#[test]
fn empty_params_default_to_es256() {
    let mut options = create_options();
    set(&mut options, &["pubKeyCredParams"], Some(j("[]")));
    let origin = Origin::parse(ORIGIN).unwrap();
    let plan = prepare_create(&options, &origin).unwrap();
    assert_eq!(plan.request.algorithms, vec![-7]);
}

#[test]
fn resident_key_mapping() {
    let origin = Origin::parse(ORIGIN).unwrap();
    for (sel, rk) in [
        (r#"{"residentKey":"required"}"#, true),
        (r#"{"residentKey":"preferred"}"#, true),
        (
            r#"{"residentKey":"discouraged","requireResidentKey":true}"#,
            false,
        ),
        (
            r#"{"residentKey":"unknown","requireResidentKey":true}"#,
            true,
        ),
        (r#"{"requireResidentKey":true}"#, true),
        (r#"{"requireResidentKey":false}"#, false),
        ("{}", false),
    ] {
        let mut options = create_options();
        set(&mut options, &["authenticatorSelection"], Some(j(sel)));
        let plan = prepare_create(&options, &origin).unwrap();
        assert_eq!(plan.request.resident_key, rk, "{sel}");
        assert_eq!(plan.request.uv, UvRequirement::Preferred);
    }
}

#[test]
fn cred_protect_mapping() {
    let origin = Origin::parse(ORIGIN).unwrap();
    for (policy, level) in [
        (
            "userVerificationOptional",
            Some(CredProtect::UserVerificationOptional),
        ),
        (
            "userVerificationOptionalWithCredentialIDList",
            Some(CredProtect::UserVerificationOptionalWithCredentialIdList),
        ),
        (
            "userVerificationRequired",
            Some(CredProtect::UserVerificationRequired),
        ),
        ("somethingElse", None),
    ] {
        let mut options = create_options();
        set(
            &mut options,
            &["extensions", "credentialProtectionPolicy"],
            Some(Json::from(policy)),
        );
        let plan = prepare_create(&options, &origin).unwrap();
        assert_eq!(plan.request.extensions.cred_protect, level, "{policy}");
    }
}

#[test]
fn get_round_trip_with_prf() {
    let mut out = vec![0xaa; 32];
    out.extend_from_slice(&[0xbb; 32]);
    let mut fake = Fake {
        hmac_out: Some(out),
        flags: FLAG_UP | FLAG_BE,
        ..Fake::default()
    };
    let reply = run(&envelope("get", ORIGIN, get_options()), &mut fake);
    assert_eq!(reply.get("ok"), Some(&Json::Bool(true)), "{reply}");
    let (req, origin) = fake.got.clone().unwrap();
    assert_eq!(origin, ORIGIN);
    assert_eq!(req.rp_id, "example.com");
    assert_eq!(req.allow_list, vec![CRED_ID.to_vec()]);
    assert_eq!(req.uv, UvRequirement::Discouraged);
    assert!(req.up);
    assert_eq!(
        req.extensions.hmac_secret,
        Some(HmacSecretSalts {
            salt1: prf_salt(b"first input"),
            salt2: Some(prf_salt(b"second input")),
        })
    );

    let cred = reply.get("credential").unwrap();
    let client_data = unb64(at(cred, &["response", "clientDataJSON"]));
    let expected = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{ORIGIN}","crossOrigin":false}}"#,
        b64(&[9u8; 16])
    );
    assert_eq!(String::from_utf8(client_data.clone()).unwrap(), expected);
    assert_eq!(req.client_data_hash, sha256(&client_data));
    assert_eq!(
        cred.get("id").unwrap().as_str(),
        Some(b64(&CRED_ID).as_str())
    );
    assert_eq!(cred.get("rawId"), cred.get("id"));
    assert_eq!(cred.get("type").unwrap().as_str(), Some("public-key"));
    assert_eq!(
        unb64(at(cred, &["response", "authenticatorData"])),
        fake.auth_data("example.com", false)
    );
    assert_eq!(
        unb64(at(cred, &["response", "signature"])),
        vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]
    );
    assert_eq!(unb64(at(cred, &["response", "userHandle"])), b"user-0001");
    assert_eq!(
        cred.get("clientExtensionResults").unwrap(),
        &j(&format!(
            r#"{{"prf":{{"results":{{"first":"{}","second":"{}"}}}}}}"#,
            b64(&[0xaa; 32]),
            b64(&[0xbb; 32])
        ))
    );
}

#[test]
fn get_discoverable_without_prf() {
    let mut options = get_options();
    set(&mut options, &["allowCredentials"], None);
    set(&mut options, &["extensions"], None);
    set(&mut options, &["rpId"], None);
    set(&mut options, &["userVerification"], None);
    let mut fake = Fake::default();
    let reply = run(&envelope("get", "https://example.com", options), &mut fake);
    let cred = reply.get("credential").unwrap();
    let (req, _) = fake.got.clone().unwrap();
    assert_eq!(req.rp_id, "example.com");
    assert!(req.allow_list.is_empty());
    assert_eq!(req.uv, UvRequirement::Preferred);
    assert_eq!(req.extensions.hmac_secret, None);
    assert_eq!(cred.get("clientExtensionResults").unwrap(), &j("{}"));

    // A discoverable assertion must carry the user handle.
    let mut options = get_options();
    set(&mut options, &["allowCredentials"], None);
    let mut fake = Fake {
        user_handle: Vec::new(),
        ..Fake::default()
    };
    let reply = run(&envelope("get", ORIGIN, options), &mut fake);
    assert_eq!(error_of(&reply), "UnknownError");
}

#[test]
fn prf_single_output_and_missing_output() {
    let mut options = get_options();
    set(
        &mut options,
        &["extensions", "prf"],
        Some(j(&format!(r#"{{"eval":{{"first":"{}"}}}}"#, b64(b"x")))),
    );
    let mut fake = Fake {
        hmac_out: Some(vec![0xcc; 32]),
        ..Fake::default()
    };
    let reply = run(&envelope("get", ORIGIN, options.clone()), &mut fake);
    assert_eq!(
        at(
            reply.get("credential").unwrap(),
            &["clientExtensionResults"]
        ),
        &j(&format!(
            r#"{{"prf":{{"results":{{"first":"{}"}}}}}}"#,
            b64(&[0xcc; 32])
        ))
    );

    let mut fake = Fake::default();
    let reply = run(&envelope("get", ORIGIN, options.clone()), &mut fake);
    assert_eq!(
        at(
            reply.get("credential").unwrap(),
            &["clientExtensionResults"]
        ),
        &j(r#"{"prf":{}}"#)
    );

    let mut fake = Fake {
        hmac_out: Some(vec![0xcc; 64]),
        ..Fake::default()
    };
    let reply = run(&envelope("get", ORIGIN, options), &mut fake);
    assert_eq!(error_of(&reply), "UnknownError");
}

#[test]
fn prf_eval_by_credential() {
    let origin = Origin::parse(ORIGIN).unwrap();
    let mut options = get_options();
    set(
        &mut options,
        &["extensions", "prf", "evalByCredential"],
        Some(j(&format!(
            r#"{{"{}":{{"first":"{}"}}}}"#,
            b64(&CRED_ID),
            b64(b"per credential")
        ))),
    );
    let plan = prepare_get(&options, &origin).unwrap();
    assert_eq!(
        plan.request.extensions.hmac_secret,
        Some(HmacSecretSalts {
            salt1: prf_salt(b"per credential"),
            salt2: None,
        })
    );

    // Two allowed credentials whose effective inputs differ cannot be expressed.
    let mut two = options.clone();
    set(
        &mut two,
        &["allowCredentials"],
        Some(j(&format!(
            r#"[{{"type":"public-key","id":"{}"}},{{"type":"public-key","id":"{}"}}]"#,
            b64(&CRED_ID),
            b64(&OTHER_ID)
        ))),
    );
    assert_eq!(get_error(two.clone()), "NotHandled");

    // ... unless both resolve to the same salts.
    set(
        &mut two,
        &["extensions", "prf", "eval"],
        Some(j(&format!(r#"{{"first":"{}"}}"#, b64(b"per credential")))),
    );
    let plan = prepare_get(&two, &origin).unwrap();
    assert_eq!(
        plan.request.extensions.hmac_secret.unwrap().salt1,
        prf_salt(b"per credential")
    );

    // A key that is not in allowCredentials.
    let mut stray = get_options();
    set(
        &mut stray,
        &["extensions", "prf", "evalByCredential"],
        Some(j(&format!(r#"{{"{}":{{"first":"AA"}}}}"#, b64(&OTHER_ID)))),
    );
    assert_eq!(get_error(stray), "NotHandled");

    // A key that is not base64url.
    let mut bad = get_options();
    set(
        &mut bad,
        &["extensions", "prf", "evalByCredential"],
        Some(j(r#"{"***":{"first":"AA"}}"#)),
    );
    assert_eq!(get_error(bad), "NotHandled");

    // evalByCredential needs allowCredentials.
    let mut no_allow = options;
    set(&mut no_allow, &["allowCredentials"], None);
    assert_eq!(get_error(no_allow), "NotSupportedError");
}

#[test]
fn not_handled_decisions() {
    let cases: Vec<(&[&str], Option<Json>)> = vec![
        (
            &["authenticatorSelection", "authenticatorAttachment"],
            Some(Json::from("cross-platform")),
        ),
        (&["hints"], Some(j(r#"["security-key", "client-device"]"#))),
        (&["hints"], Some(j(r#"["unknown", "hybrid"]"#))),
        (&["attestation"], Some(Json::from("enterprise"))),
        (
            &["pubKeyCredParams"],
            Some(j(
                r#"[{"type":"public-key","alg":-257},{"type":"public-key","alg":-35}]"#,
            )),
        ),
        (
            &["pubKeyCredParams"],
            Some(j(r#"[{"type":"other","alg":-7}]"#)),
        ),
        (&["rp", "id"], Some(Json::from("example.org"))),
        (&["rp", "id"], Some(Json::from("other.login.example.com"))),
        (&["rp", "id"], Some(Json::from("Example.com"))),
        (
            &["extensions", "largeBlob"],
            Some(j(r#"{"support":"required"}"#)),
        ),
    ];
    for (path, value) in cases {
        let mut options = create_options();
        set(&mut options, path, value.clone());
        assert_eq!(create_error(options), "NotHandled", "{path:?} = {value:?}");
    }
    // Accepted variants of the same members.
    let origin = Origin::parse(ORIGIN).unwrap();
    for (path, value) in [
        (&["hints"][..], j(r#"["client-device", "security-key"]"#)),
        (&["hints"][..], j(r#"["something-new"]"#)),
        (&["attestation"][..], Json::from("indirect")),
        (&["attestation"][..], Json::from("none")),
        (
            &["authenticatorSelection", "authenticatorAttachment"][..],
            Json::from("future"),
        ),
        (
            &["extensions", "largeBlob"][..],
            j(r#"{"support":"preferred"}"#),
        ),
    ] {
        let mut options = create_options();
        set(&mut options, path, Some(value));
        prepare_create(&options, &origin).unwrap();
    }

    let mut options = get_options();
    set(&mut options, &["hints"], Some(j(r#"["hybrid"]"#)));
    assert_eq!(get_error(options), "NotHandled");
    let mut options = get_options();
    set(&mut options, &["rpId"], Some(Json::from("example.net")));
    assert_eq!(get_error(options), "NotHandled");
    let mut options = get_options();
    set(
        &mut options,
        &["allowCredentials"],
        Some(j(r#"[{"type":"future-type","id":"AAAA"}]"#)),
    );
    assert_eq!(get_error(options), "NotHandled");
}

#[test]
fn cross_origin_frames_are_not_handled() {
    let mut fake = Fake::default();
    for (top, cross) in [
        (Some(Json::from("https://top.example")), None),
        (Some(Json::from("https://top.example")), Some(false)),
        (None, Some(true)),
        (Some(Json::from(ORIGIN)), Some(true)),
    ] {
        let mut req = envelope("get", ORIGIN, get_options());
        set(&mut req, &["topOrigin"], top);
        set(&mut req, &["crossOrigin"], cross.map(Json::Bool));
        assert_eq!(error_of(&run(&req, &mut fake)), "NotHandled");
    }
    assert!(fake.got.is_none());
    for top in [Json::from(ORIGIN), Json::Null] {
        let mut req = envelope("get", ORIGIN, get_options());
        set(&mut req, &["topOrigin"], Some(top));
        set(&mut req, &["crossOrigin"], Some(Json::Bool(false)));
        assert_eq!(run(&req, &mut fake).get("ok"), Some(&Json::Bool(true)));
    }
}

#[test]
fn origin_and_rp_id_errors() {
    let mut fake = Fake::default();
    for (origin, name) in [
        ("null", "NotAllowedError"),
        ("http://example.com", "SecurityError"),
        ("https://127.0.0.1", "SecurityError"),
        ("https://example.com.", "SecurityError"),
        ("https://EXAMPLE.com", "SecurityError"),
        ("https://example.com/path", "SecurityError"),
        ("chrome-extension://abc", "SecurityError"),
    ] {
        let reply = run(&envelope("create", origin, create_options()), &mut fake);
        assert_eq!(error_of(&reply), name, "{origin}");
    }
    for (rp_id, name) in [
        ("com", "SecurityError"),
        ("", "SecurityError"),
        ("example.com.", "SecurityError"),
        ("127.0.0.1", "SecurityError"),
    ] {
        let mut options = create_options();
        set(&mut options, &["rp", "id"], Some(Json::from(rp_id)));
        assert_eq!(create_error(options), name, "{rp_id:?}");
    }
    let mut req = envelope("create", "https://alice.github.io", create_options());
    set(
        &mut req,
        &["options", "rp", "id"],
        Some(Json::from("github.io")),
    );
    assert_eq!(error_of(&run(&req, &mut fake)), "SecurityError");
    assert!(fake.made.is_none());

    let mut req = envelope("create", "http://localhost:8080", create_options());
    set(&mut req, &["options", "rp", "id"], None);
    assert_eq!(run(&req, &mut fake).get("ok"), Some(&Json::Bool(true)));
    assert_eq!(fake.made.unwrap().0.rp.id, "localhost");
}

#[test]
fn core_errors_map_to_dom_names() {
    for (err, name) in [
        (CoreError::CredentialExcluded, "InvalidStateError"),
        (CoreError::NoCredentials, "NotAllowedError"),
        (CoreError::UvRequiredUnavailable, "NotAllowedError"),
        (
            CoreError::Approval(ApprovalError::Denied),
            "NotAllowedError",
        ),
        (
            CoreError::Approval(ApprovalError::Timeout),
            "NotAllowedError",
        ),
        (
            CoreError::Approval(ApprovalError::Unavailable),
            "NotAllowedError",
        ),
        (
            CoreError::Approval(ApprovalError::Locked),
            "NotAllowedError",
        ),
        (
            CoreError::Approval(ApprovalError::Internal("/secret/path".into())),
            "UnknownError",
        ),
        (CoreError::UnsupportedAlgorithm, "NotSupportedError"),
        (CoreError::InvalidRequest("x"), "UnknownError"),
        (CoreError::Vault("/secret/path".into()), "UnknownError"),
        (CoreError::Crypto("detail".into()), "UnknownError"),
    ] {
        for kind in ["create", "get"] {
            let mut fake = Fake {
                fail: Some(err.clone()),
                ..Fake::default()
            };
            let options = if kind == "create" {
                create_options()
            } else {
                get_options()
            };
            let reply = run(&envelope(kind, ORIGIN, options), &mut fake);
            assert_eq!(error_of(&reply), name, "{err:?}");
            assert!(!reply.to_string().contains("secret"));
        }
    }
    assert_eq!(ErrorName::AbortError.as_str(), "AbortError");
}

#[test]
fn inconsistent_engine_output_is_rejected() {
    let mut fake = Fake {
        rp_override: Some("evil.example".to_owned()),
        ..Fake::default()
    };
    let reply = run(&envelope("create", ORIGIN, create_options()), &mut fake);
    assert_eq!(error_of(&reply), "UnknownError");
    let reply = run(&envelope("get", ORIGIN, get_options()), &mut fake);
    assert_eq!(error_of(&reply), "UnknownError");

    let mut fake = Fake {
        cred_id: OTHER_ID.to_vec(),
        ..Fake::default()
    };
    let reply = run(&envelope("get", ORIGIN, get_options()), &mut fake);
    assert_eq!(error_of(&reply), "UnknownError");

    // UV required by the RP but not set by the engine.
    let mut fake = Fake {
        flags: FLAG_UP | FLAG_BE,
        ..Fake::default()
    };
    let reply = run(&envelope("create", ORIGIN, create_options()), &mut fake);
    assert_eq!(error_of(&reply), "UnknownError");

    // Algorithm the RP did not ask for.
    let mut options = create_options();
    set(
        &mut options,
        &["pubKeyCredParams"],
        Some(j(r#"[{"type":"public-key","alg":-7}]"#)),
    );
    let mut fake = Fake {
        alg: -8,
        ..Fake::default()
    };
    let reply = run(&envelope("create", ORIGIN, options), &mut fake);
    assert_eq!(error_of(&reply), "UnknownError");
}

#[test]
fn hostile_create_options() {
    let long_name = "n".repeat(1025);
    let ok_name = "\u{1f600}".repeat(1024);
    let many: Vec<String> = (0..65)
        .map(|i| format!(r#"{{"type":"public-key","id":"{}"}}"#, b64(&[i as u8; 16])))
        .collect();
    let many = format!("[{}]", many.join(","));
    let cases: Vec<(&[&str], Option<Json>)> = vec![
        (&["challenge"], None),
        (&["challenge"], Some(Json::from(5u64))),
        (&["challenge"], Some(Json::Null)),
        (&["challenge"], Some(Json::from(b64(&[1; 15])))),
        (&["challenge"], Some(Json::from(b64(&[1; 1025])))),
        (&["challenge"], Some(Json::from("AAAAAAAAAAAAAAAAAAAAAA=="))),
        (&["challenge"], Some(Json::from("AAAAAAAAAAAAAAAAAAAA+/AA"))),
        (&["challenge"], Some(Json::from("AAAA AAAAAAAAAAAAAAAAAA"))),
        (&["challenge"], Some(Json::from("A".repeat(100_000)))),
        (&["rp"], None),
        (&["rp"], Some(Json::from("example.com"))),
        (&["rp", "name"], None),
        (&["rp", "name"], Some(Json::from(long_name.as_str()))),
        (&["rp", "id"], Some(Json::Bool(true))),
        (&["user"], None),
        (&["user", "id"], None),
        (&["user", "id"], Some(Json::from(""))),
        (&["user", "id"], Some(Json::from(b64(&[1; 65])))),
        (&["user", "id"], Some(Json::Array(vec![]))),
        (&["user", "name"], None),
        (&["user", "displayName"], None),
        (
            &["user", "displayName"],
            Some(Json::from(long_name.as_str())),
        ),
        (&["pubKeyCredParams"], None),
        (&["pubKeyCredParams"], Some(j("{}"))),
        (
            &["pubKeyCredParams"],
            Some(j(r#"[{"type":"public-key","alg":"-7"}]"#)),
        ),
        (
            &["pubKeyCredParams"],
            Some(j(r#"[{"type":"public-key","alg":-7.5}]"#)),
        ),
        (&["pubKeyCredParams"], Some(j(r#"[{"type":"public-key"}]"#))),
        (&["pubKeyCredParams"], Some(j(r#"[{"alg":-7}]"#))),
        (&["pubKeyCredParams"], Some(j("[1]"))),
        (
            &["pubKeyCredParams"],
            Some(j(&format!(
                "[{}]",
                vec![r#"{"type":"public-key","alg":-7}"#; 65].join(",")
            ))),
        ),
        (&["timeout"], Some(Json::from("60000"))),
        (&["excludeCredentials"], Some(j(&many))),
        (&["excludeCredentials"], Some(j("{}"))),
        (
            &["excludeCredentials"],
            Some(j(r#"[{"type":"public-key","id":""}]"#)),
        ),
        (
            &["excludeCredentials"],
            Some(j(r#"[{"type":"public-key","id":"!!"}]"#)),
        ),
        (
            &["excludeCredentials"],
            Some(j(r#"[{"type":"public-key"}]"#)),
        ),
        (
            &["excludeCredentials"],
            Some(j(&format!(
                r#"[{{"type":"public-key","id":"{}"}}]"#,
                b64(&[0; 1024])
            ))),
        ),
        (
            &["excludeCredentials"],
            Some(j(
                r#"[{"type":"public-key","id":"AAAA","transports":"usb"}]"#,
            )),
        ),
        (&["authenticatorSelection"], Some(j("[]"))),
        (
            &["authenticatorSelection", "requireResidentKey"],
            Some(Json::from("true")),
        ),
        (
            &["authenticatorSelection", "userVerification"],
            Some(Json::from(1u64)),
        ),
        (&["hints"], Some(Json::from("client-device"))),
        (&["hints"], Some(j("[1]"))),
        (&["attestation"], Some(Json::Bool(false))),
        (&["extensions"], Some(j("[]"))),
        (&["extensions", "credProps"], Some(Json::from("yes"))),
        (&["extensions", "prf"], Some(Json::Bool(true))),
        (&["extensions", "prf", "eval"], Some(j("{}"))),
        (&["extensions", "prf", "eval"], Some(j(r#"{"first":"*"}"#))),
        (
            &["extensions", "prf", "eval"],
            Some(j(&format!(r#"{{"first":"{}"}}"#, b64(&[0; 4097])))),
        ),
        (
            &["extensions", "credentialProtectionPolicy"],
            Some(Json::Bool(true)),
        ),
        (
            &["extensions", "enforceCredentialProtectionPolicy"],
            Some(Json::from("true")),
        ),
    ];
    for (path, value) in cases {
        let mut options = create_options();
        set(&mut options, path, value.clone());
        assert_eq!(create_error(options), "NotHandled", "{path:?} = {value:?}");
    }

    let mut options = create_options();
    set(
        &mut options,
        &["extensions", "prf", "evalByCredential"],
        Some(j("{}")),
    );
    assert_eq!(create_error(options), "NotSupportedError");

    let mut options = create_options();
    set(
        &mut options,
        &["user", "displayName"],
        Some(Json::from(ok_name)),
    );
    prepare_create(&options, &Origin::parse(ORIGIN).unwrap()).unwrap();
}

#[test]
fn hostile_get_options() {
    let cases: Vec<(&[&str], Option<Json>)> = vec![
        (&["challenge"], None),
        (&["challenge"], Some(Json::from(""))),
        (&["challenge"], Some(Json::from(b64(&[1; 15])))),
        (&["rpId"], Some(Json::from(1u64))),
        (&["rpId"], Some(Json::from("a".repeat(300)))),
        (&["allowCredentials"], Some(Json::from("x"))),
        (
            &["allowCredentials"],
            Some(j(r#"[{"type":"public-key","id":"A"}]"#)),
        ),
        (&["userVerification"], Some(Json::Null)),
        (
            &["extensions", "prf", "eval", "second"],
            Some(Json::from(3u64)),
        ),
        (&["extensions", "prf", "evalByCredential"], Some(j("[]"))),
        (&["extensions", "appid"], Some(Json::Bool(true))),
    ];
    for (path, value) in cases {
        let mut options = get_options();
        set(&mut options, path, value.clone());
        assert_eq!(get_error(options), "NotHandled", "{path:?} = {value:?}");
    }
}

#[test]
fn envelope_handling() {
    let mut fake = Fake::default();

    let reply = run(&j(r#"{"v":1,"id":3,"type":"hello"}"#), &mut fake);
    assert_eq!(
        reply,
        j(&format!(
            r#"{{"v":1,"id":3,"ok":true,"version":"{}"}}"#,
            env!("CARGO_PKG_VERSION")
        ))
    );

    let reply = run(&j(r#"{"v":1,"id":4,"type":"capabilities"}"#), &mut fake);
    assert_eq!(
        reply,
        j(
            r#"{"v":1,"id":4,"ok":true,"capabilities":{"userVerifyingPlatformAuthenticator":true,"passkeyPlatformAuthenticator":true,"extension:credProps":true,"extension:credProtect":true,"extension:prf":true}}"#
        )
    );

    for (req, id, name) in [
        (
            r#"{"v":2,"id":5,"type":"get"}"#,
            Json::from(5u64),
            "NotHandled",
        ),
        (r#"{"id":5,"type":"get"}"#, Json::from(5u64), "NotHandled"),
        (
            r#"{"v":"1","id":5,"type":"get"}"#,
            Json::from(5u64),
            "NotHandled",
        ),
        (
            r#"{"v":1,"id":5,"type":"explode"}"#,
            Json::from(5u64),
            "UnknownError",
        ),
        (
            r#"{"v":1,"id":5,"type":"cancel"}"#,
            Json::from(5u64),
            "UnknownError",
        ),
        (r#"{"v":1,"id":5}"#, Json::from(5u64), "UnknownError"),
        (r#"{"v":1,"type":"hello"}"#, Json::Null, "UnknownError"),
        (
            r#"{"v":1,"id":-1,"type":"hello"}"#,
            Json::Null,
            "UnknownError",
        ),
        (
            r#"{"v":1,"id":1.5,"type":"hello"}"#,
            Json::Null,
            "UnknownError",
        ),
        (
            r#"{"v":1,"id":9007199254740992,"type":"hello"}"#,
            Json::Null,
            "UnknownError",
        ),
        (r#"[1,2]"#, Json::Null, "UnknownError"),
        (r#""text""#, Json::Null, "UnknownError"),
        (
            r#"{"v":1,"id":5,"type":"get","options":{}}"#,
            Json::from(5u64),
            "UnknownError",
        ),
        (
            r#"{"v":1,"id":5,"type":"get","origin":7,"options":{}}"#,
            Json::from(5u64),
            "UnknownError",
        ),
        (
            r#"{"v":1,"id":5,"type":"get","origin":"https://example.com"}"#,
            Json::from(5u64),
            "UnknownError",
        ),
        (
            r#"{"v":1,"id":5,"type":"get","origin":"https://example.com","options":[]}"#,
            Json::from(5u64),
            "UnknownError",
        ),
        (
            r#"{"v":1,"id":5,"type":"get","origin":"https://example.com","topOrigin":1,"options":{}}"#,
            Json::from(5u64),
            "UnknownError",
        ),
        (
            r#"{"v":1,"id":5,"type":"get","origin":"https://example.com","crossOrigin":"no","options":{}}"#,
            Json::from(5u64),
            "UnknownError",
        ),
    ] {
        let reply = run(&j(req), &mut fake);
        assert_eq!(error_of(&reply), name, "{req}");
        assert_eq!(reply.get("id"), Some(&id), "{req}");
        assert!(reply.get("message").and_then(Json::as_str).is_some());
    }
    assert!(fake.made.is_none() && fake.got.is_none());

    let reply = run(
        &j(r#"{"v":1,"id":9007199254740991,"type":"hello"}"#),
        &mut fake,
    );
    assert_eq!(
        reply.get("id").and_then(Json::as_u64),
        Some(9_007_199_254_740_991)
    );
}

fn account(id: &[u8], name: Option<&str>, display: Option<&str>) -> CandidateAccount {
    CandidateAccount {
        credential_id: id.to_vec(),
        user_name: name.map(str::to_owned),
        user_display_name: display.map(str::to_owned),
    }
}

fn list_options() -> Json {
    j(&format!(
        r#"{{"rpId": "example.com", "allowCredentials": [
            {{"type": "public-key", "id": "{id}", "transports": ["internal"]}},
            {{"type": "future-type", "id": "{other}"}}
        ], "challenge": "ignored", "mediation": "conditional"}}"#,
        id = b64(&CRED_ID),
        other = b64(&OTHER_ID),
    ))
}

#[test]
fn list_round_trip() {
    let mut fake = Fake {
        accounts: vec![
            account(&CRED_ID, Some("alice"), Some("Alice")),
            account(&OTHER_ID, None, None),
        ],
        ..Fake::default()
    };
    let reply = run(&envelope("list", ORIGIN, list_options()), &mut fake);
    let expected = format!(
        r#"{{"v":1,"id":7,"ok":true,"accounts":[
            {{"id":"{a}","name":"alice","displayName":"Alice"}},
            {{"id":"{b}","name":"","displayName":""}}]}}"#,
        a = b64(&CRED_ID),
        b = b64(&OTHER_ID),
    );
    assert_eq!(reply, j(&expected));
    assert_eq!(
        fake.listed,
        Some(("example.com".to_owned(), vec![CRED_ID.to_vec()]))
    );
    assert!(fake.made.is_none() && fake.got.is_none());
}

#[test]
fn list_defaults_and_empty_result() {
    let mut fake = Fake::default();
    let reply = run(&envelope("list", ORIGIN, j("{}")), &mut fake);
    assert_eq!(reply, j(r#"{"v":1,"id":7,"ok":true,"accounts":[]}"#));
    assert_eq!(
        fake.listed,
        Some(("login.example.com".to_owned(), Vec::new()))
    );

    let plan = prepare_list(
        &j(r#"{"rpId":"example.com","allowCredentials":[]}"#),
        &Origin::parse(ORIGIN).unwrap(),
    )
    .unwrap();
    assert_eq!(plan.rp_id, "example.com");
    assert!(plan.allow_list.is_empty());

    let mut req = envelope("list", "http://localhost:8080", j("{}"));
    set(
        &mut req,
        &["topOrigin"],
        Some(Json::from("http://localhost:8080")),
    );
    set(&mut req, &["crossOrigin"], Some(Json::Bool(false)));
    assert_eq!(run(&req, &mut fake).get("ok"), Some(&Json::Bool(true)));
    assert_eq!(fake.listed.unwrap().0, "localhost");
}

#[test]
fn list_caps_names_and_count() {
    let long = "\u{1F511}".repeat(2000);
    let mut fake = Fake {
        accounts: (0..100u8)
            .map(|n| account(&[n; 16], Some(&long), Some("x")))
            .collect(),
        ..Fake::default()
    };
    let reply = run(&envelope("list", ORIGIN, j("{}")), &mut fake);
    let list = reply.get("accounts").and_then(Json::as_array).unwrap();
    assert_eq!(list.len(), 64);
    let name = list[0].get("name").and_then(Json::as_str).unwrap();
    assert_eq!(name.chars().count(), 1024);
    assert!(name.chars().all(|c| c == '\u{1F511}'));
    for a in list {
        let keys: Vec<&str> = a
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, _)| k.as_str())
            .collect();
        assert_eq!(keys, ["id", "name", "displayName"]);
    }
}

#[test]
fn list_origin_and_rp_id_failures() {
    for (origin, rp_id, name) in [
        ("null", None, "NotAllowedError"),
        ("http://example.com", None, "SecurityError"),
        ("https://127.0.0.1", None, "SecurityError"),
        ("https://example.com/path", None, "SecurityError"),
        (ORIGIN, Some("com"), "SecurityError"),
        (ORIGIN, Some(""), "SecurityError"),
        (ORIGIN, Some("example.com."), "SecurityError"),
        (ORIGIN, Some("example.org"), "NotHandled"),
        (ORIGIN, Some("EXAMPLE.com"), "NotHandled"),
        (
            "https://alice.github.io",
            Some("github.io"),
            "SecurityError",
        ),
    ] {
        let mut fake = Fake {
            accounts: vec![account(&CRED_ID, Some("alice"), None)],
            ..Fake::default()
        };
        let mut options = j("{}");
        set(&mut options, &["rpId"], rp_id.map(Json::from));
        let reply = run(&envelope("list", origin, options), &mut fake);
        assert_eq!(error_of(&reply), name, "{origin} {rp_id:?}");
        assert!(reply.get("accounts").is_none());
        assert!(fake.listed.is_none(), "{origin} {rp_id:?}");
    }
}

#[test]
fn list_refuses_frames_and_bad_options() {
    let mut fake = Fake {
        accounts: vec![account(&CRED_ID, Some("alice"), None)],
        ..Fake::default()
    };
    for (top, cross) in [
        (Some(Json::from("https://top.example")), None),
        (None, Some(true)),
        (Some(Json::from(ORIGIN)), Some(true)),
    ] {
        let mut req = envelope("list", ORIGIN, list_options());
        set(&mut req, &["topOrigin"], top);
        set(&mut req, &["crossOrigin"], cross.map(Json::Bool));
        assert_eq!(error_of(&run(&req, &mut fake)), "NotHandled");
    }
    for options in [
        r#"{"rpId": 5}"#,
        r#"{"allowCredentials": {}}"#,
        r#"{"allowCredentials": [{"type": "public-key"}]}"#,
        r#"{"allowCredentials": [{"type": "public-key", "id": "not base64url!"}]}"#,
        r#"{"allowCredentials": [{"type": "public-key", "id": ""}]}"#,
        r#"{"allowCredentials": [{"type": "future-type", "id": "AAAA"}]}"#,
    ] {
        let reply = run(&envelope("list", ORIGIN, j(options)), &mut fake);
        assert_eq!(error_of(&reply), "NotHandled", "{options}");
    }
    let many: Vec<String> = (0..65)
        .map(|n| format!(r#"{{"type":"public-key","id":"{}"}}"#, b64(&[n; 16])))
        .collect();
    let options = j(&format!(r#"{{"allowCredentials":[{}]}}"#, many.join(",")));
    assert_eq!(
        error_of(&run(&envelope("list", ORIGIN, options), &mut fake)),
        "NotHandled"
    );
    let mut req = envelope("list", ORIGIN, j("{}"));
    set(&mut req, &["options"], None);
    assert_eq!(error_of(&run(&req, &mut fake)), "UnknownError");
    assert!(fake.listed.is_none());
}

#[test]
fn list_engine_errors() {
    for (err, name) in [
        (CoreError::Vault("broken".into()), "UnknownError"),
        (CoreError::NoCredentials, "NotAllowedError"),
    ] {
        let mut fake = Fake {
            fail: Some(err),
            ..Fake::default()
        };
        let reply = run(&envelope("list", ORIGIN, list_options()), &mut fake);
        assert_eq!(error_of(&reply), name);
    }
}

/// An engine that keeps the default `list_accounts`.
struct NoList;

impl Engine for NoList {
    fn make_credential(
        &mut self,
        _: &MakeCredentialRequest,
        _: &str,
    ) -> Result<MakeCredentialResponse, CoreError> {
        Err(CoreError::NoCredentials)
    }

    fn get_assertion(
        &mut self,
        _: &GetAssertionRequest,
        _: &str,
    ) -> Result<AssertionResponse, CoreError> {
        Err(CoreError::NoCredentials)
    }

    fn user_verification_available(&self) -> bool {
        false
    }
}

#[test]
fn list_default_is_empty() {
    let reply = handle(&envelope("list", ORIGIN, list_options()), &mut NoList);
    assert_eq!(reply, j(r#"{"v":1,"id":7,"ok":true,"accounts":[]}"#));
}
