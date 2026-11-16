//! Writes the seed corpus to `<out>/<target>/<name>` (default out: `fuzz/seeds`).
//! Seeds are small valid inputs built with the crates' own encoders, plus the W3C WebAuthn
//! test vectors from hirz-proto's test suite. Run through `scripts/fuzz.sh seeds`.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use hirz_crypto::Zeroizing;
use hirz_crypto::kdf::Argon2Params;
use hirz_ctap::hid::{self, BROADCAST_CID, REPORT_SIZE, cmd};
use hirz_fuzz::{cxf, envelope};
use hirz_proto::auth_data::{AuthenticatorData, FLAG_BE, FLAG_UP, FLAG_UV};
use hirz_proto::cbor::{self, MapBuilder, Value};
use hirz_proto::{attestation, base64url, cose};
use hirz_vault::{CredentialRecord, HmacSecretPair};

#[allow(dead_code)]
#[path = "../../crates/hirz-proto/tests/common/vectors.rs"]
mod vectors;

const P256_GX: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
const P256_GY: &str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

fn hex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s
        .bytes()
        .map(|b| (b as char).to_digit(16).expect("hex digit") as u8)
        .collect();
    digits.chunks(2).map(|c| (c[0] << 4) | c[1]).collect()
}

fn arr32(s: &str) -> [u8; 32] {
    hex(s).try_into().expect("32 bytes")
}

struct Out {
    root: PathBuf,
    total: usize,
}

impl Out {
    fn put(&mut self, target: &str, name: &str, data: &[u8]) {
        let dir = self.root.join(target);
        fs::create_dir_all(&dir).expect("create seed dir");
        fs::write(dir.join(name), data).expect("write seed");
        self.total += data.len();
    }
}

fn enc(v: &Value) -> Vec<u8> {
    cbor::encode(v).expect("encode")
}

fn imap(entries: Vec<(i64, Value)>) -> Value {
    Value::Map(entries.into_iter().map(|(k, v)| (Value::int(k), v)).collect())
}

fn descriptor(id: &[u8]) -> Value {
    MapBuilder::new()
        .text("id", id)
        .text("type", "public-key")
        .build()
}

fn make_credential_params(rk: bool) -> Vec<u8> {
    let alg = |a: i64| MapBuilder::new().text("alg", a).text("type", "public-key").build();
    enc(&imap(vec![
        (1, Value::from([0x11u8; 32].as_slice())),
        (
            2,
            MapBuilder::new()
                .text("id", "example.com")
                .text("name", "Example")
                .build(),
        ),
        (
            3,
            MapBuilder::new()
                .text("id", b"user-0001".as_slice())
                .text("name", "alice")
                .text("displayName", "Alice")
                .build(),
        ),
        (4, Value::Array(vec![alg(-7), alg(-8), alg(-257)])),
        (5, Value::Array(vec![descriptor(&[0x22; 32])])),
        (
            6,
            MapBuilder::new()
                .text("credProtect", 2i64)
                .text("hmac-secret", true)
                .build(),
        ),
        (7, MapBuilder::new().text("rk", rk).text("uv", true).build()),
    ]))
}

fn get_assertion_params(with_hmac: bool, protocol: u64) -> Vec<u8> {
    let mut e = vec![
        (1, Value::from("example.com")),
        (2, Value::from([0x22u8; 32].as_slice())),
        (3, Value::Array(vec![descriptor(&[0x11; 32])])),
        (5, MapBuilder::new().text("up", true).text("uv", false).build()),
    ];
    if with_hmac {
        let (enc_len, auth_len) = if protocol == 2 { (48, 32) } else { (32, 16) };
        let input = imap(vec![
            (1, cose::key_agreement_value(&arr32(P256_GX), &arr32(P256_GY))),
            (2, Value::Bytes(vec![0x33; enc_len])),
            (3, Value::Bytes(vec![0x44; auth_len])),
            (4, Value::Unsigned(protocol)),
        ]);
        e.push((4, MapBuilder::new().text("hmac-secret", input).build()));
    }
    enc(&imap(e))
}

fn b64(b: &[u8]) -> String {
    base64url::encode(b)
}

fn create_options() -> String {
    format!(
        concat!(
            r#"{{"rp":{{"id":"example.com","name":"Example"}},"#,
            r#""user":{{"id":"{uid}","name":"alice","displayName":"Alice"}},"#,
            r#""challenge":"{ch}","#,
            r#""pubKeyCredParams":[{{"type":"public-key","alg":-8}},{{"type":"public-key","alg":-7}}],"#,
            r#""timeout":60000,"excludeCredentials":[{{"type":"public-key","id":"{ex}"}}],"#,
            r#""authenticatorSelection":{{"residentKey":"required","userVerification":"required"}},"#,
            r#""attestation":"none","hints":[],"#,
            r#""extensions":{{"credProps":true,"prf":{{"eval":{{"first":"{p1}"}}}},"#,
            r#""credentialProtectionPolicy":"userVerificationRequired"}}}}"#
        ),
        uid = b64(b"user-0001"),
        ch = b64(&[7u8; 32]),
        ex = b64(&[0x22; 32]),
        p1 = b64(b"salt input"),
    )
}

fn get_options(discoverable: bool) -> String {
    let allow = if discoverable {
        String::new()
    } else {
        format!(
            r#""allowCredentials":[{{"type":"public-key","id":"{}","transports":["internal"]}}],"#,
            b64(&[0x11; 32])
        )
    };
    format!(
        concat!(
            r#"{{"challenge":"{ch}","timeout":30000,"rpId":"example.com",{allow}"#,
            r#""userVerification":"preferred","#,
            r#""extensions":{{"prf":{{"eval":{{"first":"{p1}","second":"{p2}"}}}}}}}}"#
        ),
        ch = b64(&[9u8; 16]),
        allow = allow,
        p1 = b64(b"first input"),
        p2 = b64(b"second input"),
    )
}

fn envelope(kind: &str, options: &str) -> String {
    format!(
        r#"{{"v":1,"id":7,"type":"{kind}","origin":"https://login.example.com","topOrigin":"https://login.example.com","crossOrigin":false,"options":{options}}}"#
    )
}

fn reports(cid: u32, command: u8, payload: &[u8]) -> Vec<[u8; REPORT_SIZE]> {
    hid::build_message(cid, command, payload).expect("message")
}

fn script(steps: &[(u8, [u8; REPORT_SIZE])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (ctl, report) in steps {
        out.push(*ctl);
        out.extend_from_slice(report);
    }
    out
}

fn proto_seeds(o: &mut Out) {
    let attestations = [
        ("none_es256", vectors::NONE_ES256_REG_ATTESTATIONOBJECT),
        ("self_es256", vectors::SELF_ES256_REG_ATTESTATIONOBJECT),
        ("cross_origin", vectors::CROSS_REG_ATTESTATIONOBJECT),
        ("top_origin", vectors::TOP_REG_ATTESTATIONOBJECT),
    ];
    let authenticator_data = [
        ("none_es256", vectors::NONE_ES256_AUTH_AUTHENTICATORDATA),
        ("self_es256", vectors::SELF_ES256_AUTH_AUTHENTICATORDATA),
        ("cross_origin", vectors::CROSS_AUTH_AUTHENTICATORDATA),
    ];
    let client_data = [
        ("reg", vectors::NONE_ES256_REG_CLIENTDATAJSON),
        ("auth", vectors::NONE_ES256_AUTH_CLIENTDATAJSON),
        ("top", vectors::TOP_REG_CLIENTDATAJSON),
    ];

    let small: [(&str, &str); 12] = [
        ("uint", "1903e8"),
        ("nint", "3903e7"),
        ("u64max", "1bffffffffffffffff"),
        ("bytes", "4401020304"),
        ("text", "6449455446"),
        ("utf8", "64f0908591"),
        ("array", "8301820203820405"),
        ("map", "a201020304"),
        ("text_map", "a26161016162820203"),
        ("simple", "83f4f5f6"),
        ("nested", "a1018182a10102f6"),
        ("empty", "a0"),
    ];
    for target in ["cbor_strict", "cbor_lenient"] {
        for (name, h) in small {
            o.put(target, name, &hex(h));
        }
        for (name, h) in attestations {
            o.put(target, &format!("att_{name}"), &hex(h));
        }
        o.put(target, "get_info", &hirz_ctap::ctap2::get_info_response()[1..]);
    }
    o.put("cbor_lenient", "unsorted_map", &hex("a2616201616102"));
    o.put("cbor_lenient", "long_form_uint", &hex("1801"));
    o.put("cbor_lenient", "int_after_text", &hex("a26161010102"));

    let es = cose::encode_es256(&arr32(P256_GX), &arr32(P256_GY));
    o.put("cose_key", "es256", &es);
    o.put("cose_key", "ed25519", &cose::encode_ed25519(&[3; 32]));
    o.put(
        "cose_key",
        "key_agreement",
        &enc(&cose::key_agreement_value(&arr32(P256_GX), &arr32(P256_GY))),
    );

    for (name, h) in authenticator_data {
        o.put("auth_data", name, &hex(h));
    }
    let with_ext = AuthenticatorData {
        rp_id_hash: [0x5a; 32],
        flags: FLAG_UP | FLAG_UV | FLAG_BE,
        sign_count: 7,
        attested_credential: None,
        extensions: Some(MapBuilder::new().text("credProtect", 2i64).build()),
    }
    .encode()
    .expect("authData");
    o.put("auth_data", "extensions", &with_ext);
    for (name, h) in attestations {
        let att = attestation::parse_webauthn(&hex(h), &cbor::Limits::default()).expect("att");
        o.put("auth_data", &format!("attested_{name}"), &att.auth_data);
        o.put("attestation", &format!("webauthn_{name}"), &hex(h));
        if name == "none_es256" {
            o.put("attestation", "ctap_none", &attestation::none_ctap(&att.auth_data));
        }
    }

    for (name, h) in client_data {
        o.put("json", &format!("client_data_{name}"), &hex(h));
    }
    o.put("json", "create_options", create_options().as_bytes());
    o.put("json", "get_options", get_options(false).as_bytes());
    o.put(
        "json",
        "numbers_and_escapes",
        br#"[0,-0,1.5e3,-2.25E-2,9007199254740993,"\u00e9\ud83d\ude00\n\"",true,false,null,{}]"#,
    );

    o.put("base64url", "empty", b"");
    o.put("base64url", "one", b"AQ");
    o.put("base64url", "two", b"AQI");
    o.put("base64url", "three", b"AQID");
    o.put("base64url", "alphabet", b"-_09azAZ");

    let mut cd = vec![0x00, 32];
    cd.extend_from_slice(&[7; 32]);
    cd.extend_from_slice(b"https://example.com");
    o.put("client_data", "create", &cd);
    let mut cd = vec![0x07, 16];
    cd.extend_from_slice(&[9; 16]);
    cd.extend_from_slice("https://a.example.com\nhttps://example.org/\u{e9}\"\\".as_bytes());
    o.put("client_data", "get_top_origin", &cd);
}

fn ctap_seeds(o: &mut Out) {
    let mut p = 1u32.to_be_bytes().to_vec();
    p.push(cmd::CBOR);
    p.push(0x04);
    o.put("ctaphid_packet", "cbor_get_info", &p);
    let mut p = 0x0102_0304u32.to_be_bytes().to_vec();
    p.push(cmd::PING);
    p.extend_from_slice(&[0xa5; 200]);
    o.put("ctaphid_packet", "ping_multi", &p);
    o.put(
        "ctaphid_packet",
        "init_report",
        &reports(BROADCAST_CID, cmd::INIT, &[1, 2, 3, 4, 5, 6, 7, 8])[0],
    );

    let init = reports(BROADCAST_CID, cmd::INIT, &[1, 2, 3, 4, 5, 6, 7, 8])[0];
    let get_info = reports(1, cmd::CBOR, &[hirz_ctap::ctap2::command::GET_INFO])[0];
    let ping = reports(1, cmd::PING, &[0x5a; 100]);
    let wink = reports(1, cmd::WINK, &[])[0];
    let cancel = reports(1, cmd::CANCEL, &[])[0];
    let mut mc = vec![hirz_ctap::ctap2::command::MAKE_CREDENTIAL];
    mc.extend_from_slice(&make_credential_params(true));
    let mc = reports(1, cmd::CBOR, &mc);

    o.put(
        "ctaphid_transport",
        "init_get_info_finish",
        &script(&[(0x00, init), (0x00, get_info), (0x41, wink)]),
    );
    let mut steps = vec![(0x00, init)];
    steps.extend(ping.iter().map(|r| (0x01, *r)));
    o.put("ctaphid_transport", "ping_multi_packet", &script(&steps));
    let mut steps = vec![(0x00, init)];
    steps.extend(mc.iter().map(|r| (0x02, *r)));
    steps.push((0x3f, wink));
    steps.push((0x00, cancel));
    o.put("ctaphid_transport", "make_credential_cancel", &script(&steps));
    o.put(
        "ctaphid_transport",
        "processing_timeout",
        &script(&[(0x00, init), (0x00, get_info), (0xa0, wink), (0x20, init)]),
    );

    o.put("ctap2_make_credential", "full", &make_credential_params(true));
    o.put("ctap2_make_credential", "no_rk", &make_credential_params(false));
    o.put("ctap2_get_assertion", "allow_list", &get_assertion_params(false, 1));
    o.put("ctap2_get_assertion", "hmac_v1", &get_assertion_params(true, 1));
    o.put("ctap2_get_assertion", "hmac_v2", &get_assertion_params(true, 2));
    let key_agreement = enc(&imap(vec![(1, Value::Unsigned(2)), (2, Value::Unsigned(2))]));
    o.put("ctap2_client_pin", "get_key_agreement", &key_agreement);
    o.put("ctap2_client_pin", "get_retries", &enc(&imap(vec![(2, Value::Unsigned(1))])));

    let with_cmd = |c: u8, body: &[u8]| {
        let mut v = vec![c];
        v.extend_from_slice(body);
        v
    };
    use hirz_ctap::ctap2::command as c;
    o.put("ctap2_handler", "get_info", &[c::GET_INFO]);
    o.put("ctap2_handler", "selection", &[c::SELECTION]);
    o.put(
        "ctap2_handler",
        "make_credential",
        &with_cmd(c::MAKE_CREDENTIAL, &make_credential_params(true)),
    );
    o.put(
        "ctap2_handler",
        "get_assertion",
        &with_cmd(c::GET_ASSERTION, &get_assertion_params(false, 1)),
    );
    o.put(
        "ctap2_handler",
        "get_assertion_hmac",
        &with_cmd(c::GET_ASSERTION, &get_assertion_params(true, 2)),
    );
    o.put("ctap2_handler", "client_pin", &with_cmd(c::CLIENT_PIN, &key_agreement));
}

fn webauthn_seeds(o: &mut Out) {
    for (name, text) in [
        ("plain", "https://login.example.com\nexample.com"),
        ("localhost", "http://localhost:8080\nlocalhost"),
        ("idn", "https://xn--bcher-kva.example\nxn--bcher-kva.example"),
        ("psl_parent", "https://a.b.example.co.uk\nexample.co.uk"),
        ("psl_suffix", "https://example.com:8443\nco.uk"),
    ] {
        o.put("webauthn_origin", name, text.as_bytes());
    }
    let mut v = vec![0x00];
    v.extend_from_slice(create_options().as_bytes());
    o.put("webauthn_prepare", "create", &v);
    let mut v = vec![0x01];
    v.extend_from_slice(get_options(false).as_bytes());
    o.put("webauthn_prepare", "get_allow_list", &v);
    let mut v = vec![0x01];
    v.extend_from_slice(get_options(true).as_bytes());
    o.put("webauthn_prepare", "get_discoverable", &v);

    o.put("webauthn_handle", "create", envelope("create", &create_options()).as_bytes());
    o.put("webauthn_handle", "get", envelope("get", &get_options(true)).as_bytes());
    o.put("webauthn_handle", "hello", br#"{"v":1,"id":1,"type":"hello"}"#);
    o.put(
        "webauthn_handle",
        "capabilities",
        br#"{"v":1,"id":2,"type":"capabilities"}"#,
    );
}

fn vault_and_uv_seeds(o: &mut Out) {
    o.put(
        "uv_config",
        "full",
        b"# approval\nmethods = polkit, fingerprint, pin\nclick_to_allow = example.com, other.example\ntimeout = 120\nprompts_per_minute = 5\n",
    );
    o.put("uv_config", "crlf", b"methods = pin\r\ntimeout = 600\r\n");

    let verifier = format!(
        "hirz-pin 1\nkdf argon2id 65536 3 4\nsalt {}\nhash {}\nfailures 2\n",
        "ab".repeat(16),
        "cd".repeat(32)
    );
    o.put("uv_pin_verifier", "valid", verifier.as_bytes());

    let tool: [(&str, u8, &[u8]); 7] = [
        (
            "verify_match",
            0,
            b"Using device /net/reactivated/Fprint/Device/0\nVerify result: verify-match (done)\n",
        ),
        (
            "verify_retry",
            1,
            b"Verify result: verify-swipe-too-short (not done)\nVerify result: verify-no-match (done)\n",
        ),
        (
            "list",
            0,
            b"Fingerprints for user alice on Example reader (press):\n - #0: right-index-finger\n",
        ),
        (
            "stat",
            0,
            b"4242 (a (b) c) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10\n",
        ),
        ("status", 0, b"Name:\tbash\nUmask:\t0022\nUid:\t1000\t1000\t1000\t1000\n"),
        (
            "passwd",
            250,
            b"root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000:Alice:/u/alice:/bin/sh\n",
        ),
        ("killed", 0xff, b"Verify result: verify-match (done)\n"),
    ];
    for (name, code, text) in tool {
        let mut v = vec![code];
        v.extend_from_slice(text);
        o.put("uv_tool_output", name, &v);
    }
}

fn tlv(version: u8, fields: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = vec![version];
    for (tag, value) in fields {
        out.push(*tag);
        out.extend_from_slice(
            &u16::try_from(value.len())
                .expect("short field")
                .to_be_bytes(),
        );
        out.extend_from_slice(value);
    }
    out
}

fn record_body(version: u8, credential_id: &[u8], full: bool) -> Vec<u8> {
    let alg = (-7i64).to_be_bytes();
    let created = 1_700_000_000u64.to_be_bytes();
    let key = [0x30u8; 40];
    let hmac = [0x44u8; 64];
    let discoverable = [u8::from(full)];
    let mut f: Vec<(u8, &[u8])> = vec![(0x01, credential_id), (0x02, b"example.com")];
    if full {
        f.push((0x03, b"Example"));
    }
    f.push((0x04, b"user-0001"));
    if full {
        f.push((0x05, b"alice"));
        f.push((0x06, b"Alice"));
    }
    f.push((0x07, &alg));
    f.push((0x08, &key));
    f.push((0x09, &created));
    if full {
        f.push((0x0a, &[2]));
        f.push((0x0b, &hmac));
    }
    f.push((0x0c, &discoverable));
    f.push((0x0d, &[1]));
    if full {
        f.push((0x40, b"ignored"));
    }
    tlv(version, &f)
}

/// The device id the vault derives from a signing key (docs/vault-format.md, 5.2).
fn device_id_for(signing_public: &[u8; 32]) -> [u8; 16] {
    let mut input = b"hirz device id v1\0".to_vec();
    input.extend_from_slice(&32u32.to_be_bytes());
    input.extend_from_slice(signing_public);
    let h = hirz_crypto::sha256(&input);
    let mut out = [0u8; 16];
    out.copy_from_slice(&h[..16]);
    out
}

fn event(kind: u8, payload: &[u8]) -> Vec<u8> {
    let lamport = 7u64.to_be_bytes();
    let mut b = tlv(
        1,
        &[
            (0x01, &[kind]),
            (0x02, &[0x10; 16]),
            (0x03, &lamport),
            (0x04, payload),
        ],
    );
    b.push(0x7f);
    b.extend_from_slice(&32u16.to_be_bytes());
    b.extend_from_slice(&[0x55; 32]);
    b
}

fn nmh_and_vault_record_seeds(o: &mut Out) {
    let mut stream = vec![0u8, 0];
    for msg in [
        &br#"{"type":"hello","id":1}"#[..],
        br#"{"type":"cancel","id":1}"#,
    ] {
        stream.extend_from_slice(&u32::try_from(msg.len()).expect("short").to_ne_bytes());
        stream.extend_from_slice(msg);
    }
    o.put("nmh_framing", "two", &stream);
    let mut chunked = stream.clone();
    chunked[0] = 3;
    chunked[1] = 2;
    o.put("nmh_framing", "chunked", &chunked);
    o.put("nmh_framing", "too_large", &[0, 0, 0xff, 0xff, 0xff, 0x7f]);

    let full = record_body(2, &[0x11; 48], true);
    let minimal = record_body(2, &[0x22; 1], false);
    let v1 = record_body(1, &[0x33; 32], false);
    o.put("vault_record", "full", &full);
    o.put("vault_record", "minimal", &minimal);
    o.put("vault_record", "v1", &v1);

    let created = 1_700_000_000u64.to_be_bytes();
    o.put("vault_event", "put", &event(1, &full));
    o.put(
        "vault_event",
        "tombstone",
        &event(2, &tlv(2, &[(0x01, &[0x11; 48])])),
    );
    o.put(
        "vault_event",
        "tombstone_v1",
        &event(2, &tlv(1, &[(0x01, &[0x33; 32])])),
    );
    o.put(
        "vault_event",
        "device_added",
        &event(
            3,
            &tlv(
                1,
                &[
                    (0x01, &device_id_for(&[0x77; 32])),
                    (0x02, b"laptop"),
                    (0x03, &[0x66; 32]),
                    (0x04, &created),
                    (0x05, &[0x77; 32]),
                    (0x06, &[0; 16]),
                    (0x07, &[0x88; 64]),
                ],
            ),
        ),
    );
    o.put(
        "vault_event",
        "device_removed",
        &event(4, &tlv(1, &[(0x01, &[0x10; 16]), (0x02, &created)])),
    );
    o.put(
        "vault_event",
        "backup_confirmed",
        &event(5, &tlv(1, &[(0x01, &created)])),
    );
}

/// PKCS#8 P-256 key with private scalar 1 (public key = generator), so seeds are stable.
fn p256_scalar_one_pkcs8() -> Vec<u8> {
    let mut k = hex(
        "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420",
    );
    k.extend_from_slice(&[0; 31]);
    k.push(1);
    k.extend_from_slice(&hex("a144034200"));
    k.push(0x04);
    k.extend_from_slice(&hex(P256_GX));
    k.extend_from_slice(&hex(P256_GY));
    assert!(hirz_crypto::es256::public_key(&k).is_ok(), "seed key parses");
    k
}

fn import_seeds(o: &mut Out) {
    let key = p256_scalar_one_pkcs8();
    let b64 = base64url::encode(&key);
    let entry = |id: &str, rp: &str, curve: &str| {
        format!(
            r#"{{"credentialId": "{id}", "keyType": "public-key", "keyAlgorithm": "ECDSA",
"keyCurve": "{curve}", "keyValue": "{b64}", "rpId": "{rp}", "userHandle": "dXNlci0x",
"userName": "alice", "counter": "0", "rpName": "Example", "userDisplayName": "Alice",
"discoverable": "true", "creationDate": "2024-02-29T12:00:00.000Z"}}"#
        )
    };
    let plain = format!(
        r#"{{"encrypted": false, "folders": [], "items": [
{{"id": "1", "type": 1, "name": "x", "login": {{"username": "alice", "password": "pw",
"fido2Credentials": [{}, {}]}}}},
{{"id": "2", "type": 2, "name": "note", "notes": "n", "secureNote": {{"type": 0}}}},
{{"id": "3", "type": 1, "name": "y", "login": {{"fido2Credentials": [{}]}}}}]}}"#,
        entry("6c7e3b2a-0d4f-4a8e-9b1c-2f3e4d5a6b7c", "example.com", "P-256"),
        entry("b64.AQIDBA", "acme.example", "P-256"),
        entry("b64.BQYH", "example.org", "P-384"),
    );
    o.put("import_bitwarden", "plain", plain.as_bytes());
    let enc = "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|\
               AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    for (name, kdf) in [
        ("pbkdf2", r#""kdfType": 0, "kdfIterations": 600000"#),
        (
            "argon2id",
            r#""kdfType": 1, "kdfIterations": 3, "kdfMemory": 64, "kdfParallelism": 4"#,
        ),
    ] {
        let doc = format!(
            r#"{{"encrypted": true, "passwordProtected": true, "salt": "c2FsdA==", {kdf},
"encKeyValidation_DO_NOT_EDIT": "{enc}", "data": "{enc}"}}"#
        );
        o.put("import_bitwarden", name, doc.as_bytes());
    }
    o.put(
        "import_bitwarden",
        "account_restricted",
        br#"{"encrypted": true, "encKeyValidation_DO_NOT_EDIT": "2.a|b|c", "items": []}"#,
    );

    let mut std_b64 = b64.replace('-', "+").replace('_', "/");
    while std_b64.len() % 4 != 0 {
        std_b64.push('=');
    }
    let body: Vec<&str> = std_b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).expect("ascii"))
        .collect();
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\\n{}\\n-----END PRIVATE KEY-----\\n",
        body.join("\\n")
    );
    let file = format!(
        "{{\n    \"credentialId\": \"AQIDBAUGBwgJCgsMDQ4PEA\",\n    \"privateKey\": \"{pem}\",\n    \
         \"relyingParty\": \"example.com\",\n    \"url\": \"https://example.com\",\n    \
         \"userHandle\": \"dXNlci0x\",\n    \"username\": \"alice\"\n}}\n"
    );
    o.put("import_keepassxc", "es256", file.as_bytes());
}

/// Seeds for the targets of hirz-cli that read files: `hex`, `cxf_parse` and `envelope_open`.
fn file_format_seeds(o: &mut Out) {
    for (name, text) in [
        ("empty", ""),
        ("one_byte", "0a"),
        ("sixteen_bytes", "000102030405060708090a0b0c0d0e0f"),
        ("uppercase", "00FF"),
        ("odd_length", "abc"),
        ("not_hex", "zz"),
    ] {
        o.put("hex", name, text.as_bytes());
    }
    o.put("hex", "binary", &[0x00, 0x01, 0x80, 0xfe, 0xff]);

    let record = |id: u8, rp: &str, hmac: bool| CredentialRecord {
        credential_id: vec![id; 32],
        rp_id: rp.to_owned(),
        rp_name: (id == 1).then(|| "Example".to_owned()),
        user_id: vec![id; 16],
        user_name: Some("alice".to_owned()),
        user_display_name: (id == 1).then(|| "Alice".to_owned()),
        algorithm: hirz_core::COSE_ALG_ES256,
        private_key_pkcs8: Zeroizing::new(p256_scalar_one_pkcs8()),
        created_at: 1_700_000_000,
        cred_protect: (id == 1).then_some(2),
        hmac_secret: hmac.then(|| HmacSecretPair {
            cred_random_with_uv: Zeroizing::new([0x11; 32]),
            cred_random_without_uv: Zeroizing::new([0x22; 32]),
        }),
        discoverable: id != 2,
        backup_eligible: true,
    };
    let records = [
        record(1, "example.com", true),
        record(2, "ssh:Work Key", false),
        record(3, "io.example.app", false),
    ];
    let refs: Vec<&CredentialRecord> = records.iter().collect();
    let export = cxf::export_json(&refs, 1_700_000_000, &[7; 16]).expect("export");
    o.put("cxf_parse", "hirz_export", &export);
    o.put(
        "cxf_parse",
        "provider_export",
        include_bytes!("../../crates/hirz-cli/tests/fixtures/provider-export.json"),
    );
    o.put(
        "cxf_parse",
        "no_accounts",
        br#"{"version": {"major": 1, "minor": 0}, "accounts": []}"#,
    );
    o.put(
        "cxf_parse",
        "newer_version",
        br#"{"version": {"major": 2, "minor": 0}, "accounts": []}"#,
    );

    const FAST: Argon2Params = Argon2Params {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };
    let sealed = envelope::seal(
        b"fuzz passphrase",
        br#"{"version": {"major": 1, "minor": 0}, "accounts": []}"#,
        FAST,
    )
    .expect("seal");
    o.put("envelope_open", "sealed", &sealed);
    let mut tampered = sealed.clone();
    if let Some(last) = tampered.last_mut() {
        *last ^= 1;
    }
    o.put("envelope_open", "sealed_tampered", &tampered);
    o.put("envelope_open", "magic_only", envelope::MAGIC);
    let header = |limit: Argon2Params| {
        let mut h = envelope::MAGIC.to_vec();
        h.extend_from_slice(&[1, 1]);
        h.extend_from_slice(&limit.m_cost_kib.to_be_bytes());
        h.extend_from_slice(&limit.t_cost.to_be_bytes());
        h.extend_from_slice(&limit.p_cost.to_be_bytes());
        h.extend_from_slice(&[0x5a; 16]);
        h.extend_from_slice(&[0xa5; 12 + 16 + 8]);
        h
    };
    let limit = envelope::IMPORT_LIMIT;
    o.put("envelope_open", "header_at_the_limit", &header(limit));
    o.put(
        "envelope_open",
        "header_over_the_limit",
        &header(Argon2Params {
            m_cost_kib: limit.m_cost_kib + 1,
            ..limit
        }),
    );
    o.put("envelope_open", "header_cheap", &header(FAST));
    let mut round_trip = vec![0u8];
    round_trip.extend_from_slice(br#"{"accounts": []}"#);
    o.put("envelope_open", "seal_and_open", &round_trip);
}

fn main() {
    let root = std::env::args_os()
        .nth(1)
        .map_or_else(|| Path::new("fuzz").join("seeds"), PathBuf::from);
    let mut out = Out { root, total: 0 };
    proto_seeds(&mut out);
    ctap_seeds(&mut out);
    webauthn_seeds(&mut out);
    vault_and_uv_seeds(&mut out);
    nmh_and_vault_record_seeds(&mut out);
    import_seeds(&mut out);
    file_format_seeds(&mut out);
    println!("wrote {} bytes of seeds to {}", out.total, out.root.display());
}
