//! Writes the seed corpus to `<out>/<target>/<name>` (default out: `fuzz/seeds`).
//! Seeds are small valid inputs built with the crates' own encoders, plus the W3C WebAuthn
//! test vectors from hirz-proto's test suite. Run through `scripts/fuzz.sh seeds`.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use hirz_ctap::hid::{self, BROADCAST_CID, REPORT_SIZE, cmd};
use hirz_proto::auth_data::{AuthenticatorData, FLAG_BE, FLAG_UP, FLAG_UV};
use hirz_proto::cbor::{self, MapBuilder, Value};
use hirz_proto::{attestation, base64url, cose};

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
    for flag in [0u8, 1] {
        let mut b = b"HIRZ".to_vec();
        b.extend_from_slice(&[6, 1]);
        b.extend_from_slice(&[0x10; 16]);
        b.push(flag);
        b.extend_from_slice(&[0x20; 16]);
        for v in [65_536u32, 3, 4] {
            b.extend_from_slice(&v.to_be_bytes());
        }
        b.extend_from_slice(&[0x30; 64]);
        o.put("vault_backup", &format!("flag{flag}"), &b);
    }

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

fn main() {
    let root = std::env::args_os()
        .nth(1)
        .map_or_else(|| Path::new("fuzz").join("seeds"), PathBuf::from);
    let mut out = Out { root, total: 0 };
    proto_seeds(&mut out);
    ctap_seeds(&mut out);
    webauthn_seeds(&mut out);
    vault_and_uv_seeds(&mut out);
    println!("wrote {} bytes of seeds to {}", out.total, out.root.display());
}
