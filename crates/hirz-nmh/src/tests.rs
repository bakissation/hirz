#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

//! The whole host loop (reader thread, queue, cancel, engine, vault) driven over OS pipes
//! with framed JSON, as Firefox drives the binary. The approvers here exist only in test
//! builds.

use super::*;
use hirz_core::{Approval, ApprovalContext, ApprovalError, Ceremony};
use hirz_proto::auth_data::{AuthenticatorData, FLAG_AT, FLAG_BE, FLAG_UP, FLAG_UV};
use hirz_proto::{attestation, base64url, cbor, cose};
use hirz_vault::Vault;
use std::ffi::OsString;
use std::io::{PipeReader, PipeWriter, pipe};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread::JoinHandle;

const ORIGIN: &str = "https://example.com";

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> TempDir {
        let mut r = [0u8; 8];
        hirz_crypto::random_fill(&mut r).unwrap();
        let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
        let p = std::env::temp_dir().join(format!("hirz-nmh-test-{hex}"));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn settings(vault: &Path, state: &Path) -> Settings {
    let (vault, state) = (vault.as_os_str().to_owned(), state.as_os_str().to_owned());
    Settings::from_vars(move |k| match k {
        session::VAULT_ENV => Some(vault.clone()),
        session::STATE_ENV => Some(state.clone()),
        "HOME" => Some(OsString::from("/nonexistent")),
        _ => None,
    })
}

/// Approves with presence and verification. With a gate, each approval first waits for a
/// message on the gate, so a test can act while the "prompt" is open.
struct TestApprover {
    gate: Option<Mutex<Receiver<()>>>,
    started: Option<Mutex<Sender<()>>>,
}

impl Approver for TestApprover {
    fn approve(&self, ctx: &ApprovalContext<'_>) -> Result<Approval, ApprovalError> {
        if let Some(s) = &self.started {
            s.lock().unwrap().send(()).unwrap();
        }
        if let Some(g) = &self.gate {
            g.lock().unwrap().recv().unwrap();
        }
        Ok(Approval {
            user_present: true,
            user_verified: true,
            selected: (ctx.ceremony == Ceremony::Get).then_some(0),
        })
    }
}

impl UvProbe for TestApprover {
    fn uv_available(&self) -> bool {
        true
    }
}

struct Harness {
    to_host: PipeWriter,
    from_host: PipeReader,
    worker: JoinHandle<Result<(), FrameError>>,
    _dir: TempDir,
    vault_dir: PathBuf,
    state_dir: PathBuf,
}

impl Harness {
    fn start(with_vault: bool, approver: TestApprover) -> Harness {
        let dir = TempDir::new();
        let vault_dir = dir.0.join("vault");
        let state_dir = dir.0.join("state");
        if with_vault {
            Vault::create(&vault_dir, &state_dir, "test").unwrap();
        }
        Harness::start_in(dir, vault_dir, state_dir, approver)
    }

    fn start_in(
        dir: TempDir,
        vault_dir: PathBuf,
        state_dir: PathBuf,
        approver: TestApprover,
    ) -> Harness {
        let session = Session::new(settings(&vault_dir, &state_dir), approver);
        let (stdin_r, stdin_w) = pipe().unwrap();
        let (stdout_r, mut stdout_w) = pipe().unwrap();
        let worker = std::thread::spawn(move || run(stdin_r, &mut stdout_w, session, true));
        Harness {
            to_host: stdin_w,
            from_host: stdout_r,
            worker,
            _dir: dir,
            vault_dir,
            state_dir,
        }
    }

    fn send(&mut self, msg: &str) {
        self.to_host
            .write_all(&(msg.len() as u32).to_ne_bytes())
            .unwrap();
        self.to_host.write_all(msg.as_bytes()).unwrap();
    }

    fn recv(&mut self) -> Json {
        let frame = read_frame(&mut self.from_host, framing::OUTBOUND_MAX)
            .unwrap()
            .unwrap();
        json::parse(&frame, &Limits::default()).unwrap()
    }

    fn finish(self) -> Result<(), FrameError> {
        drop(self.to_host);
        self.worker.join().unwrap()
    }
}

fn plain() -> TestApprover {
    TestApprover {
        gate: None,
        started: None,
    }
}

fn b64(b: &[u8]) -> String {
    base64url::encode(b)
}

fn unb64(v: Option<&Json>) -> Vec<u8> {
    base64url::decode(v.and_then(Json::as_str).unwrap()).unwrap()
}

fn at<'a>(v: &'a Json, path: &[&str]) -> Option<&'a Json> {
    path.iter().try_fold(v, |v, k| v.get(k))
}

fn create_msg(id: u64, challenge: &[u8]) -> String {
    format!(
        r#"{{"v":1,"id":{id},"type":"create","origin":"{ORIGIN}","topOrigin":"{ORIGIN}","crossOrigin":false,"options":{{"attestation":"none","attestationFormats":[],"authenticatorSelection":{{"requireResidentKey":false,"residentKey":"required","userVerification":"preferred"}},"challenge":"{}","excludeCredentials":[],"extensions":{{"credProps":true}},"hints":[],"pubKeyCredParams":[{{"alg":-7,"type":"public-key"}},{{"alg":-8,"type":"public-key"}}],"rp":{{"id":"example.com","name":"Example"}},"timeout":60000,"user":{{"displayName":"Alice","id":"{}","name":"alice"}}}}}}"#,
        b64(challenge),
        b64(b"alice")
    )
}

fn get_msg(id: u64, challenge: &[u8], allow: Option<&[u8]>) -> String {
    let allow = allow.map_or_else(String::new, |c| {
        format!(r#"{{"id":"{}","type":"public-key"}}"#, b64(c))
    });
    format!(
        r#"{{"v":1,"id":{id},"type":"get","origin":"{ORIGIN}","topOrigin":"{ORIGIN}","crossOrigin":false,"options":{{"allowCredentials":[{allow}],"challenge":"{}","extensions":{{}},"hints":[],"rpId":"example.com","userVerification":"preferred"}}}}"#,
        b64(challenge)
    )
}

fn check_client_data(cdj: &[u8], ty: &str, challenge: &[u8]) {
    let v = json::parse(cdj, &Limits::default()).unwrap();
    assert_eq!(v.get("type").and_then(Json::as_str), Some(ty));
    assert_eq!(v.get("origin").and_then(Json::as_str), Some(ORIGIN));
    assert_eq!(
        v.get("challenge").and_then(Json::as_str),
        Some(b64(challenge).as_str())
    );
}

/// Checks a registration reply and returns the credential id and public key.
fn registration(reply: &Json, challenge: &[u8]) -> (Vec<u8>, cose::PublicKey) {
    assert_eq!(reply.get("ok"), Some(&Json::Bool(true)), "{reply}");
    let cred = reply.get("credential").unwrap();
    let id = unb64(cred.get("id"));
    assert_eq!(id, unb64(cred.get("rawId")));
    let cdj = unb64(at(cred, &["response", "clientDataJSON"]));
    check_client_data(&cdj, "webauthn.create", challenge);
    let att = attestation::parse_webauthn(
        &unb64(at(cred, &["response", "attestationObject"])),
        &cbor::Limits::default(),
    )
    .unwrap();
    assert_eq!(att.fmt, "none");
    assert_eq!(
        att.auth_data,
        unb64(at(cred, &["response", "authenticatorData"]))
    );
    let ad = AuthenticatorData::parse(&att.auth_data, &cbor::Limits::default()).unwrap();
    assert_eq!(ad.rp_id_hash, hirz_crypto::sha256(b"example.com"));
    assert_eq!(ad.flags, FLAG_UP | FLAG_UV | FLAG_BE | FLAG_AT);
    let attested = ad.attested_credential.unwrap();
    assert_eq!(attested.credential_id, id);
    assert_eq!(attested.aaguid, hirz_core::AAGUID);
    let key = cbor::decode(&attested.public_key, &cbor::Limits::default()).unwrap();
    let key = cose::parse_public_key(&key).unwrap();
    assert_eq!(
        at(cred, &["clientExtensionResults", "credProps", "rk"]),
        Some(&Json::Bool(true))
    );
    (id, key)
}

/// Checks an authentication reply, including its signature.
fn authentication(reply: &Json, challenge: &[u8], id: &[u8], key: &cose::PublicKey) {
    assert_eq!(reply.get("ok"), Some(&Json::Bool(true)), "{reply}");
    let cred = reply.get("credential").unwrap();
    assert_eq!(unb64(cred.get("id")), id);
    let cdj = unb64(at(cred, &["response", "clientDataJSON"]));
    check_client_data(&cdj, "webauthn.get", challenge);
    let auth_data = unb64(at(cred, &["response", "authenticatorData"]));
    let signature = unb64(at(cred, &["response", "signature"]));
    assert_eq!(unb64(at(cred, &["response", "userHandle"])), b"alice");
    let ad = AuthenticatorData::parse(&auth_data, &cbor::Limits::default()).unwrap();
    assert_eq!(ad.flags, FLAG_UP | FLAG_UV | FLAG_BE);
    let mut msg = auth_data.clone();
    msg.extend_from_slice(&hirz_crypto::sha256(&cdj));
    match key {
        cose::PublicKey::Es256 { x, y } => {
            hirz_crypto::es256::verify(x, y, &msg, &signature).unwrap()
        }
        cose::PublicKey::Ed25519 { x } => {
            hirz_crypto::ed25519::verify(x, &msg, &signature.try_into().unwrap()).unwrap()
        }
    }
}

#[test]
fn create_then_get_end_to_end() {
    let mut h = Harness::start(true, plain());
    h.send(r#"{"v":1,"id":1,"type":"hello"}"#);
    let hello = h.recv();
    assert_eq!(hello.get("ok"), Some(&Json::Bool(true)));
    assert_eq!(
        hello.get("version").and_then(Json::as_str),
        Some(env!("CARGO_PKG_VERSION"))
    );

    h.send(r#"{"v":1,"id":2,"type":"capabilities"}"#);
    let caps = h.recv();
    assert_eq!(
        at(
            &caps,
            &["capabilities", "userVerifyingPlatformAuthenticator"]
        ),
        Some(&Json::Bool(true))
    );

    let challenge = [7u8; 32];
    h.send(&create_msg(3, &challenge));
    let reply = h.recv();
    assert_eq!(reply.get("id").and_then(Json::as_u64), Some(3));
    let (id, key) = registration(&reply, &challenge);

    let challenge = [9u8; 32];
    h.send(&get_msg(4, &challenge, Some(&id)));
    authentication(&h.recv(), &challenge, &id, &key);

    let challenge = [10u8; 32];
    h.send(&get_msg(5, &challenge, None));
    authentication(&h.recv(), &challenge, &id, &key);

    h.send(&create_msg(6, &[1u8; 32]).replace(
        r#""excludeCredentials":[]"#,
        &format!(
            r#""excludeCredentials":[{{"id":"{}","type":"public-key"}}]"#,
            b64(&id)
        ),
    ));
    assert_eq!(
        h.recv().get("error").and_then(Json::as_str),
        Some("InvalidStateError")
    );

    let vault = Vault::open(&h.vault_dir, &h.state_dir).unwrap();
    assert_eq!(vault.list_all().len(), 1);
    h.finish().unwrap();
}

#[test]
fn without_a_vault_firefox_handles_everything() {
    let mut h = Harness::start(false, plain());
    h.send(r#"{"v":1,"id":1,"type":"capabilities"}"#);
    let caps = h.recv();
    assert_eq!(
        at(
            &caps,
            &["capabilities", "userVerifyingPlatformAuthenticator"]
        ),
        Some(&Json::Bool(false))
    );
    h.send(&create_msg(2, &[1u8; 32]));
    let r = h.recv();
    assert_eq!(r.get("id").and_then(Json::as_u64), Some(2));
    assert_eq!(r.get("error").and_then(Json::as_str), Some("NotHandled"));
    h.send(&get_msg(3, &[1u8; 32], None));
    assert_eq!(
        h.recv().get("error").and_then(Json::as_str),
        Some("NotHandled")
    );
    h.finish().unwrap();
}

#[test]
fn cancel_while_the_prompt_is_open() {
    let (open_tx, open_rx) = channel();
    let (gate_tx, gate_rx) = channel();
    let mut h = Harness::start(
        true,
        TestApprover {
            gate: Some(Mutex::new(gate_rx)),
            started: Some(Mutex::new(open_tx)),
        },
    );
    h.send(&create_msg(1, &[1u8; 32]));
    h.send(&create_msg(2, &[2u8; 32]));
    open_rx.recv().unwrap();
    // Cancel the running request and the queued one; cancels of unknown ids are ignored.
    h.send(r#"{"v":1,"id":1,"type":"cancel"}"#);
    h.send(r#"{"v":1,"id":2,"type":"cancel"}"#);
    h.send(r#"{"v":1,"id":99,"type":"cancel"}"#);
    h.send(r#"{"v":1,"id":3,"type":"hello"}"#);
    // Give the reader thread time to record the cancels before the prompt "closes".
    std::thread::sleep(std::time::Duration::from_millis(200));
    gate_tx.send(()).unwrap();

    for expected in [1, 2] {
        let r = h.recv();
        assert_eq!(r.get("id").and_then(Json::as_u64), Some(expected));
        assert_eq!(r.get("error").and_then(Json::as_str), Some("AbortError"));
    }
    assert_eq!(h.recv().get("id").and_then(Json::as_u64), Some(3));
    assert!(
        Vault::open(&h.vault_dir, &h.state_dir)
            .unwrap()
            .list_all()
            .is_empty()
    );
    h.finish().unwrap();
}

#[test]
fn envelope_errors_keep_the_loop_running() {
    let mut h = Harness::start(false, plain());
    h.send("not json");
    let r = h.recv();
    assert!(r.get("id").unwrap().is_null());
    assert_eq!(r.get("error").and_then(Json::as_str), Some("UnknownError"));
    h.send(r#"{"v":2,"id":8,"type":"hello"}"#);
    assert_eq!(
        h.recv().get("error").and_then(Json::as_str),
        Some("NotHandled")
    );
    h.send(r#"{"v":1,"id":9,"type":"explode"}"#);
    assert_eq!(
        h.recv().get("error").and_then(Json::as_str),
        Some("UnknownError")
    );
    h.send(r#"{"v":1,"id":10,"type":"hello"}"#);
    assert_eq!(h.recv().get("ok"), Some(&Json::Bool(true)));
    h.finish().unwrap();
}

#[test]
fn oversize_frame_ends_the_loop() {
    let mut h = Harness::start(false, plain());
    h.send(r#"{"v":1,"id":1,"type":"hello"}"#);
    assert_eq!(h.recv().get("ok"), Some(&Json::Bool(true)));
    h.to_host.write_all(&u32::MAX.to_ne_bytes()).unwrap();
    assert!(matches!(h.finish(), Err(FrameError::TooLarge { .. })));
}

#[test]
fn truncated_stream_is_an_error() {
    let mut h = Harness::start(false, plain());
    h.to_host.write_all(&100u32.to_ne_bytes()).unwrap();
    h.to_host.write_all(b"{\"v\":").unwrap();
    assert!(matches!(h.finish(), Err(FrameError::TruncatedBody { .. })));
}

#[test]
fn clean_exit_on_eof() {
    let h = Harness::start(false, plain());
    h.finish().unwrap();
}

#[test]
fn closed_port_cancels_the_running_ceremony() {
    let (open_tx, open_rx) = channel();
    let (gate_tx, gate_rx) = channel();
    let mut h = Harness::start(
        true,
        TestApprover {
            gate: Some(Mutex::new(gate_rx)),
            started: Some(Mutex::new(open_tx)),
        },
    );
    h.send(&create_msg(1, &[1u8; 32]));
    open_rx.recv().unwrap();
    let Harness {
        to_host,
        mut from_host,
        worker,
        _dir,
        vault_dir,
        state_dir,
    } = h;
    drop(to_host);
    std::thread::sleep(std::time::Duration::from_millis(200));
    gate_tx.send(()).unwrap();
    let reply = read_frame(&mut from_host, framing::OUTBOUND_MAX)
        .unwrap()
        .unwrap();
    assert!(String::from_utf8(reply).unwrap().contains("AbortError"));
    worker.join().unwrap().unwrap();
    assert!(
        Vault::open(&vault_dir, &state_dir)
            .unwrap()
            .list_all()
            .is_empty()
    );
}

#[test]
fn imported_credential_with_a_16_byte_id_signs_through_handle() {
    let dir = TempDir::new();
    let (vault_dir, state_dir) = (dir.0.join("vault"), dir.0.join("state"));
    let (mut vault, _) = Vault::create(&vault_dir, &state_dir, "test").unwrap();
    let id: Vec<u8> = (0x40..0x50).collect();
    let (pkcs8, x, y) = hirz_crypto::es256::generate().unwrap();
    vault
        .put(hirz_vault::CredentialRecord {
            credential_id: id.clone(),
            rp_id: "example.com".to_owned(),
            rp_name: None,
            user_id: b"alice".to_vec(),
            user_name: Some("alice".to_owned()),
            user_display_name: None,
            algorithm: hirz_core::COSE_ALG_ES256,
            private_key_pkcs8: pkcs8,
            created_at: 1,
            cred_protect: None,
            hmac_secret: None,
            discoverable: true,
            backup_eligible: true,
        })
        .unwrap();
    drop(vault);
    let key = cose::PublicKey::Es256 { x, y };

    let mut session = Session::new(settings(&vault_dir, &state_dir), plain());
    assert!(matches!(session.ensure_vault(), VaultStatus::Ready));
    let cancelled = || false;
    let mut engine = HostEngine {
        session: &mut session,
        uv: true,
        cancelled: &cancelled,
    };
    for (n, allow) in [(1, Some(id.as_slice())), (2, None)] {
        let challenge = [n; 32];
        let msg = get_msg(u64::from(n), &challenge, allow);
        let msg = json::parse(msg.as_bytes(), &Limits::default()).unwrap();
        let reply = hirz_webauthn::handle(&msg, &mut engine);
        authentication(&reply, &challenge, &id, &key);
        let raw = unb64(at(&reply, &["credential", "rawId"]));
        assert_eq!(raw, id);
    }

    let mut longer = id.clone();
    longer.extend_from_slice(&[0; 16]);
    let msg = get_msg(3, &[3; 32], Some(&longer));
    let msg = json::parse(msg.as_bytes(), &Limits::default()).unwrap();
    let reply = hirz_webauthn::handle(&msg, &mut engine);
    assert_eq!(reply.get("ok"), Some(&Json::Bool(false)), "{reply}");
}

fn record(
    id: u8,
    rp_id: &str,
    created_at: u64,
    protect: Option<u8>,
    discoverable: bool,
) -> hirz_vault::CredentialRecord {
    let (pkcs8, _, _) = hirz_crypto::es256::generate().unwrap();
    hirz_vault::CredentialRecord {
        credential_id: vec![id; 16],
        rp_id: rp_id.to_owned(),
        rp_name: None,
        user_id: vec![id],
        user_name: Some(format!("user{id}")),
        user_display_name: Some(format!("User {id}")),
        algorithm: hirz_core::COSE_ALG_ES256,
        private_key_pkcs8: pkcs8,
        created_at,
        cred_protect: protect,
        hmac_secret: None,
        discoverable,
        backup_eligible: true,
    }
}

fn list_msg(id: u64, allow: &[u8]) -> String {
    let allow: Vec<String> = allow
        .iter()
        .map(|n| format!(r#"{{"type":"public-key","id":"{}"}}"#, b64(&[*n; 16])))
        .collect();
    format!(
        r#"{{"v":1,"id":{id},"type":"list","origin":"{ORIGIN}","topOrigin":"{ORIGIN}","crossOrigin":false,"options":{{"rpId":"example.com","allowCredentials":[{}]}}}}"#,
        allow.join(",")
    )
}

fn listed_ids(reply: &Json) -> Vec<u8> {
    assert_eq!(reply.get("ok"), Some(&Json::Bool(true)), "{reply}");
    reply
        .get("accounts")
        .and_then(Json::as_array)
        .unwrap()
        .iter()
        .map(|a| {
            let id = unb64(a.get("id"));
            assert_eq!(id.len(), 16);
            assert_eq!(
                a.get("name").and_then(Json::as_str),
                Some(format!("user{}", id[0]).as_str())
            );
            id[0]
        })
        .collect()
}

#[test]
fn list_honours_discoverability_and_cred_protect() {
    let mut h = Harness::start(true, plain());
    let mut vault = Vault::open(&h.vault_dir, &h.state_dir).unwrap();
    for rec in [
        record(1, "example.com", 10, None, true),
        record(2, "example.com", 30, Some(1), true),
        record(3, "example.com", 20, Some(2), true),
        record(4, "example.com", 40, Some(3), true),
        record(5, "example.com", 50, None, false),
        record(6, "other.example", 60, None, true),
    ] {
        vault.put(rec).unwrap();
    }
    drop(vault);

    h.send(&list_msg(1, &[]));
    assert_eq!(listed_ids(&h.recv()), [2, 1]);

    h.send(&list_msg(2, &[3, 4, 5, 6, 1, 3, 9]));
    assert_eq!(listed_ids(&h.recv()), [3, 5, 1]);

    let cross = list_msg(3, &[]).replace(r#""crossOrigin":false"#, r#""crossOrigin":true"#);
    h.send(&cross);
    let reply = h.recv();
    assert_eq!(
        reply.get("error").and_then(Json::as_str),
        Some("NotHandled")
    );
    h.finish().unwrap();
}

#[test]
fn list_without_a_vault_is_empty() {
    let mut h = Harness::start(false, plain());
    h.send(&list_msg(1, &[]));
    assert_eq!(
        h.recv(),
        json::parse(
            br#"{"v":1,"id":1,"ok":true,"accounts":[]}"#,
            &Limits::default()
        )
        .unwrap()
    );
    h.finish().unwrap();
}

#[test]
fn a_removed_device_hands_everything_to_firefox() {
    let dir = TempDir::new();
    let vault_dir = dir.0.join("vault");
    let a_state = dir.0.join("a");
    let state_dir = dir.0.join("state");
    let (mut a, phrase) = Vault::create(&vault_dir, &a_state, "a").unwrap();
    let b = Vault::join_with_recovery(&vault_dir, &state_dir, &phrase, "b").unwrap();
    a.reload().unwrap();
    a.put(record(1, "example.com", 10, None, true)).unwrap();
    let mut h = Harness::start_in(dir, vault_dir, state_dir, plain());

    h.send(&list_msg(1, &[]));
    assert_eq!(listed_ids(&h.recv()), [1]);

    a.remove_device(&b.device_id()).unwrap();
    h.send(&list_msg(2, &[]));
    assert_eq!(listed_ids(&h.recv()), Vec::<u8>::new());
    h.send(&list_msg(3, &[1]));
    assert_eq!(listed_ids(&h.recv()), Vec::<u8>::new());
    h.send(r#"{"v":1,"id":4,"type":"capabilities"}"#);
    assert_eq!(
        at(
            &h.recv(),
            &["capabilities", "userVerifyingPlatformAuthenticator"]
        ),
        Some(&Json::Bool(false))
    );
    for (id, msg) in [
        (5, create_msg(5, &[1u8; 32])),
        (6, get_msg(6, &[1u8; 32], Some(&[1u8; 16]))),
        (7, get_msg(7, &[1u8; 32], None)),
    ] {
        h.send(&msg);
        let r = h.recv();
        assert_eq!(r.get("id").and_then(Json::as_u64), Some(id));
        assert_eq!(r.get("error").and_then(Json::as_str), Some("NotHandled"));
    }
    a.reload().unwrap();
    assert_eq!(a.list_all().len(), 1);
    h.finish().unwrap();
}
