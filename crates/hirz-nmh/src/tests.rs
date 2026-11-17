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
use std::sync::atomic::AtomicUsize;
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
    verified: bool,
    /// Ends every approval with this error instead of approving.
    refusal: Option<ApprovalError>,
}

impl Approver for TestApprover {
    fn approve(&self, ctx: &ApprovalContext<'_>) -> Result<Approval, ApprovalError> {
        if let Some(s) = &self.started {
            s.lock().unwrap().send(()).unwrap();
        }
        if let Some(g) = &self.gate {
            g.lock().unwrap().recv().unwrap();
        }
        if let Some(e) = &self.refusal {
            return Err(e.clone());
        }
        Ok(Approval {
            user_present: true,
            user_verified: self.verified,
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
        Harness::start_full(
            dir,
            vault_dir,
            state_dir,
            approver,
            FirstRun::disabled(),
            NMH_HOLD,
        )
    }

    fn start_full<L: SetupLauncher + Send + 'static>(
        dir: TempDir,
        vault_dir: PathBuf,
        state_dir: PathBuf,
        approver: TestApprover,
        first_run: FirstRun<L>,
        hold: Hold,
    ) -> Harness {
        let session = Session::new(settings(&vault_dir, &state_dir), approver);
        let (stdin_r, stdin_w) = pipe().unwrap();
        let (stdout_r, mut stdout_w) = pipe().unwrap();
        let worker =
            std::thread::spawn(move || run(stdin_r, &mut stdout_w, session, first_run, hold, true));
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
        verified: true,
        refusal: None,
    }
}

fn refusing(error: ApprovalError) -> TestApprover {
    TestApprover {
        refusal: Some(error),
        ..plain()
    }
}

/// An approver that tells the test when a prompt opens and waits for the test to close it.
fn gated() -> (TestApprover, Receiver<()>, Sender<()>) {
    let (open_tx, open_rx) = channel();
    let (gate_tx, gate_rx) = channel();
    let approver = TestApprover {
        gate: Some(Mutex::new(gate_rx)),
        started: Some(Mutex::new(open_tx)),
        verified: true,
        refusal: None,
    };
    (approver, open_rx, gate_tx)
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

#[derive(Debug, Clone, Default)]
struct CountingLauncher(Arc<AtomicUsize>, Arc<Mutex<Vec<String>>>);

impl SetupLauncher for CountingLauncher {
    fn can_draw(&self) -> bool {
        true
    }
    fn launch(&self, _: &Path, _: &Path) -> std::io::Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn notify(&self, text: &str) {
        self.1.lock().unwrap().push(text.to_owned());
    }
}

const SHORT: Hold = Hold {
    limit: std::time::Duration::from_millis(60),
    poll: std::time::Duration::from_millis(10),
};

fn first_run_harness(
    with_vault: bool,
    launcher: &CountingLauncher,
    hold: Hold,
) -> (Harness, PathBuf) {
    let dir = TempDir::new();
    let (vault_dir, state_dir) = (dir.0.join("vault"), dir.0.join("state"));
    let runtime = dir.0.join("run");
    if with_vault {
        Vault::create(&vault_dir, &state_dir, "test").unwrap();
    }
    let first_run = FirstRun::new(
        Some(runtime.clone()),
        Some(state_dir.clone()),
        true,
        Some(PathBuf::from("/usr/bin/hirz")),
        launcher.clone(),
    );
    let h = Harness::start_full(dir, vault_dir, state_dir, plain(), first_run, hold);
    (h, runtime)
}

#[test]
fn without_a_vault_a_ceremony_opens_one_setup_window() {
    let launcher = CountingLauncher::default();
    let (mut h, runtime) = first_run_harness(false, &launcher, SHORT);
    h.send(r#"{"v":1,"id":1,"type":"capabilities"}"#);
    h.recv();
    h.send(&list_msg(2, &[]));
    h.recv();
    assert_eq!(launcher.0.load(Ordering::SeqCst), 0, "reads open nothing");
    h.send(&create_msg(3, &[1u8; 32]));
    let r = h.recv();
    assert_eq!(r.get("error").and_then(Json::as_str), Some("NotHandled"));
    assert!(
        hirz_uv::first_run::take_waiter_gone(&runtime),
        "the wait ran out while the window was starting"
    );
    for id in 4..40 {
        if id % 2 == 0 {
            h.send(&get_msg(id, &[1u8; 32], None));
        } else {
            h.send(&create_msg(id, &[1u8; 32]));
        }
        let r = h.recv();
        assert_eq!(r.get("error").and_then(Json::as_str), Some("NotHandled"));
    }
    assert_eq!(launcher.0.load(Ordering::SeqCst), 1);
    h.finish().unwrap();
}

#[test]
fn a_ceremony_waits_for_the_setup_window_and_then_asks_as_usual() {
    let launcher = CountingLauncher::default();
    let long = Hold {
        limit: std::time::Duration::from_secs(20),
        ..SHORT
    };
    let (mut h, runtime) = first_run_harness(false, &launcher, long);
    let held = hirz_uv::first_run::try_lock(&runtime).unwrap().unwrap();
    h.send(&create_msg(1, &[1u8; 32]));
    std::thread::sleep(std::time::Duration::from_millis(100));
    Vault::create(&h.vault_dir, &h.state_dir, "test").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(100));
    drop(held);
    let r = h.recv();
    assert_eq!(r.get("ok"), Some(&Json::Bool(true)), "{r}");
    let vault = Vault::open(&h.vault_dir, &h.state_dir).unwrap();
    assert_eq!(vault.list_all().len(), 1);

    let (mut h, runtime) = first_run_harness(false, &launcher, long);
    let held = hirz_uv::first_run::try_lock(&runtime).unwrap().unwrap();
    h.send(&create_msg(1, &[1u8; 32]));
    std::thread::sleep(std::time::Duration::from_millis(100));
    h.send(r#"{"v":1,"id":1,"type":"cancel"}"#);
    let r = h.recv();
    assert_eq!(r.get("error").and_then(Json::as_str), Some("AbortError"));
    assert!(hirz_uv::first_run::take_waiter_gone(&runtime));

    let started = std::time::Instant::now();
    h.send(&get_msg(2, &[1u8; 32], None));
    let r = h.recv();
    assert_eq!(r.get("error").and_then(Json::as_str), Some("NotHandled"));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "a sign-in never waits"
    );
    assert!(!hirz_uv::first_run::take_waiter_gone(&runtime));
    assert!(launcher.1.lock().unwrap().is_empty(), "no notice either");
    drop(held);
    h.finish().unwrap();
}

#[test]
fn a_sign_in_without_a_passkey_is_told_once_and_handed_to_firefox() {
    let launcher = CountingLauncher::default();
    let (mut h, _runtime) = first_run_harness(true, &launcher, SHORT);
    for id in 1..4 {
        h.send(&get_msg(id, &[1u8; 32], Some(&[9u8; 32])));
        let r = h.recv();
        assert_eq!(r.get("error").and_then(Json::as_str), Some("NotHandled"));
    }
    assert_eq!(
        launcher.1.lock().unwrap().as_slice(),
        ["hirz has no passkey for example.com."]
    );
    h.finish().unwrap();
}

#[test]
fn cancel_while_the_prompt_is_open() {
    let (approver, open_rx, gate_tx) = gated();
    let mut h = Harness::start(true, approver);
    h.send(&create_msg(1, &[1u8; 32]));
    h.send(&create_msg(2, &[2u8; 32]));
    open_rx.recv().unwrap();
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
    let (approver, open_rx, gate_tx) = gated();
    let mut h = Harness::start(true, approver);
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
        commit: None,
        no_passkey: &|_: &str| {},
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
    // A request that signs or asks always looks at the folder; lists in the next seconds reuse
    // that look instead of scanning again.
    h.send(&get_msg(8, &[1u8; 32], None));
    assert_eq!(error_name(&h.recv()), "NotHandled");
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

#[test]
fn a_fork_hands_registrations_to_firefox_and_keeps_sign_ins() {
    let dir = TempDir::new();
    let vault_dir = dir.0.join("vault");
    let state_dir = dir.0.join("state");
    let (mut a, phrase) = Vault::create(&vault_dir, &state_dir, "a").unwrap();
    let c = Vault::join_with_recovery(&vault_dir, &dir.0.join("c"), &phrase, "c").unwrap();
    a.put(record(1, "example.com", 10, None, true)).unwrap();
    a.remove_device(&c.device_id()).unwrap();
    let name = std::fs::read_dir(vault_dir.join("keys"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .find(|n| n.starts_with("0000000002-"))
        .unwrap();
    let from = vault_dir.join("keys").join(&name);
    let to = vault_dir.join(format!(".hidden-{name}"));
    std::fs::rename(&from, &to).unwrap();

    let (approver, open_rx, _gate) = gated();
    let mut h = Harness::start_in(dir, vault_dir, state_dir, approver);
    h.send(&list_msg(1, &[]));
    assert_eq!(listed_ids(&h.recv()), [1], "existing passkeys stay listed");
    h.send(&create_msg(2, &[1u8; 32]));
    let r = h.recv();
    assert_eq!(r.get("id").and_then(Json::as_u64), Some(2));
    assert_eq!(error_name(&r), "NotHandled");
    assert!(
        open_rx.try_recv().is_err(),
        "no prompt for a refused registration"
    );

    std::fs::rename(&to, &from).unwrap();
    h.send(&list_msg(3, &[]));
    assert_eq!(listed_ids(&h.recv()), [1]);
    h.finish().unwrap();
}

fn put_records(h: &Harness, records: Vec<hirz_vault::CredentialRecord>) {
    let mut vault = Vault::open(&h.vault_dir, &h.state_dir).unwrap();
    for rec in records {
        vault.put(rec).unwrap();
    }
}

fn error_name(reply: &Json) -> &str {
    assert_eq!(reply.get("ok"), Some(&Json::Bool(false)), "{reply}");
    reply.get("error").and_then(Json::as_str).unwrap()
}

#[test]
fn no_credential_here_goes_to_firefox_without_a_prompt() {
    let (approver, open_rx, _gate) = gated();
    let mut h = Harness::start(true, approver);
    put_records(
        &h,
        vec![
            record(1, "other.example", 10, None, true),
            record(2, "example.com", 20, None, false),
        ],
    );
    // An empty allow list needs a discoverable credential of this RP: there is none.
    h.send(&get_msg(1, &[1u8; 32], None));
    let r = h.recv();
    assert_eq!(r.get("id").and_then(Json::as_u64), Some(1));
    assert_eq!(error_name(&r), "NotHandled");
    // The id of a hardware key, and the id of a credential that belongs to another RP.
    for (id, allow) in [(2, [9u8; 16]), (3, [1u8; 16])] {
        h.send(&get_msg(id, &[1u8; 32], Some(&allow)));
        assert_eq!(error_name(&h.recv()), "NotHandled");
    }
    assert!(
        open_rx.try_recv().is_err(),
        "no prompt was shown for a request nothing matched"
    );
    h.finish().unwrap();
}

#[test]
fn an_empty_vault_hands_every_get_to_firefox() {
    let mut h = Harness::start(true, plain());
    h.send(&get_msg(1, &[1u8; 32], None));
    assert_eq!(error_name(&h.recv()), "NotHandled");
    h.send(&get_msg(2, &[1u8; 32], Some(&[7u8; 32])));
    assert_eq!(error_name(&h.recv()), "NotHandled");
    h.finish().unwrap();
}

#[test]
fn a_prompt_followed_by_no_usable_credential_is_a_refusal_not_a_fallback() {
    // The only credential needs user verification; the approval has none. The user already saw a
    // prompt, so Firefox must not start a second ceremony.
    let (open_tx, open_rx) = channel();
    let mut h = Harness::start(
        true,
        TestApprover {
            gate: None,
            started: Some(Mutex::new(open_tx)),
            verified: false,
            refusal: None,
        },
    );
    put_records(&h, vec![record(1, "example.com", 10, Some(3), true)]);
    h.send(&get_msg(1, &[1u8; 32], Some(&[1u8; 16])));
    assert_eq!(error_name(&h.recv()), "NotAllowedError");
    assert!(open_rx.try_recv().is_ok(), "the user was shown a prompt");
    h.finish().unwrap();
}

#[test]
fn appid_and_unparsable_origins_go_to_firefox() {
    let mut h = Harness::start(true, plain());
    h.send(&create_msg(1, &[1u8; 32]));
    let (id, _) = registration(&h.recv(), &[1u8; 32]);

    let with_appid = get_msg(2, &[2u8; 32], Some(&id)).replace(
        r#""extensions":{}"#,
        r#""extensions":{"appid":"https://example.com/app-id.json"}"#,
    );
    h.send(&with_appid);
    assert_eq!(error_name(&h.recv()), "NotHandled");

    for origin in [
        "https://my_app.example.com",
        "https://example.com.",
        "https://-a.example.com",
    ] {
        let msg = get_msg(3, &[3u8; 32], None).replace(ORIGIN, origin);
        h.send(&msg);
        assert_eq!(error_name(&h.recv()), "NotHandled", "{origin}");
    }
    h.finish().unwrap();
}

#[test]
fn a_flood_behind_an_open_prompt_neither_blocks_the_reader_nor_loses_the_cancel() {
    let (approver, open_rx, gate_tx) = gated();
    let mut h = Harness::start(true, approver);
    h.send(&create_msg(1, &[1u8; 32]));
    open_rx.recv().unwrap();
    for n in 0..70u64 {
        h.send(&list_msg(100 + n, &[]));
    }
    h.send(r#"{"v":1,"id":1,"type":"cancel"}"#);
    std::thread::sleep(std::time::Duration::from_millis(200));
    gate_tx.send(()).unwrap();

    let first = h.recv();
    assert_eq!(first.get("id").and_then(Json::as_u64), Some(1));
    assert_eq!(error_name(&first), "AbortError");
    let (mut served, mut refused) = (0, 0);
    for _ in 0..70 {
        let r = h.recv();
        match r.get("ok") {
            Some(Json::Bool(true)) => served += 1,
            _ => {
                assert_eq!(error_name(&r), "NotAllowedError");
                assert_eq!(r.get("message").and_then(Json::as_str), Some("host busy"));
                assert!(r.get("id").and_then(Json::as_u64).unwrap() >= 100);
                refused += 1;
            }
        }
    }
    assert_eq!((served, refused), (QUEUE, 70 - QUEUE));
    let vault = Vault::open(&h.vault_dir, &h.state_dir).unwrap();
    assert!(
        vault.list_all().is_empty(),
        "the cancelled create stored nothing"
    );
    h.finish().unwrap();
}

#[test]
fn closing_the_port_behind_a_full_queue_is_still_seen() {
    let (approver, open_rx, gate_tx) = gated();
    let mut h = Harness::start(true, approver);
    h.send(&create_msg(1, &[1u8; 32]));
    open_rx.recv().unwrap();
    for n in 0..(QUEUE as u64 + 10) {
        h.send(&list_msg(100 + n, &[]));
    }
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
    while read_frame(&mut from_host, framing::OUTBOUND_MAX)
        .unwrap()
        .is_some()
    {}
    worker.join().unwrap().unwrap();
    assert!(
        Vault::open(&vault_dir, &state_dir)
            .unwrap()
            .list_all()
            .is_empty()
    );
}

#[test]
fn a_credential_hirz_cannot_ask_about_looks_like_no_credential() {
    // The approver refuses before any window (prompt budget used up, no way to verify, no zenity).
    // A page must not be able to tell a matching allow list from one that matches nothing.
    let mut h = Harness::start(true, refusing(ApprovalError::NothingShown));
    put_records(&h, vec![record(1, "example.com", 10, None, true)]);
    let mut replies = Vec::new();
    for (id, allow) in [
        (1, Some([1u8; 16])),
        (2, Some([9u8; 16])),
        (3, None),
        (4, Some([1u8; 16])),
    ] {
        h.send(&get_msg(
            id,
            &[id as u8; 32],
            allow.as_ref().map(|a| a.as_slice()),
        ));
        let r = h.recv();
        assert_eq!(r.get("id").and_then(Json::as_u64), Some(id));
        assert_eq!(error_name(&r), "NotHandled", "request {id}");
        replies.push(r.get("message").and_then(Json::as_str).unwrap().to_owned());
    }
    assert!(replies.windows(2).all(|w| w[0] == w[1]), "{replies:?}");
    h.finish().unwrap();

    // After a window the user saw, a refusal stays one.
    for error in [ApprovalError::Denied, ApprovalError::Timeout] {
        let mut h = Harness::start(true, refusing(error));
        put_records(&h, vec![record(1, "example.com", 10, None, true)]);
        h.send(&get_msg(1, &[1u8; 32], Some(&[1u8; 16])));
        assert_eq!(error_name(&h.recv()), "NotAllowedError");
        h.finish().unwrap();
    }
}

#[test]
fn a_registration_nobody_can_be_asked_about_goes_to_firefox() {
    let mut h = Harness::start(true, refusing(ApprovalError::NothingShown));
    h.send(&create_msg(1, &[1u8; 32]));
    assert_eq!(error_name(&h.recv()), "NotHandled");
    assert!(
        Vault::open(&h.vault_dir, &h.state_dir)
            .unwrap()
            .list_all()
            .is_empty()
    );
    h.finish().unwrap();
}

fn host_for(
    dir: &TempDir,
) -> (
    Host<TestApprover, session::SystemLauncher>,
    PathBuf,
    PathBuf,
) {
    let (vault_dir, state_dir) = (dir.0.join("vault"), dir.0.join("state"));
    Vault::create(&vault_dir, &state_dir, "test").unwrap();
    let session = Session::new(settings(&vault_dir, &state_dir), plain());
    let host = Host {
        session,
        pending: Arc::new(Mutex::new(Pending::default())),
        removed_told: false,
        first_run: FirstRun::disabled(),
        hold: NMH_HOLD,
    };
    (host, vault_dir, state_dir)
}

#[test]
fn list_and_capability_requests_do_not_scan_the_folder_every_time() {
    let dir = TempDir::new();
    let (mut host, vault_dir, state_dir) = host_for(&dir);
    let mut vault = Vault::open(&vault_dir, &state_dir).unwrap();
    vault.put(record(1, "example.com", 10, None, true)).unwrap();
    for i in 0..100u64 {
        let msg = json::parse(list_msg(i + 1, &[]).as_bytes(), &Limits::default()).unwrap();
        let reply = host.answer(&msg);
        assert_eq!(reply.get("ok"), Some(&Json::Bool(true)), "{reply}");
        let caps = json::parse(
            format!(r#"{{"v":1,"id":{},"type":"capabilities"}}"#, 1000 + i).as_bytes(),
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(host.answer(&caps).get("ok"), Some(&Json::Bool(true)));
    }
    assert_eq!(
        host.session.looks(),
        1,
        "200 requests that only read looked at the folder once"
    );

    // A ceremony always looks again.
    let get = json::parse(
        get_msg(500, &[1u8; 32], None).as_bytes(),
        &Limits::default(),
    )
    .unwrap();
    host.answer(&get);
    assert_eq!(host.session.looks(), 2);
}

#[test]
fn only_a_cancel_that_comes_before_the_commit_can_undo_a_registration() {
    let pending = Mutex::new(Pending::default());
    lock(&pending).waiting.insert(7);
    assert!(commit_ceremony(&pending, 7));
    assert!(
        !lock(&pending).waiting.contains(&7),
        "after the commit nothing is waiting for a cancel"
    );

    let pending = Mutex::new(Pending::default());
    {
        let mut p = lock(&pending);
        p.waiting.insert(7);
        p.cancelled.insert(7);
    }
    assert!(!commit_ceremony(&pending, 7));
}

#[test]
fn a_cancel_that_lands_after_the_credential_was_stored_deletes_it_and_keeps_the_old_one() {
    let dir = TempDir::new();
    let (mut host, vault_dir, state_dir) = host_for(&dir);
    {
        let mut other = Vault::open(&vault_dir, &state_dir).unwrap();
        let mut rec = record(1, "example.com", 10, None, true);
        rec.user_id = b"alice".to_vec();
        other.put(rec).unwrap();
    }
    assert_eq!(host.session.ensure_vault(), VaultStatus::Ready);
    let pending = Arc::clone(&host.pending);
    lock(&pending).waiting.insert(5);
    // The reader records the cancel after the engine stored the credential and before it asks
    // whether to go on: the last point where a cancel is early enough.
    let commit = || {
        lock(&pending).cancelled.insert(5);
        commit_ceremony(&pending, 5)
    };
    let never = || false;
    let mut engine = HostEngine {
        session: &mut host.session,
        uv: false,
        cancelled: &never,
        commit: Some(&commit),
        no_passkey: &|_: &str| {},
    };
    let request = hirz_core::MakeCredentialRequest {
        client_data_hash: [5; 32],
        rp: hirz_core::RpEntity {
            id: "example.com".into(),
            name: None,
        },
        user: hirz_core::UserEntity {
            id: b"alice".to_vec(),
            name: Some("alice".into()),
            display_name: None,
        },
        algorithms: vec![hirz_core::COSE_ALG_ES256],
        exclude_list: Vec::new(),
        resident_key: true,
        uv: hirz_core::UvRequirement::Preferred,
        extensions: hirz_core::MakeExtensions::default(),
    };
    let r = hirz_webauthn::Engine::make_credential(&mut engine, &request, ORIGIN);
    assert_eq!(r.unwrap_err(), CoreError::Approval(ApprovalError::Denied));

    let kept = Vault::open(&vault_dir, &state_dir).unwrap();
    let ids: Vec<Vec<u8>> = kept
        .list_all()
        .iter()
        .map(|r| r.credential_id.clone())
        .collect();
    assert_eq!(
        ids,
        [vec![1u8; 16]],
        "the new credential is gone and the older one was not replaced"
    );
}
