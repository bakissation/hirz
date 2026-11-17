//! `hirzd --self-test`: plays the browser against the daemon over an in-process socketpair with a
//! fresh vault in a temporary folder; needs no root, no `/dev/uhid` and no desktop. Its approver
//! approves everything and is private to this module: no setting can put it in front of the real vault.

use std::io::{self, Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use hirz_core::{AAGUID, Approval, ApprovalContext, ApprovalError, Approver, Ceremony};
use hirz_ctap::Ctap2Handler;
use hirz_ctap::ctap2::get_info_response;
use hirz_ctap::hid::{self, StreamReportIo};
use hirz_proto::auth_data::{AuthenticatorData, FLAG_AT, FLAG_BE, FLAG_UP, FLAG_UV};
use hirz_proto::cbor::{self, Limits, MapBuilder, Value};
use hirz_proto::{attestation, cose};
use hirz_vault::Vault;

use crate::authenticator::{Notice, UvProbe, VaultAuthenticator};
use crate::log_event;
use crate::session::{STATE_ENV, Session, Settings, VAULT_ENV};

const RP_ID: &str = "example.com";
const CLIENT_DATA_HASH: [u8; 32] = [0x5a; 32];
const STATUS_OK: u8 = 0x00;
const STATUS_NOT_ALLOWED: u8 = 0x30;
#[cfg(test)]
const STATUS_NO_CREDENTIALS: u8 = 0x2e;

#[derive(Debug)]
struct ApproveAll;

impl UvProbe for ApproveAll {
    fn uv_available(&self) -> bool {
        true
    }
}

impl Approver for ApproveAll {
    fn approve(&self, ctx: &ApprovalContext<'_>) -> Result<Approval, ApprovalError> {
        Ok(Approval {
            user_present: true,
            user_verified: true,
            selected: (ctx.ceremony == Ceremony::Get).then_some(0),
        })
    }
}

#[derive(Debug)]
pub struct ScratchDir(PathBuf);

impl ScratchDir {
    pub fn new(prefix: &str) -> io::Result<ScratchDir> {
        let mut r = [0u8; 8];
        hirz_crypto::random_fill(&mut r).map_err(|_| io::Error::other("random"))?;
        let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("{prefix}-{hex}"));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(ScratchDir(path))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn settings_for(vault: &Path, state: &Path) -> Settings {
    let vault = vault.as_os_str().to_owned();
    let state = state.as_os_str().to_owned();
    Settings::from_vars(move |k| match k {
        VAULT_ENV => Some(vault.clone()),
        STATE_ENV => Some(state.clone()),
        _ => None,
    })
}

fn fail(what: &str) -> io::Error {
    io::Error::other(what.to_owned())
}

struct Host {
    stream: UnixStream,
    cid: u32,
}

impl Host {
    fn connect(stream: UnixStream) -> io::Result<Host> {
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut host = Host {
            stream,
            cid: hid::BROADCAST_CID,
        };
        let nonce = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        host.send(hid::cmd::INIT, &nonce)?;
        let reply = host.receive()?;
        if reply.get(..8) != Some(&nonce[..]) || reply.len() != 17 {
            return Err(fail("bad CTAPHID_INIT response"));
        }
        let cid: [u8; 4] = reply
            .get(8..12)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| fail("short CTAPHID_INIT response"))?;
        host.cid = u32::from_be_bytes(cid);
        Ok(host)
    }

    fn send(&mut self, command: u8, payload: &[u8]) -> io::Result<()> {
        let packets = hid::build_message(self.cid, command, payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        for p in &packets {
            self.stream.write_all(p)?;
        }
        Ok(())
    }

    fn receive(&mut self) -> io::Result<Vec<u8>> {
        let mut packet = [0u8; hid::REPORT_SIZE];
        loop {
            self.stream.read_exact(&mut packet)?;
            let Ok(hid::Packet::Init {
                cid,
                cmd,
                bcnt,
                data,
            }) = hid::parse_packet(&packet)
            else {
                return Err(fail("unexpected packet"));
            };
            if cid != self.cid {
                return Err(fail("packet on another channel"));
            }
            if cmd == hid::cmd::KEEPALIVE {
                continue;
            }
            if cmd == hid::cmd::ERROR {
                return Err(fail("CTAPHID_ERROR from the transport"));
            }
            let total = usize::from(bcnt);
            let mut message = data.get(..total.min(data.len())).unwrap_or(&[]).to_vec();
            while message.len() < total {
                self.stream.read_exact(&mut packet)?;
                let Ok(hid::Packet::Cont { data, .. }) = hid::parse_packet(&packet) else {
                    return Err(fail("expected a continuation packet"));
                };
                let want = total.saturating_sub(message.len()).min(data.len());
                message.extend_from_slice(data.get(..want).unwrap_or(&[]));
            }
            return Ok(message);
        }
    }

    fn cbor(&mut self, command: u8, params: Option<&Value>) -> io::Result<(u8, Vec<u8>)> {
        let mut request = vec![command];
        if let Some(p) = params {
            request.extend(cbor::encode(p).map_err(|_| fail("cannot encode request"))?);
        }
        self.send(hid::cmd::CBOR, &request)?;
        let response = self.receive()?;
        let (&status, body) = response
            .split_first()
            .ok_or_else(|| fail("empty CBOR response"))?;
        Ok((status, body.to_vec()))
    }
}

fn public_key_entry() -> Value {
    MapBuilder::new()
        .text("alg", -7i64)
        .text("type", "public-key")
        .build()
}

fn make_credential_params() -> Value {
    MapBuilder::new()
        .int(0x01, CLIENT_DATA_HASH.as_slice())
        .int(
            0x02,
            MapBuilder::new()
                .text("id", RP_ID)
                .text("name", "Example")
                .build(),
        )
        .int(
            0x03,
            MapBuilder::new()
                .text("id", b"alice".as_slice())
                .text("name", "alice")
                .text("displayName", "Alice")
                .build(),
        )
        .int(0x04, Value::Array(vec![public_key_entry()]))
        .int(0x07, MapBuilder::new().text("rk", true).build())
        .build()
}

fn get_assertion_params(allow: Option<&[u8]>, up: bool) -> Value {
    let mut m = MapBuilder::new()
        .int(0x01, RP_ID)
        .int(0x02, CLIENT_DATA_HASH.as_slice());
    if let Some(id) = allow {
        m = m.int(
            0x03,
            Value::Array(vec![
                MapBuilder::new()
                    .text("id", id)
                    .text("type", "public-key")
                    .build(),
            ]),
        );
    }
    if !up {
        m = m.int(0x05, MapBuilder::new().text("up", false).build());
    }
    m.build()
}

fn limits() -> Limits {
    Limits {
        max_len: hid::MAX_MESSAGE_SIZE,
        ..Limits::default()
    }
}

fn check_registration(body: &[u8]) -> io::Result<(Vec<u8>, cose::PublicKey)> {
    let att = attestation::parse_ctap(body, &limits()).map_err(|_| fail("bad attestation"))?;
    if att.fmt != attestation::FMT_NONE {
        return Err(fail("attestation format is not none"));
    }
    let ad = AuthenticatorData::parse(&att.auth_data, &limits())
        .map_err(|_| fail("bad authenticator data"))?;
    if ad.rp_id_hash != hirz_crypto::sha256(RP_ID.as_bytes())
        || ad.flags != FLAG_UP | FLAG_UV | FLAG_BE | FLAG_AT
        || ad.sign_count != 0
    {
        return Err(fail("unexpected registration authenticator data"));
    }
    let cred = ad
        .attested_credential
        .ok_or_else(|| fail("no attested credential"))?;
    if cred.aaguid != AAGUID || cred.credential_id.len() != hirz_core::CREDENTIAL_ID_LEN {
        return Err(fail("unexpected attested credential"));
    }
    let key = cbor::decode(&cred.public_key, &limits())
        .ok()
        .and_then(|v| cose::parse_public_key(&v).ok())
        .ok_or_else(|| fail("bad credential public key"))?;
    Ok((cred.credential_id, key))
}

/// Assertion: verifies the signature with `key` and returns (flags, user id, userSelected).
fn check_assertion(
    body: &[u8],
    id: &[u8],
    key: &cose::PublicKey,
) -> io::Result<(u8, Option<Vec<u8>>, bool)> {
    let v = cbor::decode(body, &limits()).map_err(|_| fail("bad assertion CBOR"))?;
    let got_id = v
        .get_int(0x01)
        .and_then(|c| c.get_text("id"))
        .and_then(Value::as_bytes);
    if got_id != Some(id) {
        return Err(fail("assertion for another credential"));
    }
    let auth_data = v
        .get_int(0x02)
        .and_then(Value::as_bytes)
        .ok_or_else(|| fail("no authenticator data"))?;
    let signature = v
        .get_int(0x03)
        .and_then(Value::as_bytes)
        .ok_or_else(|| fail("no signature"))?;
    let ad = AuthenticatorData::parse(auth_data, &limits())
        .map_err(|_| fail("bad authenticator data"))?;
    if ad.rp_id_hash != hirz_crypto::sha256(RP_ID.as_bytes()) || ad.attested_credential.is_some() {
        return Err(fail("unexpected assertion authenticator data"));
    }
    let mut message = auth_data.to_vec();
    message.extend_from_slice(&CLIENT_DATA_HASH);
    let verified = match key {
        cose::PublicKey::Es256 { x, y } => hirz_crypto::es256::verify(x, y, &message, signature),
        cose::PublicKey::Ed25519 { x } => <[u8; 64]>::try_from(signature)
            .map_err(|_| hirz_crypto::CryptoError::Invalid)
            .and_then(|s| hirz_crypto::ed25519::verify(x, &message, &s)),
    };
    verified.map_err(|_| fail("signature does not verify"))?;
    let user = v
        .get_int(0x04)
        .and_then(|u| u.get_text("id"))
        .and_then(Value::as_bytes)
        .map(<[u8]>::to_vec);
    let selected = v.get_int(0x06).and_then(Value::as_bool).unwrap_or(false);
    Ok((ad.flags, user, selected))
}

fn expect(cond: bool, what: &str) -> io::Result<()> {
    if cond { Ok(()) } else { Err(fail(what)) }
}

fn with_daemon<A: Approver + UvProbe + Send + 'static>(
    authenticator: VaultAuthenticator<A>,
    script: impl FnOnce(&mut Host) -> io::Result<()>,
) -> io::Result<()> {
    let (daemon_end, host_end) = UnixStream::pair()?;
    let handler = Arc::new(Ctap2Handler::new(authenticator));
    let worker = std::thread::spawn(move || {
        let mut io = StreamReportIo::new(daemon_end);
        hid::run(&mut io, handler, hid::Config::default(), log_event)
    });
    let result = Host::connect(host_end).and_then(|mut host| script(&mut host));
    // Dropping the host end closes the socket and ends the transport loop.
    let joined = worker.join().map_err(|_| fail("transport thread failed"))?;
    result?;
    joined
}

pub fn run() -> io::Result<()> {
    let dir = ScratchDir::new("hirzd-self-test")?;
    let vault_dir = dir.path().join("vault");
    let state_dir = dir.path().join("state");
    Vault::create(&vault_dir, &state_dir, "self-test")
        .map_err(|e| io::Error::other(format!("cannot create the test vault: {e}")))?;
    let session = Session::new(settings_for(&vault_dir, &state_dir), ApproveAll);

    with_daemon(
        VaultAuthenticator::new(session, Notice::new(false)),
        |host| {
            let (status, body) = host.cbor(0x04, None)?;
            let mut info = vec![status];
            info.extend_from_slice(&body);
            expect(info == get_info_response(), "unexpected getInfo")?;

            let (status, body) = host.cbor(0x01, Some(&make_credential_params()))?;
            expect(status == STATUS_OK, "makeCredential failed")?;
            let (id, key) = check_registration(&body)?;

            let (status, body) = host.cbor(0x02, Some(&get_assertion_params(Some(&id), true)))?;
            expect(status == STATUS_OK, "getAssertion failed")?;
            let (flags, _, selected) = check_assertion(&body, &id, &key)?;
            expect(
                flags == FLAG_UP | FLAG_UV | FLAG_BE && !selected,
                "unexpected assertion flags",
            )?;

            let (status, body) = host.cbor(0x02, Some(&get_assertion_params(None, true)))?;
            expect(status == STATUS_OK, "discoverable getAssertion failed")?;
            let (flags, user, selected) = check_assertion(&body, &id, &key)?;
            expect(
                flags == FLAG_UP | FLAG_UV | FLAG_BE
                    && user.as_deref() == Some(b"alice".as_slice())
                    && selected,
                "unexpected discoverable assertion",
            )?;

            let (status, body) = host.cbor(0x02, Some(&get_assertion_params(Some(&id), false)))?;
            expect(status == STATUS_OK, "silent probe failed")?;
            let (flags, _, _) = check_assertion(&body, &id, &key)?;
            expect(
                flags == FLAG_BE,
                "silent probe must sign with UP=0 and UV=0",
            )
        },
    )?;

    let empty = dir.path().join("empty");
    let session = Session::new(settings_for(&empty.join("vault"), &empty), ApproveAll);
    with_daemon(
        VaultAuthenticator::new(session, Notice::new(false)),
        |host| {
            let (status, _) = host.cbor(0x01, Some(&make_credential_params()))?;
            expect(
                status == STATUS_NOT_ALLOWED,
                "makeCredential without a vault must be denied",
            )
        },
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::session::Hold;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn loopback_self_test_passes() {
        run().unwrap();
    }

    #[derive(Debug, Clone, Default)]
    struct CountingLauncher(Arc<AtomicU32>, Arc<std::sync::Mutex<Vec<String>>>);

    impl crate::session::SetupLauncher for CountingLauncher {
        fn can_draw(&self) -> bool {
            true
        }
        fn launch(&self, _: &Path, _: &Path) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn notify(&self, text: &str) {
            self.1.lock().unwrap().push(text.to_owned());
        }
    }

    /// Approves like [`ApproveAll`] and counts the approvals.
    #[derive(Debug, Clone, Default)]
    struct Counted(Arc<AtomicU32>);

    impl UvProbe for Counted {
        fn uv_available(&self) -> bool {
            true
        }
    }

    impl Approver for Counted {
        fn approve(&self, ctx: &ApprovalContext<'_>) -> Result<Approval, ApprovalError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            ApproveAll.approve(ctx)
        }
    }

    const SHORT: Hold = Hold {
        limit: Duration::from_millis(60),
        poll: Duration::from_millis(10),
    };
    const LONG: Hold = Hold {
        limit: Duration::from_secs(20),
        poll: Duration::from_millis(10),
    };

    struct Setup {
        dir: ScratchDir,
        vault: PathBuf,
        state: PathBuf,
        runtime: PathBuf,
    }

    impl Setup {
        fn new(tag: &str) -> Setup {
            let dir = ScratchDir::new(tag).unwrap();
            let (vault, state, runtime) = (
                dir.path().join("vault"),
                dir.path().join("state"),
                dir.path().join("run"),
            );
            Setup {
                dir,
                vault,
                state,
                runtime,
            }
        }

        fn handler(
            &self,
            l: &CountingLauncher,
            approver: Counted,
            hold: Hold,
        ) -> Ctap2Handler<VaultAuthenticator<Counted, CountingLauncher>> {
            let _ = self.dir.path();
            let session = Session::new(settings_for(&self.vault, &self.state), approver);
            let first_run = crate::session::FirstRun::new(
                Some(self.runtime.clone()),
                Some(self.state.clone()),
                true,
                Some(PathBuf::from("/usr/bin/hirz")),
                l.clone(),
            );
            Ctap2Handler::new(
                VaultAuthenticator::new(session, Notice::new(false))
                    .with_first_run(first_run)
                    .with_hold(hold),
            )
        }
    }

    fn request(cmd: u8, params: Option<Value>) -> Vec<u8> {
        let mut r = vec![cmd];
        if let Some(p) = params {
            r.extend(cbor::encode(&p).unwrap());
        }
        r
    }

    fn probe() -> Vec<u8> {
        request(0x02, Some(get_assertion_params(Some(&[1u8; 32]), false)))
    }

    fn make() -> Vec<u8> {
        request(0x01, Some(make_credential_params()))
    }

    #[test]
    fn without_a_vault_requests_that_ask_the_user_open_one_setup_window() {
        let t = Setup::new("hirzd-first-run");
        let launcher = CountingLauncher::default();
        let get = request(0x02, Some(get_assertion_params(None, true)));
        let select = request(0x0b, None);

        let h = t.handler(&launcher, Counted::default(), SHORT);
        for _ in 0..50 {
            let ctx = hid::RequestContext::new();
            assert_eq!(h.process(&probe(), &ctx), vec![STATUS_NOT_ALLOWED]);
        }
        assert_eq!(launcher.0.load(Ordering::SeqCst), 0, "silent probes");
        for _ in 0..20 {
            for (r, status) in [
                (&make(), STATUS_NOT_ALLOWED),
                (&get, STATUS_NO_CREDENTIALS),
                (&select, STATUS_NOT_ALLOWED),
            ] {
                let ctx = hid::RequestContext::new();
                assert_eq!(h.process(r, &ctx), vec![status]);
            }
        }
        assert_eq!(launcher.0.load(Ordering::SeqCst), 1, "one window per burst");

        for (cmd, status) in [
            (&make(), STATUS_NOT_ALLOWED),
            (&get, STATUS_NO_CREDENTIALS),
            (&select, STATUS_NOT_ALLOWED),
        ] {
            let l = CountingLauncher::default();
            let ctx = hid::RequestContext::new();
            let h = t.handler(&l, Counted::default(), SHORT);
            assert_eq!(h.process(cmd, &ctx), vec![status]);
            assert_eq!(l.0.load(Ordering::SeqCst), 1, "request {:#04x}", cmd[0]);
            assert!(l.1.lock().unwrap().is_empty(), "the window is the feedback");
        }

        let held = hirz_uv::first_run::try_lock(&t.runtime).unwrap().unwrap();
        let l = CountingLauncher::default();
        let ctx = hid::RequestContext::new();
        let h = t.handler(&l, Counted::default(), SHORT);
        assert_eq!(h.process(&make(), &ctx), vec![STATUS_NOT_ALLOWED]);
        assert_eq!(l.0.load(Ordering::SeqCst), 0, "a setup window is open");
        assert!(
            hirz_uv::first_run::take_waiter_gone(&t.runtime),
            "the registration waited"
        );
        let long = t.handler(&l, Counted::default(), LONG);
        let started = std::time::Instant::now();
        assert_eq!(long.process(&get, &ctx), vec![STATUS_NO_CREDENTIALS]);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a sign-in never waits"
        );
        assert!(!hirz_uv::first_run::take_waiter_gone(&t.runtime));
        assert!(l.1.lock().unwrap().is_empty());
        drop(held);
        hirz_uv::first_run::mark_cancelled(&t.runtime, hirz_proto::time::unix_now()).unwrap();
        assert_eq!(h.process(&make(), &ctx), vec![STATUS_NOT_ALLOWED]);
        assert_eq!(
            l.0.load(Ordering::SeqCst),
            0,
            "the user cancelled a moment ago"
        );
    }

    #[test]
    fn a_held_request_goes_on_with_the_normal_approval_once_setup_is_done() {
        let t = Setup::new("hirzd-hold");
        let held = hirz_uv::first_run::try_lock(&t.runtime).unwrap().unwrap();
        let approvals = Counted::default();
        let h = Arc::new(t.handler(&CountingLauncher::default(), approvals.clone(), LONG));
        let started = std::time::Instant::now();
        let ctx = hid::RequestContext::new();
        assert_eq!(h.process(&probe(), &ctx)[0], STATUS_NOT_ALLOWED);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "probes never hold"
        );
        // Like an approval, a held request keeps the engine; the transport runs one request at a
        // time, so nothing else waits behind it.
        let worker = {
            let h = Arc::clone(&h);
            std::thread::spawn(move || h.process(&make(), &hid::RequestContext::new()))
        };
        std::thread::sleep(Duration::from_millis(100));
        Vault::create(&t.vault, &t.state, "laptop").unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !worker.is_finished(),
            "nothing is used before the window closes"
        );
        assert_eq!(approvals.0.load(Ordering::SeqCst), 0);
        drop(held);
        let response = worker.join().unwrap();
        assert_eq!(response[0], STATUS_OK);
        assert_eq!(approvals.0.load(Ordering::SeqCst), 1, "approved as usual");
        let stored = Vault::open(&t.vault, &t.state).unwrap();
        assert_eq!(stored.list_all().len(), 1);
        assert!(!hirz_uv::first_run::take_waiter_gone(&t.runtime));
    }

    #[test]
    fn a_held_request_fails_on_cancel_or_time_and_the_window_tells_later() {
        let t = Setup::new("hirzd-hold-end");
        let held = hirz_uv::first_run::try_lock(&t.runtime).unwrap().unwrap();
        let approvals = Counted::default();
        let h = Arc::new(t.handler(&CountingLauncher::default(), approvals.clone(), LONG));
        let ctx = hid::RequestContext::new();
        let worker = {
            let (h, ctx) = (Arc::clone(&h), ctx.clone());
            std::thread::spawn(move || h.process(&make(), &ctx))
        };
        std::thread::sleep(Duration::from_millis(100));
        ctx.cancel();
        let started = std::time::Instant::now();
        assert_eq!(worker.join().unwrap(), vec![0x2d], "KEEPALIVE_CANCEL");
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(hirz_uv::first_run::take_waiter_gone(&t.runtime));

        let h = t.handler(&CountingLauncher::default(), approvals.clone(), SHORT);
        let ctx = hid::RequestContext::new();
        assert_eq!(h.process(&make(), &ctx), vec![STATUS_NOT_ALLOWED]);
        assert!(
            hirz_uv::first_run::take_waiter_gone(&t.runtime),
            "timed out"
        );
        drop(held);
        assert_eq!(approvals.0.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_sign_in_without_a_passkey_for_the_site_is_told_once_a_minute() {
        let t = Setup::new("hirzd-no-passkey");
        Vault::create(&t.vault, &t.state, "laptop").unwrap();
        let l = CountingLauncher::default();
        let h = t.handler(&l, Counted::default(), SHORT);
        let sign_in = request(0x02, Some(get_assertion_params(Some(&[9u8; 32]), true)));
        for _ in 0..5 {
            let ctx = hid::RequestContext::new();
            assert_eq!(h.process(&sign_in, &ctx), vec![0x2e], "NO_CREDENTIALS");
            assert_eq!(h.process(&probe(), &ctx), vec![0x2e]);
        }
        assert_eq!(
            l.1.lock().unwrap().as_slice(),
            ["hirz has no passkey for example.com."]
        );
    }

    /// Declines every approval and counts them.
    #[derive(Debug, Clone, Default)]
    struct Declines(Arc<AtomicU32>);

    impl UvProbe for Declines {
        fn uv_available(&self) -> bool {
            true
        }
    }

    impl Approver for Declines {
        fn approve(&self, _: &ApprovalContext<'_>) -> Result<Approval, ApprovalError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(ApprovalError::Denied)
        }
    }

    #[test]
    fn a_decline_ends_the_ceremony_in_chrome_and_in_firefox() {
        let dir = ScratchDir::new("hirzd-decline").unwrap();
        let (vault_dir, state_dir) = (dir.path().join("vault"), dir.path().join("state"));
        Vault::create(&vault_dir, &state_dir, "test").unwrap();
        let asked = Declines::default();
        let session = Session::new(settings_for(&vault_dir, &state_dir), asked.clone());
        let h = Ctap2Handler::new(VaultAuthenticator::new(session, Notice::new(false)));
        let make = request(0x01, Some(make_credential_params()));
        let ctx = hid::RequestContext::new();
        assert_eq!(h.process(&make, &ctx), vec![0x27], "OPERATION_DENIED");
        assert_eq!(
            h.process(&make, &ctx),
            vec![STATUS_NOT_ALLOWED],
            "Firefox resends the same request at once"
        );
        assert_eq!(
            asked.0.load(Ordering::SeqCst),
            1,
            "and nobody is asked again"
        );
        assert!(
            Vault::open(&vault_dir, &state_dir)
                .unwrap()
                .list_all()
                .is_empty()
        );
    }

    #[test]
    fn touch_requests_store_nothing() {
        let dir = ScratchDir::new("hirzd-test").unwrap();
        let (vault_dir, state_dir) = (dir.path().join("vault"), dir.path().join("state"));
        Vault::create(&vault_dir, &state_dir, "test").unwrap();
        let session = Session::new(settings_for(&vault_dir, &state_dir), ApproveAll);
        let handler = Ctap2Handler::new(VaultAuthenticator::new(session, Notice::new(false)));
        for rp in ["make.me.blink", ".dummy"] {
            let params = MapBuilder::new()
                .int(0x01, CLIENT_DATA_HASH.as_slice())
                .int(0x02, MapBuilder::new().text("id", rp).build())
                .int(0x03, MapBuilder::new().text("id", [0u8].as_slice()).build())
                .int(0x04, Value::Array(vec![public_key_entry()]))
                .build();
            let mut request = vec![0x01];
            request.extend(cbor::encode(&params).unwrap());
            let ctx = hid::RequestContext::new();
            assert_eq!(handler.process(&request, &ctx), vec![STATUS_NOT_ALLOWED]);
        }
        assert!(
            Vault::open(&vault_dir, &state_dir)
                .unwrap()
                .list_all()
                .is_empty()
        );
    }

    struct Counting(Arc<std::sync::atomic::AtomicUsize>);

    impl UvProbe for Counting {
        fn uv_available(&self) -> bool {
            true
        }
    }

    impl Approver for Counting {
        fn approve(&self, ctx: &ApprovalContext<'_>) -> Result<Approval, ApprovalError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            ApproveAll.approve(ctx)
        }
        fn confirm_selection(&self) -> Result<Approval, ApprovalError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            ApproveAll.confirm_selection()
        }
    }

    #[test]
    fn machine_login_rp_ids_are_refused_without_a_prompt() {
        let dir = ScratchDir::new("hirzd-test").unwrap();
        let (vault_dir, state_dir) = (dir.path().join("vault"), dir.path().join("state"));
        Vault::create(&vault_dir, &state_dir, "test").unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let session = Session::new(
            settings_for(&vault_dir, &state_dir),
            Counting(Arc::clone(&calls)),
        );
        let handler = Ctap2Handler::new(VaultAuthenticator::new(session, Notice::new(false)));
        let ctx = hid::RequestContext::new();
        for rp in ["pam://laptop", "io.systemd.home", "io.systemd.cryptsetup"] {
            let params = MapBuilder::new()
                .int(0x01, CLIENT_DATA_HASH.as_slice())
                .int(0x02, MapBuilder::new().text("id", rp).build())
                .int(0x03, MapBuilder::new().text("id", [1u8].as_slice()).build())
                .int(0x04, Value::Array(vec![public_key_entry()]))
                .build();
            let mut request = vec![0x01];
            request.extend(cbor::encode(&params).unwrap());
            assert_eq!(handler.process(&request, &ctx), vec![STATUS_NOT_ALLOWED]);
            for up in [true, false] {
                let p = MapBuilder::new()
                    .int(0x01, rp)
                    .int(0x02, CLIENT_DATA_HASH.as_slice())
                    .int(0x05, MapBuilder::new().text("up", up).build())
                    .build();
                let mut request = vec![0x02];
                request.extend(cbor::encode(&p).unwrap());
                assert_eq!(handler.process(&request, &ctx), vec![STATUS_NOT_ALLOWED]);
            }
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(
            Vault::open(&vault_dir, &state_dir)
                .unwrap()
                .list_all()
                .is_empty()
        );
    }

    fn import_es256(vault_dir: &Path, state_dir: &Path, id: &[u8]) -> cose::PublicKey {
        let (pkcs8, x, y) = hirz_crypto::es256::generate().unwrap();
        let mut vault = Vault::open(vault_dir, state_dir).unwrap();
        vault
            .put(hirz_vault::CredentialRecord {
                credential_id: id.to_vec(),
                rp_id: RP_ID.to_owned(),
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
        cose::PublicKey::Es256 { x, y }
    }

    fn get_assertion<A: Approver + UvProbe + Send>(
        handler: &Ctap2Handler<VaultAuthenticator<A>>,
        p: &Value,
    ) -> Vec<u8> {
        let mut request = vec![0x02];
        request.extend(cbor::encode(p).unwrap());
        handler.process(&request, &hid::RequestContext::new())
    }

    #[test]
    fn imported_credential_with_a_16_byte_id_signs_over_ctap() {
        let dir = ScratchDir::new("hirzd-test").unwrap();
        let (vault_dir, state_dir) = (dir.path().join("vault"), dir.path().join("state"));
        Vault::create(&vault_dir, &state_dir, "test").unwrap();
        let id: Vec<u8> = (0x40..0x50).collect();
        let key = import_es256(&vault_dir, &state_dir, &id);
        let session = Session::new(settings_for(&vault_dir, &state_dir), ApproveAll);
        let handler = Ctap2Handler::new(VaultAuthenticator::new(session, Notice::new(false)));

        for (allow, up) in [
            (Some(id.as_slice()), true),
            (None, true),
            (Some(&id), false),
        ] {
            let reply = get_assertion(&handler, &get_assertion_params(allow, up));
            let (status, body) = reply.split_first().unwrap();
            assert_eq!(*status, STATUS_OK, "allow {allow:?} up {up}");
            let (flags, _, _) = check_assertion(body, &id, &key).unwrap();
            assert_eq!(flags & FLAG_UP != 0, up);
        }

        // A 32-byte id that starts with the imported one is a different credential.
        let mut longer = id.clone();
        longer.extend_from_slice(&[0; 16]);
        let reply = get_assertion(&handler, &get_assertion_params(Some(&longer), true));
        assert_eq!(reply, vec![0x2e]);
    }

    #[test]
    fn silent_probes_do_not_scan_the_vault_folder_every_time() {
        let dir = ScratchDir::new("hirzd-test").unwrap();
        let (vault_dir, state_dir) = (dir.path().join("vault"), dir.path().join("state"));
        Vault::create(&vault_dir, &state_dir, "test").unwrap();
        let session = Session::new(settings_for(&vault_dir, &state_dir), ApproveAll);
        let handler = Ctap2Handler::new(VaultAuthenticator::new(session, Notice::new(false)));

        let id: Vec<u8> = (0x40..0x50).collect();
        let reply = get_assertion(&handler, &get_assertion_params(Some(&id), false));
        assert_eq!(reply, vec![0x2e], "nothing there yet");
        let key = import_es256(&vault_dir, &state_dir, &id);

        for _ in 0..20 {
            let reply = get_assertion(&handler, &get_assertion_params(Some(&id), false));
            assert_eq!(
                reply,
                vec![0x2e],
                "a probe in the window answers from the last look, without a scan"
            );
        }

        let reply = get_assertion(&handler, &get_assertion_params(Some(&id), true));
        let (status, body) = reply.split_first().unwrap();
        assert_eq!(
            *status, STATUS_OK,
            "a request that asks the user always looks"
        );
        check_assertion(body, &id, &key).unwrap();
        let reply = get_assertion(&handler, &get_assertion_params(Some(&id), false));
        assert_eq!(reply.first(), Some(&STATUS_OK));
    }

    #[test]
    fn cancelled_requests_are_not_started() {
        let dir = ScratchDir::new("hirzd-test").unwrap();
        let (vault_dir, state_dir) = (dir.path().join("vault"), dir.path().join("state"));
        Vault::create(&vault_dir, &state_dir, "test").unwrap();
        let session = Session::new(settings_for(&vault_dir, &state_dir), ApproveAll);
        let handler = Ctap2Handler::new(VaultAuthenticator::new(session, Notice::new(false)));
        let ctx = hid::RequestContext::new();
        ctx.cancel();
        let mut request = vec![0x01];
        request.extend(cbor::encode(&make_credential_params()).unwrap());
        assert_eq!(handler.process(&request, &ctx), vec![0x2d]);
        assert!(
            Vault::open(&vault_dir, &state_dir)
                .unwrap()
                .list_all()
                .is_empty()
        );
    }

    #[test]
    fn removed_device_stops_serving() {
        let dir = ScratchDir::new("hirzd-test").unwrap();
        let vault_dir = dir.path().join("vault");
        let (a_state, b_state) = (dir.path().join("a"), dir.path().join("b"));
        let (mut a, phrase) = Vault::create(&vault_dir, &a_state, "a").unwrap();
        let b = Vault::join_with_recovery(&vault_dir, &b_state, &phrase, "b").unwrap();
        let id: Vec<u8> = (0x40..0x50).collect();
        let key = import_es256(&vault_dir, &a_state, &id);
        let session = Session::new(settings_for(&vault_dir, &b_state), ApproveAll);
        let handler = Ctap2Handler::new(VaultAuthenticator::new(session, Notice::new(false)));

        let reply = get_assertion(&handler, &get_assertion_params(Some(&id), true));
        let (status, body) = reply.split_first().unwrap();
        assert_eq!(*status, STATUS_OK);
        check_assertion(body, &id, &key).unwrap();

        a.reload().unwrap();
        a.remove_device(&b.device_id()).unwrap();
        for up in [true, false] {
            let reply = get_assertion(&handler, &get_assertion_params(Some(&id), up));
            assert_eq!(reply, vec![STATUS_NOT_ALLOWED]);
        }
        let mut request = vec![0x01];
        request.extend(cbor::encode(&make_credential_params()).unwrap());
        assert_eq!(
            handler.process(&request, &hid::RequestContext::new()),
            vec![STATUS_NOT_ALLOWED]
        );
        assert_eq!(
            Vault::open(&vault_dir, &a_state).unwrap().list_all().len(),
            1
        );
    }

    #[test]
    fn a_fork_refuses_new_passkeys_without_a_prompt_and_keeps_signing_in() {
        let dir = ScratchDir::new("hirzd-test").unwrap();
        let vault_dir = dir.path().join("vault");
        let (a_state, b_state) = (dir.path().join("a"), dir.path().join("b"));
        let (mut a, phrase) = Vault::create(&vault_dir, &a_state, "a").unwrap();
        let b = Vault::join_with_recovery(&vault_dir, &b_state, &phrase, "b").unwrap();
        let id: Vec<u8> = (0x40..0x50).collect();
        let key = import_es256(&vault_dir, &a_state, &id);
        a.reload().unwrap();
        a.remove_device(&b.device_id()).unwrap();
        let name = std::fs::read_dir(vault_dir.join("keys"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .find(|n| n.starts_with("0000000002-"))
            .unwrap();
        let from = vault_dir.join("keys").join(&name);
        let to = vault_dir.join(format!(".hidden-{name}"));
        std::fs::rename(&from, &to).unwrap();

        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let session = Session::new(
            settings_for(&vault_dir, &a_state),
            Counting(Arc::clone(&calls)),
        );
        let handler = Ctap2Handler::new(VaultAuthenticator::new(session, Notice::new(false)));
        let ctx = hid::RequestContext::new();
        let mut request = vec![0x01];
        request.extend(cbor::encode(&make_credential_params()).unwrap());
        for _ in 0..2 {
            assert_eq!(handler.process(&request, &ctx), vec![STATUS_NOT_ALLOWED]);
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);

        let reply = get_assertion(&handler, &get_assertion_params(Some(&id), true));
        let (status, body) = reply.split_first().unwrap();
        assert_eq!(*status, STATUS_OK);
        check_assertion(body, &id, &key).unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

        std::fs::rename(&to, &from).unwrap();
        let reply = handler.process(&request, &ctx);
        assert_eq!(reply.first(), Some(&STATUS_OK));
    }
}
