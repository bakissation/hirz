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

use crate::authenticator::{Notice, VaultAuthenticator};
use crate::log_event;
use crate::session::{STATE_ENV, Session, Settings, VAULT_ENV};

const RP_ID: &str = "example.com";
const CLIENT_DATA_HASH: [u8; 32] = [0x5a; 32];
const STATUS_OK: u8 = 0x00;
const STATUS_NOT_ALLOWED: u8 = 0x30;

#[derive(Debug)]
struct ApproveAll;

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

fn with_daemon<A: Approver + Send + 'static>(
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn loopback_self_test_passes() {
        run().unwrap();
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
        let rp = "pam://laptop";
        let params = MapBuilder::new()
            .int(0x01, CLIENT_DATA_HASH.as_slice())
            .int(0x02, MapBuilder::new().text("id", rp).build())
            .int(0x03, MapBuilder::new().text("id", [1u8].as_slice()).build())
            .int(0x04, Value::Array(vec![public_key_entry()]))
            .build();
        let mut request = vec![0x01];
        request.extend(cbor::encode(&params).unwrap());
        let ctx = hid::RequestContext::new();
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

    fn get_assertion(handler: &Ctap2Handler<VaultAuthenticator<ApproveAll>>, p: &Value) -> Vec<u8> {
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
}
