#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use super::Engine;
use crate::types::*;
use hirz_proto::auth_data::{
    AuthenticatorData, FLAG_AT, FLAG_BE, FLAG_BS, FLAG_ED, FLAG_UP, FLAG_UV,
};
use hirz_proto::cbor::{self, Limits, Value};
use hirz_proto::cose::{self, PublicKey};
use hirz_vault::Vault;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs;
use std::path::PathBuf;

const RP: &str = "example.com";
const HASH: [u8; 32] = [0x42; 32];

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> TempDir {
        let mut r = [0u8; 8];
        hirz_crypto::random_fill(&mut r).unwrap();
        let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
        let p = std::env::temp_dir().join(format!("hirz-core-test-{hex}"));
        fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    fn path(&self, sub: &str) -> PathBuf {
        self.0.join(sub)
    }
    fn vault(&self) -> Vault {
        Vault::create(&self.path("vault"), &self.path("state"), "laptop")
            .unwrap()
            .0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug, Clone)]
struct Seen {
    ceremony: Ceremony,
    rp_id: String,
    uv_required: bool,
    candidates: Vec<Vec<u8>>,
    new_account: Option<Vec<u8>>,
    origin: Option<String>,
}

#[derive(Default)]
struct Fake {
    script: RefCell<VecDeque<Result<Approval, ApprovalError>>>,
    seen: RefCell<Vec<Seen>>,
    selections: RefCell<VecDeque<Result<Approval, ApprovalError>>>,
}

impl Fake {
    fn with(script: Vec<Result<Approval, ApprovalError>>) -> Fake {
        let f = Fake::default();
        f.script.borrow_mut().extend(script);
        f
    }
    fn push(&self, r: Result<Approval, ApprovalError>) {
        self.script.borrow_mut().push_back(r);
    }
    fn calls(&self) -> usize {
        self.seen.borrow().len()
    }
    fn last(&self) -> Seen {
        self.seen.borrow().last().cloned().unwrap()
    }
}

impl Approver for Fake {
    fn approve(&self, ctx: &ApprovalContext<'_>) -> Result<Approval, ApprovalError> {
        self.seen.borrow_mut().push(Seen {
            ceremony: ctx.ceremony,
            rp_id: ctx.rp_id.to_owned(),
            uv_required: ctx.uv_required,
            candidates: ctx
                .candidates
                .iter()
                .map(|c| c.credential_id.clone())
                .collect(),
            new_account: ctx.new_account.map(|u| u.id.clone()),
            origin: ctx.origin.map(str::to_owned),
        });
        self.script
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| Err(ApprovalError::Internal("unscripted".into())))
    }

    fn confirm_selection(&self) -> Result<Approval, ApprovalError> {
        self.selections
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| Err(ApprovalError::Internal("unscripted".into())))
    }
}

struct Minimal;

impl Approver for Minimal {
    fn approve(&self, _: &ApprovalContext<'_>) -> Result<Approval, ApprovalError> {
        Ok(up())
    }
}

fn up() -> Approval {
    Approval {
        user_present: true,
        user_verified: false,
        selected: None,
    }
}

fn uv() -> Approval {
    Approval {
        user_present: true,
        user_verified: true,
        selected: None,
    }
}

fn pick(i: usize, verified: bool) -> Approval {
    Approval {
        user_present: true,
        user_verified: verified,
        selected: Some(i),
    }
}

fn make_req(user: &str, algorithms: &[i64]) -> MakeCredentialRequest {
    MakeCredentialRequest {
        client_data_hash: HASH,
        rp: RpEntity {
            id: RP.to_owned(),
            name: Some("Example".to_owned()),
        },
        user: UserEntity {
            id: user.as_bytes().to_vec(),
            name: Some(user.to_owned()),
            display_name: Some(format!("{user} display")),
        },
        algorithms: algorithms.to_vec(),
        exclude_list: Vec::new(),
        resident_key: true,
        uv: UvRequirement::Preferred,
        extensions: MakeExtensions::default(),
    }
}

fn get_req(allow: &[&[u8]]) -> GetAssertionRequest {
    GetAssertionRequest {
        client_data_hash: HASH,
        rp_id: RP.to_owned(),
        allow_list: allow.iter().map(|a| a.to_vec()).collect(),
        uv: UvRequirement::Preferred,
        up: true,
        extensions: GetExtensions::default(),
    }
}

fn parse(ad: &[u8]) -> AuthenticatorData {
    AuthenticatorData::parse(ad, &Limits::default()).unwrap()
}

fn public_key(resp: &MakeCredentialResponse) -> PublicKey {
    let v = cbor::decode(&resp.public_key_cose, &Limits::default()).unwrap();
    cose::parse_public_key(&v).unwrap()
}

fn verify(key: &PublicKey, a: &AssertionResponse) {
    let mut msg = a.auth_data.clone();
    msg.extend_from_slice(&HASH);
    match key {
        PublicKey::Es256 { x, y } => hirz_crypto::es256::verify(x, y, &msg, &a.signature).unwrap(),
        PublicKey::Ed25519 { x } => {
            let sig: [u8; 64] = a.signature.as_slice().try_into().unwrap();
            hirz_crypto::ed25519::verify(x, &msg, &sig).unwrap()
        }
    }
}

fn create(vault: &mut Vault, req: &MakeCredentialRequest, a: Approval) -> MakeCredentialResponse {
    let fake = Fake::with(vec![Ok(a)]);
    Engine::new(vault, &fake)
        .make_credential(req, None)
        .unwrap()
}

fn assert_with(
    vault: &mut Vault,
    req: &GetAssertionRequest,
    a: Approval,
) -> Result<AssertionResponse, CoreError> {
    let fake = Fake::with(vec![Ok(a)]);
    Engine::new(vault, &fake).get_assertion(req, None, None)
}

#[test]
fn create_and_assert_es256_and_ed25519() {
    for alg in [COSE_ALG_ES256, COSE_ALG_EDDSA] {
        let t = TempDir::new();
        let mut vault = t.vault();
        let fake = Fake::with(vec![Ok(up())]);
        let mut engine = Engine::new(&mut vault, &fake).with_clock(|| 1_700_000_000);
        let req = make_req("alice", &[-257, alg]);
        let made = engine
            .make_credential(&req, Some("https://example.com"))
            .unwrap();
        assert_eq!(made.algorithm, alg);
        assert_eq!(made.credential_id.len(), CREDENTIAL_ID_LEN);
        assert!(made.resident_key);
        assert!(!made.hmac_secret);
        let s = fake.last();
        assert_eq!(s.ceremony, Ceremony::Create);
        assert_eq!(s.rp_id, RP);
        assert!(!s.uv_required);
        assert_eq!(s.new_account.as_deref(), Some(&b"alice"[..]));
        assert_eq!(s.origin.as_deref(), Some("https://example.com"));

        let ad = parse(&made.auth_data);
        assert_eq!(ad.rp_id_hash, hirz_crypto::sha256(RP.as_bytes()));
        assert_eq!(ad.flags, FLAG_UP | FLAG_BE | FLAG_AT);
        assert_eq!(ad.sign_count, 0);
        assert!(ad.extensions.is_none());
        let att = ad.attested_credential.unwrap();
        assert_eq!(att.aaguid, AAGUID);
        assert_eq!(att.credential_id, made.credential_id);
        assert_eq!(att.public_key, made.public_key_cose);
        match (alg, public_key(&made)) {
            (COSE_ALG_ES256, PublicKey::Es256 { .. })
            | (COSE_ALG_EDDSA, PublicKey::Ed25519 { .. }) => {}
            other => panic!("unexpected key {other:?}"),
        }
        let rec = engine.vault().get(&made.credential_id).unwrap();
        assert_eq!(rec.created_at, 1_700_000_000);
        assert!(rec.discoverable && rec.backup_eligible);
        assert_eq!(rec.user_name.as_deref(), Some("alice"));

        fake.push(Ok(up()));
        let a = engine
            .get_assertion(&get_req(&[&made.credential_id]), None, None)
            .unwrap();
        let s = fake.last();
        assert_eq!(s.ceremony, Ceremony::Get);
        assert_eq!(s.candidates, vec![made.credential_id.clone()]);
        assert_eq!(a.credential_id, made.credential_id);
        assert_eq!(a.user_handle, b"alice");
        assert!(a.user.is_none());
        assert!(a.hmac_secret_output.is_none());
        let ad = parse(&a.auth_data);
        assert_eq!(a.auth_data.len(), 37);
        assert_eq!(ad.rp_id_hash, hirz_crypto::sha256(RP.as_bytes()));
        assert_eq!(ad.flags, FLAG_UP | FLAG_BE);
        assert_eq!(ad.sign_count, 0);
        verify(&public_key(&made), &a);
    }
}

#[test]
fn algorithm_choice_follows_rp_order() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let made = create(&mut vault, &make_req("alice", &[-8, -7]), up());
    assert_eq!(made.algorithm, COSE_ALG_EDDSA);
    let fake = Fake::with(vec![Ok(up())]);
    let r = Engine::new(&mut vault, &fake).make_credential(&make_req("bob", &[-257, -35]), None);
    assert_eq!(r, Err(CoreError::UnsupportedAlgorithm));
    assert_eq!(fake.calls(), 0);
}

#[test]
fn uv_flag_only_after_verified_approval() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let made = create(&mut vault, &make_req("alice", &[-7]), uv());
    assert_eq!(
        parse(&made.auth_data).flags,
        FLAG_UP | FLAG_UV | FLAG_BE | FLAG_AT
    );
    let a = assert_with(&mut vault, &get_req(&[]), uv()).unwrap();
    assert_eq!(parse(&a.auth_data).flags, FLAG_UP | FLAG_UV | FLAG_BE);
    let user = a.user.unwrap();
    assert_eq!(user.id, b"alice");
    assert_eq!(user.name.as_deref(), Some("alice"));
    assert_eq!(user.display_name.as_deref(), Some("alice display"));
    let a = assert_with(&mut vault, &get_req(&[]), up()).unwrap();
    assert_eq!(parse(&a.auth_data).flags, FLAG_UP | FLAG_BE);
    let user = a.user.unwrap();
    assert_eq!(user.id, b"alice");
    assert!(user.name.is_none() && user.display_name.is_none());
}

#[test]
fn backup_state_after_confirmed_backup() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let made = create(&mut vault, &make_req("alice", &[-7]), up());
    assert_eq!(parse(&made.auth_data).flags & FLAG_BS, 0);
    let a = assert_with(&mut vault, &get_req(&[]), up()).unwrap();
    assert_eq!(parse(&a.auth_data).flags & FLAG_BS, 0);
    vault.confirm_backup().unwrap();
    let a = assert_with(&mut vault, &get_req(&[]), up()).unwrap();
    assert_eq!(parse(&a.auth_data).flags, FLAG_UP | FLAG_BE | FLAG_BS);
    verify(&public_key(&made), &a);
    let made = create(&mut vault, &make_req("bob", &[-7]), up());
    assert_eq!(
        parse(&made.auth_data).flags,
        FLAG_UP | FLAG_BE | FLAG_BS | FLAG_AT
    );
}

#[test]
fn backup_state_after_second_device_joins() {
    let t = TempDir::new();
    let (mut vault, phrase) = Vault::create(&t.path("vault"), &t.path("state"), "laptop").unwrap();
    let made = create(&mut vault, &make_req("alice", &[-7]), up());
    assert_eq!(parse(&made.auth_data).flags & FLAG_BS, 0);
    let _other =
        Vault::join_with_recovery(&t.path("vault"), &t.path("state2"), &phrase, "desktop").unwrap();
    let a = assert_with(&mut vault, &get_req(&[&made.credential_id]), up()).unwrap();
    assert_eq!(parse(&a.auth_data).flags, FLAG_UP | FLAG_BE | FLAG_BS);
    verify(&public_key(&made), &a);
}

#[test]
fn exclude_list_asks_then_refuses() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let made = create(&mut vault, &make_req("alice", &[-7]), up());
    let mut req = make_req("alice2", &[-7]);
    req.exclude_list = vec![vec![9; 32], made.credential_id.clone()];

    let fake = Fake::with(vec![Ok(up())]);
    let r = Engine::new(&mut vault, &fake).make_credential(&req, None);
    assert_eq!(r, Err(CoreError::CredentialExcluded));
    assert_eq!(fake.calls(), 1);
    assert_eq!(fake.last().ceremony, Ceremony::Create);

    for (err, want) in [
        (
            ApprovalError::Denied,
            CoreError::Approval(ApprovalError::Denied),
        ),
        (
            ApprovalError::Timeout,
            CoreError::Approval(ApprovalError::Timeout),
        ),
    ] {
        let fake = Fake::with(vec![Err(err)]);
        let r = Engine::new(&mut vault, &fake).make_credential(&req, None);
        assert_eq!(r, Err(want));
    }
    assert_eq!(vault.list_all().len(), 1);

    let mut other = req.clone();
    other.exclude_list = vec![vec![9; 32]];
    create(&mut vault, &other, up());
    assert_eq!(vault.list_all().len(), 2);
}

#[test]
fn exclude_list_only_matches_same_rp() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let mut req = make_req("alice", &[-7]);
    req.rp.id = "acme.example".to_owned();
    let made = create(&mut vault, &req, up());
    let mut req = make_req("alice", &[-7]);
    req.exclude_list = vec![made.credential_id.clone()];
    create(&mut vault, &req, up());
    assert_eq!(vault.list_all().len(), 2);
}

#[test]
fn excluded_cred_protect_3_counts_only_with_uv() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let mut req = make_req("alice", &[-7]);
    req.extensions.cred_protect = Some(CredProtect::UserVerificationRequired);
    req.resident_key = false;
    let made = create(&mut vault, &req, uv());
    let mut req = make_req("alice", &[-7]);
    req.resident_key = false;
    req.exclude_list = vec![made.credential_id.clone()];
    let fake = Fake::with(vec![Ok(uv())]);
    let r = Engine::new(&mut vault, &fake).make_credential(&req, None);
    assert_eq!(r, Err(CoreError::CredentialExcluded));
    create(&mut vault, &req, up());
    assert_eq!(vault.list_all().len(), 2);
}

#[test]
fn cred_protect_output_and_storage() {
    let t = TempDir::new();
    let mut vault = t.vault();
    for (level, n) in [
        (CredProtect::UserVerificationOptional, 1u64),
        (CredProtect::UserVerificationOptionalWithCredentialIdList, 2),
        (CredProtect::UserVerificationRequired, 3),
    ] {
        let mut req = make_req(&format!("user{n}"), &[-7]);
        req.extensions.cred_protect = Some(level);
        let made = create(&mut vault, &req, uv());
        let ad = parse(&made.auth_data);
        assert_eq!(ad.flags, FLAG_UP | FLAG_UV | FLAG_BE | FLAG_AT | FLAG_ED);
        let ext = ad.extensions.unwrap();
        assert_eq!(ext.get_text("credProtect").and_then(Value::as_u64), Some(n));
        let rec = vault.get(&made.credential_id).unwrap();
        assert_eq!(rec.cred_protect, Some(u8::try_from(n).unwrap()));
    }
}

fn protected(vault: &mut Vault, user: &str, level: CredProtect) -> MakeCredentialResponse {
    let mut req = make_req(user, &[-7]);
    req.extensions.cred_protect = Some(level);
    create(vault, &req, uv())
}

#[test]
fn cred_protect_2_hidden_from_discovery_without_uv() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let made = protected(
        &mut vault,
        "alice",
        CredProtect::UserVerificationOptionalWithCredentialIdList,
    );

    let fake = Fake::with(vec![Err(ApprovalError::Unavailable)]);
    let r = Engine::new(&mut vault, &fake).get_assertion(&get_req(&[]), None, None);
    assert_eq!(r, Err(CoreError::NoCredentials));
    assert_eq!(fake.calls(), 1);
    assert!(fake.last().uv_required);

    let fake = Fake::with(vec![Ok(uv())]);
    let a = Engine::new(&mut vault, &fake)
        .get_assertion(&get_req(&[]), None, None)
        .unwrap();
    assert!(fake.last().uv_required);
    assert_eq!(parse(&a.auth_data).flags, FLAG_UP | FLAG_UV | FLAG_BE);

    let fake = Fake::with(vec![Ok(up())]);
    let a = Engine::new(&mut vault, &fake)
        .get_assertion(&get_req(&[&made.credential_id]), None, None)
        .unwrap();
    assert!(!fake.last().uv_required);
    assert_eq!(parse(&a.auth_data).flags, FLAG_UP | FLAG_BE);
    verify(&public_key(&made), &a);
}

#[test]
fn cred_protect_3_requires_uv() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let made = protected(&mut vault, "alice", CredProtect::UserVerificationRequired);
    let req = get_req(&[&made.credential_id]);

    let fake = Fake::with(vec![Ok(up())]);
    let r = Engine::new(&mut vault, &fake).get_assertion(&req, None, None);
    assert_eq!(r, Err(CoreError::NoCredentials));
    assert!(fake.last().uv_required);

    let fake = Fake::with(vec![Ok(uv())]);
    let a = Engine::new(&mut vault, &fake)
        .get_assertion(&req, None, None)
        .unwrap();
    assert_eq!(parse(&a.auth_data).flags, FLAG_UP | FLAG_UV | FLAG_BE);
    verify(&public_key(&made), &a);
}

#[test]
fn cred_protect_mixed_falls_back_to_unprotected() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let open = protected(&mut vault, "alice", CredProtect::UserVerificationOptional);
    let locked = protected(&mut vault, "bob", CredProtect::UserVerificationRequired);

    let fake = Fake::with(vec![Err(ApprovalError::Unavailable), Ok(up())]);
    let a = Engine::new(&mut vault, &fake)
        .get_assertion(&get_req(&[]), None, None)
        .unwrap();
    let seen = fake.seen.borrow().clone();
    assert_eq!(seen.len(), 2);
    assert!(seen[0].uv_required);
    assert_eq!(seen[0].candidates.len(), 2);
    assert!(!seen[1].uv_required);
    assert_eq!(seen[1].candidates, vec![open.credential_id.clone()]);
    assert_eq!(a.credential_id, open.credential_id);

    let fake = Fake::with(vec![Err(ApprovalError::Unavailable)]);
    let mut req = get_req(&[]);
    req.uv = UvRequirement::Required;
    let r = Engine::new(&mut vault, &fake).get_assertion(&req, None, None);
    assert_eq!(r, Err(CoreError::UvRequiredUnavailable));
    assert_eq!(fake.calls(), 1);

    let fake = Fake::with(vec![Ok(pick(1, true))]);
    let a = Engine::new(&mut vault, &fake)
        .get_assertion(&get_req(&[]), None, None)
        .unwrap();
    let chosen = fake.last().candidates[1].clone();
    assert_eq!(a.credential_id, chosen);
    assert!(a.credential_id == locked.credential_id || a.credential_id == open.credential_id);
}

#[test]
fn discoverable_and_allow_list_flows() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let mut req = make_req("alice", &[-7]);
    req.resident_key = false;
    let hidden = create(&mut vault, &req, up());
    assert!(!hidden.resident_key);
    assert!(!vault.get(&hidden.credential_id).unwrap().discoverable);

    let fake = Fake::default();
    let r = Engine::new(&mut vault, &fake).get_assertion(&get_req(&[]), None, None);
    assert_eq!(r, Err(CoreError::NoCredentials));
    assert_eq!(fake.calls(), 0);

    let a = assert_with(&mut vault, &get_req(&[&hidden.credential_id]), up()).unwrap();
    assert_eq!(a.credential_id, hidden.credential_id);
    assert!(a.user.is_none());

    let shown = create(&mut vault, &make_req("bob", &[-7]), up());
    let a = assert_with(&mut vault, &get_req(&[]), up()).unwrap();
    assert_eq!(a.credential_id, shown.credential_id);
    assert_eq!(a.user.unwrap().id, b"bob");

    let unknown = [7u8; 32];
    let fake = Fake::with(vec![Ok(up())]);
    let a = Engine::new(&mut vault, &fake)
        .get_assertion(
            &get_req(&[
                &unknown[..],
                shown.credential_id.as_slice(),
                hidden.credential_id.as_slice(),
            ]),
            None,
            None,
        )
        .unwrap();
    assert_eq!(fake.last().candidates, vec![shown.credential_id.clone()]);
    assert_eq!(a.credential_id, shown.credential_id);

    let mut other = get_req(&[&shown.credential_id]);
    other.rp_id = "acme.example".to_owned();
    let fake = Fake::default();
    let r = Engine::new(&mut vault, &fake).get_assertion(&other, None, None);
    assert_eq!(r, Err(CoreError::NoCredentials));
    assert_eq!(fake.calls(), 0);
}

#[test]
fn multiple_accounts_need_selection() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let alice = create(&mut vault, &make_req("alice", &[-7]), up());
    let bob = create(&mut vault, &make_req("bob", &[-8]), up());

    for i in 0..2 {
        let fake = Fake::with(vec![Ok(pick(i, false))]);
        let a = Engine::new(&mut vault, &fake)
            .get_assertion(&get_req(&[]), None, None)
            .unwrap();
        let s = fake.last();
        assert_eq!(s.candidates.len(), 2);
        assert_eq!(a.credential_id, s.candidates[i]);
        let key = if a.credential_id == alice.credential_id {
            assert_eq!(a.user_handle, b"alice");
            public_key(&alice)
        } else {
            assert_eq!(a.credential_id, bob.credential_id);
            assert_eq!(a.user_handle, b"bob");
            public_key(&bob)
        };
        verify(&key, &a);
    }

    for bad in [up(), pick(2, false)] {
        let fake = Fake::with(vec![Ok(bad)]);
        let r = Engine::new(&mut vault, &fake).get_assertion(&get_req(&[]), None, None);
        assert!(matches!(
            r,
            Err(CoreError::Approval(ApprovalError::Internal(_)))
        ));
    }
}

#[test]
fn uv_required_with_presence_only_approver() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let mut req = make_req("alice", &[-7]);
    req.uv = UvRequirement::Required;
    for answer in [Err(ApprovalError::Unavailable), Ok(up())] {
        let fake = Fake::with(vec![answer]);
        let r = Engine::new(&mut vault, &fake).make_credential(&req, None);
        assert_eq!(r, Err(CoreError::UvRequiredUnavailable));
        assert!(fake.last().uv_required);
    }
    assert!(vault.list_all().is_empty());

    let made = create(&mut vault, &make_req("alice", &[-7]), up());
    let mut get = get_req(&[&made.credential_id]);
    get.uv = UvRequirement::Required;
    for answer in [Err(ApprovalError::Unavailable), Ok(up())] {
        let fake = Fake::with(vec![answer]);
        let r = Engine::new(&mut vault, &fake).get_assertion(&get, None, None);
        assert_eq!(r, Err(CoreError::UvRequiredUnavailable));
        assert_eq!(fake.calls(), 1);
    }
    let a = assert_with(&mut vault, &get, uv()).unwrap();
    assert_eq!(parse(&a.auth_data).flags, FLAG_UP | FLAG_UV | FLAG_BE);
}

#[test]
fn approval_errors_map() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let made = create(&mut vault, &make_req("alice", &[-7]), up());
    let get = get_req(&[&made.credential_id]);
    for err in [
        ApprovalError::Denied,
        ApprovalError::Timeout,
        ApprovalError::Locked,
        ApprovalError::Unavailable,
        ApprovalError::Internal("x".into()),
    ] {
        let fake = Fake::with(vec![Err(err.clone())]);
        let r = Engine::new(&mut vault, &fake).make_credential(&make_req("bob", &[-7]), None);
        assert_eq!(r, Err(CoreError::Approval(err.clone())));
        let fake = Fake::with(vec![Err(err.clone())]);
        let r = Engine::new(&mut vault, &fake).get_assertion(&get, None, None);
        assert_eq!(r, Err(CoreError::Approval(err)));
    }
    let absent = Approval {
        user_present: false,
        user_verified: false,
        selected: None,
    };
    let fake = Fake::with(vec![Ok(absent)]);
    let r = Engine::new(&mut vault, &fake).make_credential(&make_req("bob", &[-7]), None);
    assert_eq!(r, Err(CoreError::Approval(ApprovalError::Denied)));
    let fake = Fake::with(vec![Ok(absent)]);
    let r = Engine::new(&mut vault, &fake).get_assertion(&get, None, None);
    assert_eq!(r, Err(CoreError::Approval(ApprovalError::Denied)));
    assert_eq!(vault.list_all().len(), 1);
}

fn silent(allow: &[&[u8]]) -> GetAssertionRequest {
    let mut req = get_req(allow);
    req.up = false;
    req
}

#[test]
fn silent_probe_signs_without_prompt_or_presence() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let mut req = make_req("alice", &[-8]);
    req.extensions.hmac_secret = true;
    let made = create(&mut vault, &req, uv());
    let other = [1u8; 32];

    let mut probe = silent(&[&other, &made.credential_id]);
    probe.extensions.hmac_secret = Some(HmacSecretSalts {
        salt1: [0x11; 32],
        salt2: None,
    });
    let fake = Fake::default();
    let a = Engine::new(&mut vault, &fake)
        .get_assertion(&probe, None, Some(&XorWrap))
        .unwrap();
    assert_eq!(fake.calls(), 0);
    assert_eq!(a.credential_id, made.credential_id);
    assert_eq!(a.user_handle, b"alice");
    assert!(a.user.is_none());
    assert!(a.hmac_secret_output.is_none());
    let ad = parse(&a.auth_data);
    assert_eq!(ad.flags, FLAG_BE);
    assert!(ad.extensions.is_none());
    assert_eq!(ad.rp_id_hash, hirz_crypto::sha256(RP.as_bytes()));
    verify(&public_key(&made), &a);
}

#[test]
fn silent_probe_reports_backup_state() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let made = create(&mut vault, &make_req("alice", &[-7]), up());
    vault.confirm_backup().unwrap();
    let fake = Fake::default();
    let a = Engine::new(&mut vault, &fake)
        .get_assertion(&silent(&[&made.credential_id]), None, None)
        .unwrap();
    assert_eq!(parse(&a.auth_data).flags, FLAG_BE | FLAG_BS);
}

#[test]
fn silent_probe_without_match_or_allow_list() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let made = create(&mut vault, &make_req("alice", &[-7]), up());
    let fake = Fake::default();
    let mut engine = Engine::new(&mut vault, &fake);
    assert_eq!(
        engine.get_assertion(&silent(&[]), None, None),
        Err(CoreError::NoCredentials)
    );
    assert_eq!(
        engine.get_assertion(&silent(&[&[1u8; 32]]), None, None),
        Err(CoreError::NoCredentials)
    );
    let mut other_rp = silent(&[&made.credential_id]);
    other_rp.rp_id = "other.example".to_owned();
    assert_eq!(
        engine.get_assertion(&other_rp, None, None),
        Err(CoreError::NoCredentials)
    );
    let mut wants_uv = silent(&[&made.credential_id]);
    wants_uv.uv = UvRequirement::Required;
    assert_eq!(
        engine.get_assertion(&wants_uv, None, None),
        Err(CoreError::UvRequiredUnavailable)
    );
    assert_eq!(fake.calls(), 0);
}

#[test]
fn silent_probe_skips_cred_protect_3() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let strict = protected(&mut vault, "alice", CredProtect::UserVerificationRequired);
    let listed = protected(
        &mut vault,
        "bob",
        CredProtect::UserVerificationOptionalWithCredentialIdList,
    );
    let fake = Fake::default();
    let mut engine = Engine::new(&mut vault, &fake);
    assert_eq!(
        engine.get_assertion(&silent(&[&strict.credential_id]), None, None),
        Err(CoreError::NoCredentials)
    );
    let a = engine
        .get_assertion(
            &silent(&[&strict.credential_id, &listed.credential_id]),
            None,
            None,
        )
        .unwrap();
    assert_eq!(a.credential_id, listed.credential_id);
    assert_eq!(fake.calls(), 0);
}

fn hmac_req(allow: &[u8], salt2: bool) -> GetAssertionRequest {
    let mut req = get_req(&[allow]);
    req.extensions.hmac_secret = Some(HmacSecretSalts {
        salt1: [0x11; 32],
        salt2: salt2.then_some([0x22; 32]),
    });
    req
}

#[test]
fn hmac_secret_raw_output() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let mut req = make_req("alice", &[-7]);
    req.extensions.hmac_secret = true;
    let made = create(&mut vault, &req, up());
    assert!(made.hmac_secret);
    let ad = parse(&made.auth_data);
    assert_eq!(ad.flags & FLAG_ED, FLAG_ED);
    assert_eq!(
        ad.extensions.unwrap().get_text("hmac-secret"),
        Some(&Value::Bool(true))
    );

    let id = made.credential_id.clone();
    let a1 = assert_with(&mut vault, &hmac_req(&id, false), up()).unwrap();
    let a2 = assert_with(&mut vault, &hmac_req(&id, false), up()).unwrap();
    let out1 = a1.hmac_secret_output.clone().unwrap();
    assert_eq!(out1.len(), 32);
    assert_eq!(Some(out1.clone()), a2.hmac_secret_output);
    assert_eq!(parse(&a1.auth_data).flags, FLAG_UP | FLAG_BE);

    let pair = vault.get(&id).unwrap().hmac_secret.clone().unwrap();
    assert_eq!(
        out1,
        hirz_crypto::hmac_sha256(pair.cred_random_without_uv.as_slice(), &[0x11; 32])
    );

    let both = assert_with(&mut vault, &hmac_req(&id, true), up()).unwrap();
    let both = both.hmac_secret_output.unwrap();
    assert_eq!(both.len(), 64);
    assert_eq!(&both[..32], out1.as_slice());
    assert_eq!(
        &both[32..],
        hirz_crypto::hmac_sha256(pair.cred_random_without_uv.as_slice(), &[0x22; 32])
    );

    let with_uv = assert_with(&mut vault, &hmac_req(&id, false), uv()).unwrap();
    let with_uv = with_uv.hmac_secret_output.unwrap();
    assert_ne!(with_uv, out1);
    assert_eq!(
        with_uv,
        hirz_crypto::hmac_sha256(pair.cred_random_with_uv.as_slice(), &[0x11; 32])
    );
    let again = assert_with(&mut vault, &hmac_req(&id, false), uv()).unwrap();
    assert_eq!(again.hmac_secret_output.unwrap(), with_uv);
}

#[test]
fn hmac_secret_absent_without_creation_secrets() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let made = create(&mut vault, &make_req("alice", &[-7]), up());
    assert!(
        vault
            .get(&made.credential_id)
            .unwrap()
            .hmac_secret
            .is_none()
    );
    let a = assert_with(&mut vault, &hmac_req(&made.credential_id, true), up()).unwrap();
    assert!(a.hmac_secret_output.is_none());
    assert_eq!(parse(&a.auth_data).flags, FLAG_UP | FLAG_BE);
}

struct XorWrap;

impl HmacSecretWrap for XorWrap {
    fn wrap(&self, output: &[u8]) -> Result<Vec<u8>, CoreError> {
        let mut v: Vec<u8> = output.iter().map(|b| b ^ 0x5a).collect();
        v.extend_from_slice(b"iv");
        Ok(v)
    }
}

struct FailWrap;

impl HmacSecretWrap for FailWrap {
    fn wrap(&self, _: &[u8]) -> Result<Vec<u8>, CoreError> {
        Err(CoreError::Crypto("wrap".into()))
    }
}

#[test]
fn hmac_secret_wrapped_into_auth_data() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let mut req = make_req("alice", &[-8]);
    req.extensions.hmac_secret = true;
    let made = create(&mut vault, &req, up());
    let id = made.credential_id.clone();
    let raw = assert_with(&mut vault, &hmac_req(&id, true), uv())
        .unwrap()
        .hmac_secret_output
        .unwrap();

    let fake = Fake::with(vec![Ok(uv())]);
    let a = Engine::new(&mut vault, &fake)
        .get_assertion(&hmac_req(&id, true), None, Some(&XorWrap))
        .unwrap();
    assert!(a.hmac_secret_output.is_none());
    let ad = parse(&a.auth_data);
    assert_eq!(ad.flags, FLAG_UP | FLAG_UV | FLAG_BE | FLAG_ED);
    let ext = ad.extensions.unwrap();
    assert_eq!(
        ext.get_text("hmac-secret").and_then(Value::as_bytes),
        Some(XorWrap.wrap(&raw).unwrap().as_slice())
    );
    verify(&public_key(&made), &a);

    let fake = Fake::with(vec![Ok(uv())]);
    let r =
        Engine::new(&mut vault, &fake).get_assertion(&hmac_req(&id, true), None, Some(&FailWrap));
    assert_eq!(r, Err(CoreError::Crypto("wrap".into())));

    let fake = Fake::with(vec![Ok(uv())]);
    let a = Engine::new(&mut vault, &fake)
        .get_assertion(&get_req(&[&id]), None, Some(&XorWrap))
        .unwrap();
    assert!(parse(&a.auth_data).extensions.is_none());
}

#[test]
fn reload_sees_credentials_from_another_handle() {
    let t = TempDir::new();
    let mut first = t.vault();
    let mut second = Vault::open(&t.path("vault"), &t.path("state")).unwrap();
    let made = create(&mut second, &make_req("alice", &[-7]), up());
    assert!(first.get(&made.credential_id).is_none());
    let a = assert_with(&mut first, &get_req(&[&made.credential_id]), up()).unwrap();
    verify(&public_key(&made), &a);
    let a = assert_with(&mut first, &get_req(&[]), up()).unwrap();
    assert_eq!(a.credential_id, made.credential_id);
}

#[test]
fn same_account_replaces_older_discoverable() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let mut req = make_req("alice", &[-7]);
    req.resident_key = false;
    let kept = create(&mut vault, &req, up());
    let old = create(&mut vault, &make_req("alice", &[-7]), up());
    let other = create(&mut vault, &make_req("bob", &[-7]), up());
    let new = create(&mut vault, &make_req("alice", &[-8]), up());
    assert!(vault.get(&old.credential_id).is_none());
    assert!(vault.get(&kept.credential_id).is_some());
    assert!(vault.get(&other.credential_id).is_some());
    assert!(vault.get(&new.credential_id).is_some());
    assert_eq!(vault.list_all().len(), 3);
}

#[test]
fn long_names_are_clipped() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let mut req = make_req("alice", &[-7]);
    req.user.display_name = Some("é".repeat(600));
    let made = create(&mut vault, &req, up());
    let name = vault
        .get(&made.credential_id)
        .unwrap()
        .user_display_name
        .clone()
        .unwrap();
    assert_eq!(name.len(), 1024);
    assert!(name.chars().all(|c| c == 'é'));
}

#[test]
fn invalid_requests() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let fake = Fake::default();
    let mut engine = Engine::new(&mut vault, &fake);
    let mut req = make_req("alice", &[-7]);
    req.user.id = Vec::new();
    assert!(matches!(
        engine.make_credential(&req, None),
        Err(CoreError::InvalidRequest(_))
    ));
    req.user.id = vec![1; 65];
    assert!(matches!(
        engine.make_credential(&req, None),
        Err(CoreError::InvalidRequest(_))
    ));
    let mut req = make_req("alice", &[-7]);
    req.rp.id = String::new();
    assert!(matches!(
        engine.make_credential(&req, None),
        Err(CoreError::InvalidRequest(_))
    ));
    let mut get = get_req(&[]);
    get.rp_id = String::new();
    assert!(matches!(
        engine.get_assertion(&get, None, None),
        Err(CoreError::InvalidRequest(_))
    ));
    assert_eq!(fake.calls(), 0);
}

#[test]
fn machine_login_rp_ids_are_refused_without_a_prompt() {
    assert!(super::is_machine_login_rp_id("pam://laptop"));
    assert!(super::is_machine_login_rp_id("PAM://laptop"));
    assert!(super::is_machine_login_rp_id("pam://"));
    assert!(!super::is_machine_login_rp_id("pam:"));
    assert!(!super::is_machine_login_rp_id("pam.example.com"));
    assert!(!super::is_machine_login_rp_id("ssh:"));
    assert!(!super::is_machine_login_rp_id("p\u{00E4}m://x"));
    assert!(!super::is_machine_login_rp_id(
        "\u{00E9}\u{00E9}\u{00E9}://"
    ));

    let t = TempDir::new();
    let mut vault = t.vault();
    let allowed = create(&mut vault, &make_req("alice", &[-7]), up());
    let fake = Fake::with(vec![Ok(uv()), Ok(uv()), Ok(uv())]);
    let mut engine = Engine::new(&mut vault, &fake);
    fn refused<T>(r: &Result<T, CoreError>) -> bool {
        matches!(r, Err(CoreError::Approval(ApprovalError::Unavailable)))
    }

    let mut req = make_req("alice", &[-7]);
    req.rp.id = "pam://laptop".to_owned();
    assert!(refused(&engine.make_credential(&req, None)));
    assert!(refused(
        &engine.make_credential(&req, Some("https://example.com"))
    ));

    for up in [true, false] {
        let mut get = get_req(&[&allowed.credential_id]);
        get.rp_id = "pam://laptop".to_owned();
        get.up = up;
        assert!(refused(&engine.get_assertion(&get, None, None)));
        get.allow_list.clear();
        assert!(refused(&engine.get_assertion(&get, None, None)));
    }
    assert_eq!(fake.calls(), 0);
    assert_eq!(engine.vault().list_all().len(), 1);
}

#[test]
fn selection_is_presence_only() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let fake = Fake::default();
    fake.selections.borrow_mut().extend([
        Ok(up()),
        Ok(Approval {
            user_present: false,
            user_verified: false,
            selected: None,
        }),
        Err(ApprovalError::Timeout),
    ]);
    let mut engine = Engine::new(&mut vault, &fake);
    assert_eq!(engine.select(), Ok(()));
    assert_eq!(
        engine.select(),
        Err(CoreError::Approval(ApprovalError::Denied))
    );
    assert_eq!(
        engine.select(),
        Err(CoreError::Approval(ApprovalError::Timeout))
    );
    assert_eq!(fake.calls(), 0);

    let mut engine = Engine::new(&mut vault, &Minimal);
    assert_eq!(
        engine.select(),
        Err(CoreError::Approval(ApprovalError::Unavailable))
    );
}

fn import_es256(vault: &mut Vault, id: &[u8], user: &str) -> PublicKey {
    let (pkcs8, x, y) = hirz_crypto::es256::generate().unwrap();
    vault
        .put(hirz_vault::CredentialRecord {
            credential_id: id.to_vec(),
            rp_id: RP.to_owned(),
            rp_name: None,
            user_id: user.as_bytes().to_vec(),
            user_name: Some(user.to_owned()),
            user_display_name: None,
            algorithm: COSE_ALG_ES256,
            private_key_pkcs8: pkcs8,
            created_at: 1,
            cred_protect: None,
            hmac_secret: None,
            discoverable: true,
            backup_eligible: true,
        })
        .unwrap();
    PublicKey::Es256 { x, y }
}

#[test]
fn imported_ids_of_other_lengths() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let short: Vec<u8> = (1..=16).collect();
    let long = vec![0x77; 1023];
    let short_key = import_es256(&mut vault, &short, "alice");
    let long_key = import_es256(&mut vault, &long, "bob");

    for (id, key) in [(&short, &short_key), (&long, &long_key)] {
        let a = assert_with(&mut vault, &get_req(&[id]), up()).unwrap();
        assert_eq!(&a.credential_id, id);
        verify(key, &a);
        assert!(parse(&a.auth_data).attested_credential.is_none());

        let a = Engine::new(&mut vault, &Fake::default())
            .get_assertion(&silent(&[id]), None, None)
            .unwrap();
        assert_eq!(&a.credential_id, id);
        verify(key, &a);
    }

    let mut longer = short.clone();
    longer.push(0);
    let near: [&[u8]; 3] = [&short[..15], &longer, &long[..1022]];
    for id in near {
        assert_eq!(
            assert_with(&mut vault, &get_req(&[id]), up()),
            Err(CoreError::NoCredentials)
        );
    }

    let fake = Fake::with(vec![Ok(pick(1, false))]);
    let a = Engine::new(&mut vault, &fake)
        .get_assertion(&get_req(&[]), None, None)
        .unwrap();
    let shown = fake.last().candidates;
    assert_eq!(shown.len(), 2);
    assert!(shown.contains(&short) && shown.contains(&long));
    assert_eq!(a.credential_id, shown[1]);

    let mut req = make_req("carol", &[-7]);
    req.exclude_list = vec![vec![1; 16], short.clone()];
    let fake = Fake::with(vec![Ok(up())]);
    let r = Engine::new(&mut vault, &fake).make_credential(&req, None);
    assert_eq!(r, Err(CoreError::CredentialExcluded));
}

struct Hook<'h> {
    hook: RefCell<Option<Box<dyn FnOnce() + 'h>>>,
    answer: Approval,
}

impl<'h> Hook<'h> {
    fn new(answer: Approval, hook: impl FnOnce() + 'h) -> Hook<'h> {
        Hook {
            hook: RefCell::new(Some(Box::new(hook))),
            answer,
        }
    }
}

impl Approver for Hook<'_> {
    fn approve(&self, _: &ApprovalContext<'_>) -> Result<Approval, ApprovalError> {
        if let Some(hook) = self.hook.borrow_mut().take() {
            hook();
        }
        Ok(self.answer)
    }
}

fn two_devices(t: &TempDir) -> (Vault, Vault) {
    let (first, phrase) = Vault::create(&t.path("vault"), &t.path("state"), "laptop").unwrap();
    let second =
        Vault::join_with_recovery(&t.path("vault"), &t.path("state2"), &phrase, "phone").unwrap();
    (first, second)
}

const DENIED: CoreError = CoreError::Approval(ApprovalError::Denied);

#[test]
fn a_cancel_during_the_prompt_creates_and_signs_nothing() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let made = create(&mut vault, &make_req("alice", &[-7]), up());
    let before = vault.list_all().len();

    let cancelled = std::cell::Cell::new(false);
    let hook = Hook::new(up(), || cancelled.set(true));
    let flag = || cancelled.get();
    let r = Engine::new(&mut vault, &hook)
        .with_cancel(&flag)
        .make_credential(&make_req("bob", &[-7]), None);
    assert_eq!(r.unwrap_err(), DENIED);
    vault.reload().unwrap();
    assert_eq!(vault.list_all().len(), before);

    cancelled.set(false);
    let hook = Hook::new(up(), || cancelled.set(true));
    let r = Engine::new(&mut vault, &hook)
        .with_cancel(&flag)
        .get_assertion(&get_req(&[&made.credential_id]), None, None);
    assert_eq!(r.unwrap_err(), DENIED);
}

#[test]
fn a_cancel_after_the_credential_was_stored_takes_it_back() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let calls = std::cell::Cell::new(0u32);
    let flag = || {
        calls.set(calls.get() + 1);
        calls.get() >= 2
    };
    let r = Engine::new(&mut vault, &Minimal)
        .with_cancel(&flag)
        .make_credential(&make_req("alice", &[-7]), None);
    assert_eq!(r.unwrap_err(), DENIED);
    assert_eq!(calls.get(), 2);
    vault.reload().unwrap();
    assert!(vault.list_all().is_empty());
}

#[test]
fn a_credential_deleted_during_the_prompt_is_not_signed_with() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let made = create(&mut vault, &make_req("alice", &[-7]), up());
    let id = made.credential_id.clone();
    let mut other = Vault::open(&t.path("vault"), &t.path("state")).unwrap();
    let hook = Hook::new(up(), || {
        other.delete(&id).unwrap();
    });
    let r = Engine::new(&mut vault, &hook).get_assertion(&get_req(&[&id]), None, None);
    assert_eq!(r.unwrap_err(), CoreError::NoCredentials);
}

#[test]
fn a_device_removed_during_the_prompt_neither_creates_nor_signs() {
    let t = TempDir::new();
    let (mut first, mut second) = two_devices(&t);
    let made = create(&mut first, &make_req("alice", &[-7]), up());
    let me = first.device_id();
    let hook = Hook::new(up(), || second.remove_device(&me).unwrap());
    let r =
        Engine::new(&mut first, &hook).get_assertion(&get_req(&[&made.credential_id]), None, None);
    assert_eq!(
        r.unwrap_err(),
        CoreError::Approval(ApprovalError::Unavailable)
    );

    let t = TempDir::new();
    let (mut first, mut second) = two_devices(&t);
    let me = first.device_id();
    let hook = Hook::new(up(), || second.remove_device(&me).unwrap());
    let r = Engine::new(&mut first, &hook).make_credential(&make_req("bob", &[-7]), None);
    drop(hook);
    assert_eq!(
        r.unwrap_err(),
        CoreError::Approval(ApprovalError::Unavailable)
    );
    second.reload().unwrap();
    assert!(second.list_all().is_empty());
}

fn refused<T>(r: &Result<T, CoreError>) -> bool {
    matches!(r, Err(CoreError::Approval(ApprovalError::Unavailable)))
}

#[test]
fn every_machine_login_rp_id_is_refused_without_a_prompt() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let allowed = create(&mut vault, &make_req("alice", &[-7]), up());
    let fake = Fake::with(vec![Ok(uv()), Ok(uv()), Ok(uv())]);
    let mut engine = Engine::new(&mut vault, &fake);

    let ids = [
        "io.systemd.home",
        "IO.SYSTEMD.HOME",
        "io.systemd.cryptsetup",
        "Io.Systemd.CryptSetup",
        "pam://laptop",
        "PAM://",
        "pam://example.com",
    ];
    for id in ids {
        let mut req = make_req("alice", &[-7]);
        req.rp.id = id.to_owned();
        assert!(refused(&engine.make_credential(&req, None)), "{id}");
        assert!(
            refused(&engine.make_credential(&req, Some("https://example.com"))),
            "{id}"
        );
        for up in [true, false] {
            for allow in [&[allowed.credential_id.as_slice()][..], &[]] {
                let mut get = get_req(allow);
                get.rp_id = id.to_owned();
                get.up = up;
                assert!(refused(&engine.get_assertion(&get, None, None)), "{id}");
            }
        }
    }
    assert_eq!(fake.calls(), 0);
    assert_eq!(engine.vault().list_all().len(), 1);

    for id in [
        "io.systemd.home.example.com",
        "systemd.home",
        "io.systemd.cryptsetup.example.org",
    ] {
        let mut req = make_req("alice", &[-7]);
        req.rp.id = id.to_owned();
        engine.make_credential(&req, None).unwrap();
    }
    assert_eq!(fake.calls(), 3);
}

fn hide_generation(vault: &std::path::Path, number: u32) {
    let prefix = format!("{number:010}-");
    let keys = vault.join("keys");
    let name = fs::read_dir(&keys)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .find(|n| n.starts_with(&prefix))
        .unwrap();
    fs::rename(keys.join(&name), vault.join(format!(".hidden-{name}"))).unwrap();
}

#[test]
fn a_loaded_vault_skips_only_the_first_look_before_the_prompt() {
    let t = TempDir::new();
    let mut first = t.vault();
    let mut second = Vault::open(&t.path("vault"), &t.path("state")).unwrap();
    let made = create(&mut second, &make_req("alice", &[-7]), up());
    let fake = Fake::with(vec![Ok(up())]);
    let mut engine = Engine::new(&mut first, &fake).with_loaded_vault();

    let early = engine.get_assertion(&get_req(&[&made.credential_id]), None, None);
    assert_eq!(early, Err(CoreError::NoCredentials));
    assert_eq!(fake.calls(), 0);

    let a = engine
        .get_assertion(&get_req(&[&made.credential_id]), None, None)
        .unwrap();
    verify(&public_key(&made), &a);
    assert_eq!(fake.calls(), 1);
}

#[test]
fn the_look_after_the_approval_still_happens_with_a_loaded_vault() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let made = create(&mut vault, &make_req("alice", &[-7]), up());
    let id = made.credential_id.clone();
    let mut other = Vault::open(&t.path("vault"), &t.path("state")).unwrap();
    let hook = Hook::new(up(), || {
        other.delete(&id).unwrap();
    });
    let r = Engine::new(&mut vault, &hook)
        .with_loaded_vault()
        .get_assertion(&get_req(&[&id]), None, None);
    assert_eq!(r.unwrap_err(), CoreError::NoCredentials);

    let t = TempDir::new();
    let (mut first, mut second) = two_devices(&t);
    let made = create(&mut first, &make_req("alice", &[-7]), up());
    let me = first.device_id();
    let hook = Hook::new(up(), || second.remove_device(&me).unwrap());
    let r = Engine::new(&mut first, &hook)
        .with_loaded_vault()
        .get_assertion(&get_req(&[&made.credential_id]), None, None);
    assert!(refused(&r));

    let t = TempDir::new();
    let (mut first, mut second) = two_devices(&t);
    let me = first.device_id();
    let hook = Hook::new(up(), || second.remove_device(&me).unwrap());
    let r = Engine::new(&mut first, &hook)
        .with_loaded_vault()
        .make_credential(&make_req("bob", &[-7]), None);
    drop(hook);
    assert!(refused(&r));
    second.reload().unwrap();
    assert!(second.list_all().is_empty());
}

#[test]
fn a_removed_device_is_refused_before_any_prompt() {
    let t = TempDir::new();
    let (mut first, mut second) = two_devices(&t);
    let made = create(&mut first, &make_req("alice", &[-7]), up());
    second.reload().unwrap();
    second.remove_device(&first.device_id()).unwrap();

    let fake = Fake::with(vec![Ok(up()), Ok(up()), Ok(up())]);
    let mut engine = Engine::new(&mut first, &fake);
    assert!(refused(
        &engine.make_credential(&make_req("bob", &[-7]), None)
    ));
    assert!(refused(&engine.get_assertion(
        &get_req(&[&made.credential_id]),
        None,
        None
    )));
    assert!(refused(&engine.get_assertion(&get_req(&[]), None, None)));
    assert!(refused(&engine.get_assertion(
        &silent(&[&made.credential_id]),
        None,
        None
    )));
    assert_eq!(fake.calls(), 0);
}

#[test]
fn a_fork_stops_registrations_before_the_prompt_and_keeps_sign_ins() {
    let t = TempDir::new();
    let (mut first, second) = two_devices(&t);
    let made = create(&mut first, &make_req("alice", &[-7]), up());
    first.remove_device(&second.device_id()).unwrap();
    hide_generation(&t.path("vault"), 2);
    assert!(first.reload().unwrap().fork_detected);

    let fake = Fake::with(vec![Ok(up()), Ok(up())]);
    let mut engine = Engine::new(&mut first, &fake);
    assert!(refused(
        &engine.make_credential(&make_req("bob", &[-7]), None)
    ));
    assert_eq!(
        fake.calls(),
        0,
        "nothing is asked when nothing can be saved"
    );

    let a = engine
        .get_assertion(&get_req(&[&made.credential_id]), None, None)
        .unwrap();
    verify(&public_key(&made), &a);
    assert_eq!(fake.calls(), 1);
    assert_eq!(engine.vault().list_all().len(), 1);
}

#[test]
fn a_fork_that_appears_during_the_prompt_is_a_refusal_not_a_vault_failure() {
    let t = TempDir::new();
    let (mut first, second) = two_devices(&t);
    first.remove_device(&second.device_id()).unwrap();
    let vault_dir = t.path("vault");
    let hook = Hook::new(up(), || hide_generation(&vault_dir, 2));
    let r = Engine::new(&mut first, &hook).make_credential(&make_req("bob", &[-7]), None);
    drop(hook);
    assert!(refused(&r), "{r:?}");
    assert!(first.report().fork_detected);
    assert!(first.list_all().is_empty());
}

#[test]
fn a_commit_that_says_no_takes_the_new_passkey_back_and_keeps_the_older_one() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let older = create(&mut vault, &make_req("alice", &[-7]), up());
    let asked = std::cell::Cell::new(0u32);
    let refuse = || {
        asked.set(asked.get() + 1);
        false
    };
    let r = Engine::new(&mut vault, &Minimal)
        .with_commit(&refuse)
        .make_credential(&make_req("alice", &[-8]), None);
    assert_eq!(r.unwrap_err(), DENIED);
    assert_eq!(
        asked.get(),
        1,
        "asked once, after the credential was stored"
    );
    vault.reload().unwrap();
    let all = vault.list_all();
    assert_eq!(
        all.len(),
        1,
        "the new credential is gone and nothing else changed"
    );
    assert_eq!(all[0].credential_id, older.credential_id);
}

#[test]
fn a_commit_that_says_yes_replaces_the_older_passkey() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let older = create(&mut vault, &make_req("alice", &[-7]), up());
    let allow = || true;
    let newer = Engine::new(&mut vault, &Minimal)
        .with_commit(&allow)
        .make_credential(&make_req("alice", &[-8]), None)
        .unwrap();
    assert!(vault.get(&older.credential_id).is_none());
    assert!(vault.get(&newer.credential_id).is_some());
}

#[test]
fn a_commit_is_never_asked_for_a_request_that_failed_earlier() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let asked = std::cell::Cell::new(false);
    let commit = || {
        asked.set(true);
        true
    };
    let fake = Fake::with(vec![Err(ApprovalError::Denied)]);
    let r = Engine::new(&mut vault, &fake)
        .with_commit(&commit)
        .make_credential(&make_req("alice", &[-7]), None);
    assert_eq!(r.unwrap_err(), DENIED);
    assert!(!asked.get());
}

#[test]
fn a_refusal_before_any_window_for_a_protected_credential_tries_the_others() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let open = protected(&mut vault, "alice", CredProtect::UserVerificationOptional);
    let _locked = protected(&mut vault, "bob", CredProtect::UserVerificationRequired);

    let fake = Fake::with(vec![Err(ApprovalError::NothingShown), Ok(up())]);
    let a = Engine::new(&mut vault, &fake)
        .get_assertion(&get_req(&[]), None, None)
        .unwrap();
    assert_eq!(a.credential_id, open.credential_id);
    assert_eq!(fake.calls(), 2);
    assert!(fake.seen.borrow()[0].uv_required);
    assert!(!fake.seen.borrow()[1].uv_required);
}

#[test]
fn a_refusal_before_any_window_is_passed_on_as_it_is() {
    let t = TempDir::new();
    let mut vault = t.vault();
    let made = create(&mut vault, &make_req("alice", &[-7]), up());
    let nothing = CoreError::Approval(ApprovalError::NothingShown);

    let fake = Fake::with(vec![Err(ApprovalError::NothingShown)]);
    let r =
        Engine::new(&mut vault, &fake).get_assertion(&get_req(&[&made.credential_id]), None, None);
    assert_eq!(r.unwrap_err(), nothing);
    assert_eq!(fake.calls(), 1);

    let mut req = get_req(&[&made.credential_id]);
    req.uv = UvRequirement::Required;
    let fake = Fake::with(vec![Err(ApprovalError::NothingShown)]);
    let r = Engine::new(&mut vault, &fake).get_assertion(&req, None, None);
    assert_eq!(r.unwrap_err(), nothing, "not turned into a UV error");

    let fake = Fake::with(vec![Err(ApprovalError::NothingShown)]);
    let r = Engine::new(&mut vault, &fake).make_credential(&make_req("bob", &[-7]), None);
    assert_eq!(r.unwrap_err(), nothing);
}
