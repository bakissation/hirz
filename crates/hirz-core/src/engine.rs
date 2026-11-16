//! The authenticator engine: makeCredential, getAssertion and authenticatorSelection over the
//! vault, independent of the transport.
//!
//! Every ceremony first reloads the vault, so credentials another frontend or the user's
//! folder sync tool wrote in the meantime are visible.
//!
//! Policy, relative to CTAP 2.2 section 6:
//!
//! - **Silent probes** (`up: false`): platforms send getAssertion with `up: false` to find
//!   out which entries of an allow list or exclude list exist here before the real request
//!   (CTAP 2.2 section 6.2.2, "pre-flight"). With a non-empty allow list the engine signs for
//!   the first applicable credential without calling the approver: flags UP=0 and UV=0, BE
//!   and BS as usual, no hmac-secret output and no user entity. Relying parties reject
//!   assertions without UP for sign-in, so a probe result cannot log anyone in. Credentials
//!   with credProtect level 3 are not applicable without UV and are skipped. An empty allow
//!   list, or a probe that asks for UV, never reaches a credential (`NoCredentials` and
//!   `UvRequiredUnavailable`). A probe reveals to local processes whether a credential exists
//!   for a site, which processes of the same user can learn from the vault anyway.
//! - **excludeList**: a listed credential of this RP still asks the user (a Create prompt)
//!   before [`CoreError::CredentialExcluded`] is returned, so a page cannot probe for
//!   credentials without a gesture. If the user declines or the prompt times out, the
//!   approval error is returned instead, exactly as for a declined creation (WebAuthn
//!   section 6.3.2 step 3). Excluded credentials with credProtect level 3 only count when
//!   the approval included UV, as in CTAP.
//! - **credProtect**: level 3 needs UV; level 2 needs UV when there is no allow list. CTAP
//!   decides UV before looking up credentials, hirz decides it during the approval. So when
//!   a shown candidate needs UV the approver is asked with `uv_required`. If UV turns out to
//!   be unavailable and the RP did not require it, the protected candidates are dropped and
//!   the approver is asked again with the rest, or `NoCredentials` is returned: protected
//!   credentials stay invisible without UV, as in CTAP.
//! - **No applicable credential**: `NoCredentials` at once, without a prompt (CTAP 2.2
//!   getAssertion step 7). A client role that must hide this from pages (WebAuthn privacy
//!   considerations) has to delay or prompt on its own.
//! - **Allow list**: the first applicable credential in allow-list order is used, without a
//!   choice (CTAP: "select any credential"). Without an allow list the user picks among the
//!   discoverable credentials, newest first.
//! - **Same account again**: creating a discoverable credential replaces older discoverable
//!   credentials of the same RP id and user id (CTAP makeCredential, `rk`), after the new one
//!   is stored.
//! - **User entity**: returned for flows without an allow list; name and display name only
//!   when the approval included UV (CTAP getAssertion, user identifiable information).
//! - **Machine login**: RP ids starting with `pam://` (pam-u2f for login, sudo and screen
//!   unlock) are refused with `ApprovalError::Unavailable` (CTAP2_ERR_NOT_ALLOWED) before any
//!   prompt or vault access, silent probes included. hirz passkeys are synced software keys and
//!   must not become a login factor for the computer they run on, and an unlock that waits for
//!   a hirz approval could deadlock. See [`is_machine_login_rp_id`].

use crate::types::{
    AAGUID, Approval, ApprovalContext, ApprovalError, Approver, AssertionResponse, COSE_ALG_EDDSA,
    COSE_ALG_ES256, CREDENTIAL_ID_LEN, CandidateAccount, Ceremony, CoreError, CredProtect,
    GetAssertionRequest, HmacSecretSalts, HmacSecretWrap, MakeCredentialRequest,
    MakeCredentialResponse, UserEntity, UvRequirement,
};
use core::fmt;
use hirz_crypto::{Zeroizing, ed25519, es256};
use hirz_proto::auth_data::{
    AttestedCredentialData, AuthenticatorData, FLAG_BE, FLAG_BS, FLAG_UP, FLAG_UV,
};
use hirz_proto::cbor::MapBuilder;
use hirz_proto::cose;
use hirz_vault::{
    CredentialRecord, HmacSecretPair, MAX_STRING_LEN, MAX_USER_ID_LEN, Vault, VaultError,
};

/// Authenticator engine over one opened vault and one approver.
pub struct Engine<'a> {
    vault: &'a mut Vault,
    approver: &'a dyn Approver,
    clock: fn() -> u64,
}

impl fmt::Debug for Engine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Engine")
            .field("vault", &self.vault)
            .finish_non_exhaustive()
    }
}

impl<'a> Engine<'a> {
    pub fn new(vault: &'a mut Vault, approver: &'a dyn Approver) -> Self {
        Engine {
            vault,
            approver,
            clock: hirz_proto::time::unix_now,
        }
    }

    /// Replaces the clock used for `created_at` (Unix seconds).
    pub fn with_clock(mut self, clock: fn() -> u64) -> Self {
        self.clock = clock;
        self
    }

    pub fn vault(&self) -> &Vault {
        self.vault
    }

    fn reload(&mut self) -> Result<(), CoreError> {
        self.vault.reload().map(|_| ()).map_err(vault_error)
    }

    /// CTAP authenticatorMakeCredential / WebAuthn create. `origin` is shown in the prompt
    /// (extension path only).
    pub fn make_credential(
        &mut self,
        req: &MakeCredentialRequest,
        origin: Option<&str>,
    ) -> Result<MakeCredentialResponse, CoreError> {
        check_rp_id(&req.rp.id)?;
        refuse_machine_login(&req.rp.id)?;
        if req.user.id.is_empty() || req.user.id.len() > MAX_USER_ID_LEN {
            return Err(CoreError::InvalidRequest("user id must be 1 to 64 bytes"));
        }
        let algorithm = req
            .algorithms
            .iter()
            .copied()
            .find(|a| *a == COSE_ALG_ES256 || *a == COSE_ALG_EDDSA)
            .ok_or(CoreError::UnsupportedAlgorithm)?;
        self.reload()?;

        let (excluded, excluded_with_uv) = self.excluded(req);
        let rp_uv = req.uv == UvRequirement::Required;
        let ctx = ApprovalContext {
            ceremony: Ceremony::Create,
            rp_id: &req.rp.id,
            rp_name: req.rp.name.as_deref(),
            candidates: &[],
            new_account: Some(&req.user),
            uv_required: rp_uv,
            origin,
        };
        let approval = self
            .approver
            .approve(&ctx)
            .map_err(|e| approval_error(e, rp_uv))?;
        if !approval.user_present {
            return Err(CoreError::Approval(ApprovalError::Denied));
        }
        if excluded || (excluded_with_uv && approval.user_verified) {
            return Err(CoreError::CredentialExcluded);
        }
        if rp_uv && !approval.user_verified {
            return Err(CoreError::UvRequiredUnavailable);
        }

        let (private_key_pkcs8, public_key_cose) = generate_key(algorithm)?;
        let mut credential_id = vec![0u8; CREDENTIAL_ID_LEN];
        hirz_crypto::random_fill(&mut credential_id).map_err(crypto_error)?;
        let hmac_secret = req.extensions.hmac_secret.then(new_hmac_pair).transpose()?;
        let cred_protect = req.extensions.cred_protect.map(cred_protect_level);
        let record = CredentialRecord {
            credential_id: credential_id.clone(),
            rp_id: req.rp.id.clone(),
            rp_name: clip(req.rp.name.as_deref()),
            user_id: req.user.id.clone(),
            user_name: clip(req.user.name.as_deref()),
            user_display_name: clip(req.user.display_name.as_deref()),
            algorithm,
            private_key_pkcs8,
            created_at: (self.clock)(),
            cred_protect,
            hmac_secret,
            discoverable: req.resident_key,
            backup_eligible: true,
        };
        let backup_state = self.vault.backup_state();
        self.vault.put(record).map_err(vault_error)?;
        if req.resident_key {
            self.replace_older(&req.rp.id, &req.user.id, &credential_id);
        }

        let mut ext = MapBuilder::new();
        let mut has_ext = false;
        if let Some(level) = cred_protect {
            ext = ext.text("credProtect", i64::from(level));
            has_ext = true;
        }
        if req.extensions.hmac_secret {
            ext = ext.text("hmac-secret", true);
            has_ext = true;
        }
        let auth_data = AuthenticatorData {
            rp_id_hash: hirz_crypto::sha256(req.rp.id.as_bytes()),
            flags: flags(true, approval.user_verified, backup_state),
            sign_count: 0,
            attested_credential: Some(AttestedCredentialData {
                aaguid: AAGUID,
                credential_id: credential_id.clone(),
                public_key: public_key_cose.clone(),
            }),
            extensions: has_ext.then(|| ext.build()),
        }
        .encode()
        .map_err(encoding_error)?;

        Ok(MakeCredentialResponse {
            auth_data,
            credential_id,
            public_key_cose,
            algorithm,
            hmac_secret: req.extensions.hmac_secret,
            resident_key: req.resident_key,
        })
    }

    /// (any excluded credential without credProtect 3, any excluded with credProtect 3)
    fn excluded(&self, req: &MakeCredentialRequest) -> (bool, bool) {
        let mut plain = false;
        let mut uv_only = false;
        for id in &req.exclude_list {
            if let Some(rec) = self.vault.get(id)
                && rec.rp_id == req.rp.id
            {
                if rec.cred_protect == Some(3) {
                    uv_only = true;
                } else {
                    plain = true;
                }
            }
        }
        (plain, uv_only)
    }

    fn replace_older(&mut self, rp_id: &str, user_id: &[u8], keep: &[u8]) {
        let older: Vec<Vec<u8>> = self
            .vault
            .credentials_for_rp(rp_id)
            .into_iter()
            .filter(|r| r.discoverable && r.user_id == user_id && r.credential_id != keep)
            .map(|r| r.credential_id.clone())
            .collect();
        for id in older {
            // Best effort: the new credential is already stored, and a leftover older one
            // only shows up as an extra account.
            let _ = self.vault.delete(&id);
        }
    }

    /// CTAP authenticatorGetAssertion / WebAuthn get. With `hmac` (CTAP path) the
    /// hmac-secret output is wrapped into the authData extensions; without it (extension
    /// path) it is returned raw in `hmac_secret_output`.
    pub fn get_assertion(
        &mut self,
        req: &GetAssertionRequest,
        origin: Option<&str>,
        hmac: Option<&dyn HmacSecretWrap>,
    ) -> Result<AssertionResponse, CoreError> {
        check_rp_id(&req.rp_id)?;
        refuse_machine_login(&req.rp_id)?;
        if !req.up {
            return self.silent_probe(req);
        }
        self.reload()?;
        let vault: &Vault = self.vault;
        let with_list = !req.allow_list.is_empty();
        let mut pool = locate(vault, req);
        if pool.is_empty() {
            return Err(CoreError::NoCredentials);
        }
        let rp_uv = req.uv == UvRequirement::Required;
        let (record, approval) = match ask(self.approver, req, origin, &pool, rp_uv) {
            Ok(v) => v,
            Err(CoreError::UvRequiredUnavailable) if !rp_uv => {
                pool.retain(|r| !needs_uv(r, with_list));
                if pool.is_empty() {
                    return Err(CoreError::NoCredentials);
                }
                ask(self.approver, req, origin, &pool, false)?
            }
            Err(e) => return Err(e),
        };
        let uv = approval.user_verified;

        let output = req
            .extensions
            .hmac_secret
            .as_ref()
            .and_then(|salts| hmac_secret_output(record, salts, uv));
        let (extensions, hmac_secret_output) = match (output, hmac) {
            (None, _) => (None, None),
            (Some(out), Some(wrap)) => (
                Some(
                    MapBuilder::new()
                        .text("hmac-secret", wrap.wrap(&out)?)
                        .build(),
                ),
                None,
            ),
            (Some(out), None) => (None, Some(out.to_vec())),
        };
        let assertion = sign_assertion(
            record,
            req,
            flags(true, uv, vault.backup_state()),
            extensions,
        )?;

        let user = (!with_list).then(|| UserEntity {
            id: record.user_id.clone(),
            name: record.user_name.clone().filter(|_| uv),
            display_name: record.user_display_name.clone().filter(|_| uv),
        });
        Ok(AssertionResponse {
            user,
            hmac_secret_output,
            ..assertion
        })
    }

    /// getAssertion with `up: false` (see the module documentation). Never prompts.
    fn silent_probe(&mut self, req: &GetAssertionRequest) -> Result<AssertionResponse, CoreError> {
        if req.allow_list.is_empty() {
            return Err(CoreError::NoCredentials);
        }
        if req.uv == UvRequirement::Required {
            return Err(CoreError::UvRequiredUnavailable);
        }
        self.reload()?;
        let vault: &Vault = self.vault;
        let record = locate(vault, req)
            .into_iter()
            .find(|r| !needs_uv(r, true))
            .ok_or(CoreError::NoCredentials)?;
        sign_assertion(record, req, flags(false, false, vault.backup_state()), None)
    }

    /// CTAP authenticatorSelection: user presence only.
    pub fn select(&mut self) -> Result<(), CoreError> {
        let approval = self
            .approver
            .confirm_selection()
            .map_err(CoreError::Approval)?;
        if approval.user_present {
            Ok(())
        } else {
            Err(CoreError::Approval(ApprovalError::Denied))
        }
    }
}

const MACHINE_LOGIN_PREFIX: &str = "pam://";

/// True for RP ids that ask for a login factor of this computer (pam-u2f uses `pam://HOST`
/// by default). The engine refuses them; frontends use this to log the refusal.
pub fn is_machine_login_rp_id(rp_id: &str) -> bool {
    rp_id
        .get(..MACHINE_LOGIN_PREFIX.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(MACHINE_LOGIN_PREFIX))
}

fn refuse_machine_login(rp_id: &str) -> Result<(), CoreError> {
    if is_machine_login_rp_id(rp_id) {
        return Err(CoreError::Approval(ApprovalError::Unavailable));
    }
    Ok(())
}

fn check_rp_id(rp_id: &str) -> Result<(), CoreError> {
    if rp_id.is_empty() || rp_id.len() > MAX_STRING_LEN {
        return Err(CoreError::InvalidRequest("invalid rp id"));
    }
    Ok(())
}

/// Applicable credentials before credProtect: allow-list order without duplicates, or the
/// discoverable credentials of the RP, newest first.
fn locate<'v>(vault: &'v Vault, req: &GetAssertionRequest) -> Vec<&'v CredentialRecord> {
    if req.allow_list.is_empty() {
        let mut found: Vec<&CredentialRecord> = vault
            .credentials_for_rp(&req.rp_id)
            .into_iter()
            .filter(|r| r.discoverable)
            .collect();
        found.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.credential_id.cmp(&b.credential_id))
        });
        return found;
    }
    let mut found: Vec<&CredentialRecord> = Vec::new();
    for id in &req.allow_list {
        if let Some(rec) = vault.get(id)
            && rec.rp_id == req.rp_id
            && !found.iter().any(|f| f.credential_id == rec.credential_id)
        {
            found.push(rec);
        }
    }
    found
}

/// CTAP credProtect: whether this credential is usable only after UV in this request.
fn needs_uv(rec: &CredentialRecord, with_list: bool) -> bool {
    match rec.cred_protect {
        Some(3) => true,
        Some(2) => !with_list,
        _ => false,
    }
}

/// One Get approval over `pool`. UV is required when the RP requires it or when a shown
/// candidate is protected by credProtect.
fn ask<'v>(
    approver: &dyn Approver,
    req: &GetAssertionRequest,
    origin: Option<&str>,
    pool: &[&'v CredentialRecord],
    rp_uv: bool,
) -> Result<(&'v CredentialRecord, Approval), CoreError> {
    let with_list = !req.allow_list.is_empty();
    let shown: &[&CredentialRecord] = if with_list {
        pool.get(..1).unwrap_or(&[])
    } else {
        pool
    };
    if shown.is_empty() {
        return Err(CoreError::NoCredentials);
    }
    let uv_required = rp_uv || shown.iter().any(|r| needs_uv(r, with_list));
    let candidates: Vec<CandidateAccount> = shown
        .iter()
        .map(|r| CandidateAccount {
            credential_id: r.credential_id.clone(),
            user_name: r.user_name.clone(),
            user_display_name: r.user_display_name.clone(),
        })
        .collect();
    let ctx = ApprovalContext {
        ceremony: Ceremony::Get,
        rp_id: &req.rp_id,
        rp_name: shown.first().and_then(|r| r.rp_name.as_deref()),
        candidates: &candidates,
        new_account: None,
        uv_required,
        origin,
    };
    let approval = approver
        .approve(&ctx)
        .map_err(|e| approval_error(e, uv_required))?;
    let index = match (shown.len(), approval.selected) {
        (1, None) => 0,
        (_, Some(i)) => i,
        (_, None) => return Err(invalid_selection()),
    };
    let record = *shown.get(index).ok_or_else(invalid_selection)?;
    if !approval.user_present {
        return Err(CoreError::Approval(ApprovalError::Denied));
    }
    if uv_required && !approval.user_verified {
        return Err(CoreError::UvRequiredUnavailable);
    }
    Ok((record, approval))
}

fn invalid_selection() -> CoreError {
    CoreError::Approval(ApprovalError::Internal(
        "approver returned no valid account selection".into(),
    ))
}

fn approval_error(e: ApprovalError, uv_required: bool) -> CoreError {
    match e {
        ApprovalError::Unavailable if uv_required => CoreError::UvRequiredUnavailable,
        e => CoreError::Approval(e),
    }
}

fn flags(up: bool, uv: bool, backup_state: bool) -> u8 {
    let mut f = FLAG_BE;
    if up {
        f |= FLAG_UP;
    }
    if uv {
        f |= FLAG_UV;
    }
    if backup_state {
        f |= FLAG_BS;
    }
    f
}

fn cred_protect_level(c: CredProtect) -> u8 {
    match c {
        CredProtect::UserVerificationOptional => 1,
        CredProtect::UserVerificationOptionalWithCredentialIdList => 2,
        CredProtect::UserVerificationRequired => 3,
    }
}

/// Truncates at a character boundary so overlong names never fail a registration.
fn clip(s: Option<&str>) -> Option<String> {
    let s = s?;
    let mut end = s.len().min(MAX_STRING_LEN);
    while !s.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    Some(s.get(..end).unwrap_or_default().to_owned())
}

fn generate_key(algorithm: i64) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), CoreError> {
    match algorithm {
        COSE_ALG_ES256 => {
            let (pkcs8, x, y) = es256::generate().map_err(crypto_error)?;
            Ok((pkcs8, cose::encode_es256(&x, &y)))
        }
        COSE_ALG_EDDSA => {
            let (pkcs8, public) = ed25519::generate().map_err(crypto_error)?;
            Ok((pkcs8, cose::encode_ed25519(&public)))
        }
        _ => Err(CoreError::UnsupportedAlgorithm),
    }
}

fn new_hmac_pair() -> Result<HmacSecretPair, CoreError> {
    let mut with_uv = Zeroizing::new([0u8; 32]);
    let mut without_uv = Zeroizing::new([0u8; 32]);
    hirz_crypto::random_fill(with_uv.as_mut_slice()).map_err(crypto_error)?;
    hirz_crypto::random_fill(without_uv.as_mut_slice()).map_err(crypto_error)?;
    Ok(HmacSecretPair {
        cred_random_with_uv: with_uv,
        cred_random_without_uv: without_uv,
    })
}

/// HMAC-SHA-256(CredRandom, salt1) [|| HMAC-SHA-256(CredRandom, salt2)], CredRandom chosen
/// by the UV result. None when the credential was created without hmac-secret.
fn hmac_secret_output(
    rec: &CredentialRecord,
    salts: &HmacSecretSalts,
    uv: bool,
) -> Option<Zeroizing<Vec<u8>>> {
    let pair = rec.hmac_secret.as_ref()?;
    let key: &[u8; 32] = if uv {
        &pair.cred_random_with_uv
    } else {
        &pair.cred_random_without_uv
    };
    let mut out = Zeroizing::new(Vec::with_capacity(64));
    out.extend_from_slice(Zeroizing::new(hirz_crypto::hmac_sha256(key, &salts.salt1)).as_slice());
    if let Some(salt2) = &salts.salt2 {
        out.extend_from_slice(Zeroizing::new(hirz_crypto::hmac_sha256(key, salt2)).as_slice());
    }
    Some(out)
}

/// authenticatorData for an assertion and the signature over it and the client data hash,
/// without a user entity or a raw hmac-secret output.
fn sign_assertion(
    record: &CredentialRecord,
    req: &GetAssertionRequest,
    flags: u8,
    extensions: Option<hirz_proto::cbor::Value>,
) -> Result<AssertionResponse, CoreError> {
    let auth_data = AuthenticatorData {
        rp_id_hash: hirz_crypto::sha256(req.rp_id.as_bytes()),
        flags,
        sign_count: 0,
        attested_credential: None,
        extensions,
    }
    .encode()
    .map_err(encoding_error)?;
    let mut message = Vec::with_capacity(auth_data.len().saturating_add(32));
    message.extend_from_slice(&auth_data);
    message.extend_from_slice(&req.client_data_hash);
    let signature = sign(record, &message)?;
    Ok(AssertionResponse {
        credential_id: record.credential_id.clone(),
        auth_data,
        signature,
        user_handle: record.user_id.clone(),
        user: None,
        hmac_secret_output: None,
    })
}

fn sign(rec: &CredentialRecord, message: &[u8]) -> Result<Vec<u8>, CoreError> {
    match rec.algorithm {
        COSE_ALG_ES256 => es256::sign(&rec.private_key_pkcs8, message).map_err(crypto_error),
        COSE_ALG_EDDSA => ed25519::sign(&rec.private_key_pkcs8, message)
            .map(|s| s.to_vec())
            .map_err(crypto_error),
        _ => Err(CoreError::Crypto(
            "unsupported algorithm in credential record".into(),
        )),
    }
}

fn vault_error(e: VaultError) -> CoreError {
    CoreError::Vault(e.to_string())
}

fn crypto_error(e: hirz_crypto::CryptoError) -> CoreError {
    CoreError::Crypto(format!("{e:?}"))
}

fn encoding_error(_: hirz_proto::Error) -> CoreError {
    CoreError::InvalidRequest("authenticator data encoding failed")
}

#[cfg(test)]
mod tests;
