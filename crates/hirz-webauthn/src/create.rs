//! `navigator.credentials.create()`: PublicKeyCredentialCreationOptionsJSON to a
//! makeCredential request (WebAuthn Level 3 section 5.1.3).

use crate::common::{
    CHALLENGE_MAX, CHALLENGE_MIN, MAX_NAME_CHARS, MAX_RP_ID_CHARS, MAX_TOKEN_CHARS, PUBLIC_KEY,
    descriptors, hints_prefer_other, not_handled_if, prf_values, user_verification,
};
use crate::error::Error;
use crate::fields::{Obj, Result};
use crate::origin::Origin;
use crate::rp_id::validate_rp_id;
use hirz_core::{
    COSE_ALG_EDDSA, COSE_ALG_ES256, CredProtect, MakeCredentialRequest, MakeExtensions, RpEntity,
    UserEntity,
};
use hirz_crypto::sha256;
use hirz_proto::client_data::{self, CeremonyType};
use hirz_proto::json::Json;

pub(crate) const USER_ID_MAX: usize = 64;
const MAX_PARAMS: usize = 64;
const MAX_ATTESTATION_FORMATS: usize = 16;

/// A validated create ceremony, ready for the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatePlan {
    pub request: MakeCredentialRequest,
    /// The exact clientDataJSON whose SHA-256 is `request.client_data_hash`.
    pub client_data_json: String,
    /// The RP asked for credProps.
    pub cred_props: bool,
    /// The RP asked for prf.
    pub prf: bool,
}

fn cred_protect(value: Option<&str>) -> Option<CredProtect> {
    match value {
        Some("userVerificationOptional") => Some(CredProtect::UserVerificationOptional),
        Some("userVerificationOptionalWithCredentialIDList") => {
            Some(CredProtect::UserVerificationOptionalWithCredentialIdList)
        }
        Some("userVerificationRequired") => Some(CredProtect::UserVerificationRequired),
        _ => None,
    }
}

fn algorithms(o: &Obj<'_>) -> Result<Vec<i64>> {
    let params = o.req_array("pubKeyCredParams", MAX_PARAMS)?;
    let mut algs = Vec::new();
    for p in params {
        let p = Obj::new(p, "pubKeyCredParams")?;
        let ty = p.req_str("type", MAX_TOKEN_CHARS)?;
        let alg = p
            .get("alg")
            .and_then(Json::as_i64)
            .ok_or(Error::InvalidOptions("pubKeyCredParams"))?;
        if ty == PUBLIC_KEY
            && matches!(alg, COSE_ALG_ES256 | COSE_ALG_EDDSA)
            && !algs.contains(&alg)
        {
            algs.push(alg);
        }
    }
    if params.is_empty() {
        // The spec default is ES256 then RS256; only ES256 is supported.
        algs.push(COSE_ALG_ES256);
    }
    Ok(algs)
}

/// Validates creation options for a top-level, same-origin call from `origin`.
pub fn prepare_create(options: &Json, origin: &Origin) -> core::result::Result<CreatePlan, Error> {
    let o = Obj::new(options, "options")?;

    let rp = o.req_obj("rp")?;
    let rp_name = rp.req_str("name", MAX_NAME_CHARS)?;
    let rp_id = rp.opt_str("id", MAX_RP_ID_CHARS)?;

    let user = o.req_obj("user")?;
    let user_id = user.req_bytes("id", 1, USER_ID_MAX)?;
    let user_name = user.req_str("name", MAX_NAME_CHARS)?;
    let user_display_name = user.req_str("displayName", MAX_NAME_CHARS)?;

    let challenge = o.req_bytes("challenge", CHALLENGE_MIN, CHALLENGE_MAX)?;
    let algs = algorithms(&o)?;
    o.opt_number("timeout")?;
    let (exclude_list, _) = descriptors(&o, "excludeCredentials")?;

    let (attachment, resident_key, uv) = match o.opt_obj("authenticatorSelection")? {
        Some(sel) => {
            let attachment = sel.opt_str("authenticatorAttachment", MAX_TOKEN_CHARS)?;
            let resident = sel.opt_str("residentKey", MAX_TOKEN_CHARS)?;
            let require = sel.opt_bool("requireResidentKey")?.unwrap_or(false);
            let uv = sel.opt_str("userVerification", MAX_TOKEN_CHARS)?;
            let resident_key = match resident {
                Some("required" | "preferred") => true,
                Some("discouraged") => false,
                _ => require,
            };
            (attachment, resident_key, user_verification(uv))
        }
        None => (None, false, user_verification(None)),
    };

    let attestation = o.opt_str("attestation", MAX_TOKEN_CHARS)?;
    o.opt_str_list(
        "attestationFormats",
        MAX_ATTESTATION_FORMATS,
        MAX_TOKEN_CHARS,
    )?;
    let hints_other = hints_prefer_other(&o)?;

    let mut extensions = MakeExtensions::default();
    let mut cred_props = false;
    let mut prf = false;
    let mut large_blob_required = false;
    if let Some(ext) = o.opt_obj("extensions")? {
        cred_props = ext.opt_bool("credProps")?.unwrap_or(false);
        if let Some(p) = ext.opt_obj("prf")? {
            if p.get("evalByCredential").is_some() {
                return Err(Error::NotSupported("prf evalByCredential at creation"));
            }
            if let Some(eval) = p.get("eval") {
                prf_values(eval, "prf")?;
            }
            prf = true;
        }
        let policy = ext.opt_str("credentialProtectionPolicy", MAX_TOKEN_CHARS)?;
        ext.opt_bool("enforceCredentialProtectionPolicy")?;
        extensions.cred_protect = cred_protect(policy);
        if let Some(lb) = ext.opt_obj("largeBlob")? {
            large_blob_required = lb.opt_str("support", MAX_TOKEN_CHARS)? == Some("required");
        }
    }
    extensions.cred_props = cred_props;
    extensions.hmac_secret = prf;

    let rp_id = validate_rp_id(rp_id, origin)?;

    not_handled_if(
        attachment == Some("cross-platform"),
        "cross-platform authenticator requested",
    )?;
    not_handled_if(hints_other, "hints prefer another authenticator")?;
    not_handled_if(
        attestation == Some("enterprise"),
        "enterprise attestation requested",
    )?;
    not_handled_if(large_blob_required, "largeBlob required")?;
    not_handled_if(algs.is_empty(), "no supported algorithm")?;

    let client_data_json = client_data::serialize(
        CeremonyType::Create,
        &challenge,
        origin.as_str(),
        false,
        None,
    );
    let client_data_hash = sha256(client_data_json.as_bytes());

    Ok(CreatePlan {
        request: MakeCredentialRequest {
            client_data_hash,
            rp: RpEntity {
                id: rp_id,
                name: Some(rp_name.to_owned()),
            },
            user: UserEntity {
                id: user_id,
                name: Some(user_name.to_owned()),
                display_name: Some(user_display_name.to_owned()),
            },
            algorithms: algs,
            exclude_list,
            resident_key,
            uv,
            extensions,
        },
        client_data_json,
        cred_props,
        prf,
    })
}
