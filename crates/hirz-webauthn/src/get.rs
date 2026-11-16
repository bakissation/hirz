//! `navigator.credentials.get()`: PublicKeyCredentialRequestOptionsJSON to a
//! getAssertion request (WebAuthn Level 3 section 5.1.4), and the account list behind
//! the extension's conditional mediation suggestions.

use crate::common::{
    CHALLENGE_MAX, CHALLENGE_MIN, CREDENTIAL_ID_MAX, MAX_DESCRIPTORS, MAX_RP_ID_CHARS,
    MAX_TOKEN_CHARS, descriptors, hints_prefer_other, not_handled_if, prf_values,
    user_verification,
};
use crate::error::Error;
use crate::fields::{Obj, Result, b64};
use crate::origin::Origin;
use crate::rp_id::validate_rp_id;
use hirz_core::{GetAssertionRequest, GetExtensions, HmacSecretSalts};
use hirz_crypto::sha256;
use hirz_proto::client_data::{self, CeremonyType};
use hirz_proto::json::Json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetPlan {
    pub request: GetAssertionRequest,
    /// The exact clientDataJSON whose SHA-256 is `request.client_data_hash`.
    pub client_data_json: String,
    pub prf: bool,
}

/// `evalByCredential` entries override `eval` per credential; the engine takes a single salt set,
/// so requests whose allowed credentials need different salts are left to Firefox.
fn prf_salts(
    prf: &Obj<'_>,
    allow_list: &[Vec<u8>],
    listed: usize,
) -> Result<Option<HmacSecretSalts>> {
    let eval = prf.get("eval").map(|v| prf_values(v, "prf")).transpose()?;
    let Some(by_cred) = prf.opt_obj("evalByCredential")? else {
        return Ok(eval);
    };
    let entries = by_cred.members();
    if entries.is_empty() {
        return Ok(eval);
    }
    if entries.len() > MAX_DESCRIPTORS {
        return Err(Error::InvalidOptions("evalByCredential"));
    }
    if listed == 0 {
        return Err(Error::NotSupported(
            "prf evalByCredential without allowCredentials",
        ));
    }
    let mut overrides: Vec<(Vec<u8>, HmacSecretSalts)> = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        let id = b64(key, 1, CREDENTIAL_ID_MAX).ok_or(Error::InvalidOptions("evalByCredential"))?;
        if !allow_list.contains(&id) {
            return Err(Error::InvalidOptions("evalByCredential"));
        }
        overrides.push((id, prf_values(value, "evalByCredential")?));
    }
    let mut chosen: Option<Option<HmacSecretSalts>> = None;
    for id in allow_list {
        let salts = overrides
            .iter()
            .find(|(k, _)| k == id)
            .map(|(_, s)| s.clone())
            .or_else(|| eval.clone());
        match &chosen {
            None => chosen = Some(salts),
            Some(prev) if *prev == salts => {}
            Some(_) => {
                return Err(Error::NotHandled(
                    "prf inputs differ between allowed credentials",
                ));
            }
        }
    }
    Ok(chosen.flatten())
}

pub fn prepare_get(options: &Json, origin: &Origin) -> core::result::Result<GetPlan, Error> {
    let o = Obj::new(options, "options")?;

    let challenge = o.req_bytes("challenge", CHALLENGE_MIN, CHALLENGE_MAX)?;
    o.opt_number("timeout")?;
    let rp_id = o.opt_str("rpId", MAX_RP_ID_CHARS)?;
    let (allow_list, listed) = descriptors(&o, "allowCredentials")?;
    let uv = user_verification(o.opt_str("userVerification", MAX_TOKEN_CHARS)?);
    let hints_other = hints_prefer_other(&o)?;

    let mut salts = None;
    let mut prf = false;
    if let Some(ext) = o.opt_obj("extensions")? {
        // The U2F application parameter and the `appid` result are not implemented.
        if ext.opt_str("appid", 2048)?.is_some() {
            return Err(Error::NotHandled("appid extension"));
        }
        if let Some(p) = ext.opt_obj("prf")? {
            salts = prf_salts(&p, &allow_list, listed)?;
            prf = true;
        }
    }

    let rp_id = validate_rp_id(rp_id, origin)?;

    not_handled_if(hints_other, "hints prefer another authenticator")?;
    not_handled_if(
        listed > 0 && allow_list.is_empty(),
        "no allowed credential of a supported type",
    )?;

    let client_data_json =
        client_data::serialize(CeremonyType::Get, &challenge, origin.as_str(), false, None);
    let client_data_hash = sha256(client_data_json.as_bytes());

    Ok(GetPlan {
        request: GetAssertionRequest {
            client_data_hash,
            rp_id,
            allow_list,
            uv,
            up: true,
            extensions: GetExtensions { hmac_secret: salts },
        },
        client_data_json,
        prf,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPlan {
    pub rp_id: String,
    pub allow_list: Vec<Vec<u8>>,
}

/// Same RP ID rules as [`prepare_get`]; other members are ignored.
pub fn prepare_list(options: &Json, origin: &Origin) -> core::result::Result<ListPlan, Error> {
    let o = Obj::new(options, "options")?;
    let rp_id = o.opt_str("rpId", MAX_RP_ID_CHARS)?;
    let (allow_list, listed) = descriptors(&o, "allowCredentials")?;
    let rp_id = validate_rp_id(rp_id, origin)?;
    not_handled_if(
        listed > 0 && allow_list.is_empty(),
        "no allowed credential of a supported type",
    )?;
    Ok(ListPlan { rp_id, allow_list })
}
