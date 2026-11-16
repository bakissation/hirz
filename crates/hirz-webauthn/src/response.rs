//! RegistrationResponseJSON and AuthenticationResponseJSON (WebAuthn Level 3 section 5.1).
//!
//! The engine output is cross-checked against the request before anything is returned:
//! a mismatch is an engine bug and must not reach the relying party.

use crate::create::{CreatePlan, USER_ID_MAX};
use crate::error::Error;
use crate::get::GetPlan;
use hirz_core::{
    AssertionResponse, COSE_ALG_EDDSA, COSE_ALG_ES256, MakeCredentialResponse, UvRequirement,
};
use hirz_crypto::{ed25519, es256, sha256};
use hirz_proto::auth_data::{AuthenticatorData, FLAG_UP, FLAG_UV};
use hirz_proto::json::Json;
use hirz_proto::{attestation, base64url, cbor, cose};

type Result<T> = core::result::Result<T, Error>;

fn b64(bytes: &[u8]) -> Json {
    Json::String(base64url::encode(bytes))
}

fn obj(members: Vec<(&str, Json)>) -> Json {
    Json::Object(
        members
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect(),
    )
}

fn check_auth_data(raw: &[u8], rp_id: &str, uv: UvRequirement) -> Result<AuthenticatorData> {
    let ad = AuthenticatorData::parse(raw, &cbor::Limits::default())
        .map_err(|_| Error::EngineOutput("malformed authenticator data"))?;
    if ad.rp_id_hash != sha256(rp_id.as_bytes()) {
        return Err(Error::EngineOutput("authenticator data for another RP ID"));
    }
    if ad.flags & FLAG_UP == 0 {
        return Err(Error::EngineOutput("user presence flag missing"));
    }
    if uv == UvRequirement::Required && ad.flags & FLAG_UV == 0 {
        return Err(Error::EngineOutput("user verification flag missing"));
    }
    Ok(ad)
}

fn spki(public_key_cose: &[u8], algorithm: i64) -> Result<Vec<u8>> {
    let value = cbor::decode(public_key_cose, &cbor::Limits::default())
        .map_err(|_| Error::EngineOutput("malformed public key"))?;
    let key = cose::parse_public_key(&value)
        .map_err(|_| Error::EngineOutput("unsupported public key"))?;
    match (key, algorithm) {
        (cose::PublicKey::Es256 { x, y }, COSE_ALG_ES256) => Ok(es256::spki_der(&x, &y)),
        (cose::PublicKey::Ed25519 { x }, COSE_ALG_EDDSA) => Ok(ed25519::spki_der(&x)),
        _ => Err(Error::EngineOutput("public key does not match algorithm")),
    }
}

/// Builds RegistrationResponseJSON.
pub fn registration_response(plan: &CreatePlan, resp: &MakeCredentialResponse) -> Result<Json> {
    let req = &plan.request;
    if !req.algorithms.contains(&resp.algorithm) {
        return Err(Error::EngineOutput("algorithm not requested"));
    }
    let ad = check_auth_data(&resp.auth_data, &req.rp.id, req.uv)?;
    let attested = ad
        .attested_credential
        .as_ref()
        .ok_or(Error::EngineOutput("attested credential data missing"))?;
    if attested.credential_id != resp.credential_id || attested.public_key != resp.public_key_cose {
        return Err(Error::EngineOutput(
            "credential does not match authenticator data",
        ));
    }
    let public_key = spki(&resp.public_key_cose, resp.algorithm)?;

    let mut ext = Vec::new();
    if plan.cred_props {
        ext.push((
            "credProps",
            obj(vec![("rk", Json::Bool(resp.resident_key))]),
        ));
    }
    if plan.prf {
        ext.push(("prf", obj(vec![("enabled", Json::Bool(resp.hmac_secret))])));
    }

    Ok(obj(vec![
        ("id", b64(&resp.credential_id)),
        ("rawId", b64(&resp.credential_id)),
        (
            "response",
            obj(vec![
                ("clientDataJSON", b64(plan.client_data_json.as_bytes())),
                ("authenticatorData", b64(&resp.auth_data)),
                ("transports", Json::Array(vec![Json::from("internal")])),
                ("publicKey", b64(&public_key)),
                ("publicKeyAlgorithm", Json::from(resp.algorithm)),
                (
                    "attestationObject",
                    b64(&attestation::none_webauthn(&resp.auth_data)),
                ),
            ]),
        ),
        ("authenticatorAttachment", Json::from("platform")),
        ("clientExtensionResults", obj(ext)),
        ("type", Json::from("public-key")),
    ]))
}

fn prf_results(plan: &GetPlan, output: Option<&[u8]>) -> Result<Json> {
    let Some(salts) = &plan.request.extensions.hmac_secret else {
        return Ok(obj(vec![]));
    };
    let Some(output) = output else {
        return Ok(obj(vec![]));
    };
    let (first, second) = match (output.split_at_checked(32), salts.salt2.is_some()) {
        (Some((first, [])), false) => (first, None),
        (Some((first, rest)), true) if rest.len() == 32 => (first, Some(rest)),
        _ => {
            return Err(Error::EngineOutput(
                "hmac-secret output has the wrong length",
            ));
        }
    };
    let mut results = vec![("first", b64(first))];
    if let Some(second) = second {
        results.push(("second", b64(second)));
    }
    Ok(obj(vec![("results", obj(results))]))
}

/// Builds AuthenticationResponseJSON.
pub fn authentication_response(plan: &GetPlan, resp: &AssertionResponse) -> Result<Json> {
    let req = &plan.request;
    let ad = check_auth_data(&resp.auth_data, &req.rp_id, req.uv)?;
    if ad.attested_credential.is_some() {
        return Err(Error::EngineOutput(
            "attested credential data in an assertion",
        ));
    }
    if resp.credential_id.is_empty()
        || (!req.allow_list.is_empty() && !req.allow_list.contains(&resp.credential_id))
    {
        return Err(Error::EngineOutput("credential not allowed"));
    }
    if resp.signature.is_empty() {
        return Err(Error::EngineOutput("empty signature"));
    }
    if resp.user_handle.len() > USER_ID_MAX
        || (req.allow_list.is_empty() && resp.user_handle.is_empty())
    {
        return Err(Error::EngineOutput("invalid user handle"));
    }

    let mut response = vec![
        ("clientDataJSON", b64(plan.client_data_json.as_bytes())),
        ("authenticatorData", b64(&resp.auth_data)),
        ("signature", b64(&resp.signature)),
    ];
    if !resp.user_handle.is_empty() {
        response.push(("userHandle", b64(&resp.user_handle)));
    }

    let mut ext = Vec::new();
    if plan.prf {
        ext.push((
            "prf",
            prf_results(plan, resp.hmac_secret_output.as_deref())?,
        ));
    }

    Ok(obj(vec![
        ("id", b64(&resp.credential_id)),
        ("rawId", b64(&resp.credential_id)),
        ("response", obj(response)),
        ("authenticatorAttachment", Json::from("platform")),
        ("clientExtensionResults", obj(ext)),
        ("type", Json::from("public-key")),
    ]))
}
