//! The message envelope shared with the Firefox extension, and the pure entry point the
//! native host calls for every request.
//!
//! Request: `{"v":1,"id":n,"type":"create"|"get"|"list"|"hello"|"capabilities","origin":s,
//! "topOrigin"?:s|null,"crossOrigin"?:bool,"options":{...}}`.
//! Success: `{"v":1,"id":n,"ok":true,...}` with `credential`, `accounts`, `version` or
//! `capabilities`. Failure: `{"v":1,"id":n|null,"ok":false,"error":name,"message":s}`.
//!
//! `list` backs the extension's conditional mediation suggestions: `options` is
//! `{rpId?, allowCredentials?}`, validated like `get`, and the reply carries
//! `accounts: [{id, name, displayName}]`. It never returns key material.
//!
//! Decisions:
//! - An unknown `v` gets `NotHandled`: a newer extension then falls back to Firefox
//!   instead of failing the page.
//! - An unknown `type` (and any other malformed envelope) gets `UnknownError`: it is a
//!   bug in the caller, not a ceremony Firefox could run instead.
//! - `origin` is the parent-process `sender.origin`. `topOrigin` and `crossOrigin` are
//!   only used to refuse frames: any request not same-origin with its top-level
//!   document gets `NotHandled`.

use crate::common::{MAX_DESCRIPTORS, MAX_NAME_CHARS};
use crate::create::prepare_create;
use crate::error::Error;
use crate::get::{prepare_get, prepare_list};
use crate::origin::Origin;
use crate::response::{authentication_response, registration_response};
use hirz_core::{
    AssertionResponse, CandidateAccount, CoreError, GetAssertionRequest, MakeCredentialRequest,
    MakeCredentialResponse,
};
use hirz_proto::base64url;
use hirz_proto::json::Json;

pub const PROTOCOL_VERSION: u64 = 1;

/// Largest integer that survives a round trip through a JavaScript number.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The authenticator as seen by the extension frontend. `origin_for_display` is the
/// validated origin, for the approval prompt only.
pub trait Engine {
    fn make_credential(
        &mut self,
        request: &MakeCredentialRequest,
        origin_for_display: &str,
    ) -> Result<MakeCredentialResponse, CoreError>;

    fn get_assertion(
        &mut self,
        request: &GetAssertionRequest,
        origin_for_display: &str,
    ) -> Result<AssertionResponse, CoreError>;

    /// True when a host-verified method (polkit, fprintd, PIN) is configured, so that
    /// `userVerifyingPlatformAuthenticator` is reported honestly.
    fn user_verification_available(&self) -> bool;

    /// The accounts a `get` for `rp_id` could offer without user verification: with an
    /// empty `allow_list` the discoverable credentials of the RP, otherwise the listed
    /// ones that belong to the RP; credProtect 3 never, credProtect 2 only when listed.
    /// No prompt, no signature. The default lists nothing, so Firefox keeps the request.
    fn list_accounts(
        &mut self,
        rp_id: &str,
        allow_list: &[Vec<u8>],
    ) -> Result<Vec<CandidateAccount>, CoreError> {
        let _ = (rp_id, allow_list);
        Ok(Vec::new())
    }
}

fn reply(id: Option<u64>, ok: bool, body: Vec<(&str, Json)>) -> Json {
    let mut members = vec![
        ("v".to_owned(), Json::from(PROTOCOL_VERSION)),
        ("id".to_owned(), id.map_or(Json::Null, Json::from)),
        ("ok".to_owned(), Json::Bool(ok)),
    ];
    members.extend(body.into_iter().map(|(k, v)| (k.to_owned(), v)));
    Json::Object(members)
}

/// The error reply for `err`.
pub fn error_reply(id: Option<u64>, err: &Error) -> Json {
    reply(
        id,
        false,
        vec![
            ("error", Json::from(err.name().as_str())),
            ("message", Json::from(err.message())),
        ],
    )
}

fn capabilities(engine: &dyn Engine) -> Json {
    let uv = engine.user_verification_available();
    Json::Object(
        [
            ("userVerifyingPlatformAuthenticator", uv),
            ("passkeyPlatformAuthenticator", uv),
            ("extension:credProps", true),
            ("extension:credProtect", true),
            ("extension:prf", true),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), Json::Bool(v)))
        .collect(),
    )
}

fn truncated(s: Option<&str>) -> Json {
    let s = s.unwrap_or("");
    match s.char_indices().nth(MAX_NAME_CHARS) {
        Some((end, _)) => Json::from(s.get(..end).unwrap_or("")),
        None => Json::from(s),
    }
}

/// At most `MAX_DESCRIPTORS` accounts, names capped like page-supplied names.
fn accounts(list: &[CandidateAccount]) -> Json {
    Json::Array(
        list.iter()
            .take(MAX_DESCRIPTORS)
            .map(|a| {
                Json::Object(vec![
                    (
                        "id".to_owned(),
                        Json::from(base64url::encode(&a.credential_id)),
                    ),
                    ("name".to_owned(), truncated(a.user_name.as_deref())),
                    (
                        "displayName".to_owned(),
                        truncated(a.user_display_name.as_deref()),
                    ),
                ])
            })
            .collect(),
    )
}

/// Handles one request and returns the reply to send back. Never panics.
pub fn handle(request: &Json, engine: &mut dyn Engine) -> Json {
    let id = request
        .get("id")
        .and_then(Json::as_u64)
        .filter(|&n| n <= MAX_SAFE_INTEGER);
    match dispatch(request, id, engine) {
        Ok(body) => reply(id, true, body),
        Err(e) => error_reply(id, &e),
    }
}

fn dispatch(
    request: &Json,
    id: Option<u64>,
    engine: &mut dyn Engine,
) -> Result<Vec<(&'static str, Json)>, Error> {
    if request.as_object().is_none() {
        return Err(Error::BadEnvelope("request is not an object"));
    }
    if request.get("v").and_then(Json::as_u64) != Some(PROTOCOL_VERSION) {
        return Err(Error::NotHandled("unsupported protocol version"));
    }
    if id.is_none() {
        return Err(Error::BadEnvelope("missing or invalid id"));
    }
    match request.get("type").and_then(Json::as_str) {
        Some("hello") => Ok(vec![("version", Json::from(VERSION))]),
        Some("capabilities") => Ok(vec![("capabilities", capabilities(engine))]),
        Some("create") => {
            let (origin, options) = ceremony_input(request)?;
            let plan = prepare_create(options, &origin)?;
            let resp = engine.make_credential(&plan.request, origin.as_str())?;
            Ok(vec![("credential", registration_response(&plan, &resp)?)])
        }
        Some("get") => {
            let (origin, options) = ceremony_input(request)?;
            let plan = prepare_get(options, &origin)?;
            let resp = engine.get_assertion(&plan.request, origin.as_str())?;
            Ok(vec![("credential", authentication_response(&plan, &resp)?)])
        }
        Some("list") => {
            let (origin, options) = ceremony_input(request)?;
            let plan = prepare_list(options, &origin)?;
            let found = engine.list_accounts(&plan.rp_id, &plan.allow_list)?;
            Ok(vec![("accounts", accounts(&found))])
        }
        _ => Err(Error::BadEnvelope("unknown request type")),
    }
}

fn ceremony_input(request: &Json) -> Result<(Origin, &Json), Error> {
    let origin = request
        .get("origin")
        .and_then(Json::as_str)
        .ok_or(Error::BadEnvelope("missing origin"))?;
    let top_origin = match request.get("topOrigin") {
        None | Some(Json::Null) => None,
        Some(Json::String(s)) => Some(s.as_str()),
        Some(_) => return Err(Error::BadEnvelope("invalid topOrigin")),
    };
    let cross_origin = match request.get("crossOrigin") {
        None => false,
        Some(Json::Bool(b)) => *b,
        Some(_) => return Err(Error::BadEnvelope("invalid crossOrigin")),
    };
    let options = request
        .get("options")
        .filter(|o| o.as_object().is_some())
        .ok_or(Error::BadEnvelope("missing options"))?;
    if cross_origin || top_origin.is_some_and(|t| t != origin) {
        return Err(Error::NotHandled("cross-origin frame"));
    }
    Ok((Origin::parse(origin)?, options))
}
