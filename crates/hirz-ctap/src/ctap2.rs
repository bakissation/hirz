//! CTAP2 authenticator commands (CTAP 2.2 section 6) for an authenticator with built-in user
//! verification and no clientPin. Parsers are pure functions over `&[u8]` so they can be fuzzed.
//! Policy notes: docs/uhid.md, "CTAP2 command policy".

use std::sync::Mutex;

use hirz_core::{
    AAGUID, AssertionResponse, COSE_ALG_EDDSA, COSE_ALG_ES256, CoreError, CredProtect,
    GetAssertionRequest, GetExtensions, HmacSecretWrap, MakeCredentialRequest,
    MakeCredentialResponse, MakeExtensions, RpEntity, UserEntity, UvRequirement,
};
use hirz_proto::auth_data::MAX_CREDENTIAL_ID_LEN;
use hirz_proto::cbor::{self, Limits, MapBuilder, Value};
use hirz_proto::cose::{self, KeyAgreementKey};

use crate::hid::{CborHandler, KeepaliveStatus, MAX_MESSAGE_SIZE, RequestContext};
use crate::pin_uv::{self, HmacSecretWrapper, KeyAgreementKeys, PinUvAuthProtocol};
use crate::status::Status;

pub mod command {
    pub const MAKE_CREDENTIAL: u8 = 0x01;
    pub const GET_ASSERTION: u8 = 0x02;
    pub const GET_INFO: u8 = 0x04;
    pub const CLIENT_PIN: u8 = 0x06;
    pub const RESET: u8 = 0x07;
    pub const GET_NEXT_ASSERTION: u8 = 0x08;
    pub const BIO_ENROLLMENT: u8 = 0x09;
    pub const CREDENTIAL_MANAGEMENT: u8 = 0x0a;
    pub const SELECTION: u8 = 0x0b;
    pub const LARGE_BLOBS: u8 = 0x0c;
    pub const CONFIG: u8 = 0x0d;
}

pub mod client_pin {
    pub const GET_PIN_RETRIES: u64 = 0x01;
    pub const GET_KEY_AGREEMENT: u64 = 0x02;
    pub const SET_PIN: u64 = 0x03;
    pub const CHANGE_PIN: u64 = 0x04;
    pub const GET_PIN_TOKEN: u64 = 0x05;
    pub const GET_PIN_UV_AUTH_TOKEN_USING_UV_WITH_PERMISSIONS: u64 = 0x06;
    pub const GET_UV_RETRIES: u64 = 0x07;
    pub const GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS: u64 = 0x09;
}

/// Entries per list that platforms may send, so their silent pre-flight probes need few round trips.
pub const MAX_CREDENTIAL_COUNT_IN_LIST: u64 = 16;

/// hirz creates 32-byte ids, but imported passkeys keep theirs (up to 1023) and browsers drop longer
/// allow-list ids before sending them.
pub const MAX_ACCEPTED_CREDENTIAL_ID_LEN: u64 = MAX_CREDENTIAL_ID_LEN as u64;

/// getInfo firmwareVersion: the package version as `major << 16 | minor << 8 | patch`.
pub const FIRMWARE_VERSION: u64 = 0x00_01_00;

pub const MAX_USER_ID_LEN: usize = hirz_proto::MAX_USER_ID_LEN;

const PUBLIC_KEY: &str = "public-key";
const MAX_ITEMS: usize = 2048;
const MAX_DEPTH: usize = 8;

/// Map key order is not enforced: Firefox sends getAssertion options as `{"uv": .., "up": ..}`,
/// which is not canonical. Everything else stays strict.
pub fn limits() -> Limits {
    Limits {
        max_len: MAX_MESSAGE_SIZE,
        max_depth: MAX_DEPTH,
        max_items: MAX_ITEMS,
        require_canonical: false,
    }
}

/// Methods may block on the approval prompt and should give up once `ctx.is_cancelled()`.
pub trait Authenticator: Send {
    fn make_credential(
        &mut self,
        req: &MakeCredentialRequest,
        ctx: &RequestContext,
    ) -> Result<MakeCredentialResponse, CoreError>;

    fn get_assertion(
        &mut self,
        req: &GetAssertionRequest,
        hmac: Option<&dyn HmacSecretWrap>,
        ctx: &RequestContext,
    ) -> Result<AssertionResponse, CoreError>;

    /// Waits for a user gesture without any ceremony (authenticatorSelection, zero-length pinUvAuthParam probe).
    fn select(&mut self, ctx: &RequestContext) -> Result<(), CoreError>;
}

type Res<T> = Result<T, Status>;

fn decode_params(params: &[u8]) -> Res<Value> {
    if params.len() > MAX_MESSAGE_SIZE {
        return Err(Status::RequestTooLarge);
    }
    let value = cbor::decode(params, &limits())?;
    if value.as_map().is_none() {
        return Err(Status::CborUnexpectedType);
    }
    Ok(value)
}

fn as_map(v: &Value) -> Res<&Value> {
    v.as_map().map(|_| v).ok_or(Status::CborUnexpectedType)
}

fn as_bytes(v: &Value) -> Res<&[u8]> {
    v.as_bytes().ok_or(Status::CborUnexpectedType)
}

fn as_text(v: &Value) -> Res<&str> {
    v.as_text().ok_or(Status::CborUnexpectedType)
}

fn as_bool(v: &Value) -> Res<bool> {
    v.as_bool().ok_or(Status::CborUnexpectedType)
}

fn as_uint(v: &Value) -> Res<u64> {
    v.as_u64().ok_or(Status::CborUnexpectedType)
}

fn as_array(v: &Value) -> Res<&[Value]> {
    v.as_array().ok_or(Status::CborUnexpectedType)
}

fn required(v: Option<&Value>) -> Res<&Value> {
    v.ok_or(Status::MissingParameter)
}

fn opt_bytes(v: Option<&Value>) -> Res<Option<Vec<u8>>> {
    v.map(|v| as_bytes(v).map(<[u8]>::to_vec)).transpose()
}

fn opt_text(map: &Value, key: &str) -> Res<Option<String>> {
    map.get_text(key)
        .map(|v| as_text(v).map(str::to_owned))
        .transpose()
}

fn client_data_hash(v: Option<&Value>) -> Res<[u8; 32]> {
    let b = as_bytes(required(v)?)?;
    <[u8; 32]>::try_from(b).map_err(|_| Status::InvalidParameter)
}

/// Descriptors of other types are skipped. Longer ids than WebAuthn allows are refused rather
/// than dropped, so a list never turns into an empty (discoverable) one.
fn descriptor_ids(v: &Value) -> Res<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for item in as_array(v)? {
        let item = as_map(item)?;
        let ty = as_text(required(item.get_text("type"))?)?;
        let id = as_bytes(required(item.get_text("id"))?)?;
        if ty == PUBLIC_KEY {
            if id.len() > MAX_CREDENTIAL_ID_LEN {
                return Err(Status::InvalidParameter);
            }
            out.push(id.to_vec());
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Options {
    pub rk: Option<bool>,
    pub up: Option<bool>,
    pub uv: Option<bool>,
}

/// Unknown option keys are treated as absent (6.1.2 step 5).
fn options(v: Option<&Value>) -> Res<Options> {
    let Some(v) = v else {
        return Ok(Options::default());
    };
    let v = as_map(v)?;
    let get = |k: &str| v.get_text(k).map(as_bool).transpose();
    Ok(Options {
        rk: get("rk")?,
        up: get("up")?,
        uv: get("uv")?,
    })
}

fn uv_requirement(uv: Option<bool>) -> UvRequirement {
    if uv == Some(true) {
        UvRequirement::Required
    } else {
        UvRequirement::Discouraged
    }
}

/// Shared by makeCredential and getAssertion. hirz never issues a pinUvAuthToken, so a non-empty
/// pinUvAuthParam with a supported protocol can never verify.
fn check_pin_uv_auth(param: Option<&[u8]>, protocol: Option<u64>) -> Res<()> {
    if param.is_none() {
        return Ok(());
    }
    let protocol = protocol.ok_or(Status::MissingParameter)?;
    PinUvAuthProtocol::from_u64(protocol).ok_or(Status::InvalidParameter)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakeCredentialParams {
    pub client_data_hash: [u8; 32],
    pub rp: RpEntity,
    pub user: UserEntity,
    /// Supported algorithms (ES256, EdDSA) in the RP's order; others are dropped.
    pub algorithms: Vec<i64>,
    pub exclude_list: Vec<Vec<u8>>,
    pub extensions: MakeExtensions,
    pub options: Options,
    pub pin_uv_auth_param: Option<Vec<u8>>,
    pub pin_uv_auth_protocol: Option<u64>,
    pub enterprise_attestation: bool,
}

/// Decodes the CBOR parameters of authenticatorMakeCredential (without the command byte).
pub fn parse_make_credential(params: &[u8]) -> Res<MakeCredentialParams> {
    let m = decode_params(params)?;
    let client_data_hash = client_data_hash(m.get_int(0x01))?;

    let rp = as_map(required(m.get_int(0x02))?)?;
    let rp = RpEntity {
        id: as_text(required(rp.get_text("id"))?)?.to_owned(),
        name: opt_text(rp, "name")?,
    };

    let user = as_map(required(m.get_int(0x03))?)?;
    let user_id = as_bytes(required(user.get_text("id"))?)?;
    if user_id.is_empty() || user_id.len() > MAX_USER_ID_LEN {
        return Err(Status::InvalidParameter);
    }
    let user = UserEntity {
        id: user_id.to_vec(),
        name: opt_text(user, "name")?,
        display_name: opt_text(user, "displayName")?,
    };

    // 6.1.2 step 3: validate every element, pick supported algorithms in RP order, skip unknown types.
    let mut algorithms = Vec::new();
    for p in as_array(required(m.get_int(0x04))?)? {
        let p = as_map(p)?;
        let alg = required(p.get_text("alg"))?;
        let ty = as_text(required(p.get_text("type"))?)?;
        let alg = alg.as_i128().ok_or(Status::CborUnexpectedType)?;
        if ty != PUBLIC_KEY {
            continue;
        }
        if let Ok(alg) = i64::try_from(alg)
            && (alg == COSE_ALG_ES256 || alg == COSE_ALG_EDDSA)
            && !algorithms.contains(&alg)
        {
            algorithms.push(alg);
        }
    }

    let exclude_list = m
        .get_int(0x05)
        .map(descriptor_ids)
        .transpose()?
        .unwrap_or_default();

    let mut extensions = MakeExtensions::default();
    if let Some(ext) = m.get_int(0x06) {
        let ext = as_map(ext)?;
        if let Some(v) = ext.get_text("hmac-secret") {
            extensions.hmac_secret = as_bool(v)?;
        }
        if let Some(v) = ext.get_text("credProtect") {
            extensions.cred_protect = Some(match as_uint(v)? {
                1 => CredProtect::UserVerificationOptional,
                2 => CredProtect::UserVerificationOptionalWithCredentialIdList,
                3 => CredProtect::UserVerificationRequired,
                _ => return Err(Status::InvalidParameter),
            });
        }
    }

    let options = options(m.get_int(0x07))?;
    let pin_uv_auth_param = opt_bytes(m.get_int(0x08))?;
    let pin_uv_auth_protocol = m.get_int(0x09).map(as_uint).transpose()?;
    let enterprise_attestation = m.get_int(0x0a).is_some();

    Ok(MakeCredentialParams {
        client_data_hash,
        rp,
        user,
        algorithms,
        exclude_list,
        extensions,
        options,
        pin_uv_auth_param,
        pin_uv_auth_protocol,
        enterprise_attestation,
    })
}

impl MakeCredentialParams {
    pub fn is_touch_probe(&self) -> bool {
        self.pin_uv_auth_param.as_ref().is_some_and(Vec::is_empty)
    }

    /// Step 7 (PUAT_REQUIRED when uv is false on a UV-protected authenticator) is not applied: the
    /// approval method decides, so click-to-allow without UV stays possible.
    pub fn into_request(self) -> Res<MakeCredentialRequest> {
        check_pin_uv_auth(self.pin_uv_auth_param.as_deref(), self.pin_uv_auth_protocol)?;
        if self.algorithms.is_empty() {
            return Err(Status::UnsupportedAlgorithm);
        }
        if self.options.up == Some(false) {
            return Err(Status::InvalidOption);
        }
        if self.enterprise_attestation {
            return Err(Status::InvalidParameter);
        }
        if self.pin_uv_auth_param.is_some() {
            return Err(Status::PinAuthInvalid);
        }
        Ok(MakeCredentialRequest {
            client_data_hash: self.client_data_hash,
            rp: self.rp,
            user: self.user,
            algorithms: self.algorithms,
            exclude_list: self.exclude_list,
            resident_key: self.options.rk.unwrap_or(false),
            uv: uv_requirement(self.options.uv),
            extensions: self.extensions,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HmacSecretInput {
    pub key_agreement: KeyAgreementKey,
    pub salt_enc: Vec<u8>,
    pub salt_auth: Vec<u8>,
    /// Defaults to 1 when absent.
    pub pin_uv_auth_protocol: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAssertionParams {
    pub rp_id: String,
    pub client_data_hash: [u8; 32],
    pub allow_list: Vec<Vec<u8>>,
    pub hmac_secret: Option<HmacSecretInput>,
    pub options: Options,
    pub pin_uv_auth_param: Option<Vec<u8>>,
    pub pin_uv_auth_protocol: Option<u64>,
}

fn hmac_secret_input(v: &Value) -> Res<HmacSecretInput> {
    let v = as_map(v)?;
    let key = as_map(required(v.get_int(0x01))?)?;
    let key_agreement = cose::parse_key_agreement(key).map_err(|_| Status::InvalidParameter)?;
    let salt_enc = as_bytes(required(v.get_int(0x02))?)?.to_vec();
    let salt_auth = as_bytes(required(v.get_int(0x03))?)?.to_vec();
    let pin_uv_auth_protocol = v.get_int(0x04).map(as_uint).transpose()?.unwrap_or(1);
    Ok(HmacSecretInput {
        key_agreement,
        salt_enc,
        salt_auth,
        pin_uv_auth_protocol,
    })
}

pub fn parse_get_assertion(params: &[u8]) -> Res<GetAssertionParams> {
    let m = decode_params(params)?;
    let rp_id = as_text(required(m.get_int(0x01))?)?.to_owned();
    let client_data_hash = client_data_hash(m.get_int(0x02))?;
    let allow_list = m
        .get_int(0x03)
        .map(descriptor_ids)
        .transpose()?
        .unwrap_or_default();
    let mut hmac_secret = None;
    if let Some(ext) = m.get_int(0x04) {
        let ext = as_map(ext)?;
        if let Some(v) = ext.get_text("hmac-secret") {
            hmac_secret = Some(hmac_secret_input(v)?);
        }
    }
    let opts = m.get_int(0x05);
    let mut options = options(opts)?;
    // Any "rk" key is an error for getAssertion (6.2.2 step 4), whatever its value.
    if opts.and_then(|o| o.get_text("rk")).is_some() {
        options.rk = Some(true);
    }
    let pin_uv_auth_param = opt_bytes(m.get_int(0x06))?;
    let pin_uv_auth_protocol = m.get_int(0x07).map(as_uint).transpose()?;
    Ok(GetAssertionParams {
        rp_id,
        client_data_hash,
        allow_list,
        hmac_secret,
        options,
        pin_uv_auth_param,
        pin_uv_auth_protocol,
    })
}

impl GetAssertionParams {
    pub fn is_touch_probe(&self) -> bool {
        self.pin_uv_auth_param.as_ref().is_some_and(Vec::is_empty)
    }

    /// Steps that need no engine; returns the request without salts and the validated hmac-secret input.
    pub fn into_request(
        self,
    ) -> Res<(
        GetAssertionRequest,
        Option<(HmacSecretInput, PinUvAuthProtocol)>,
    )> {
        check_pin_uv_auth(self.pin_uv_auth_param.as_deref(), self.pin_uv_auth_protocol)?;
        if self.options.rk.is_some() {
            return Err(Status::UnsupportedOption);
        }
        if self.pin_uv_auth_param.is_some() {
            return Err(Status::PinAuthInvalid);
        }
        let hmac = self
            .hmac_secret
            .map(|h| {
                PinUvAuthProtocol::from_u64(h.pin_uv_auth_protocol)
                    .map(|p| (h, p))
                    .ok_or(Status::InvalidParameter)
            })
            .transpose()?;
        let req = GetAssertionRequest {
            client_data_hash: self.client_data_hash,
            rp_id: self.rp_id,
            allow_list: self.allow_list,
            uv: uv_requirement(self.options.uv),
            up: self.options.up.unwrap_or(true),
            extensions: GetExtensions::default(),
        };
        Ok((req, hmac))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientPinParams {
    pub pin_uv_auth_protocol: Option<u64>,
    pub sub_command: u64,
}

pub fn parse_client_pin(params: &[u8]) -> Res<ClientPinParams> {
    let m = decode_params(params)?;
    let pin_uv_auth_protocol = m.get_int(0x01).map(as_uint).transpose()?;
    let sub_command = as_uint(required(m.get_int(0x02))?)?;
    Ok(ClientPinParams {
        pin_uv_auth_protocol,
        sub_command,
    })
}

fn text_array(items: &[&str]) -> Value {
    Value::Array(items.iter().map(|s| Value::from(*s)).collect())
}

fn algorithm(alg: i64) -> Value {
    MapBuilder::new()
        .text("alg", alg)
        .text("type", PUBLIC_KEY)
        .build()
}

pub fn get_info_value() -> Value {
    MapBuilder::new()
        .int(0x01, text_array(&["FIDO_2_0", "FIDO_2_1"]))
        .int(0x02, text_array(&["credProtect", "hmac-secret"]))
        .int(0x03, AAGUID.as_slice())
        .int(
            0x04,
            MapBuilder::new()
                .text("rk", true)
                .text("up", true)
                .text("uv", true)
                .text("plat", false)
                .build(),
        )
        .int(0x05, MAX_MESSAGE_SIZE as u64)
        .int(0x06, Value::Array(vec![Value::int(2), Value::int(1)]))
        .int(0x07, MAX_CREDENTIAL_COUNT_IN_LIST)
        .int(0x08, MAX_ACCEPTED_CREDENTIAL_ID_LEN)
        .int(0x09, text_array(&["usb"]))
        .int(
            0x0a,
            Value::Array(vec![algorithm(COSE_ALG_ES256), algorithm(COSE_ALG_EDDSA)]),
        )
        .int(0x0e, FIRMWARE_VERSION)
        .build()
}

fn ok_with(value: &Value) -> Res<Vec<u8>> {
    let body = cbor::encode(value).map_err(|_| Status::Other)?;
    let mut out = Vec::with_capacity(body.len().saturating_add(1));
    out.push(Status::Ok.code());
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn get_info_response() -> Vec<u8> {
    ok_with(&get_info_value()).unwrap_or_else(|s| s.response())
}

pub fn encode_make_credential(resp: &MakeCredentialResponse) -> Res<Vec<u8>> {
    let v = MapBuilder::new()
        .int(0x01, hirz_proto::attestation::FMT_NONE)
        .int(0x02, resp.auth_data.as_slice())
        .int(0x03, Value::Map(Vec::new()))
        .build();
    ok_with(&v)
}

/// `user` carries only the id: hirz picks the account itself, so the platform needs no name for
/// its picker. `userSelected` is set for discoverable flows.
pub fn encode_get_assertion(resp: &AssertionResponse, user_selected: bool) -> Res<Vec<u8>> {
    let credential = MapBuilder::new()
        .text("id", resp.credential_id.as_slice())
        .text("type", PUBLIC_KEY)
        .build();
    let mut m = MapBuilder::new()
        .int(0x01, credential)
        .int(0x02, resp.auth_data.as_slice())
        .int(0x03, resp.signature.as_slice());
    let user_id = resp
        .user
        .as_ref()
        .map(|u| u.id.as_slice())
        .filter(|id| !id.is_empty())
        .or(Some(resp.user_handle.as_slice()).filter(|id| !id.is_empty()));
    if let Some(id) = user_id {
        m = m.int(0x04, MapBuilder::new().text("id", id).build());
    }
    if user_selected {
        m = m.int(0x06, true);
    }
    ok_with(&m.build())
}

#[derive(Debug)]
pub struct Ctap2Handler<A> {
    engine: Mutex<A>,
    keys: Mutex<KeyAgreementKeys>,
}

impl<A: Authenticator> Ctap2Handler<A> {
    pub fn new(engine: A) -> Self {
        Self {
            engine: Mutex::new(engine),
            keys: Mutex::new(KeyAgreementKeys::new()),
        }
    }

    pub fn regenerate_key_agreement(&self) {
        if let Ok(mut keys) = self.keys.lock() {
            keys.regenerate();
        }
    }

    /// `request` is the command byte plus CBOR parameters; returns the status byte plus CBOR response.
    pub fn process(&self, request: &[u8], ctx: &RequestContext) -> Vec<u8> {
        let result = self.dispatch(request, ctx);
        if ctx.is_cancelled() {
            return Status::KeepaliveCancel.response();
        }
        match result {
            Ok(response) => response,
            Err(status) => status.response(),
        }
    }

    fn dispatch(&self, request: &[u8], ctx: &RequestContext) -> Res<Vec<u8>> {
        let (&cmd, params) = request.split_first().ok_or(Status::InvalidLength)?;
        match cmd {
            command::MAKE_CREDENTIAL => self.make_credential(params, ctx),
            command::GET_ASSERTION => self.get_assertion(params, ctx),
            command::GET_INFO => Ok(get_info_response()),
            command::CLIENT_PIN => self.client_pin(params),
            command::RESET => Err(Status::OperationDenied),
            command::GET_NEXT_ASSERTION => Err(Status::NotAllowed),
            command::SELECTION => {
                self.touch(ctx)?;
                Ok(Status::Ok.response())
            }
            _ => Err(Status::InvalidCommand),
        }
    }

    fn engine_error(e: &CoreError, ctx: &RequestContext) -> Status {
        if ctx.is_cancelled() {
            Status::KeepaliveCancel
        } else {
            Status::from(e)
        }
    }

    fn with_engine<T>(
        &self,
        ctx: &RequestContext,
        call: impl FnOnce(&mut A) -> Result<T, CoreError>,
    ) -> Res<T> {
        let mut engine = self.engine.lock().map_err(|_| Status::Other)?;
        ctx.set_status(KeepaliveStatus::UpNeeded);
        call(&mut engine).map_err(|e| Self::engine_error(&e, ctx))
    }

    fn touch(&self, ctx: &RequestContext) -> Res<()> {
        self.with_engine(ctx, |e| e.select(ctx))
    }

    /// After a gesture, report that no PIN is set (6.1.2 / 6.2.2 step 1).
    fn touch_probe(&self, ctx: &RequestContext) -> Res<Vec<u8>> {
        self.touch(ctx)?;
        Err(Status::PinNotSet)
    }

    fn make_credential(&self, params: &[u8], ctx: &RequestContext) -> Res<Vec<u8>> {
        let p = parse_make_credential(params)?;
        if p.is_touch_probe() {
            return self.touch_probe(ctx);
        }
        let req = p.into_request()?;
        let resp = self.with_engine(ctx, |e| e.make_credential(&req, ctx))?;
        encode_make_credential(&resp)
    }

    fn get_assertion(&self, params: &[u8], ctx: &RequestContext) -> Res<Vec<u8>> {
        let p = parse_get_assertion(params)?;
        if p.is_touch_probe() {
            return self.touch_probe(ctx);
        }
        let (mut req, hmac) = p.into_request()?;
        let wrapper = match hmac {
            Some((input, protocol)) => {
                let secret = self
                    .keys
                    .lock()
                    .map_err(|_| Status::Other)?
                    .shared_secret(protocol, &input.key_agreement)
                    .map_err(|_| Status::InvalidParameter)?;
                let salts = pin_uv::decrypt_salts(&secret, &input.salt_enc, &input.salt_auth)?;
                req.extensions.hmac_secret = Some(salts);
                Some(HmacSecretWrapper::new(secret))
            }
            None => None,
        };
        let user_selected = req.allow_list.is_empty() && req.up;
        let hmac = wrapper.as_ref().map(|w| w as &dyn HmacSecretWrap);
        let resp = self.with_engine(ctx, |e| e.get_assertion(&req, hmac, ctx))?;
        encode_get_assertion(&resp, user_selected)
    }

    /// Only getKeyAgreement: other subcommands need clientPin or a pinUvAuthToken, which getInfo
    /// does not advertise (CTAP2_ERR_INVALID_SUBCOMMAND).
    fn client_pin(&self, params: &[u8]) -> Res<Vec<u8>> {
        let p = parse_client_pin(params)?;
        if p.sub_command != client_pin::GET_KEY_AGREEMENT {
            return Err(Status::InvalidSubcommand);
        }
        let protocol = p.pin_uv_auth_protocol.ok_or(Status::MissingParameter)?;
        let protocol = PinUvAuthProtocol::from_u64(protocol).ok_or(Status::InvalidParameter)?;
        let (x, y) = self
            .keys
            .lock()
            .map_err(|_| Status::Other)?
            .public_key(protocol)
            .map_err(|_| Status::Other)?;
        ok_with(
            &MapBuilder::new()
                .int(0x01, cose::key_agreement_value(&x, &y))
                .build(),
        )
    }
}

impl<A: Authenticator> CborHandler for Ctap2Handler<A> {
    fn handle(&self, request: &[u8], ctx: &RequestContext) -> Vec<u8> {
        self.process(request, ctx)
    }
}

#[cfg(test)]
mod tests;
