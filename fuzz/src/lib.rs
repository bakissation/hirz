//! Shared helpers for the fuzz targets: engines that answer every ceremony with well-formed
//! but unsigned output, so the frontends run their full encode path on fuzzed requests.

#![forbid(unsafe_code)]

/// The Bitwarden and KeePassXC import parsers of the `hirz` command, which has no library
/// target.
#[path = "../../crates/hirz-cli/src/foreign/mod.rs"]
pub mod foreign;

/// The CXF reader, the passphrase envelope and the display helpers they use, from the same
/// source files as the `hirz` command.
#[path = "../../crates/hirz-cli/src/cxf.rs"]
pub mod cxf;
#[path = "../../crates/hirz-cli/src/envelope.rs"]
pub mod envelope;
#[path = "../../crates/hirz-cli/src/ui.rs"]
pub mod ui;

use hirz_core::{
    AAGUID, AssertionResponse, COSE_ALG_EDDSA, CoreError, GetAssertionRequest, HmacSecretWrap,
    MakeCredentialRequest, MakeCredentialResponse, UserEntity,
};
use hirz_crypto::sha256;
use hirz_ctap::Authenticator;
use hirz_ctap::hid::RequestContext;
use hirz_proto::auth_data::{AttestedCredentialData, AuthenticatorData, FLAG_BE, FLAG_UP, FLAG_UV};
use hirz_proto::cbor::{MapBuilder, Value};
use hirz_proto::cose;

pub const FAKE_CREDENTIAL_ID: [u8; 32] = [0x11; 32];
pub const FAKE_USER_HANDLE: &[u8] = b"user-0001";
pub const FAKE_SIGNATURE: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];

fn public_key(alg: i64) -> Vec<u8> {
    if alg == COSE_ALG_EDDSA {
        cose::encode_ed25519(&[3; 32])
    } else {
        cose::encode_es256(&[1; 32], &[2; 32])
    }
}

fn auth_data(
    rp_id: &str,
    flags: u8,
    attested: Option<(&[u8], &[u8])>,
    extensions: Option<Value>,
) -> Result<Vec<u8>, CoreError> {
    AuthenticatorData {
        rp_id_hash: sha256(rp_id.as_bytes()),
        flags,
        sign_count: 0,
        attested_credential: attested.map(|(id, key)| AttestedCredentialData {
            aaguid: AAGUID,
            credential_id: id.to_vec(),
            public_key: key.to_vec(),
        }),
        extensions,
    }
    .encode()
    .map_err(|_| CoreError::InvalidRequest("fake authenticator data"))
}

fn make(req: &MakeCredentialRequest, flags: u8) -> Result<MakeCredentialResponse, CoreError> {
    let algorithm = *req
        .algorithms
        .first()
        .ok_or(CoreError::UnsupportedAlgorithm)?;
    let key = public_key(algorithm);
    Ok(MakeCredentialResponse {
        auth_data: auth_data(
            &req.rp.id,
            flags,
            Some((&FAKE_CREDENTIAL_ID, &key)),
            None,
        )?,
        credential_id: FAKE_CREDENTIAL_ID.to_vec(),
        public_key_cose: key,
        algorithm,
        hmac_secret: req.extensions.hmac_secret,
        resident_key: req.resident_key,
    })
}

fn chosen_credential(req: &GetAssertionRequest) -> Vec<u8> {
    req.allow_list
        .first()
        .cloned()
        .unwrap_or_else(|| FAKE_CREDENTIAL_ID.to_vec())
}

fn hmac_output(req: &GetAssertionRequest) -> Option<Vec<u8>> {
    req.extensions.hmac_secret.as_ref().map(|salts| {
        let mut out = vec![0x5a; 32];
        if salts.salt2.is_some() {
            out.extend_from_slice(&[0xa5; 32]);
        }
        out
    })
}

#[derive(Debug, Default)]
pub struct NoSignAuthenticator;

impl Authenticator for NoSignAuthenticator {
    fn make_credential(
        &mut self,
        req: &MakeCredentialRequest,
        _ctx: &RequestContext,
    ) -> Result<MakeCredentialResponse, CoreError> {
        make(req, FLAG_UP | FLAG_UV)
    }

    fn get_assertion(
        &mut self,
        req: &GetAssertionRequest,
        hmac: Option<&dyn HmacSecretWrap>,
        _ctx: &RequestContext,
    ) -> Result<AssertionResponse, CoreError> {
        let extensions = match (hmac, hmac_output(req)) {
            (Some(wrap), Some(output)) => {
                let wrapped = wrap.wrap(&output)?;
                Some(
                    MapBuilder::new()
                        .text("hmac-secret", wrapped.as_slice())
                        .build(),
                )
            }
            _ => None,
        };
        let flags = if req.up { FLAG_UP | FLAG_UV } else { 0 };
        let discoverable = req.allow_list.is_empty();
        Ok(AssertionResponse {
            credential_id: chosen_credential(req),
            auth_data: auth_data(&req.rp_id, flags, None, extensions)?,
            signature: FAKE_SIGNATURE.to_vec(),
            user_handle: FAKE_USER_HANDLE.to_vec(),
            user: discoverable.then(|| UserEntity {
                id: FAKE_USER_HANDLE.to_vec(),
                name: Some("alice".to_owned()),
                display_name: None,
            }),
            hmac_secret_output: None,
        })
    }

    fn select(&mut self, _ctx: &RequestContext) -> Result<(), CoreError> {
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct NoSignEngine;

impl NoSignEngine {
    pub fn make(&self, req: &MakeCredentialRequest) -> Result<MakeCredentialResponse, CoreError> {
        make(req, FLAG_UP | FLAG_UV | FLAG_BE)
    }

    pub fn get(&self, req: &GetAssertionRequest) -> Result<AssertionResponse, CoreError> {
        Ok(AssertionResponse {
            credential_id: chosen_credential(req),
            auth_data: auth_data(&req.rp_id, FLAG_UP | FLAG_UV | FLAG_BE, None, None)?,
            signature: FAKE_SIGNATURE.to_vec(),
            user_handle: FAKE_USER_HANDLE.to_vec(),
            user: None,
            hmac_secret_output: hmac_output(req),
        })
    }
}

impl hirz_webauthn::Engine for NoSignEngine {
    fn make_credential(
        &mut self,
        request: &MakeCredentialRequest,
        _origin_for_display: &str,
    ) -> Result<MakeCredentialResponse, CoreError> {
        self.make(request)
    }

    fn get_assertion(
        &mut self,
        request: &GetAssertionRequest,
        _origin_for_display: &str,
    ) -> Result<AssertionResponse, CoreError> {
        self.get(request)
    }

    fn user_verification_available(&self) -> bool {
        true
    }
}

pub const ORIGINS: [&str; 4] = [
    "https://login.example.com",
    "https://example.com",
    "http://localhost:8080",
    "https://a.b.example.co.uk",
];
