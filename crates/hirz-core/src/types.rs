//! Shared request, response and approval types. This file is the contract between the
//! engine, the two frontends and the approval layer; change it deliberately.

/// AAGUID of hirz: `c049d046-0de0-4b9c-824f-5b5eeeff218f`.
pub const AAGUID: [u8; 16] = [
    0xc0, 0x49, 0xd0, 0x46, 0x0d, 0xe0, 0x4b, 0x9c, 0x82, 0x4f, 0x5b, 0x5e, 0xee, 0xff, 0x21, 0x8f,
];

/// Length of every credential id hirz creates.
pub const CREDENTIAL_ID_LEN: usize = 32;

/// COSE algorithm identifiers hirz supports, in hirz's own preference order.
pub const COSE_ALG_ES256: i64 = -7;
pub const COSE_ALG_EDDSA: i64 = -8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UvRequirement {
    Required,
    Preferred,
    Discouraged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpEntity {
    pub id: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserEntity {
    pub id: Vec<u8>,
    pub name: Option<String>,
    pub display_name: Option<String>,
}

/// CTAP credProtect levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredProtect {
    UserVerificationOptional = 1,
    UserVerificationOptionalWithCredentialIdList = 2,
    UserVerificationRequired = 3,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MakeExtensions {
    /// WebAuthn credProps: report whether the credential is discoverable.
    pub cred_props: bool,
    /// CTAP hmac-secret / WebAuthn prf: create the per-credential secrets.
    pub hmac_secret: bool,
    pub cred_protect: Option<CredProtect>,
}

/// Salts for hmac-secret, already decrypted by the transport layer (CTAP path) or
/// derived from the prf inputs (extension path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HmacSecretSalts {
    pub salt1: [u8; 32],
    pub salt2: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GetExtensions {
    pub hmac_secret: Option<HmacSecretSalts>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakeCredentialRequest {
    pub client_data_hash: [u8; 32],
    pub rp: RpEntity,
    pub user: UserEntity,
    /// COSE algorithm ids in the relying party's preference order.
    pub algorithms: Vec<i64>,
    pub exclude_list: Vec<Vec<u8>>,
    /// What the RP asked for. hirz stores every credential in the vault either way;
    /// this sets the record's discoverable flag, which credProps reports.
    pub resident_key: bool,
    pub uv: UvRequirement,
    pub extensions: MakeExtensions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAssertionRequest {
    pub client_data_hash: [u8; 32],
    pub rp_id: String,
    pub allow_list: Vec<Vec<u8>>,
    pub uv: UvRequirement,
    /// False only for CTAP silent probes (`up: false`); no signature is released then
    /// without a later ceremony.
    pub up: bool,
    pub extensions: GetExtensions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakeCredentialResponse {
    /// Full authenticatorData including attested credential data.
    pub auth_data: Vec<u8>,
    pub credential_id: Vec<u8>,
    /// COSE_Key encoding of the public key.
    pub public_key_cose: Vec<u8>,
    pub algorithm: i64,
    /// True when hmac-secret was requested and enabled.
    pub hmac_secret: bool,
    /// The credential's discoverable flag (equal to the request's `resident_key`).
    pub resident_key: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionResponse {
    pub credential_id: Vec<u8>,
    pub auth_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
    /// Present for discoverable-credential flows (CTAP `user` member).
    pub user: Option<UserEntity>,
    /// hmac-secret output(s): 32 or 64 bytes, before transport encryption.
    pub hmac_secret_output: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ceremony {
    Create,
    Get,
}

/// One account the user can choose during a Get ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateAccount {
    pub credential_id: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
}

#[derive(Debug)]
pub struct ApprovalContext<'a> {
    pub ceremony: Ceremony,
    pub rp_id: &'a str,
    pub rp_name: Option<&'a str>,
    /// Get: accounts to choose from (never empty when the approver is called).
    pub candidates: &'a [CandidateAccount],
    /// Create: the account being created.
    pub new_account: Option<&'a UserEntity>,
    /// True when the RP requires user verification; click-to-allow must refuse.
    pub uv_required: bool,
    /// Extension path only, for display. Already validated by the host.
    pub origin: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Approval {
    pub user_present: bool,
    /// Only true after a host-verified method (polkit, fprintd, hirz PIN).
    pub user_verified: bool,
    /// Get: index into `ApprovalContext::candidates`.
    pub selected: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalError {
    /// The user cancelled or closed the prompt.
    Denied,
    /// No approval within the ceremony timeout.
    Timeout,
    /// The required verification is not available on this system.
    Unavailable,
    /// Too many failed attempts; locked for a while.
    Locked,
    Internal(String),
}

/// CTAP path only: encrypts the hmac-secret output for the platform (PIN/UV auth protocol
/// shared secret) so the engine can embed it in authData extensions before signing.
/// When `None` is passed (extension path), the engine leaves authData without the
/// hmac-secret extension and returns the raw output in `AssertionResponse`.
pub trait HmacSecretWrap {
    fn wrap(&self, output: &[u8]) -> Result<Vec<u8>, CoreError>;
}

/// Implemented by hirz-uv. The engine never signs unless `approve` returns `Ok`.
pub trait Approver {
    fn approve(&self, ctx: &ApprovalContext<'_>) -> Result<Approval, ApprovalError>;

    /// CTAP authenticatorSelection: the user only confirms that this authenticator should
    /// handle the platform's next request. No site, account or signature is involved; only
    /// `user_present` of the result is used. The default refuses, so an approver that cannot
    /// show such a prompt never reports presence it did not observe.
    fn confirm_selection(&self) -> Result<Approval, ApprovalError> {
        Err(ApprovalError::Unavailable)
    }
}

/// Errors the engine reports; frontends map them to CTAP status codes or DOMException names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// A credential in the exclude list already exists (CTAP2_ERR_CREDENTIAL_EXCLUDED,
    /// InvalidStateError).
    CredentialExcluded,
    /// No usable credential (CTAP2_ERR_NO_CREDENTIALS, NotAllowedError).
    NoCredentials,
    /// None of the requested algorithms is supported (CTAP2_ERR_UNSUPPORTED_ALGORITHM,
    /// NotSupportedError).
    UnsupportedAlgorithm,
    /// The RP requires UV and only click-to-allow is possible (NotAllowedError).
    UvRequiredUnavailable,
    Approval(ApprovalError),
    /// getAssertion with `up: false`. hirz never signs without a prompt, so silent
    /// assertions are refused before any credential lookup.
    SilentNotAllowed,
    InvalidRequest(&'static str),
    Vault(String),
    Crypto(String),
}
