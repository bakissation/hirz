//! Shared request, response and approval types. This file is the contract between the
//! engine, the two frontends and the approval layer; change it deliberately.

/// AAGUID of hirz: `c049d046-0de0-4b9c-824f-5b5eeeff218f`.
pub const AAGUID: [u8; 16] = [
    0xc0, 0x49, 0xd0, 0x46, 0x0d, 0xe0, 0x4b, 0x9c, 0x82, 0x4f, 0x5b, 0x5e, 0xee, 0xff, 0x21, 0x8f,
];

pub const CREDENTIAL_ID_LEN: usize = 32;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredProtect {
    UserVerificationOptional = 1,
    UserVerificationOptionalWithCredentialIdList = 2,
    UserVerificationRequired = 3,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MakeExtensions {
    pub cred_props: bool,
    pub hmac_secret: bool,
    pub cred_protect: Option<CredProtect>,
}

/// Already decrypted (CTAP) or derived from the prf inputs (extension).
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
    /// In the relying party's preference order.
    pub algorithms: Vec<i64>,
    pub exclude_list: Vec<Vec<u8>>,
    /// Every credential is stored in the vault; this only sets the discoverable flag.
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
    /// False only for CTAP silent probes: no prompt, signed with UP=0.
    pub up: bool,
    pub extensions: GetExtensions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakeCredentialResponse {
    pub auth_data: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub public_key_cose: Vec<u8>,
    pub algorithm: i64,
    pub hmac_secret: bool,
    pub resident_key: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionResponse {
    pub credential_id: Vec<u8>,
    pub auth_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub user: Option<UserEntity>,
    /// 32 or 64 bytes, before transport encryption.
    pub hmac_secret_output: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ceremony {
    Create,
    Get,
}

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
    /// Never empty when the approver is called.
    pub candidates: &'a [CandidateAccount],
    pub new_account: Option<&'a UserEntity>,
    /// Click-to-allow must refuse.
    pub uv_required: bool,
    /// Extension path only, already validated by the host; display only.
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

/// A new device asks to join the vault; shown before a UV method (docs/vault-format.md, section 11).
#[derive(Debug)]
pub struct PairingApprovalContext<'a> {
    /// Untrusted: chosen by the new device.
    pub device_name: &'a str,
    pub words: &'a [&'a str],
    /// Unix seconds, as stated in the request.
    pub requested_at: u64,
}

/// The user removes another device from the vault; shown before a UV method.
#[derive(Debug)]
pub struct RemovalApprovalContext<'a> {
    /// Untrusted: read from the vault.
    pub device_name: &'a str,
    pub device_id_short: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalError {
    Denied,
    Timeout,
    Unavailable,
    Locked,
    Internal(String),
}

/// CTAP path only: encrypts the hmac-secret output with the PIN/UV protocol shared secret.
/// Without it (extension path) the raw output is returned in `AssertionResponse`.
pub trait HmacSecretWrap {
    fn wrap(&self, output: &[u8]) -> Result<Vec<u8>, CoreError>;
}

/// Implemented by hirz-uv. Nothing is signed with UP=1 unless `approve` returns `Ok`;
/// silent probes (`up: false`) sign with UP=0 without asking.
pub trait Approver {
    fn approve(&self, ctx: &ApprovalContext<'_>) -> Result<Approval, ApprovalError>;

    /// The default refuses so an approver that cannot prompt never reports presence it did not observe.
    fn confirm_selection(&self) -> Result<Approval, ApprovalError> {
        Err(ApprovalError::Unavailable)
    }

    /// Click-to-allow never counts: callers act only on `user_verified`. The default refuses (fails closed).
    fn confirm_pairing(
        &self,
        _ctx: &PairingApprovalContext<'_>,
    ) -> Result<Approval, ApprovalError> {
        Err(ApprovalError::Unavailable)
    }

    /// Click-to-allow never counts: callers act only on `user_verified`. The default refuses (fails closed).
    fn confirm_removal(
        &self,
        _ctx: &RemovalApprovalContext<'_>,
    ) -> Result<Approval, ApprovalError> {
        Err(ApprovalError::Unavailable)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    CredentialExcluded,
    NoCredentials,
    UnsupportedAlgorithm,
    UvRequiredUnavailable,
    Approval(ApprovalError),
    InvalidRequest(&'static str),
    Vault(String),
    Crypto(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ApproveOnly;

    impl Approver for ApproveOnly {
        fn approve(&self, _: &ApprovalContext<'_>) -> Result<Approval, ApprovalError> {
            Ok(Approval {
                user_present: true,
                user_verified: true,
                selected: None,
            })
        }
    }

    #[test]
    fn pairing_fails_closed_by_default() {
        let words = ["maple", "orbit", "quartz", "ember"];
        let ctx = PairingApprovalContext {
            device_name: "desk",
            words: &words,
            requested_at: 0,
        };
        assert_eq!(
            ApproveOnly.confirm_pairing(&ctx),
            Err(ApprovalError::Unavailable)
        );
    }

    #[test]
    fn removal_fails_closed_by_default() {
        let ctx = RemovalApprovalContext {
            device_name: "desk",
            device_id_short: "0a1b2c3d4e5f",
        };
        assert_eq!(
            ApproveOnly.confirm_removal(&ctx),
            Err(ApprovalError::Unavailable)
        );
    }
}
