//! Encrypted, folder-synced credential vault. Every file is written once and never modified, so
//! sync tools never produce conflict copies; changes are events merged deterministically. The vault
//! key is random, never derived from a password. Byte-level format: docs/vault-format.md.
#![forbid(unsafe_code)]

mod backup;
mod codec;
mod error;
mod format;
mod fsutil;
mod pairing;
mod record;
mod recovery;
mod vault;

#[cfg(test)]
mod tests;

pub type DeviceId = [u8; 16];

pub use backup::{IMPORT_LIMIT, import_backup};
pub use error::{PhraseError, VaultError};
pub use format::GenId;
pub use fsutil::{VAULT_POINTER_FILE, VaultPointerError, read_vault_pointer};
pub use pairing::{PAIRING_LIFETIME_SECS, PAIRING_WORDS, PairingPoll, PairingRequest, PendingJoin};
pub use record::{
    CredentialRecord, HmacSecretPair, MAX_CREDENTIAL_ID_LEN, MAX_DEVICE_NAME_LEN, MAX_PKCS8_LEN,
    MAX_STRING_LEN, MAX_USER_ID_LEN,
};
pub use recovery::RecoveryPhrase;
pub use vault::{DeviceInfo, ScanReport, SkippedFile, Vault};

pub const HEADER_FILE: &str = format::HEADER_NAME;
pub const DEVICE_STATE_FILE: &str = format::STATE_DEVICE;

/// Fuzzing entry point, not a stable API.
#[doc(hidden)]
pub fn fuzz_decode_record_body(
    data: &[u8],
) -> Result<Result<hirz_crypto::Zeroizing<Vec<u8>>, VaultError>, VaultError> {
    record::CredentialRecord::decode(data).map(|rec| rec.encode())
}

/// Fuzzing entry point, not a stable API.
#[doc(hidden)]
pub fn fuzz_decode_event(
    data: &[u8],
) -> Result<Result<hirz_crypto::Zeroizing<Vec<u8>>, VaultError>, VaultError> {
    let (event, _, tag) = record::Event::decode(data)?;
    Ok(event.encode_body().map(|mut body| {
        record::append_tag(&mut body, &tag);
        body
    }))
}
