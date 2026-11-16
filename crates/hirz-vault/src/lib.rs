//! Encrypted, folder-synced credential vault.
//!
//! A vault is a directory the user syncs with any file-sync tool. Every file is written once
//! and never modified, so sync tools never produce conflict copies; changes are events merged
//! deterministically. Records are encrypted under a random 256-bit vault key that is never
//! derived from a password, so a copy of the folder is not an offline guessing target.
//! The byte-level format is specified in `docs/vault-format.md`.
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

/// Random 16-byte device identifier.
pub type DeviceId = [u8; 16];

pub use backup::{IMPORT_LIMIT, import_backup};
pub use error::{PhraseError, VaultError};
pub use format::GenId;
pub use pairing::{PAIRING_LIFETIME_SECS, PAIRING_WORDS, PairingPoll, PairingRequest, PendingJoin};
pub use record::{
    CredentialRecord, HmacSecretPair, MAX_CREDENTIAL_ID_LEN, MAX_DEVICE_NAME_LEN, MAX_PKCS8_LEN,
    MAX_STRING_LEN, MAX_USER_ID_LEN,
};
pub use recovery::RecoveryPhrase;
pub use vault::{DeviceInfo, ScanReport, SkippedFile, Vault};

/// Name of the vault header file inside the vault directory (`docs/vault-format.md`, section 3).
pub const HEADER_FILE: &str = format::HEADER_NAME;
/// Name of the device state file inside the local state directory (`docs/vault-format.md`,
/// section 7).
pub const DEVICE_STATE_FILE: &str = format::STATE_DEVICE;

/// Fuzzing entry point, not a stable API. Decodes a credential record body; on success
/// returns the result of encoding the decoded record again.
#[doc(hidden)]
pub fn fuzz_decode_record_body(
    data: &[u8],
) -> Result<Result<hirz_crypto::Zeroizing<Vec<u8>>, VaultError>, VaultError> {
    record::CredentialRecord::decode(data).map(|rec| rec.encode())
}

/// Fuzzing entry point, not a stable API. Decodes an event (body and author tag); on success
/// returns the result of encoding the decoded event and its tag again.
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
