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
pub use record::{
    CREDENTIAL_ID_LEN, CredentialRecord, HmacSecretPair, MAX_DEVICE_NAME_LEN, MAX_PKCS8_LEN,
    MAX_STRING_LEN, MAX_USER_ID_LEN,
};
pub use recovery::RecoveryPhrase;
pub use vault::{DeviceInfo, ScanReport, SkippedFile, Vault};
