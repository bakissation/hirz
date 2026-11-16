use core::fmt;

/// Errors from recovery phrase parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhraseError {
    /// A recovery phrase has exactly 24 words.
    WordCount(usize),
    /// The word at this zero-based position is not in the word list.
    UnknownWord(usize),
    /// All words are valid but the checksum does not match (a typo or swapped words).
    Checksum,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// File system error (kind and the operation that failed).
    Io(std::io::ErrorKind, &'static str),
    /// A cryptographic operation failed (not an authentication failure of a file).
    Crypto,
    /// A file is malformed or failed authentication.
    Corrupt(&'static str),
    /// A file uses a format version this build does not understand.
    UnsupportedVersion,
    /// A value could not be encoded (too long or out of order).
    Encode,
    /// The record fails validation (field sizes, algorithm, missing data).
    InvalidRecord(&'static str),
    /// `create` found an existing vault, or `join` found an existing device state.
    AlreadyExists,
    /// No vault header, or no device state for this vault.
    NotFound,
    /// The device state belongs to a different vault.
    WrongVault,
    Phrase(PhraseError),
    /// The recovery phrase is valid but does not belong to this vault.
    WrongRecoveryKey,
    /// No key generation of this vault can be opened with the available keys.
    NoAccess,
    /// The local state lock could not be taken in time.
    LockTimeout,
    UnknownDevice,
    /// A device cannot remove itself.
    CannotRemoveSelf,
    /// Two key rotations removed each other's creators; see `ScanReport::rotation_conflict`.
    RotationConflict,
    /// Backup export or import parameters are out of bounds.
    InvalidParameters,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::Io(kind, op) => write!(f, "i/o error during {op}: {kind}"),
            VaultError::Crypto => f.write_str("cryptographic operation failed"),
            VaultError::Corrupt(what) => write!(f, "corrupt or unauthenticated data: {what}"),
            VaultError::UnsupportedVersion => f.write_str("unsupported format version"),
            VaultError::Encode => f.write_str("value cannot be encoded"),
            VaultError::InvalidRecord(what) => write!(f, "invalid credential record: {what}"),
            VaultError::AlreadyExists => f.write_str("already exists"),
            VaultError::NotFound => f.write_str("not found"),
            VaultError::WrongVault => f.write_str("device state belongs to another vault"),
            VaultError::Phrase(PhraseError::WordCount(n)) => {
                write!(f, "recovery phrase has {n} words, expected 24")
            }
            VaultError::Phrase(PhraseError::UnknownWord(i)) => {
                write!(
                    f,
                    "recovery phrase word {} is not in the word list",
                    i.saturating_add(1)
                )
            }
            VaultError::Phrase(PhraseError::Checksum) => {
                f.write_str("recovery phrase checksum mismatch")
            }
            VaultError::WrongRecoveryKey => f.write_str("recovery key does not open this vault"),
            VaultError::NoAccess => f.write_str("no usable key generation for this device"),
            VaultError::LockTimeout => f.write_str("timed out waiting for the state lock"),
            VaultError::UnknownDevice => f.write_str("unknown device"),
            VaultError::CannotRemoveSelf => f.write_str("a device cannot remove itself"),
            VaultError::RotationConflict => {
                f.write_str("conflicting key rotations; remove the untrusted device again")
            }
            VaultError::InvalidParameters => f.write_str("parameters out of bounds"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<hirz_crypto::CryptoError> for VaultError {
    fn from(_: hirz_crypto::CryptoError) -> Self {
        VaultError::Crypto
    }
}

pub(crate) fn io(op: &'static str) -> impl Fn(std::io::Error) -> VaultError {
    move |e| VaultError::Io(e.kind(), op)
}
