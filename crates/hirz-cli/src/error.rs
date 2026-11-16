use core::fmt;
use hirz_vault::{PhraseError, VaultError};

/// Process exit statuses. Documented in `docs/cli.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Exit {
    Ok = 0,
    Failed = 1,
    Usage = 2,
    NotSetUp = 3,
    Cancelled = 4,
    Denied = 5,
    Partial = 6,
}

impl Exit {
    pub fn code(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    pub exit: Exit,
    pub message: String,
}

impl CliError {
    pub fn new(exit: Exit, message: impl Into<String>) -> Self {
        CliError {
            exit,
            message: message.into(),
        }
    }
    pub fn failed(message: impl Into<String>) -> Self {
        Self::new(Exit::Failed, message)
    }
    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(Exit::Usage, message)
    }
    pub fn cancelled(message: impl Into<String>) -> Self {
        Self::new(Exit::Cancelled, message)
    }
    pub fn denied(message: impl Into<String>) -> Self {
        Self::new(Exit::Denied, message)
    }
    pub fn not_set_up(message: impl Into<String>) -> Self {
        Self::new(Exit::NotSetUp, message)
    }
    pub fn io(what: &str, e: &std::io::Error) -> Self {
        Self::failed(format!("{what}: {}", describe_io(e.kind())))
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

pub type CliResult<T = ()> = Result<T, CliError>;

pub fn describe_io(kind: std::io::ErrorKind) -> String {
    use std::io::ErrorKind as K;
    match kind {
        K::NotFound => "not found".into(),
        K::PermissionDenied => "permission denied".into(),
        K::AlreadyExists => "already exists".into(),
        K::ReadOnlyFilesystem => "the disk is read-only".into(),
        K::StorageFull => "the disk is full".into(),
        other => other.to_string(),
    }
}

pub fn phrase_problem(e: PhraseError) -> String {
    match e {
        PhraseError::WordCount(n) => {
            format!("You typed {n} words. The recovery phrase has exactly 24 words.")
        }
        PhraseError::UnknownWord(i) => format!(
            "Word {} is not a recovery phrase word. Check its spelling.",
            i.saturating_add(1)
        ),
        PhraseError::Checksum => "All words are known, but they do not form a valid phrase. \
             Check for a typo or two words in the wrong order."
            .into(),
    }
}

pub fn vault_error(e: &VaultError) -> CliError {
    match e {
        VaultError::Io(kind, op) => CliError::failed(format!(
            "Could not access the vault files ({op}: {}).",
            describe_io(*kind)
        )),
        VaultError::NotFound => CliError::not_set_up(
            "hirz is not set up on this computer. Run `hirz init` to start a new vault, \
             or `hirz join --vault DIR` to use one you already have.",
        ),
        VaultError::WrongVault => CliError::failed(
            "The vault folder holds a different vault than the one this computer joined. \
             Check the --vault path.",
        ),
        VaultError::NoAccess => CliError::failed(
            "This computer can no longer read the vault. It may have been removed from the \
             vault on another device. To use it here again, run `hirz join` with your \
             recovery phrase (after removing this computer's old setup).",
        ),
        VaultError::Fork => CliError::failed(
            "The vault folder no longer holds the key changes this computer followed, so \
             nothing new can be saved. Passkeys still work. Run `hirz status`, then `hirz repair`.",
        ),
        VaultError::Removed => CliError::failed(format!(
            "{} Run `hirz status` to see more.",
            crate::app::REMOVED
        )),
        VaultError::RotationConflict => CliError::failed(
            "Two devices removed each other from the vault, so hirz does not know which one \
             to trust. First stop sharing the vault folder with the device you do not trust, \
             then run `hirz remove-device` for it again on a device you trust. `hirz repair` \
             shows the key changes and can delete one.",
        ),
        VaultError::LockTimeout => {
            CliError::failed("Another hirz program is busy with the vault. Try again in a moment.")
        }
        VaultError::Phrase(p) => CliError::denied(phrase_problem(*p)),
        VaultError::WrongRecoveryKey => {
            CliError::denied("The recovery phrase does not belong to this vault.")
        }
        other => CliError::failed(format!("Vault error: {other}.")),
    }
}

impl From<VaultError> for CliError {
    fn from(e: VaultError) -> Self {
        vault_error(&e)
    }
}
