use crate::origin::OriginError;
use crate::rp_id::RpIdError;
use core::fmt;
use hirz_core::{ApprovalError, CoreError};

/// Error names sent back to the extension. All but `NotHandled` are DOMException names
/// the page sees; `NotHandled` tells the extension to let Firefox run the ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorName {
    NotAllowedError,
    InvalidStateError,
    NotSupportedError,
    SecurityError,
    AbortError,
    NotHandled,
    UnknownError,
}

impl ErrorName {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorName::NotAllowedError => "NotAllowedError",
            ErrorName::InvalidStateError => "InvalidStateError",
            ErrorName::NotSupportedError => "NotSupportedError",
            ErrorName::SecurityError => "SecurityError",
            ErrorName::AbortError => "AbortError",
            ErrorName::NotHandled => "NotHandled",
            ErrorName::UnknownError => "UnknownError",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    BadEnvelope(&'static str),
    NotHandled(&'static str),
    /// The options violate the WebAuthn JSON grammar or a hirz size limit. Firefox gets
    /// the request so the page sees the browser's own TypeError or SyntaxError.
    InvalidOptions(&'static str),
    NotSupported(&'static str),
    /// The host cannot take the request now (its queue is full). The page sees a refusal.
    Busy(&'static str),
    /// An origin hirz cannot validate. Firefox applies the real rules, so it gets the request.
    Origin(OriginError),
    RpId(RpIdError),
    Core(CoreError),
    EngineOutput(&'static str),
}

impl Error {
    pub fn name(&self) -> ErrorName {
        match self {
            Error::BadEnvelope(_) | Error::EngineOutput(_) => ErrorName::UnknownError,
            Error::NotHandled(_) | Error::InvalidOptions(_) => ErrorName::NotHandled,
            Error::NotSupported(_) => ErrorName::NotSupportedError,
            Error::Busy(_) => ErrorName::NotAllowedError,
            Error::Origin(_) => ErrorName::NotHandled,
            Error::RpId(RpIdError::RelatedOriginRequired | RpIdError::NonCanonical) => {
                ErrorName::NotHandled
            }
            Error::RpId(_) => ErrorName::SecurityError,
            Error::Core(e) => core_error_name(e),
        }
    }

    /// A fixed diagnostic text. Never contains request data or engine internals.
    pub fn message(&self) -> &'static str {
        match self {
            Error::BadEnvelope(m)
            | Error::NotHandled(m)
            | Error::InvalidOptions(m)
            | Error::NotSupported(m)
            | Error::Busy(m)
            | Error::EngineOutput(m) => m,
            Error::Origin(_) => "origin not accepted",
            Error::RpId(RpIdError::RelatedOriginRequired) => "related origins not supported",
            Error::RpId(RpIdError::NonCanonical) => "rp id not in canonical form",
            Error::RpId(_) => "rp id rejected",
            Error::Core(
                CoreError::NoCredentials | CoreError::Approval(ApprovalError::NothingShown),
            ) => "no credential here",
            Error::Core(_) => "authenticator error",
        }
    }
}

/// `NoCredentials` is only reported when nothing matched and the user saw nothing, so Firefox
/// runs its own ceremony and the page learns nothing about the vault (WebAuthn privacy
/// considerations for authentication ceremonies). A refusal that came before any window
/// (`NothingShown`: prompt budget used up, no verification method, zenity missing) looks the same:
/// when hirz has a credential but cannot ask, the page must not tell it from "no credential".
pub fn core_error_name(e: &CoreError) -> ErrorName {
    match e {
        CoreError::CredentialExcluded => ErrorName::InvalidStateError,
        CoreError::NoCredentials | CoreError::Approval(ApprovalError::NothingShown) => {
            ErrorName::NotHandled
        }
        CoreError::UvRequiredUnavailable
        | CoreError::Approval(
            ApprovalError::Denied
            | ApprovalError::Timeout
            | ApprovalError::Unavailable
            | ApprovalError::Locked,
        ) => ErrorName::NotAllowedError,
        CoreError::UnsupportedAlgorithm => ErrorName::NotSupportedError,
        CoreError::Approval(ApprovalError::Internal(_))
        | CoreError::InvalidRequest(_)
        | CoreError::Vault(_)
        | CoreError::Crypto(_) => ErrorName::UnknownError,
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Origin(e) => e.fmt(f),
            Error::RpId(e) => e.fmt(f),
            _ => f.write_str(self.message()),
        }
    }
}

impl std::error::Error for Error {}

impl From<OriginError> for Error {
    fn from(e: OriginError) -> Self {
        Error::Origin(e)
    }
}

impl From<RpIdError> for Error {
    fn from(e: RpIdError) -> Self {
        Error::RpId(e)
    }
}

impl From<CoreError> for Error {
    fn from(e: CoreError) -> Self {
        Error::Core(e)
    }
}
