//! CTAP status codes (CTAP 2.2 section 8.2) and the mapping from engine errors.

use hirz_core::{ApprovalError, CoreError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Status {
    Ok = 0x00,
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    InvalidSeq = 0x04,
    Timeout = 0x05,
    ChannelBusy = 0x06,
    LockRequired = 0x0a,
    InvalidChannel = 0x0b,
    CborUnexpectedType = 0x11,
    InvalidCbor = 0x12,
    MissingParameter = 0x14,
    LimitExceeded = 0x15,
    FpDatabaseFull = 0x17,
    LargeBlobStorageFull = 0x18,
    CredentialExcluded = 0x19,
    Processing = 0x21,
    InvalidCredential = 0x22,
    UserActionPending = 0x23,
    OperationPending = 0x24,
    NoOperations = 0x25,
    UnsupportedAlgorithm = 0x26,
    OperationDenied = 0x27,
    KeyStoreFull = 0x28,
    UnsupportedOption = 0x2b,
    InvalidOption = 0x2c,
    KeepaliveCancel = 0x2d,
    NoCredentials = 0x2e,
    UserActionTimeout = 0x2f,
    NotAllowed = 0x30,
    PinInvalid = 0x31,
    PinBlocked = 0x32,
    PinAuthInvalid = 0x33,
    PinAuthBlocked = 0x34,
    PinNotSet = 0x35,
    PuatRequired = 0x36,
    PinPolicyViolation = 0x37,
    RequestTooLarge = 0x39,
    ActionTimeout = 0x3a,
    UpRequired = 0x3b,
    UvBlocked = 0x3c,
    IntegrityFailure = 0x3d,
    InvalidSubcommand = 0x3e,
    UvInvalid = 0x3f,
    UnauthorizedPermission = 0x40,
    Other = 0x7f,
}

impl Status {
    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn response(self) -> Vec<u8> {
        vec![self.code()]
    }
}

impl From<&ApprovalError> for Status {
    fn from(e: &ApprovalError) -> Self {
        match e {
            // Firefox treats OPERATION_DENIED as a failed verification and resends at once, looping forever on
            // a user refusal; NOT_ALLOWED ends the ceremony (docs/uhid.md, "Refusals end the ceremony").
            ApprovalError::Denied => Status::NotAllowed,
            ApprovalError::Timeout => Status::UserActionTimeout,
            // No clientPin: PIN_BLOCKED would point the platform at a PIN it cannot see.
            ApprovalError::Locked => Status::UvBlocked,
            // UV_INVALID and OPERATION_DENIED make platforms retry built-in UV in a loop.
            ApprovalError::Unavailable => Status::NotAllowed,
            ApprovalError::Internal(_) => Status::Other,
        }
    }
}

impl From<&CoreError> for Status {
    fn from(e: &CoreError) -> Self {
        match e {
            CoreError::CredentialExcluded => Status::CredentialExcluded,
            CoreError::NoCredentials => Status::NoCredentials,
            CoreError::UnsupportedAlgorithm => Status::UnsupportedAlgorithm,
            CoreError::UvRequiredUnavailable => Status::NotAllowed,
            CoreError::Approval(a) => Status::from(a),
            CoreError::InvalidRequest(_) => Status::InvalidParameter,
            CoreError::Vault(_) | CoreError::Crypto(_) => Status::Other,
        }
    }
}

impl From<CoreError> for Status {
    fn from(e: CoreError) -> Self {
        Status::from(&e)
    }
}

impl From<hirz_proto::Error> for Status {
    fn from(e: hirz_proto::Error) -> Self {
        match e {
            hirz_proto::Error::LimitExceeded => Status::LimitExceeded,
            _ => Status::InvalidCbor,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_match_the_specification() {
        assert_eq!(Status::Ok.code(), 0x00);
        assert_eq!(Status::InvalidCbor.code(), 0x12);
        assert_eq!(Status::CredentialExcluded.code(), 0x19);
        assert_eq!(Status::OperationDenied.code(), 0x27);
        assert_eq!(Status::KeepaliveCancel.code(), 0x2d);
        assert_eq!(Status::PinNotSet.code(), 0x35);
        assert_eq!(Status::InvalidSubcommand.code(), 0x3e);
        assert_eq!(Status::UnauthorizedPermission.code(), 0x40);
        assert_eq!(Status::Other.code(), 0x7f);
        assert_eq!(
            Status::KeepaliveCancel.code(),
            crate::hid::ctap2_status::ERR_KEEPALIVE_CANCEL
        );
        assert_eq!(
            Status::UserActionTimeout.code(),
            crate::hid::ctap2_status::ERR_USER_ACTION_TIMEOUT
        );
    }

    #[test]
    fn engine_errors_map_to_statuses() {
        let cases = [
            (CoreError::CredentialExcluded, Status::CredentialExcluded),
            (CoreError::NoCredentials, Status::NoCredentials),
            (
                CoreError::UnsupportedAlgorithm,
                Status::UnsupportedAlgorithm,
            ),
            (CoreError::UvRequiredUnavailable, Status::NotAllowed),
            (
                CoreError::Approval(ApprovalError::Denied),
                Status::NotAllowed,
            ),
            (
                CoreError::Approval(ApprovalError::Timeout),
                Status::UserActionTimeout,
            ),
            (
                CoreError::Approval(ApprovalError::Locked),
                Status::UvBlocked,
            ),
            (
                CoreError::Approval(ApprovalError::Unavailable),
                Status::NotAllowed,
            ),
            (
                CoreError::Approval(ApprovalError::Internal("x".into())),
                Status::Other,
            ),
            (CoreError::InvalidRequest("x"), Status::InvalidParameter),
            (CoreError::Vault("x".into()), Status::Other),
            (CoreError::Crypto("x".into()), Status::Other),
        ];
        for (e, s) in cases {
            assert_eq!(Status::from(&e), s, "{e:?}");
        }
    }
}
