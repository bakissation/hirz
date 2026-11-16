//! Wire formats for hirz: strict CBOR, COSE_Key, authenticatorData, `none` attestation objects,
//! clientDataJSON, base64url, hex and strict JSON. Every decoder is a pure function over `&[u8]`
//! with explicit limits so it can be fuzzed directly; no dependencies, no cryptography.
#![forbid(unsafe_code)]

pub mod attestation;
pub mod auth_data;
pub mod base64url;
pub mod cbor;
pub mod client_data;
pub mod cose;
pub mod hex;
pub mod json;
pub mod time;

pub const MAX_USER_ID_LEN: usize = 64;

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    Truncated,
    TrailingBytes,
    LimitExceeded,
    /// A valid but non-canonical encoding (non-shortest integer, unsorted map keys).
    NonCanonical,
    DuplicateKey,
    /// A construct outside the supported subset (floats, tags, indefinite lengths).
    Unsupported,
    /// Text that is not valid UTF-8 or contains forbidden code points.
    InvalidUtf8,
    Malformed,
    InvalidValue,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Error::Truncated => "input truncated",
            Error::TrailingBytes => "trailing bytes after item",
            Error::LimitExceeded => "limit exceeded",
            Error::NonCanonical => "non-canonical encoding",
            Error::DuplicateKey => "duplicate key",
            Error::Unsupported => "unsupported construct",
            Error::InvalidUtf8 => "invalid UTF-8",
            Error::Malformed => "malformed input",
            Error::InvalidValue => "invalid value",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
