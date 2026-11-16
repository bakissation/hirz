//! Wire formats for hirz: strict CBOR, COSE_Key, authenticatorData, `none` attestation
//! objects, clientDataJSON, base64url and a small strict JSON reader and writer.
//!
//! Every decoder is a pure function over `&[u8]` with explicit limits, so it can be fuzzed
//! directly (see `FUZZING.md`). This crate has no dependencies and does no cryptography.
#![forbid(unsafe_code)]

pub mod attestation;
pub mod auth_data;
pub mod base64url;
pub mod cbor;
pub mod client_data;
pub mod cose;
pub mod json;

use core::fmt;

/// Errors returned by every decoder and encoder in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input ended before the structure was complete.
    Truncated,
    /// Bytes remain after a complete top-level item.
    TrailingBytes,
    /// A configured length, depth or item limit was exceeded.
    LimitExceeded,
    /// A valid but non-canonical encoding (non-shortest integer, unsorted map keys).
    NonCanonical,
    /// A map or object contains the same key twice.
    DuplicateKey,
    /// A construct outside the supported subset (floats, tags, indefinite lengths).
    Unsupported,
    /// Text that is not valid UTF-8 or contains forbidden code points.
    InvalidUtf8,
    /// Syntactically invalid input.
    Malformed,
    /// A well-formed value has the wrong type or an invalid field.
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

/// Result type of this crate.
pub type Result<T> = core::result::Result<T, Error>;
