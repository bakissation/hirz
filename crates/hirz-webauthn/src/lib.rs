//! The WebAuthn client role for the Firefox extension path: origin parsing, RP ID
//! validation against the public suffix list, options JSON to engine requests,
//! clientDataJSON, and engine output to response JSON.
//!
//! In the virtual security key path the browser does all of this itself.
#![forbid(unsafe_code)]

mod common;
pub mod create;
pub mod envelope;
mod error;
mod fields;
pub mod get;
pub mod origin;
pub mod psl;
mod punycode;
pub mod response;
pub mod rp_id;

pub use common::prf_salt;
pub use create::{CreatePlan, prepare_create};
pub use envelope::{Engine, PROTOCOL_VERSION, handle};
pub use error::{Error, ErrorName, core_error_name};
pub use get::{GetPlan, prepare_get};
pub use origin::{Origin, OriginError};
pub use response::{authentication_response, registration_response};
pub use rp_id::{RpIdError, validate_rp_id};

#[cfg(test)]
mod tests;
