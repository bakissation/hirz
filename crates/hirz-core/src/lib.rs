//! hirz authenticator engine. Transport independent: the uhid frontend decodes CTAP2
//! into these types, the extension frontend builds them from WebAuthn JSON.
#![forbid(unsafe_code)]

pub mod engine;
pub mod types;

pub use engine::Engine;
pub use types::*;
