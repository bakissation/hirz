//! Approval methods and trusted prompts for hirz.
//!
//! [`HirzApprover`] implements [`hirz_core::Approver`]. Methods:
//!
//! | Method | Flags | Check |
//! |---|---|---|
//! | System password | UP + UV | `pkcheck` on the `dev.hirz.authenticate` polkit action (`auth_self`) |
//! | Fingerprint | UP + UV | `fprintd-verify` |
//! | hirz PIN | UP + UV | Argon2id verifier in the state directory, retry limit |
//! | Click-to-allow | UP only | zenity question; opt-in per RP id, refused when UV is required |
//!
//! Prompts use zenity through argument vectors (never a shell). See `docs/approval.md`.
#![forbid(unsafe_code)]

pub mod approver;
pub mod config;
pub mod display;
pub mod fprint;
pub mod pin;
pub mod polkit;
pub mod ratelimit;
pub mod runner;

pub use approver::{HirzApprover, Method};
pub use config::{Config, ConfigError, Paths, UvMethod};
pub use pin::{PinError, PinStatus, PinStore};
pub use runner::{CommandRunner, SystemRunner};
