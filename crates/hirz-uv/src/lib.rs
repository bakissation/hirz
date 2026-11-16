//! Approval methods and trusted prompts for hirz: [`HirzApprover`] implements
//! [`hirz_core::Approver`] with polkit, fprintd, a hirz PIN and click-to-allow. Prompts use zenity
//! through argument vectors, never a shell. See `docs/approval.md`.
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
