//! The only crate in hirz that contains `unsafe` code.
//!
//! Every `unsafe` block is a single libc call with a `SAFETY` comment. Anything that can be
//! expressed with safe code (the uhid event encoding, environment parsing) is safe and unit
//! tested.
#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod activation;
pub mod caps;
pub mod harden;
pub mod peercred;
pub mod poll;
pub mod uhid;

pub use activation::{ListenEnvError, listen_fds, parse_listen_env};
pub use caps::drop_all_capabilities;
pub use harden::{
    disable_core_dumps, harden_process, lock_memory, set_no_new_privs, set_non_dumpable,
};
pub use peercred::{PeerCredentials, SocketInfo, peer_credentials, socket_info};
pub use poll::{PollStatus, poll_readable};
