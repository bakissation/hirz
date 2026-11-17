//! The first bytes on a connection to `hirz-uhid-broker` (docs/uhid.md, "How the broker works").
//! A client sends one hello of [`HELLO_LEN`] bytes; anything else closes the connection.

pub const HELLO_LEN: usize = 8;
/// Asks for a FIDO device; 64-byte reports follow in both directions.
pub const HELLO_DEVICE: [u8; HELLO_LEN] = *b"hirzdev1";
/// Asks only whether the broker runs. It answers [`ALIVE`] and closes the connection.
pub const HELLO_PROBE: [u8; HELLO_LEN] = *b"hirzprb1";
pub const ALIVE: [u8; HELLO_LEN] = *b"hirzok01";
