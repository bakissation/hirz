//! The `HIRZ_DEBUG_CTAP=1` trace: CTAP2 requests and responses in hex, without the user entity.
//! The messages carry relying party ids, credential ids, signatures and, in a makeCredential
//! request, account and display names, so the trace goes to a terminal only (see `main.rs`) and the
//! names never reach it.

use hirz_ctap::ctap2::{command, limits};
use hirz_proto::cbor::{self, Value};
use hirz_proto::hex::encode as hex;

const REDACTED: &str = "redacted";

/// The CBOR key of the user entity in a request, or in a response to `cmd`.
fn user_key(cmd: u8, request: bool) -> Option<i64> {
    match (cmd, request) {
        (command::MAKE_CREDENTIAL, true) => Some(0x03),
        (command::GET_ASSERTION, false) => Some(0x04),
        _ => None,
    }
}

fn without_user(body: &[u8], key: i64) -> Option<Vec<u8>> {
    if body.is_empty() {
        return Some(Vec::new());
    }
    let mut decoded = cbor::decode(body, &limits()).ok()?;
    let Value::Map(entries) = &mut decoded else {
        return None;
    };
    let hidden = Value::int(key);
    for (k, v) in entries.iter_mut() {
        if *k == hidden {
            *v = Value::from(REDACTED);
        }
    }
    cbor::encode(&decoded).ok()
}

/// `first` is the command of a request or the status of a response. A message that should have a
/// user entity but cannot be read is reported by its size only.
fn render(first: u8, body: &[u8], key: Option<i64>) -> String {
    let shown = match key {
        None => Some(body.to_vec()),
        Some(k) => without_user(body, k),
    };
    match shown {
        Some(b) => format!("{first:02x}{}", hex(&b)),
        None => format!("{first:02x} ({} bytes not shown)", body.len()),
    }
}

/// A request: the command byte, then its CBOR parameters.
pub fn request(message: &[u8]) -> String {
    match message.split_first() {
        Some((&cmd, body)) => render(cmd, body, user_key(cmd, true)),
        None => "(empty)".to_owned(),
    }
}

/// A response to the request with command `cmd`: the status byte, then CBOR.
pub fn response(cmd: Option<u8>, message: &[u8]) -> String {
    match message.split_first() {
        Some((&status, body)) => {
            let key = cmd.and_then(|c| user_key(c, false));
            render(status, body, key)
        }
        None => "(empty)".to_owned(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use hirz_proto::cbor::MapBuilder;

    fn make_credential_request() -> Vec<u8> {
        let user = MapBuilder::new()
            .text("id", [7u8; 8].as_slice())
            .text("name", "alice@example.com")
            .text("displayName", "Alice Example")
            .build();
        let m = MapBuilder::new()
            .int(0x01, [1u8; 32].as_slice())
            .int(0x02, MapBuilder::new().text("id", "example.com").build())
            .int(0x03, user)
            .build();
        let mut out = vec![command::MAKE_CREDENTIAL];
        out.extend(cbor::encode(&m).unwrap());
        out
    }

    #[test]
    fn a_make_credential_trace_has_no_account_names() {
        let t = request(&make_credential_request());
        assert!(t.starts_with("01"));
        assert!(!t.contains(&hex(b"alice")));
        assert!(!t.contains(&hex(b"Alice")));
        assert!(!t.contains(&hex(&[7u8; 8])));
        assert!(t.contains(&hex(b"example.com")));
        assert!(t.contains(&hex(REDACTED.as_bytes())));
    }

    #[test]
    fn a_get_assertion_response_hides_its_user_and_other_messages_pass() {
        let m = MapBuilder::new()
            .int(0x03, [9u8; 4].as_slice())
            .int(
                0x04,
                MapBuilder::new().text("id", [5u8; 6].as_slice()).build(),
            )
            .build();
        let mut resp = vec![0x00];
        resp.extend(cbor::encode(&m).unwrap());
        let t = response(Some(command::GET_ASSERTION), &resp);
        assert!(t.starts_with("00"));
        assert!(!t.contains(&hex(&[5u8; 6])));
        assert!(t.contains(&hex(&[9u8; 4])));
        assert_eq!(response(Some(command::GET_INFO), &[0x00, 0xa0]), "00a0");
        assert_eq!(response(None, &[0x2d]), "2d");
        assert_eq!(response(None, &[]), "(empty)");
        assert_eq!(request(&[command::GET_INFO]), "04");
    }

    #[test]
    fn an_unreadable_request_that_may_hold_names_is_not_dumped() {
        let t = request(&[command::MAKE_CREDENTIAL, 0xa1, 0x03, 0x65, 0x61, 0x6c]);
        assert_eq!(t, "01 (5 bytes not shown)");
        let t = request(&[command::MAKE_CREDENTIAL, 0xff, 0xff]);
        assert_eq!(t, "01 (2 bytes not shown)");
    }
}
