#![no_main]

//! The whole native-messaging request handler on a JSON envelope, with an engine that never
//! signs. Every reply must be a well-formed envelope the strict reader accepts.

use hirz_fuzz::NoSignEngine;
use hirz_proto::json::{self, Json, Limits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(request) = json::parse(data, &Limits::default()) else {
        return;
    };
    let reply = hirz_webauthn::handle(&request, &mut NoSignEngine);
    let text = reply.to_string();
    assert_eq!(json::parse(text.as_bytes(), &Limits::default()).as_ref(), Ok(&reply));
    assert_eq!(reply.get("v").and_then(Json::as_u64), Some(hirz_webauthn::PROTOCOL_VERSION));
    let ok = reply.get("ok").and_then(Json::as_bool).expect("ok flag");
    let id = reply.get("id").expect("id member");
    assert!(id.is_null() || id.as_u64().is_some_and(|n| n < (1 << 53)));
    if ok {
        assert!(reply.get("error").is_none());
    } else {
        assert!(reply.get("error").and_then(Json::as_str).is_some());
        assert!(reply.get("message").and_then(Json::as_str).is_some());
    }
});
