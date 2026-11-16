#![no_main]

use hirz_proto::base64url;
use hirz_proto::client_data::{self, CeremonyType};
use hirz_proto::json::{self, Json, Limits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&ctl, rest)) = data.split_first() else {
        return;
    };
    let Some((&n, rest)) = rest.split_first() else {
        return;
    };
    let (challenge, rest) = rest.split_at(usize::from(n % 64).min(rest.len()));
    let Ok(text) = core::str::from_utf8(rest) else {
        return;
    };
    let (origin, top) = match text.split_once('\n') {
        Some((o, t)) => (o, Some(t)),
        None => (text, None),
    };
    let top = top.filter(|_| ctl & 4 != 0);
    let ceremony = if ctl & 1 == 0 {
        CeremonyType::Create
    } else {
        CeremonyType::Get
    };
    let cross_origin = ctl & 2 != 0;
    let s = client_data::serialize(ceremony, challenge, origin, cross_origin, top);
    let roomy = Limits {
        max_len: usize::MAX,
        ..Limits::default()
    };
    let v = json::parse(s.as_bytes(), &roomy).expect("clientDataJSON must be valid JSON");
    assert_eq!(v.get("type").and_then(Json::as_str), Some(ceremony.as_str()));
    let ch = v.get("challenge").and_then(Json::as_str).expect("challenge");
    assert_eq!(base64url::decode(ch).expect("challenge is base64url"), challenge);
    assert_eq!(v.get("origin").and_then(Json::as_str), Some(origin));
    assert_eq!(v.get("crossOrigin").and_then(Json::as_bool), Some(cross_origin));
    assert_eq!(v.get("topOrigin").and_then(Json::as_str), top);
    assert_eq!(v.as_object().map(<[_]>::len), Some(4 + usize::from(top.is_some())));
});
