#![no_main]

use hirz_proto::json::{self, Limits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = json::parse(data, &Limits::default()) else {
        return;
    };
    let text = value.to_string();
    // Numbers like 1e300 print in full, so the writer output may exceed the input limit.
    let roomy = Limits {
        max_len: usize::MAX,
        ..Limits::default()
    };
    let back = json::parse(text.as_bytes(), &roomy).expect("writer output must parse");
    assert_eq!(back, value, "parse(to_string(v)) == v");
    assert_eq!(back.to_string(), text, "the writer is idempotent");
});
