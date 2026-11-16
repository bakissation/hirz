#![no_main]

//! Parsers for text produced by other programs or the kernel: fprintd-verify and
//! fprintd-list output, /proc/<pid>/stat and status, and /etc/passwd. Input: one byte for
//! the exit status, then the text.

use hirz_uv::fprint::{self, VerifyOutcome};
use hirz_uv::polkit;
use hirz_uv::runner;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&ctl, text)) = data.split_first() else {
        return;
    };
    let code = match ctl {
        0xff => None,
        c => Some(i32::from(c & 0x7f)),
    };
    let outcome = fprint::classify_verify(code, text);
    if outcome == VerifyOutcome::Match {
        assert_eq!(code, Some(0), "a match needs exit status 0");
        let s = core::str::from_utf8(text).expect("a match needs UTF-8");
        assert!(s.contains("Verify result: verify-match (done)"));
    }
    if fprint::has_enrolled_fingers(code, text) {
        assert_eq!(code, Some(0));
    }
    let _ = polkit::parse_stat_start_time(text);
    let _ = polkit::parse_status_uid(text);
    let uid = u32::from(ctl) * 4;
    if let Some(name) = runner::passwd_name_for_uid(text, uid) {
        assert!(runner::valid_username(&name));
        assert!(!name.starts_with('-'));
    }
});
