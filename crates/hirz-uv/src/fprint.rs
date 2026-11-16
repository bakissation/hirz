//! Fingerprint through the fprintd command line tools (no D-Bus library).

/// Result of one `fprintd-verify` run that exited on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    Match,
    NoMatch,
    /// No reader, no enrolled finger, permission denied, device error or output that does not
    /// follow the expected shape.
    Unavailable,
}

const RESULT_PREFIX: &str = "Verify result: ";

/// Classifies a finished `fprintd-verify` run. A match needs all of: exit status 0, valid
/// UTF-8 output, exactly one final (`done`) result line, and that line being the last result
/// line and saying `verify-match`. Anything else is not a match.
pub fn classify_verify(code: Option<i32>, stdout: &[u8]) -> VerifyOutcome {
    let Ok(text) = core::str::from_utf8(stdout) else {
        return VerifyOutcome::Unavailable;
    };
    let results: Vec<(&str, bool)> = text
        .lines()
        .filter_map(|l| l.trim_end_matches('\r').strip_prefix(RESULT_PREFIX))
        .filter_map(parse_result)
        .collect();
    let done_count = results.iter().filter(|(_, done)| *done).count();
    match results.last() {
        Some(("verify-match", true)) if code == Some(0) && done_count == 1 => VerifyOutcome::Match,
        Some(("verify-no-match", true)) if done_count == 1 => VerifyOutcome::NoMatch,
        _ => VerifyOutcome::Unavailable,
    }
}

fn parse_result(rest: &str) -> Option<(&str, bool)> {
    if let Some(r) = rest.strip_suffix(" (done)") {
        Some((r, true))
    } else {
        rest.strip_suffix(" (not done)").map(|r| (r, false))
    }
}

/// True when `fprintd-list <user>` succeeded and lists at least one finger
/// (lines of the form ` - #0: right-index-finger`).
pub fn has_enrolled_fingers(code: Option<i32>, stdout: &[u8]) -> bool {
    if code != Some(0) {
        return false;
    }
    let Ok(text) = core::str::from_utf8(stdout) else {
        return false;
    };
    text.lines().any(|l| {
        l.strip_prefix(" - #")
            .and_then(|r| r.split_once(": "))
            .is_some_and(|(n, finger)| {
                !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) && !finger.trim().is_empty()
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MATCH: &[u8] = b"Using device /net/reactivated/Fprint/Device/0\nListing enrolled fingers:\n - #0: right-index-finger\nVerify started!\nVerifying: right-index-finger\nVerify result: verify-match (done)\n";

    #[test]
    fn match_needs_status_zero() {
        assert_eq!(classify_verify(Some(0), MATCH), VerifyOutcome::Match);
        assert_eq!(classify_verify(Some(1), MATCH), VerifyOutcome::Unavailable);
        assert_eq!(classify_verify(None, MATCH), VerifyOutcome::Unavailable);
    }

    #[test]
    fn retries_then_match() {
        let out = b"Verify started!\nVerify result: verify-swipe-too-short (not done)\nVerify result: verify-retry-scan (not done)\nVerify result: verify-match (done)\n";
        assert_eq!(classify_verify(Some(0), out), VerifyOutcome::Match);
    }

    #[test]
    fn no_match() {
        let out = b"Verify started!\nVerify result: verify-no-match (done)\n";
        assert_eq!(classify_verify(Some(1), out), VerifyOutcome::NoMatch);
        assert_eq!(classify_verify(Some(0), out), VerifyOutcome::NoMatch);
    }

    #[test]
    fn partial_or_odd_output_is_not_a_match() {
        let not_done = b"Verify result: verify-match (not done)\n";
        assert_eq!(
            classify_verify(Some(0), not_done),
            VerifyOutcome::Unavailable
        );
        let match_then_more =
            b"Verify result: verify-match (done)\nVerify result: verify-no-match (done)\n";
        assert_eq!(
            classify_verify(Some(0), match_then_more),
            VerifyOutcome::Unavailable
        );
        let two_matches =
            b"Verify result: verify-match (done)\nVerify result: verify-match (done)\n";
        assert_eq!(
            classify_verify(Some(0), two_matches),
            VerifyOutcome::Unavailable
        );
        let truncated = b"Verify started!\nVerify result: verify-ma";
        assert_eq!(
            classify_verify(Some(0), truncated),
            VerifyOutcome::Unavailable
        );
        let indented = b"  Verify result: verify-match (done)\n";
        assert_eq!(
            classify_verify(Some(0), indented),
            VerifyOutcome::Unavailable
        );
        let suffix = b"Verify result: verify-match (done) extra\n";
        assert_eq!(classify_verify(Some(0), suffix), VerifyOutcome::Unavailable);
        assert_eq!(classify_verify(Some(0), b""), VerifyOutcome::Unavailable);
        assert_eq!(
            classify_verify(Some(0), b"\xff\xfe"),
            VerifyOutcome::Unavailable
        );
        let other = b"Verify result: verify-disconnected (done)\n";
        assert_eq!(classify_verify(Some(1), other), VerifyOutcome::Unavailable);
        let no_fingers = b"Using device /net/reactivated/Fprint/Device/0\nNo fingers enrolled for this device.\n";
        assert_eq!(
            classify_verify(Some(1), no_fingers),
            VerifyOutcome::Unavailable
        );
    }

    #[test]
    fn crlf_tolerated() {
        let out = b"Verify result: verify-match (done)\r\n";
        assert_eq!(classify_verify(Some(0), out), VerifyOutcome::Match);
    }

    #[test]
    fn enrolled() {
        let out = b"found 1 devices\nDevice at /net/reactivated/Fprint/Device/0\nUsing device /net/reactivated/Fprint/Device/0\nFingerprints for user alice on Acme Reader (press):\n - #0: right-index-finger\n - #1: left-index-finger\n";
        assert!(has_enrolled_fingers(Some(0), out));
        assert!(!has_enrolled_fingers(Some(1), out));
        let none = b"found 1 devices\nDevice at /net/reactivated/Fprint/Device/0\nUser alice has no fingers enrolled for Acme Reader.\n";
        assert!(!has_enrolled_fingers(Some(0), none));
        let denied = b"found 1 devices\nListEnrolledFingers failed: GDBus.Error:net.reactivated.Fprint.Error.PermissionDenied: Not Authorized\n";
        assert!(!has_enrolled_fingers(Some(0), denied));
        assert!(!has_enrolled_fingers(Some(0), b" - #x: finger\n - #0: \n"));
        assert!(!has_enrolled_fingers(Some(0), b"No devices available\n"));
    }
}
