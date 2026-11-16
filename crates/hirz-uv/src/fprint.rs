//! Fingerprint through the fprintd command line tools (no D-Bus library).

use std::io::Read;
use std::path::PathBuf;

use crate::pin::{ensure_private_dir, write_atomic};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    Match,
    Retry(Retry),
    NoFingers,
    ReaderError,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retry {
    NoMatch,
    RetryScan,
    SwipeTooShort,
    NotCentered,
    RemoveAndRetry,
}

impl Retry {
    pub fn message(self) -> &'static str {
        match self {
            Retry::NoMatch => "Not recognised.",
            Retry::RetryScan => "The reader could not read your finger.",
            Retry::SwipeTooShort => "The swipe was too short.",
            Retry::NotCentered => "Your finger was not centred on the reader.",
            Retry::RemoveAndRetry => "Lift your finger, then touch the reader again.",
        }
    }
}

const RESULT_PREFIX: &str = "Verify result: ";
/// fprintd reports a user without enrolled fingers with these texts (CLI message, D-Bus error).
const NO_FINGERS_MARKERS: [&str; 3] = [
    "No fingers enrolled",
    "no fingers enrolled",
    "net.reactivated.Fprint.Error.NoEnrolledPrints",
];

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
    if let Some(("verify-match", true)) = results.last()
        && code == Some(0)
        && done_count == 1
    {
        return VerifyOutcome::Match;
    }
    if NO_FINGERS_MARKERS.iter().any(|m| text.contains(m)) {
        return VerifyOutcome::NoFingers;
    }
    if done_count > 1 {
        return VerifyOutcome::Unavailable;
    }
    match results.last() {
        Some(("verify-no-match", true)) => VerifyOutcome::Retry(Retry::NoMatch),
        Some(("verify-retry-scan", _)) => VerifyOutcome::Retry(Retry::RetryScan),
        Some(("verify-swipe-too-short", _)) => VerifyOutcome::Retry(Retry::SwipeTooShort),
        Some(("verify-finger-not-centered", _)) => VerifyOutcome::Retry(Retry::NotCentered),
        Some(("verify-remove-and-retry", _)) => VerifyOutcome::Retry(Retry::RemoveAndRetry),
        Some(("verify-unknown-error" | "verify-disconnected", _)) => VerifyOutcome::ReaderError,
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

pub fn says_no_fingers(stdout: &[u8]) -> bool {
    core::str::from_utf8(stdout).is_ok_and(|t| NO_FINGERS_MARKERS.iter().any(|m| t.contains(m)))
}

/// True when `fprintd-list <user>` succeeded and lists at least one finger (` - #0: right-index-finger`).
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

/// Fingerprints in a row that were not recognised, over all requests and processes, after which
/// the reader is paused. Three misses end one request (docs/approval.md); this counts across them.
pub const MAX_MISSES: u32 = 9;
/// How long the reader stays paused after the last miss, unless another method approves first.
pub const PAUSE_SECS: u64 = 15 * 60;
const MISS_FILE: &str = "fingerprint-misses";
const MISS_FILE_MAX: u64 = 64;

/// The miss counter in the state directory: `<count> <unix time of the last miss>`. It is not
/// locked: two processes missing at the same moment can lose one count. A damaged file counts as
/// paused until a verified approval by any method removes it.
#[derive(Debug, Clone)]
pub struct MissCounter {
    dir: PathBuf,
}

impl MissCounter {
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        MissCounter {
            dir: state_dir.into(),
        }
    }

    fn read(&self) -> (u32, u64) {
        let file = match std::fs::File::open(self.dir.join(MISS_FILE)) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (0, 0),
            Err(_) => return (MAX_MISSES, u64::MAX),
        };
        let mut text = String::new();
        let parsed = file
            .take(MISS_FILE_MAX)
            .read_to_string(&mut text)
            .ok()
            .and_then(|_| {
                let (n, t) = text.strip_suffix('\n')?.split_once(' ')?;
                Some((n.parse::<u32>().ok()?, t.parse::<u64>().ok()?))
            });
        parsed.unwrap_or((MAX_MISSES, u64::MAX))
    }

    /// True while the reader must not be offered.
    pub fn paused(&self, now: u64) -> bool {
        let (count, last) = self.read();
        count >= MAX_MISSES && now < last.saturating_add(PAUSE_SECS)
    }

    /// Best effort: a state directory that cannot be written leaves the reader unpaused.
    pub fn record_miss(&self, now: u64) {
        let (count, last) = self.read();
        let count = if count >= MAX_MISSES && now >= last.saturating_add(PAUSE_SECS) {
            0
        } else {
            count
        };
        let text = format!("{} {now}\n", count.saturating_add(1).min(MAX_MISSES));
        if ensure_private_dir(&self.dir).is_ok() {
            let _ = write_atomic(&self.dir, MISS_FILE, &text);
        }
    }

    pub fn clear(&self) {
        let _ = std::fs::remove_file(self.dir.join(MISS_FILE));
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
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
        let miss = VerifyOutcome::Retry(Retry::NoMatch);
        assert_eq!(classify_verify(Some(1), out), miss);
        assert_eq!(classify_verify(Some(0), out), miss);
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
        assert_eq!(classify_verify(Some(1), other), VerifyOutcome::ReaderError);
        let no_fingers = b"Using device /net/reactivated/Fprint/Device/0\nNo fingers enrolled for this device.\n";
        assert_eq!(
            classify_verify(Some(1), no_fingers),
            VerifyOutcome::NoFingers
        );
        let dbus = b"VerifyStart failed: GDBus.Error:net.reactivated.Fprint.Error.NoEnrolledPrints: No fingerprints enrolled\n";
        assert_eq!(classify_verify(Some(1), dbus), VerifyOutcome::NoFingers);
        let two_misses =
            b"Verify result: verify-no-match (done)\nVerify result: verify-no-match (done)\n";
        assert_eq!(
            classify_verify(Some(1), two_misses),
            VerifyOutcome::Unavailable
        );
    }

    #[test]
    fn scan_problems_are_retries() {
        for (line, want) in [
            ("verify-retry-scan", Retry::RetryScan),
            ("verify-swipe-too-short", Retry::SwipeTooShort),
            ("verify-finger-not-centered", Retry::NotCentered),
            ("verify-remove-and-retry", Retry::RemoveAndRetry),
        ] {
            for done in ["done", "not done"] {
                let out = format!("Verify started!\nVerify result: {line} ({done})\n");
                assert_eq!(
                    classify_verify(Some(1), out.as_bytes()),
                    VerifyOutcome::Retry(want)
                );
            }
            assert!(want.message().ends_with('.'));
        }
        let err = b"Verify result: verify-unknown-error (done)\n";
        assert_eq!(classify_verify(Some(1), err), VerifyOutcome::ReaderError);
        assert_eq!(Retry::NoMatch.message(), "Not recognised.");
    }

    #[test]
    fn no_fingers_in_list_output() {
        assert!(says_no_fingers(
            b"User alice has no fingers enrolled for Acme Reader.\n"
        ));
        assert!(!says_no_fingers(b" - #0: right-index-finger\n"));
        assert!(!says_no_fingers(b"\xff"));
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

    #[test]
    fn misses_pause_the_reader_until_the_pause_ends_or_another_method_approves() {
        let d = crate::pin::tests::TempDir::new("misses");
        let m = MissCounter::new(d.0.join("state"));
        assert!(!m.paused(1_000));
        for i in 0..MAX_MISSES - 1 {
            m.record_miss(1_000 + u64::from(i));
            assert!(!m.paused(1_010), "after {} misses", i + 1);
        }
        m.record_miss(1_010);
        assert!(m.paused(1_010));
        assert!(m.paused(1_010 + PAUSE_SECS - 1));
        assert!(!m.paused(1_010 + PAUSE_SECS));
        m.record_miss(1_010 + PAUSE_SECS);
        assert!(!m.paused(1_010 + PAUSE_SECS));
        m.clear();
        for _ in 0..MAX_MISSES {
            m.record_miss(5_000);
        }
        assert!(m.paused(5_001));
        m.clear();
        assert!(!m.paused(5_001));
    }

    #[test]
    fn a_damaged_counter_pauses_the_reader() {
        let d = crate::pin::tests::TempDir::new("misses-bad");
        let state = d.0.join("state");
        assert!(std::fs::create_dir_all(&state).is_ok());
        for bad in [
            "",
            "x\n",
            "3\n",
            "3 4",
            "3 4 5\n",
            "-1 5\n",
            "99999999999 5\n",
        ] {
            assert!(std::fs::write(state.join(MISS_FILE), bad).is_ok());
            let m = MissCounter::new(&state);
            assert!(m.paused(10), "{bad:?}");
            m.clear();
            assert!(!m.paused(10));
        }
    }
}
