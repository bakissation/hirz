//! System password through polkit: `pkcheck` against the hirz action with `auth_self`.

pub const ACTION_ID: &str = "dev.hirz.authenticate";
pub const POLICY_FILE_NAME: &str = "dev.hirz.authenticate.policy";
pub const POLICY_DIRS: &[&str] = &[
    "/usr/share/polkit-1/actions",
    "/usr/local/share/polkit-1/actions",
];

/// The three-part subject form avoids the pid reuse races documented in pkcheck(1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    /// Field 22 of `/proc/<pid>/stat`, in clock ticks since boot.
    pub start_time: u64,
    pub uid: u32,
}

/// Arguments for `pkcheck`. `--details` is not passed: polkit does not show untrusted
/// details to the user, and the site is already shown in hirz's own dialog. Without
/// `interactive` pkcheck never asks anyone, so it shows whether polkit would grant or refuse the
/// action on its own (exit 0 or 1) or needs a password (exit 2).
pub fn pkcheck_args(id: &ProcessIdentity, interactive: bool) -> Vec<String> {
    let mut args = vec![
        "--action-id".into(),
        ACTION_ID.into(),
        "--process".into(),
        format!("{},{},{}", id.pid, id.start_time, id.uid),
    ];
    if interactive {
        args.push("--allow-user-interaction".into());
    }
    args
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkcheckOutcome {
    Authorized,
    NotAuthorized,
    NoAgent,
    Dismissed,
    CheckError,
    BadArguments,
    Unknown,
}

pub fn classify_pkcheck(code: Option<i32>) -> PkcheckOutcome {
    match code {
        Some(0) => PkcheckOutcome::Authorized,
        Some(1) => PkcheckOutcome::NotAuthorized,
        Some(2) => PkcheckOutcome::NoAgent,
        Some(3) => PkcheckOutcome::Dismissed,
        Some(126) => PkcheckOutcome::BadArguments,
        Some(127) => PkcheckOutcome::CheckError,
        _ => PkcheckOutcome::Unknown,
    }
}

/// Start time from `/proc/<pid>/stat`. The command name (field 2) may contain spaces and
/// parentheses, so parsing starts after the last `)`.
pub fn parse_stat_start_time(stat: &[u8]) -> Option<u64> {
    let close = stat.iter().rposition(|&b| b == b')')?;
    let rest = core::str::from_utf8(stat.get(close.checked_add(1)?..)?).ok()?;
    // `rest` begins with field 3 (state); field 22 is therefore the 20th entry.
    rest.split_ascii_whitespace().nth(19)?.parse().ok()
}

pub fn parse_status_uid(status: &[u8]) -> Option<u32> {
    let text = core::str::from_utf8(status).ok()?;
    let line = text.lines().find(|l| l.starts_with("Uid:"))?;
    line.get(4..)?.split_ascii_whitespace().next()?.parse().ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes() {
        assert_eq!(classify_pkcheck(Some(0)), PkcheckOutcome::Authorized);
        assert_eq!(classify_pkcheck(Some(1)), PkcheckOutcome::NotAuthorized);
        assert_eq!(classify_pkcheck(Some(2)), PkcheckOutcome::NoAgent);
        assert_eq!(classify_pkcheck(Some(3)), PkcheckOutcome::Dismissed);
        assert_eq!(classify_pkcheck(Some(126)), PkcheckOutcome::BadArguments);
        assert_eq!(classify_pkcheck(Some(127)), PkcheckOutcome::CheckError);
        assert_eq!(classify_pkcheck(Some(4)), PkcheckOutcome::Unknown);
        assert_eq!(classify_pkcheck(Some(-1)), PkcheckOutcome::Unknown);
        assert_eq!(classify_pkcheck(None), PkcheckOutcome::Unknown);
    }

    #[test]
    fn args() {
        let id = ProcessIdentity {
            pid: 4242,
            start_time: 987654,
            uid: 1000,
        };
        assert_eq!(
            pkcheck_args(&id, true),
            [
                "--action-id",
                "dev.hirz.authenticate",
                "--process",
                "4242,987654,1000",
                "--allow-user-interaction"
            ]
        );
        assert_eq!(
            pkcheck_args(&id, false),
            [
                "--action-id",
                "dev.hirz.authenticate",
                "--process",
                "4242,987654,1000"
            ]
        );
    }

    #[test]
    fn stat_start_time() {
        let stat = b"4242 (hirzd) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 200 18446744073709551615";
        assert_eq!(parse_stat_start_time(stat), Some(987654));
        let tricky =
            b"4242 (a) b (c) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 55 1000 200";
        assert_eq!(parse_stat_start_time(tricky), Some(55));
        assert_eq!(parse_stat_start_time(b"4242 (x) S 1 2"), None);
        assert_eq!(parse_stat_start_time(b"no paren"), None);
        assert_eq!(parse_stat_start_time(b""), None);
        let bad = b"1 (x) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 notanumber 1";
        assert_eq!(parse_stat_start_time(bad), None);
    }

    #[test]
    fn status_uid() {
        let s = b"Name:\thirzd\nUmask:\t0022\nState:\tS (sleeping)\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(parse_status_uid(s), Some(1000));
        assert_eq!(parse_status_uid(b"Name:\tx\n"), None);
        assert_eq!(parse_status_uid(b"Uid:\tabc\n"), None);
    }

    #[test]
    fn real_proc_files() {
        let stat = std::fs::read("/proc/self/stat").unwrap();
        assert!(parse_stat_start_time(&stat).is_some());
        let status = std::fs::read("/proc/self/status").unwrap();
        assert!(parse_status_uid(&status).is_some());
    }
}
