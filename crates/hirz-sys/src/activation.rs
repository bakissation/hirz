//! systemd socket activation (the `sd_listen_fds` protocol) without libsystemd. Descriptors
//! start at fd 3, `LISTEN_PID` must be our pid, `LISTEN_FDS` is the count.

use std::fmt;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};

const SD_LISTEN_FDS_START: RawFd = 3;
/// Upper bound on accepted descriptors; hirz units pass exactly one.
pub const MAX_LISTEN_FDS: usize = 16;

static TAKEN: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenEnvError {
    InvalidPid,
    InvalidCount,
    TooMany(usize),
}

impl fmt::Display for ListenEnvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPid => write!(f, "LISTEN_PID is not a number"),
            Self::InvalidCount => write!(f, "LISTEN_FDS is not a number"),
            Self::TooMany(n) => write!(f, "LISTEN_FDS={n} exceeds {MAX_LISTEN_FDS}"),
        }
    }
}

impl std::error::Error for ListenEnvError {}

/// 0 when the variables are absent or meant for another process.
pub fn parse_listen_env(
    listen_pid: Option<&str>,
    listen_fds: Option<&str>,
    own_pid: u32,
) -> Result<usize, ListenEnvError> {
    let Some(pid) = listen_pid else {
        return Ok(0);
    };
    let pid: u32 = pid.trim().parse().map_err(|_| ListenEnvError::InvalidPid)?;
    if pid != own_pid {
        return Ok(0);
    }
    let Some(count) = listen_fds else {
        return Ok(0);
    };
    let count: usize = count
        .trim()
        .parse()
        .map_err(|_| ListenEnvError::InvalidCount)?;
    if count > MAX_LISTEN_FDS {
        return Err(ListenEnvError::TooMany(count));
    }
    Ok(count)
}

/// Takes ownership and sets close-on-exec. Only the first call returns descriptors, so none
/// is ever owned twice.
pub fn listen_fds() -> io::Result<Vec<OwnedFd>> {
    let pid_var = std::env::var("LISTEN_PID").ok();
    let fds_var = std::env::var("LISTEN_FDS").ok();
    let count = parse_listen_env(pid_var.as_deref(), fds_var.as_deref(), std::process::id())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    if count == 0 || TAKEN.swap(true, Ordering::SeqCst) {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(count);
    let mut fd = SD_LISTEN_FDS_START;
    for _ in 0..count {
        // SAFETY: F_GETFD only reads the descriptor flags; an invalid fd yields EBADF.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: F_SETFD only changes the close-on-exec flag of a valid descriptor.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: systemd passed this open descriptor to this pid and the TAKEN flag makes this loop
        // run at most once per process, so the OwnedFd is the unique owner.
        out.push(unsafe { OwnedFd::from_raw_fd(fd) });
        fd = fd.saturating_add(1);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_or_foreign_env_means_zero() {
        assert_eq!(parse_listen_env(None, None, 10), Ok(0));
        assert_eq!(parse_listen_env(Some("11"), Some("1"), 10), Ok(0));
        assert_eq!(parse_listen_env(Some("10"), None, 10), Ok(0));
    }

    #[test]
    fn matching_env_returns_count() {
        assert_eq!(parse_listen_env(Some("10"), Some("1"), 10), Ok(1));
        assert_eq!(parse_listen_env(Some(" 10\n"), Some("2"), 10), Ok(2));
    }

    #[test]
    fn malformed_env_is_rejected() {
        assert_eq!(
            parse_listen_env(Some("x"), Some("1"), 10),
            Err(ListenEnvError::InvalidPid)
        );
        assert_eq!(
            parse_listen_env(Some("10"), Some("-1"), 10),
            Err(ListenEnvError::InvalidCount)
        );
        assert_eq!(
            parse_listen_env(Some("10"), Some("17"), 10),
            Err(ListenEnvError::TooMany(17))
        );
    }
}
