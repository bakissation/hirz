//! poll(2) on a small set of file descriptors.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::time::Duration;

/// Result of polling one descriptor for input.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PollStatus {
    /// Data (or end of file) can be read without blocking.
    pub readable: bool,
    /// The peer hung up (POLLHUP or POLLRDHUP).
    pub hangup: bool,
    /// POLLERR or POLLNVAL.
    pub error: bool,
}

const MAX_FDS: usize = 8;

/// Waits until one of `fds` is readable or the timeout expires (`None` waits forever).
/// Returns one status per descriptor, in order; all-default statuses mean a timeout.
/// EINTR is reported as a timeout so callers re-check their deadlines.
pub fn poll_readable(
    fds: &[BorrowedFd<'_>],
    timeout: Option<Duration>,
) -> io::Result<Vec<PollStatus>> {
    if fds.len() > MAX_FDS {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "too many fds"));
    }
    let mut pollfds: Vec<libc::pollfd> = fds
        .iter()
        .map(|fd| libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN | libc::POLLRDHUP,
            revents: 0,
        })
        .collect();
    let timeout_ms: libc::c_int = match timeout {
        None => -1,
        Some(t) => libc::c_int::try_from(t.as_millis()).unwrap_or(libc::c_int::MAX),
    };
    let nfds = libc::nfds_t::try_from(pollfds.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many fds"))?;
    // SAFETY: `pollfds` is a valid, writable array of `nfds` pollfd structs that outlives the
    // call. The descriptors are borrowed from the caller and stay open during the call.
    let ret = unsafe { libc::poll(pollfds.as_mut_ptr(), nfds, timeout_ms) };
    if ret == -1 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            return Ok(vec![PollStatus::default(); fds.len()]);
        }
        return Err(err);
    }
    Ok(pollfds
        .iter()
        .map(|p| PollStatus {
            readable: p.revents & libc::POLLIN != 0,
            hangup: p.revents & (libc::POLLHUP | libc::POLLRDHUP) != 0,
            error: p.revents & (libc::POLLERR | libc::POLLNVAL) != 0,
        })
        .collect())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn poll_reports_readable_and_hangup() {
        let (a, mut b) = UnixStream::pair().unwrap();
        let st = poll_readable(&[a.as_fd()], Some(Duration::from_millis(10))).unwrap();
        assert_eq!(st[0], PollStatus::default());
        b.write_all(b"x").unwrap();
        let st = poll_readable(&[a.as_fd()], Some(Duration::from_millis(10))).unwrap();
        assert!(st[0].readable);
        drop(b);
        let st = poll_readable(&[a.as_fd()], Some(Duration::from_millis(10))).unwrap();
        assert!(st[0].hangup);
    }
}
