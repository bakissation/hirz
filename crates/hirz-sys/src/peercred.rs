//! Socket queries: SO_PEERCRED and the type of an inherited socket.

use std::cell::Cell;
use std::io;
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::sync::{Mutex, MutexGuard};

/// Recorded by the kernel at `connect` time; the peer cannot forge them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

pub fn peer_credentials<S: AsFd>(socket: &S) -> io::Result<PeerCredentials> {
    let fd = socket.as_fd();
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = socklen_of::<libc::ucred>()?;
    // SAFETY: `cred` is a valid, writable ucred and `len` holds its exact size; the kernel
    // writes at most `len` bytes and updates `len`. The fd is borrowed for the call.
    let ret = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }
    if len != socklen_of::<libc::ucred>()? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short SO_PEERCRED result",
        ));
    }
    Ok(PeerCredentials {
        pid: cred.pid,
        uid: cred.uid,
        gid: cred.gid,
    })
}

/// The effective uid of this process.
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid cannot fail and takes no arguments.
    unsafe { libc::geteuid() }
}

/// Sets the umask of the whole process and returns the previous one.
pub fn set_umask(mask: u32) -> u32 {
    // SAFETY: umask cannot fail; it takes and returns a plain integer.
    unsafe { libc::umask(mask & 0o777) }
}

/// Runs `f` with the umask set to `mask` and restores the old one afterwards, so a caller can
/// create a file or directory with exactly the mode it asks for, without a `chmod` by path that
/// would follow a symbolic link swapped in meanwhile. The umask belongs to the whole process:
/// other threads that create files meanwhile see it too. Calls from different threads wait for
/// each other; a call made inside `f` is fine.
pub fn with_umask<T>(mask: u32, f: impl FnOnce() -> T) -> T {
    thread_local! {
        static INSIDE: Cell<bool> = const { Cell::new(false) };
    }
    struct Section {
        previous: u32,
        outermost: Option<MutexGuard<'static, ()>>,
    }
    impl Drop for Section {
        fn drop(&mut self) {
            set_umask(self.previous);
            if self.outermost.is_some() {
                INSIDE.set(false);
            }
        }
    }
    static SECTION: Mutex<()> = Mutex::new(());
    let outermost = if INSIDE.get() {
        None
    } else {
        let guard = SECTION.lock().unwrap_or_else(|e| e.into_inner());
        INSIDE.set(true);
        Some(guard)
    };
    let _section = Section {
        previous: set_umask(mask),
        outermost,
    };
    f()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketInfo {
    pub domain: i32,
    pub sock_type: i32,
    pub listening: bool,
}

impl SocketInfo {
    pub fn is_unix_stream_listener(&self) -> bool {
        self.domain == libc::AF_UNIX && self.sock_type == libc::SOCK_STREAM && self.listening
    }
}

/// Fails with ENOTSOCK for non-sockets.
pub fn socket_info(fd: BorrowedFd<'_>) -> io::Result<SocketInfo> {
    Ok(SocketInfo {
        domain: int_sockopt(fd, libc::SO_DOMAIN)?,
        sock_type: int_sockopt(fd, libc::SO_TYPE)?,
        listening: int_sockopt(fd, libc::SO_ACCEPTCONN)? != 0,
    })
}

fn int_sockopt(fd: BorrowedFd<'_>, opt: libc::c_int) -> io::Result<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut len = socklen_of::<libc::c_int>()?;
    // SAFETY: `value` is a writable c_int and `len` is its size; the kernel writes at most
    // `len` bytes. The fd is borrowed for the duration of the call.
    let ret = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            opt,
            (&mut value as *mut libc::c_int).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

fn socklen_of<T>() -> io::Result<libc::socklen_t> {
    libc::socklen_t::try_from(mem::size_of::<T>())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "type too large"))
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
    use std::os::unix::net::{UnixListener, UnixStream};

    #[test]
    fn peer_credentials_of_socketpair_are_ours() {
        let (a, _b) = UnixStream::pair().unwrap();
        let cred = peer_credentials(&a).unwrap();
        // SAFETY: getuid/getgid/getpid cannot fail and take no arguments.
        let (uid, gid, pid) = unsafe { (libc::getuid(), libc::getgid(), libc::getpid()) };
        assert_eq!(cred, PeerCredentials { pid, uid, gid });
    }

    #[test]
    fn effective_uid_matches_libc() {
        // SAFETY: geteuid cannot fail and takes no arguments.
        assert_eq!(effective_uid(), unsafe { libc::geteuid() });
    }

    #[test]
    fn with_umask_applies_the_mask_and_restores_the_old_one() {
        let inside = with_umask(0o111, || set_umask(0o111));
        assert_eq!(inside, 0o111);
        let nested = with_umask(0o077, || with_umask(0o022, || set_umask(0o022)));
        assert_eq!(nested, 0o022);
        let outer_kept = with_umask(0o077, || {
            with_umask(0o022, || ());
            set_umask(0o077)
        });
        assert_eq!(outer_kept, 0o077, "the inner call restored the outer mask");
        let current = set_umask(0o022);
        assert_eq!(set_umask(current), 0o022);
    }

    #[test]
    fn socket_info_detects_listener() {
        let dir = std::env::temp_dir().join(format!("hirz-sys-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("l.sock");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let info = socket_info(listener.as_fd()).unwrap();
        assert!(info.is_unix_stream_listener());
        let (a, _b) = UnixStream::pair().unwrap();
        let info = socket_info(a.as_fd()).unwrap();
        assert!(!info.is_unix_stream_listener());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn socket_info_rejects_files() {
        let file = std::fs::File::open("/proc/self/stat").unwrap();
        assert!(socket_info(file.as_fd()).is_err());
    }
}
