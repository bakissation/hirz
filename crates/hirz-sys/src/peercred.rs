//! Socket queries: SO_PEERCRED and the type of an inherited socket.

use std::io;
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};

/// Credentials of the process that connected a Unix socket, as recorded by the kernel at
/// `connect` time. They cannot be forged by the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

/// Reads SO_PEERCRED from a connected Unix stream socket.
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

/// Domain, type and listening state of a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketInfo {
    pub domain: i32,
    pub sock_type: i32,
    pub listening: bool,
}

impl SocketInfo {
    /// True for a listening AF_UNIX SOCK_STREAM socket.
    pub fn is_unix_stream_listener(&self) -> bool {
        self.domain == libc::AF_UNIX && self.sock_type == libc::SOCK_STREAM && self.listening
    }
}

/// Queries SO_DOMAIN, SO_TYPE and SO_ACCEPTCONN. Fails with ENOTSOCK for non-sockets.
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
