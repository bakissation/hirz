//! An exclusive advisory lock on a file, so that processes sharing a state file (hirzd, hirz-nmh
//! and the hirz CLI) can serialize their read-modify-write updates.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

/// Blocks until this process holds an exclusive `flock(2)` lock on `file`. The lock belongs to the
/// open file description and ends when the last descriptor for it is closed, also when the process
/// dies, so a crash leaves no stale lock. Two descriptors opened separately conflict with each
/// other, in one process as well as between processes.
pub fn lock_exclusive(file: &File) -> io::Result<()> {
    loop {
        // SAFETY: `file` keeps the descriptor open for the call and the operation is a constant.
        let r = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if r == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    #[test]
    fn a_second_descriptor_waits_until_the_first_is_closed() {
        let path = std::env::temp_dir().join(format!("hirz-sys-flock-{}", std::process::id()));
        let first = File::create(&path).expect("create");
        lock_exclusive(&first).expect("first lock");

        let got = Arc::new(AtomicBool::new(false));
        let waiter = {
            let (got, path) = (Arc::clone(&got), path.clone());
            std::thread::spawn(move || {
                let second = File::open(path).expect("open");
                lock_exclusive(&second).expect("second lock");
                got.store(true, Ordering::SeqCst);
            })
        };
        std::thread::sleep(Duration::from_millis(150));
        assert!(!got.load(Ordering::SeqCst), "the lock was not exclusive");
        drop(first);
        waiter.join().expect("waiter");
        assert!(got.load(Ordering::SeqCst));
        let _ = std::fs::remove_file(path);
    }
}
