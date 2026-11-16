//! Process hardening: no core dumps, no ptrace attach by the same user, no privilege gain.

use std::io;

// prctl is variadic and the kernel reads every argument as unsigned long.
pub(crate) const ZERO: libc::c_ulong = 0;
pub(crate) const ONE: libc::c_ulong = 1;

fn check(ret: libc::c_int) -> io::Result<()> {
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// `prctl(PR_SET_DUMPABLE, 0)`: no core dumps and no ptrace attach by non-root processes of
/// the same user. It also makes `/proc/self` owned by root.
pub fn set_non_dumpable() -> io::Result<()> {
    // SAFETY: PR_SET_DUMPABLE takes an integer argument and touches no memory of ours.
    let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, ZERO, ZERO, ZERO, ZERO) };
    check(ret)
}

/// `prctl(PR_SET_NO_NEW_PRIVS, 1)`: execve can never grant privileges (setuid bits, file caps).
pub fn set_no_new_privs() -> io::Result<()> {
    // SAFETY: PR_SET_NO_NEW_PRIVS takes integer arguments only; the unused ones must be 0.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, ONE, ZERO, ZERO, ZERO) };
    check(ret)
}

/// `setrlimit(RLIMIT_CORE, 0, 0)`.
pub fn disable_core_dumps() -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, initialized rlimit that outlives the call; the kernel only
    // reads it.
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
    check(ret)
}

/// `mlockall(MCL_CURRENT | MCL_FUTURE)`. Fails without CAP_IPC_LOCK when the memory exceeds
/// RLIMIT_MEMLOCK; with MCL_FUTURE later allocations (thread stacks) can then fail too, so
/// callers enable this only on purpose.
pub fn lock_memory() -> io::Result<()> {
    // SAFETY: mlockall takes flags only and does not access our memory through pointers.
    let ret = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    check(ret)
}

/// Applies [`set_non_dumpable`], [`set_no_new_privs`] and [`disable_core_dumps`], and
/// [`lock_memory`] when `mlock` is true. Stops at the first error.
pub fn harden_process(mlock: bool) -> io::Result<()> {
    disable_core_dumps()?;
    set_non_dumpable()?;
    set_no_new_privs()?;
    if mlock {
        lock_memory()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardening_succeeds_unprivileged() {
        // These calls only reduce privileges, so they work for any user. They affect the
        // test process, which is fine.
        assert!(harden_process(false).is_ok());
        // SAFETY: PR_GET_DUMPABLE and PR_GET_NO_NEW_PRIVS only return integers.
        let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, ZERO, ZERO, ZERO, ZERO) };
        // SAFETY: as above.
        let nnp = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, ZERO, ZERO, ZERO, ZERO) };
        assert_eq!(dumpable, 0);
        assert_eq!(nnp, 1);
    }
}
