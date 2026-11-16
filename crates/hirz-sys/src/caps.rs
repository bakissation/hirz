//! Dropping every Linux capability. Used by the root broker when it is started by hand
//! (`sudo`); under systemd the unit already empties the bounding set.

use std::io;

use crate::harden::{ONE, ZERO};

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
// Highest capability number the loop probes; PR_CAPBSET_READ reports EINVAL past the
// kernel's last capability, which ends the loop earlier.
const CAP_PROBE_MAX: libc::c_ulong = 63;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Clears the ambient set, drops every capability still present in the bounding set, then
/// sets the effective, permitted and inheritable sets to empty. Afterwards the process keeps
/// its uid (root stays the owner of root files) but holds no capability. Combine with
/// [`crate::set_no_new_privs`] so that no later execve can regain one.
pub fn drop_all_capabilities() -> io::Result<()> {
    // SAFETY: integer-only prctl; EINVAL on kernels without ambient capabilities is ignored.
    let ret = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            ZERO,
            ZERO,
            ZERO,
        )
    };
    if ret == -1 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINVAL) {
            return Err(err);
        }
    }

    let mut cap: libc::c_ulong = 0;
    while cap <= CAP_PROBE_MAX {
        // SAFETY: integer-only prctl query.
        let present = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, ZERO, ZERO, ZERO) };
        if present == -1 {
            break;
        }
        if present == 1 {
            // SAFETY: integer-only prctl.
            let ret = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, ZERO, ZERO, ZERO) };
            if ret == -1 {
                let err = io::Error::last_os_error();
                // Without CAP_SETPCAP the bounding set cannot shrink. That only happens for
                // an unprivileged process, whose empty permitted set (set below) together
                // with no_new_privs keeps the bounding set unusable anyway.
                if err.raw_os_error() == Some(libc::EPERM) {
                    break;
                }
                return Err(err);
            }
        }
        cap = cap.saturating_add(ONE);
    }

    let mut header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: capset(2) reads a cap_user_header_t and, for version 3, an array of two
    // cap_user_data_t. Both are #[repr(C)] with the kernel layout, initialized, and live
    // until the call returns. The kernel may write the preferred version into the header,
    // which is why it is passed as a mutable pointer.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &mut header as *mut CapHeader,
            data.as_ptr(),
        )
    };
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropping_capabilities_works_unprivileged() {
        // An unprivileged test process has an empty permitted set, so setting everything to
        // empty is allowed and the bounding set loop only reads.
        assert!(drop_all_capabilities().is_ok());
    }
}
