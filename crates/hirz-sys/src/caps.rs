//! Dropping every Linux capability. Used by the root broker when it is started by hand
//! (`sudo`); under systemd the unit already empties the bounding set.

use std::io;

use crate::harden::{ONE, ZERO};

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
// PR_CAPBSET_READ reports EINVAL past the kernel's last capability, which ends the loop early.
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

/// Afterwards the process keeps its uid but holds no capability. Combine with
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
                // Without CAP_SETPCAP the bounding set cannot shrink; that only happens unprivileged, where the
                // empty permitted set and no_new_privs make it unusable anyway.
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
    // SAFETY: capset(2) reads a version-3 header and two cap_user_data_t, both #[repr(C)],
    // initialized and live for the call; the kernel may write the header, hence the mutable pointer.
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
        assert!(drop_all_capabilities().is_ok());
    }
}
