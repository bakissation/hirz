//! Starting a program outside the caller's session.

use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;

/// Makes `cmd` call `setsid(2)` in the child before it runs the program, so the program leads a
/// session and process group of its own: no controlling terminal, and no signal sent to the
/// caller's group (a Ctrl-C, a terminal hang-up) reaches it.
pub fn new_session(cmd: &mut Command) -> &mut Command {
    // SAFETY: the closure runs in the forked child before exec and only calls setsid(2), which is
    // async-signal-safe, and reads errno through `last_os_error`; it touches no lock or allocator
    // state of the parent.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn field(stat: &str, n: usize) -> String {
        let after = stat.rsplit_once(')').expect("comm").1;
        after.split_whitespace().nth(n).expect("field").to_owned()
    }

    #[test]
    fn the_child_leads_its_own_session() {
        let Ok(sh) = std::fs::canonicalize("/bin/sh") else {
            return;
        };
        let out = new_session(Command::new(sh).args(["-c", "cat /proc/$$/stat"]))
            .output()
            .expect("run");
        let stat = String::from_utf8(out.stdout).expect("utf8");
        let pid = stat.split_whitespace().next().expect("pid").to_owned();
        assert_eq!(field(&stat, 2), pid, "process group");
        assert_eq!(field(&stat, 3), pid, "session");
        let own = std::fs::read_to_string("/proc/self/stat").expect("own stat");
        assert_ne!(field(&own, 3), pid);
    }
}
