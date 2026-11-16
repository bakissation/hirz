//! Typing a secret at a terminal: echo off while it is typed and back on every way out, including
//! the signals that end the process, and a read that keeps no copy of what it reads.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::sync::atomic::{AtomicI32, Ordering};

const NO_FD: RawFd = -1;
/// The terminal whose echo the signal handler turns back on, or `NO_FD` while echo is not ours.
static ACTIVE: AtomicI32 = AtomicI32::new(NO_FD);
/// Signals that end the process and would leave the terminal without echo.
const SIGNALS: [libc::c_int; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

fn termios_of(fd: RawFd) -> io::Result<libc::termios> {
    // SAFETY: termios is plain data and all zeros is a valid value; tcgetattr overwrites it.
    let mut t: libc::termios = unsafe { core::mem::zeroed() };
    // SAFETY: `t` is a valid termios that outlives the call.
    if unsafe { libc::tcgetattr(fd, &mut t) } == 0 {
        Ok(t)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn apply(fd: RawFd, t: &libc::termios, when: libc::c_int) -> io::Result<()> {
    // SAFETY: `t` is a valid termios that outlives the call; the kernel only reads it.
    if unsafe { libc::tcsetattr(fd, when, t) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Only async-signal-safe calls: this runs in a signal handler.
fn echo_back_on(fd: RawFd) {
    // SAFETY: as in `termios_of`; both calls are async-signal-safe and touch only `t`.
    unsafe {
        let mut t: libc::termios = core::mem::zeroed();
        if libc::tcgetattr(fd, &mut t) == 0 {
            t.c_lflag |= libc::ECHO;
            libc::tcsetattr(fd, libc::TCSANOW, &t);
        }
    }
}

extern "C" fn on_signal(sig: libc::c_int) {
    let fd = ACTIVE.load(Ordering::SeqCst);
    if fd != NO_FD {
        echo_back_on(fd);
        // SAFETY: write(2) is async-signal-safe and the buffer is a static byte.
        let _ = unsafe { libc::write(libc::STDERR_FILENO, b"\n".as_ptr().cast(), 1) };
    }
    // SA_RESETHAND put the default action back before this ran, so the signal ends the process
    // the way it would have without the handler (the shell sees "killed by SIGINT").
    // SAFETY: raise(3) is async-signal-safe.
    unsafe { libc::raise(sig) };
}

type Saved = [Option<libc::sigaction>; SIGNALS.len()];

fn install_handlers() -> Saved {
    let mut saved: Saved = [None; SIGNALS.len()];
    for (slot, sig) in saved.iter_mut().zip(SIGNALS) {
        // SAFETY: sigaction is plain data and all zeros is a valid value.
        let mut old: libc::sigaction = unsafe { core::mem::zeroed() };
        // SAFETY: a null new action only reads the current one into `old`.
        if unsafe { libc::sigaction(sig, core::ptr::null(), &mut old) } != 0
            || old.sa_sigaction == libc::SIG_IGN
        {
            // A signal the parent ignores on purpose (nohup) stays ignored.
            continue;
        }
        // SAFETY: as above.
        let mut new: libc::sigaction = unsafe { core::mem::zeroed() };
        new.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        new.sa_flags = libc::SA_RESETHAND;
        // SAFETY: `new` is valid, `sa_mask` is the empty set from zeroing, and the handler only
        // calls async-signal-safe functions.
        unsafe { libc::sigemptyset(&mut new.sa_mask) };
        // SAFETY: as above.
        if unsafe { libc::sigaction(sig, &new, core::ptr::null_mut()) } == 0 {
            *slot = Some(old);
        }
    }
    saved
}

fn restore_handlers(saved: &Saved) {
    for (old, sig) in saved.iter().zip(SIGNALS) {
        if let Some(old) = old {
            // SAFETY: `old` is the action the system gave us for this signal.
            unsafe { libc::sigaction(sig, old, core::ptr::null_mut()) };
        }
    }
}

/// Echo is off on a terminal while this lives. It is back on when this is dropped and when
/// SIGINT, SIGTERM, SIGHUP or SIGQUIT end the process, so a Ctrl-C at a hidden prompt does not
/// leave the shell without echo. One at a time per process.
pub struct EchoOff {
    fd: RawFd,
    saved: libc::termios,
    handlers: Saved,
    ours: bool,
}

impl core::fmt::Debug for EchoOff {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EchoOff")
            .field("turned_off", &self.ours)
            .finish_non_exhaustive()
    }
}

impl EchoOff {
    /// Fails (`ENOTTY`) when `fd` is not a terminal. The caller keeps `fd` open while this lives.
    pub fn start(fd: BorrowedFd<'_>) -> io::Result<EchoOff> {
        let fd = fd.as_raw_fd();
        let saved = termios_of(fd)?;
        if saved.c_lflag & libc::ECHO == 0 {
            return Ok(EchoOff {
                fd,
                saved,
                handlers: [None; SIGNALS.len()],
                ours: false,
            });
        }
        ACTIVE
            .compare_exchange(NO_FD, fd, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "echo is already off"))?;
        let handlers = install_handlers();
        let mut quiet = saved;
        quiet.c_lflag &= !libc::ECHO;
        if let Err(e) = apply(fd, &quiet, libc::TCSAFLUSH) {
            restore_handlers(&handlers);
            ACTIVE.store(NO_FD, Ordering::SeqCst);
            return Err(e);
        }
        Ok(EchoOff {
            fd,
            saved,
            handlers,
            ours: true,
        })
    }

    /// Whether this call turned echo off (it was on before).
    pub fn turned_off(&self) -> bool {
        self.ours
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        if !self.ours {
            return;
        }
        let _ = apply(self.fd, &self.saved, libc::TCSADRAIN);
        restore_handlers(&self.handlers);
        ACTIVE.store(NO_FD, Ordering::SeqCst);
    }
}

/// One `read(2)` from `fd`, retried after a signal. Nothing is buffered here or in the standard
/// library, so a secret read this way is only in the caller's buffer.
pub fn read_fd(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        // SAFETY: `buf` is valid for `buf.len()` bytes and the descriptor stays open for the call.
        let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if let Ok(n) = usize::try_from(n) {
            return Ok(n);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// [`read_fd`] on standard input.
pub fn read_stdin(buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: descriptor 0 is open for as long as the process runs, or the read fails with EBADF.
    let stdin = unsafe { BorrowedFd::borrow_raw(libc::STDIN_FILENO) };
    read_fd(stdin, buf)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::os::fd::{AsFd, FromRawFd, OwnedFd};
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};

    const CHILD_ENV: &str = "HIRZ_SYS_TERMINAL_CHILD";

    /// A pseudo terminal: the master end (kept open) and the slave end a program would use.
    fn pty() -> Option<(OwnedFd, File)> {
        // SAFETY: plain libc calls; the master descriptor is owned by the returned OwnedFd.
        unsafe {
            let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            if master < 0 {
                return None;
            }
            let master = OwnedFd::from_raw_fd(master);
            if libc::grantpt(master.as_raw_fd()) != 0 || libc::unlockpt(master.as_raw_fd()) != 0 {
                return None;
            }
            let mut name = [0 as libc::c_char; 128];
            if libc::ptsname_r(master.as_raw_fd(), name.as_mut_ptr(), name.len()) != 0 {
                return None;
            }
            let path = std::ffi::CStr::from_ptr(name.as_ptr())
                .to_str()
                .ok()?
                .to_owned();
            let slave = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOCTTY)
                .open(path)
                .ok()?;
            Some((master, slave))
        }
    }

    use std::os::unix::fs::OpenOptionsExt;

    fn echo_on(slave: &File) -> bool {
        termios_of(slave.as_raw_fd()).unwrap().c_lflag & libc::ECHO != 0
    }

    #[test]
    fn echo_is_off_while_the_guard_lives_and_back_after() {
        let Some((_master, slave)) = pty() else {
            eprintln!("skipped: no pseudo terminal here");
            return;
        };
        assert!(echo_on(&slave));
        let guard = EchoOff::start(slave.as_fd()).unwrap();
        assert!(guard.turned_off());
        assert!(!echo_on(&slave));
        let second = EchoOff::start(slave.as_fd()).unwrap();
        assert!(!second.turned_off(), "echo is only ours once");
        drop(second);
        assert!(
            !echo_on(&slave),
            "a guard that changed nothing restores nothing"
        );
        drop(guard);
        assert!(echo_on(&slave));
    }

    #[test]
    fn a_terminal_that_already_hides_typing_is_left_alone() {
        let Some((_master, slave)) = pty() else {
            eprintln!("skipped: no pseudo terminal here");
            return;
        };
        let mut t = termios_of(slave.as_raw_fd()).unwrap();
        t.c_lflag &= !libc::ECHO;
        apply(slave.as_raw_fd(), &t, libc::TCSANOW).unwrap();
        let guard = EchoOff::start(slave.as_fd()).unwrap();
        assert!(!guard.turned_off());
        drop(guard);
        assert!(
            !echo_on(&slave),
            "not turned on by someone who did not turn it off"
        );
    }

    #[test]
    fn a_pipe_is_not_a_terminal() {
        let (reader, _writer) = std::io::pipe().unwrap();
        let err = EchoOff::start(reader.as_fd()).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENOTTY));
    }

    /// Runs only in the child process of `ctrl_c_at_a_hidden_prompt_puts_echo_back`.
    #[test]
    #[ignore = "helper process of ctrl_c_at_a_hidden_prompt_puts_echo_back"]
    fn child_hides_typing_then_gets_sigint() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        // SAFETY: descriptor 0 is the terminal the parent gave this process.
        let stdin = unsafe { BorrowedFd::borrow_raw(libc::STDIN_FILENO) };
        let guard = EchoOff::start(stdin).expect("echo off");
        assert!(guard.turned_off());
        // SAFETY: raising a signal in this process.
        unsafe { libc::raise(libc::SIGINT) };
        std::thread::sleep(std::time::Duration::from_secs(30));
        drop(guard);
    }

    #[test]
    fn ctrl_c_at_a_hidden_prompt_puts_echo_back() {
        let Some((_master, slave)) = pty() else {
            eprintln!("skipped: no pseudo terminal here");
            return;
        };
        let child_stdin = slave.try_clone().unwrap();
        let exe = std::env::current_exe().unwrap();
        let mut child = Command::new(exe)
            .args([
                "--exact",
                "terminal::tests::child_hides_typing_then_gets_sigint",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, "1")
            .stdin(Stdio::from(OwnedFd::from(child_stdin)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let status = child.wait().unwrap();
        assert_eq!(
            status.signal(),
            Some(libc::SIGINT),
            "the signal still ends the process: {status:?}"
        );
        assert!(echo_on(&slave), "echo was left off after Ctrl-C");
    }

    #[test]
    fn a_read_takes_what_is_there_and_no_more() {
        let (reader, mut writer) = std::io::pipe().unwrap();
        writer.write_all(b"ab\ncd\n").unwrap();
        let mut one = [0u8; 1];
        let mut line = Vec::new();
        loop {
            assert_eq!(read_fd(reader.as_fd(), &mut one).unwrap(), 1);
            line.push(one[0]);
            if one[0] == b'\n' {
                break;
            }
        }
        assert_eq!(line, b"ab\n");
        let mut rest = [0u8; 16];
        let n = read_fd(reader.as_fd(), &mut rest).unwrap();
        assert_eq!(&rest[..n], b"cd\n", "nothing past the first line was taken");
        drop(writer);
        assert_eq!(read_fd(reader.as_fd(), &mut rest).unwrap(), 0);
    }
}
