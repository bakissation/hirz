//! The hello every client sends first: a device request or a probe (docs/uhid.md, "How the broker
//! works"). Reading it is bounded in time, in the number of connections that may be waiting for
//! one, and per uid, so a client that connects and sends nothing cannot hold the broker up.

use std::collections::HashMap;
use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use hirz_sys::broker::{HELLO_DEVICE, HELLO_LEN, HELLO_PROBE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hello {
    Device,
    Probe,
}

pub fn parse(bytes: &[u8; HELLO_LEN]) -> Option<Hello> {
    if *bytes == HELLO_DEVICE {
        Some(Hello::Device)
    } else if *bytes == HELLO_PROBE {
        Some(Hello::Probe)
    } else {
        None
    }
}

/// Exactly [`HELLO_LEN`] bytes within `limit` in total, however they are split. `None` for
/// anything else: other bytes, end of input, an error or the time running out.
pub fn read(client: &mut UnixStream, limit: Duration) -> Option<Hello> {
    let deadline = Instant::now().checked_add(limit)?;
    let mut buf = [0u8; HELLO_LEN];
    let mut got = 0usize;
    while got < HELLO_LEN {
        let left = deadline.checked_duration_since(Instant::now())?;
        if left.is_zero() {
            return None;
        }
        client.set_read_timeout(Some(left)).ok()?;
        let dst = buf.get_mut(got..)?;
        match client.read(dst) {
            Ok(0) => return None,
            Ok(n) => got = got.saturating_add(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    client.set_read_timeout(None).ok()?;
    parse(&buf)
}

#[derive(Debug, Default)]
struct Waiting {
    total: usize,
    per_uid: HashMap<u32, usize>,
}

/// Connections whose hello has not been read yet.
#[derive(Debug)]
pub struct Handshakes {
    waiting: Mutex<Waiting>,
    max_total: usize,
    max_per_uid: usize,
}

#[derive(Debug)]
pub struct Pending {
    owner: Arc<Handshakes>,
    uid: u32,
}

impl Handshakes {
    pub fn new(max_total: usize, max_per_uid: usize) -> Arc<Handshakes> {
        Arc::new(Handshakes {
            waiting: Mutex::new(Waiting::default()),
            max_total,
            max_per_uid,
        })
    }

    fn lock(&self) -> MutexGuard<'_, Waiting> {
        self.waiting.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `None` when too many connections, or too many of this uid, wait for their hello.
    pub fn try_start(self: &Arc<Self>, uid: u32) -> Option<Pending> {
        let mut w = self.lock();
        let mine = w.per_uid.get(&uid).copied().unwrap_or(0);
        if w.total >= self.max_total || mine >= self.max_per_uid {
            return None;
        }
        w.total = w.total.saturating_add(1);
        w.per_uid.insert(uid, mine.saturating_add(1));
        Some(Pending {
            owner: Arc::clone(self),
            uid,
        })
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        let mut w = self.owner.lock();
        w.total = w.total.saturating_sub(1);
        if let Some(n) = w.per_uid.get_mut(&self.uid) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                w.per_uid.remove(&self.uid);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn only_the_two_hellos_are_known() {
        assert_eq!(parse(&HELLO_DEVICE), Some(Hello::Device));
        assert_eq!(parse(&HELLO_PROBE), Some(Hello::Probe));
        assert_eq!(parse(b"hirzdev2"), None);
        assert_eq!(parse(&[0u8; HELLO_LEN]), None);
        assert_eq!(parse(&hirz_sys::broker::ALIVE), None);
    }

    #[test]
    fn a_hello_is_read_whole_and_in_time() {
        let limit = Duration::from_millis(300);
        let (mut a, mut b) = UnixStream::pair().unwrap();
        b.write_all(&HELLO_PROBE).unwrap();
        assert_eq!(read(&mut a, limit), Some(Hello::Probe));

        let (mut a, mut b) = UnixStream::pair().unwrap();
        b.write_all(&HELLO_DEVICE[..3]).unwrap();
        b.write_all(&HELLO_DEVICE[3..]).unwrap();
        assert_eq!(read(&mut a, limit), Some(Hello::Device));

        let (mut a, mut b) = UnixStream::pair().unwrap();
        b.write_all(&[0u8; 64]).unwrap();
        assert_eq!(read(&mut a, limit), None, "a report is not a hello");

        let (mut a, mut b) = UnixStream::pair().unwrap();
        b.write_all(&HELLO_DEVICE[..4]).unwrap();
        drop(b);
        assert_eq!(read(&mut a, limit), None, "end of input");

        let (mut a, b) = UnixStream::pair().unwrap();
        let started = Instant::now();
        assert_eq!(read(&mut a, limit), None, "silence");
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(b);

        let (mut a, mut b) = UnixStream::pair().unwrap();
        let dribble = std::thread::spawn(move || {
            for byte in HELLO_DEVICE {
                if b.write_all(&[byte]).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let started = Instant::now();
        assert_eq!(
            read(&mut a, limit),
            None,
            "the limit covers the whole hello"
        );
        assert!(started.elapsed() < Duration::from_millis(700));
        drop(a);
        dribble.join().unwrap();
    }

    #[test]
    fn waiting_connections_are_capped_in_total_and_per_uid() {
        let h = Handshakes::new(3, 2);
        let a1 = h.try_start(1000).unwrap();
        let a2 = h.try_start(1000).unwrap();
        assert!(h.try_start(1000).is_none(), "per uid");
        let b1 = h.try_start(1001).unwrap();
        assert!(h.try_start(1002).is_none(), "in total");
        drop(a1);
        let a3 = h.try_start(1000).unwrap();
        drop((a2, a3, b1));
        assert_eq!(h.lock().total, 0);
        assert!(h.lock().per_uid.is_empty());
    }
}
