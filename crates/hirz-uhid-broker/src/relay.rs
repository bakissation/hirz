//! Relays 64-byte reports between one client connection and one uhid device. The client sees only
//! report bytes: the descriptor is never sent, and the socket is read with plain `read`, so
//! SCM_RIGHTS descriptors a client attaches are discarded by the kernel.

use std::io::{self, Read, Write};
use std::os::fd::AsFd;

use hirz_sys::poll_readable;
use hirz_sys::uhid::{self, ReportType, UhidEvent};

use crate::device::{REPORT_SIZE, create_params, output_report};

/// errno returned for feature report requests, which the FIDO descriptor does not declare.
const EIO: u16 = 5;
const EINVAL: i32 = 22;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayEnd {
    ClientClosed,
    DeviceClosed,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub to_client: u64,
    pub to_device: u64,
    pub dropped: u64,
}

/// `uhid` is `/dev/uhid` in production and a socket in tests.
pub fn run_device<U, C>(
    uhid: &mut U,
    client: &mut C,
    phys: &str,
    stats: &mut Stats,
) -> io::Result<RelayEnd>
where
    U: Read + Write + AsFd,
    C: Read + Write + AsFd,
{
    let create = uhid::encode_create2(&create_params(phys))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    uhid.write_all(&create)?;
    let result = relay(uhid, client, stats);
    // Closing the descriptor destroys the device too; the explicit event makes the order
    // deterministic.
    let destroyed = uhid.write_all(&uhid::encode_destroy());
    let end = result?;
    if end == RelayEnd::ClientClosed {
        destroyed?;
    }
    Ok(end)
}

fn relay<U, C>(uhid: &mut U, client: &mut C, stats: &mut Stats) -> io::Result<RelayEnd>
where
    U: Read + Write + AsFd,
    C: Read + Write + AsFd,
{
    let mut event = vec![0u8; uhid::UHID_EVENT_SIZE];
    let mut pending = [0u8; REPORT_SIZE];
    let mut filled = 0usize;
    loop {
        let status = poll_readable(&[uhid.as_fd(), client.as_fd()], None)?;
        let (Some(dev), Some(cli)) = (status.first(), status.get(1)) else {
            return Err(io::Error::other("poll returned too few entries"));
        };

        if dev.readable {
            // /dev/uhid returns exactly one struct uhid_event per read.
            match uhid.read_exact(&mut event) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    return Ok(RelayEnd::DeviceClosed);
                }
                Err(e) => return Err(e),
            }
            handle_device_event(uhid, client, &event, stats)?;
        } else if dev.hangup || dev.error {
            return Ok(RelayEnd::DeviceClosed);
        }

        if cli.readable || cli.hangup {
            let Some(dst) = pending.get_mut(filled..) else {
                return Err(io::Error::other("report buffer overflow"));
            };
            let n = match client.read(dst) {
                Ok(0) => return Ok(RelayEnd::ClientClosed),
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => 0,
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {
                    return Ok(RelayEnd::ClientClosed);
                }
                Err(e) => return Err(e),
            };
            filled = filled.saturating_add(n);
            if filled == REPORT_SIZE {
                filled = 0;
                let input = uhid::encode_input2(&pending)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                match uhid.write_all(&input) {
                    Ok(()) => stats.to_device = stats.to_device.saturating_add(1),
                    // EINVAL: the kernel has not finished starting the device yet. The
                    // report is lost, as it would be on a real bus; CTAPHID retries.
                    Err(e) if e.raw_os_error() == Some(EINVAL) => {
                        stats.dropped = stats.dropped.saturating_add(1);
                    }
                    Err(e) => return Err(e),
                }
            }
        } else if cli.error {
            return Ok(RelayEnd::ClientClosed);
        }
    }
}

fn handle_device_event<U: Write, C: Write>(
    uhid: &mut U,
    client: &mut C,
    event: &[u8],
    stats: &mut Stats,
) -> io::Result<()> {
    let decoded = match uhid::decode_event(event) {
        Ok(ev) => ev,
        Err(_) => {
            stats.dropped = stats.dropped.saturating_add(1);
            return Ok(());
        }
    };
    match decoded {
        UhidEvent::Output {
            data,
            rtype: ReportType::Output,
        } => match output_report(&data) {
            Some(report) => {
                client.write_all(&report)?;
                stats.to_client = stats.to_client.saturating_add(1);
            }
            None => stats.dropped = stats.dropped.saturating_add(1),
        },
        UhidEvent::GetReport { id, .. } => {
            let reply = uhid::encode_get_report_reply(id, EIO, &[])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            uhid.write_all(&reply)?;
        }
        UhidEvent::SetReport { id, .. } => {
            uhid.write_all(&uhid::encode_set_report_reply(id, EIO))?;
        }
        UhidEvent::Output { .. } => stats.dropped = stats.dropped.saturating_add(1),
        UhidEvent::Start { .. }
        | UhidEvent::Stop
        | UhidEvent::Open
        | UhidEvent::Close
        | UhidEvent::Other(_) => {}
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use crate::device::{FIDO_REPORT_DESCRIPTOR, PRODUCT_ID, VENDOR_ID};
    use hirz_sys::uhid::{UHID_EVENT_SIZE, event_type};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    fn read_event(s: &mut UnixStream) -> Vec<u8> {
        let mut ev = vec![0u8; UHID_EVENT_SIZE];
        s.read_exact(&mut ev).unwrap();
        ev
    }

    fn ne32(b: &[u8], off: usize) -> u32 {
        u32::from_ne_bytes(b[off..off + 4].try_into().unwrap())
    }

    fn kernel_event(kind: u32) -> Vec<u8> {
        let mut ev = vec![0u8; UHID_EVENT_SIZE];
        ev[..4].copy_from_slice(&kind.to_ne_bytes());
        ev
    }

    fn kernel_output(data: &[u8]) -> Vec<u8> {
        let mut ev = kernel_event(event_type::OUTPUT);
        ev[4..4 + data.len()].copy_from_slice(data);
        ev[4100..4102].copy_from_slice(&(data.len() as u16).to_ne_bytes());
        ev[4102] = 1;
        ev
    }

    #[test]
    fn relays_reports_and_destroys_device() {
        // `kernel` stands in for /dev/uhid, `host` for the hirzd side of the connection.
        let (mut uhid_end, mut kernel) = UnixStream::pair().unwrap();
        let (mut client_end, mut daemon) = UnixStream::pair().unwrap();
        kernel
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        daemon
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let relay = std::thread::spawn(move || {
            let mut stats = Stats::default();
            let end = run_device(&mut uhid_end, &mut client_end, "1000", &mut stats);
            (end.unwrap(), stats)
        });

        let create = read_event(&mut kernel);
        assert_eq!(ne32(&create, 0), event_type::CREATE2);
        assert_eq!(&create[4..30], b"hirz virtual authenticator");
        assert_eq!(&create[132..137], b"1000\0");
        assert_eq!(ne32(&create, 264), VENDOR_ID);
        assert_eq!(ne32(&create, 268), PRODUCT_ID);
        assert_eq!(&create[280..314], &FIDO_REPORT_DESCRIPTOR);

        kernel.write_all(&kernel_event(event_type::START)).unwrap();
        kernel.write_all(&kernel_event(event_type::OPEN)).unwrap();

        // Host to device: 65 bytes with report number 0 become 64 bytes for the daemon.
        let mut out = vec![0u8; 65];
        for (i, b) in out.iter_mut().enumerate().skip(1) {
            *b = i as u8;
        }
        kernel.write_all(&kernel_output(&out)).unwrap();
        let mut report = [0u8; 64];
        daemon.read_exact(&mut report).unwrap();
        assert_eq!(&report[..], &out[1..]);

        kernel.write_all(&kernel_output(&[0u8; 10])).unwrap();
        kernel.write_all(&kernel_output(&[0x42u8; 64])).unwrap();
        daemon.read_exact(&mut report).unwrap();
        assert_eq!(report, [0x42u8; 64]);

        let input = [0x5au8; 64];
        daemon.write_all(&input[..20]).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        daemon.write_all(&input[20..]).unwrap();
        let ev = read_event(&mut kernel);
        assert_eq!(ne32(&ev, 0), event_type::INPUT2);
        assert_eq!(u16::from_ne_bytes([ev[4], ev[5]]), 64);
        assert_eq!(&ev[6..70], &input[..]);

        let mut get = kernel_event(event_type::GET_REPORT);
        get[4..8].copy_from_slice(&77u32.to_ne_bytes());
        kernel.write_all(&get).unwrap();
        let reply = read_event(&mut kernel);
        assert_eq!(ne32(&reply, 0), event_type::GET_REPORT_REPLY);
        assert_eq!(ne32(&reply, 4), 77);
        assert_eq!(u16::from_ne_bytes([reply[8], reply[9]]), 5);
        let mut set = kernel_event(event_type::SET_REPORT);
        set[4..8].copy_from_slice(&78u32.to_ne_bytes());
        kernel.write_all(&set).unwrap();
        let reply = read_event(&mut kernel);
        assert_eq!(ne32(&reply, 0), event_type::SET_REPORT_REPLY);
        assert_eq!(ne32(&reply, 4), 78);

        drop(daemon);
        let destroy = read_event(&mut kernel);
        assert_eq!(ne32(&destroy, 0), event_type::DESTROY);
        let (end, stats) = relay.join().unwrap();
        assert_eq!(end, RelayEnd::ClientClosed);
        assert_eq!(
            stats,
            Stats {
                to_client: 2,
                to_device: 1,
                dropped: 1
            }
        );
    }

    #[test]
    fn device_close_ends_relay() {
        let (mut uhid_end, mut kernel) = UnixStream::pair().unwrap();
        let (mut client_end, _daemon) = UnixStream::pair().unwrap();
        let relay = std::thread::spawn(move || {
            let mut stats = Stats::default();
            run_device(&mut uhid_end, &mut client_end, "1000", &mut stats)
        });
        let _ = read_event(&mut kernel);
        drop(kernel);
        assert_eq!(relay.join().unwrap().unwrap(), RelayEnd::DeviceClosed);
    }
}
