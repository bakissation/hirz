//! The Linux uhid ABI (`include/uapi/linux/uhid.h`) as byte-level encode and decode.
//!
//! uhid needs no ioctls: user space writes one `struct uhid_event` per `write(2)` and reads
//! one per `read(2)` on `/dev/uhid`. All structs are packed and use host byte order. The
//! functions here are safe and pure; opening the device is plain `std::fs::File` I/O.
//!
//! Encoders always produce a full [`UHID_EVENT_SIZE`] buffer. The kernel accepts shorter
//! writes, but fixed-size events keep framing trivial when a test stands in for the kernel
//! over a stream socket.

use std::fmt;

/// `UHID_DATA_MAX`.
pub const UHID_DATA_MAX: usize = 4096;
/// `HID_MAX_DESCRIPTOR_SIZE`.
pub const HID_MAX_DESCRIPTOR_SIZE: usize = 4096;
/// `sizeof(struct uhid_event)`: a u32 type plus the largest union member, `uhid_create2_req`
/// (128 + 64 + 64 + 2 + 2 + 4 * 4 + 4096 = 4372 bytes).
pub const UHID_EVENT_SIZE: usize = 4376;
/// `BUS_USB` from `linux/input.h`.
pub const BUS_USB: u16 = 0x03;

/// `enum uhid_event_type` values used by hirz.
pub mod event_type {
    pub const DESTROY: u32 = 1;
    pub const START: u32 = 2;
    pub const STOP: u32 = 3;
    pub const OPEN: u32 = 4;
    pub const CLOSE: u32 = 5;
    pub const OUTPUT: u32 = 6;
    pub const GET_REPORT: u32 = 9;
    pub const GET_REPORT_REPLY: u32 = 10;
    pub const CREATE2: u32 = 11;
    pub const INPUT2: u32 = 12;
    pub const SET_REPORT: u32 = 13;
    pub const SET_REPORT_REPLY: u32 = 14;
}

// Byte offsets inside struct uhid_event (the union starts at 4).
const UNION: usize = 4;
const CREATE2_NAME: usize = UNION;
const CREATE2_NAME_LEN: usize = 128;
const CREATE2_PHYS: usize = UNION + 128;
const CREATE2_PHYS_LEN: usize = 64;
const CREATE2_UNIQ: usize = UNION + 192;
const CREATE2_UNIQ_LEN: usize = 64;
const CREATE2_RD_SIZE: usize = UNION + 256;
const CREATE2_BUS: usize = UNION + 258;
const CREATE2_VENDOR: usize = UNION + 260;
const CREATE2_PRODUCT: usize = UNION + 264;
const CREATE2_VERSION: usize = UNION + 268;
const CREATE2_COUNTRY: usize = UNION + 272;
const CREATE2_RD_DATA: usize = UNION + 276;
const INPUT2_SIZE: usize = UNION;
const INPUT2_DATA: usize = UNION + 2;
const OUTPUT_DATA: usize = UNION;
const OUTPUT_SIZE: usize = UNION + UHID_DATA_MAX;
const OUTPUT_RTYPE: usize = UNION + UHID_DATA_MAX + 2;
const REQ_ID: usize = UNION;
const REQ_RNUM: usize = UNION + 4;
const REQ_RTYPE: usize = UNION + 5;
const REPLY_ERR: usize = UNION + 4;
const GET_REPLY_SIZE: usize = UNION + 6;
const GET_REPLY_DATA: usize = UNION + 8;
const SET_REPORT_SIZE: usize = UNION + 6;
const SET_REPORT_DATA: usize = UNION + 8;
const START_FLAGS: usize = UNION;

/// Errors from encoding or decoding uhid events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UhidError {
    /// A string field does not fit (with its NUL terminator) or contains NUL.
    BadString(&'static str),
    /// The report descriptor is empty or larger than `HID_MAX_DESCRIPTOR_SIZE`.
    BadDescriptor,
    /// A report payload is larger than `UHID_DATA_MAX`.
    DataTooLarge,
    /// The event is shorter than its 4-byte type field.
    Truncated,
}

impl fmt::Display for UhidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadString(field) => write!(f, "uhid {field} string invalid or too long"),
            Self::BadDescriptor => write!(f, "uhid report descriptor size invalid"),
            Self::DataTooLarge => write!(f, "uhid report data too large"),
            Self::Truncated => write!(f, "uhid event truncated"),
        }
    }
}

impl std::error::Error for UhidError {}

/// Parameters of `UHID_CREATE2`.
#[derive(Debug, Clone, Copy)]
pub struct CreateParams<'a> {
    pub name: &'a str,
    pub phys: &'a str,
    pub uniq: &'a str,
    pub bus: u16,
    pub vendor: u32,
    pub product: u32,
    pub version: u32,
    pub country: u32,
    pub report_descriptor: &'a [u8],
}

/// `enum uhid_report_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportType {
    Feature,
    Output,
    Input,
    Unknown(u8),
}

impl From<u8> for ReportType {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Feature,
            1 => Self::Output,
            2 => Self::Input,
            other => Self::Unknown(other),
        }
    }
}

/// Events the kernel sends to user space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UhidEvent {
    Start {
        dev_flags: u64,
    },
    Stop,
    Open,
    Close,
    Output {
        data: Vec<u8>,
        rtype: ReportType,
    },
    GetReport {
        id: u32,
        rnum: u8,
        rtype: ReportType,
    },
    SetReport {
        id: u32,
        rnum: u8,
        rtype: ReportType,
        data: Vec<u8>,
    },
    /// Any other event type (including ones user space sends, which the kernel never emits).
    Other(u32),
}

fn new_event(kind: u32) -> Vec<u8> {
    let mut buf = vec![0u8; UHID_EVENT_SIZE];
    put(&mut buf, 0, &kind.to_ne_bytes());
    buf
}

fn put(buf: &mut [u8], off: usize, bytes: &[u8]) {
    let end = off.saturating_add(bytes.len());
    if let Some(dst) = buf.get_mut(off..end) {
        dst.copy_from_slice(bytes);
    }
}

fn put_str(
    buf: &mut [u8],
    off: usize,
    cap: usize,
    s: &str,
    field: &'static str,
) -> Result<(), UhidError> {
    // The kernel copies these with strscpy-like semantics; keep room for the terminator.
    if s.len() >= cap || s.as_bytes().contains(&0) {
        return Err(UhidError::BadString(field));
    }
    put(buf, off, s.as_bytes());
    Ok(())
}

fn get<const N: usize>(buf: &[u8], off: usize) -> [u8; N] {
    let mut out = [0u8; N];
    if let Some(src) = buf.get(off..off.saturating_add(N)) {
        out.copy_from_slice(src);
    }
    out
}

fn get_u8(buf: &[u8], off: usize) -> u8 {
    buf.get(off).copied().unwrap_or(0)
}

fn get_data(buf: &[u8], off: usize, size: u16) -> Result<Vec<u8>, UhidError> {
    let size = usize::from(size);
    if size > UHID_DATA_MAX {
        return Err(UhidError::DataTooLarge);
    }
    // Short events are zero-extended, as the ABI requires of user space.
    let mut out = vec![0u8; size];
    let end = off.saturating_add(size).min(buf.len());
    if let Some(src) = buf.get(off..end)
        && let Some(dst) = out.get_mut(..src.len())
    {
        dst.copy_from_slice(src);
    }
    Ok(out)
}

/// `UHID_CREATE2`.
pub fn encode_create2(p: &CreateParams<'_>) -> Result<Vec<u8>, UhidError> {
    let rd_len = p.report_descriptor.len();
    if rd_len == 0 || rd_len > HID_MAX_DESCRIPTOR_SIZE {
        return Err(UhidError::BadDescriptor);
    }
    let rd_size = u16::try_from(rd_len).map_err(|_| UhidError::BadDescriptor)?;
    let mut buf = new_event(event_type::CREATE2);
    put_str(&mut buf, CREATE2_NAME, CREATE2_NAME_LEN, p.name, "name")?;
    put_str(&mut buf, CREATE2_PHYS, CREATE2_PHYS_LEN, p.phys, "phys")?;
    put_str(&mut buf, CREATE2_UNIQ, CREATE2_UNIQ_LEN, p.uniq, "uniq")?;
    put(&mut buf, CREATE2_RD_SIZE, &rd_size.to_ne_bytes());
    put(&mut buf, CREATE2_BUS, &p.bus.to_ne_bytes());
    put(&mut buf, CREATE2_VENDOR, &p.vendor.to_ne_bytes());
    put(&mut buf, CREATE2_PRODUCT, &p.product.to_ne_bytes());
    put(&mut buf, CREATE2_VERSION, &p.version.to_ne_bytes());
    put(&mut buf, CREATE2_COUNTRY, &p.country.to_ne_bytes());
    put(&mut buf, CREATE2_RD_DATA, p.report_descriptor);
    Ok(buf)
}

/// `UHID_DESTROY`.
pub fn encode_destroy() -> Vec<u8> {
    new_event(event_type::DESTROY)
}

/// `UHID_INPUT2`: one input report from the device to the host.
pub fn encode_input2(data: &[u8]) -> Result<Vec<u8>, UhidError> {
    if data.len() > UHID_DATA_MAX {
        return Err(UhidError::DataTooLarge);
    }
    let size = u16::try_from(data.len()).map_err(|_| UhidError::DataTooLarge)?;
    let mut buf = new_event(event_type::INPUT2);
    put(&mut buf, INPUT2_SIZE, &size.to_ne_bytes());
    put(&mut buf, INPUT2_DATA, data);
    Ok(buf)
}

/// `UHID_GET_REPORT_REPLY`. A non-zero `err` is an errno value reported to the requester.
pub fn encode_get_report_reply(id: u32, err: u16, data: &[u8]) -> Result<Vec<u8>, UhidError> {
    if data.len() > UHID_DATA_MAX {
        return Err(UhidError::DataTooLarge);
    }
    let size = u16::try_from(data.len()).map_err(|_| UhidError::DataTooLarge)?;
    let mut buf = new_event(event_type::GET_REPORT_REPLY);
    put(&mut buf, REQ_ID, &id.to_ne_bytes());
    put(&mut buf, REPLY_ERR, &err.to_ne_bytes());
    put(&mut buf, GET_REPLY_SIZE, &size.to_ne_bytes());
    put(&mut buf, GET_REPLY_DATA, data);
    Ok(buf)
}

/// `UHID_SET_REPORT_REPLY`.
pub fn encode_set_report_reply(id: u32, err: u16) -> Vec<u8> {
    let mut buf = new_event(event_type::SET_REPORT_REPLY);
    put(&mut buf, REQ_ID, &id.to_ne_bytes());
    put(&mut buf, REPLY_ERR, &err.to_ne_bytes());
    buf
}

/// Decodes one event read from `/dev/uhid`. Input shorter than the full struct is treated as
/// zero-extended; bytes past [`UHID_EVENT_SIZE`] are ignored.
pub fn decode_event(buf: &[u8]) -> Result<UhidEvent, UhidError> {
    if buf.len() < 4 {
        return Err(UhidError::Truncated);
    }
    let buf = buf.get(..UHID_EVENT_SIZE).unwrap_or(buf);
    let kind = u32::from_ne_bytes(get::<4>(buf, 0));
    Ok(match kind {
        event_type::START => UhidEvent::Start {
            dev_flags: u64::from_ne_bytes(get::<8>(buf, START_FLAGS)),
        },
        event_type::STOP => UhidEvent::Stop,
        event_type::OPEN => UhidEvent::Open,
        event_type::CLOSE => UhidEvent::Close,
        event_type::OUTPUT => {
            let size = u16::from_ne_bytes(get::<2>(buf, OUTPUT_SIZE));
            UhidEvent::Output {
                data: get_data(buf, OUTPUT_DATA, size)?,
                rtype: ReportType::from(get_u8(buf, OUTPUT_RTYPE)),
            }
        }
        event_type::GET_REPORT => UhidEvent::GetReport {
            id: u32::from_ne_bytes(get::<4>(buf, REQ_ID)),
            rnum: get_u8(buf, REQ_RNUM),
            rtype: ReportType::from(get_u8(buf, REQ_RTYPE)),
        },
        event_type::SET_REPORT => {
            let size = u16::from_ne_bytes(get::<2>(buf, SET_REPORT_SIZE));
            UhidEvent::SetReport {
                id: u32::from_ne_bytes(get::<4>(buf, REQ_ID)),
                rnum: get_u8(buf, REQ_RNUM),
                rtype: ReportType::from(get_u8(buf, REQ_RTYPE)),
                data: get_data(buf, SET_REPORT_DATA, size)?,
            }
        }
        other => UhidEvent::Other(other),
    })
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

    fn ne32(b: &[u8], off: usize) -> u32 {
        u32::from_ne_bytes(b[off..off + 4].try_into().unwrap())
    }

    #[test]
    fn create2_layout_matches_header() {
        let rd = [0x06, 0xd0, 0xf1, 0x09, 0x01];
        let ev = encode_create2(&CreateParams {
            name: "dev",
            phys: "1000",
            uniq: "",
            bus: BUS_USB,
            vendor: 0x1209,
            product: 0x0007,
            version: 1,
            country: 0,
            report_descriptor: &rd,
        })
        .unwrap();
        assert_eq!(ev.len(), UHID_EVENT_SIZE);
        assert_eq!(ne32(&ev, 0), 11);
        assert_eq!(&ev[4..8], b"dev\0");
        assert_eq!(&ev[132..137], b"1000\0");
        assert_eq!(ev[196], 0);
        assert_eq!(u16::from_ne_bytes([ev[260], ev[261]]), 5);
        assert_eq!(u16::from_ne_bytes([ev[262], ev[263]]), 3);
        assert_eq!(ne32(&ev, 264), 0x1209);
        assert_eq!(ne32(&ev, 268), 0x0007);
        assert_eq!(ne32(&ev, 272), 1);
        assert_eq!(ne32(&ev, 276), 0);
        assert_eq!(&ev[280..285], &rd);
        assert!(ev[285..].iter().all(|&b| b == 0));
    }

    #[test]
    fn create2_rejects_bad_input() {
        let mut p = CreateParams {
            name: "x",
            phys: "",
            uniq: "",
            bus: BUS_USB,
            vendor: 0,
            product: 0,
            version: 0,
            country: 0,
            report_descriptor: &[],
        };
        assert_eq!(encode_create2(&p), Err(UhidError::BadDescriptor));
        let big = vec![0u8; HID_MAX_DESCRIPTOR_SIZE + 1];
        p.report_descriptor = &big;
        assert_eq!(encode_create2(&p), Err(UhidError::BadDescriptor));
        p.report_descriptor = &[1];
        let long = "a".repeat(128);
        p.name = &long;
        assert_eq!(encode_create2(&p), Err(UhidError::BadString("name")));
        p.name = "a\0b";
        assert_eq!(encode_create2(&p), Err(UhidError::BadString("name")));
        p.name = "ok";
        let long_phys = "p".repeat(64);
        p.phys = &long_phys;
        assert_eq!(encode_create2(&p), Err(UhidError::BadString("phys")));
    }

    #[test]
    fn input2_and_destroy_layout() {
        let report = [0xabu8; 64];
        let ev = encode_input2(&report).unwrap();
        assert_eq!(ne32(&ev, 0), 12);
        assert_eq!(u16::from_ne_bytes([ev[4], ev[5]]), 64);
        assert_eq!(&ev[6..70], &report[..]);
        assert_eq!(ev[70], 0);
        assert_eq!(
            encode_input2(&vec![0; UHID_DATA_MAX + 1]),
            Err(UhidError::DataTooLarge)
        );
        let d = encode_destroy();
        assert_eq!(d.len(), UHID_EVENT_SIZE);
        assert_eq!(ne32(&d, 0), 1);
    }

    #[test]
    fn replies_layout() {
        let ev = encode_get_report_reply(7, 5, &[]).unwrap();
        assert_eq!(ne32(&ev, 0), 10);
        assert_eq!(ne32(&ev, 4), 7);
        assert_eq!(u16::from_ne_bytes([ev[8], ev[9]]), 5);
        assert_eq!(u16::from_ne_bytes([ev[10], ev[11]]), 0);
        let ev = encode_set_report_reply(9, 5);
        assert_eq!(ne32(&ev, 0), 14);
        assert_eq!(ne32(&ev, 4), 9);
        assert_eq!(u16::from_ne_bytes([ev[8], ev[9]]), 5);
    }

    fn kernel_event(kind: u32) -> Vec<u8> {
        let mut b = vec![0u8; UHID_EVENT_SIZE];
        b[..4].copy_from_slice(&kind.to_ne_bytes());
        b
    }

    #[test]
    fn decodes_output() {
        let mut b = kernel_event(6);
        b[4] = 0x00;
        b[5] = 0xff;
        b[4 + 4096..4 + 4098].copy_from_slice(&65u16.to_ne_bytes());
        b[4 + 4098] = 1;
        match decode_event(&b).unwrap() {
            UhidEvent::Output { data, rtype } => {
                assert_eq!(data.len(), 65);
                assert_eq!(data[1], 0xff);
                assert_eq!(rtype, ReportType::Output);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn decodes_simple_events() {
        let mut b = kernel_event(2);
        b[4..12].copy_from_slice(&7u64.to_ne_bytes());
        assert_eq!(decode_event(&b).unwrap(), UhidEvent::Start { dev_flags: 7 });
        assert_eq!(decode_event(&kernel_event(3)).unwrap(), UhidEvent::Stop);
        assert_eq!(decode_event(&kernel_event(4)).unwrap(), UhidEvent::Open);
        assert_eq!(decode_event(&kernel_event(5)).unwrap(), UhidEvent::Close);
        assert_eq!(
            decode_event(&kernel_event(99)).unwrap(),
            UhidEvent::Other(99)
        );
        assert_eq!(decode_event(&[1, 0]), Err(UhidError::Truncated));
        // Short events are zero-extended.
        assert_eq!(decode_event(&3u32.to_ne_bytes()).unwrap(), UhidEvent::Stop);
    }

    #[test]
    fn decodes_report_requests() {
        let mut b = kernel_event(9);
        b[4..8].copy_from_slice(&42u32.to_ne_bytes());
        b[8] = 3;
        b[9] = 0;
        assert_eq!(
            decode_event(&b).unwrap(),
            UhidEvent::GetReport {
                id: 42,
                rnum: 3,
                rtype: ReportType::Feature
            }
        );
        let mut b = kernel_event(13);
        b[4..8].copy_from_slice(&43u32.to_ne_bytes());
        b[10..12].copy_from_slice(&2u16.to_ne_bytes());
        b[12] = 0xaa;
        b[13] = 0xbb;
        assert_eq!(
            decode_event(&b).unwrap(),
            UhidEvent::SetReport {
                id: 43,
                rnum: 0,
                rtype: ReportType::Feature,
                data: vec![0xaa, 0xbb]
            }
        );
    }

    #[test]
    fn oversized_sizes_are_rejected() {
        let mut b = kernel_event(6);
        b[4 + 4096..4 + 4098].copy_from_slice(&4097u16.to_ne_bytes());
        assert_eq!(decode_event(&b), Err(UhidError::DataTooLarge));
        let mut b = kernel_event(13);
        b[10..12].copy_from_slice(&u16::MAX.to_ne_bytes());
        assert_eq!(decode_event(&b), Err(UhidError::DataTooLarge));
    }
}
