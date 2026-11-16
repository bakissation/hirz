//! Native messaging framing: a 32-bit unsigned length in native byte order,
//! followed by that many bytes of UTF-8 JSON.

use std::fmt;
use std::io::{self, Read, Write};

/// Our own cap on browser-to-host messages. Firefox would send up to 4 GiB.
pub const INBOUND_MAX: usize = 256 * 1024;

/// Firefox refuses host-to-browser messages larger than 1 MiB.
pub const OUTBOUND_MAX: usize = 1024 * 1024;

const HEADER_LEN: usize = 4;

#[derive(Debug)]
pub enum FrameError {
    /// The stream ended inside the 4-byte length prefix.
    TruncatedHeader,
    /// The stream ended inside a message body.
    TruncatedBody {
        expected: usize,
        got: usize,
    },
    /// A zero-length message; never valid JSON.
    Empty,
    /// The announced or supplied length is above the cap.
    TooLarge {
        len: u64,
        max: usize,
    },
    Io(io::Error),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader => f.write_str("stream ended inside a length prefix"),
            Self::TruncatedBody { expected, got } => {
                write!(
                    f,
                    "stream ended inside a message ({got} of {expected} bytes)"
                )
            }
            Self::Empty => f.write_str("zero-length message"),
            Self::TooLarge { len, max } => write!(f, "message of {len} bytes exceeds {max}"),
            Self::Io(e) => write!(f, "i/o error: {e}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<io::Error> for FrameError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Reads one framed message. Returns `Ok(None)` on a clean end of stream,
/// that is EOF before the first byte of a length prefix.
///
/// The length is checked against `max` before any allocation, so a hostile
/// prefix can never make us reserve more than `max` bytes.
pub fn read_frame<R: Read>(reader: &mut R, max: usize) -> Result<Option<Vec<u8>>, FrameError> {
    let mut header = [0u8; HEADER_LEN];
    let mut filled = 0usize;
    while filled < HEADER_LEN {
        let rest = header
            .get_mut(filled..)
            .ok_or(FrameError::TruncatedHeader)?;
        match reader.read(rest) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => return Err(FrameError::TruncatedHeader),
            Ok(n) => filled = filled.checked_add(n).ok_or(FrameError::TruncatedHeader)?,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(FrameError::Io(e)),
        }
    }

    let announced = u32::from_ne_bytes(header);
    let len = usize::try_from(announced).map_err(|_| FrameError::TooLarge {
        len: u64::from(announced),
        max,
    })?;
    if len == 0 {
        return Err(FrameError::Empty);
    }
    if len > max {
        return Err(FrameError::TooLarge {
            len: u64::from(announced),
            max,
        });
    }

    let mut body = Vec::with_capacity(len);
    let limit = u64::from(announced);
    reader.by_ref().take(limit).read_to_end(&mut body)?;
    if body.len() != len {
        return Err(FrameError::TruncatedBody {
            expected: len,
            got: body.len(),
        });
    }
    Ok(Some(body))
}

/// Writes one framed message and flushes, so the browser sees it at once.
pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> Result<(), FrameError> {
    let too_large = || FrameError::TooLarge {
        len: u64::try_from(payload.len()).unwrap_or(u64::MAX),
        max: OUTBOUND_MAX,
    };
    if payload.is_empty() {
        return Err(FrameError::Empty);
    }
    if payload.len() > OUTBOUND_MAX {
        return Err(too_large());
    }
    let len = u32::try_from(payload.len()).map_err(|_| too_large())?;
    writer.write_all(&len.to_ne_bytes())?;
    writer.write_all(payload)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut out = (payload.len() as u32).to_ne_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    fn header(len: u32) -> Vec<u8> {
        len.to_ne_bytes().to_vec()
    }

    #[test]
    fn round_trip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, br#"{"v":1}"#).unwrap();
        assert_eq!(&buf[..4], &7u32.to_ne_bytes());
        let mut r = Cursor::new(buf);
        assert_eq!(
            read_frame(&mut r, INBOUND_MAX).unwrap().unwrap(),
            br#"{"v":1}"#
        );
        assert!(read_frame(&mut r, INBOUND_MAX).unwrap().is_none());
    }

    #[test]
    fn several_frames_in_sequence() {
        let mut data = frame(b"{}");
        data.extend(frame(b"[1]"));
        data.extend(frame(b"\"x\""));
        let mut r = Cursor::new(data);
        assert_eq!(read_frame(&mut r, 16).unwrap().unwrap(), b"{}");
        assert_eq!(read_frame(&mut r, 16).unwrap().unwrap(), b"[1]");
        assert_eq!(read_frame(&mut r, 16).unwrap().unwrap(), b"\"x\"");
        assert!(read_frame(&mut r, 16).unwrap().is_none());
    }

    #[test]
    fn clean_eof_on_empty_stream() {
        let mut r = Cursor::new(Vec::new());
        assert!(read_frame(&mut r, INBOUND_MAX).unwrap().is_none());
    }

    #[test]
    fn truncated_header() {
        for n in 1..4 {
            let mut r = Cursor::new(vec![1u8; n]);
            assert!(matches!(
                read_frame(&mut r, INBOUND_MAX),
                Err(FrameError::TruncatedHeader)
            ));
        }
    }

    #[test]
    fn truncated_body() {
        let mut data = header(10);
        data.extend_from_slice(b"abc");
        let mut r = Cursor::new(data);
        assert!(matches!(
            read_frame(&mut r, INBOUND_MAX),
            Err(FrameError::TruncatedBody {
                expected: 10,
                got: 3
            })
        ));
    }

    #[test]
    fn zero_length_rejected() {
        let mut r = Cursor::new(header(0));
        assert!(matches!(
            read_frame(&mut r, INBOUND_MAX),
            Err(FrameError::Empty)
        ));
    }

    #[test]
    fn exactly_at_cap_is_accepted() {
        let payload = vec![b' '; INBOUND_MAX];
        let mut r = Cursor::new(frame(&payload));
        assert_eq!(
            read_frame(&mut r, INBOUND_MAX).unwrap().unwrap().len(),
            INBOUND_MAX
        );
    }

    #[test]
    fn one_over_cap_is_rejected_before_reading_body() {
        let len = u32::try_from(INBOUND_MAX + 1).unwrap();
        let mut r = Cursor::new(header(len));
        assert!(matches!(
            read_frame(&mut r, INBOUND_MAX),
            Err(FrameError::TooLarge { .. })
        ));
        assert_eq!(r.position(), 4);
    }

    #[test]
    fn hostile_lengths_rejected() {
        for len in [
            u32::MAX,
            u32::MAX - 1,
            0x8000_0000,
            0x0100_0000,
            1024 * 1024,
        ] {
            let mut r = Cursor::new(header(len));
            match read_frame(&mut r, INBOUND_MAX) {
                Err(FrameError::TooLarge { len: got, max }) => {
                    assert_eq!(got, u64::from(len));
                    assert_eq!(max, INBOUND_MAX);
                }
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    #[test]
    fn byte_order_is_native() {
        let mut data = vec![0u8; 4];
        data.copy_from_slice(&3u32.to_ne_bytes());
        data.extend_from_slice(b"abc");
        let mut r = Cursor::new(data);
        assert_eq!(read_frame(&mut r, 8).unwrap().unwrap(), b"abc");
    }

    struct Trickle {
        data: Vec<u8>,
        pos: usize,
        interrupt_next: bool,
    }

    impl Read for Trickle {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.interrupt_next {
                self.interrupt_next = false;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            self.interrupt_next = true;
            if self.pos >= self.data.len() || buf.is_empty() {
                return Ok(0);
            }
            buf[0] = self.data[self.pos];
            self.pos += 1;
            Ok(1)
        }
    }

    #[test]
    fn one_byte_reads_with_interrupts() {
        let mut data = frame(br#"{"id":1}"#);
        data.extend(frame(b"{}"));
        let mut r = Trickle {
            data,
            pos: 0,
            interrupt_next: true,
        };
        assert_eq!(read_frame(&mut r, 64).unwrap().unwrap(), br#"{"id":1}"#);
        assert_eq!(read_frame(&mut r, 64).unwrap().unwrap(), b"{}");
        assert!(read_frame(&mut r, 64).unwrap().is_none());
    }

    struct Failing;

    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    #[test]
    fn io_errors_surface() {
        assert!(matches!(
            read_frame(&mut Failing, 64),
            Err(FrameError::Io(_))
        ));
    }

    #[test]
    fn write_rejects_oversize_and_empty() {
        let mut out = Vec::new();
        let big = vec![b'a'; OUTBOUND_MAX + 1];
        assert!(matches!(
            write_frame(&mut out, &big),
            Err(FrameError::TooLarge { .. })
        ));
        assert!(matches!(write_frame(&mut out, b""), Err(FrameError::Empty)));
        assert!(out.is_empty());
    }

    #[test]
    fn write_accepts_exactly_outbound_max() {
        let mut out = Vec::new();
        let max = vec![b'a'; OUTBOUND_MAX];
        write_frame(&mut out, &max).unwrap();
        assert_eq!(out.len(), OUTBOUND_MAX + 4);
    }
}
