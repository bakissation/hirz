#![no_main]

//! Native messaging framing. First byte: bytes per `read` call (0: as many as asked); second:
//! frame size cap (0: `INBOUND_MAX`); the rest is the stream. Frames read have length 1..=cap,
//! consumption is exact, and `write_frame` round-trips.

use std::io::{self, Cursor, Read};

use hirz_nmh::framing::{FrameError, INBOUND_MAX, OUTBOUND_MAX, read_frame, write_frame};
use libfuzzer_sys::fuzz_target;

struct Chunked<'a> {
    data: &'a [u8],
    chunk: usize,
}

impl Read for Chunked<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(self.data.len()).min(self.chunk);
        let (head, rest) = self.data.split_at(n);
        buf[..n].copy_from_slice(head);
        self.data = rest;
        Ok(n)
    }
}

fuzz_target!(|data: &[u8]| {
    let [chunk, cap, stream @ ..] = data else {
        return;
    };
    let chunk = if *chunk == 0 {
        usize::MAX
    } else {
        usize::from(*chunk)
    };
    let max = if *cap == 0 {
        INBOUND_MAX
    } else {
        usize::from(*cap) * 16
    };
    let mut reader = Chunked {
        data: stream,
        chunk,
    };
    let mut consumed = 0usize;
    loop {
        match read_frame(&mut reader, max) {
            Ok(None) => {
                assert_eq!(
                    consumed,
                    stream.len(),
                    "clean end only after the last frame"
                );
                break;
            }
            Ok(Some(frame)) => {
                assert!(!frame.is_empty() && frame.len() <= max);
                consumed += 4 + frame.len();
                assert_eq!(consumed, stream.len() - reader.data.len());
                assert!(frame.len() <= OUTBOUND_MAX);
                let mut out = Vec::new();
                write_frame(&mut out, &frame).expect("a read frame can be written");
                assert_eq!(out.len(), 4 + frame.len());
                let again = read_frame(&mut Cursor::new(&out), max).expect("reads back");
                assert_eq!(again.as_deref(), Some(frame.as_slice()));
            }
            Err(FrameError::Io(e)) => panic!("no i/o error from a slice: {e}"),
            Err(FrameError::TooLarge { len, max: m }) => {
                assert_eq!(m, max);
                assert!(len > max as u64);
                break;
            }
            Err(_) => break,
        }
    }
});
