#![no_main]

use hirz_ctap::hid::{
    self, CONT_DATA_SIZE, INIT_DATA_SIZE, MAX_MESSAGE_SIZE, Packet, REPORT_SIZE,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    assert_eq!(hid::parse_packet(data).is_ok(), data.len() == REPORT_SIZE);
    if let Some(report) = data.get(..REPORT_SIZE) {
        match hid::parse_packet(report).expect("64-byte report") {
            Packet::Init { cmd, data, .. } => {
                assert!(cmd & 0x80 == 0);
                assert_eq!(data.len(), INIT_DATA_SIZE);
            }
            Packet::Cont { seq, data, .. } => {
                assert!(seq & 0x80 == 0);
                assert_eq!(data.len(), CONT_DATA_SIZE);
            }
        }
    }

    let Some((head, payload)) = data.split_first_chunk::<5>() else {
        return;
    };
    let cid = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    let command = head[4] & 0x7f;
    let reports = match hid::build_message(cid, command, payload) {
        Ok(r) => r,
        Err(_) => {
            assert!(payload.len() > MAX_MESSAGE_SIZE);
            return;
        }
    };
    let cont = payload.len().saturating_sub(INIT_DATA_SIZE).div_ceil(CONT_DATA_SIZE);
    assert_eq!(reports.len(), 1 + cont, "minimal number of packets");
    let mut buf = Vec::new();
    for (i, report) in reports.iter().enumerate() {
        match hid::parse_packet(report).expect("own report parses") {
            Packet::Init {
                cid: c,
                cmd,
                bcnt,
                data,
            } => {
                assert_eq!(i, 0);
                assert_eq!((c, cmd, usize::from(bcnt)), (cid, command, payload.len()));
                buf.extend_from_slice(data);
            }
            Packet::Cont { cid: c, seq, data } => {
                assert_eq!((c, usize::from(seq)), (cid, i - 1));
                buf.extend_from_slice(data);
            }
        }
    }
    assert_eq!(&buf[..payload.len()], payload);
    assert!(buf[payload.len()..].iter().all(|&b| b == 0), "zero padding");
});
