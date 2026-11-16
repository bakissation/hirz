//! authenticatorGetInfo for the Phase 0 spike: a fixed, hand-written canonical CBOR map.

use hirz_core::AAGUID;

/// CTAP2 command byte of authenticatorGetInfo.
pub const CMD_GET_INFO: u8 = 0x04;

// Diagnostic notation of the encoded map (keys in CTAP2 canonical order):
//
// {
//   1: ["FIDO_2_0", "FIDO_2_1"],                          versions
//   2: ["credProtect", "hmac-secret"],                    extensions
//   3: h'c049d0460de04b9c824f5b5eeeff218f',               aaguid
//   4: {"rk": true, "up": true, "uv": true, "plat": false}, options
//   5: 7609,                                              maxMsgSize
//   6: [2, 1],                                            pinUvAuthProtocols
//   9: ["usb"],                                           transports
//   10: [{"alg": -7, "type": "public-key"},               algorithms
//        {"alg": -8, "type": "public-key"}]
// }
const BEFORE_AAGUID: &[u8] = &[
    0xa8, // map(8)
    0x01, 0x82, // 1: array(2)
    0x68, b'F', b'I', b'D', b'O', b'_', b'2', b'_', b'0', // "FIDO_2_0"
    0x68, b'F', b'I', b'D', b'O', b'_', b'2', b'_', b'1', // "FIDO_2_1"
    0x02, 0x82, // 2: array(2)
    0x6b, b'c', b'r', b'e', b'd', b'P', b'r', b'o', b't', b'e', b'c', b't', // "credProtect"
    0x6b, b'h', b'm', b'a', b'c', b'-', b's', b'e', b'c', b'r', b'e', b't', // "hmac-secret"
    0x03, 0x50, // 3: bytes(16), followed by the AAGUID
];

const AFTER_AAGUID: &[u8] = &[
    0x04, 0xa4, // 4: map(4)
    0x62, b'r', b'k', 0xf5, // "rk": true
    0x62, b'u', b'p', 0xf5, // "up": true
    0x62, b'u', b'v', 0xf5, // "uv": true
    0x64, b'p', b'l', b'a', b't', 0xf4, // "plat": false
    0x05, 0x19, 0x1d, 0xb9, // 5: 7609
    0x06, 0x82, 0x02, 0x01, // 6: [2, 1]
    0x09, 0x81, 0x63, b'u', b's', b'b', // 9: ["usb"]
    0x0a, 0x82, // 10: array(2)
    0xa2, 0x63, b'a', b'l', b'g', 0x26, // {"alg": -7,
    0x64, b't', b'y', b'p', b'e', // "type":
    0x6a, b'p', b'u', b'b', b'l', b'i', b'c', b'-', b'k', b'e', b'y', // "public-key"}
    0xa2, 0x63, b'a', b'l', b'g', 0x27, // {"alg": -8,
    0x64, b't', b'y', b'p', b'e', // "type":
    0x6a, b'p', b'u', b'b', b'l', b'i', b'c', b'-', b'k', b'e', b'y', // "public-key"}
];

const RESPONSE_LEN: usize = 1 + BEFORE_AAGUID.len() + AAGUID.len() + AFTER_AAGUID.len();

/// Status byte CTAP2_OK followed by the getInfo map.
pub fn get_info_response() -> Vec<u8> {
    let mut out = Vec::with_capacity(RESPONSE_LEN);
    out.push(0x00);
    out.extend_from_slice(BEFORE_AAGUID);
    out.extend_from_slice(&AAGUID);
    out.extend_from_slice(AFTER_AAGUID);
    out
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn shape_of_get_info() {
        let r = get_info_response();
        assert_eq!(r.len(), 146);
        assert_eq!(RESPONSE_LEN, 146);
        assert_eq!(r[0], 0x00);
        assert_eq!(r[1], 0xa8);
        assert_eq!(&r[2..4], &[0x01, 0x82]);
        assert_eq!(&r[4..13], b"\x68FIDO_2_0");
        // 3: bytes(16) at offset 48, AAGUID right after.
        assert_eq!(&r[48..50], &[0x03, 0x50]);
        assert_eq!(&r[50..66], &AAGUID);
        assert_eq!(r[50], 0xc0);
        assert_eq!(&r[66..68], &[0x04, 0xa4]);
        // maxMsgSize 7609 = 0x1db9.
        assert_eq!(&r[86..90], &[0x05, 0x19, 0x1d, 0xb9]);
        assert_eq!(&r[90..94], &[0x06, 0x82, 0x02, 0x01]);
        assert_eq!(&r[94..100], b"\x09\x81\x63usb");
        assert_eq!(&r[r.len() - 11..], b"\x6apublic-key");
    }
}
