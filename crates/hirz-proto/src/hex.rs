//! Lowercase hexadecimal, with a strict decoder.

use crate::wipe::Buffer;
use crate::{Error, Result};

const DIGITS: &[u8; 16] = b"0123456789abcdef";

pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b.wrapping_shr(4), b & 0x0f] {
            if let Some(&d) = DIGITS.get(usize::from(nibble)) {
                s.push(char::from(d));
            }
        }
    }
    s
}

fn nibble(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Ok(c.wrapping_sub(b'a').wrapping_add(10)),
        _ => Err(Error::Malformed),
    }
}

/// Lowercase and even length only: uppercase digits, whitespace and odd lengths are rejected.
pub fn decode(s: &str) -> Result<Vec<u8>> {
    let (pairs, rest) = s.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return Err(Error::Malformed);
    }
    let mut out = Buffer::with_capacity(pairs.len());
    for [hi, lo] in pairs {
        out.push(nibble(*hi)?.wrapping_shl(4) | nibble(*lo)?);
    }
    Ok(out.into_vec())
}

pub fn decode_array<const N: usize>(s: &str) -> Result<[u8; N]> {
    if s.len() != N.checked_mul(2).ok_or(Error::LimitExceeded)? {
        return Err(Error::InvalidValue);
    }
    let mut out = [0u8; N];
    for (o, [hi, lo]) in out.iter_mut().zip(s.as_bytes().as_chunks::<2>().0) {
        *o = nibble(*hi)?.wrapping_shl(4) | nibble(*lo)?;
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_decode_that_fails_wipes_the_bytes_it_had_made() {
        let _ = crate::wipe::take_wiped();
        assert!(decode("aabbzz").is_err());
        assert_eq!(crate::wipe::take_wiped(), 2);
        assert_eq!(decode("aabb").unwrap(), [0xaa, 0xbb]);
        assert_eq!(crate::wipe::take_wiped(), 0);
    }

    #[test]
    fn round_trip() {
        assert_eq!(encode(&[]), "");
        assert_eq!(encode(&[0, 1, 0x0f, 0xa0, 0xfe, 0xff]), "00010fa0feff");
        assert_eq!(
            decode("00010fa0feff").unwrap(),
            [0, 1, 0x0f, 0xa0, 0xfe, 0xff]
        );
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(decode_array::<2>("0fa0").unwrap(), [0x0f, 0xa0]);
    }

    #[test]
    fn strict_rejections() {
        for bad in ["0", "abc", "0g", "0A", " 00", "00 ", "+0"] {
            assert!(decode(bad).is_err(), "{bad}");
        }
        assert!(decode_array::<2>("0fa").is_err());
        assert!(decode_array::<2>("0fa000").is_err());
        assert!(decode_array::<2>("0FA0").is_err());
    }
}
