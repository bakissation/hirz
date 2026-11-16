//! base64url without padding (RFC 4648 section 5), with a strict decoder.

use crate::{Error, Result};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn symbol(index: u8) -> char {
    ALPHABET
        .get(usize::from(index & 0x3f))
        .map_or('A', |&c| char::from(c))
}

fn value(c: u8) -> Result<u8> {
    match c {
        b'A'..=b'Z' => Ok(c.wrapping_sub(b'A')),
        b'a'..=b'z' => Ok(c.wrapping_sub(b'a').wrapping_add(26)),
        b'0'..=b'9' => Ok(c.wrapping_sub(b'0').wrapping_add(52)),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err(Error::Malformed),
    }
}

/// Encodes bytes as base64url without padding.
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().saturating_mul(4).div_ceil(3));
    for chunk in input.chunks(3) {
        let (b0, b1, b2) = match *chunk {
            [a] => (a, 0, 0),
            [a, b] => (a, b, 0),
            [a, b, c] => (a, b, c),
            _ => break,
        };
        out.push(symbol(b0.wrapping_shr(2)));
        out.push(symbol((b0 & 0x03).wrapping_shl(4) | b1.wrapping_shr(4)));
        if chunk.len() > 1 {
            out.push(symbol((b1 & 0x0f).wrapping_shl(2) | b2.wrapping_shr(6)));
        }
        if chunk.len() > 2 {
            out.push(symbol(b2));
        }
    }
    out
}

/// Decodes unpadded base64url; rejects padding, whitespace and non-zero trailing bits.
pub fn decode(input: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    for chunk in input.as_bytes().chunks(4) {
        match *chunk {
            [a, b] => {
                let (a, b) = (value(a)?, value(b)?);
                if b & 0x0f != 0 {
                    return Err(Error::NonCanonical);
                }
                out.push(a.wrapping_shl(2) | b.wrapping_shr(4));
            }
            [a, b, c] => {
                let (a, b, c) = (value(a)?, value(b)?, value(c)?);
                if c & 0x03 != 0 {
                    return Err(Error::NonCanonical);
                }
                out.push(a.wrapping_shl(2) | b.wrapping_shr(4));
                out.push(b.wrapping_shl(4) | c.wrapping_shr(2));
            }
            [a, b, c, d] => {
                let (a, b, c, d) = (value(a)?, value(b)?, value(c)?, value(d)?);
                out.push(a.wrapping_shl(2) | b.wrapping_shr(4));
                out.push(b.wrapping_shl(4) | c.wrapping_shr(2));
                out.push(c.wrapping_shl(6) | d);
            }
            _ => return Err(Error::Malformed),
        }
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        let cases = [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, enc) in cases {
            assert_eq!(encode(plain.as_bytes()), enc);
            assert_eq!(decode(enc).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn url_alphabet() {
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(decode("-_8").unwrap(), [0xfb, 0xff]);
        assert_eq!(encode(&[0xff; 3]), "____");
        assert_eq!(encode(&[0xf8; 3]), "-Pj4");
    }

    #[test]
    fn strict_rejections() {
        for bad in [
            "Zg==", "Zm8=", "Z", "Zm9vY", "Zh", "Zm9", "Zm 8", "Zm+8", "Zm/8", " Zg", "Zg\n", "Zé",
        ] {
            assert!(decode(bad).is_err(), "{bad:?}");
        }
        assert_eq!(decode("Zh"), Err(Error::NonCanonical));
        assert_eq!(decode("Zm9"), Err(Error::NonCanonical));
    }

    #[test]
    fn all_byte_values_round_trip() {
        let all: Vec<u8> = (0..=255u8).collect();
        for len in 0..all.len() {
            let data = all.get(..len).unwrap();
            assert_eq!(decode(&encode(data)).unwrap(), data);
        }
    }
}
