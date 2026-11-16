//! Small length-prefixed binary encoding used by every vault file.
//!
//! A body is a version byte followed by fields `tag (u8) || length (u16, big endian) ||
//! value`. Tags appear in strictly increasing order, so every value has one encoding.

use crate::error::VaultError;
use hirz_crypto::Zeroizing;

/// Initial capacity for buffers that may hold secrets, so they do not reallocate (and leave
/// copies in freed memory) while being filled.
const SECRET_CAPACITY: usize = 4096;

#[derive(Debug)]
pub(crate) struct Writer {
    buf: Zeroizing<Vec<u8>>,
    last_tag: Option<u8>,
}

impl Writer {
    pub(crate) fn new(version: u8) -> Self {
        let mut buf = Zeroizing::new(Vec::with_capacity(SECRET_CAPACITY));
        buf.push(version);
        Writer {
            buf,
            last_tag: None,
        }
    }

    pub(crate) fn field(&mut self, tag: u8, value: &[u8]) -> Result<(), VaultError> {
        if self.last_tag.is_some_and(|t| t >= tag) {
            return Err(VaultError::Encode);
        }
        let len = u16::try_from(value.len()).map_err(|_| VaultError::Encode)?;
        self.buf.push(tag);
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.buf.extend_from_slice(value);
        self.last_tag = Some(tag);
        Ok(())
    }

    pub(crate) fn u8_field(&mut self, tag: u8, v: u8) -> Result<(), VaultError> {
        self.field(tag, &[v])
    }

    pub(crate) fn u64_field(&mut self, tag: u8, v: u64) -> Result<(), VaultError> {
        self.field(tag, &v.to_be_bytes())
    }

    pub(crate) fn i64_field(&mut self, tag: u8, v: i64) -> Result<(), VaultError> {
        self.field(tag, &v.to_be_bytes())
    }

    pub(crate) fn finish(self) -> Zeroizing<Vec<u8>> {
        self.buf
    }
}

/// Iterates over the fields of a body, enforcing the canonical form.
#[derive(Debug)]
pub(crate) struct Fields<'a> {
    rest: &'a [u8],
    last_tag: Option<u8>,
}

impl<'a> Fields<'a> {
    /// Checks the version byte and returns the field iterator.
    pub(crate) fn new(data: &'a [u8], version: u8) -> Result<Self, VaultError> {
        Fields::new_versions(data, &[version]).map(|(f, _)| f)
    }

    /// Like `new`, for bodies whose readers accept several versions; returns the version.
    pub(crate) fn new_versions(data: &'a [u8], accepted: &[u8]) -> Result<(Self, u8), VaultError> {
        match data.split_first() {
            Some((v, rest)) if accepted.contains(v) => Ok((
                Fields {
                    rest,
                    last_tag: None,
                },
                *v,
            )),
            Some(_) => Err(VaultError::UnsupportedVersion),
            None => Err(VaultError::Corrupt("empty body")),
        }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.rest.len()
    }

    pub(crate) fn next_field(&mut self) -> Result<Option<(u8, &'a [u8])>, VaultError> {
        if self.rest.is_empty() {
            return Ok(None);
        }
        let mut r = Reader::new(self.rest);
        let tag = r.u8()?;
        let len = usize::from(r.u16()?);
        let value = r.take(len)?;
        if self.last_tag.is_some_and(|t| t >= tag) {
            return Err(VaultError::Corrupt("field order"));
        }
        self.last_tag = Some(tag);
        self.rest = r.rest();
        Ok(Some((tag, value)))
    }
}

#[derive(Debug)]
pub(crate) struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Reader { data }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], VaultError> {
        if n > self.data.len() {
            return Err(VaultError::Corrupt("truncated"));
        }
        let (head, tail) = self.data.split_at(n);
        self.data = tail;
        Ok(head)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], VaultError> {
        let s = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, VaultError> {
        Ok(u8::from_be_bytes(self.array::<1>()?))
    }

    pub(crate) fn u16(&mut self) -> Result<u16, VaultError> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, VaultError> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, VaultError> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    pub(crate) fn rest(&self) -> &'a [u8] {
        self.data
    }

    pub(crate) fn finish(&self) -> Result<(), VaultError> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(VaultError::Corrupt("trailing bytes"))
        }
    }
}

pub(crate) fn fixed<const N: usize>(value: &[u8]) -> Result<[u8; N], VaultError> {
    if value.len() != N {
        return Err(VaultError::Corrupt("field length"));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(value);
    Ok(out)
}

pub(crate) fn u64_value(value: &[u8]) -> Result<u64, VaultError> {
    Ok(u64::from_be_bytes(fixed::<8>(value)?))
}

pub(crate) fn i64_value(value: &[u8]) -> Result<i64, VaultError> {
    Ok(i64::from_be_bytes(fixed::<8>(value)?))
}

pub(crate) fn u8_value(value: &[u8]) -> Result<u8, VaultError> {
    let [b] = fixed::<1>(value)?;
    Ok(b)
}

pub(crate) fn bool_value(value: &[u8]) -> Result<bool, VaultError> {
    match u8_value(value)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(VaultError::Corrupt("boolean")),
    }
}

pub(crate) fn string_value(value: &[u8], max: usize) -> Result<String, VaultError> {
    if value.len() > max {
        return Err(VaultError::Corrupt("string too long"));
    }
    String::from_utf8(value.to_vec()).map_err(|_| VaultError::Corrupt("utf-8"))
}

/// Unambiguous associated data: `label || 0x00 || (u32 length || part)*`.
pub(crate) fn aad(label: &str, parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(label.as_bytes());
    out.push(0);
    for p in parts {
        let len = u32::try_from(p.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

const HEX: &[u8; 16] = b"0123456789abcdef";

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b.wrapping_shr(4), b & 0x0f] {
            if let Some(c) = HEX.get(usize::from(nibble)) {
                s.push(char::from(*c));
            }
        }
    }
    s
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => c.checked_sub(b'0'),
        b'a'..=b'f' => c.checked_sub(b'a').and_then(|v| v.checked_add(10)),
        _ => None,
    }
}

/// Strict lowercase hex decoding of exactly `N` bytes.
pub(crate) fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let bytes = s.as_bytes();
    if bytes.len() != N.checked_mul(2)? {
        return None;
    }
    let mut out = [0u8; N];
    for (o, [hi, lo]) in out.iter_mut().zip(bytes.as_chunks::<2>().0) {
        *o = nibble(*hi)?.wrapping_shl(4) | nibble(*lo)?;
    }
    Some(out)
}
