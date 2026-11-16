//! Strict CBOR subset used by CTAP2 and WebAuthn, with a CTAP2 canonical encoder: definite
//! lengths only, no floats, tags or `undefined`, integer or text map keys. Canonical order
//! follows CTAP2 section 8; see docs/architecture.md, "Implementation notes".

use crate::wipe;
use crate::{Error, Result};
use core::cmp::Ordering;

const MAJOR_UNSIGNED: u8 = 0x00;
const MAJOR_NEGATIVE: u8 = 0x20;
const MAJOR_BYTES: u8 = 0x40;
const MAJOR_TEXT: u8 = 0x60;
const MAJOR_ARRAY: u8 = 0x80;
const MAJOR_MAP: u8 = 0xa0;
const MAJOR_TAG: u8 = 0xc0;
const MAJOR_MASK: u8 = 0xe0;
const INFO_MASK: u8 = 0x1f;
const SIMPLE_FALSE: u8 = 0xf4;
const SIMPLE_TRUE: u8 = 0xf5;
const SIMPLE_NULL: u8 = 0xf6;

/// A decoded value wipes the bytes and text it holds when it is dropped: a CTAP request carries
/// PIN and salt blobs, and an item that failed to decode part way is dropped the same way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Unsigned(u64),
    /// Major type 1: `Negative(n)` is the integer `-1 - n`.
    Negative(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Map entries in encoded order; keys are integers or text.
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

impl Drop for Value {
    fn drop(&mut self) {
        match self {
            Value::Bytes(b) => wipe::bytes(b),
            Value::Text(t) => wipe::string(t),
            // Items inside an array or map are dropped, and so wiped, one by one.
            Value::Unsigned(_)
            | Value::Negative(_)
            | Value::Array(_)
            | Value::Map(_)
            | Value::Bool(_)
            | Value::Null => {}
        }
    }
}

impl Value {
    pub fn int(v: i64) -> Value {
        match u64::try_from(v) {
            Ok(u) => Value::Unsigned(u),
            Err(_) => Value::Negative((!v).unsigned_abs()),
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Unsigned(n) => i64::try_from(*n).ok(),
            Value::Negative(n) => i64::try_from(*n).ok().map(|m| !m),
            _ => None,
        }
    }

    pub fn as_i128(&self) -> Option<i128> {
        match self {
            Value::Unsigned(n) => Some(i128::from(*n)),
            Value::Negative(n) => Some(!i128::from(*n)),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Unsigned(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    pub fn get(&self, key: &Value) -> Option<&Value> {
        self.as_map()?
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    pub fn get_int(&self, key: i64) -> Option<&Value> {
        self.get(&Value::int(key))
    }

    pub fn get_text(&self, key: &str) -> Option<&Value> {
        self.as_map()?
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v)
    }
}

impl From<u64> for Value {
    fn from(v: u64) -> Self {
        Value::Unsigned(v)
    }
}

impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Value::int(v)
    }
}

impl From<i32> for Value {
    fn from(v: i32) -> Self {
        Value::int(i64::from(v))
    }
}

impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Value::Bool(v)
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::Text(v.to_owned())
    }
}

impl From<String> for Value {
    fn from(v: String) -> Self {
        Value::Text(v)
    }
}

impl From<&[u8]> for Value {
    fn from(v: &[u8]) -> Self {
        Value::Bytes(v.to_vec())
    }
}

impl From<Vec<u8>> for Value {
    fn from(v: Vec<u8>) -> Self {
        Value::Bytes(v)
    }
}

impl From<Vec<Value>> for Value {
    fn from(v: Vec<Value>) -> Self {
        Value::Array(v)
    }
}

/// `encode` sorts keys canonically.
#[derive(Debug, Clone, Default)]
pub struct MapBuilder {
    entries: Vec<(Value, Value)>,
}

impl MapBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn int(mut self, key: i64, value: impl Into<Value>) -> Self {
        self.entries.push((Value::int(key), value.into()));
        self
    }

    pub fn text(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.entries.push((Value::from(key), value.into()));
        self
    }

    pub fn build(self) -> Value {
        Value::Map(self.entries)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_len: usize,
    pub max_depth: usize,
    pub max_items: usize,
    /// Require CTAP2 canonical map key order; duplicate keys are rejected either way.
    pub require_canonical: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_len: 65_536,
            max_depth: 8,
            max_items: 8_192,
            require_canonical: true,
        }
    }
}

/// Exactly one item; trailing bytes are rejected.
pub fn decode(input: &[u8], limits: &Limits) -> Result<Value> {
    let (value, used) = decode_prefix(input, limits)?;
    if used != input.len() {
        return Err(Error::TrailingBytes);
    }
    Ok(value)
}

pub(crate) fn decode_prefix(input: &[u8], limits: &Limits) -> Result<(Value, usize)> {
    if input.len() > limits.max_len {
        return Err(Error::LimitExceeded);
    }
    let mut d = Decoder {
        input,
        pos: 0,
        limits,
        items: 0,
    };
    let value = d.item(0)?;
    Ok((value, d.pos))
}

struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
    limits: &'a Limits,
    items: usize,
}

impl<'a> Decoder<'a> {
    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        let s = self.input.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        <[u8; N]>::try_from(self.take(N)?).map_err(|_| Error::Truncated)
    }

    fn peek(&self) -> Result<u8> {
        self.input.get(self.pos).copied().ok_or(Error::Truncated)
    }

    fn argument(&mut self, info: u8) -> Result<u64> {
        let (value, min) = match info {
            0..=23 => return Ok(u64::from(info)),
            24 => (u64::from(self.take_array::<1>()?[0]), 24),
            25 => (u64::from(u16::from_be_bytes(self.take_array()?)), 0x100),
            26 => (u64::from(u32::from_be_bytes(self.take_array()?)), 0x1_0000),
            27 => (u64::from_be_bytes(self.take_array()?), 0x1_0000_0000),
            31 => return Err(Error::Unsupported),
            _ => return Err(Error::Malformed),
        };
        if value < min {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }

    fn length(&mut self, info: u8) -> Result<usize> {
        let n = self.argument(info)?;
        usize::try_from(n).map_err(|_| Error::LimitExceeded)
    }

    fn enter(&self, depth: usize) -> Result<usize> {
        let d = depth.checked_add(1).ok_or(Error::LimitExceeded)?;
        if d > self.limits.max_depth {
            return Err(Error::LimitExceeded);
        }
        Ok(d)
    }

    /// Rejects a declared item count before any allocation: every item needs at least one input
    /// byte and one unit of the item budget.
    fn check_count(&self, count: usize, per_entry: usize) -> Result<()> {
        let needed = count.checked_mul(per_entry).ok_or(Error::LimitExceeded)?;
        let budget = self.items.checked_add(needed).ok_or(Error::LimitExceeded)?;
        if budget > self.limits.max_items {
            return Err(Error::LimitExceeded);
        }
        if needed > self.remaining() {
            return Err(Error::Truncated);
        }
        Ok(())
    }

    fn item(&mut self, depth: usize) -> Result<Value> {
        self.items = self.items.checked_add(1).ok_or(Error::LimitExceeded)?;
        if self.items > self.limits.max_items {
            return Err(Error::LimitExceeded);
        }
        let initial = self.take_array::<1>()?[0];
        let info = initial & INFO_MASK;
        match initial & MAJOR_MASK {
            MAJOR_UNSIGNED => Ok(Value::Unsigned(self.argument(info)?)),
            MAJOR_NEGATIVE => Ok(Value::Negative(self.argument(info)?)),
            MAJOR_BYTES => {
                let len = self.length(info)?;
                Ok(Value::Bytes(self.take(len)?.to_vec()))
            }
            MAJOR_TEXT => {
                let len = self.length(info)?;
                let raw = self.take(len)?;
                let text = core::str::from_utf8(raw).map_err(|_| Error::InvalidUtf8)?;
                Ok(Value::Text(text.to_owned()))
            }
            MAJOR_ARRAY => {
                let count = self.length(info)?;
                let depth = self.enter(depth)?;
                self.check_count(count, 1)?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(self.item(depth)?);
                }
                Ok(Value::Array(items))
            }
            MAJOR_MAP => self.map(info, depth),
            MAJOR_TAG => Err(Error::Unsupported),
            _ => match initial {
                SIMPLE_FALSE => Ok(Value::Bool(false)),
                SIMPLE_TRUE => Ok(Value::Bool(true)),
                SIMPLE_NULL => Ok(Value::Null),
                0xfc..=0xfe => Err(Error::Malformed),
                _ => Err(Error::Unsupported),
            },
        }
    }

    fn map(&mut self, info: u8, depth: usize) -> Result<Value> {
        let count = self.length(info)?;
        let depth = self.enter(depth)?;
        self.check_count(count, 2)?;
        let canonical = self.limits.require_canonical;
        let mut entries = Vec::with_capacity(count);
        let mut raw_keys: Vec<&'a [u8]> = Vec::new();
        if !canonical {
            raw_keys.reserve(count);
        }
        let mut previous: Option<&'a [u8]> = None;
        for _ in 0..count {
            let start = self.pos;
            if !matches!(
                self.peek()? & MAJOR_MASK,
                MAJOR_UNSIGNED | MAJOR_NEGATIVE | MAJOR_TEXT
            ) {
                return Err(Error::Unsupported);
            }
            let key = self.item(depth)?;
            let raw = self.input.get(start..self.pos).ok_or(Error::Malformed)?;
            if let Some(prev) = previous {
                match cmp_keys(prev, raw) {
                    Ordering::Less => {}
                    Ordering::Equal => return Err(Error::DuplicateKey),
                    Ordering::Greater if canonical => return Err(Error::NonCanonical),
                    Ordering::Greater => {}
                }
            }
            previous = Some(raw);
            if !canonical {
                raw_keys.push(raw);
            }
            let value = self.item(depth)?;
            entries.push((key, value));
        }
        if !canonical {
            raw_keys.sort_unstable_by(|a, b| cmp_keys(a, b));
            if raw_keys.windows(2).any(|w| matches!(w, [a, b] if a == b)) {
                return Err(Error::DuplicateKey);
            }
        }
        Ok(Value::Map(entries))
    }
}

/// CTAP2 key order over encoded keys: major type, then length, then bytes.
fn cmp_keys(a: &[u8], b: &[u8]) -> Ordering {
    let major = |k: &[u8]| k.first().map(|x| x & MAJOR_MASK);
    major(a)
        .cmp(&major(b))
        .then(a.len().cmp(&b.len()))
        .then_with(|| a.cmp(b))
}

/// Encodes `value` in CTAP2 canonical form; fails on duplicate or unsupported map keys.
pub fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encode_into(value, &mut out)?;
    Ok(out)
}

fn encode_into(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Unsigned(n) => write_head(out, MAJOR_UNSIGNED, *n),
        Value::Negative(n) => write_head(out, MAJOR_NEGATIVE, *n),
        Value::Bytes(b) => write_bytes(out, b),
        Value::Text(t) => write_text(out, t),
        Value::Array(items) => {
            write_head(out, MAJOR_ARRAY, len_u64(items.len()));
            for item in items {
                encode_into(item, out)?;
            }
        }
        Value::Map(entries) => {
            let mut keyed = Vec::with_capacity(entries.len());
            for (k, v) in entries {
                if !matches!(k, Value::Unsigned(_) | Value::Negative(_) | Value::Text(_)) {
                    return Err(Error::Unsupported);
                }
                let mut kb = Vec::new();
                encode_into(k, &mut kb)?;
                keyed.push((kb, v));
            }
            keyed.sort_by(|a, b| cmp_keys(&a.0, &b.0));
            if keyed.windows(2).any(|w| matches!(w, [a, b] if a.0 == b.0)) {
                return Err(Error::DuplicateKey);
            }
            write_head(out, MAJOR_MAP, len_u64(keyed.len()));
            for (k, v) in keyed {
                out.extend_from_slice(&k);
                encode_into(v, out)?;
            }
        }
        Value::Bool(false) => out.push(SIMPLE_FALSE),
        Value::Bool(true) => out.push(SIMPLE_TRUE),
        Value::Null => out.push(SIMPLE_NULL),
    }
    Ok(())
}

fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// Initial byte and argument in shortest form.
pub(crate) fn write_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    if let Ok(small) = u8::try_from(arg) {
        if small < 24 {
            out.push(major | small);
        } else {
            out.push(major | 24);
            out.push(small);
        }
    } else if let Ok(v) = u16::try_from(arg) {
        out.push(major | 25);
        out.extend_from_slice(&v.to_be_bytes());
    } else if let Ok(v) = u32::try_from(arg) {
        out.push(major | 26);
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

pub(crate) fn write_int(out: &mut Vec<u8>, v: i64) {
    match u64::try_from(v) {
        Ok(u) => write_head(out, MAJOR_UNSIGNED, u),
        Err(_) => write_head(out, MAJOR_NEGATIVE, (!v).unsigned_abs()),
    }
}

pub(crate) fn write_bytes(out: &mut Vec<u8>, b: &[u8]) {
    write_head(out, MAJOR_BYTES, len_u64(b.len()));
    out.extend_from_slice(b);
}

pub(crate) fn write_text(out: &mut Vec<u8>, t: &str) {
    write_head(out, MAJOR_TEXT, len_u64(t.len()));
    out.extend_from_slice(t.as_bytes());
}

pub(crate) fn write_map_header(out: &mut Vec<u8>, len: usize) {
    write_head(out, MAJOR_MAP, len_u64(len));
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::wipe;

    fn strict() -> Limits {
        Limits::default()
    }

    #[test]
    fn a_decoded_value_wipes_its_bytes_and_text_when_it_is_dropped() {
        let value = MapBuilder::new()
            .int(1, vec![7u8; 8])
            .text("k", "secret")
            .int(
                3,
                Value::Array(vec![Value::from(vec![1u8, 2, 3]), Value::from("xy")]),
            )
            .build();
        let bytes = encode(&value).unwrap();
        drop(value);
        let _ = wipe::take_wiped();
        let decoded = decode(&bytes, &strict()).unwrap();
        assert_eq!(wipe::take_wiped(), 0);
        drop(decoded);
        // 8 bytes, the key "k", "secret", 3 bytes, "xy"
        assert_eq!(wipe::take_wiped(), 8 + 1 + 6 + 3 + 2);
    }

    #[test]
    fn a_decode_that_fails_wipes_what_it_had_built() {
        let _ = wipe::take_wiped();
        // An array of a 4 byte string, a text "ab" and a truncated 5 byte string.
        let input = [0x83, 0x44, 1, 2, 3, 4, 0x62, b'a', b'b', 0x45, 1, 2];
        assert_eq!(decode(&input, &strict()).unwrap_err(), Error::Truncated);
        assert_eq!(wipe::take_wiped(), 4 + 2);

        // A map whose second key repeats the first: the key and value already read.
        let dup = [0xa2, 0x61, b'k', 0x43, 9, 9, 9, 0x61, b'k', 0x01];
        assert_eq!(decode(&dup, &strict()).unwrap_err(), Error::DuplicateKey);
        assert_eq!(wipe::take_wiped(), 1 + 3 + 1);

        // Trailing bytes after a complete item.
        let trailing = [0x43, 5, 6, 7, 0x00];
        assert_eq!(
            decode(&trailing, &strict()).unwrap_err(),
            Error::TrailingBytes
        );
        assert_eq!(wipe::take_wiped(), 3);
    }

    fn lenient() -> Limits {
        Limits {
            require_canonical: false,
            ..Limits::default()
        }
    }

    #[test]
    fn integer_helpers() {
        for v in [0i64, 1, -1, 23, -24, -25, 1000, -1000, i64::MAX, i64::MIN] {
            assert_eq!(Value::int(v).as_i64(), Some(v));
            assert_eq!(Value::int(v).as_i128(), Some(i128::from(v)));
            let mut out = Vec::new();
            write_int(&mut out, v);
            assert_eq!(out, encode(&Value::int(v)).unwrap());
        }
        assert_eq!(Value::Negative(u64::MAX).as_i64(), None);
        assert_eq!(
            Value::Negative(u64::MAX).as_i128(),
            Some(-18_446_744_073_709_551_616)
        );
    }

    #[test]
    fn non_shortest_rejected() {
        for hex in [
            &[0x18, 0x17][..],
            &[0x19, 0x00, 0xff],
            &[0x1a, 0x00, 0x00, 0xff, 0xff],
            &[0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
            &[0x38, 0x00],
            &[0x58, 0x01, 0x00],
            &[0x78, 0x00],
            &[0x98, 0x00],
            &[0xb8, 0x00],
        ] {
            assert_eq!(decode(hex, &strict()), Err(Error::NonCanonical), "{hex:x?}");
            assert_eq!(decode(hex, &lenient()), Err(Error::NonCanonical));
        }
    }

    #[test]
    fn map_order_and_duplicates() {
        let unsorted = [0xa2, 0x02, 0x00, 0x01, 0x00];
        assert_eq!(decode(&unsorted, &strict()), Err(Error::NonCanonical));
        assert!(decode(&unsorted, &lenient()).is_ok());
        let dup = [0xa2, 0x01, 0x00, 0x01, 0x01];
        assert_eq!(decode(&dup, &strict()), Err(Error::DuplicateKey));
        assert_eq!(decode(&dup, &lenient()), Err(Error::DuplicateKey));
        let dup_far = [0xa3, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00];
        assert_eq!(decode(&dup_far, &strict()), Err(Error::NonCanonical));
        assert_eq!(decode(&dup_far, &lenient()), Err(Error::DuplicateKey));
        // CTAP2 sorts by major type first: 24 (major 0) before -1 (major 1), ints before text.
        assert!(decode(&[0xa2, 0x18, 0x18, 0x00, 0x20, 0x00], &strict()).is_ok());
        assert_eq!(
            decode(&[0xa2, 0x20, 0x00, 0x18, 0x18, 0x00], &strict()),
            Err(Error::NonCanonical)
        );
        assert!(decode(&[0xa2, 0x19, 0x03, 0xe8, 0x00, 0x61, 0x61, 0x00], &strict()).is_ok());
        assert_eq!(
            decode(&[0xa2, 0x61, 0x61, 0x00, 0x01, 0x00], &strict()),
            Err(Error::NonCanonical)
        );
        assert!(decode(&[0xa2, 0x61, 0x62, 0x00, 0x62, 0x61, 0x61, 0x00], &strict()).is_ok());
        assert_eq!(
            decode(&[0xa2, 0x62, 0x61, 0x61, 0x00, 0x61, 0x62, 0x00], &strict()),
            Err(Error::NonCanonical)
        );
    }

    #[test]
    fn unsupported_keys() {
        assert_eq!(
            decode(&[0xa1, 0x40, 0x00], &strict()),
            Err(Error::Unsupported)
        );
        assert_eq!(
            decode(&[0xa1, 0x80, 0x00], &strict()),
            Err(Error::Unsupported)
        );
        let v = Value::Map(vec![(Value::Null, Value::Null)]);
        assert_eq!(encode(&v), Err(Error::Unsupported));
    }

    #[test]
    fn encoder_sorts_and_rejects_duplicates() {
        let v = MapBuilder::new()
            .text("b", 1)
            .int(-1, 2)
            .text("aa", 3)
            .int(24, 4)
            .int(1, 5)
            .text("a", 6)
            .build();
        let enc = encode(&v).unwrap();
        assert_eq!(
            enc,
            [
                0xa6, 0x01, 0x05, 0x18, 0x18, 0x04, 0x20, 0x02, 0x61, 0x61, 0x06, 0x61, 0x62, 0x01,
                0x62, 0x61, 0x61, 0x03
            ]
        );
        assert!(decode(&enc, &strict()).is_ok());
        let dup = MapBuilder::new().int(1, 1).int(1, 2).build();
        assert_eq!(encode(&dup), Err(Error::DuplicateKey));
    }

    #[test]
    fn lookup_helpers() {
        let v = MapBuilder::new()
            .int(1, "x")
            .text("k", vec![1u8, 2])
            .int(-2, true)
            .build();
        assert_eq!(v.get_int(1).and_then(Value::as_text), Some("x"));
        assert_eq!(
            v.get_text("k").and_then(Value::as_bytes),
            Some(&[1u8, 2][..])
        );
        assert_eq!(v.get_int(-2).and_then(Value::as_bool), Some(true));
        assert!(v.get_int(2).is_none());
        assert!(Value::Null.get_int(1).is_none());
    }

    #[test]
    fn depth_limit() {
        let mut ok = vec![0x81u8; 8];
        ok.push(0x00);
        assert!(decode(&ok, &strict()).is_ok());
        let mut deep = vec![0x81u8; 9];
        deep.push(0x00);
        assert_eq!(decode(&deep, &strict()), Err(Error::LimitExceeded));
        let mut maps = Vec::new();
        for _ in 0..9 {
            maps.extend_from_slice(&[0xa1, 0x01]);
        }
        maps.push(0x00);
        assert_eq!(decode(&maps, &strict()), Err(Error::LimitExceeded));
    }

    #[test]
    fn huge_declared_lengths() {
        let cases: [&[u8]; 8] = [
            &[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            &[0x7b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x61],
            &[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            &[0xbb, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01],
            &[0x5a, 0xff, 0xff, 0xff, 0xff, 0x00],
            &[0x9a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            &[0xba, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            &[0x99, 0x01, 0x00, 0x00],
        ];
        for c in cases {
            let r = decode(c, &strict());
            assert!(
                matches!(r, Err(Error::Truncated | Error::LimitExceeded)),
                "{c:x?}: {r:?}"
            );
        }
    }

    #[test]
    fn item_and_length_limits() {
        let limits = Limits {
            max_items: 3,
            ..Limits::default()
        };
        assert!(decode(&[0x82, 0x01, 0x02], &limits).is_ok());
        assert_eq!(
            decode(&[0x83, 0x01, 0x02, 0x03], &limits),
            Err(Error::LimitExceeded)
        );
        let limits = Limits {
            max_len: 2,
            ..Limits::default()
        };
        assert_eq!(
            decode(&[0x42, 0x00, 0x00], &limits),
            Err(Error::LimitExceeded)
        );
    }

    #[test]
    fn invalid_utf8_and_trailing() {
        assert_eq!(decode(&[0x61, 0xff], &strict()), Err(Error::InvalidUtf8));
        assert_eq!(
            decode(&[0x63, 0xed, 0xa0, 0x80], &strict()),
            Err(Error::InvalidUtf8)
        );
        assert_eq!(decode(&[0x01, 0x02], &strict()), Err(Error::TrailingBytes));
        assert_eq!(decode(&[], &strict()), Err(Error::Truncated));
    }
}
