//! Small strict JSON (RFC 8259) reader and writer for untrusted messages.
//!
//! The reader accepts only UTF-8 input without a byte order mark, rejects duplicate object
//! keys, lone surrogate escapes, raw control characters in strings, non-finite numbers and
//! anything after the top-level value except whitespace.

use crate::{Error, Result};
use core::fmt;

/// Parser limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum input length in bytes.
    pub max_len: usize,
    /// Maximum nesting of arrays and objects.
    pub max_depth: usize,
    /// Maximum total number of values.
    pub max_items: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_len: 1_048_576,
            max_depth: 16,
            max_items: 65_536,
        }
    }
}

/// A JSON number: a finite `f64`, plus the exact value when written as a plain integer.
#[derive(Debug, Clone, Copy)]
pub struct Number {
    value: f64,
    exact: Option<i128>,
}

impl Number {
    /// Wraps a finite `f64`; `None` for NaN and infinities.
    pub fn from_f64(value: f64) -> Option<Number> {
        value.is_finite().then_some(Number { value, exact: None })
    }

    /// The value as `f64` (may be rounded for large integers).
    pub fn as_f64(&self) -> f64 {
        self.value
    }

    /// The exact value if it was a plain integer in `u64` range.
    pub fn as_u64(&self) -> Option<u64> {
        self.exact.and_then(|e| u64::try_from(e).ok())
    }

    /// The exact value if it was a plain integer in `i64` range.
    pub fn as_i64(&self) -> Option<i64> {
        self.exact.and_then(|e| i64::try_from(e).ok())
    }
}

impl PartialEq for Number {
    fn eq(&self, other: &Self) -> bool {
        match (self.exact, other.exact) {
            (Some(a), Some(b)) => a == b,
            _ => self.value == other.value,
        }
    }
}

impl From<u64> for Number {
    fn from(v: u64) -> Self {
        Number {
            value: v as f64,
            exact: Some(i128::from(v)),
        }
    }
}

impl From<i64> for Number {
    fn from(v: i64) -> Self {
        Number {
            value: v as f64,
            exact: Some(i128::from(v)),
        }
    }
}

/// A JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A finite number.
    Number(Number),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Json>),
    /// An object with members in document order and unique keys.
    Object(Vec<(String, Json)>),
}

impl Json {
    /// Looks up a member of an object.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Returns the string value.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the boolean value.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Returns the number.
    pub fn as_number(&self) -> Option<&Number> {
        match self {
            Json::Number(n) => Some(n),
            _ => None,
        }
    }

    /// Returns an exact non-negative integer.
    pub fn as_u64(&self) -> Option<u64> {
        self.as_number()?.as_u64()
    }

    /// Returns an exact integer.
    pub fn as_i64(&self) -> Option<i64> {
        self.as_number()?.as_i64()
    }

    /// Returns the array items.
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Returns the object members.
    pub fn as_object(&self) -> Option<&[(String, Json)]> {
        match self {
            Json::Object(m) => Some(m),
            _ => None,
        }
    }

    /// True for `null`.
    pub fn is_null(&self) -> bool {
        matches!(self, Json::Null)
    }
}

impl From<bool> for Json {
    fn from(v: bool) -> Self {
        Json::Bool(v)
    }
}

impl From<&str> for Json {
    fn from(v: &str) -> Self {
        Json::String(v.to_owned())
    }
}

impl From<String> for Json {
    fn from(v: String) -> Self {
        Json::String(v)
    }
}

impl From<u64> for Json {
    fn from(v: u64) -> Self {
        Json::Number(Number::from(v))
    }
}

impl From<i64> for Json {
    fn from(v: i64) -> Self {
        Json::Number(Number::from(v))
    }
}

/// Parses one JSON text from `input`.
pub fn parse(input: &[u8], limits: &Limits) -> Result<Json> {
    if input.len() > limits.max_len {
        return Err(Error::LimitExceeded);
    }
    let text = core::str::from_utf8(input).map_err(|_| Error::InvalidUtf8)?;
    let mut p = Parser {
        s: text.as_bytes(),
        pos: 0,
        limits,
        items: 0,
    };
    p.skip_ws();
    let value = p.value(0)?;
    p.skip_ws();
    if p.pos != p.s.len() {
        return Err(Error::TrailingBytes);
    }
    Ok(value)
}

struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
    limits: &'a Limits,
    items: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }

    fn bump(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    fn next(&mut self) -> Result<u8> {
        let b = self.peek().ok_or(Error::Truncated)?;
        self.bump();
        Ok(b)
    }

    fn expect(&mut self, b: u8) -> Result<()> {
        if self.next()? != b {
            return Err(Error::Malformed);
        }
        Ok(())
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump();
        }
    }

    fn literal(&mut self, word: &[u8], value: Json) -> Result<Json> {
        let end = self.pos.saturating_add(word.len());
        match self.s.get(self.pos..end) {
            Some(w) if w == word => {
                self.pos = end;
                Ok(value)
            }
            Some(_) => Err(Error::Malformed),
            None => match self.s.get(self.pos..) {
                Some(rest) if word.starts_with(rest) => Err(Error::Truncated),
                _ => Err(Error::Malformed),
            },
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json> {
        self.items = self.items.checked_add(1).ok_or(Error::LimitExceeded)?;
        if self.items > self.limits.max_items {
            return Err(Error::LimitExceeded);
        }
        match self.peek().ok_or(Error::Truncated)? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => Ok(Json::String(self.string()?)),
            b't' => self.literal(b"true", Json::Bool(true)),
            b'f' => self.literal(b"false", Json::Bool(false)),
            b'n' => self.literal(b"null", Json::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(Error::Malformed),
        }
    }

    fn enter(&self, depth: usize) -> Result<usize> {
        let d = depth.checked_add(1).ok_or(Error::LimitExceeded)?;
        if d > self.limits.max_depth {
            return Err(Error::LimitExceeded);
        }
        Ok(d)
    }

    fn array(&mut self, depth: usize) -> Result<Json> {
        let depth = self.enter(depth)?;
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.bump();
            return Ok(Json::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth)?);
            self.skip_ws();
            match self.next()? {
                b',' => {}
                b']' => return Ok(Json::Array(items)),
                _ => return Err(Error::Malformed),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json> {
        let depth = self.enter(depth)?;
        self.expect(b'{')?;
        let mut members = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.bump();
            return Ok(Json::Object(members));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(if self.peek().is_none() {
                    Error::Truncated
                } else {
                    Error::Malformed
                });
            }
            let key = self.string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let value = self.value(depth)?;
            members.push((key, value));
            self.skip_ws();
            match self.next()? {
                b',' => {}
                b'}' => break,
                _ => return Err(Error::Malformed),
            }
        }
        let mut keys: Vec<&str> = members.iter().map(|(k, _)| k.as_str()).collect();
        keys.sort_unstable();
        if keys.windows(2).any(|w| matches!(w, [a, b] if a == b)) {
            return Err(Error::DuplicateKey);
        }
        Ok(Json::Object(members))
    }

    fn hex4(&mut self) -> Result<u16> {
        let end = self.pos.saturating_add(4);
        let digits = self.s.get(self.pos..end).ok_or(Error::Truncated)?;
        if !digits.iter().all(u8::is_ascii_hexdigit) {
            return Err(Error::Malformed);
        }
        let text = core::str::from_utf8(digits).map_err(|_| Error::Malformed)?;
        let unit = u16::from_str_radix(text, 16).map_err(|_| Error::Malformed)?;
        self.pos = end;
        Ok(unit)
    }

    fn escape(&mut self, out: &mut String) -> Result<()> {
        let c = match self.next()? {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let unit = self.hex4()?;
                match unit {
                    0xd800..=0xdbff => {
                        self.expect(b'\\')?;
                        self.expect(b'u')?;
                        let low = self.hex4()?;
                        if !(0xdc00..=0xdfff).contains(&low) {
                            return Err(Error::InvalidUtf8);
                        }
                        match char::decode_utf16([unit, low]).next() {
                            Some(Ok(c)) => c,
                            _ => return Err(Error::InvalidUtf8),
                        }
                    }
                    0xdc00..=0xdfff => return Err(Error::InvalidUtf8),
                    _ => char::from_u32(u32::from(unit)).ok_or(Error::InvalidUtf8)?,
                }
            }
            _ => return Err(Error::Malformed),
        };
        out.push(c);
        Ok(())
    }

    fn string(&mut self) -> Result<String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let start = self.pos;
            while matches!(self.peek(), Some(b) if b != b'"' && b != b'\\' && b >= 0x20) {
                self.bump();
            }
            let run = self.s.get(start..self.pos).ok_or(Error::Malformed)?;
            out.push_str(core::str::from_utf8(run).map_err(|_| Error::InvalidUtf8)?);
            match self.next()? {
                b'"' => return Ok(out),
                b'\\' => self.escape(&mut out)?,
                _ => return Err(Error::Malformed),
            }
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.bump();
        }
        self.pos.saturating_sub(start)
    }

    fn number(&mut self) -> Result<Json> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.bump();
        }
        match self.peek() {
            Some(b'0') => self.bump(),
            Some(b'1'..=b'9') => {
                self.digits();
            }
            Some(_) => return Err(Error::Malformed),
            None => return Err(Error::Truncated),
        }
        let mut integral = true;
        if self.peek() == Some(b'.') {
            integral = false;
            self.bump();
            if self.digits() == 0 {
                return Err(self.peek().map_or(Error::Truncated, |_| Error::Malformed));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            integral = false;
            self.bump();
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.bump();
            }
            if self.digits() == 0 {
                return Err(self.peek().map_or(Error::Truncated, |_| Error::Malformed));
            }
        }
        let raw = self.s.get(start..self.pos).ok_or(Error::Malformed)?;
        let text = core::str::from_utf8(raw).map_err(|_| Error::Malformed)?;
        let value: f64 = text.parse().map_err(|_| Error::Malformed)?;
        if !value.is_finite() {
            return Err(Error::InvalidValue);
        }
        let exact = if integral {
            text.parse::<i128>().ok()
        } else {
            None
        };
        Ok(Json::Number(Number { value, exact }))
    }
}

fn write_string(f: &mut fmt::Formatter<'_>, s: &str) -> fmt::Result {
    f.write_str("\"")?;
    for c in s.chars() {
        match c {
            '"' => f.write_str("\\\"")?,
            '\\' => f.write_str("\\\\")?,
            '\n' => f.write_str("\\n")?,
            '\r' => f.write_str("\\r")?,
            '\t' => f.write_str("\\t")?,
            '\u{8}' => f.write_str("\\b")?,
            '\u{c}' => f.write_str("\\f")?,
            '\u{0}'..='\u{1f}' => write!(f, "\\u{:04x}", u32::from(c))?,
            _ => fmt::Write::write_char(f, c)?,
        }
    }
    f.write_str("\"")
}

/// Writes compact JSON. Callers must not build objects with duplicate keys.
impl fmt::Display for Json {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Json::Null => f.write_str("null"),
            Json::Bool(true) => f.write_str("true"),
            Json::Bool(false) => f.write_str("false"),
            Json::Number(n) => match n.exact {
                Some(e) => write!(f, "{e}"),
                None => write!(f, "{}", n.value),
            },
            Json::String(s) => write_string(f, s),
            Json::Array(items) => {
                f.write_str("[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    item.fmt(f)?;
                }
                f.write_str("]")
            }
            Json::Object(members) => {
                f.write_str("{")?;
                for (i, (k, v)) in members.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    write_string(f, k)?;
                    f.write_str(":")?;
                    v.fmt(f)?;
                }
                f.write_str("}")
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<Json> {
        parse(s.as_bytes(), &Limits::default())
    }

    #[test]
    fn basic_values() {
        assert_eq!(p("null").unwrap(), Json::Null);
        assert_eq!(p(" true ").unwrap(), Json::Bool(true));
        assert_eq!(p("\t\r\nfalse").unwrap(), Json::Bool(false));
        assert_eq!(p("\"x\"").unwrap(), Json::from("x"));
        let v = p(r#"{"a":[1,-2,3.5,"s",{"b":null}],"c":{}}"#).unwrap();
        assert_eq!(v.get("a").unwrap().as_array().unwrap().len(), 5);
        assert_eq!(
            v.get("a").unwrap().as_array().unwrap()[1].as_i64(),
            Some(-2)
        );
        assert_eq!(v.to_string(), r#"{"a":[1,-2,3.5,"s",{"b":null}],"c":{}}"#);
    }

    #[test]
    fn numbers() {
        assert_eq!(p("0").unwrap().as_u64(), Some(0));
        assert_eq!(p("-0").unwrap().as_i64(), Some(0));
        assert_eq!(p("18446744073709551615").unwrap().as_u64(), Some(u64::MAX));
        assert_eq!(p("18446744073709551616").unwrap().as_u64(), None);
        assert_eq!(
            p("9007199254740993").unwrap().as_u64(),
            Some(9_007_199_254_740_993)
        );
        assert_eq!(p("-9223372036854775808").unwrap().as_i64(), Some(i64::MIN));
        assert_eq!(p("-1").unwrap().as_u64(), None);
        assert_eq!(p("1.5e3").unwrap().as_number().unwrap().as_f64(), 1500.0);
        assert_eq!(p("1.5e3").unwrap().as_u64(), None);
        assert_eq!(p("1E-2").unwrap().as_number().unwrap().as_f64(), 0.01);
        assert_eq!(p("1e-400").unwrap().as_number().unwrap().as_f64(), 0.0);
        let long = "1".repeat(300);
        assert!(p(&long).unwrap().as_u64().is_none());
        for bad in [
            "01",
            "1.",
            ".5",
            "+1",
            "1e",
            "1e+",
            "-",
            "--1",
            "0x10",
            "1.e3",
            "NaN",
            "Infinity",
            "-Infinity",
        ] {
            assert!(p(bad).is_err(), "{bad}");
        }
        assert_eq!(p("1e400"), Err(Error::InvalidValue));
        assert_eq!(p("-1e400"), Err(Error::InvalidValue));
    }

    #[test]
    fn strings_and_escapes() {
        assert_eq!(
            p(r#""\"\\\/\b\f\n\r\t\u0041\u00e9""#).unwrap(),
            Json::from("\"\\/\u{8}\u{c}\n\r\tA\u{e9}")
        );
        assert_eq!(p(r#""\ud83d\ude00""#).unwrap(), Json::from("\u{1f600}"));
        assert_eq!(p(r#""\uD83D\uDE00""#).unwrap(), Json::from("\u{1f600}"));
        assert_eq!(p(r#""\u0000""#).unwrap(), Json::from("\u{0}"));
        assert_eq!(
            p("\"\u{e9}\u{1f600}\"").unwrap(),
            Json::from("\u{e9}\u{1f600}")
        );
        for bad in [
            r#""\ud800""#,
            r#""\udc00""#,
            r#""\ud800\u0041""#,
            r#""\ud800x""#,
            r#""\ude00\ud83d""#,
            r#""\u12""#,
            r#""\u+123""#,
            r#""\x""#,
            "\"a\u{1}b\"",
            "\"tab\there\"",
            "\"open",
            "\"\\",
        ] {
            assert!(p(bad).is_err(), "{bad}");
        }
        assert!(parse(b"\"\xff\"", &Limits::default()).is_err());
        assert!(parse(b"\"\xed\xa0\x80\"", &Limits::default()).is_err());
        assert!(parse(b"\xef\xbb\xbfnull", &Limits::default()).is_err());
    }

    #[test]
    fn structure_errors() {
        for bad in [
            "",
            " ",
            "[1,]",
            "[,1]",
            "{\"a\":1,}",
            "{,}",
            "{\"a\"}",
            "{\"a\" 1}",
            "{1:2}",
            "[1 2]",
            "[",
            "{",
            "nul",
            "truex",
            "null null",
            "[1]]",
            "{'a':1}",
            "tru",
        ] {
            assert!(p(bad).is_err(), "{bad:?}");
        }
        assert_eq!(p(r#"{"a":1,"a":2}"#), Err(Error::DuplicateKey));
        assert_eq!(p(r#"{"a":1,"b":{"c":1,"c":1}}"#), Err(Error::DuplicateKey));
        assert_eq!(p(r#"{"a":1,"\u0061":2}"#), Err(Error::DuplicateKey));
        assert_eq!(p("[1] x"), Err(Error::TrailingBytes));
    }

    #[test]
    fn limits() {
        let ok = format!("{}{}", "[".repeat(16), "]".repeat(16));
        assert!(p(&ok).is_ok());
        let deep = format!("{}{}", "[".repeat(17), "]".repeat(17));
        assert_eq!(p(&deep), Err(Error::LimitExceeded));
        let hostile = "[".repeat(100_000);
        assert_eq!(p(&hostile), Err(Error::LimitExceeded));
        let objs = format!("{}1{}", "{\"a\":".repeat(17), "}".repeat(17));
        assert_eq!(p(&objs), Err(Error::LimitExceeded));
        let small = Limits {
            max_items: 3,
            ..Limits::default()
        };
        assert!(parse(b"[1,2]", &small).is_ok());
        assert_eq!(parse(b"[1,2,3]", &small), Err(Error::LimitExceeded));
        let short = Limits {
            max_len: 4,
            ..Limits::default()
        };
        assert!(parse(b"true", &short).is_ok());
        assert_eq!(parse(b"false", &short), Err(Error::LimitExceeded));
    }

    #[test]
    fn writer_escapes() {
        let v = Json::Object(vec![(
            "k\"\\\n".to_owned(),
            Json::from("\u{1}\u{8}\u{c}\r\t\u{7f}\u{e9}\u{2028}"),
        )]);
        let s = v.to_string();
        assert_eq!(
            s,
            "{\"k\\\"\\\\\\n\":\"\\u0001\\b\\f\\r\\t\u{7f}\u{e9}\u{2028}\"}"
        );
        assert_eq!(p(&s).unwrap(), v);
        assert_eq!(Json::from(u64::MAX).to_string(), "18446744073709551615");
        assert_eq!(Json::from(i64::MIN).to_string(), "-9223372036854775808");
        assert_eq!(
            Json::Number(Number::from_f64(0.1).unwrap()).to_string(),
            "0.1"
        );
        assert!(Number::from_f64(f64::NAN).is_none());
        assert!(Number::from_f64(f64::INFINITY).is_none());
        let big = Json::Number(Number::from_f64(1e300).unwrap());
        assert_eq!(p(&big.to_string()).unwrap(), big);
    }
}
