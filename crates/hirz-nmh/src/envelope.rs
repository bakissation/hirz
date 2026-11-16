//! Minimal strict reader for the request envelope.
//!
//! It validates the whole message as RFC 8259 JSON (structure, string escapes,
//! number grammar, UTF-8, nesting depth) but only extracts the top-level `v`,
//! `id` and `type` members. Everything else stays opaque until the full JSON
//! parser from hirz-proto is wired in.

use std::fmt;

const MAX_DEPTH: usize = 64;

/// Largest integer that survives a round trip through a JavaScript number.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

pub const PROTOCOL_VERSION: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    Hello,
    Capabilities,
    Create,
    Get,
    Cancel,
}

impl MsgType {
    fn from_bytes(raw: &[u8]) -> Option<Self> {
        match raw {
            b"hello" => Some(Self::Hello),
            b"capabilities" => Some(Self::Capabilities),
            b"create" => Some(Self::Create),
            b"get" => Some(Self::Get),
            b"cancel" => Some(Self::Cancel),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hello => "hello",
            Self::Capabilities => "capabilities",
            Self::Create => "create",
            Self::Get => "get",
            Self::Cancel => "cancel",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Envelope {
    pub id: u64,
    pub kind: MsgType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Not valid JSON, not an object, or a member we read has the wrong shape.
    Malformed,
    /// `v` is missing or not a version we speak.
    UnsupportedVersion,
    /// `type` is missing or unknown.
    UnknownType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeError {
    pub kind: ErrorKind,
    /// The request id, when the message was well formed enough to trust it.
    pub id: Option<u64>,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.kind {
            ErrorKind::Malformed => "malformed envelope",
            ErrorKind::UnsupportedVersion => "unsupported protocol version",
            ErrorKind::UnknownType => "unknown message type",
        };
        f.write_str(what)
    }
}

impl std::error::Error for EnvelopeError {}

const fn malformed() -> EnvelopeError {
    EnvelopeError {
        kind: ErrorKind::Malformed,
        id: None,
    }
}

/// Parses the envelope of one inbound message.
pub fn parse(input: &[u8]) -> Result<Envelope, EnvelopeError> {
    if std::str::from_utf8(input).is_err() {
        return Err(malformed());
    }
    let mut s = Scanner { buf: input, pos: 0 };
    let fields = s.top_level().map_err(|()| malformed())?;

    let id = fields.id.ok_or_else(malformed)?;
    if fields.v != Some(PROTOCOL_VERSION) {
        return Err(EnvelopeError {
            kind: ErrorKind::UnsupportedVersion,
            id: Some(id),
        });
    }
    let kind = fields
        .kind
        .and_then(|(start, end)| input.get(start..end))
        .and_then(MsgType::from_bytes)
        .ok_or(EnvelopeError {
            kind: ErrorKind::UnknownType,
            id: Some(id),
        })?;
    Ok(Envelope { id, kind })
}

#[derive(Default)]
struct Fields {
    v: Option<u64>,
    id: Option<u64>,
    kind: Option<(usize, usize)>,
}

struct Scanner<'a> {
    buf: &'a [u8],
    pos: usize,
}

type Res<T> = Result<T, ()>;

struct StrSpan {
    start: usize,
    end: usize,
    escaped: bool,
}

struct NumSpan {
    start: usize,
    end: usize,
    plain_uint: bool,
}

impl Scanner<'_> {
    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    fn bump(&mut self) -> Res<()> {
        self.pos = self.pos.checked_add(1).ok_or(())?;
        Ok(())
    }

    fn next(&mut self) -> Res<u8> {
        let b = self.peek().ok_or(())?;
        self.bump()?;
        Ok(b)
    }

    fn expect(&mut self, want: u8) -> Res<()> {
        if self.next()? == want {
            Ok(())
        } else {
            Err(())
        }
    }

    fn skip_ws(&mut self) -> Res<()> {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.peek() {
            self.bump()?;
        }
        Ok(())
    }

    fn top_level(&mut self) -> Res<Fields> {
        let mut fields = Fields::default();
        self.skip_ws()?;
        self.expect(b'{')?;
        self.skip_ws()?;
        if self.peek() == Some(b'}') {
            self.bump()?;
        } else {
            loop {
                self.skip_ws()?;
                let key = self.string()?;
                self.skip_ws()?;
                self.expect(b':')?;
                self.skip_ws()?;
                let name = if key.escaped {
                    None
                } else {
                    self.buf.get(key.start..key.end)
                };
                match name {
                    Some(b"v") => {
                        let n = self.number()?;
                        if fields.v.replace(self.uint(&n)?).is_some() {
                            return Err(());
                        }
                    }
                    Some(b"id") => {
                        let n = self.number()?;
                        if fields.id.replace(self.uint(&n)?).is_some() {
                            return Err(());
                        }
                    }
                    Some(b"type") => {
                        if self.peek() != Some(b'"') {
                            return Err(());
                        }
                        let t = self.string()?;
                        if t.escaped || fields.kind.replace((t.start, t.end)).is_some() {
                            return Err(());
                        }
                    }
                    _ => self.value(1)?,
                }
                self.skip_ws()?;
                match self.next()? {
                    b',' => continue,
                    b'}' => break,
                    _ => return Err(()),
                }
            }
        }
        self.skip_ws()?;
        if self.pos == self.buf.len() {
            Ok(fields)
        } else {
            Err(())
        }
    }

    fn value(&mut self, depth: usize) -> Res<()> {
        match self.peek().ok_or(())? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => self.string().map(|_| ()),
            b'-' | b'0'..=b'9' => self.number().map(|_| ()),
            b't' => self.literal(b"true"),
            b'f' => self.literal(b"false"),
            b'n' => self.literal(b"null"),
            _ => Err(()),
        }
    }

    fn object(&mut self, depth: usize) -> Res<()> {
        let depth = depth.checked_add(1).ok_or(())?;
        if depth > MAX_DEPTH {
            return Err(());
        }
        self.expect(b'{')?;
        self.skip_ws()?;
        if self.peek() == Some(b'}') {
            return self.bump();
        }
        loop {
            self.skip_ws()?;
            self.string()?;
            self.skip_ws()?;
            self.expect(b':')?;
            self.skip_ws()?;
            self.value(depth)?;
            self.skip_ws()?;
            match self.next()? {
                b',' => continue,
                b'}' => return Ok(()),
                _ => return Err(()),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Res<()> {
        let depth = depth.checked_add(1).ok_or(())?;
        if depth > MAX_DEPTH {
            return Err(());
        }
        self.expect(b'[')?;
        self.skip_ws()?;
        if self.peek() == Some(b']') {
            return self.bump();
        }
        loop {
            self.skip_ws()?;
            self.value(depth)?;
            self.skip_ws()?;
            match self.next()? {
                b',' => continue,
                b']' => return Ok(()),
                _ => return Err(()),
            }
        }
    }

    fn literal(&mut self, word: &[u8]) -> Res<()> {
        let end = self.pos.checked_add(word.len()).ok_or(())?;
        if self.buf.get(self.pos..end) == Some(word) {
            self.pos = end;
            Ok(())
        } else {
            Err(())
        }
    }

    fn string(&mut self) -> Res<StrSpan> {
        self.expect(b'"')?;
        let start = self.pos;
        let mut escaped = false;
        loop {
            let end = self.pos;
            match self.next()? {
                b'"' => {
                    return Ok(StrSpan {
                        start,
                        end,
                        escaped,
                    });
                }
                b'\\' => {
                    escaped = true;
                    match self.next()? {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {}
                        b'u' => {
                            for _ in 0..4 {
                                if !self.next()?.is_ascii_hexdigit() {
                                    return Err(());
                                }
                            }
                        }
                        _ => return Err(()),
                    }
                }
                0x00..=0x1f => return Err(()),
                _ => {}
            }
        }
    }

    fn digits(&mut self) -> Res<usize> {
        let mut count = 0usize;
        while let Some(b'0'..=b'9') = self.peek() {
            self.bump()?;
            count = count.checked_add(1).ok_or(())?;
        }
        Ok(count)
    }

    fn number(&mut self) -> Res<NumSpan> {
        let start = self.pos;
        let mut plain_uint = true;
        if self.peek() == Some(b'-') {
            self.bump()?;
            plain_uint = false;
        }
        match self.next()? {
            b'0' => {}
            b'1'..=b'9' => {
                self.digits()?;
            }
            _ => return Err(()),
        }
        if self.peek() == Some(b'.') {
            self.bump()?;
            plain_uint = false;
            if self.digits()? == 0 {
                return Err(());
            }
        }
        if let Some(b'e' | b'E') = self.peek() {
            self.bump()?;
            plain_uint = false;
            if let Some(b'+' | b'-') = self.peek() {
                self.bump()?;
            }
            if self.digits()? == 0 {
                return Err(());
            }
        }
        Ok(NumSpan {
            start,
            end: self.pos,
            plain_uint,
        })
    }

    fn uint(&self, n: &NumSpan) -> Res<u64> {
        if !n.plain_uint {
            return Err(());
        }
        let digits = self.buf.get(n.start..n.end).ok_or(())?;
        let mut value: u64 = 0;
        for d in digits {
            let digit = u64::from(d.checked_sub(b'0').ok_or(())?);
            value = value
                .checked_mul(10)
                .and_then(|v| v.checked_add(digit))
                .ok_or(())?;
            if value > MAX_SAFE_INTEGER {
                return Err(());
            }
        }
        Ok(value)
    }
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

    fn ok(input: &str) -> Envelope {
        parse(input.as_bytes()).unwrap_or_else(|e| panic!("{input}: {e:?}"))
    }

    fn err(input: &[u8]) -> EnvelopeError {
        match parse(input) {
            Ok(e) => panic!("{:?} parsed as {e:?}", String::from_utf8_lossy(input)),
            Err(e) => e,
        }
    }

    #[test]
    fn minimal_hello() {
        assert_eq!(
            ok(r#"{"v":1,"id":7,"type":"hello"}"#),
            Envelope {
                id: 7,
                kind: MsgType::Hello
            }
        );
    }

    #[test]
    fn all_types() {
        for (name, kind) in [
            ("hello", MsgType::Hello),
            ("capabilities", MsgType::Capabilities),
            ("create", MsgType::Create),
            ("get", MsgType::Get),
            ("cancel", MsgType::Cancel),
        ] {
            let m = format!(r#"{{"type":"{name}","id":1,"v":1}}"#);
            assert_eq!(ok(&m).kind, kind);
            assert_eq!(kind.as_str(), name);
        }
    }

    #[test]
    fn full_create_request_with_nested_decoys() {
        let m = r#" {
            "v": 1, "id": 42, "type": "create",
            "origin": "https://example.com", "topOrigin": "https://example.com",
            "crossOrigin": false,
            "options": {
                "id": 99, "type": "get", "v": 2,
                "rp": {"id": "example.com", "name": "Acme \"Corp\" \u00e9"},
                "user": {"id": "YWxpY2U", "name": "alice", "displayName": "Alice"},
                "challenge": "AAAAAAAAAAAAAAAAAAAAAA",
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -8}],
                "timeout": 6.0e4, "excludeCredentials": [], "hints": [null, true, false],
                "extensions": {"credProps": true}
            }
        } "#;
        assert_eq!(
            ok(m),
            Envelope {
                id: 42,
                kind: MsgType::Create
            }
        );
    }

    #[test]
    fn id_bounds() {
        assert_eq!(ok(r#"{"v":1,"id":0,"type":"get"}"#).id, 0);
        let max = format!(r#"{{"v":1,"id":{MAX_SAFE_INTEGER},"type":"get"}}"#);
        assert_eq!(ok(&max).id, MAX_SAFE_INTEGER);
        let over = format!(r#"{{"v":1,"id":{},"type":"get"}}"#, MAX_SAFE_INTEGER + 1);
        assert_eq!(err(over.as_bytes()).kind, ErrorKind::Malformed);
        assert_eq!(
            err(br#"{"v":1,"id":99999999999999999999999999,"type":"get"}"#).kind,
            ErrorKind::Malformed
        );
    }

    #[test]
    fn id_must_be_plain_unsigned_integer() {
        for id in [
            "-1", "1.0", "1e2", "01", "\"1\"", "null", "true", "[1]", "-0",
        ] {
            let m = format!(r#"{{"v":1,"id":{id},"type":"get"}}"#);
            let e = err(m.as_bytes());
            assert_eq!(e.kind, ErrorKind::Malformed, "{id}");
            assert_eq!(e.id, None);
        }
    }

    #[test]
    fn missing_id_is_malformed() {
        assert_eq!(err(br#"{"v":1,"type":"get"}"#).kind, ErrorKind::Malformed);
    }

    #[test]
    fn version_errors_keep_id() {
        for m in [
            r#"{"id":3,"type":"get"}"#,
            r#"{"v":2,"id":3,"type":"get"}"#,
            r#"{"v":0,"id":3,"type":"get"}"#,
        ] {
            assert_eq!(
                err(m.as_bytes()),
                EnvelopeError {
                    kind: ErrorKind::UnsupportedVersion,
                    id: Some(3)
                },
                "{m}"
            );
        }
    }

    #[test]
    fn type_errors_keep_id() {
        for m in [
            r#"{"v":1,"id":5}"#,
            r#"{"v":1,"id":5,"type":"sign"}"#,
            r#"{"v":1,"id":5,"type":"Hello"}"#,
            r#"{"v":1,"id":5,"type":""}"#,
        ] {
            assert_eq!(
                err(m.as_bytes()),
                EnvelopeError {
                    kind: ErrorKind::UnknownType,
                    id: Some(5)
                },
                "{m}"
            );
        }
    }

    #[test]
    fn type_must_be_unescaped_string() {
        assert_eq!(
            err(br#"{"v":1,"id":5,"type":"h\u0065llo"}"#).kind,
            ErrorKind::Malformed
        );
        assert_eq!(
            err(br#"{"v":1,"id":5,"type":1}"#).kind,
            ErrorKind::Malformed
        );
    }

    #[test]
    fn escaped_keys_are_not_our_members() {
        let e = err(br#"{"v":1,"\u0069d":5,"type":"get"}"#);
        assert_eq!(e.kind, ErrorKind::Malformed);
    }

    #[test]
    fn duplicate_members_rejected() {
        for m in [
            r#"{"v":1,"id":1,"id":2,"type":"get"}"#,
            r#"{"v":1,"v":1,"id":1,"type":"get"}"#,
            r#"{"v":1,"id":1,"type":"get","type":"create"}"#,
        ] {
            assert_eq!(err(m.as_bytes()).kind, ErrorKind::Malformed, "{m}");
        }
    }

    #[test]
    fn structural_errors() {
        let cases: &[&[u8]] = &[
            b"",
            b" ",
            b"[]",
            b"\"x\"",
            b"null",
            b"{",
            b"{}",
            br#"{"v":1,"id":1,"type":"get""#,
            br#"{"v":1,"id":1,"type":"get",}"#,
            br#"{"v":1,"id":1,"type":"get"} x"#,
            br#"{"v":1,"id":1,"type":"get"}{}"#,
            br#"{"v":1 "id":1,"type":"get"}"#,
            br#"{"v":1,"id":1,"type":"get","x":[1,]}"#,
            br#"{"v":1,"id":1,"type":"get","x":{"a"}}"#,
            br#"{"v":1,"id":1,"type":"get","x":tru}"#,
            br#"{"v":1,"id":1,"type":"get","x":nul}"#,
            br#"{"v":1,"id":1,"type":"get","x":01}"#,
            br#"{"v":1,"id":1,"type":"get","x":1.}"#,
            br#"{"v":1,"id":1,"type":"get","x":.5}"#,
            br#"{"v":1,"id":1,"type":"get","x":1e}"#,
            br#"{"v":1,"id":1,"type":"get","x":+1}"#,
            br#"{"v":1,"id":1,"type":"get","x":"\x"}"#,
            br#"{"v":1,"id":1,"type":"get","x":"\u12"}"#,
            br#"{"v":1,"id":1,"type":"get","x":'a'}"#,
            b"{\"v\":1,\"id\":1,\"type\":\"get\",\"x\":\"a\nb\"}",
            b"{\"v\":1,\"id\":1,\"type\":\"get\",\"x\":\"\xff\"}",
            b"\xef\xbb\xbf{\"v\":1,\"id\":1,\"type\":\"get\"}",
        ];
        for c in cases {
            assert_eq!(
                err(c).kind,
                ErrorKind::Malformed,
                "{:?}",
                String::from_utf8_lossy(c)
            );
        }
    }

    #[test]
    fn valid_values_in_unknown_members() {
        ok(r#"{"v":1,"id":1,"type":"get","a":-0.5e-3,"b":"\ud83d\ude00\/","c":[[],{}],"d":0}"#);
    }

    #[test]
    fn nesting_limit() {
        let deep_ok = format!(
            r#"{{"v":1,"id":1,"type":"get","x":{}{}}}"#,
            "[".repeat(MAX_DEPTH - 1),
            "]".repeat(MAX_DEPTH - 1)
        );
        ok(&deep_ok);
        let too_deep = format!(
            r#"{{"v":1,"id":1,"type":"get","x":{}{}}}"#,
            "[".repeat(MAX_DEPTH),
            "]".repeat(MAX_DEPTH)
        );
        assert_eq!(err(too_deep.as_bytes()).kind, ErrorKind::Malformed);
        let hostile = "[".repeat(100_000);
        assert_eq!(err(hostile.as_bytes()).kind, ErrorKind::Malformed);
        let hostile_obj = format!(r#"{{"x":{}"#, "{\"a\":".repeat(100_000));
        assert_eq!(err(hostile_obj.as_bytes()).kind, ErrorKind::Malformed);
    }

    #[test]
    fn never_panics_on_prefixes() {
        let m =
            br#"{"v":1,"id":12,"type":"create","options":{"a":[1,2,{"b":"c\"d"}],"e":-1.5E+3}}"#;
        for end in 0..m.len() {
            assert!(parse(&m[..end]).is_err());
        }
        assert!(parse(m).is_ok());
    }
}
