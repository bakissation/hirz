//! clientDataJSON serialization per WebAuthn Level 3 section 5.8.1.1.
//!
//! The output is the exact byte sequence the limited verification algorithm of section
//! 5.8.1.2 expects, with no fields after `crossOrigin` and `topOrigin`.

use crate::base64url;
use core::fmt::Write;

/// The `type` member of CollectedClientData.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyType {
    /// `webauthn.create`
    Create,
    /// `webauthn.get`
    Get,
}

impl CeremonyType {
    /// The string used in clientDataJSON.
    pub fn as_str(self) -> &'static str {
        match self {
            CeremonyType::Create => "webauthn.create",
            CeremonyType::Get => "webauthn.get",
        }
    }
}

fn ccd_to_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{20}'.. => out.push(c),
            _ => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
        }
    }
    out.push('"');
}

/// Serializes CollectedClientData; `top_origin` is written whenever it is given.
pub fn serialize(
    ceremony: CeremonyType,
    challenge: &[u8],
    origin: &str,
    cross_origin: bool,
    top_origin: Option<&str>,
) -> String {
    let mut out = String::with_capacity(128);
    out.push_str("{\"type\":");
    ccd_to_string(&mut out, ceremony.as_str());
    out.push_str(",\"challenge\":");
    ccd_to_string(&mut out, &base64url::encode(challenge));
    out.push_str(",\"origin\":");
    ccd_to_string(&mut out, origin);
    out.push_str(",\"crossOrigin\":");
    out.push_str(if cross_origin { "true" } else { "false" });
    if let Some(top) = top_origin {
        out.push_str(",\"topOrigin\":");
        ccd_to_string(&mut out, top);
    }
    out.push('}');
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::json;

    #[test]
    fn simple_get() {
        let s = serialize(
            CeremonyType::Get,
            &[0xfb, 0xff],
            "https://example.com",
            false,
            None,
        );
        assert_eq!(
            s,
            r#"{"type":"webauthn.get","challenge":"-_8","origin":"https://example.com","crossOrigin":false}"#
        );
    }

    #[test]
    fn escaping_matches_ccd_to_string() {
        let s = serialize(
            CeremonyType::Create,
            b"",
            "a\"b\\c\u{1}\u{1f}\u{7f}\u{e9}\u{1f600}",
            true,
            Some("https://acme.example"),
        );
        assert_eq!(
            s,
            "{\"type\":\"webauthn.create\",\"challenge\":\"\",\"origin\":\"a\\\"b\\\\c\\u0001\\u001f\u{7f}\u{e9}\u{1f600}\",\"crossOrigin\":true,\"topOrigin\":\"https://acme.example\"}"
        );
        let parsed = json::parse(s.as_bytes(), &json::Limits::default()).unwrap();
        assert_eq!(
            parsed.get("origin").and_then(json::Json::as_str),
            Some("a\"b\\c\u{1}\u{1f}\u{7f}\u{e9}\u{1f600}")
        );
        assert_eq!(
            parsed.get("crossOrigin").and_then(json::Json::as_bool),
            Some(true)
        );
    }
}
