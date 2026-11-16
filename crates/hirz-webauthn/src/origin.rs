//! Serialized origins as Firefox reports them in `MessageSender.origin`: `https` with a domain host
//! or `http` with `localhost` (or a subdomain). Anything not already in browser serialization is
//! rejected rather than normalized, because the string is copied verbatim into clientDataJSON.

use core::fmt;

/// Longest origin string accepted: `https://` + 253 byte host + `:65535`.
pub const MAX_ORIGIN_LEN: usize = 8 + MAX_DOMAIN_LEN + 6;
pub const MAX_DOMAIN_LEN: usize = 253;
pub const MAX_LABEL_LEN: usize = 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainError {
    Empty,
    TooLong,
    Uppercase,
    NonAscii,
    InvalidChar,
    TrailingDot,
    EmptyLabel,
    LabelTooLong,
    Hyphen,
    IpAddress,
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DomainError::Empty => "empty host",
            DomainError::TooLong => "host too long",
            DomainError::Uppercase => "host is not lowercase",
            DomainError::NonAscii => "host is not ASCII",
            DomainError::InvalidChar => "invalid character in host",
            DomainError::TrailingDot => "trailing dot in host",
            DomainError::EmptyLabel => "empty label in host",
            DomainError::LabelTooLong => "label longer than 63 bytes",
            DomainError::Hyphen => "label starts or ends with a hyphen",
            DomainError::IpAddress => "IP address instead of a domain",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginError {
    TooLong,
    Opaque,
    UnsupportedScheme,
    Insecure,
    Userinfo,
    PathOrQuery,
    InvalidPort,
    Host(DomainError),
}

impl fmt::Display for OriginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OriginError::TooLong => f.write_str("origin too long"),
            OriginError::Opaque => f.write_str("opaque origin"),
            OriginError::UnsupportedScheme => f.write_str("unsupported scheme"),
            OriginError::Insecure => f.write_str("origin is not a secure context"),
            OriginError::Userinfo => f.write_str("userinfo in origin"),
            OriginError::PathOrQuery => f.write_str("path, query or fragment in origin"),
            OriginError::InvalidPort => f.write_str("invalid port"),
            OriginError::Host(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for OriginError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Https,
    Http,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    serialized: String,
    scheme: Scheme,
    host: String,
    port: Option<u16>,
}

impl Origin {
    pub fn parse(input: &str) -> Result<Origin, OriginError> {
        if input == "null" {
            return Err(OriginError::Opaque);
        }
        if input.len() > MAX_ORIGIN_LEN {
            return Err(OriginError::TooLong);
        }
        let (scheme, rest) = if let Some(rest) = input.strip_prefix("https://") {
            (Scheme::Https, rest)
        } else if let Some(rest) = input.strip_prefix("http://") {
            (Scheme::Http, rest)
        } else {
            return Err(OriginError::UnsupportedScheme);
        };
        if rest.contains('@') {
            return Err(OriginError::Userinfo);
        }
        if rest.contains(['/', '?', '#', '\\']) {
            return Err(OriginError::PathOrQuery);
        }
        if rest.starts_with('[') {
            return Err(OriginError::Host(DomainError::IpAddress));
        }
        let (host, port) = match rest.split_once(':') {
            Some((host, port)) => (host, Some(parse_port(port, scheme)?)),
            None => (rest, None),
        };
        validate_domain(host).map_err(OriginError::Host)?;
        if scheme == Scheme::Http && !is_localhost(host) {
            return Err(OriginError::Insecure);
        }
        Ok(Origin {
            serialized: input.to_owned(),
            scheme,
            host: host.to_owned(),
            port,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.serialized
    }

    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// The effective domain. For the accepted origins this is always the host.
    pub fn effective_domain(&self) -> &str {
        &self.host
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.serialized)
    }
}

fn parse_port(port: &str, scheme: Scheme) -> Result<u16, OriginError> {
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(OriginError::InvalidPort);
    }
    if port.starts_with('0') {
        return Err(OriginError::InvalidPort);
    }
    let value: u16 = port.parse().map_err(|_| OriginError::InvalidPort)?;
    let default = match scheme {
        Scheme::Https => 443,
        Scheme::Http => 80,
    };
    if value == default {
        return Err(OriginError::InvalidPort);
    }
    Ok(value)
}

pub fn is_localhost(host: &str) -> bool {
    host == "localhost" || host.ends_with(".localhost")
}

/// Checks that `host` is a domain in canonical ASCII form: lowercase, punycode for IDN
/// labels, 1 to 63 byte labels, at most 253 bytes, no trailing dot, not an IP literal.
pub fn validate_domain(host: &str) -> Result<(), DomainError> {
    if host.is_empty() {
        return Err(DomainError::Empty);
    }
    if !host.is_ascii() {
        return Err(DomainError::NonAscii);
    }
    if host.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(DomainError::Uppercase);
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return Err(DomainError::InvalidChar);
    }
    if host.len() > MAX_DOMAIN_LEN {
        return Err(DomainError::TooLong);
    }
    if host.ends_with('.') {
        return Err(DomainError::TrailingDot);
    }
    let mut last = "";
    for label in host.split('.') {
        if label.is_empty() {
            return Err(DomainError::EmptyLabel);
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(DomainError::LabelTooLong);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(DomainError::Hyphen);
        }
        last = label;
    }
    if ends_in_number(last) {
        return Err(DomainError::IpAddress);
    }
    Ok(())
}

/// The URL Standard's "ends in a number" test on the last label: such a host is parsed
/// as IPv4 by browsers.
fn ends_in_number(last: &str) -> bool {
    if last.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    match last.strip_prefix("0x") {
        Some(hex) => hex.bytes().all(|b| b.is_ascii_hexdigit()),
        None => false,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn accepts_secure_origins() {
        for (input, host, port) in [
            ("https://example.com", "example.com", None),
            ("https://a.b.example.com", "a.b.example.com", None),
            ("https://example.com:8443", "example.com", Some(8443)),
            (
                "https://xn--85x722f.xn--fiqs8s",
                "xn--85x722f.xn--fiqs8s",
                None,
            ),
            ("https://a-b.example", "a-b.example", None),
            ("https://1password.example", "1password.example", None),
            ("https://localhost", "localhost", None),
            ("http://localhost", "localhost", None),
            ("http://localhost:8080", "localhost", Some(8080)),
            ("http://app.localhost", "app.localhost", None),
            ("http://a.b.localhost:3000", "a.b.localhost", Some(3000)),
            ("https://example.com:1", "example.com", Some(1)),
            ("https://example.com:65535", "example.com", Some(65535)),
            ("https://example.com:80", "example.com", Some(80)),
        ] {
            let o = Origin::parse(input).unwrap();
            assert_eq!(o.as_str(), input);
            assert_eq!(o.host(), host, "{input}");
            assert_eq!(o.effective_domain(), host);
            assert_eq!(o.port(), port, "{input}");
        }
        assert_eq!(
            Origin::parse("http://localhost").unwrap().scheme(),
            Scheme::Http
        );
    }

    #[test]
    fn rejects_bad_origins() {
        use DomainError as D;
        use OriginError as E;
        let label64 = format!("https://{}.example", "a".repeat(64));
        let label63 = format!("https://{}.example", "a".repeat(63));
        assert!(Origin::parse(&label63).is_ok());
        let long_host = format!("https://{}.com", vec!["a".repeat(62); 4].join("."));
        assert_eq!(long_host.len() - 8, 255);
        let max_host = format!("https://{}.co", vec!["a".repeat(62); 4].join("."));
        assert!(max_host.len() - 8 == 254);
        let ok_host = format!("https://{}.c", vec!["a".repeat(62); 4].join("."));
        assert!(Origin::parse(&ok_host).is_ok());
        for (input, err) in [
            ("null", E::Opaque),
            ("", E::UnsupportedScheme),
            ("example.com", E::UnsupportedScheme),
            ("ftp://example.com", E::UnsupportedScheme),
            ("HTTPS://example.com", E::UnsupportedScheme),
            ("file://", E::UnsupportedScheme),
            ("moz-extension://abc", E::UnsupportedScheme),
            ("data:text/html,x", E::UnsupportedScheme),
            ("https:example.com", E::UnsupportedScheme),
            ("http://example.com", E::Insecure),
            ("http://localhost.example", E::Insecure),
            ("http://notlocalhost", E::Insecure),
            ("https://user@example.com", E::Userinfo),
            ("https://user:pw@example.com", E::Userinfo),
            ("https://example.com/", E::PathOrQuery),
            ("https://example.com/path", E::PathOrQuery),
            ("https://example.com?q", E::PathOrQuery),
            ("https://example.com#f", E::PathOrQuery),
            ("https://example.com\\x", E::PathOrQuery),
            ("https://example.com:", E::InvalidPort),
            ("https://example.com:443", E::InvalidPort),
            ("http://localhost:80", E::InvalidPort),
            ("https://example.com:0443", E::InvalidPort),
            ("https://example.com:0", E::InvalidPort),
            ("https://example.com:65536", E::InvalidPort),
            ("https://example.com:123456", E::InvalidPort),
            ("https://example.com:+1", E::InvalidPort),
            ("https://example.com:1:2", E::InvalidPort),
            ("https://", E::Host(D::Empty)),
            ("https://:8443", E::Host(D::Empty)),
            ("https://Example.com", E::Host(D::Uppercase)),
            ("https://EXAMPLE.COM", E::Host(D::Uppercase)),
            ("https://ex\u{e4}mple.com", E::Host(D::NonAscii)),
            ("https://\u{98df}\u{72ee}.com", E::Host(D::NonAscii)),
            ("https://exa_mple.com", E::Host(D::InvalidChar)),
            ("https://exa mple.com", E::Host(D::InvalidChar)),
            ("https://exa%41mple.com", E::Host(D::InvalidChar)),
            ("https://example.com.", E::Host(D::TrailingDot)),
            ("https://.example.com", E::Host(D::EmptyLabel)),
            ("https://example..com", E::Host(D::EmptyLabel)),
            (label64.as_str(), E::Host(D::LabelTooLong)),
            (long_host.as_str(), E::Host(D::TooLong)),
            (max_host.as_str(), E::Host(D::TooLong)),
            ("https://-example.com", E::Host(D::Hyphen)),
            ("https://example-.com", E::Host(D::Hyphen)),
            ("https://127.0.0.1", E::Host(D::IpAddress)),
            ("https://192.168.1.1:8443", E::Host(D::IpAddress)),
            ("https://example.123", E::Host(D::IpAddress)),
            ("https://0x7f000001", E::Host(D::IpAddress)),
            ("https://example.0x1f", E::Host(D::IpAddress)),
            ("https://[::1]", E::Host(D::IpAddress)),
            ("https://[::1]:8443", E::Host(D::IpAddress)),
            ("http://127.0.0.1", E::Host(D::IpAddress)),
        ] {
            assert_eq!(Origin::parse(input), Err(err), "{input:?}");
        }
        let huge = format!("https://{}", "a".repeat(400));
        assert_eq!(Origin::parse(&huge), Err(E::TooLong));
    }

    #[test]
    fn hex_like_labels_that_are_not_numbers() {
        assert!(Origin::parse("https://0xg.example").is_ok());
        assert!(Origin::parse("https://example.0xg").is_ok());
        assert!(Origin::parse("https://123.example").is_ok());
    }
}
