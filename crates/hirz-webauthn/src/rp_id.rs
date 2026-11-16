//! RP ID validation (WebAuthn Level 3 sections 5.1.3 and 5.1.4, with the HTML "is a
//! registrable domain suffix of or is equal to" algorithm).

use crate::origin::{DomainError, Origin, validate_domain};
use crate::psl;
use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpIdError {
    /// Not a domain in canonical form (empty, IP literal, trailing dot, bad label).
    Invalid(DomainError),
    /// Uppercase or Unicode: Firefox applies its own normalization, so the request is
    /// left to it instead of guessing which RP ID it would hash.
    NonCanonical,
    /// A parent domain that is a public suffix or crosses the origin's public suffix.
    PublicSuffix,
    /// Neither equal to nor a parent of the origin's effective domain. Only a Related
    /// Origin Request (`/.well-known/webauthn`) could allow it, which hirz does not do.
    RelatedOriginRequired,
}

impl fmt::Display for RpIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RpIdError::Invalid(e) => write!(f, "invalid RP ID: {e}"),
            RpIdError::NonCanonical => f.write_str("RP ID is not lowercase ASCII"),
            RpIdError::PublicSuffix => f.write_str("RP ID is a public suffix"),
            RpIdError::RelatedOriginRequired => {
                f.write_str("RP ID is not a registrable domain suffix of the origin")
            }
        }
    }
}

impl std::error::Error for RpIdError {}

/// Returns the RP ID to use for `origin`: the effective domain when `rp_id` is absent,
/// otherwise `rp_id` after checking it is equal to the effective domain or a registrable
/// domain suffix of it.
///
/// An RP ID equal to the effective domain is accepted even when it is a public suffix,
/// as the HTML algorithm does: only that exact origin can use such credentials.
pub fn validate_rp_id(rp_id: Option<&str>, origin: &Origin) -> Result<String, RpIdError> {
    let domain = origin.effective_domain();
    let Some(rp_id) = rp_id else {
        return Ok(domain.to_owned());
    };
    match validate_domain(rp_id) {
        Ok(()) => {}
        Err(DomainError::Uppercase | DomainError::NonAscii) => {
            return Err(RpIdError::NonCanonical);
        }
        Err(e) => return Err(RpIdError::Invalid(e)),
    }
    if rp_id == domain {
        return Ok(rp_id.to_owned());
    }
    let is_parent = domain
        .strip_suffix(rp_id)
        .is_some_and(|prefix| prefix.ends_with('.'));
    if !is_parent {
        return Err(RpIdError::RelatedOriginRequired);
    }
    if psl::is_public_suffix(rp_id) {
        return Err(RpIdError::PublicSuffix);
    }
    let origin_suffix = psl::public_suffix(domain).ok_or(RpIdError::PublicSuffix)?;
    let crosses = origin_suffix
        .strip_suffix(rp_id)
        .is_some_and(|prefix| prefix.ends_with('.'));
    if crosses || origin_suffix == rp_id {
        return Err(RpIdError::PublicSuffix);
    }
    Ok(rp_id.to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn check(origin: &str, rp_id: Option<&str>) -> Result<String, RpIdError> {
        validate_rp_id(rp_id, &Origin::parse(origin).unwrap())
    }

    #[test]
    fn defaults_to_effective_domain() {
        assert_eq!(check("https://example.com", None).unwrap(), "example.com");
        assert_eq!(
            check("https://login.example.com:8443", None).unwrap(),
            "login.example.com"
        );
        assert_eq!(check("http://localhost:3000", None).unwrap(), "localhost");
        assert_eq!(
            check("https://alice.github.io", None).unwrap(),
            "alice.github.io"
        );
    }

    #[test]
    fn equal_and_parent() {
        assert_eq!(
            check("https://example.com", Some("example.com")).unwrap(),
            "example.com"
        );
        assert_eq!(
            check("https://login.example.com", Some("example.com")).unwrap(),
            "example.com"
        );
        assert_eq!(
            check("https://a.b.example.co.uk", Some("b.example.co.uk")).unwrap(),
            "b.example.co.uk"
        );
        assert_eq!(
            check("https://a.b.example.co.uk", Some("example.co.uk")).unwrap(),
            "example.co.uk"
        );
        assert_eq!(
            check("https://x.alice.github.io", Some("alice.github.io")).unwrap(),
            "alice.github.io"
        );
        assert_eq!(
            check("http://app.localhost", Some("app.localhost")).unwrap(),
            "app.localhost"
        );
        assert_eq!(
            check("http://localhost", Some("localhost")).unwrap(),
            "localhost"
        );
        assert_eq!(
            check("https://www.city.kobe.jp", Some("city.kobe.jp")).unwrap(),
            "city.kobe.jp"
        );
    }

    #[test]
    fn public_suffixes_rejected() {
        use RpIdError::PublicSuffix as P;
        assert_eq!(check("https://example.com", Some("com")), Err(P));
        assert_eq!(check("https://example.co.uk", Some("co.uk")), Err(P));
        assert_eq!(check("https://example.co.uk", Some("uk")), Err(P));
        assert_eq!(check("https://alice.github.io", Some("github.io")), Err(P));
        assert_eq!(check("https://alice.github.io", Some("io")), Err(P));
        assert_eq!(check("http://app.localhost", Some("localhost")), Err(P));
        assert_eq!(check("https://b.c.kobe.jp", Some("c.kobe.jp")), Err(P));
        assert_eq!(check("https://b.c.kobe.jp", Some("kobe.jp")), Err(P));
    }

    #[test]
    fn siblings_and_unrelated_need_related_origins() {
        use RpIdError::RelatedOriginRequired as R;
        assert_eq!(
            check("https://a.example.com", Some("b.example.com")),
            Err(R)
        );
        assert_eq!(
            check("https://example.com", Some("login.example.com")),
            Err(R)
        );
        assert_eq!(check("https://example.com", Some("example.org")), Err(R));
        assert_eq!(check("https://badexample.com", Some("example.com")), Err(R));
        assert_eq!(
            check("https://alice.github.io", Some("bob.github.io")),
            Err(R)
        );
        assert_eq!(check("http://localhost", Some("example.com")), Err(R));
    }

    #[test]
    fn format_checks() {
        use DomainError as D;
        use RpIdError::{Invalid, NonCanonical};
        let o = "https://login.example.com";
        assert_eq!(check(o, Some("Example.com")), Err(NonCanonical));
        assert_eq!(check(o, Some("ex\u{e4}mple.com")), Err(NonCanonical));
        assert_eq!(check(o, Some("")), Err(Invalid(D::Empty)));
        assert_eq!(check(o, Some("example.com.")), Err(Invalid(D::TrailingDot)));
        assert_eq!(check(o, Some(".example.com")), Err(Invalid(D::EmptyLabel)));
        assert_eq!(check(o, Some("127.0.0.1")), Err(Invalid(D::IpAddress)));
        assert_eq!(check(o, Some("[::1]")), Err(Invalid(D::InvalidChar)));
        assert_eq!(
            check(o, Some("example.com:443")),
            Err(Invalid(D::InvalidChar))
        );
        assert_eq!(
            check(o, Some("https://example.com")),
            Err(Invalid(D::InvalidChar))
        );
        assert_eq!(check(o, Some("ex ample.com")), Err(Invalid(D::InvalidChar)));
        let long = format!("{}.example.com", "a".repeat(64));
        assert_eq!(check(o, Some(&long)), Err(Invalid(D::LabelTooLong)));
    }
}
