//! The Public Suffix List, compiled into the binary.
//!
//! Data: `data/public_suffix_list.dat`, VERSION 2026-11-15_20-28-43_UTC, COMMIT
//! fd22c6c8b3fd7e854c1eff2194cfd4ebc9854b88, downloaded 2026-11-16 from
//! <https://publicsuffix.org/list/public_suffix_list.dat>. Mozilla Public License 2.0.
//!
//! Rules from both the ICANN and the PRIVATE sections are used, as browsers do. Unicode
//! rules are converted to punycode when the table is built, so lookups take hosts in the
//! ASCII form browsers serialize. Lookups expect lowercase input; hosts with uppercase
//! ASCII, non-ASCII characters or empty labels get no answer (`None` or `false`).

use crate::punycode;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::OnceLock;

const DATA: &str = include_str!("../data/public_suffix_list.dat");

const NORMAL: u8 = 1;
const WILDCARD: u8 = 2;
const EXCEPTION: u8 = 4;

#[derive(Debug)]
struct Rules {
    /// Rule body (without `*.` or `!`) to the kinds of rules with that body.
    map: HashMap<Cow<'static, str>, u8>,
}

fn rules() -> &'static Rules {
    static RULES: OnceLock<Rules> = OnceLock::new();
    RULES.get_or_init(|| parse(DATA))
}

fn parse(data: &'static str) -> Rules {
    let mut map: HashMap<Cow<'static, str>, u8> = HashMap::with_capacity(10_000);
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let Some(rule) = line.split_whitespace().next() else {
            continue;
        };
        let (kind, body) = if let Some(body) = rule.strip_prefix('!') {
            (EXCEPTION, body)
        } else if let Some(body) = rule.strip_prefix("*.") {
            (WILDCARD, body)
        } else {
            (NORMAL, rule)
        };
        if body.is_empty() || body.contains(['*', '!']) || body.split('.').any(str::is_empty) {
            continue;
        }
        let key = if body.is_ascii() {
            Cow::Borrowed(body)
        } else {
            match punycode::domain_to_ascii(body) {
                Some(ascii) => Cow::Owned(ascii),
                None => continue,
            }
        };
        let entry = map.entry(key).or_insert(0);
        *entry |= kind;
    }
    Rules { map }
}

fn well_formed(host: &str) -> bool {
    !host.is_empty()
        && host.is_ascii()
        && !host.bytes().any(|b| b.is_ascii_uppercase())
        && !host.split('.').any(str::is_empty)
}

/// The public suffix of `host` per the PSL algorithm, as a suffix of `host`. An unlisted
/// top-level label is its own public suffix (the implicit `*` rule).
pub fn public_suffix(host: &str) -> Option<&str> {
    if !well_formed(host) {
        return None;
    }
    let rules = rules();
    let mut starts: Vec<usize> = vec![0];
    starts.extend(
        host.bytes()
            .enumerate()
            .filter(|&(_, b)| b == b'.')
            .filter_map(|(i, _)| i.checked_add(1)),
    );
    let mut best: Option<usize> = None;
    for (idx, &start) in starts.iter().enumerate() {
        let suffix = host.get(start..)?;
        let kinds = rules.map.get(suffix).copied().unwrap_or(0);
        if kinds & EXCEPTION != 0 {
            // An exception rule prevails over every other match; the public suffix is
            // the rule minus its leftmost label.
            let parent = starts.get(idx.checked_add(1)?)?;
            return host.get(*parent..);
        }
        let parent_wildcard = starts
            .get(idx.wrapping_add(1))
            .and_then(|&p| host.get(p..))
            .and_then(|p| rules.map.get(p))
            .is_some_and(|k| k & WILDCARD != 0);
        if best.is_none() && (kinds & NORMAL != 0 || parent_wildcard) {
            best = Some(start);
        }
    }
    let start = match best {
        Some(start) => start,
        None => *starts.last()?,
    };
    host.get(start..)
}

/// True when `host` is itself a public suffix.
pub fn is_public_suffix(host: &str) -> bool {
    public_suffix(host).is_some_and(|ps| ps.len() == host.len())
}

/// The registrable domain (public suffix plus one label), or `None` when `host` is a
/// public suffix or not well formed.
pub fn registrable_domain(host: &str) -> Option<&str> {
    let ps = public_suffix(host)?;
    let prefix_len = host.len().checked_sub(ps.len())?.checked_sub(1)?;
    let prefix = host.get(..prefix_len)?;
    let start = prefix.rfind('.').map_or(0, |i| i.saturating_add(1));
    host.get(start..)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const VECTORS: &str = include_str!("../data/test_psl.txt");

    fn normalize(s: &str) -> String {
        punycode::domain_to_ascii(&s.to_ascii_lowercase()).unwrap()
    }

    fn arg(s: &str) -> Option<String> {
        let s = s.trim();
        if s == "null" {
            return None;
        }
        Some(
            s.strip_prefix('\'')
                .and_then(|s| s.strip_suffix('\''))
                .unwrap()
                .to_owned(),
        )
    }

    #[test]
    fn official_test_vectors() {
        let mut count = 0;
        for line in VECTORS.lines() {
            let line = line.trim();
            let Some(inner) = line
                .strip_prefix("checkPublicSuffix(")
                .and_then(|l| l.strip_suffix(");"))
            else {
                continue;
            };
            let (input, expected) = inner.split_once(',').unwrap();
            let input = arg(input);
            let expected = arg(expected);
            let got = input
                .as_deref()
                .map(normalize)
                .and_then(|h| registrable_domain(&h).map(str::to_owned));
            assert_eq!(got, expected.as_deref().map(normalize), "{line}");
            count += 1;
        }
        assert_eq!(count, 78);
    }

    #[test]
    fn table_is_complete() {
        let r = rules();
        assert!(r.map.len() > 9_000, "{}", r.map.len());
        assert_eq!(r.map.get("com").copied(), Some(NORMAL));
        assert_eq!(r.map.get("github.io").copied(), Some(NORMAL));
        assert_eq!(r.map.get("ck").copied(), Some(WILDCARD));
        assert_eq!(r.map.get("www.ck").copied(), Some(EXCEPTION));
        assert!(r.map.contains_key("xn--fiqs8s"));
    }

    #[test]
    fn suffixes() {
        assert_eq!(public_suffix("example.com"), Some("com"));
        assert_eq!(public_suffix("www.example.co.uk"), Some("co.uk"));
        assert_eq!(public_suffix("alice.github.io"), Some("github.io"));
        assert_eq!(public_suffix("localhost"), Some("localhost"));
        assert_eq!(public_suffix("app.localhost"), Some("localhost"));
        assert_eq!(public_suffix("a.b.c.kobe.jp"), Some("c.kobe.jp"));
        assert_eq!(public_suffix("www.city.kobe.jp"), Some("kobe.jp"));
        assert!(is_public_suffix("com"));
        assert!(is_public_suffix("co.uk"));
        assert!(is_public_suffix("github.io"));
        assert!(is_public_suffix("anything.ck"));
        assert!(!is_public_suffix("www.ck"));
        assert!(!is_public_suffix("example.com"));
        assert!(is_public_suffix("localhost"));
        assert_eq!(
            registrable_domain("a.b.example.co.uk"),
            Some("example.co.uk")
        );
        assert_eq!(
            registrable_domain("alice.github.io"),
            Some("alice.github.io")
        );
        assert_eq!(
            registrable_domain("x.alice.github.io"),
            Some("alice.github.io")
        );
        assert_eq!(registrable_domain("github.io"), None);
        assert_eq!(registrable_domain("app.localhost"), Some("app.localhost"));
    }

    #[test]
    fn malformed_hosts() {
        for host in [
            "",
            ".",
            ".com",
            "com.",
            "a..com",
            "Example.com",
            "\u{e4}.com",
        ] {
            assert_eq!(public_suffix(host), None, "{host:?}");
            assert_eq!(registrable_domain(host), None, "{host:?}");
            assert!(!is_public_suffix(host), "{host:?}");
        }
    }
}
