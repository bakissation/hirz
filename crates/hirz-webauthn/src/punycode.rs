//! Punycode encoding (RFC 3492), used only to convert the Unicode rules of the public
//! suffix list into the ASCII form browsers serialize hosts in. Input is assumed to be
//! already lowercased and NFC normalized, which the list guarantees.

const BASE: u32 = 36;
const TMIN: u32 = 1;
const TMAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 128;
const ADAPT_LIMIT: u32 = ((BASE - TMIN) * TMAX) / 2;
const BASE_MINUS_TMIN: u32 = BASE - TMIN;

fn digit(d: u32) -> Option<char> {
    let b = match d {
        0..=25 => b'a'.checked_add(u8::try_from(d).ok()?)?,
        26..=35 => b'0'.checked_add(u8::try_from(d.checked_sub(26)?).ok()?)?,
        _ => return None,
    };
    Some(char::from(b))
}

fn adapt(delta: u32, num_points: u32, first: bool) -> Option<u32> {
    let mut delta = if first {
        delta.checked_div(DAMP)?
    } else {
        delta.checked_div(2)?
    };
    delta = delta.checked_add(delta.checked_div(num_points)?)?;
    let mut k = 0u32;
    while delta > ADAPT_LIMIT {
        delta = delta.checked_div(BASE_MINUS_TMIN)?;
        k = k.checked_add(BASE)?;
    }
    let num = BASE_MINUS_TMIN.checked_add(1)?.checked_mul(delta)?;
    k.checked_add(num.checked_div(delta.checked_add(SKEW)?)?)
}

/// Encodes one label; `None` on overflow. The `xn--` prefix is not added.
pub(crate) fn encode(input: &str) -> Option<String> {
    let code_points: Vec<u32> = input.chars().map(u32::from).collect();
    let mut out: String = input.chars().filter(char::is_ascii).collect();
    let basic = u32::try_from(out.len()).ok()?;
    let total = u32::try_from(code_points.len()).ok()?;
    let mut handled = basic;
    if basic > 0 {
        out.push('-');
    }
    let mut n = INITIAL_N;
    let mut delta = 0u32;
    let mut bias = INITIAL_BIAS;
    while handled < total {
        let m = code_points.iter().copied().filter(|&c| c >= n).min()?;
        let step = m.checked_sub(n)?.checked_mul(handled.checked_add(1)?)?;
        delta = delta.checked_add(step)?;
        n = m;
        for &c in &code_points {
            if c < n {
                delta = delta.checked_add(1)?;
            }
            if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias {
                        TMIN
                    } else if k >= bias.checked_add(TMAX)? {
                        TMAX
                    } else {
                        k.checked_sub(bias)?
                    };
                    if q < t {
                        break;
                    }
                    let span = BASE.checked_sub(t)?;
                    let rem = q.checked_sub(t)?;
                    out.push(digit(t.checked_add(rem.checked_rem(span)?)?)?);
                    q = rem.checked_div(span)?;
                    k = k.checked_add(BASE)?;
                }
                out.push(digit(q)?);
                bias = adapt(delta, handled.checked_add(1)?, handled == basic)?;
                delta = 0;
                handled = handled.checked_add(1)?;
            }
        }
        delta = delta.checked_add(1)?;
        n = n.checked_add(1)?;
    }
    Some(out)
}

/// Converts a lowercase Unicode domain to its ASCII form label by label.
pub(crate) fn domain_to_ascii(domain: &str) -> Option<String> {
    let mut out = String::with_capacity(domain.len());
    for (i, label) in domain.split('.').enumerate() {
        if i > 0 {
            out.push('.');
        }
        if label.is_ascii() {
            out.push_str(label);
        } else {
            out.push_str("xn--");
            out.push_str(&encode(label)?);
        }
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rfc3492_samples() {
        // RFC 3492 section 7.1, samples (A), (B), (L) and (M); the RFC keeps uppercase
        // basic code points as they are.
        assert_eq!(
            encode(
                "\u{0644}\u{064A}\u{0647}\u{0645}\u{0627}\u{0628}\u{062A}\u{0643}\u{0644}\
                 \u{0645}\u{0648}\u{0634}\u{0639}\u{0631}\u{0628}\u{064A}\u{061F}"
            )
            .unwrap(),
            "egbpdaj6bu4bxfgehfvwxn"
        );
        assert_eq!(
            encode("\u{4ED6}\u{4EEC}\u{4E3A}\u{4EC0}\u{4E48}\u{4E0D}\u{8BF4}\u{4E2D}\u{6587}")
                .unwrap(),
            "ihqwcrb4cv8a8dqg056pqjye"
        );
        assert_eq!(
            encode("3\u{5E74}B\u{7D44}\u{91D1}\u{516B}\u{5148}\u{751F}").unwrap(),
            "3B-ww4c5e180e575a65lsy2b"
        );
        assert_eq!(
            encode("\u{5B89}\u{5BA4}\u{5948}\u{7F8E}\u{6075}-with-SUPER-MONKEYS").unwrap(),
            "-with-SUPER-MONKEYS-pc58ag80a8qai00g7n9n"
        );
    }

    #[test]
    fn domains() {
        assert_eq!(
            domain_to_ascii("\u{98df}\u{72ee}.\u{516c}\u{53f8}.cn").unwrap(),
            "xn--85x722f.xn--55qx5d.cn"
        );
        assert_eq!(domain_to_ascii("\u{4e2d}\u{56fd}").unwrap(), "xn--fiqs8s");
        assert_eq!(domain_to_ascii("example.com").unwrap(), "example.com");
        assert_eq!(encode("").unwrap(), "");
        assert_eq!(encode("abc").unwrap(), "abc-");
    }
}
