//! Passkeys from other password managers' export files: Bitwarden JSON exports and
//! KeePassXC `.passkey` files.
//!
//! Pure functions over bytes that depend only on hirz library crates, so the fuzz targets
//! can include this module as is. Only passkey fields are read; passwords, notes, TOTP
//! secrets and every other field are skipped and never copied out of the parsed tree, which
//! is wiped before it is dropped.

pub mod bitwarden;
pub mod keepassxc;

use hirz_core::{COSE_ALG_EDDSA, COSE_ALG_ES256};
use hirz_crypto::{Zeroize, Zeroizing};
use hirz_proto::json::{Json, Limits};
use hirz_vault::{CredentialRecord, MAX_PKCS8_LEN, MAX_STRING_LEN};

/// Largest export file hirz reads.
pub const MAX_FILE_LEN: usize = 64 * 1024 * 1024;
/// Largest number of passkeys read from one import.
pub const MAX_PASSKEYS: usize = 100_000;

/// One passkey found in an export.
#[derive(Debug)]
pub enum Found {
    Ready(Box<CredentialRecord>),
    Skipped {
        site: String,
        account: Option<String>,
        reason: String,
    },
}

/// The passkeys of one export, and how many other entries it held.
#[derive(Debug, Default)]
pub struct Parsed {
    pub passkeys: Vec<Found>,
    /// Entries without a passkey (passwords, notes, cards...).
    pub other_items: usize,
}

/// Overwrites every string and key of a JSON tree.
pub fn wipe(v: &mut Json) {
    match v {
        Json::String(s) => s.zeroize(),
        Json::Array(a) => a.iter_mut().for_each(wipe),
        Json::Object(o) => o.iter_mut().for_each(|(k, v)| {
            k.zeroize();
            wipe(v);
        }),
        _ => {}
    }
}

/// Parses JSON, then runs `f` on the tree and wipes it whatever the outcome.
fn with_json<T>(
    data: &[u8],
    limits: &Limits,
    not_json: &str,
    f: impl FnOnce(&Json) -> Result<T, String>,
) -> Result<T, String> {
    let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    let mut doc = hirz_proto::json::parse(data, limits).map_err(|e| match e {
        hirz_proto::Error::LimitExceeded => {
            "The file is too large or too deeply nested for hirz to read.".to_string()
        }
        _ => not_json.to_string(),
    })?;
    let out = f(&doc);
    wipe(&mut doc);
    out
}

/// base64 in either alphabet, with or without `=` padding.
pub fn lenient_base64(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    let trimmed = s.trim_end_matches('=');
    if s.len().saturating_sub(trimmed.len()) > 2 {
        return None;
    }
    let mut url = Zeroizing::new(String::with_capacity(trimmed.len()));
    for c in trimmed.chars() {
        url.push(match c {
            '+' => '-',
            '/' => '_',
            c => c,
        });
    }
    hirz_proto::base64url::decode(&url).ok().map(Zeroizing::new)
}

fn opt_text<'a>(o: &'a Json, key: &str) -> Result<Option<&'a str>, String> {
    match o.get(key) {
        None | Some(Json::Null) => Ok(None),
        Some(Json::String(s)) if s.len() <= MAX_STRING_LEN => Ok(Some(s)),
        Some(Json::String(_)) => Err(format!("the field {key} is too long")),
        Some(_) => Err(format!("the field {key} is not text")),
    }
}

fn non_empty(s: Option<&str>) -> Option<String> {
    s.filter(|v| !v.is_empty()).map(str::to_string)
}

/// Bytes of a base64 field of at most `max` decoded bytes; empty for a missing field.
fn base64_field(o: &Json, key: &str, max: usize) -> Result<Zeroizing<Vec<u8>>, String> {
    let s = match o.get(key) {
        None | Some(Json::Null) => return Ok(Zeroizing::new(Vec::new())),
        Some(Json::String(s)) => s,
        Some(_) => return Err(format!("the field {key} is not text")),
    };
    if s.len() > max.saturating_mul(2).saturating_add(8) {
        return Err(format!("the field {key} is too long"));
    }
    let b = lenient_base64(s).ok_or_else(|| format!("the field {key} is not valid base64"))?;
    if b.len() > max {
        return Err(format!("the field {key} is too long"));
    }
    Ok(b)
}

fn site_id(raw: &str) -> Result<String, String> {
    let rp_id = raw.to_ascii_lowercase();
    if !hirz_uv::config::valid_rp_id(&rp_id) {
        return Err("its site id is not a valid domain name".into());
    }
    Ok(rp_id)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// COSE algorithm of a PKCS#8 private key, if hirz supports it.
pub fn identify_key(pkcs8: &[u8]) -> Result<i64, String> {
    if pkcs8.len() > MAX_PKCS8_LEN {
        return Err("its private key is too long".into());
    }
    if hirz_crypto::es256::public_key(pkcs8).is_ok() {
        return Ok(COSE_ALG_ES256);
    }
    if hirz_crypto::ed25519::public_key(pkcs8).is_ok() {
        return Ok(COSE_ALG_EDDSA);
    }
    const KNOWN: &[(&[u8], &str)] = &[
        (
            &[
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
            ],
            "an RSA key",
        ),
        (
            &[
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
            ],
            "an RSA-PSS key",
        ),
        (&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22], "a P-384 key"),
        (&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23], "a P-521 key"),
        (&[0x06, 0x03, 0x2b, 0x65, 0x71], "an Ed448 key"),
        (
            &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
            "a P-256 key hirz could not read",
        ),
        (
            &[0x06, 0x03, 0x2b, 0x65, 0x70],
            "an Ed25519 key hirz could not read",
        ),
    ];
    let kind = KNOWN
        .iter()
        .find(|(oid, _)| contains(pkcs8, oid))
        .map_or("a key type hirz does not know", |(_, k)| *k);
    Err(format!(
        "it uses {kind}; hirz supports P-256 (ES256) and Ed25519 keys"
    ))
}

/// Days from 1970-01-01 to a proleptic Gregorian date (H. Hinnant's algorithm).
fn days_from_civil(y: u64, m: u64, d: u64) -> Option<u64> {
    let y = if m <= 2 { y.checked_sub(1)? } else { y };
    let era = y / 400;
    let yoe = y.checked_sub(era.checked_mul(400)?)?;
    let mp = if m > 2 {
        m.checked_sub(3)?
    } else {
        m.checked_add(9)?
    };
    let doy = mp
        .checked_mul(153)?
        .checked_add(2)?
        .checked_div(5)?
        .checked_add(d)?
        .checked_sub(1)?;
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe / 4)?
        .checked_sub(yoe / 100)?
        .checked_add(doy)?;
    era.checked_mul(146_097)?
        .checked_add(doe)?
        .checked_sub(719_468)
}

fn digits(s: &str, len: usize) -> Option<u64> {
    (s.len() == len && s.bytes().all(|b| b.is_ascii_digit()))
        .then(|| s.parse().ok())
        .flatten()
}

/// Unix seconds of an RFC 3339 UTC time such as `2024-05-01T12:30:00.000Z`.
pub fn parse_utc(s: &str) -> Option<u64> {
    let s = s.strip_suffix('Z').or_else(|| s.strip_suffix("+00:00"))?;
    let (date, time) = s.split_once('T')?;
    let time = time.split_once('.').map_or(time, |(t, frac)| {
        if !frac.is_empty() && frac.len() <= 9 && frac.bytes().all(|b| b.is_ascii_digit()) {
            t
        } else {
            ""
        }
    });
    let mut d = date.split('-');
    let (y, mo, da) = (
        digits(d.next()?, 4)?,
        digits(d.next()?, 2)?,
        digits(d.next()?, 2)?,
    );
    let mut t = time.split(':');
    let (h, mi, se) = (
        digits(t.next()?, 2)?,
        digits(t.next()?, 2)?,
        digits(t.next()?, 2)?,
    );
    if d.next().is_some()
        || t.next().is_some()
        || y < 1970
        || !(1..=12).contains(&mo)
        || !(1..=31).contains(&da)
        || h > 23
        || mi > 59
        || se > 60
    {
        return None;
    }
    days_from_civil(y, mo, da)?
        .checked_mul(86_400)?
        .checked_add(h.checked_mul(3600)?)?
        .checked_add(mi.checked_mul(60)?)?
        .checked_add(se)
}

/// A creation time from the file, or `now` when it is missing or in the future.
fn creation_time(at: Option<u64>, now: u64) -> u64 {
    at.filter(|t| *t > 0 && *t <= now.saturating_add(86_400))
        .unwrap_or(now)
}

/// Checks a record built from an export, as every stored record is checked.
/// Printable form of a short value from the file, for messages.
fn shown(s: &str) -> String {
    let out: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(24)
        .collect();
    if out.is_empty() { "(none)".into() } else { out }
}

fn finish(record: CredentialRecord) -> Result<CredentialRecord, String> {
    record
        .validate()
        .map_err(|e| format!("it is not a valid passkey ({e})"))?;
    Ok(record)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn utc_times() {
        assert_eq!(parse_utc("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_utc("2024-02-29T12:00:00.123Z"), Some(1_709_208_000));
        assert_eq!(parse_utc("2000-03-01T00:00:01+00:00"), Some(951_868_801));
        for bad in [
            "",
            "2024-02-29",
            "2024-02-29T12:00:00",
            "2024-13-01T00:00:00Z",
            "2024-1-01T00:00:00Z",
            "1969-12-31T23:59:59Z",
            "2024-02-29T12:00:00.Z",
            "2024-02-29T12:00:00.12aZ",
            "2024-02-29T24:00:00Z",
        ] {
            assert_eq!(parse_utc(bad), None, "{bad}");
        }
    }

    #[test]
    fn base64_alphabets() {
        assert_eq!(lenient_base64("-_8").unwrap().as_slice(), [0xfb, 0xff]);
        assert_eq!(lenient_base64("+/8=").unwrap().as_slice(), [0xfb, 0xff]);
        assert!(lenient_base64("+/8===").is_none());
        assert!(lenient_base64("a b").is_none());
    }

    #[test]
    fn wipe_clears_keys_and_values() {
        let mut v =
            hirz_proto::json::parse(br#"{"k":["s",{"p":"x"}],"n":1}"#, &Limits::default()).unwrap();
        wipe(&mut v);
        let o = v.as_object().unwrap();
        assert!(o.iter().all(|(k, _)| k.is_empty()));
        let inner = o[0].1.as_array().unwrap();
        assert_eq!(inner[0].as_str(), Some(""));
        assert_eq!(inner[1].as_object().unwrap()[0].1.as_str(), Some(""));
        assert_eq!(o[1].1.as_u64(), Some(1));
    }

    #[test]
    fn identifies_keys() {
        let (es, _, _) = hirz_crypto::es256::generate().unwrap();
        let (ed, _) = hirz_crypto::ed25519::generate().unwrap();
        assert_eq!(identify_key(&es), Ok(COSE_ALG_ES256));
        assert_eq!(identify_key(&ed), Ok(COSE_ALG_EDDSA));
        let p384 = [0x30, 0x10, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x00];
        assert!(identify_key(&p384).unwrap_err().contains("P-384"));
        assert!(
            identify_key(b"garbage")
                .unwrap_err()
                .contains("does not know")
        );
    }
}
