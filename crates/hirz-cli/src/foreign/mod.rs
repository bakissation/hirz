//! Passkeys from other password managers' export files. Pure functions over bytes that depend only
//! on hirz library crates, so the fuzz targets include this module as is. Only passkey fields are
//! read; everything else is never copied out of the parsed tree, which is wiped before it is dropped.

pub mod bitwarden;
pub mod keepassxc;

use hirz_core::{COSE_ALG_EDDSA, COSE_ALG_ES256};
use hirz_crypto::{Zeroize, Zeroizing};
use hirz_proto::json::{Json, Limits};
use hirz_vault::{CredentialRecord, MAX_PKCS8_LEN, MAX_STRING_LEN};

pub const MAX_FILE_LEN: usize = 64 * 1024 * 1024;
pub const MAX_PASSKEYS: usize = 100_000;

#[derive(Debug)]
pub enum Found {
    Ready(Box<CredentialRecord>),
    Skipped {
        site: String,
        account: Option<String>,
        reason: String,
    },
}

#[derive(Debug, Default)]
pub struct Parsed {
    pub passkeys: Vec<Found>,
    pub other_items: usize,
}

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
pub fn with_json<T>(
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

pub fn opt_text<'a>(o: &'a Json, key: &str) -> Result<Option<&'a str>, String> {
    opt_text_up_to(o, key, MAX_STRING_LEN)
}

pub fn opt_text_up_to<'a>(o: &'a Json, key: &str, max: usize) -> Result<Option<&'a str>, String> {
    match o.get(key) {
        None | Some(Json::Null) => Ok(None),
        Some(Json::String(s)) if s.len() <= max => Ok(Some(s)),
        Some(Json::String(_)) => Err(format!("the field {key} is too long")),
        Some(_) => Err(format!("the field {key} is not text")),
    }
}

pub fn non_empty(s: Option<&str>) -> Option<String> {
    s.filter(|v| !v.is_empty()).map(str::to_string)
}

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

const SSH_PREFIX: &str = "ssh:";
const MACHINE_LOGIN: &str =
    "its site id logs in to a computer or unlocks a disk, which hirz refuses to serve";

fn printable_ascii(s: &str) -> bool {
    s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// A site id from another program's file: a host name (lowercased), or an OpenSSH security key id
/// (`ssh:` or `ssh:NAME`, case kept because the name is chosen by the user and compared as is).
pub fn site_id(raw: &str) -> Result<String, String> {
    if machine_login_id(raw) {
        return Err(MACHINE_LOGIN.into());
    }
    if raw.starts_with(SSH_PREFIX) && raw.len() <= MAX_STRING_LEN && printable_ascii(raw) {
        return Ok(raw.to_string());
    }
    let rp_id = raw.to_ascii_lowercase();
    if !hirz_uv::config::valid_rp_id(&rp_id) {
        return Err("its site id is not a valid domain name".into());
    }
    Ok(rp_id)
}

/// A site id from a hirz export, kept exactly: hirz stores whatever a security key client sent,
/// except machine login ids, which it refuses to serve. Printable ASCII only.
pub fn exact_site_id(raw: &str) -> Result<String, String> {
    if machine_login_id(raw) {
        return Err(MACHINE_LOGIN.into());
    }
    if raw.is_empty() || raw.len() > MAX_STRING_LEN || !printable_ascii(raw) {
        return Err("its site id is not text hirz can keep as it is".into());
    }
    Ok(raw.to_string())
}

/// The engine refuses these ids (`pam://HOST`, `io.systemd.home`, `io.systemd.cryptsetup`), so a
/// passkey for one could be stored but never used; the list is the engine's own.
fn machine_login_id(raw: &str) -> bool {
    hirz_core::machine_login::is_machine_login_rp_id(raw)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

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
pub fn creation_time(at: Option<u64>, now: u64) -> u64 {
    at.filter(|t| *t > 0).map_or(now, |t| t.min(now))
}

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
    fn site_ids() {
        assert_eq!(site_id("Example.COM").unwrap(), "example.com");
        assert_eq!(site_id("ssh:").unwrap(), "ssh:");
        assert_eq!(site_id("ssh:Work Key").unwrap(), "ssh:Work Key");
        for bad in [
            "",
            "ssh:\u{1b}[2J",
            "ssh:caf\u{e9}",
            "a_b.com",
            "pam://host",
            "x:y",
        ] {
            assert!(site_id(bad).is_err(), "{bad:?}");
        }
        for machine in [
            "pam://host",
            "PAM://host",
            "io.systemd.home",
            "IO.Systemd.Cryptsetup",
            "io.systemd.cryptsetup",
        ] {
            assert_eq!(site_id(machine).unwrap_err(), MACHINE_LOGIN, "{machine}");
        }
        assert!(site_id("io.systemd.home.example.com").is_ok());
        assert!(site_id(&format!("ssh:{}", "a".repeat(MAX_STRING_LEN))).is_err());
    }

    #[test]
    fn exact_site_ids_keep_what_hirz_stores() {
        for ok in [
            "Example.COM",
            "ssh:",
            "ssh:Work Key",
            "io.example.app",
            "a:b",
        ] {
            assert_eq!(exact_site_id(ok).unwrap(), ok);
        }
        for bad in [
            "",
            "pam://host",
            "PAM://host",
            "io.systemd.home",
            "io.systemd.cryptsetup",
            "tab\t",
            "caf\u{e9}",
            "\u{1b}",
        ] {
            assert!(exact_site_id(bad).is_err(), "{bad:?}");
        }
        assert!(exact_site_id(&"a".repeat(MAX_STRING_LEN + 1)).is_err());
    }

    #[test]
    fn creation_times_never_lie_about_the_future() {
        assert_eq!(creation_time(Some(100), 500), 100);
        assert_eq!(creation_time(Some(500), 500), 500);
        assert_eq!(creation_time(Some(501), 500), 500);
        assert_eq!(creation_time(Some(500 + 86_400), 500), 500);
        assert_eq!(creation_time(Some(u64::MAX), 500), 500);
        assert_eq!(creation_time(Some(0), 500), 500);
        assert_eq!(creation_time(None, 500), 500);
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
