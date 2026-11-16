//! Bitwarden JSON exports: unencrypted, and password protected (a PBKDF2-SHA256 or Argon2id
//! key stretched with HKDF into AES-256-CBC and HMAC-SHA256 keys). Exports encrypted with
//! the Bitwarden account key ("account restricted") cannot be read outside Bitwarden.
//!
//! Only `login.fido2Credentials` entries are read.

use super::{
    Found, MAX_FILE_LEN, MAX_PASSKEYS, Parsed, base64_field, creation_time, finish, identify_key,
    lenient_base64, non_empty, opt_text, parse_utc, shown, site_id, with_json,
};
use hirz_core::COSE_ALG_ES256;
use hirz_crypto::kdf::Argon2Params;
use hirz_crypto::{Secret, Zeroizing, aes_cbc_hmac};
use hirz_proto::json::{Json, Limits};
use hirz_vault::{CredentialRecord, MAX_CREDENTIAL_ID_LEN, MAX_PKCS8_LEN, MAX_USER_ID_LEN};

/// Largest number of vault items (of any kind) in one export.
pub const MAX_ITEMS: usize = 200_000;

const LIMITS: Limits = Limits {
    max_len: MAX_FILE_LEN,
    max_depth: 32,
    max_items: 3_000_000,
};

/// KDF parameter ranges Bitwarden clients accept for password protected exports.
const PBKDF2_ITERATIONS: core::ops::RangeInclusive<u64> = 5_000..=2_000_000;
const ARGON2_ITERATIONS: core::ops::RangeInclusive<u64> = 2..=10;
const ARGON2_MEMORY_MIB: core::ops::RangeInclusive<u64> = 16..=1024;
const ARGON2_PARALLELISM: core::ops::RangeInclusive<u64> = 1..=16;

const NOT_BITWARDEN: &str = "The file is not valid JSON, so it is not a Bitwarden JSON export.";

/// Key derivation of a password protected export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    Pbkdf2 {
        iterations: u32,
    },
    Argon2id {
        iterations: u32,
        memory_mib: u32,
        parallelism: u32,
    },
}

/// A Bitwarden EncString of type 2: AES-256-CBC, then HMAC-SHA256 over IV and ciphertext.
#[derive(Debug, Clone)]
struct EncString {
    iv: [u8; aes_cbc_hmac::IV_LEN],
    ciphertext: Vec<u8>,
    mac: [u8; aes_cbc_hmac::TAG_LEN],
}

impl EncString {
    fn parse(s: &str) -> Result<EncString, String> {
        let Some(body) = s.strip_prefix("2.") else {
            return Err(
                "The password protected export uses an encryption type hirz does not \
                        read."
                    .into(),
            );
        };
        let damaged = || "The password protected export is damaged.".to_string();
        let mut parts = body.split('|');
        let (Some(iv), Some(ct), Some(mac), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(damaged());
        };
        let iv = lenient_base64(iv)
            .and_then(|b| <[u8; aes_cbc_hmac::IV_LEN]>::try_from(b.as_slice()).ok())
            .ok_or_else(damaged)?;
        let mac = lenient_base64(mac)
            .and_then(|b| <[u8; aes_cbc_hmac::TAG_LEN]>::try_from(b.as_slice()).ok())
            .ok_or_else(damaged)?;
        let ciphertext = lenient_base64(ct)
            .filter(|b| !b.is_empty() && b.len().is_multiple_of(16))
            .ok_or_else(damaged)?
            .to_vec();
        Ok(EncString {
            iv,
            ciphertext,
            mac,
        })
    }

    fn open(&self, key: &StretchedKey) -> Result<Secret, hirz_crypto::CryptoError> {
        aes_cbc_hmac::open(&key.enc, &key.mac, &self.iv, &self.ciphertext, &self.mac)
    }
}

/// The encryption and MAC keys derived from the file password.
#[derive(Debug)]
pub struct StretchedKey {
    enc: Zeroizing<[u8; 32]>,
    mac: Zeroizing<[u8; 32]>,
}

impl StretchedKey {
    pub fn from_parts(enc: [u8; 32], mac: [u8; 32]) -> StretchedKey {
        StretchedKey {
            enc: Zeroizing::new(enc),
            mac: Zeroizing::new(mac),
        }
    }

    /// HKDF-Expand of the KDF output with the infos "enc" and "mac", as Bitwarden stretches
    /// keys.
    fn stretch(master: &[u8]) -> Result<StretchedKey, hirz_crypto::CryptoError> {
        let mut key = StretchedKey::from_parts([0; 32], [0; 32]);
        hirz_crypto::hkdf_sha256_expand(master, b"enc", key.enc.as_mut_slice())?;
        hirz_crypto::hkdf_sha256_expand(master, b"mac", key.mac.as_mut_slice())?;
        Ok(key)
    }
}

/// Why a password protected export could not be opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    WrongPassword,
    Damaged,
}

/// A password protected export, before the password is known.
#[derive(Debug, Clone)]
pub struct Protected {
    salt: String,
    pub kdf: Kdf,
    validation: EncString,
    data: EncString,
}

fn derive(salt: &str, kdf: Kdf, password: &[u8]) -> Result<StretchedKey, OpenError> {
    let master = match kdf {
        Kdf::Pbkdf2 { iterations } => {
            hirz_crypto::pbkdf2_hmac_sha256(password, salt.as_bytes(), iterations, 32)
        }
        Kdf::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => hirz_crypto::kdf::argon2id(
            password,
            &hirz_crypto::sha256(salt.as_bytes()),
            Argon2Params {
                m_cost_kib: memory_mib.saturating_mul(1024),
                t_cost: iterations,
                p_cost: parallelism,
            },
        ),
    }
    .map_err(|_| OpenError::Damaged)?;
    StretchedKey::stretch(&master).map_err(|_| OpenError::Damaged)
}

impl Protected {
    pub fn derive_key(&self, password: &[u8]) -> Result<StretchedKey, OpenError> {
        derive(&self.salt, self.kdf, password)
    }

    /// Checks the key against the validation value, then decrypts the inner export.
    pub fn decrypt_with(&self, key: &StretchedKey) -> Result<Secret, OpenError> {
        self.validation.open(key).map_err(|e| match e {
            hirz_crypto::CryptoError::Auth => OpenError::WrongPassword,
            _ => OpenError::Damaged,
        })?;
        self.data.open(key).map_err(|_| OpenError::Damaged)
    }

    pub fn decrypt(&self, password: &[u8]) -> Result<Secret, OpenError> {
        if password.is_empty() {
            return Err(OpenError::WrongPassword);
        }
        self.decrypt_with(&self.derive_key(password)?)
    }
}

/// What an export file holds.
#[derive(Debug)]
pub enum Export {
    Plain(Parsed),
    Protected(Box<Protected>),
}

fn bounded(v: Option<&Json>, range: &core::ops::RangeInclusive<u64>) -> Option<u32> {
    v.and_then(Json::as_u64)
        .filter(|n| range.contains(n))
        .and_then(|n| u32::try_from(n).ok())
}

fn kdf(doc: &Json) -> Result<Kdf, String> {
    let out_of_range = || {
        "The password protected export asks for key derivation settings outside the range \
         Bitwarden uses; hirz will not read it."
            .to_string()
    };
    match doc.get("kdfType").and_then(Json::as_u64) {
        Some(0) => Ok(Kdf::Pbkdf2 {
            iterations: bounded(doc.get("kdfIterations"), &PBKDF2_ITERATIONS)
                .ok_or_else(out_of_range)?,
        }),
        Some(1) => Ok(Kdf::Argon2id {
            iterations: bounded(doc.get("kdfIterations"), &ARGON2_ITERATIONS)
                .ok_or_else(out_of_range)?,
            memory_mib: bounded(doc.get("kdfMemory"), &ARGON2_MEMORY_MIB)
                .ok_or_else(out_of_range)?,
            parallelism: bounded(doc.get("kdfParallelism"), &ARGON2_PARALLELISM)
                .ok_or_else(out_of_range)?,
        }),
        _ => Err("The password protected export uses a key derivation hirz does not know.".into()),
    }
}

fn protected(doc: &Json) -> Result<Protected, String> {
    let text = |key: &str| {
        doc.get(key)
            .and_then(Json::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("The password protected export is damaged: {key} is missing."))
    };
    let salt = text("salt")?;
    if salt.len() > 1024 {
        return Err("The password protected export is damaged: its salt is too long.".into());
    }
    Ok(Protected {
        salt: salt.to_string(),
        kdf: kdf(doc)?,
        validation: EncString::parse(text("encKeyValidation_DO_NOT_EDIT")?)?,
        data: EncString::parse(text("data")?)?,
    })
}

fn classify(doc: &Json, now: u64) -> Result<Export, String> {
    if doc.as_object().is_none() {
        return Err("The file is not a Bitwarden JSON export.".into());
    }
    if doc.get("encrypted").and_then(Json::as_bool) == Some(true) {
        if doc.get("passwordProtected").and_then(Json::as_bool) == Some(true) {
            return protected(doc).map(|p| Export::Protected(Box::new(p)));
        }
        return Err(
            "This Bitwarden export is encrypted with your Bitwarden account key \
                    (\"account restricted\"), which only Bitwarden can read. Export again \
                    from Bitwarden and choose the \"password protected\" file type or an \
                    unencrypted .json file."
                .into(),
        );
    }
    items(doc, now).map(Export::Plain)
}

/// Reads an export file: the passkeys of an unencrypted export, or the parameters of a
/// password protected one.
pub fn read(data: &[u8], now: u64) -> Result<Export, String> {
    with_json(data, &LIMITS, NOT_BITWARDEN, |doc| classify(doc, now))
}

/// Reads the decrypted contents of a password protected export.
pub fn read_decrypted(data: &[u8], now: u64) -> Result<Parsed, String> {
    with_json(
        data,
        &LIMITS,
        "The decrypted export is not valid JSON.",
        |doc| {
            if doc.get("encrypted").and_then(Json::as_bool) == Some(true) {
                return Err("The decrypted export is encrypted again; hirz cannot read it.".into());
            }
            items(doc, now)
        },
    )
}

fn items(doc: &Json, now: u64) -> Result<Parsed, String> {
    let Some(items) = doc.get("items").and_then(Json::as_array) else {
        return Err("This is not a Bitwarden JSON export: it has no items list.".into());
    };
    if items.len() > MAX_ITEMS {
        return Err(format!(
            "The export holds more than {MAX_ITEMS} items; hirz will not read it."
        ));
    }
    let mut parsed = Parsed::default();
    for item in items {
        let creds = item
            .get("login")
            .and_then(|l| l.get("fido2Credentials"))
            .and_then(Json::as_array)
            .unwrap_or(&[]);
        if creds.is_empty() {
            parsed.other_items = parsed.other_items.saturating_add(1);
            continue;
        }
        for c in creds {
            if parsed.passkeys.len() >= MAX_PASSKEYS {
                return Err(format!(
                    "The export holds more than {MAX_PASSKEYS} passkeys; hirz will not read it."
                ));
            }
            parsed.passkeys.push(match passkey(c, now) {
                Ok(record) => Found::Ready(Box::new(record)),
                Err(reason) => Found::Skipped {
                    site: c
                        .get("rpId")
                        .and_then(Json::as_str)
                        .unwrap_or("(unknown site)")
                        .to_string(),
                    account: c.get("userName").and_then(Json::as_str).map(str::to_string),
                    reason,
                },
            });
        }
    }
    Ok(parsed)
}

/// Raw bytes of a credential id as Bitwarden stores it: `b64.` and base64url, or a GUID
/// that stands for its 16 bytes.
pub fn credential_id(s: &str) -> Option<Vec<u8>> {
    if let Some(b64) = s.strip_prefix("b64.") {
        if b64.len() > MAX_CREDENTIAL_ID_LEN.saturating_mul(2) {
            return None;
        }
        return lenient_base64(b64)
            .filter(|b| !b.is_empty() && b.len() <= MAX_CREDENTIAL_ID_LEN)
            .map(|b| b.to_vec());
    }
    let groups: Vec<&str> = s.split('-').collect();
    let lens: Vec<usize> = groups.iter().map(|g| g.len()).collect();
    if lens != [8, 4, 4, 4, 12] {
        return None;
    }
    hirz_proto::hex::decode(&groups.concat().to_ascii_lowercase()).ok()
}

fn text_or_bool(v: Option<&Json>) -> bool {
    match v {
        Some(Json::Bool(b)) => *b,
        Some(Json::String(s)) => s == "true",
        _ => false,
    }
}

fn passkey(c: &Json, now: u64) -> Result<CredentialRecord, String> {
    if c.as_object().is_none() {
        return Err("its entry is malformed".into());
    }
    let key_type = opt_text(c, "keyType")?.unwrap_or_default();
    let alg = opt_text(c, "keyAlgorithm")?.unwrap_or_default();
    let curve = opt_text(c, "keyCurve")?.unwrap_or_default();
    if key_type != "public-key" || alg != "ECDSA" || curve != "P-256" {
        return Err(format!(
            "its key type is {} {}; hirz imports only P-256 (ES256) passkeys from Bitwarden",
            shown(alg),
            shown(curve)
        ));
    }
    let credential_id = opt_text(c, "credentialId")?
        .and_then(credential_id)
        .ok_or("its credential id is missing or malformed")?;
    let rp_id = site_id(opt_text(c, "rpId")?.ok_or("the field rpId is missing")?)?;
    let key = base64_field(c, "keyValue", MAX_PKCS8_LEN)?;
    if key.is_empty() {
        return Err("its private key is missing".into());
    }
    if identify_key(&key)? != COSE_ALG_ES256 {
        return Err("its private key is not the P-256 key the entry declares".into());
    }
    let user_id = base64_field(c, "userHandle", MAX_USER_ID_LEN)?;
    let created = opt_text(c, "creationDate")?.and_then(parse_utc);
    finish(CredentialRecord {
        credential_id,
        rp_id,
        rp_name: non_empty(opt_text(c, "rpName")?),
        user_id: user_id.to_vec(),
        user_name: non_empty(opt_text(c, "userName")?),
        user_display_name: non_empty(opt_text(c, "userDisplayName")?),
        algorithm: COSE_ALG_ES256,
        private_key_pkcs8: key,
        created_at: creation_time(created, now),
        cred_protect: None,
        hmac_secret: None,
        discoverable: text_or_bool(c.get("discoverable")),
        backup_eligible: true,
    })
}

/// Encrypts an export as a password protected Bitwarden export, for tests.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub fn protect(plain: &[u8], password: &str, salt: &str, kdf: Kdf) -> String {
    let key = derive(salt, kdf, password.as_bytes()).unwrap();
    let b64 = |x: &[u8]| {
        let mut s = hirz_proto::base64url::encode(x)
            .replace('-', "+")
            .replace('_', "/");
        while !s.len().is_multiple_of(4) {
            s.push('=');
        }
        s
    };
    let enc = |msg: &[u8]| {
        let (iv, ct, mac) = aes_cbc_hmac::seal(&key.enc, &key.mac, msg).unwrap();
        format!("2.{}|{}|{}", b64(&iv), b64(&ct), b64(&mac))
    };
    let (kdf_type, it, mem, par) = match kdf {
        Kdf::Pbkdf2 { iterations } => (0, iterations, "null".to_string(), "null".to_string()),
        Kdf::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => (
            1,
            iterations,
            memory_mib.to_string(),
            parallelism.to_string(),
        ),
    };
    format!(
        r#"{{"encrypted": true, "passwordProtected": true, "salt": "{salt}", "kdfType": {kdf_type},
"kdfIterations": {it}, "kdfMemory": {mem}, "kdfParallelism": {par},
"encKeyValidation_DO_NOT_EDIT": "{}", "data": "{}"}}"#,
        enc(b"6c7e3b2a-0d4f-4a8e-9b1c-2f3e4d5a6b7c"),
        enc(plain)
    )
}

/// One `fido2Credentials` entry as Bitwarden exports it, for tests.
#[cfg(test)]
pub fn fido2_entry(id: &str, rp: &str, user: &str, curve: &str, pkcs8: &[u8]) -> String {
    format!(
        r#"{{"credentialId": "{id}", "keyType": "public-key", "keyAlgorithm": "ECDSA",
"keyCurve": "{curve}", "keyValue": "{}", "rpId": "{rp}", "userHandle": "{}",
"userName": "{user}", "counter": "0", "rpName": "{rp}", "userDisplayName": "{user}",
"discoverable": "true", "creationDate": "2024-02-29T12:00:00.000Z"}}"#,
        hirz_proto::base64url::encode(pkcs8),
        hirz_proto::base64url::encode(user.as_bytes()),
    )
}

/// An unencrypted export with one login per entry list and one secure note, for tests.
#[cfg(test)]
pub fn plain_export(logins: &[Vec<String>]) -> String {
    let mut items: Vec<String> = logins
        .iter()
        .enumerate()
        .map(|(i, creds)| {
            format!(
                r#"{{"id": "item-{i}", "type": 1, "name": "login {i}", "notes": "secret note",
"login": {{"username": "alice", "password": "hunter2", "totp": "otpauth://totp/x",
"uris": [{{"uri": "https://example.com", "match": null}}],
"fido2Credentials": [{}]}}}}"#,
                creds.join(",")
            )
        })
        .collect();
    items.push(
        r#"{"id": "note", "type": 2, "name": "note", "notes": "n", "secureNote": {"type": 0}}"#
            .into(),
    );
    format!(
        r#"{{"encrypted": false, "folders": [], "items": [{}]}}"#,
        items.join(",")
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const GUID: &str = "6C7E3B2A-0d4f-4a8e-9b1c-2f3e4d5a6b7c";
    const GUID_BYTES: [u8; 16] = [
        0x6c, 0x7e, 0x3b, 0x2a, 0x0d, 0x4f, 0x4a, 0x8e, 0x9b, 0x1c, 0x2f, 0x3e, 0x4d, 0x5a, 0x6b,
        0x7c,
    ];
    const NOW: u64 = 1_800_000_000;

    fn key() -> Secret {
        hirz_crypto::es256::generate().unwrap().0
    }

    fn sample() -> (String, Secret, Secret) {
        let (k1, k2) = (key(), key());
        let doc = plain_export(&[
            vec![
                fido2_entry(GUID, "Example.com", "alice", "P-256", &k1),
                fido2_entry("b64.AQIDBA", "acme.example", "bob", "P-256", &k2),
            ],
            vec![fido2_entry(
                "b64.BQYH",
                "example.org",
                "carol",
                "P-384",
                &k1,
            )],
        ]);
        (doc, k1, k2)
    }

    fn plain(data: &[u8]) -> Parsed {
        match read(data, NOW).unwrap() {
            Export::Plain(p) => p,
            Export::Protected(_) => panic!("expected a plain export"),
        }
    }

    fn check_sample(p: &Parsed, k1: &[u8], k2: &[u8]) {
        assert_eq!(p.other_items, 1);
        assert_eq!(p.passkeys.len(), 3);
        let Found::Ready(a) = &p.passkeys[0] else {
            panic!("{:?}", p.passkeys[0])
        };
        assert_eq!(a.credential_id, GUID_BYTES);
        assert_eq!(a.rp_id, "example.com");
        assert_eq!(a.user_id, b"alice");
        assert_eq!(a.user_name.as_deref(), Some("alice"));
        assert_eq!(a.user_display_name.as_deref(), Some("alice"));
        assert_eq!(a.rp_name.as_deref(), Some("Example.com"));
        assert_eq!(a.private_key_pkcs8.as_slice(), k1);
        assert_eq!(a.algorithm, COSE_ALG_ES256);
        assert_eq!(a.created_at, 1_709_208_000);
        assert!(a.discoverable && a.backup_eligible);
        let Found::Ready(b) = &p.passkeys[1] else {
            panic!("{:?}", p.passkeys[1])
        };
        assert_eq!(b.credential_id, [1, 2, 3, 4]);
        assert_eq!(b.private_key_pkcs8.as_slice(), k2);
        match &p.passkeys[2] {
            Found::Skipped {
                site,
                account,
                reason,
            } => {
                assert_eq!(site, "example.org");
                assert_eq!(account.as_deref(), Some("carol"));
                assert!(reason.contains("P-384"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn credential_ids() {
        assert_eq!(credential_id(GUID).unwrap(), GUID_BYTES);
        assert_eq!(credential_id("b64.-_8").unwrap(), [0xfb, 0xff]);
        for bad in [
            "",
            "b64.",
            "b64.!!",
            "6c7e3b2a0d4f4a8e9b1c2f3e4d5a6b7c",
            "6c7e3b2a-0d4f-4a8e-9b1c-2f3e4d5a6b7",
            "6c7e3b2a-0d4f-4a8e-9b1c-2f3e4d5a6b7g",
            "6c7e3b2a-0d4f-4a8e-9b1c2f3e-4d5a6b7c",
        ] {
            assert_eq!(credential_id(bad), None, "{bad}");
        }
        let long = format!("b64.{}", "A".repeat(1400));
        assert_eq!(credential_id(&long), None);
    }

    #[test]
    fn plain_export_keeps_passkeys_only() {
        let (doc, k1, k2) = sample();
        check_sample(&plain(doc.as_bytes()), &k1, &k2);
        let with_bom = [b"\xef\xbb\xbf".as_slice(), doc.as_bytes()].concat();
        check_sample(&plain(&with_bom), &k1, &k2);
    }

    #[test]
    fn password_protected_exports() {
        let (doc, k1, k2) = sample();
        for kdf in [
            Kdf::Pbkdf2 { iterations: 5_000 },
            Kdf::Argon2id {
                iterations: 2,
                memory_mib: 16,
                parallelism: 1,
            },
        ] {
            let file = protect(doc.as_bytes(), "pässword", "c2FsdHNhbHRzYWx0c2FsdA==", kdf);
            let Export::Protected(p) = read(file.as_bytes(), NOW).unwrap() else {
                panic!("expected a protected export");
            };
            assert_eq!(p.kdf, kdf);
            assert_eq!(p.decrypt(b"wrong").unwrap_err(), OpenError::WrongPassword);
            assert_eq!(p.decrypt(b"").unwrap_err(), OpenError::WrongPassword);
            let inner = p.decrypt("pässword".as_bytes()).unwrap();
            check_sample(&read_decrypted(&inner, NOW).unwrap(), &k1, &k2);

            let mut tampered = (*p).clone();
            tampered.data.mac[0] ^= 1;
            assert_eq!(
                tampered.decrypt("pässword".as_bytes()).unwrap_err(),
                OpenError::Damaged
            );
            let mut tampered = (*p).clone();
            tampered.data.ciphertext[0] ^= 1;
            assert_eq!(
                tampered.decrypt("pässword".as_bytes()).unwrap_err(),
                OpenError::Damaged
            );
            let mut tampered = (*p).clone();
            tampered.validation.mac[31] ^= 1;
            assert_eq!(
                tampered.decrypt("pässword".as_bytes()).unwrap_err(),
                OpenError::WrongPassword
            );
        }
    }

    #[test]
    fn rejected_containers() {
        let account = r#"{"encrypted": true, "encKeyValidation_DO_NOT_EDIT": "2.x|y|z",
            "folders": [], "items": []}"#;
        assert!(
            read(account.as_bytes(), NOW)
                .unwrap_err()
                .contains("account key")
        );
        let file = protect(b"{}", "pw", "salt", Kdf::Pbkdf2 { iterations: 5_000 });
        for (from, to) in [
            ("\"kdfIterations\": 5000", "\"kdfIterations\": 4999"),
            ("\"kdfIterations\": 5000", "\"kdfIterations\": 2000001"),
            ("\"kdfType\": 0", "\"kdfType\": 2"),
            ("\"kdfType\": 0", "\"kdfType\": 1"),
            ("\"data\": \"2.", "\"data\": \"0."),
            ("\"salt\": \"salt\"", "\"salt\": \"\""),
        ] {
            let bad = file.replace(from, to);
            assert_ne!(bad, file);
            assert!(read(bad.as_bytes(), NOW).is_err(), "{to}");
        }
        let argon = protect(
            b"{}",
            "pw",
            "salt",
            Kdf::Argon2id {
                iterations: 2,
                memory_mib: 16,
                parallelism: 1,
            },
        );
        for (from, to) in [
            ("\"kdfMemory\": 16", "\"kdfMemory\": 1025"),
            ("\"kdfParallelism\": 1", "\"kdfParallelism\": 17"),
            ("\"kdfIterations\": 2", "\"kdfIterations\": 11"),
        ] {
            assert!(
                read(argon.replace(from, to).as_bytes(), NOW).is_err(),
                "{to}"
            );
        }
        for bad in ["", "[]", "{}", "{\"items\": 1}", "not json"] {
            assert!(read(bad.as_bytes(), NOW).is_err(), "{bad}");
        }
        assert!(read_decrypted(account.as_bytes(), NOW).is_err());
    }

    #[test]
    fn malformed_entries_are_skipped() {
        let k = key();
        let good = fido2_entry("b64.AQ", "example.com", "a", "P-256", &k);
        let ed = hirz_crypto::ed25519::generate().unwrap().0;
        for (entry, why) in [
            (good.replace("b64.AQ", "nope"), "credential id"),
            (good.replace("\"ECDSA\"", "\"EdDSA\""), "EdDSA"),
            (good.replace("\"public-key\"", "\"x\""), "P-256"),
            (good.replace("example.com", "exa_mple.com"), "domain"),
            (
                fido2_entry("b64.AQ", "example.com", "a", "P-256", &ed),
                "not the P-256",
            ),
            (
                fido2_entry("b64.AQ", "example.com", "a", "P-256", b""),
                "missing",
            ),
            (
                good.replace("\"userName\": \"a\"", "\"userName\": 7"),
                "not text",
            ),
            ("7".to_string(), "malformed"),
        ] {
            let p = plain(plain_export(&[vec![entry]]).as_bytes());
            match &p.passkeys[0] {
                Found::Skipped { reason, .. } => assert!(reason.contains(why), "{reason}"),
                Found::Ready(_) => panic!("{why} should be skipped"),
            }
        }
        let future = good.replace("2024-02-29", "2999-01-01");
        let p = plain(plain_export(&[vec![future]]).as_bytes());
        let Found::Ready(r) = &p.passkeys[0] else {
            panic!("should import")
        };
        assert_eq!(r.created_at, NOW);
        let hidden = good.replace("\"discoverable\": \"true\"", "\"discoverable\": \"false\"");
        let p = plain(plain_export(&[vec![hidden]]).as_bytes());
        let Found::Ready(r) = &p.passkeys[0] else {
            panic!("should import")
        };
        assert!(!r.discoverable);
    }
}
