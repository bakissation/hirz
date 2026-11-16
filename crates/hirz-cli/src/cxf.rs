//! FIDO Credential Exchange Format 1.0 (Proposed Standard): passkey items only. Export writes one
//! `Account` with one `Item` per passkey; import reads every `passkey` credential and counts the
//! other credential types, which hirz does not store.

use crate::foreign::{
    MAX_FILE_LEN, creation_time, exact_site_id, identify_key, non_empty, opt_text, site_id,
    with_json,
};
use hirz_crypto::{Zeroize, Zeroizing};
use hirz_proto::json::{Json, Limits};
use hirz_vault::{
    CredentialRecord, HmacSecretPair, MAX_CREDENTIAL_ID_LEN, MAX_PKCS8_LEN, MAX_USER_ID_LEN,
};
use serde_json::{Map, Value, json};

pub const EXPORTER_RP_ID: &str = "hirz.berkati.xyz";
pub const EXPORTER_NAME: &str = "hirz";
/// Item extension carrying hirz fields that CXF has no place for.
pub const HIRZ_EXTENSION: &str = "hirz.berkati.xyz/passkey";
pub const MAX_PASSKEYS: usize = 100_000;

const LIMITS: Limits = Limits {
    max_len: MAX_FILE_LEN,
    max_depth: 32,
    max_items: 3_000_000,
};

fn b64(bytes: &[u8]) -> String {
    hirz_proto::base64url::encode(bytes)
}

/// base64url as CXF requires; trailing `=` padding from lenient exporters is accepted.
fn unb64(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    hirz_proto::base64url::decode(s.trim_end_matches('='))
        .ok()
        .map(Zeroizing::new)
}

pub fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(o) => o.values_mut().for_each(wipe),
        _ => {}
    }
}

/// `json!` copies every value it is given, and the original is then freed without being wiped, so
/// nothing that holds a secret goes through it: the document is built from maps and strings that
/// are moved into place and wiped together with it.
fn secret_text(bytes: &[u8]) -> Value {
    Value::String(b64(bytes))
}

fn passkey_item(r: &CredentialRecord) -> Value {
    let mut passkey = Map::new();
    passkey.insert("type".into(), Value::from("passkey"));
    passkey.insert("credentialId".into(), Value::from(b64(&r.credential_id)));
    passkey.insert("rpId".into(), Value::from(r.rp_id.as_str()));
    passkey.insert(
        "username".into(),
        Value::from(r.user_name.as_deref().unwrap_or_default()),
    );
    passkey.insert(
        "userDisplayName".into(),
        Value::from(r.user_display_name.as_deref().unwrap_or_default()),
    );
    passkey.insert("userHandle".into(), Value::from(b64(&r.user_id)));
    passkey.insert("key".into(), secret_text(&r.private_key_pkcs8));
    if let Some(h) = &r.hmac_secret {
        let mut credentials = Map::new();
        credentials.insert("algorithm".into(), Value::from("hmac-sha256"));
        credentials.insert(
            "credWithUV".into(),
            secret_text(h.cred_random_with_uv.as_slice()),
        );
        credentials.insert(
            "credWithoutUV".into(),
            secret_text(h.cred_random_without_uv.as_slice()),
        );
        let mut extensions = Map::new();
        extensions.insert("hmacCredentials".into(), Value::Object(credentials));
        passkey.insert("fido2Extensions".into(), Value::Object(extensions));
    }
    let mut ext = Map::new();
    ext.insert("name".into(), Value::from(HIRZ_EXTENSION));
    ext.insert("discoverable".into(), Value::from(r.discoverable));
    if let Some(n) = &r.rp_name {
        ext.insert("rpName".into(), Value::from(n.as_str()));
    }
    if let Some(level) = r.cred_protect {
        ext.insert("credProtect".into(), Value::from(level));
    }
    let mut item = Map::new();
    item.insert("id".into(), Value::from(b64(&r.credential_id)));
    item.insert("creationAt".into(), Value::from(r.created_at));
    item.insert("title".into(), Value::from(r.rp_id.as_str()));
    item.insert(
        "credentials".into(),
        Value::Array(vec![Value::Object(passkey)]),
    );
    item.insert("extensions".into(), Value::Array(vec![Value::Object(ext)]));
    if let Some(name) = &r.user_name {
        item.insert("subtitle".into(), Value::from(name.as_str()));
    }
    Value::Object(item)
}

/// Counts what a serializer writes, so the real pass can start with a buffer of exactly that size.
struct Measure(usize);

impl std::io::Write for Measure {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The file holds every private key in the clear, so it is written once into a buffer of its
/// final size: a buffer that grows would leave copies in memory that is freed without being wiped.
fn serialize_exact(doc: &Value) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut size = Measure(0);
    serde_json::to_writer_pretty(&mut size, doc).map_err(|e| e.to_string())?;
    let mut out = Zeroizing::new(Vec::with_capacity(size.0));
    serde_json::to_writer_pretty(&mut *out, doc).map_err(|e| e.to_string())?;
    if out.len() != size.0 {
        return Err("the export changed while it was written".into());
    }
    Ok(out)
}

/// hirz never uses a signature counter, so every passkey qualifies for export.
pub fn export_json(
    records: &[&CredentialRecord],
    timestamp: u64,
    account_id: &[u8; 16],
) -> Result<Zeroizing<Vec<u8>>, String> {
    let items: Vec<Value> = records.iter().map(|r| passkey_item(r)).collect();
    let mut account = Map::new();
    account.insert("id".into(), Value::from(b64(account_id)));
    account.insert("username".into(), Value::from(""));
    account.insert("email".into(), Value::from(""));
    account.insert("collections".into(), Value::Array(Vec::new()));
    account.insert("items".into(), Value::Array(items));
    let mut doc = Map::new();
    doc.insert("version".into(), json!({ "major": 1, "minor": 0 }));
    doc.insert("exporterRpId".into(), Value::from(EXPORTER_RP_ID));
    doc.insert("exporterDisplayName".into(), Value::from(EXPORTER_NAME));
    doc.insert("timestamp".into(), Value::from(timestamp));
    doc.insert(
        "accounts".into(),
        Value::Array(vec![Value::Object(account)]),
    );
    let mut doc = Value::Object(doc);
    let out = serialize_exact(&doc);
    wipe(&mut doc);
    out
}

/// Passkeys whose site id `hirz import` would refuse, so a restore from this export would lose them.
pub fn not_reimportable<'a>(records: &[&'a CredentialRecord]) -> Vec<&'a CredentialRecord> {
    records
        .iter()
        .copied()
        .filter(|r| exact_site_id(&r.rp_id).is_err())
        .collect()
}

#[derive(Debug)]
pub enum Candidate {
    Ready {
        record: Box<CredentialRecord>,
        dropped: Vec<&'static str>,
    },
    Skipped {
        label: String,
        reason: String,
    },
}

#[derive(Debug, Default)]
pub struct Parsed {
    pub exporter: String,
    pub passkeys: Vec<Candidate>,
    pub other_credentials: usize,
}

pub fn label(rp_id: &str, account: Option<&str>) -> String {
    let site = crate::ui::site(rp_id, 60);
    match account.map(|a| crate::ui::clean(a, 40)) {
        Some(a) if !a.is_empty() => format!("{site} ({a})"),
        _ => site,
    }
}

fn req_str<'a>(o: &'a Json, key: &str) -> Result<&'a str, String> {
    opt_text(o, key)?.ok_or_else(|| format!("the field {key} is missing"))
}

fn req_bytes(o: &Json, key: &str, max: usize) -> Result<Zeroizing<Vec<u8>>, String> {
    let s = match o.get(key) {
        Some(Json::String(s)) => s,
        Some(_) => return Err(format!("the field {key} is not text")),
        None => return Err(format!("the field {key} is missing")),
    };
    if s.len() > max.saturating_mul(2).saturating_add(8) {
        return Err(format!("the field {key} is too long"));
    }
    let b = unb64(s).ok_or_else(|| format!("the field {key} is not valid base64url"))?;
    if b.len() > max {
        return Err(format!("the field {key} is too long"));
    }
    Ok(b)
}

#[derive(Debug, Default)]
struct HirzExt {
    /// The item carries hirz's own extension, so the file is a hirz export.
    present: bool,
    rp_name: Option<String>,
    cred_protect: Option<u8>,
    discoverable: Option<bool>,
}

fn hirz_ext(item: &Json) -> HirzExt {
    let mut out = HirzExt::default();
    let Some(exts) = item.get("extensions").and_then(Json::as_array) else {
        return out;
    };
    for e in exts {
        if e.get("name").and_then(Json::as_str) != Some(HIRZ_EXTENSION) {
            continue;
        }
        out.present = true;
        out.rp_name = opt_text(e, "rpName")
            .ok()
            .flatten()
            .and_then(|s| non_empty(Some(s)));
        out.cred_protect = e
            .get("credProtect")
            .and_then(Json::as_u64)
            .filter(|v| (1..=3).contains(v))
            .and_then(|v| u8::try_from(v).ok());
        out.discoverable = e.get("discoverable").and_then(Json::as_bool);
    }
    out
}

fn passkey(
    pk: &Json,
    item: &Json,
    now: u64,
) -> Result<(CredentialRecord, Vec<&'static str>), String> {
    let credential_id = req_bytes(pk, "credentialId", MAX_CREDENTIAL_ID_LEN)?;
    if credential_id.is_empty() {
        return Err("its credential id is empty".into());
    }
    let extra = hirz_ext(item);
    let raw_rp_id = req_str(pk, "rpId")?;
    let rp_id = if extra.present {
        exact_site_id(raw_rp_id)?
    } else {
        site_id(raw_rp_id)?
    };
    let user_name = non_empty(opt_text(pk, "username")?);
    let user_display_name = non_empty(opt_text(pk, "userDisplayName")?);
    let user_id = req_bytes(pk, "userHandle", MAX_USER_ID_LEN)?;
    let key = req_bytes(pk, "key", MAX_PKCS8_LEN)?;
    if key.is_empty() {
        return Err("its private key is empty".into());
    }
    let algorithm = identify_key(&key)?;

    let mut dropped = Vec::new();
    let mut hmac_secret = None;
    match pk.get("fido2Extensions") {
        None | Some(Json::Null) => {}
        Some(ext @ Json::Object(_)) => {
            match ext.get("hmacCredentials") {
                None | Some(Json::Null) => {}
                Some(h @ Json::Object(_)) => {
                    if h.get("algorithm").and_then(Json::as_str) == Some("hmac-sha256") {
                        let with = req_bytes(h, "credWithUV", 64)?;
                        let without = req_bytes(h, "credWithoutUV", 64)?;
                        let (Ok(w), Ok(wo)) = (
                            <[u8; 32]>::try_from(with.as_slice()),
                            <[u8; 32]>::try_from(without.as_slice()),
                        ) else {
                            return Err("its PRF (hmac-secret) values are not 32 bytes; \
                                 hirz could not reproduce them"
                                .into());
                        };
                        hmac_secret = Some(HmacSecretPair {
                            cred_random_with_uv: Zeroizing::new(w),
                            cred_random_without_uv: Zeroizing::new(wo),
                        });
                    } else {
                        dropped.push("PRF values for an unknown algorithm");
                    }
                }
                Some(_) => return Err("its hmacCredentials field is malformed".into()),
            }
            if ext.get("credBlob").is_some_and(|v| !v.is_null()) {
                dropped.push("credBlob data");
            }
            if ext.get("largeBlob").is_some_and(|v| !v.is_null()) {
                dropped.push("largeBlob data");
            }
        }
        Some(_) => return Err("its fido2Extensions field is malformed".into()),
    }

    let created_at = creation_time(item.get("creationAt").and_then(Json::as_u64), now);
    let record = CredentialRecord {
        credential_id: credential_id.to_vec(),
        rp_id,
        rp_name: extra.rp_name,
        user_id: user_id.to_vec(),
        user_name,
        user_display_name,
        algorithm,
        private_key_pkcs8: key,
        created_at,
        cred_protect: extra.cred_protect,
        hmac_secret,
        discoverable: extra.discoverable.unwrap_or(true),
        backup_eligible: true,
    };
    record
        .validate()
        .map_err(|e| format!("it is not a valid passkey ({e})"))?;
    Ok((record, dropped))
}

fn version_ok(doc: &Json) -> Result<(), String> {
    let Some(v @ Json::Object(_)) = doc.get("version") else {
        return Err("This is not a CXF file: it has no version.".into());
    };
    match v.get("major").and_then(Json::as_u64) {
        Some(1) => Ok(()),
        Some(m) => Err(format!(
            "This file uses version {m} of the exchange format; hirz reads version 1."
        )),
        None => Err("This is not a CXF file: its version is malformed.".into()),
    }
}

fn object_list<'a>(o: &'a Json, key: &str) -> Result<&'a [Json], String> {
    match o.get(key) {
        None => Ok(&[]),
        Some(Json::Array(a)) => Ok(a),
        Some(_) => Err(format!("The file is malformed: {key} is not a list.")),
    }
}

/// Fails only when the document as a whole is unusable; a bad passkey becomes a `Skipped` entry.
pub fn parse(data: &[u8], now: u64) -> Result<Parsed, String> {
    parse_with(data, now, &LIMITS)
}

fn parse_with(data: &[u8], now: u64, limits: &Limits) -> Result<Parsed, String> {
    with_json(
        data,
        limits,
        "The file is not valid JSON, so it is not a CXF export.",
        |doc| parse_doc(doc, now),
    )
}

fn parse_doc(doc: &Json, now: u64) -> Result<Parsed, String> {
    if doc.as_object().is_none() {
        return Err("The file is not a CXF export.".into());
    }
    version_ok(doc)?;
    if doc.get("accounts").and_then(Json::as_array).is_none() {
        return Err("This is not a CXF file: it has no accounts list.".into());
    }
    let mut parsed = Parsed {
        exporter: doc
            .get("exporterDisplayName")
            .and_then(Json::as_str)
            .map(|s| crate::ui::clean(s, 60))
            .unwrap_or_default(),
        ..Parsed::default()
    };
    for account in object_list(doc, "accounts")? {
        if account.as_object().is_none() {
            continue;
        }
        for item in object_list(account, "items")? {
            if item.as_object().is_none() {
                continue;
            }
            for cred in object_list(item, "credentials")? {
                if cred.as_object().is_none() {
                    continue;
                }
                if cred.get("type").and_then(Json::as_str) != Some("passkey") {
                    parsed.other_credentials = parsed.other_credentials.saturating_add(1);
                    continue;
                }
                if parsed.passkeys.len() >= MAX_PASSKEYS {
                    return Err(format!(
                        "The file holds more than {MAX_PASSKEYS} passkeys; hirz will not read it."
                    ));
                }
                let candidate = match passkey(cred, item, now) {
                    Ok((record, dropped)) => Candidate::Ready {
                        record: Box::new(record),
                        dropped,
                    },
                    Err(reason) => Candidate::Skipped {
                        label: label(
                            cred.get("rpId")
                                .and_then(Json::as_str)
                                .unwrap_or("(unknown site)"),
                            cred.get("username").and_then(Json::as_str),
                        ),
                        reason,
                    },
                };
                parsed.passkeys.push(candidate);
            }
        }
    }
    Ok(parsed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use hirz_core::COSE_ALG_ES256;

    #[test]
    fn export_then_parse() {
        let (key, _, _) = hirz_crypto::es256::generate().unwrap();
        let r = CredentialRecord {
            credential_id: vec![9; 32],
            rp_id: "example.com".into(),
            rp_name: None,
            user_id: vec![],
            user_name: None,
            user_display_name: None,
            algorithm: COSE_ALG_ES256,
            private_key_pkcs8: key,
            created_at: 1_600_000_000,
            cred_protect: Some(2),
            hmac_secret: None,
            discoverable: false,
            backup_eligible: true,
        };
        let json = export_json(&[&r], 1_700_000_000, &[0; 16]).unwrap();
        let parsed = parse(&json, 1_700_000_000).unwrap();
        assert_eq!(parsed.exporter, "hirz");
        assert_eq!(parsed.other_credentials, 0);
        match &parsed.passkeys[..] {
            [Candidate::Ready { record, dropped }] => {
                assert_eq!(**record, r);
                assert!(dropped.is_empty());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn wipe_clears_strings() {
        let mut v = json!({"a": ["secret", {"b": "key"}], "n": 1});
        wipe(&mut v);
        assert_eq!(v, json!({"a": ["", {"b": ""}], "n": 1}));
    }

    #[test]
    fn future_creation_times_become_now() {
        for future in ["99999999999", "1800003600", "1800000001"] {
            let doc = include_str!("../tests/fixtures/provider-export.json")
                .replace("1700000000", future);
            let parsed = parse(doc.as_bytes(), 1_800_000_000).unwrap();
            let Candidate::Ready { record, .. } = &parsed.passkeys[0] else {
                panic!("first passkey should import");
            };
            assert_eq!(record.created_at, 1_800_000_000, "{future}");
        }
        let past = include_str!("../tests/fixtures/provider-export.json");
        let parsed = parse(past.as_bytes(), 1_800_000_000).unwrap();
        let Candidate::Ready { record, .. } = &parsed.passkeys[0] else {
            panic!("first passkey should import");
        };
        assert_eq!(record.created_at, 1_700_000_000);
    }

    fn sample(rp: &str, id: u8) -> CredentialRecord {
        let (key, _, _) = hirz_crypto::es256::generate().unwrap();
        CredentialRecord {
            credential_id: vec![id; 32],
            rp_id: rp.into(),
            rp_name: None,
            user_id: vec![id; 16],
            user_name: Some("alice".into()),
            user_display_name: None,
            algorithm: COSE_ALG_ES256,
            private_key_pkcs8: key,
            created_at: 1_600_000_000,
            cred_protect: None,
            hmac_secret: None,
            discoverable: false,
            backup_eligible: true,
        }
    }

    #[test]
    fn export_round_trip_keeps_ssh_and_other_ids() {
        let ids = [
            "ssh:",
            "ssh:Work Key",
            "Example.COM",
            "localhost",
            "io.example.app",
        ];
        let records: Vec<CredentialRecord> = ids
            .iter()
            .enumerate()
            .map(|(i, rp)| sample(rp, u8::try_from(i).unwrap() + 1))
            .collect();
        let refs: Vec<&CredentialRecord> = records.iter().collect();
        assert!(not_reimportable(&refs).is_empty());
        let json = export_json(&refs, 1_700_000_000, &[0; 16]).unwrap();
        let parsed = parse(&json, 1_700_000_000).unwrap();
        assert_eq!(parsed.passkeys.len(), ids.len());
        for (c, want) in parsed.passkeys.iter().zip(&records) {
            match c {
                Candidate::Ready { record, .. } => assert_eq!(**record, *want),
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn the_export_is_built_once_in_a_buffer_of_its_own_size() {
        let records: Vec<CredentialRecord> = (1..=30).map(|i| sample("example.com", i)).collect();
        let refs: Vec<&CredentialRecord> = records.iter().collect();
        let json = export_json(&refs, 1_700_000_000, &[0; 16]).unwrap();
        assert!(json.len() > 8000);
        assert_eq!(
            json.capacity(),
            json.len(),
            "a buffer that grew would have left copies of the private keys in freed memory"
        );
        let again = export_json(&refs, 1_700_000_000, &[0; 16]).unwrap();
        assert_eq!(
            *json, *again,
            "the measuring pass and the writing pass agree"
        );
        let empty = export_json(&[], 1, &[0; 16]).unwrap();
        assert_eq!(empty.capacity(), empty.len());
        assert!(parse(&empty, 2).unwrap().passkeys.is_empty());
    }

    #[test]
    fn export_reports_ids_an_import_would_refuse() {
        let odd = [
            sample("caf\u{e9}.example", 1),
            sample("tab\there", 2),
            sample("pam://host", 3),
            sample("ok.example", 4),
        ];
        let refs: Vec<&CredentialRecord> = odd.iter().collect();
        let lost: Vec<&str> = not_reimportable(&refs)
            .iter()
            .map(|r| r.rp_id.as_str())
            .collect();
        assert_eq!(lost, ["caf\u{e9}.example", "tab\there", "pam://host"]);
        let json = export_json(&refs, 1_700_000_000, &[0; 16]).unwrap();
        let parsed = parse(&json, 1_700_000_000).unwrap();
        let ready = parsed
            .passkeys
            .iter()
            .filter(|c| matches!(c, Candidate::Ready { .. }))
            .count();
        assert_eq!(ready, 1);
    }

    #[test]
    fn other_programs_files_need_host_names_or_ssh_ids() {
        let mut doc: Value =
            serde_json::from_str(include_str!("../tests/fixtures/provider-export.json")).unwrap();
        for (rp, want) in [
            ("ssh:work", Some("ssh:work")),
            ("Mixed.Example", Some("mixed.example")),
            ("https://example.com", None),
            ("ssh:bad\u{1b}", None),
        ] {
            doc["accounts"][0]["items"][0]["credentials"][0]["rpId"] = Value::from(rp);
            let parsed = parse(&serde_json::to_vec(&doc).unwrap(), 1_700_000_000).unwrap();
            match (&parsed.passkeys[0], want) {
                (Candidate::Ready { record, .. }, Some(w)) => assert_eq!(record.rp_id, w),
                (Candidate::Skipped { reason, .. }, None) => {
                    assert!(reason.contains("not a valid domain name"), "{rp}");
                }
                (other, _) => panic!("{rp}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_flood_of_values_is_refused_before_any_structure_check() {
        let limits = Limits {
            max_items: 1000,
            ..LIMITS
        };
        let flood = format!("[{}0]", "0,".repeat(5000));
        let err = parse_with(flood.as_bytes(), 0, &limits).unwrap_err();
        assert!(err.contains("too large or too deeply nested"), "{err}");
        let deep = format!("{}{}", "[".repeat(40), "]".repeat(40));
        let err = parse(deep.as_bytes(), 0).unwrap_err();
        assert!(err.contains("too large or too deeply nested"), "{err}");
        assert_eq!(LIMITS.max_len, crate::foreign::MAX_FILE_LEN);
        assert!(LIMITS.max_items >= MAX_PASSKEYS.saturating_mul(27));
    }

    #[test]
    fn duplicate_keys_are_refused() {
        let doc = br#"{"version":{"major":1,"major":1},"accounts":[]}"#;
        assert!(parse(doc, 0).is_err());
    }
}
