//! FIDO Credential Exchange Format 1.0 (Proposed Standard): passkey items only. Export writes one
//! `Account` with one `Item` per passkey; import reads every `passkey` credential and counts the
//! other credential types, which hirz does not store.

use crate::foreign::identify_key;
use hirz_crypto::{Zeroize, Zeroizing};
use hirz_vault::{
    CredentialRecord, HmacSecretPair, MAX_CREDENTIAL_ID_LEN, MAX_PKCS8_LEN, MAX_STRING_LEN,
    MAX_USER_ID_LEN,
};
use serde_json::{Map, Value, json};

pub const EXPORTER_RP_ID: &str = "hirz.berkati.xyz";
pub const EXPORTER_NAME: &str = "hirz";
/// Item extension carrying hirz fields that CXF has no place for.
pub const HIRZ_EXTENSION: &str = "hirz.berkati.xyz/passkey";
pub const MAX_PASSKEYS: usize = 100_000;

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

fn passkey_item(r: &CredentialRecord) -> Value {
    let mut passkey = json!({
        "type": "passkey",
        "credentialId": b64(&r.credential_id),
        "rpId": r.rp_id,
        "username": r.user_name.clone().unwrap_or_default(),
        "userDisplayName": r.user_display_name.clone().unwrap_or_default(),
        "userHandle": b64(&r.user_id),
        "key": b64(&r.private_key_pkcs8),
    });
    if let (Some(h), Value::Object(obj)) = (&r.hmac_secret, &mut passkey) {
        obj.insert(
            "fido2Extensions".into(),
            json!({
                "hmacCredentials": {
                    "algorithm": "hmac-sha256",
                    "credWithUV": b64(h.cred_random_with_uv.as_slice()),
                    "credWithoutUV": b64(h.cred_random_without_uv.as_slice()),
                }
            }),
        );
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
    let mut item = json!({
        "id": b64(&r.credential_id),
        "creationAt": r.created_at,
        "title": r.rp_id,
        "credentials": [passkey],
        "extensions": [Value::Object(ext)],
    });
    if let (Some(name), Value::Object(obj)) = (r.user_name.as_ref(), &mut item) {
        obj.insert("subtitle".into(), Value::from(name.as_str()));
    }
    item
}

/// hirz never uses a signature counter, so every passkey qualifies for export.
pub fn export_json(
    records: &[&CredentialRecord],
    timestamp: u64,
    account_id: &[u8; 16],
) -> Result<Zeroizing<Vec<u8>>, String> {
    let items: Vec<Value> = records.iter().map(|r| passkey_item(r)).collect();
    let mut doc = json!({
        "version": { "major": 1, "minor": 0 },
        "exporterRpId": EXPORTER_RP_ID,
        "exporterDisplayName": EXPORTER_NAME,
        "timestamp": timestamp,
        "accounts": [{
            "id": b64(account_id),
            "username": "",
            "email": "",
            "collections": [],
            "items": items,
        }],
    });
    let out = serde_json::to_vec_pretty(&doc).map_err(|e| e.to_string());
    wipe(&mut doc);
    out.map(Zeroizing::new)
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

fn opt_str<'a>(o: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>, String> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.len() <= MAX_STRING_LEN => Ok(Some(s)),
        Some(Value::String(_)) => Err(format!("the field {key} is too long")),
        Some(_) => Err(format!("the field {key} is not text")),
    }
}

fn req_str<'a>(o: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    opt_str(o, key)?.ok_or_else(|| format!("the field {key} is missing"))
}

fn req_bytes(o: &Map<String, Value>, key: &str, max: usize) -> Result<Zeroizing<Vec<u8>>, String> {
    let s = match o.get(key) {
        Some(Value::String(s)) => s,
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

fn non_empty(s: Option<&str>) -> Option<String> {
    s.filter(|v| !v.is_empty()).map(str::to_string)
}

#[derive(Debug, Default)]
struct HirzExt {
    rp_name: Option<String>,
    cred_protect: Option<u8>,
    discoverable: Option<bool>,
}

fn hirz_ext(item: &Map<String, Value>) -> HirzExt {
    let mut out = HirzExt::default();
    let Some(Value::Array(exts)) = item.get("extensions") else {
        return out;
    };
    for e in exts {
        let Value::Object(o) = e else { continue };
        if o.get("name").and_then(Value::as_str) != Some(HIRZ_EXTENSION) {
            continue;
        }
        out.rp_name = opt_str(o, "rpName")
            .ok()
            .flatten()
            .and_then(|s| non_empty(Some(s)));
        out.cred_protect = o
            .get("credProtect")
            .and_then(Value::as_u64)
            .filter(|v| (1..=3).contains(v))
            .and_then(|v| u8::try_from(v).ok());
        out.discoverable = o.get("discoverable").and_then(Value::as_bool);
    }
    out
}

fn passkey(
    pk: &Map<String, Value>,
    item: &Map<String, Value>,
    now: u64,
) -> Result<(CredentialRecord, Vec<&'static str>), String> {
    let credential_id = req_bytes(pk, "credentialId", MAX_CREDENTIAL_ID_LEN)?;
    if credential_id.is_empty() {
        return Err("its credential id is empty".into());
    }
    let rp_id = req_str(pk, "rpId")?.to_ascii_lowercase();
    if !hirz_uv::config::valid_rp_id(&rp_id) {
        return Err("its site id is not a valid domain name".into());
    }
    let user_name = non_empty(opt_str(pk, "username")?);
    let user_display_name = non_empty(opt_str(pk, "userDisplayName")?);
    let user_id = req_bytes(pk, "userHandle", MAX_USER_ID_LEN)?;
    let key = req_bytes(pk, "key", MAX_PKCS8_LEN)?;
    if key.is_empty() {
        return Err("its private key is empty".into());
    }
    let algorithm = identify_key(&key)?;

    let mut dropped = Vec::new();
    let mut hmac_secret = None;
    match pk.get("fido2Extensions") {
        None | Some(Value::Null) => {}
        Some(Value::Object(ext)) => {
            match ext.get("hmacCredentials") {
                None | Some(Value::Null) => {}
                Some(Value::Object(h)) => {
                    if h.get("algorithm").and_then(Value::as_str) == Some("hmac-sha256") {
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

    let extra = hirz_ext(item);
    let created_at = item
        .get("creationAt")
        .and_then(Value::as_u64)
        .filter(|t| *t > 0 && *t <= now.saturating_add(86_400))
        .unwrap_or(now);
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

fn version_ok(doc: &Map<String, Value>) -> Result<(), String> {
    let Some(Value::Object(v)) = doc.get("version") else {
        return Err("This is not a CXF file: it has no version.".into());
    };
    let major = v.get("major").and_then(Value::as_u64);
    match major {
        Some(1) => Ok(()),
        Some(m) => Err(format!(
            "This file uses version {m} of the exchange format; hirz reads version 1."
        )),
        None => Err("This is not a CXF file: its version is malformed.".into()),
    }
}

fn object_list<'a>(o: &'a Map<String, Value>, key: &str) -> Result<&'a [Value], String> {
    match o.get(key) {
        None => Ok(&[]),
        Some(Value::Array(a)) => Ok(a),
        Some(_) => Err(format!("The file is malformed: {key} is not a list.")),
    }
}

/// Fails only when the document as a whole is unusable; a bad passkey becomes a `Skipped` entry.
pub fn parse(data: &[u8], now: u64) -> Result<Parsed, String> {
    let mut doc: Value = serde_json::from_slice(data)
        .map_err(|_| "The file is not valid JSON, so it is not a CXF export.".to_string())?;
    let result = parse_doc(&doc, now);
    wipe(&mut doc);
    result
}

fn parse_doc(doc: &Value, now: u64) -> Result<Parsed, String> {
    let Value::Object(root) = doc else {
        return Err("The file is not a CXF export.".into());
    };
    version_ok(root)?;
    if !matches!(root.get("accounts"), Some(Value::Array(_))) {
        return Err("This is not a CXF file: it has no accounts list.".into());
    }
    let mut parsed = Parsed {
        exporter: root
            .get("exporterDisplayName")
            .and_then(Value::as_str)
            .map(|s| crate::ui::clean(s, 60))
            .unwrap_or_default(),
        ..Parsed::default()
    };
    for account in object_list(root, "accounts")? {
        let Value::Object(account) = account else {
            continue;
        };
        for item in object_list(account, "items")? {
            let Value::Object(item) = item else { continue };
            for cred in object_list(item, "credentials")? {
                let Value::Object(cred) = cred else { continue };
                if cred.get("type").and_then(Value::as_str) != Some("passkey") {
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
                                .and_then(Value::as_str)
                                .unwrap_or("(unknown site)"),
                            cred.get("username").and_then(Value::as_str),
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
    fn far_future_creation_time_is_replaced() {
        let doc = include_str!("../tests/fixtures/provider-export.json")
            .replace("1700000000", "99999999999");
        let parsed = parse(doc.as_bytes(), 1_800_000_000).unwrap();
        let Candidate::Ready { record, .. } = &parsed.passkeys[0] else {
            panic!("first passkey should import");
        };
        assert_eq!(record.created_at, 1_800_000_000);
    }
}
