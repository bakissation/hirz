//! KeePassXC passkey files (`.passkey`, written by "Export passkey" for one entry): a JSON
//! object with `relyingParty`, `url`, `username`, `credentialId` and `userHandle`
//! (base64url) and `privateKey` (a PKCS#8 PEM block).
//!
//! KeePass XML exports, which keep passkeys in `KPEX_PASSKEY_*` entry attributes, are not
//! read: hirz has no XML parser.

use super::{
    Found, base64_field, finish, identify_key, lenient_base64, non_empty, opt_text, site_id,
    with_json,
};
use hirz_crypto::Zeroizing;
use hirz_proto::json::{Json, Limits};
use hirz_vault::{CredentialRecord, MAX_CREDENTIAL_ID_LEN, MAX_PKCS8_LEN, MAX_USER_ID_LEN};

/// Largest `.passkey` file hirz reads.
pub const MAX_PASSKEY_FILE_LEN: usize = 64 * 1024;
/// File name extension KeePassXC gives passkey exports.
pub const EXTENSION: &str = "passkey";

const LIMITS: Limits = Limits {
    max_len: MAX_PASSKEY_FILE_LEN,
    max_depth: 4,
    max_items: 256,
};

const PEM_BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
const PEM_END: &str = "-----END PRIVATE KEY-----";

fn pem_pkcs8(pem: &str) -> Option<Zeroizing<Vec<u8>>> {
    let body = pem.trim().strip_prefix(PEM_BEGIN)?.strip_suffix(PEM_END)?;
    let mut b64 = Zeroizing::new(String::with_capacity(body.len()));
    b64.extend(body.chars().filter(|c| !c.is_ascii_whitespace()));
    if b64.len() > MAX_PKCS8_LEN.saturating_mul(2) {
        return None;
    }
    lenient_base64(&b64).filter(|k| !k.is_empty() && k.len() <= MAX_PKCS8_LEN)
}

fn passkey(doc: &Json, now: u64) -> Result<CredentialRecord, String> {
    let credential_id = base64_field(doc, "credentialId", MAX_CREDENTIAL_ID_LEN)?;
    if credential_id.is_empty() {
        return Err("its credential id is missing".into());
    }
    let rp_id =
        site_id(opt_text(doc, "relyingParty")?.ok_or("the field relyingParty is missing")?)?;
    let key = match doc.get("privateKey") {
        Some(Json::String(pem)) if pem.len() <= MAX_PKCS8_LEN.saturating_mul(3) => {
            pem_pkcs8(pem).ok_or("its private key is not a PKCS#8 PEM block")?
        }
        _ => return Err("its private key is missing or too long".into()),
    };
    let algorithm = identify_key(&key)?;
    let user_id = base64_field(doc, "userHandle", MAX_USER_ID_LEN)?;
    finish(CredentialRecord {
        credential_id: credential_id.to_vec(),
        rp_id,
        rp_name: None,
        user_id: user_id.to_vec(),
        user_name: non_empty(opt_text(doc, "username")?),
        user_display_name: None,
        algorithm,
        private_key_pkcs8: key,
        created_at: now,
        cred_protect: None,
        hmac_secret: None,
        discoverable: true,
        backup_eligible: true,
    })
}

/// Reads one `.passkey` file. Fails when the file is not a KeePassXC passkey export; a
/// passkey hirz cannot use comes back as [`Found::Skipped`].
pub fn read(data: &[u8], now: u64) -> Result<Found, String> {
    with_json(
        data,
        &LIMITS,
        "The file is not valid JSON, so it is not a KeePassXC passkey export.",
        |doc| {
            if doc.as_object().is_none()
                || doc.get("privateKey").is_none()
                || doc.get("credentialId").is_none()
            {
                return Err("This is not a KeePassXC passkey export.".into());
            }
            Ok(match passkey(doc, now) {
                Ok(r) => Found::Ready(Box::new(r)),
                Err(reason) => Found::Skipped {
                    site: doc
                        .get("relyingParty")
                        .and_then(Json::as_str)
                        .unwrap_or("(unknown site)")
                        .to_string(),
                    account: doc
                        .get("username")
                        .and_then(Json::as_str)
                        .map(str::to_string),
                    reason,
                },
            })
        },
    )
}

/// Builds a `.passkey` file as KeePassXC writes it, for tests.
#[cfg(test)]
pub fn passkey_file(rp: &str, user: &str, id: &[u8], handle: &[u8], pkcs8: &[u8]) -> String {
    let mut b64 = hirz_proto::base64url::encode(pkcs8)
        .replace('-', "+")
        .replace('_', "/");
    while !b64.len().is_multiple_of(4) {
        b64.push('=');
    }
    let lines: Vec<String> = b64
        .as_bytes()
        .chunks(64)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    let pem = format!("{PEM_BEGIN}\\n{}\\n{PEM_END}\\n", lines.join("\\n"));
    format!(
        "{{\n    \"credentialId\": \"{}\",\n    \"privateKey\": \"{pem}\",\n    \
         \"relyingParty\": \"{rp}\",\n    \"url\": \"https://{rp}\",\n    \
         \"userHandle\": \"{}\",\n    \"username\": \"{user}\"\n}}\n",
        hirz_proto::base64url::encode(id),
        hirz_proto::base64url::encode(handle),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use hirz_core::{COSE_ALG_EDDSA, COSE_ALG_ES256};

    #[test]
    fn reads_es256_and_ed25519_files() {
        let (es, _, _) = hirz_crypto::es256::generate().unwrap();
        let (ed, _) = hirz_crypto::ed25519::generate().unwrap();
        for (key, alg) in [(&es, COSE_ALG_ES256), (&ed, COSE_ALG_EDDSA)] {
            let f = passkey_file("Example.com", "alice", &[5; 20], b"user-1", key);
            let Found::Ready(r) = read(f.as_bytes(), 1_700_000_000).unwrap() else {
                panic!("should import");
            };
            assert_eq!(r.algorithm, alg);
            assert_eq!(r.rp_id, "example.com");
            assert_eq!(r.credential_id, vec![5; 20]);
            assert_eq!(r.user_id, b"user-1");
            assert_eq!(r.user_name.as_deref(), Some("alice"));
            assert_eq!(r.private_key_pkcs8.as_slice(), key.as_slice());
            assert!(r.discoverable && r.backup_eligible);
            assert_eq!(r.created_at, 1_700_000_000);
        }
    }

    #[test]
    fn bad_passkeys_are_skipped_and_bad_files_fail() {
        let (es, _, _) = hirz_crypto::es256::generate().unwrap();
        let good = passkey_file("example.com", "alice", &[5; 20], b"u", &es);
        let p384 = [0x30, 0x10, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x00];
        for (bad, why) in [
            (good.replace("example.com\"", "exa mple.com\""), "domain"),
            (
                passkey_file("example.com", "a", &[5; 20], b"u", &p384),
                "P-384",
            ),
            (
                passkey_file("example.com", "a", &[], b"u", &es),
                "credential id",
            ),
            (
                passkey_file("example.com", "a", &[1], &[7; 65], &es),
                "too long",
            ),
            (good.replace("BEGIN PRIVATE", "BEGIN EC PRIVATE"), "PEM"),
        ] {
            match read(bad.as_bytes(), 0).unwrap() {
                Found::Skipped { reason, .. } => assert!(reason.contains(why), "{reason}"),
                Found::Ready(_) => panic!("{why} should be skipped"),
            }
        }
        for bad in ["", "[]", "{}", "{\"privateKey\": \"x\"}", "not json"] {
            assert!(read(bad.as_bytes(), 0).is_err(), "{bad}");
        }
        let big = format!(
            "{{\"credentialId\": \"{}\"}}",
            "A".repeat(MAX_PASSKEY_FILE_LEN)
        );
        assert!(read(big.as_bytes(), 0).is_err());
    }
}
