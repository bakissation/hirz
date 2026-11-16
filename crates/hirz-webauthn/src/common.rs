//! Pieces shared by the create and get option parsers.

use crate::error::Error;
use crate::fields::{Obj, Result};
use hirz_core::{HmacSecretSalts, UvRequirement};
use hirz_crypto::sha256;
use hirz_proto::json::Json;

pub(crate) const CHALLENGE_MIN: usize = 16;
pub(crate) const CHALLENGE_MAX: usize = 1024;
pub(crate) const CREDENTIAL_ID_MAX: usize = hirz_proto::auth_data::MAX_CREDENTIAL_ID_LEN;
pub(crate) const MAX_DESCRIPTORS: usize = 64;
pub(crate) const MAX_HINTS: usize = 16;
pub(crate) const MAX_TRANSPORTS: usize = 16;
/// Cap for identifier-like strings (enum values, types, hints).
pub(crate) const MAX_TOKEN_CHARS: usize = 64;
/// Cap for display strings (names). Matches the extension's own cap.
pub(crate) const MAX_NAME_CHARS: usize = 1024;
/// Cap for an RP ID before domain validation: 253 ASCII bytes, with room for the
/// non-canonical inputs that are reported as such.
pub(crate) const MAX_RP_ID_CHARS: usize = 253;
pub(crate) const PRF_INPUT_MAX: usize = 4096;
pub(crate) const PUBLIC_KEY: &str = "public-key";

/// Reads a list of PublicKeyCredentialDescriptorJSON and returns the ids of the
/// `public-key` entries. Entries of unknown type are skipped, as the spec requires.
pub(crate) fn descriptors(o: &Obj<'_>, key: &'static str) -> Result<(Vec<Vec<u8>>, usize)> {
    let items = o.opt_array(key, MAX_DESCRIPTORS)?;
    let mut ids = Vec::with_capacity(items.len());
    for item in items {
        let d = Obj::new(item, key)?;
        let ty = d.req_str("type", MAX_TOKEN_CHARS)?;
        let id = d.req_bytes("id", 1, CREDENTIAL_ID_MAX)?;
        d.opt_str_list("transports", MAX_TRANSPORTS, MAX_TOKEN_CHARS)?;
        if ty == PUBLIC_KEY {
            ids.push(id);
        }
    }
    Ok((ids, items.len()))
}

/// True when the RP's most preferred known hint points away from a platform
/// authenticator. Unknown hint values are ignored.
pub(crate) fn hints_prefer_other(o: &Obj<'_>) -> Result<bool> {
    let hints = o.opt_str_list("hints", MAX_HINTS, MAX_TOKEN_CHARS)?;
    let first = hints
        .iter()
        .copied()
        .find(|h| matches!(*h, "security-key" | "client-device" | "hybrid"));
    Ok(matches!(first, Some("security-key" | "hybrid")))
}

/// Unknown values fall back to the default, `preferred`.
pub(crate) fn user_verification(value: Option<&str>) -> UvRequirement {
    match value {
        Some("required") => UvRequirement::Required,
        Some("discouraged") => UvRequirement::Discouraged,
        _ => UvRequirement::Preferred,
    }
}

const PRF_CONTEXT: &[u8] = b"WebAuthn PRF\x00";

/// The hmac-secret salt for a PRF input: SHA-256("WebAuthn PRF" || 0x00 || input).
pub fn prf_salt(input: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(PRF_CONTEXT.len().saturating_add(input.len()));
    buf.extend_from_slice(PRF_CONTEXT);
    buf.extend_from_slice(input);
    sha256(&buf)
}

/// Reads AuthenticationExtensionsPRFValuesJSON and derives the salts.
pub(crate) fn prf_values(v: &Json, key: &'static str) -> Result<HmacSecretSalts> {
    let o = Obj::new(v, key)?;
    let first = o.req_bytes("first", 0, PRF_INPUT_MAX)?;
    let second = o.opt_bytes("second", 0, PRF_INPUT_MAX)?;
    Ok(HmacSecretSalts {
        salt1: prf_salt(&first),
        salt2: second.as_deref().map(prf_salt),
    })
}

pub(crate) fn not_handled_if(cond: bool, why: &'static str) -> Result<()> {
    if cond {
        return Err(Error::NotHandled(why));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn prf_salt_known_answers() {
        // Computed independently: printf 'WebAuthn PRF\0<input>' | sha256sum
        assert_eq!(
            hex(&prf_salt(b"")),
            "6a7e64b2aa34c92736143a062fa149aff1bd8bb3f7ee6f346885481f9414a3d3"
        );
        assert_eq!(
            hex(&prf_salt(b"example")),
            "a34ce807603cdea06c663b00ccd598b39c9135806b11e710c886a42f7525272b"
        );
        assert_eq!(
            hex(&prf_salt(&[0u8; 32])),
            "4f24c9221e0ed3b764b4558a0d880ecea08117d62f2bdc13ae2c6c3ea662e3a1"
        );
    }

    #[test]
    fn uv_mapping() {
        assert_eq!(user_verification(Some("required")), UvRequirement::Required);
        assert_eq!(
            user_verification(Some("preferred")),
            UvRequirement::Preferred
        );
        assert_eq!(
            user_verification(Some("discouraged")),
            UvRequirement::Discouraged
        );
        assert_eq!(
            user_verification(Some("REQUIRED")),
            UvRequirement::Preferred
        );
        assert_eq!(user_verification(None), UvRequirement::Preferred);
    }
}
