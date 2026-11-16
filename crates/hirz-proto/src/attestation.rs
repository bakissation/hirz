//! Attestation objects with the `none` format, in WebAuthn and CTAP2 form.

use crate::cbor::{self, Limits, Value};
use crate::{Error, Result};

pub const FMT_NONE: &str = "none";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationObject {
    pub fmt: String,
    pub att_stmt: Value,
    pub auth_data: Vec<u8>,
}

/// Encodes the WebAuthn form `{"fmt": "none", "attStmt": {}, "authData": auth_data}`.
pub fn none_webauthn(auth_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(auth_data.len().saturating_add(32));
    cbor::write_map_header(&mut out, 3);
    cbor::write_text(&mut out, "fmt");
    cbor::write_text(&mut out, FMT_NONE);
    cbor::write_text(&mut out, "attStmt");
    cbor::write_map_header(&mut out, 0);
    cbor::write_text(&mut out, "authData");
    cbor::write_bytes(&mut out, auth_data);
    out
}

/// Encodes the CTAP2 authenticatorMakeCredential response `{1: "none", 2: auth_data, 3: {}}`.
pub fn none_ctap(auth_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(auth_data.len().saturating_add(16));
    cbor::write_map_header(&mut out, 3);
    cbor::write_int(&mut out, 1);
    cbor::write_text(&mut out, FMT_NONE);
    cbor::write_int(&mut out, 2);
    cbor::write_bytes(&mut out, auth_data);
    cbor::write_int(&mut out, 3);
    cbor::write_map_header(&mut out, 0);
    out
}

fn fields(
    fmt: Option<&Value>,
    stmt: Option<&Value>,
    data: Option<&Value>,
) -> Result<AttestationObject> {
    let fmt = fmt.and_then(Value::as_text).ok_or(Error::InvalidValue)?;
    let att_stmt = stmt
        .filter(|v| v.as_map().is_some())
        .ok_or(Error::InvalidValue)?;
    let auth_data = data.and_then(Value::as_bytes).ok_or(Error::InvalidValue)?;
    Ok(AttestationObject {
        fmt: fmt.to_owned(),
        att_stmt: att_stmt.clone(),
        auth_data: auth_data.to_vec(),
    })
}

/// Parses a WebAuthn attestation object (text keys); other keys are ignored.
pub fn parse_webauthn(input: &[u8], limits: &Limits) -> Result<AttestationObject> {
    let v = cbor::decode(input, limits)?;
    fields(
        v.get_text("fmt"),
        v.get_text("attStmt"),
        v.get_text("authData"),
    )
}

/// Parses a CTAP2 makeCredential response (integer keys 1, 2, 3); other keys are ignored.
pub fn parse_ctap(input: &[u8], limits: &Limits) -> Result<AttestationObject> {
    let v = cbor::decode(input, limits)?;
    fields(v.get_int(1), v.get_int(3), v.get_int(2))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn both_forms_are_canonical_and_parse() {
        let ad = [0x42u8; 37];
        for (enc, parse) in [
            (
                none_webauthn(&ad),
                parse_webauthn as fn(&[u8], &Limits) -> Result<_>,
            ),
            (none_ctap(&ad), parse_ctap),
        ] {
            let v = cbor::decode(&enc, &Limits::default()).unwrap();
            assert_eq!(cbor::encode(&v).unwrap(), enc);
            let obj = parse(&enc, &Limits::default()).unwrap();
            assert_eq!(obj.fmt, FMT_NONE);
            assert_eq!(obj.att_stmt, Value::Map(vec![]));
            assert_eq!(obj.auth_data, ad);
        }
        assert_eq!(
            &none_ctap(&ad)[..8],
            &[0xa3, 0x01, 0x64, b'n', b'o', b'n', b'e', 0x02]
        );
    }

    #[test]
    fn wrong_types_rejected() {
        let ad = [0u8; 37];
        assert!(parse_ctap(&none_webauthn(&ad), &Limits::default()).is_err());
        assert!(parse_webauthn(&none_ctap(&ad), &Limits::default()).is_err());
        let bad = cbor::encode(
            &cbor::MapBuilder::new()
                .int(1, "none")
                .int(2, "not bytes")
                .int(3, Value::Map(vec![]))
                .build(),
        )
        .unwrap();
        assert_eq!(
            parse_ctap(&bad, &Limits::default()),
            Err(Error::InvalidValue)
        );
    }
}
