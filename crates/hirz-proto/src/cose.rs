//! COSE_Key encoding (RFC 9052/9053) for credential keys and the CTAP key-agreement key.
//! Only the encoding is checked here; the crypto layer checks that a point lies on the curve.

use crate::cbor::{self, MapBuilder, Value};
use crate::{Error, Result};

pub const KTY_OKP: i64 = 1;
pub const KTY_EC2: i64 = 2;
pub const ALG_ES256: i64 = -7;
pub const ALG_EDDSA: i64 = -8;
/// COSE algorithm Ed25519 (fully specified, RFC 9864); accepted when parsing.
pub const ALG_ED25519: i64 = -19;
pub const ALG_ECDH_ES_HKDF_256: i64 = -25;
pub const CRV_P256: i64 = 1;
pub const CRV_ED25519: i64 = 6;

const LABEL_KTY: i64 = 1;
const LABEL_ALG: i64 = 3;
const LABEL_CRV: i64 = -1;
const LABEL_X: i64 = -2;
const LABEL_Y: i64 = -3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    Es256 { x: [u8; 32], y: [u8; 32] },
    Ed25519 { x: [u8; 32] },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAgreementKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

/// `{1: kty, 3: alg, -1: crv, -2: x [, -3: y]}`, already in canonical key order.
fn encode_key(kty: i64, alg: i64, crv: i64, x: &[u8; 32], y: Option<&[u8; 32]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(77);
    cbor::write_map_header(&mut out, if y.is_some() { 5 } else { 4 });
    for (label, value) in [(LABEL_KTY, kty), (LABEL_ALG, alg), (LABEL_CRV, crv)] {
        cbor::write_int(&mut out, label);
        cbor::write_int(&mut out, value);
    }
    cbor::write_int(&mut out, LABEL_X);
    cbor::write_bytes(&mut out, x);
    if let Some(y) = y {
        cbor::write_int(&mut out, LABEL_Y);
        cbor::write_bytes(&mut out, y);
    }
    out
}

pub fn encode_es256(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
    encode_key(KTY_EC2, ALG_ES256, CRV_P256, x, Some(y))
}

pub fn encode_ed25519(x: &[u8; 32]) -> Vec<u8> {
    encode_key(KTY_OKP, ALG_EDDSA, CRV_ED25519, x, None)
}

pub fn key_agreement_value(x: &[u8; 32], y: &[u8; 32]) -> Value {
    MapBuilder::new()
        .int(LABEL_KTY, KTY_EC2)
        .int(LABEL_ALG, ALG_ECDH_ES_HKDF_256)
        .int(LABEL_CRV, CRV_P256)
        .int(LABEL_X, x.as_slice())
        .int(LABEL_Y, y.as_slice())
        .build()
}

fn int_field(key: &Value, label: i64) -> Result<i64> {
    key.get_int(label)
        .and_then(Value::as_i64)
        .ok_or(Error::InvalidValue)
}

fn coordinate(key: &Value, label: i64) -> Result<[u8; 32]> {
    let bytes = key
        .get_int(label)
        .and_then(Value::as_bytes)
        .ok_or(Error::InvalidValue)?;
    <[u8; 32]>::try_from(bytes).map_err(|_| Error::InvalidValue)
}

/// Parses an ES256 (EC2 P-256) or Ed25519 (OKP) COSE_Key; other labels are ignored.
pub fn parse_public_key(key: &Value) -> Result<PublicKey> {
    if key.as_map().is_none() {
        return Err(Error::InvalidValue);
    }
    let kty = int_field(key, LABEL_KTY)?;
    let alg = int_field(key, LABEL_ALG)?;
    let crv = int_field(key, LABEL_CRV)?;
    match (kty, alg, crv) {
        (KTY_EC2, ALG_ES256, CRV_P256) => Ok(PublicKey::Es256 {
            x: coordinate(key, LABEL_X)?,
            y: coordinate(key, LABEL_Y)?,
        }),
        (KTY_OKP, ALG_EDDSA | ALG_ED25519, CRV_ED25519) => {
            if key.get_int(LABEL_Y).is_some() {
                return Err(Error::InvalidValue);
            }
            Ok(PublicKey::Ed25519 {
                x: coordinate(key, LABEL_X)?,
            })
        }
        _ => Err(Error::InvalidValue),
    }
}

/// Parses the platform key-agreement key: EC2, P-256, alg -25, 32-byte x and y, no other labels.
pub fn parse_key_agreement(key: &Value) -> Result<KeyAgreementKey> {
    let entries = key.as_map().ok_or(Error::InvalidValue)?;
    let allowed = [LABEL_KTY, LABEL_ALG, LABEL_CRV, LABEL_X, LABEL_Y];
    if entries
        .iter()
        .any(|(k, _)| !k.as_i64().is_some_and(|l| allowed.contains(&l)))
    {
        return Err(Error::InvalidValue);
    }
    if int_field(key, LABEL_KTY)? != KTY_EC2
        || int_field(key, LABEL_ALG)? != ALG_ECDH_ES_HKDF_256
        || int_field(key, LABEL_CRV)? != CRV_P256
    {
        return Err(Error::InvalidValue);
    }
    Ok(KeyAgreementKey {
        x: coordinate(key, LABEL_X)?,
        y: coordinate(key, LABEL_Y)?,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::cbor::{Limits, decode, encode};

    const X: [u8; 32] = [0x11; 32];
    const Y: [u8; 32] = [0x22; 32];

    #[test]
    fn es256_layout() {
        let enc = encode_es256(&X, &Y);
        let mut expected = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
        expected.extend_from_slice(&X);
        expected.extend_from_slice(&[0x22, 0x58, 0x20]);
        expected.extend_from_slice(&Y);
        assert_eq!(enc, expected);
        let v = decode(&enc, &Limits::default()).unwrap();
        assert_eq!(encode(&v).unwrap(), enc);
        assert_eq!(
            parse_public_key(&v).unwrap(),
            PublicKey::Es256 { x: X, y: Y }
        );
    }

    #[test]
    fn ed25519_layout() {
        let enc = encode_ed25519(&X);
        let mut expected = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
        expected.extend_from_slice(&X);
        assert_eq!(enc, expected);
        let v = decode(&enc, &Limits::default()).unwrap();
        assert_eq!(parse_public_key(&v).unwrap(), PublicKey::Ed25519 { x: X });
    }

    #[test]
    fn key_agreement_round_trip() {
        let v = key_agreement_value(&X, &Y);
        let enc = encode(&v).unwrap();
        assert_eq!(&enc[..7], &[0xa5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20]);
        let decoded = decode(&enc, &Limits::default()).unwrap();
        assert_eq!(
            parse_key_agreement(&decoded).unwrap(),
            KeyAgreementKey { x: X, y: Y }
        );
    }

    #[test]
    fn key_agreement_rejects() {
        let base = || {
            MapBuilder::new()
                .int(1, 2)
                .int(-1, 1)
                .int(-2, X.as_slice())
                .int(-3, Y.as_slice())
        };
        assert!(parse_key_agreement(&base().int(3, -25).build()).is_ok());
        assert!(parse_key_agreement(&base().build()).is_err());
        assert!(parse_key_agreement(&base().int(3, -7).build()).is_err());
        assert!(parse_key_agreement(&base().int(3, -25).int(4, 0).build()).is_err());
        assert!(parse_key_agreement(&base().int(3, -25).text("x", 0).build()).is_err());
        let short = MapBuilder::new()
            .int(1, 2)
            .int(3, -25)
            .int(-1, 1)
            .int(-2, &X[..31])
            .int(-3, Y.as_slice())
            .build();
        assert!(parse_key_agreement(&short).is_err());
        let wrong_curve = MapBuilder::new()
            .int(1, 2)
            .int(3, -25)
            .int(-1, 2)
            .int(-2, X.as_slice())
            .int(-3, Y.as_slice())
            .build();
        assert!(parse_key_agreement(&wrong_curve).is_err());
        let x_text = MapBuilder::new()
            .int(1, 2)
            .int(3, -25)
            .int(-1, 1)
            .int(-2, "x")
            .int(-3, Y.as_slice())
            .build();
        assert!(parse_key_agreement(&x_text).is_err());
        assert!(parse_key_agreement(&Value::Null).is_err());
    }

    #[test]
    fn public_key_rejects() {
        let okp_with_y = MapBuilder::new()
            .int(1, 1)
            .int(3, -8)
            .int(-1, 6)
            .int(-2, X.as_slice())
            .int(-3, Y.as_slice())
            .build();
        assert!(parse_public_key(&okp_with_y).is_err());
        let mismatched = MapBuilder::new()
            .int(1, 2)
            .int(3, -8)
            .int(-1, 1)
            .int(-2, X.as_slice())
            .int(-3, Y.as_slice())
            .build();
        assert!(parse_public_key(&mismatched).is_err());
        assert!(parse_public_key(&Value::Array(vec![])).is_err());
    }
}
