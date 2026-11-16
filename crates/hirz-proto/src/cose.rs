//! COSE_Key encoding (RFC 9052/9053) for credential keys and the CTAP key-agreement key.
//!
//! Only the encoding is checked here. Whether a point lies on the curve is checked by the
//! crypto layer when the key is used.

use crate::cbor::{self, MapBuilder, Value};
use crate::{Error, Result};

/// COSE key type OKP.
pub const KTY_OKP: i64 = 1;
/// COSE key type EC2.
pub const KTY_EC2: i64 = 2;
/// COSE algorithm ES256.
pub const ALG_ES256: i64 = -7;
/// COSE algorithm EdDSA.
pub const ALG_EDDSA: i64 = -8;
/// COSE algorithm Ed25519 (fully specified, RFC 9864); accepted when parsing.
pub const ALG_ED25519: i64 = -19;
/// COSE algorithm ECDH-ES+HKDF-256, as used by CTAP pinUvAuthProtocol.
pub const ALG_ECDH_ES_HKDF_256: i64 = -25;
/// COSE curve P-256.
pub const CRV_P256: i64 = 1;
/// COSE curve Ed25519.
pub const CRV_ED25519: i64 = 6;

const LABEL_KTY: i64 = 1;
const LABEL_ALG: i64 = 3;
const LABEL_CRV: i64 = -1;
const LABEL_X: i64 = -2;
const LABEL_Y: i64 = -3;

/// A credential public key parsed from a COSE_Key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// P-256 ECDSA key as affine coordinates.
    Es256 {
        /// Big-endian x coordinate.
        x: [u8; 32],
        /// Big-endian y coordinate.
        y: [u8; 32],
    },
    /// Ed25519 key.
    Ed25519 {
        /// Encoded public key.
        x: [u8; 32],
    },
}

/// A P-256 key-agreement public key from a CTAP clientPIN request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAgreementKey {
    /// Big-endian x coordinate.
    pub x: [u8; 32],
    /// Big-endian y coordinate.
    pub y: [u8; 32],
}

fn ec2_key(alg: i64, x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(77);
    cbor::write_map_header(&mut out, 5);
    for (label, value) in [
        (LABEL_KTY, KTY_EC2),
        (LABEL_ALG, alg),
        (LABEL_CRV, CRV_P256),
    ] {
        cbor::write_int(&mut out, label);
        cbor::write_int(&mut out, value);
    }
    cbor::write_int(&mut out, LABEL_X);
    cbor::write_bytes(&mut out, x);
    cbor::write_int(&mut out, LABEL_Y);
    cbor::write_bytes(&mut out, y);
    out
}

/// Encodes an ES256 public key as a canonical COSE_Key `{1:2, 3:-7, -1:1, -2:x, -3:y}`.
pub fn encode_es256(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
    ec2_key(ALG_ES256, x, y)
}

/// Encodes an Ed25519 public key as a canonical COSE_Key `{1:1, 3:-8, -1:6, -2:x}`.
pub fn encode_ed25519(x: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(42);
    cbor::write_map_header(&mut out, 4);
    for (label, value) in [
        (LABEL_KTY, KTY_OKP),
        (LABEL_ALG, ALG_EDDSA),
        (LABEL_CRV, CRV_ED25519),
    ] {
        cbor::write_int(&mut out, label);
        cbor::write_int(&mut out, value);
    }
    cbor::write_int(&mut out, LABEL_X);
    cbor::write_bytes(&mut out, x);
    out
}

/// Returns the authenticator key-agreement key `{1:2, 3:-25, -1:1, -2:x, -3:y}` as a value.
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
