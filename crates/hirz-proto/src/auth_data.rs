//! authenticatorData (WebAuthn Level 3 section 6.1) builder and parser.
//!
//! Layout: rpIdHash (32) | flags (1) | signCount (u32 BE) | attested credential data
//! (AAGUID 16, credentialIdLength u16 BE, credentialId, COSE_Key) | extensions (CBOR map).

use crate::cbor::{self, Limits, Value};
use crate::{Error, Result};

/// User Present.
pub const FLAG_UP: u8 = 0x01;
/// User Verified.
pub const FLAG_UV: u8 = 0x04;
/// Backup Eligible.
pub const FLAG_BE: u8 = 0x08;
/// Backup State.
pub const FLAG_BS: u8 = 0x10;
/// Attested credential data included.
pub const FLAG_AT: u8 = 0x40;
/// Extension data included.
pub const FLAG_ED: u8 = 0x80;
const FLAGS_RESERVED: u8 = 0x22;

/// Largest credential id WebAuthn allows.
pub const MAX_CREDENTIAL_ID_LEN: usize = 1023;

/// Attested credential data of a registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedCredentialData {
    /// Authenticator model identifier.
    pub aaguid: [u8; 16],
    /// Credential id, 1 to 1023 bytes.
    pub credential_id: Vec<u8>,
    /// Encoded COSE_Key of the credential public key.
    pub public_key: Vec<u8>,
}

/// Decoded or to-be-encoded authenticatorData.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatorData {
    /// SHA-256 of the RP ID, computed by the caller.
    pub rp_id_hash: [u8; 32],
    /// Flag bits; AT and ED are derived from the optional parts when encoding.
    pub flags: u8,
    /// Signature counter.
    pub sign_count: u32,
    /// Present for registrations.
    pub attested_credential: Option<AttestedCredentialData>,
    /// Authenticator extension outputs, a CBOR map.
    pub extensions: Option<Value>,
}

impl AuthenticatorData {
    /// Encodes; rejects reserved flag bits, BS without BE and malformed optional parts.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.flags & FLAGS_RESERVED != 0 {
            return Err(Error::InvalidValue);
        }
        if self.flags & FLAG_BS != 0 && self.flags & FLAG_BE == 0 {
            return Err(Error::InvalidValue);
        }
        let mut flags = self.flags & !(FLAG_AT | FLAG_ED);
        if self.attested_credential.is_some() {
            flags |= FLAG_AT;
        }
        if self.extensions.is_some() {
            flags |= FLAG_ED;
        }
        let mut out = Vec::with_capacity(160);
        out.extend_from_slice(&self.rp_id_hash);
        out.push(flags);
        out.extend_from_slice(&self.sign_count.to_be_bytes());
        if let Some(cred) = &self.attested_credential {
            if cred.credential_id.is_empty() || cred.credential_id.len() > MAX_CREDENTIAL_ID_LEN {
                return Err(Error::InvalidValue);
            }
            let id_len =
                u16::try_from(cred.credential_id.len()).map_err(|_| Error::InvalidValue)?;
            if !matches!(
                cbor::decode(&cred.public_key, &Limits::default())?,
                Value::Map(_)
            ) {
                return Err(Error::InvalidValue);
            }
            out.extend_from_slice(&cred.aaguid);
            out.extend_from_slice(&id_len.to_be_bytes());
            out.extend_from_slice(&cred.credential_id);
            out.extend_from_slice(&cred.public_key);
        }
        if let Some(ext) = &self.extensions {
            if !matches!(ext, Value::Map(_)) {
                return Err(Error::InvalidValue);
            }
            out.extend_from_slice(&cbor::encode(ext)?);
        }
        Ok(out)
    }

    /// Parses authenticatorData; AT and ED must match the content and no bytes may trail.
    pub fn parse(input: &[u8], limits: &Limits) -> Result<Self> {
        let (rp_id_hash, rest) = input.split_first_chunk::<32>().ok_or(Error::Truncated)?;
        let (&[flags], rest) = rest.split_first_chunk::<1>().ok_or(Error::Truncated)?;
        let (count, mut rest) = rest.split_first_chunk::<4>().ok_or(Error::Truncated)?;
        let attested_credential = if flags & FLAG_AT != 0 {
            let (aaguid, r) = rest.split_first_chunk::<16>().ok_or(Error::Truncated)?;
            let (id_len, r) = r.split_first_chunk::<2>().ok_or(Error::Truncated)?;
            let id_len = usize::from(u16::from_be_bytes(*id_len));
            if id_len == 0 || id_len > MAX_CREDENTIAL_ID_LEN {
                return Err(Error::InvalidValue);
            }
            let (credential_id, r) = r.split_at_checked(id_len).ok_or(Error::Truncated)?;
            let (key, used) = cbor::decode_prefix(r, limits)?;
            if !matches!(key, Value::Map(_)) {
                return Err(Error::InvalidValue);
            }
            let (public_key, r) = r.split_at_checked(used).ok_or(Error::Malformed)?;
            rest = r;
            Some(AttestedCredentialData {
                aaguid: *aaguid,
                credential_id: credential_id.to_vec(),
                public_key: public_key.to_vec(),
            })
        } else {
            None
        };
        let extensions = if flags & FLAG_ED != 0 {
            let (ext, used) = cbor::decode_prefix(rest, limits)?;
            if !matches!(ext, Value::Map(_)) {
                return Err(Error::InvalidValue);
            }
            rest = rest.get(used..).ok_or(Error::Malformed)?;
            Some(ext)
        } else {
            None
        };
        if !rest.is_empty() {
            return Err(Error::TrailingBytes);
        }
        Ok(Self {
            rp_id_hash: *rp_id_hash,
            flags,
            sign_count: u32::from_be_bytes(*count),
            attested_credential,
            extensions,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::cbor::MapBuilder;
    use crate::cose;

    fn sample() -> AuthenticatorData {
        AuthenticatorData {
            rp_id_hash: [0xab; 32],
            flags: FLAG_UP | FLAG_UV | FLAG_BE,
            sign_count: 0,
            attested_credential: Some(AttestedCredentialData {
                aaguid: [0x01; 16],
                credential_id: vec![0x5a; 32],
                public_key: cose::encode_es256(&[3; 32], &[4; 32]),
            }),
            extensions: Some(MapBuilder::new().text("credProtect", 2).build()),
        }
    }

    #[test]
    fn round_trip_with_all_parts() {
        let ad = sample();
        let enc = ad.encode().unwrap();
        assert_eq!(enc[32], FLAG_UP | FLAG_UV | FLAG_BE | FLAG_AT | FLAG_ED);
        assert_eq!(&enc[33..37], &[0, 0, 0, 0]);
        assert_eq!(&enc[53..55], &[0x00, 0x20]);
        let parsed = AuthenticatorData::parse(&enc, &Limits::default()).unwrap();
        assert_eq!(parsed.flags, enc[32]);
        assert_eq!(parsed.encode().unwrap(), enc);
        assert_eq!(parsed.attested_credential, ad.attested_credential);
        assert_eq!(parsed.extensions, ad.extensions);
    }

    #[test]
    fn assertion_form_is_37_bytes() {
        let ad = AuthenticatorData {
            rp_id_hash: [0; 32],
            flags: FLAG_UP | FLAG_AT,
            sign_count: 7,
            attested_credential: None,
            extensions: None,
        };
        let enc = ad.encode().unwrap();
        assert_eq!(enc.len(), 37);
        assert_eq!(enc[32], FLAG_UP);
        assert_eq!(&enc[33..], &[0, 0, 0, 7]);
    }

    #[test]
    fn encode_rejects() {
        let mut ad = sample();
        ad.flags = FLAG_UP | 0x02;
        assert!(ad.encode().is_err());
        ad.flags = FLAG_UP | FLAG_BS;
        assert!(ad.encode().is_err());
        let mut ad = sample();
        ad.attested_credential.as_mut().unwrap().credential_id = vec![];
        assert!(ad.encode().is_err());
        ad.attested_credential.as_mut().unwrap().credential_id = vec![0; 1024];
        assert!(ad.encode().is_err());
        ad.attested_credential.as_mut().unwrap().credential_id = vec![0; 1023];
        assert!(ad.encode().is_ok());
        ad.attested_credential.as_mut().unwrap().public_key = vec![0x01];
        assert!(ad.encode().is_err());
        let mut ad = sample();
        ad.extensions = Some(Value::Null);
        assert!(ad.encode().is_err());
    }

    #[test]
    fn parse_rejects() {
        let enc = sample().encode().unwrap();
        for len in 0..enc.len() {
            assert!(AuthenticatorData::parse(&enc[..len], &Limits::default()).is_err());
        }
        let mut trailing = enc.clone();
        trailing.push(0);
        assert_eq!(
            AuthenticatorData::parse(&trailing, &Limits::default()),
            Err(Error::TrailingBytes)
        );
        let mut no_ed = enc.clone();
        no_ed[32] &= !FLAG_ED;
        assert_eq!(
            AuthenticatorData::parse(&no_ed, &Limits::default()),
            Err(Error::TrailingBytes)
        );
        let mut zero_len = enc.clone();
        zero_len[53] = 0;
        zero_len[54] = 0;
        assert_eq!(
            AuthenticatorData::parse(&zero_len, &Limits::default()),
            Err(Error::InvalidValue)
        );
        let mut huge_len = enc;
        huge_len[53] = 0xff;
        assert!(AuthenticatorData::parse(&huge_len, &Limits::default()).is_err());
    }
}
