//! Passphrase envelope around a CXF export; the layout is in `docs/sync.md`, "Encrypted export file".

use hirz_crypto::Zeroizing;
use hirz_crypto::kdf::{self, Argon2Params};

pub const MAGIC: &[u8; 8] = b"HIRZ-CXF";
const VERSION: u8 = 1;
const KDF_ARGON2ID: u8 = 1;
const SALT_LEN: usize = 16;
const HEADER_LEN: usize = 8 + 1 + 1 + 12 + SALT_LEN;
const INFO: &[u8] = b"hirz cxf envelope v1";
/// Same bounds as hirz-vault backups: a hostile file cannot demand absurd work.
pub const IMPORT_LIMIT: Argon2Params = hirz_vault::IMPORT_LIMIT;
pub const MAX_FILE_LEN: u64 = 64 << 20;
pub const MIN_PASSPHRASE_CHARS: usize = 12;
pub const MAX_PASSPHRASE_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    Malformed,
    UnsupportedVersion,
    TooCostly,
    WrongPassphrase,
    Crypto,
}

pub fn is_envelope(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    params: Argon2Params,
) -> Result<Zeroizing<[u8; 32]>, EnvelopeError> {
    let stretched = kdf::argon2id(passphrase, salt, params).map_err(|_| EnvelopeError::Crypto)?;
    let mut key = Zeroizing::new([0u8; 32]);
    hirz_crypto::hkdf_sha256(salt, &stretched, INFO, key.as_mut_slice())
        .map_err(|_| EnvelopeError::Crypto)?;
    Ok(key)
}

fn within_limit(p: Argon2Params) -> bool {
    p.m_cost_kib <= IMPORT_LIMIT.m_cost_kib
        && p.t_cost <= IMPORT_LIMIT.t_cost
        && p.p_cost <= IMPORT_LIMIT.p_cost
        && p.t_cost >= 1
        && p.p_cost >= 1
}

pub fn seal(
    passphrase: &[u8],
    plaintext: &[u8],
    params: Argon2Params,
) -> Result<Vec<u8>, EnvelopeError> {
    if !within_limit(params) {
        return Err(EnvelopeError::TooCostly);
    }
    let mut salt = [0u8; SALT_LEN];
    hirz_crypto::random_fill(&mut salt).map_err(|_| EnvelopeError::Crypto)?;
    let mut head = Vec::with_capacity(HEADER_LEN);
    head.extend_from_slice(MAGIC);
    head.push(VERSION);
    head.push(KDF_ARGON2ID);
    head.extend_from_slice(&params.m_cost_kib.to_be_bytes());
    head.extend_from_slice(&params.t_cost.to_be_bytes());
    head.extend_from_slice(&params.p_cost.to_be_bytes());
    head.extend_from_slice(&salt);
    let key = derive_key(passphrase, &salt, params)?;
    let sealed =
        hirz_crypto::aead::seal(&key, &head, plaintext).map_err(|_| EnvelopeError::Crypto)?;
    let mut out = head;
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn be_u32(b: &[u8], at: usize) -> Result<u32, EnvelopeError> {
    let end = at.checked_add(4).ok_or(EnvelopeError::Malformed)?;
    let s = b.get(at..end).ok_or(EnvelopeError::Malformed)?;
    let arr: [u8; 4] = s.try_into().map_err(|_| EnvelopeError::Malformed)?;
    Ok(u32::from_be_bytes(arr))
}

pub fn params(data: &[u8]) -> Result<Argon2Params, EnvelopeError> {
    if !is_envelope(data) || data.len() < HEADER_LEN {
        return Err(EnvelopeError::Malformed);
    }
    if data.get(8) != Some(&VERSION) {
        return Err(EnvelopeError::UnsupportedVersion);
    }
    if data.get(9) != Some(&KDF_ARGON2ID) {
        return Err(EnvelopeError::UnsupportedVersion);
    }
    let p = Argon2Params {
        m_cost_kib: be_u32(data, 10)?,
        t_cost: be_u32(data, 14)?,
        p_cost: be_u32(data, 18)?,
    };
    if !within_limit(p) {
        return Err(EnvelopeError::TooCostly);
    }
    Ok(p)
}

pub fn open(passphrase: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
    if u64::try_from(data.len()).unwrap_or(u64::MAX) > MAX_FILE_LEN {
        return Err(EnvelopeError::Malformed);
    }
    let p = params(data)?;
    let (head, sealed) = data
        .split_at_checked(HEADER_LEN)
        .ok_or(EnvelopeError::Malformed)?;
    let salt = head.get(22..).ok_or(EnvelopeError::Malformed)?;
    let key = derive_key(passphrase, salt, p)?;
    hirz_crypto::aead::open(&key, head, sealed).map_err(|_| EnvelopeError::WrongPassphrase)
}

pub fn passphrase_problem(p: &str) -> Option<String> {
    if p.len() > MAX_PASSPHRASE_BYTES {
        return Some("That passphrase is too long.".into());
    }
    if p.chars().count() < MIN_PASSPHRASE_CHARS {
        return Some(format!(
            "Use at least {MIN_PASSPHRASE_CHARS} characters. Several random words work well, \
             for example four words from a dictionary."
        ));
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const FAST: Argon2Params = Argon2Params {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };

    #[test]
    fn round_trip() {
        let sealed = seal(b"correct horse battery", b"{\"a\":1}", FAST).unwrap();
        assert!(is_envelope(&sealed));
        assert_eq!(params(&sealed).unwrap(), FAST);
        assert_eq!(
            open(b"correct horse battery", &sealed).unwrap().as_slice(),
            b"{\"a\":1}"
        );
        assert_eq!(
            open(b"wrong horse battery", &sealed),
            Err(EnvelopeError::WrongPassphrase)
        );
    }

    #[test]
    fn header_is_authenticated() {
        let mut sealed = seal(b"correct horse battery", b"x", FAST).unwrap();
        sealed[30] ^= 1;
        assert_eq!(
            open(b"correct horse battery", &sealed),
            Err(EnvelopeError::WrongPassphrase)
        );
        let mut costly = seal(b"correct horse battery", b"x", FAST).unwrap();
        costly[14..18].copy_from_slice(&1000u32.to_be_bytes());
        assert_eq!(params(&costly), Err(EnvelopeError::TooCostly));
        let mut v2 = seal(b"correct horse battery", b"x", FAST).unwrap();
        v2[8] = 2;
        assert_eq!(params(&v2), Err(EnvelopeError::UnsupportedVersion));
        assert_eq!(params(b"HIRZ-CXF"), Err(EnvelopeError::Malformed));
        assert_eq!(open(b"p", &[0u8; 3]), Err(EnvelopeError::Malformed));
    }

    #[test]
    fn passphrase_rules() {
        assert!(passphrase_problem("short").is_some());
        assert!(passphrase_problem("twelve chars").is_none());
    }
}
