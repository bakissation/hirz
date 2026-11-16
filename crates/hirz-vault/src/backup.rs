//! Backup export: every live credential in one file, encrypted under a key derived from the
//! recovery phrase and, optionally, a passphrase (Argon2id).

use crate::codec::{Reader, aad};
use crate::error::VaultError;
use crate::format::{FileType, prefix, strip_prefix};
use crate::fsutil::MAX_BACKUP_LEN;
use crate::record::CredentialRecord;
use crate::recovery::RecoveryPhrase;
use crate::vault::Vault;
use hirz_crypto::Zeroizing;
use hirz_crypto::kdf::{self, Argon2Params};

/// Argon2id costs accepted when importing, so a hostile file cannot demand absurd work.
pub const IMPORT_LIMIT: Argon2Params = Argon2Params {
    m_cost_kib: 1024 * 1024,
    t_cost: 16,
    p_cost: 16,
};

const MAX_RECORDS: u32 = 100_000;
const MAX_RECORD_LEN: u32 = 64 * 1024;

fn backup_key(
    phrase: &RecoveryPhrase,
    passphrase: Option<&[u8]>,
    salt: &[u8; 16],
    params: Argon2Params,
    vault_id: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(phrase.backup_ikm()?.as_slice());
    if let Some(p) = passphrase {
        let stretched = kdf::argon2id(p, salt, params)?;
        ikm.extend_from_slice(&stretched);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    hirz_crypto::hkdf_sha256(
        salt,
        &ikm,
        &aad("hirz backup v1", &[vault_id]),
        key.as_mut_slice(),
    )?;
    Ok(key)
}

impl Vault {
    /// Exports every live credential, protected by the recovery phrase and an optional
    /// passphrase (Argon2id with the RFC 9106 second recommended parameters).
    pub fn export_backup(
        &self,
        phrase: &RecoveryPhrase,
        passphrase: Option<&[u8]>,
    ) -> Result<Vec<u8>, VaultError> {
        self.export_backup_with_params(phrase, passphrase, kdf::DEFAULT)
    }

    pub fn export_backup_with_params(
        &self,
        phrase: &RecoveryPhrase,
        passphrase: Option<&[u8]>,
        params: Argon2Params,
    ) -> Result<Vec<u8>, VaultError> {
        if !hirz_crypto::ct_eq(&phrase.x25519_public()?, &self.recovery_pub()) {
            return Err(VaultError::WrongRecoveryKey);
        }
        if passphrase.is_some() && !within_import_limit(params) {
            return Err(VaultError::InvalidParameters);
        }
        let records = self.list_all();
        let mut body = Zeroizing::new(Vec::with_capacity(
            records.len().saturating_mul(512).saturating_add(4),
        ));
        let count = u32::try_from(records.len()).map_err(|_| VaultError::InvalidParameters)?;
        body.extend_from_slice(&count.to_be_bytes());
        for r in records {
            let enc = r.encode()?;
            let len = u32::try_from(enc.len()).map_err(|_| VaultError::Encode)?;
            body.extend_from_slice(&len.to_be_bytes());
            body.extend_from_slice(&enc);
        }
        let mut salt = [0u8; 16];
        hirz_crypto::random_fill(&mut salt)?;
        let vault_id = self.vault_id();
        let stored = if passphrase.is_some() {
            params
        } else {
            Argon2Params {
                m_cost_kib: 0,
                t_cost: 0,
                p_cost: 0,
            }
        };
        let mut head = prefix(FileType::Backup).to_vec();
        head.extend_from_slice(&vault_id);
        head.push(u8::from(passphrase.is_some()));
        head.extend_from_slice(&salt);
        head.extend_from_slice(&stored.m_cost_kib.to_be_bytes());
        head.extend_from_slice(&stored.t_cost.to_be_bytes());
        head.extend_from_slice(&stored.p_cost.to_be_bytes());
        let key = backup_key(phrase, passphrase, &salt, params, &vault_id)?;
        let sealed = hirz_crypto::aead::seal(&key, &head, &body)?;
        let mut out = head;
        out.extend_from_slice(&sealed);
        Ok(out)
    }
}

fn within_import_limit(p: Argon2Params) -> bool {
    p.m_cost_kib <= IMPORT_LIMIT.m_cost_kib
        && p.t_cost <= IMPORT_LIMIT.t_cost
        && p.p_cost <= IMPORT_LIMIT.p_cost
}

/// Decrypts a backup made by `Vault::export_backup`.
pub fn import_backup(
    data: &[u8],
    phrase: &RecoveryPhrase,
    passphrase: Option<&[u8]>,
) -> Result<Vec<CredentialRecord>, VaultError> {
    if u64::try_from(data.len()).unwrap_or(u64::MAX) > MAX_BACKUP_LEN {
        return Err(VaultError::InvalidParameters);
    }
    let mut r = Reader::new(strip_prefix(data, FileType::Backup)?);
    let vault_id = r.array::<16>()?;
    let flag = r.u8()?;
    let salt = r.array::<16>()?;
    let params = Argon2Params {
        m_cost_kib: r.u32()?,
        t_cost: r.u32()?,
        p_cost: r.u32()?,
    };
    let head_len = data.len().saturating_sub(r.rest().len());
    let head = data
        .get(..head_len)
        .ok_or(VaultError::Corrupt("backup header"))?;
    let pass = match (flag, passphrase) {
        (0, _) => None,
        (1, Some(p)) => {
            if !within_import_limit(params) {
                return Err(VaultError::InvalidParameters);
            }
            Some(p)
        }
        (1, None) => return Err(VaultError::InvalidParameters),
        _ => return Err(VaultError::Corrupt("backup flags")),
    };
    let key = backup_key(phrase, pass, &salt, params, &vault_id)?;
    let body =
        hirz_crypto::aead::open(&key, head, r.rest()).map_err(|_| VaultError::WrongRecoveryKey)?;
    let mut br = Reader::new(&body);
    let count = br.u32()?;
    if count > MAX_RECORDS {
        return Err(VaultError::Corrupt("backup record count"));
    }
    let mut out = Vec::new();
    for _ in 0..count {
        let len = br.u32()?;
        if len > MAX_RECORD_LEN {
            return Err(VaultError::Corrupt("backup record length"));
        }
        let enc = br.take(usize::try_from(len).map_err(|_| VaultError::Corrupt("length"))?)?;
        out.push(CredentialRecord::decode(enc)?);
    }
    br.finish()?;
    Ok(out)
}
