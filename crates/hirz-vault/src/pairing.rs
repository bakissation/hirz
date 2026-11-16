//! Device pairing without the recovery phrase. A new device writes a request into the synced
//! folder; a device holding the vault key approves it after the user compared four words on both
//! screens, and seals the key generations to the new device's X25519 key (docs/vault-format.md, 11).

use crate::DeviceId;
use crate::codec::{self, Fields, Reader, Writer, aad, hex, unhex};
use crate::error::VaultError;
use crate::format::{
    self, FORMAT_VERSION, FileType, GEN_INFO_NAME, GenId, GenInfo, Header, KEYS_DIR, Keyring,
    KeyringEntry, LocalDevice, prefix, strip_prefix,
};
use crate::fsutil::{self, MAX_FILE_LEN};
use crate::record::{MAX_DEVICE_NAME_LEN, expect_end, expect_field};
use crate::vault::{self, KeyedJoin, Vault};
use hirz_crypto::kdf::{self, Argon2Params};
use hirz_crypto::{Zeroizing, x25519};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub(crate) const PAIRING_DIR: &str = "pairing";
const REQUEST_SUFFIX: &str = ".req";
const APPROVAL_SUFFIX: &str = ".ok";
const REQUEST_VERSION: u8 = 1;

pub const PAIRING_LIFETIME_SECS: u64 = 15 * 60;
/// Requests dated this far in the future still count (clocks of two devices differ).
const MAX_CLOCK_SKEW_SECS: u64 = 5 * 60;
/// An approval the new device never picked up is deleted this long after the request expired.
const APPROVAL_KEEP_SECS: u64 = 60 * 60;
/// A pairing file that stays unreadable this long is not an incomplete sync: it is deleted.
const UNREADABLE_KEEP_SECS: u64 = 20 * 60;
pub const PAIRING_WORDS: usize = 4;
const CHAIN_ENTRY_LEN: usize = 52;
const MAX_CHAIN: usize = 10_000;

/// Memory-hard, so that finding a second request with the same 44-bit words costs about
/// 2^43 Argon2id evaluations instead of 2^43 hashes.
const WORDS_KDF: Argon2Params = kdf::DEFAULT;

/// All fields are public; the user authenticates them by comparing the words derived from them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingRequest {
    pub request_id: [u8; 16],
    pub device_id: DeviceId,
    /// Untrusted, chosen by the new device; clean before display.
    pub name: String,
    pub public_key: [u8; 32],
    /// Unix seconds, by the new device's clock.
    pub created_at: u64,
    pub expires_at: u64,
}

impl PairingRequest {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, VaultError> {
        if self.name.is_empty() || self.name.len() > MAX_DEVICE_NAME_LEN {
            return Err(VaultError::Encode);
        }
        let mut w = Writer::new(REQUEST_VERSION);
        w.field(0x01, &self.request_id)?;
        w.field(0x02, &self.device_id)?;
        w.field(0x03, self.name.as_bytes())?;
        w.field(0x04, &self.public_key)?;
        w.u64_field(0x05, self.created_at)?;
        w.u64_field(0x06, self.expires_at)?;
        let body = w.finish();
        let mut out = prefix(FileType::PairingRequest).to_vec();
        out.extend_from_slice(&body);
        Ok(out)
    }

    pub(crate) fn decode(data: &[u8]) -> Result<PairingRequest, VaultError> {
        let mut f = Fields::new(
            strip_prefix(data, FileType::PairingRequest)?,
            REQUEST_VERSION,
        )?;
        let request_id = codec::fixed::<16>(expect_field(&mut f, 0x01)?)?;
        let device_id = codec::fixed::<16>(expect_field(&mut f, 0x02)?)?;
        let name = codec::string_value(expect_field(&mut f, 0x03)?, MAX_DEVICE_NAME_LEN)?;
        let public_key = codec::fixed::<32>(expect_field(&mut f, 0x04)?)?;
        let created_at = codec::u64_value(expect_field(&mut f, 0x05)?)?;
        let expires_at = codec::u64_value(expect_field(&mut f, 0x06)?)?;
        expect_end(&mut f)?;
        if name.is_empty() {
            return Err(VaultError::Corrupt("pairing request name"));
        }
        let lifetime = expires_at.checked_sub(created_at);
        if lifetime.is_none_or(|l| l == 0 || l > PAIRING_LIFETIME_SECS) {
            return Err(VaultError::Corrupt("pairing request lifetime"));
        }
        Ok(PairingRequest {
            request_id,
            device_id,
            name,
            public_key,
            created_at,
            expires_at,
        })
    }

    fn usable_at(&self, now: u64) -> bool {
        now <= self.expires_at && self.created_at <= now.saturating_add(MAX_CLOCK_SKEW_SECS)
    }
}

fn request_name(id: &[u8; 16]) -> String {
    format!("{}{REQUEST_SUFFIX}", hex(id))
}

fn approval_name(id: &[u8; 16]) -> String {
    format!("{}{APPROVAL_SUFFIX}", hex(id))
}

fn parse_name(name: &str, suffix: &str) -> Option<[u8; 16]> {
    unhex::<16>(name.strip_suffix(suffix)?)
}

/// The four verification words as BIP-39 indices; derivation in docs/vault-format.md, 11.2.
pub(crate) fn word_indices(
    vault_id: &[u8; 16],
    genesis_fingerprint: &[u8; 32],
    req: &PairingRequest,
) -> Result<[u16; PAIRING_WORDS], VaultError> {
    let input = aad(
        "hirz pairing words v1",
        &[
            &[FORMAT_VERSION],
            vault_id,
            genesis_fingerprint,
            &req.request_id,
            &req.device_id,
            req.name.as_bytes(),
            &req.public_key,
            &req.created_at.to_be_bytes(),
            &req.expires_at.to_be_bytes(),
        ],
    );
    let out = kdf::argon2id(&input, &req.request_id, WORDS_KDF)?;
    let mut first = [0u8; 8];
    for (d, s) in first.iter_mut().zip(out.iter()) {
        *d = *s;
    }
    let bits = u64::from_be_bytes(first).wrapping_shr(20);
    let mut idx = [0u16; PAIRING_WORDS];
    for (i, slot) in idx.iter_mut().enumerate() {
        let shift = u32::try_from(PAIRING_WORDS.saturating_sub(1).saturating_sub(i))
            .unwrap_or(0)
            .saturating_mul(11);
        *slot = u16::try_from(bits.wrapping_shr(shift) & 0x7ff).unwrap_or(0);
    }
    Ok(idx)
}

pub(crate) fn words_text(
    vault_id: &[u8; 16],
    genesis_fingerprint: &[u8; 32],
    req: &PairingRequest,
) -> Result<String, VaultError> {
    let idx = word_indices(vault_id, genesis_fingerprint, req)?;
    let mut words = Vec::with_capacity(PAIRING_WORDS);
    for i in idx {
        words.push(crate::recovery::word_at(i).ok_or(VaultError::Crypto)?);
    }
    Ok(words.join(" "))
}

fn gen_info_path(vault_dir: &Path, id: &GenId) -> PathBuf {
    vault_dir
        .join(KEYS_DIR)
        .join(id.dir_name())
        .join(GEN_INFO_NAME)
}

/// SHA-256 of the genesis `gen.info` file. That file is written once and never collected,
/// so it identifies the vault beyond its (plaintext, copyable) vault id.
pub(crate) fn genesis_fingerprint(
    vault_dir: &Path,
    genesis: &GenId,
) -> Result<[u8; 32], VaultError> {
    let data = fsutil::read_capped(&gen_info_path(vault_dir, genesis), MAX_FILE_LEN)?;
    Ok(hirz_crypto::sha256(&data))
}

/// The single genesis generation. Several mean the folder was tampered with; none means it is
/// not completely synced yet.
fn find_genesis(vault_dir: &Path) -> Result<GenId, VaultError> {
    let keys = vault_dir.join(KEYS_DIR);
    let mut found = None;
    for name in fsutil::list(&keys)? {
        let Some(id) = GenId::parse_dir(&name) else {
            continue;
        };
        if id.number != 1 || !gen_info_path(vault_dir, &id).is_file() {
            continue;
        }
        if found.is_some() {
            return Err(VaultError::Corrupt("more than one genesis generation"));
        }
        found = Some(id);
    }
    found.ok_or(VaultError::NotFound)
}

fn approval_aad(vault_id: &[u8; 16], req: &PairingRequest) -> Vec<u8> {
    aad(
        "hirz pairing approval v1",
        &[
            &[FORMAT_VERSION],
            vault_id,
            &req.request_id,
            &req.device_id,
            &req.public_key,
            &req.expires_at.to_be_bytes(),
        ],
    )
}

/// `prefix(0x08) || expires_at u64 || sealed box to the request key of n x (GenId || K)`.
pub(crate) fn seal_approval(
    vault_id: &[u8; 16],
    req: &PairingRequest,
    chain: &[KeyringEntry],
) -> Result<Vec<u8>, VaultError> {
    if chain.is_empty() || chain.len() > MAX_CHAIN {
        return Err(VaultError::Encode);
    }
    let mut pt = Zeroizing::new(Vec::with_capacity(
        chain.len().saturating_mul(CHAIN_ENTRY_LEN),
    ));
    for e in chain {
        pt.extend_from_slice(&e.gen_id.bytes());
        pt.extend_from_slice(e.key.as_slice());
    }
    let sealed = x25519::seal_to(&req.public_key, &approval_aad(vault_id, req), &pt)?;
    let mut out = prefix(FileType::PairingApproval).to_vec();
    out.extend_from_slice(&req.expires_at.to_be_bytes());
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn approval_expiry(data: &[u8]) -> Result<u64, VaultError> {
    Reader::new(strip_prefix(data, FileType::PairingApproval)?).u64()
}

/// Checks only the encoding; the caller verifies the keys against the vault.
pub(crate) fn open_approval(
    data: &[u8],
    vault_id: &[u8; 16],
    req: &PairingRequest,
    private: &[u8; 32],
) -> Result<Vec<KeyringEntry>, VaultError> {
    let mut r = Reader::new(strip_prefix(data, FileType::PairingApproval)?);
    if r.u64()? != req.expires_at {
        return Err(VaultError::Corrupt("pairing approval expiry"));
    }
    let pt = x25519::open_from(private, &approval_aad(vault_id, req), r.rest())
        .map_err(|_| VaultError::Corrupt("pairing approval authentication"))?;
    if pt.is_empty() || pt.len() % CHAIN_ENTRY_LEN != 0 || pt.len() / CHAIN_ENTRY_LEN > MAX_CHAIN {
        return Err(VaultError::Corrupt("pairing approval length"));
    }
    let mut out: Vec<KeyringEntry> = Vec::new();
    for chunk in pt.as_chunks::<CHAIN_ENTRY_LEN>().0 {
        let mut c = Reader::new(chunk);
        let gen_id = GenId::from_bytes(c.take(20)?)?;
        let key = Zeroizing::new(c.array::<32>()?);
        let follows = match out.last() {
            None => gen_id.number == 1,
            Some(prev) => prev.gen_id.number.checked_add(1) == Some(gen_id.number),
        };
        if !follows {
            return Err(VaultError::Corrupt("pairing approval chain"));
        }
        out.push(KeyringEntry {
            gen_id,
            key,
            root: out.is_empty(),
        });
    }
    Ok(out)
}

fn remove_if_old(path: &Path, now: u64) {
    let modified = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs());
    if let Some(m) = modified
        && now > m.saturating_add(UNREADABLE_KEEP_SECS)
    {
        let _ = fsutil::remove_file(path);
    }
}

/// Valid requests that can still be approved, oldest first. Also deletes expired or known-device
/// requests, approvals nobody picked up, and files unreadable for longer than a request lives.
pub(crate) fn list_requests(
    vault_dir: &Path,
    now: u64,
    known: &BTreeSet<DeviceId>,
) -> Result<Vec<PairingRequest>, VaultError> {
    let dir = vault_dir.join(PAIRING_DIR);
    let mut out = Vec::new();
    for name in fsutil::list(&dir)? {
        let path = dir.join(&name);
        if let Some(id) = parse_name(&name, REQUEST_SUFFIX) {
            match fsutil::read_capped(&path, MAX_FILE_LEN).and_then(|d| PairingRequest::decode(&d))
            {
                Ok(r) if r.request_id == id => {
                    if now > r.expires_at || known.contains(&r.device_id) {
                        let _ = fsutil::remove_file(&path);
                    } else if r.usable_at(now) {
                        out.push(r);
                    }
                }
                Err(VaultError::Io(std::io::ErrorKind::NotFound, _)) => {}
                _ => remove_if_old(&path, now),
            }
        } else if parse_name(&name, APPROVAL_SUFFIX).is_some() {
            match fsutil::read_capped(&path, MAX_FILE_LEN).and_then(|d| approval_expiry(&d)) {
                Ok(exp) => {
                    if now > exp.saturating_add(APPROVAL_KEEP_SECS) {
                        let _ = fsutil::remove_file(&path);
                    }
                }
                Err(VaultError::Io(std::io::ErrorKind::NotFound, _)) => {}
                Err(_) => remove_if_old(&path, now),
            }
        }
    }
    out.sort_by_key(|r| (r.created_at, r.request_id));
    Ok(out)
}

/// Fails unless the file still holds exactly `req` and it can still be approved, so the key is
/// never sealed to a request the user did not see.
pub(crate) fn check_unchanged(
    vault_dir: &Path,
    req: &PairingRequest,
    now: u64,
) -> Result<(), VaultError> {
    let path = vault_dir
        .join(PAIRING_DIR)
        .join(request_name(&req.request_id));
    let data = match fsutil::read_capped(&path, MAX_FILE_LEN) {
        Ok(d) => d,
        Err(VaultError::Io(std::io::ErrorKind::NotFound, _)) => return Err(VaultError::NotFound),
        Err(e) => return Err(e),
    };
    if PairingRequest::decode(&data).ok().as_ref() != Some(req) {
        return Err(VaultError::Corrupt("pairing request changed"));
    }
    if !req.usable_at(now) {
        return Err(VaultError::NotFound);
    }
    Ok(())
}

pub(crate) fn write_approval(
    vault_dir: &Path,
    req: &PairingRequest,
    data: &[u8],
) -> Result<(), VaultError> {
    fsutil::write_atomic(
        &vault_dir.join(PAIRING_DIR),
        &approval_name(&req.request_id),
        data,
    )
}

/// Deletes a request. Returns false when it was already gone.
pub(crate) fn remove_request(vault_dir: &Path, request_id: &[u8; 16]) -> Result<bool, VaultError> {
    let path = vault_dir.join(PAIRING_DIR).join(request_name(request_id));
    let existed = path.exists();
    fsutil::remove_file(&path)?;
    Ok(existed)
}

#[derive(Debug)]
pub enum PairingPoll {
    Waiting,
    /// Forged by someone with access to the folder, or incomplete; nothing changed, polling may continue.
    Invalid(&'static str),
    Joined(Box<Vault>),
}

pub struct PendingJoin {
    vault_dir: PathBuf,
    header: Header,
    genesis: GenId,
    device: LocalDevice,
    request: PairingRequest,
    words: String,
}

impl core::fmt::Debug for PendingJoin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PendingJoin")
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

impl PendingJoin {
    /// Nothing is written to `state_dir` until the request is approved.
    pub fn start(
        vault_dir: &Path,
        state_dir: &Path,
        device_name: &str,
    ) -> Result<PendingJoin, VaultError> {
        PendingJoin::start_at(vault_dir, state_dir, device_name, vault::now())
    }

    pub(crate) fn start_at(
        vault_dir: &Path,
        state_dir: &Path,
        device_name: &str,
        now: u64,
    ) -> Result<PendingJoin, VaultError> {
        if device_name.is_empty() || device_name.len() > MAX_DEVICE_NAME_LEN {
            return Err(VaultError::InvalidParameters);
        }
        let header = vault::read_header(vault_dir)?;
        if Vault::is_set_up(state_dir) {
            return Err(VaultError::AlreadyExists);
        }
        let genesis = find_genesis(vault_dir)?;
        let fingerprint = genesis_fingerprint(vault_dir, &genesis)?;
        let device = vault::new_device(header.vault_id, device_name)?;
        let request = PairingRequest {
            request_id: vault::random16()?,
            device_id: device.device_id,
            name: device_name.to_string(),
            public_key: x25519::public_key(&device.x25519_private)?,
            created_at: now,
            expires_at: now.saturating_add(PAIRING_LIFETIME_SECS),
        };
        let words = words_text(&header.vault_id, &fingerprint, &request)?;
        fsutil::write_atomic(
            &vault_dir.join(PAIRING_DIR),
            &request_name(&request.request_id),
            &request.encode()?,
        )?;
        Ok(PendingJoin {
            vault_dir: vault_dir.to_path_buf(),
            header,
            genesis,
            device,
            request,
            words,
        })
    }

    pub fn request(&self) -> &PairingRequest {
        &self.request
    }

    pub fn words(&self) -> &str {
        &self.words
    }

    /// On success writes this device's state to `state_dir` and removes the request files.
    pub fn poll(&self, state_dir: &Path) -> Result<PairingPoll, VaultError> {
        if Vault::is_set_up(state_dir) {
            return Err(VaultError::AlreadyExists);
        }
        let dir = self.vault_dir.join(PAIRING_DIR);
        let data = match fsutil::read_capped(
            &dir.join(approval_name(&self.request.request_id)),
            MAX_FILE_LEN,
        ) {
            Ok(d) => d,
            Err(VaultError::Io(std::io::ErrorKind::NotFound, _)) => {
                return Ok(PairingPoll::Waiting);
            }
            Err(_) => return Ok(PairingPoll::Invalid("the approval file cannot be read")),
        };
        let vault_id = self.header.vault_id;
        let Ok(chain) = open_approval(&data, &vault_id, &self.request, &self.device.x25519_private)
        else {
            return Ok(PairingPoll::Invalid(
                "the approval does not open with this device's key",
            ));
        };
        let Some(genesis) = chain.first().filter(|e| e.gen_id == self.genesis) else {
            return Ok(PairingPoll::Invalid("the approval is for another vault"));
        };
        let info =
            fsutil::read_capped(&gen_info_path(&self.vault_dir, &self.genesis), MAX_FILE_LEN)
                .and_then(|d| GenInfo::open(&d, &genesis.key, &vault_id, &self.genesis));
        let Ok(info) = info else {
            return Ok(PairingPoll::Invalid(
                "the approved key does not open this vault",
            ));
        };
        if !hirz_crypto::ct_eq(
            &info.commitment,
            &format::commitment(&genesis.key, &vault_id, &self.genesis),
        ) {
            return Ok(PairingPoll::Invalid(
                "the approved key does not open this vault",
            ));
        }
        let keyring = Keyring {
            recovery_pub: info.recovery_pub,
            entries: chain,
        };
        match vault::join_with_keys(
            &self.vault_dir,
            state_dir,
            self.header,
            self.device.clone(),
            keyring,
        )? {
            KeyedJoin::Joined(v) => {
                let _ = fsutil::remove_file(&dir.join(approval_name(&self.request.request_id)));
                let _ = remove_request(&self.vault_dir, &self.request.request_id);
                Ok(PairingPoll::Joined(v))
            }
            KeyedJoin::NotReady => Ok(PairingPoll::Waiting),
            KeyedJoin::Rejected(why) => Ok(PairingPoll::Invalid(why)),
        }
    }

    pub fn cancel(&self) -> Result<(), VaultError> {
        remove_request(&self.vault_dir, &self.request.request_id).map(|_| ())
    }
}
