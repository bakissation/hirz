//! Device pairing without the recovery phrase. A new device writes a request into the synced
//! folder; a device holding the vault key approves it after the user compared four words on both
//! screens, and seals the key generations to the new device's X25519 key (docs/vault-format.md, 11).

use crate::DeviceId;
use crate::codec::{self, Fields, Reader, Writer, aad, hex, unhex};
use crate::error::VaultError;
use crate::format::{
    self, FORMAT_VERSION, FileType, GEN_INFO_NAME, GenId, GenInfo, Header, KEYS_DIR, Keyring,
    KeyringEntry, LocalDevice, MAX_GENERATIONS, RECOVERY_SLOT_NAME, prefix, strip_prefix,
};
use crate::fsutil::{self, MAX_FILE_LEN};
use crate::record::{MAX_DEVICE_NAME_LEN, device_id_for, expect_end, expect_field};
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
/// Requests a listing returns; the rest are counted, so a folder full of planted requests
/// cannot flood the approval screen.
pub const MAX_LISTED_REQUESTS: usize = 16;

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
    /// Ed25519 key the new device will sign key rotations with; `device_id` is derived from it.
    pub signing_key: [u8; 32],
    /// Unix seconds, by the new device's clock.
    pub created_at: u64,
    pub expires_at: u64,
}

impl PairingRequest {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, VaultError> {
        if device_name_problem(&self.name).is_some() {
            return Err(VaultError::Encode);
        }
        let mut w = Writer::new(REQUEST_VERSION);
        w.field(0x01, &self.request_id)?;
        w.field(0x02, &self.device_id)?;
        w.field(0x03, self.name.as_bytes())?;
        w.field(0x04, &self.public_key)?;
        w.u64_field(0x05, self.created_at)?;
        w.u64_field(0x06, self.expires_at)?;
        w.field(0x07, &self.signing_key)?;
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
        let signing_key = codec::fixed::<32>(expect_field(&mut f, 0x07)?)?;
        expect_end(&mut f)?;
        if device_name_problem(&name).is_some() {
            return Err(VaultError::Corrupt("pairing request name"));
        }
        if device_id_for(&signing_key) != device_id {
            return Err(VaultError::Corrupt("pairing request device id"));
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
            signing_key,
            created_at,
            expires_at,
        })
    }

    fn usable_at(&self, now: u64) -> bool {
        now <= self.expires_at && self.created_at <= now.saturating_add(MAX_CLOCK_SKEW_SECS)
    }
}

/// Longest device name a pairing request carries.
pub const MAX_REQUEST_NAME_LEN: usize = 32;
/// A name with more tokens from the recovery word list than this is refused.
const MAX_WORDLIST_TOKENS: usize = 2;
const FALLBACK_NAME: &str = "new-device";

fn is_separator(c: char) -> bool {
    matches!(c, ' ' | '-' | '_' | '.')
}

fn is_capitals_token(t: &str) -> bool {
    t.len() >= 3 && t.bytes().all(|b| b.is_ascii_uppercase())
}

/// Why `name` may not be the name in a pairing request, or `None` when it may. The name is chosen
/// by the device that asks to join and anyone who can write to the folder can make one up, so it
/// is limited to a short alphabet and cannot read as the verification words: no token in capitals
/// (the words are shown in capitals) and at most two tokens from the recovery word list.
pub fn device_name_problem(name: &str) -> Option<&'static str> {
    if name.is_empty() || name.len() > MAX_REQUEST_NAME_LEN {
        return Some("a device name has 1 to 32 characters");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b' '))
    {
        return Some("a device name uses only letters, digits, spaces and - _ .");
    }
    if name.starts_with(' ') || name.ends_with(' ') || name.contains("  ") {
        return Some("a device name has no leading, trailing or repeated spaces");
    }
    let mut listed = 0usize;
    for token in name.split(is_separator).filter(|t| !t.is_empty()) {
        if is_capitals_token(token) {
            return Some("a device name has no word in capitals");
        }
        if crate::recovery::index_of(&token.to_ascii_lowercase()).is_some() {
            listed = listed.saturating_add(1);
        }
    }
    (listed > MAX_WORDLIST_TOKENS)
        .then_some("a device name has too many words of the recovery word list")
}

/// `name` reduced to one [`device_name_problem`] accepts: other characters become `-`, white
/// space is collapsed, capitals words are lowercased and the result is cut to
/// [`MAX_REQUEST_NAME_LEN`]. A name that cannot be repaired becomes `new-device`.
pub fn request_device_name(name: &str) -> String {
    let mut mapped = String::new();
    for c in name.chars() {
        let c = match c {
            c if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') => c,
            c if c.is_whitespace() => ' ',
            _ => '-',
        };
        if c == ' ' && (mapped.is_empty() || mapped.ends_with(' ')) {
            continue;
        }
        mapped.push(c);
        if mapped.len() >= MAX_REQUEST_NAME_LEN {
            break;
        }
    }
    let mut out = String::new();
    let mut token = String::new();
    for c in mapped.trim_end().chars().chain(Some(' ')) {
        if is_separator(c) {
            if is_capitals_token(&token) {
                token.make_ascii_lowercase();
            }
            out.push_str(&token);
            token.clear();
            out.push(c);
        } else {
            token.push(c);
        }
    }
    out.pop();
    if out.bytes().any(|b| b.is_ascii_alphanumeric()) && device_name_problem(&out).is_none() {
        out
    } else {
        FALLBACK_NAME.to_owned()
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
            &req.signing_key,
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

/// Byte lengths of a genesis `gen.info` and its `recovery.slot`. Both are fixed: a genesis has one
/// member, a recovery tag, no removals and no endorsement chain.
fn genesis_file_lens() -> Result<(usize, usize), VaultError> {
    let zero = [0u8; 32];
    let id = GenId {
        number: 1,
        rotator: [0u8; 16],
    };
    let info = GenInfo {
        commitment: zero,
        recovery_pub: zero,
        removed: Vec::new(),
        created_at: 0,
        reemit_first: 0,
        reemit_count: 0,
        recovery_tag: Some(zero),
        recovery_signing_pub: zero,
        members: vec![format::Member {
            device_id: [0u8; 16],
            signing_public: zero,
            x25519_public: zero,
        }],
        chain: Vec::new(),
    };
    let public = x25519::public_key(&[1u8; 32])?;
    let info_len = info.seal(&zero, &[0u8; 16], &id, None, &zero)?.len();
    let slot_len = format::seal_recovery_slot(&[0u8; 16], &id, &public, &zero)?.len();
    Ok((info_len, slot_len))
}

/// The single genesis generation. Several mean the folder was tampered with; none means it is
/// not completely synced yet. Without a key the new device cannot authenticate a candidate, so
/// it counts only those shaped exactly like a genesis: a `gen.info` of the genesis length with
/// the genesis prefix and a `recovery.slot` of the slot length. Anything else is junk.
fn find_genesis(vault_dir: &Path) -> Result<GenId, VaultError> {
    let keys = vault_dir.join(KEYS_DIR);
    let (info_len, slot_len) = genesis_file_lens()?;
    let mut found = None;
    for name in fsutil::list(&keys)? {
        let Some(id) = GenId::parse_dir(&name) else {
            continue;
        };
        if id.number != 1 || !fsutil::is_real_dir(&keys.join(&name)) {
            continue;
        }
        let is_genesis = fsutil::read_capped(&gen_info_path(vault_dir, &id), MAX_FILE_LEN)
            .is_ok_and(|d| d.len() == info_len && matches!(GenInfo::parent_of(&d), Ok(None)))
            && fsutil::read_capped(&keys.join(&name).join(RECOVERY_SLOT_NAME), MAX_FILE_LEN)
                .is_ok_and(|d| d.len() == slot_len);
        if !is_genesis {
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
    if chain.is_empty() || chain.len() > MAX_GENERATIONS {
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
    if pt.is_empty()
        || pt.len() % CHAIN_ENTRY_LEN != 0
        || pt.len() / CHAIN_ENTRY_LEN > MAX_GENERATIONS
    {
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

fn remove_pairing_file(vault_dir: &Path, name: &str) -> Result<(), VaultError> {
    fsutil::remove_in(vault_dir, &[PAIRING_DIR], name)
}

fn remove_if_old(vault_dir: &Path, name: &str, now: u64) {
    let modified = std::fs::symlink_metadata(vault_dir.join(PAIRING_DIR).join(name))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs());
    if let Some(m) = modified
        && now > m.saturating_add(UNREADABLE_KEEP_SECS)
    {
        let _ = remove_pairing_file(vault_dir, name);
    }
}

/// Valid requests that can still be approved, oldest first, at most `MAX_LISTED_REQUESTS`, and
/// how many more there are. Also deletes expired or known-device requests, approvals nobody
/// picked up, and files unreadable for longer than a request lives.
pub(crate) fn list_requests(
    vault_dir: &Path,
    now: u64,
    known: &BTreeSet<DeviceId>,
) -> Result<(Vec<PairingRequest>, usize), VaultError> {
    let dir = vault_dir.join(PAIRING_DIR);
    let mut out = Vec::new();
    for name in fsutil::list(&dir)? {
        let path = dir.join(&name);
        if let Some(id) = parse_name(&name, REQUEST_SUFFIX) {
            match fsutil::read_capped(&path, MAX_FILE_LEN).and_then(|d| PairingRequest::decode(&d))
            {
                Ok(r) if r.request_id == id => {
                    if now > r.expires_at || known.contains(&r.device_id) {
                        let _ = remove_pairing_file(vault_dir, &name);
                    } else if r.usable_at(now) {
                        out.push(r);
                    }
                }
                Err(VaultError::Io(std::io::ErrorKind::NotFound, _)) => {}
                _ => remove_if_old(vault_dir, &name, now),
            }
        } else if parse_name(&name, APPROVAL_SUFFIX).is_some() {
            match fsutil::read_capped(&path, MAX_FILE_LEN).and_then(|d| approval_expiry(&d)) {
                Ok(exp) => {
                    if now > exp.saturating_add(APPROVAL_KEEP_SECS) {
                        let _ = remove_pairing_file(vault_dir, &name);
                    }
                }
                Err(VaultError::Io(std::io::ErrorKind::NotFound, _)) => {}
                Err(_) => remove_if_old(vault_dir, &name, now),
            }
        }
    }
    out.sort_by_key(|r| (r.created_at, r.request_id));
    let hidden = out.len().saturating_sub(MAX_LISTED_REQUESTS);
    out.truncate(MAX_LISTED_REQUESTS);
    Ok((out, hidden))
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
        &fsutil::vault_subdir(vault_dir, &[PAIRING_DIR])?,
        &approval_name(&req.request_id),
        data,
    )
}

/// Deletes a request. Returns false when it was already gone.
pub(crate) fn remove_request(vault_dir: &Path, request_id: &[u8; 16]) -> Result<bool, VaultError> {
    let name = request_name(request_id);
    let existed = fsutil::exists_no_follow(&vault_dir.join(PAIRING_DIR).join(&name));
    remove_pairing_file(vault_dir, &name)?;
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
        let device_name = request_device_name(device_name);
        let device_name = device_name.as_str();
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
            signing_key: device.signing_public()?,
            created_at: now,
            expires_at: now.saturating_add(PAIRING_LIFETIME_SECS),
        };
        let words = words_text(&header.vault_id, &fingerprint, &request)?;
        fsutil::write_atomic(
            &fsutil::vault_subdir(vault_dir, &[PAIRING_DIR])?,
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
                let _ =
                    remove_pairing_file(&self.vault_dir, &approval_name(&self.request.request_id));
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod name_policy_tests {
    use super::*;

    #[test]
    fn ordinary_names_pass() {
        for name in [
            "laptop",
            "work laptop",
            "alice-desktop",
            "thinkpad_x1.2",
            "Pixel 8",
            "X1 Carbon",
            "PC",
            "a",
            &"a".repeat(MAX_REQUEST_NAME_LEN),
        ] {
            assert_eq!(device_name_problem(name), None, "{name:?}");
        }
    }

    #[test]
    fn the_alphabet_is_short() {
        for name in [
            "",
            &"a".repeat(MAX_REQUEST_NAME_LEN + 1),
            "caf\u{e9}",
            "desk\n",
            "a\tb",
            "my \"laptop\"",
            "[laptop]",
            "a<b",
            "a&b",
            "a\u{202e}b",
            "a\u{200b}b",
            "\u{2800}x",
            " lead",
            "trail ",
            "two  spaces",
            "a/b",
            "name: x",
        ] {
            assert!(device_name_problem(name).is_some(), "{name:?}");
        }
    }

    #[test]
    fn a_name_cannot_carry_the_verification_words() {
        for name in [
            "laptop MAPLE ORBIT WHEAT OCEAN",
            "MAPLE ORBIT WHEAT OCEAN",
            "ORBIT-WHEAT",
            "x.OCEAN",
            "ABC",
            "maple orbit wheat ocean",
            "Maple Orbit Wheat Ocean",
            "maple-orbit_wheat.ocean",
            "maple orbit wheat",
            "laptop maple orbit wheat",
        ] {
            assert!(device_name_problem(name).is_some(), "{name:?}");
        }
        assert_eq!(device_name_problem("maple orbit"), None);
        assert_eq!(device_name_problem("work laptop"), None);
        assert_eq!(device_name_problem("mapleorbitwheatocean"), None);
        assert_eq!(device_name_problem("MAPLE1"), None);
    }

    #[test]
    fn a_free_form_name_is_reduced_to_the_alphabet() {
        for (given, want) in [
            ("laptop", "laptop"),
            ("  alice's   MacBook Pro  ", "alice-s MacBook Pro"),
            ("DESKTOP-ABC123", "desktop-ABC123"),
            ("LAPTOP MAPLE ORBIT WHEAT OCEAN", "new-device"),
            ("MacBook Air PRO", "MacBook Air pro"),
            ("caf\u{e9}", "caf-"),
            ("a\u{202e}b", "a-b"),
            ("tab\tname", "tab name"),
            ("\u{2800}\u{200b}", "new-device"),
            ("---", "new-device"),
            ("work laptop home", "new-device"),
        ] {
            let got = request_device_name(given);
            assert_eq!(got, want, "{given:?}");
            assert_eq!(device_name_problem(&got), None, "{given:?}");
        }
        let long = request_device_name(&"word ".repeat(40));
        assert!(long.len() <= MAX_REQUEST_NAME_LEN);
        assert_eq!(device_name_problem(&long), None);
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let mut r = [0u8; 8];
        hirz_crypto::random_fill(&mut r).unwrap();
        let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
        let p = std::env::temp_dir().join(format!("hirz-vault-name-{tag}-{hex}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn a_planted_request_with_a_forged_name_is_never_listed() {
        let dir = scratch("planted");
        let vault_dir = dir.join("vault");
        let (mut vault, _phrase) = Vault::create(&vault_dir, &dir.join("state"), "first").unwrap();
        let pending = PendingJoin::start(&vault_dir, &dir.join("state2"), "laptop").unwrap();
        assert_eq!(pending.request().name, "laptop");
        assert_eq!(vault.pairing_requests().unwrap().len(), 1);

        let file = vault_dir
            .join(PAIRING_DIR)
            .join(request_name(&pending.request().request_id));
        let mut bytes = std::fs::read(&file).unwrap();
        let at = bytes.windows(6).position(|w| w == b"laptop").unwrap();
        bytes[at..at + 6].copy_from_slice(b"LAPTOP");
        std::fs::write(&file, &bytes).unwrap();
        assert!(vault.pairing_requests().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_new_device_asks_under_a_name_the_policy_allows() {
        let dir = scratch("start");
        let vault_dir = dir.join("vault");
        let (_vault, _phrase) = Vault::create(&vault_dir, &dir.join("state"), "first").unwrap();
        let pending =
            PendingJoin::start(&vault_dir, &dir.join("state2"), "ALICE'S DESKTOP-PC").unwrap();
        assert_eq!(pending.request().name, "alice-S desktop-PC");
        assert_eq!(device_name_problem(&pending.request().name), None);
        assert_eq!(
            PendingJoin::start(&vault_dir, &dir.join("state3"), "").err(),
            Some(VaultError::InvalidParameters)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
