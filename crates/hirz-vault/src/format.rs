//! Byte layouts of every vault and local state file. See docs/vault-format.md.

use crate::DeviceId;
use crate::codec::{self, Fields, Reader, Writer, aad, hex, unhex};
use crate::error::VaultError;
use hirz_crypto::Zeroizing;
use hirz_crypto::{aead, x25519};

pub(crate) const MAGIC: [u8; 4] = *b"HIRZ";
pub(crate) const FORMAT_VERSION: u8 = 1;

pub(crate) const HEADER_NAME: &str = "hirz-vault";
pub(crate) const KEYS_DIR: &str = "keys";
pub(crate) const RECORDS_DIR: &str = "records";
pub(crate) const GEN_INFO_NAME: &str = "gen.info";
pub(crate) const RECOVERY_SLOT_NAME: &str = "recovery.slot";
pub(crate) const SLOT_SUFFIX: &str = ".slot";
pub(crate) const RECORD_SUFFIX: &str = ".rec";

pub(crate) const STATE_DEVICE: &str = "device";
pub(crate) const STATE_KEYRING: &str = "keyring";
pub(crate) const STATE_COUNTER: &str = "counter";

pub(crate) type VaultKey = Zeroizing<[u8; 32]>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum FileType {
    Header = 1,
    Record = 2,
    GenInfo = 3,
    DeviceSlot = 4,
    RecoverySlot = 5,
    Backup = 6,
    PairingRequest = 7,
    PairingApproval = 8,
    LocalDevice = 0x10,
    LocalKeyring = 0x11,
    LocalCounter = 0x12,
}

pub(crate) fn prefix(t: FileType) -> [u8; 6] {
    let [m0, m1, m2, m3] = MAGIC;
    [m0, m1, m2, m3, t as u8, FORMAT_VERSION]
}

pub(crate) fn strip_prefix(data: &[u8], t: FileType) -> Result<&[u8], VaultError> {
    let mut r = Reader::new(data);
    if r.array::<4>()? != MAGIC {
        return Err(VaultError::Corrupt("magic"));
    }
    if r.u8()? != t as u8 {
        return Err(VaultError::Corrupt("file type"));
    }
    if r.u8()? != FORMAT_VERSION {
        return Err(VaultError::UnsupportedVersion);
    }
    Ok(r.rest())
}

/// Ordering (number, then rotator id) picks the winner when two devices rotate at the same time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GenId {
    pub number: u32,
    pub rotator: DeviceId,
}

impl GenId {
    pub(crate) fn bytes(&self) -> [u8; 20] {
        let mut out = [0u8; 20];
        let (n, r) = out.split_at_mut(4);
        n.copy_from_slice(&self.number.to_be_bytes());
        r.copy_from_slice(&self.rotator);
        out
    }

    pub(crate) fn from_bytes(b: &[u8]) -> Result<GenId, VaultError> {
        let mut r = Reader::new(b);
        let number = r.u32()?;
        let rotator = r.array::<16>()?;
        r.finish()?;
        Ok(GenId { number, rotator })
    }

    pub(crate) fn dir_name(&self) -> String {
        format!("{:010}-{}", self.number, hex(&self.rotator))
    }

    pub(crate) fn parse_dir(name: &str) -> Option<GenId> {
        let (num, dev) = name.split_once('-')?;
        if num.len() != 10 || !num.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let number = num.parse::<u32>().ok()?;
        if number == 0 {
            return None;
        }
        Some(GenId {
            number,
            rotator: unhex::<16>(dev)?,
        })
    }
}

/// `<lamport:020>-<16 hex>.rec`
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RecordName {
    pub(crate) lamport: u64,
    pub(crate) nonce: [u8; 8],
}

impl RecordName {
    pub(crate) fn new(lamport: u64) -> Result<RecordName, VaultError> {
        let mut nonce = [0u8; 8];
        hirz_crypto::random_fill(&mut nonce)?;
        Ok(RecordName { lamport, nonce })
    }

    pub(crate) fn file_name(&self) -> String {
        format!("{:020}-{}{RECORD_SUFFIX}", self.lamport, hex(&self.nonce))
    }

    pub(crate) fn parse(name: &str) -> Option<RecordName> {
        let stem = name.strip_suffix(RECORD_SUFFIX)?;
        let (num, nonce) = stem.split_once('-')?;
        if num.len() != 20 || !num.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        Some(RecordName {
            lamport: num.parse::<u64>().ok()?,
            nonce: unhex::<8>(nonce)?,
        })
    }
}

pub(crate) fn device_dir_name(id: &DeviceId) -> String {
    hex(id)
}

pub(crate) fn parse_device_dir(name: &str) -> Option<DeviceId> {
    unhex::<16>(name)
}

pub(crate) fn record_rel_path(writer: &DeviceId, name: &RecordName) -> String {
    format!("{RECORDS_DIR}/{}/{}", hex(writer), name.file_name())
}

pub(crate) fn slot_name(device: &DeviceId) -> String {
    format!("{}{SLOT_SUFFIX}", hex(device))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    pub(crate) vault_id: [u8; 16],
    pub(crate) created_at: u64,
}

impl Header {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = prefix(FileType::Header).to_vec();
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out
    }

    pub(crate) fn decode(data: &[u8]) -> Result<Header, VaultError> {
        let mut r = Reader::new(strip_prefix(data, FileType::Header)?);
        let vault_id = r.array::<16>()?;
        let created_at = r.u64()?;
        r.finish()?;
        Ok(Header {
            vault_id,
            created_at,
        })
    }
}

pub(crate) fn commitment(key: &[u8; 32], vault_id: &[u8; 16], gen_id: &GenId) -> [u8; 32] {
    hirz_crypto::hmac_sha256(
        key,
        &aad("hirz key commitment v1", &[vault_id, &gen_id.bytes()]),
    )
}

pub(crate) fn genesis_tag(
    auth_key: &[u8; 32],
    vault_id: &[u8; 16],
    gen_id: &GenId,
    commitment: &[u8; 32],
    recovery_pub: &[u8; 32],
) -> [u8; 32] {
    hirz_crypto::hmac_sha256(
        auth_key,
        &aad(
            "hirz genesis v1",
            &[vault_id, &gen_id.bytes(), commitment, recovery_pub],
        ),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GenInfo {
    pub(crate) commitment: [u8; 32],
    pub(crate) recovery_pub: [u8; 32],
    pub(crate) removed: Vec<DeviceId>,
    pub(crate) created_at: u64,
    pub(crate) reemit_first: u64,
    pub(crate) reemit_count: u64,
    pub(crate) recovery_tag: Option<[u8; 32]>,
}

const MAX_REMOVED: usize = 1024;

fn gen_info_aad(vault_id: &[u8; 16], gen_id: &GenId, parent: Option<&GenId>) -> Vec<u8> {
    let parent_bytes = parent.map(GenId::bytes).unwrap_or([0u8; 20]);
    aad(
        "hirz gen info v1",
        &[&[FORMAT_VERSION], vault_id, &gen_id.bytes(), &parent_bytes],
    )
}

impl GenInfo {
    /// Sealed under the parent generation's key, or under its own key for the genesis.
    pub(crate) fn seal(
        &self,
        key: &[u8; 32],
        vault_id: &[u8; 16],
        gen_id: &GenId,
        parent: Option<&GenId>,
    ) -> Result<Vec<u8>, VaultError> {
        if self.removed.len() > MAX_REMOVED {
            return Err(VaultError::Encode);
        }
        let mut w = Writer::new(1);
        w.field(0x01, &self.commitment)?;
        w.field(0x02, &self.recovery_pub)?;
        let removed: Vec<u8> = self.removed.iter().flatten().copied().collect();
        w.field(0x03, &removed)?;
        w.u64_field(0x04, self.created_at)?;
        w.u64_field(0x05, self.reemit_first)?;
        w.u64_field(0x06, self.reemit_count)?;
        if let Some(tag) = &self.recovery_tag {
            w.field(0x07, tag)?;
        }
        let body = w.finish();
        let sealed = aead::seal(key, &gen_info_aad(vault_id, gen_id, parent), &body)?;
        let mut out = prefix(FileType::GenInfo).to_vec();
        match parent {
            Some(p) => {
                out.push(1);
                out.extend_from_slice(&p.bytes());
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; 20]);
            }
        }
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Returns the parent named in the (authenticated) plaintext prefix, before decryption.
    pub(crate) fn parent_of(data: &[u8]) -> Result<Option<GenId>, VaultError> {
        let mut r = Reader::new(strip_prefix(data, FileType::GenInfo)?);
        let has_parent = r.u8()?;
        let parent = r.array::<20>()?;
        match has_parent {
            0 if parent == [0u8; 20] => Ok(None),
            1 => Ok(Some(GenId::from_bytes(&parent)?)),
            _ => Err(VaultError::Corrupt("gen.info parent")),
        }
    }

    pub(crate) fn open(
        data: &[u8],
        key: &[u8; 32],
        vault_id: &[u8; 16],
        gen_id: &GenId,
    ) -> Result<GenInfo, VaultError> {
        let parent = GenInfo::parent_of(data)?;
        let mut r = Reader::new(strip_prefix(data, FileType::GenInfo)?);
        r.take(21)?;
        let body = aead::open(
            key,
            &gen_info_aad(vault_id, gen_id, parent.as_ref()),
            r.rest(),
        )
        .map_err(|_| VaultError::Corrupt("gen.info authentication"))?;
        let mut f = Fields::new(&body, 1)?;
        let mut commitment = None;
        let mut recovery_pub = None;
        let mut removed = None;
        let mut created_at = None;
        let mut reemit_first = None;
        let mut reemit_count = None;
        let mut recovery_tag = None;
        while let Some((tag, v)) = f.next_field()? {
            match tag {
                0x01 => commitment = Some(codec::fixed::<32>(v)?),
                0x02 => recovery_pub = Some(codec::fixed::<32>(v)?),
                0x03 => {
                    if v.len() % 16 != 0 || v.len() / 16 > MAX_REMOVED {
                        return Err(VaultError::Corrupt("removed list"));
                    }
                    let mut list = Vec::new();
                    for c in v.as_chunks::<16>().0 {
                        list.push(codec::fixed::<16>(c)?);
                    }
                    removed = Some(list);
                }
                0x04 => created_at = Some(codec::u64_value(v)?),
                0x05 => reemit_first = Some(codec::u64_value(v)?),
                0x06 => reemit_count = Some(codec::u64_value(v)?),
                0x07 => recovery_tag = Some(codec::fixed::<32>(v)?),
                t if t >= 0x40 => {}
                _ => return Err(VaultError::Corrupt("gen.info field")),
            }
        }
        let missing = VaultError::Corrupt("gen.info missing field");
        Ok(GenInfo {
            commitment: commitment.ok_or(missing.clone())?,
            recovery_pub: recovery_pub.ok_or(missing.clone())?,
            removed: removed.ok_or(missing.clone())?,
            created_at: created_at.ok_or(missing.clone())?,
            reemit_first: reemit_first.ok_or(missing.clone())?,
            reemit_count: reemit_count.ok_or(missing)?,
            recovery_tag,
        })
    }
}

fn device_slot_aad(vault_id: &[u8; 16], gen_id: &GenId, device: &DeviceId) -> Vec<u8> {
    aad(
        "hirz device slot v1",
        &[&[FORMAT_VERSION], vault_id, &gen_id.bytes(), device],
    )
}

fn recovery_slot_aad(vault_id: &[u8; 16], gen_id: &GenId) -> Vec<u8> {
    aad(
        "hirz recovery slot v1",
        &[&[FORMAT_VERSION], vault_id, &gen_id.bytes()],
    )
}

fn seal_slot(
    t: FileType,
    recipient: &[u8; 32],
    aad: &[u8],
    key: &[u8; 32],
) -> Result<Vec<u8>, VaultError> {
    let sealed = x25519::seal_to(recipient, aad, key)?;
    let mut out = prefix(t).to_vec();
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn open_slot(
    t: FileType,
    data: &[u8],
    private: &[u8; 32],
    aad: &[u8],
) -> Result<VaultKey, VaultError> {
    let body = strip_prefix(data, t)?;
    let key = x25519::open_from(private, aad, body)
        .map_err(|_| VaultError::Corrupt("slot authentication"))?;
    let arr: [u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::Corrupt("slot key length"))?;
    Ok(Zeroizing::new(arr))
}

pub(crate) fn seal_device_slot(
    vault_id: &[u8; 16],
    gen_id: &GenId,
    device: &DeviceId,
    device_pub: &[u8; 32],
    key: &[u8; 32],
) -> Result<Vec<u8>, VaultError> {
    seal_slot(
        FileType::DeviceSlot,
        device_pub,
        &device_slot_aad(vault_id, gen_id, device),
        key,
    )
}

pub(crate) fn open_device_slot(
    data: &[u8],
    vault_id: &[u8; 16],
    gen_id: &GenId,
    device: &DeviceId,
    private: &[u8; 32],
) -> Result<VaultKey, VaultError> {
    open_slot(
        FileType::DeviceSlot,
        data,
        private,
        &device_slot_aad(vault_id, gen_id, device),
    )
}

pub(crate) fn seal_recovery_slot(
    vault_id: &[u8; 16],
    gen_id: &GenId,
    recovery_pub: &[u8; 32],
    key: &[u8; 32],
) -> Result<Vec<u8>, VaultError> {
    seal_slot(
        FileType::RecoverySlot,
        recovery_pub,
        &recovery_slot_aad(vault_id, gen_id),
        key,
    )
}

pub(crate) fn open_recovery_slot(
    data: &[u8],
    vault_id: &[u8; 16],
    gen_id: &GenId,
    private: &[u8; 32],
) -> Result<VaultKey, VaultError> {
    open_slot(
        FileType::RecoverySlot,
        data,
        private,
        &recovery_slot_aad(vault_id, gen_id),
    )
}

fn record_key(
    key: &[u8; 32],
    vault_id: &[u8; 16],
    gen_id: &GenId,
    rel_path: &str,
) -> Result<VaultKey, VaultError> {
    let mut out = Zeroizing::new([0u8; 32]);
    hirz_crypto::hkdf_sha256(
        vault_id,
        key,
        &aad(
            "hirz record key v1",
            &[&gen_id.bytes(), rel_path.as_bytes()],
        ),
        out.as_mut_slice(),
    )?;
    Ok(out)
}

fn record_aad(vault_id: &[u8; 16], gen_id: &GenId, rel_path: &str) -> Vec<u8> {
    aad(
        "hirz record v1",
        &[
            &[FORMAT_VERSION],
            vault_id,
            &gen_id.bytes(),
            rel_path.as_bytes(),
        ],
    )
}

pub(crate) fn seal_record(
    key: &[u8; 32],
    vault_id: &[u8; 16],
    gen_id: &GenId,
    rel_path: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let k = record_key(key, vault_id, gen_id, rel_path)?;
    let sealed = aead::seal(&k, &record_aad(vault_id, gen_id, rel_path), plaintext)?;
    let mut out = prefix(FileType::Record).to_vec();
    out.extend_from_slice(&gen_id.bytes());
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// The generation a record file claims to be encrypted under (authenticated on open).
pub(crate) fn record_gen(data: &[u8]) -> Result<GenId, VaultError> {
    let mut r = Reader::new(strip_prefix(data, FileType::Record)?);
    GenId::from_bytes(r.take(20)?)
}

pub(crate) fn open_record(
    data: &[u8],
    key: &[u8; 32],
    vault_id: &[u8; 16],
    gen_id: &GenId,
    rel_path: &str,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let mut r = Reader::new(strip_prefix(data, FileType::Record)?);
    r.take(20)?;
    let k = record_key(key, vault_id, gen_id, rel_path)?;
    aead::open(&k, &record_aad(vault_id, gen_id, rel_path), r.rest())
        .map_err(|_| VaultError::Corrupt("record authentication"))
}

pub(crate) fn author_tag(
    device_secret: &[u8; 32],
    vault_id: &[u8; 16],
    rel_path: &str,
    body: &[u8],
) -> [u8; 32] {
    hirz_crypto::hmac_sha256(
        device_secret,
        &aad("hirz author v1", &[vault_id, rel_path.as_bytes(), body]),
    )
}

#[derive(Clone)]
pub(crate) struct LocalDevice {
    pub(crate) vault_id: [u8; 16],
    pub(crate) device_id: DeviceId,
    pub(crate) secret: VaultKey,
    pub(crate) x25519_private: VaultKey,
    pub(crate) name: String,
}

impl core::fmt::Debug for LocalDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LocalDevice")
            .field("device_id", &hex(&self.device_id))
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl LocalDevice {
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let mut w = Writer::new(1);
        w.field(0x01, &self.vault_id)?;
        w.field(0x02, &self.device_id)?;
        w.field(0x03, self.secret.as_slice())?;
        w.field(0x04, self.x25519_private.as_slice())?;
        w.field(0x05, self.name.as_bytes())?;
        let body = w.finish();
        let mut out = Zeroizing::new(Vec::with_capacity(body.len().saturating_add(6)));
        out.extend_from_slice(&prefix(FileType::LocalDevice));
        out.extend_from_slice(&body);
        Ok(out)
    }

    pub(crate) fn decode(data: &[u8]) -> Result<LocalDevice, VaultError> {
        let mut f = Fields::new(strip_prefix(data, FileType::LocalDevice)?, 1)?;
        let mut get = |tag: u8| -> Result<&[u8], VaultError> {
            match f.next_field()? {
                Some((t, v)) if t == tag => Ok(v),
                _ => Err(VaultError::Corrupt("device state")),
            }
        };
        let vault_id = codec::fixed::<16>(get(0x01)?)?;
        let device_id = codec::fixed::<16>(get(0x02)?)?;
        let secret = Zeroizing::new(codec::fixed::<32>(get(0x03)?)?);
        let x25519_private = Zeroizing::new(codec::fixed::<32>(get(0x04)?)?);
        let name = codec::string_value(get(0x05)?, crate::record::MAX_DEVICE_NAME_LEN)?;
        Ok(LocalDevice {
            vault_id,
            device_id,
            secret,
            x25519_private,
            name,
        })
    }
}

#[derive(Clone)]
pub(crate) struct KeyringEntry {
    pub(crate) gen_id: GenId,
    pub(crate) key: VaultKey,
    pub(crate) root: bool,
}

impl core::fmt::Debug for KeyringEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyringEntry")
            .field("gen_id", &self.gen_id)
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

const KEYRING_ENTRY_LEN: usize = 53;

#[derive(Debug, Clone)]
pub(crate) struct Keyring {
    pub(crate) recovery_pub: [u8; 32],
    pub(crate) entries: Vec<KeyringEntry>,
}

fn keyring_aad(vault_id: &[u8; 16], device: &DeviceId) -> Vec<u8> {
    aad("hirz keyring v1", &[&[FORMAT_VERSION], vault_id, device])
}

impl Keyring {
    pub(crate) fn get(&self, gen_id: &GenId) -> Option<&KeyringEntry> {
        self.entries.iter().find(|e| e.gen_id == *gen_id)
    }

    pub(crate) fn seal(&self, dev: &LocalDevice) -> Result<Vec<u8>, VaultError> {
        let mut entries = Zeroizing::new(Vec::with_capacity(
            self.entries.len().saturating_mul(KEYRING_ENTRY_LEN),
        ));
        for e in &self.entries {
            entries.extend_from_slice(&e.gen_id.bytes());
            entries.extend_from_slice(e.key.as_slice());
            entries.push(u8::from(e.root));
        }
        let mut w = Writer::new(1);
        w.field(0x01, &self.recovery_pub)?;
        w.field(0x02, &entries)?;
        let body = w.finish();
        let sealed = aead::seal(
            &dev.secret,
            &keyring_aad(&dev.vault_id, &dev.device_id),
            &body,
        )?;
        let mut out = prefix(FileType::LocalKeyring).to_vec();
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    pub(crate) fn open(data: &[u8], dev: &LocalDevice) -> Result<Keyring, VaultError> {
        let body = aead::open(
            &dev.secret,
            &keyring_aad(&dev.vault_id, &dev.device_id),
            strip_prefix(data, FileType::LocalKeyring)?,
        )
        .map_err(|_| VaultError::Corrupt("keyring authentication"))?;
        let mut f = Fields::new(&body, 1)?;
        let recovery_pub = match f.next_field()? {
            Some((0x01, v)) => codec::fixed::<32>(v)?,
            _ => return Err(VaultError::Corrupt("keyring")),
        };
        let raw = match f.next_field()? {
            Some((0x02, v)) => v,
            _ => return Err(VaultError::Corrupt("keyring")),
        };
        if raw.len() % KEYRING_ENTRY_LEN != 0 {
            return Err(VaultError::Corrupt("keyring entries"));
        }
        let mut entries = Vec::new();
        for chunk in raw.as_chunks::<KEYRING_ENTRY_LEN>().0 {
            let mut r = Reader::new(chunk);
            let gen_id = GenId::from_bytes(r.take(20)?)?;
            let key = Zeroizing::new(r.array::<32>()?);
            let root = match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(VaultError::Corrupt("keyring root flag")),
            };
            entries.push(KeyringEntry { gen_id, key, root });
        }
        Ok(Keyring {
            recovery_pub,
            entries,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Counter {
    pub(crate) next: u64,
    pub(crate) max_seen: u64,
}

impl Counter {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = prefix(FileType::LocalCounter).to_vec();
        out.extend_from_slice(&self.next.to_be_bytes());
        out.extend_from_slice(&self.max_seen.to_be_bytes());
        out
    }

    pub(crate) fn decode(data: &[u8]) -> Result<Counter, VaultError> {
        let mut r = Reader::new(strip_prefix(data, FileType::LocalCounter)?);
        let next = r.u64()?;
        let max_seen = r.u64()?;
        r.finish()?;
        Ok(Counter { next, max_seen })
    }
}
