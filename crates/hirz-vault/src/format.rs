//! Byte layouts of every vault and local state file. See docs/vault-format.md.

use crate::DeviceId;
use crate::codec::{self, Fields, Reader, Writer, aad, hex, unhex};
use crate::error::VaultError;
use crate::record::{DeviceAnnouncement, EventId, device_id_for};
use hirz_crypto::Zeroizing;
use hirz_crypto::{aead, x25519};
use std::collections::BTreeMap;

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
pub(crate) const STATE_LINE: &str = "line";

/// Cap on key generations a device keeps and a pairing approval carries.
pub(crate) const MAX_GENERATIONS: usize = 10_000;

pub(crate) type VaultKey = Zeroizing<[u8; 32]>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum FileType {
    Header = 1,
    Record = 2,
    GenInfo = 3,
    DeviceSlot = 4,
    RecoverySlot = 5,
    PairingRequest = 7,
    PairingApproval = 8,
    LocalDevice = 0x10,
    LocalKeyring = 0x11,
    LocalCounter = 0x12,
    LocalLine = 0x13,
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

    /// The directory name under `keys/`, as `ScanReport::rejected` entries are shown to users.
    pub fn dir_name(&self) -> String {
        format!("{:010}-{}", self.number, hex(&self.rotator))
    }

    pub fn parse_dir(name: &str) -> Option<GenId> {
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
    recovery_signing_pub: &[u8; 32],
) -> [u8; 32] {
    hirz_crypto::hmac_sha256(
        auth_key,
        &aad(
            "hirz genesis v2",
            &[
                vault_id,
                &gen_id.bytes(),
                commitment,
                recovery_pub,
                recovery_signing_pub,
            ],
        ),
    )
}

/// A device that holds a slot in a generation, as listed and signed by its rotator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Member {
    pub(crate) device_id: DeviceId,
    pub(crate) signing_public: [u8; 32],
    pub(crate) x25519_public: [u8; 32],
}

const MEMBER_LEN: usize = 80;
pub(crate) const MAX_MEMBERS: usize = 512;
/// Announcements that prove a rotator's membership when the parent does not list it.
pub(crate) const MAX_ENDORSEMENT_CHAIN: usize = 32;

/// A device removal and why (docs/vault-format.md, 4.1 and 9.5): the `device removed` event
/// that caused it, and the cutoff, every event of the removed device that the remover held when
/// it removed it. Events of a removed device count only when every cutoff holds them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Removal {
    pub(crate) device: DeviceId,
    pub(crate) cause_author: DeviceId,
    pub(crate) cause: EventId,
    /// Sorted, without duplicates.
    pub(crate) cutoff: Vec<EventId>,
}

/// Identifies one removal decision; copies made when other devices apply it keep it.
pub(crate) type RemovalKey = (DeviceId, DeviceId, EventId);

impl Removal {
    pub(crate) fn key(&self) -> RemovalKey {
        (self.device, self.cause_author, self.cause)
    }
}

/// Removal entries and cutoff ids one file may hold.
pub(crate) const MAX_REMOVALS: usize = 1024;
pub(crate) const MAX_CUTOFF_IDS: usize = 50_000;
const REMOVAL_CHUNK_TAGS: core::ops::RangeInclusive<u8> = 0x20..=0x3f;

pub(crate) fn encode_removals(list: &[Removal]) -> Result<Vec<u8>, VaultError> {
    let ids: usize = list.iter().map(|r| r.cutoff.len()).sum();
    if list.len() > MAX_REMOVALS || ids > MAX_CUTOFF_IDS {
        return Err(VaultError::Encode);
    }
    let mut out = Vec::new();
    out.extend_from_slice(
        &u32::try_from(list.len())
            .map_err(|_| VaultError::Encode)?
            .to_be_bytes(),
    );
    for r in list {
        if !r.cutoff.windows(2).all(|w| matches!(w, [a, b] if a < b)) {
            return Err(VaultError::Encode);
        }
        out.extend_from_slice(&r.device);
        out.extend_from_slice(&r.cause_author);
        out.extend_from_slice(&r.cause);
        out.extend_from_slice(
            &u32::try_from(r.cutoff.len())
                .map_err(|_| VaultError::Encode)?
                .to_be_bytes(),
        );
        for id in &r.cutoff {
            out.extend_from_slice(id);
        }
    }
    Ok(out)
}

pub(crate) fn decode_removals(data: &[u8]) -> Result<Vec<Removal>, VaultError> {
    let bad = || VaultError::Corrupt("removal list");
    let mut r = Reader::new(data);
    let n = usize::try_from(r.u32()?).map_err(|_| bad())?;
    if n > MAX_REMOVALS {
        return Err(bad());
    }
    let mut out = Vec::new();
    let mut total = 0usize;
    for _ in 0..n {
        let device = r.array::<16>()?;
        let cause_author = r.array::<16>()?;
        let cause = r.array::<16>()?;
        let m = usize::try_from(r.u32()?).map_err(|_| bad())?;
        total = total.saturating_add(m);
        if total > MAX_CUTOFF_IDS || r.rest().len() < m.saturating_mul(16) {
            return Err(bad());
        }
        let mut cutoff: Vec<EventId> = Vec::with_capacity(m);
        for _ in 0..m {
            let id = r.array::<16>()?;
            if cutoff.last().is_some_and(|l| *l >= id) {
                return Err(bad());
            }
            cutoff.push(id);
        }
        out.push(Removal {
            device,
            cause_author,
            cause,
            cutoff,
        });
    }
    r.finish()?;
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GenInfo {
    pub(crate) commitment: [u8; 32],
    pub(crate) recovery_pub: [u8; 32],
    pub(crate) removed: Vec<Removal>,
    /// Informational only: chosen by the rotator, never used for timing decisions.
    pub(crate) created_at: u64,
    pub(crate) reemit_first: u64,
    pub(crate) reemit_count: u64,
    pub(crate) recovery_tag: Option<[u8; 32]>,
    pub(crate) recovery_signing_pub: [u8; 32],
    /// Sorted by device id; includes the rotator.
    pub(crate) members: Vec<Member>,
    pub(crate) chain: Vec<DeviceAnnouncement>,
}

const GEN_INFO_VERSION: u8 = 3;

fn gen_info_aad(vault_id: &[u8; 16], gen_id: &GenId, parent: Option<&GenId>) -> Vec<u8> {
    let parent_bytes = parent.map(GenId::bytes).unwrap_or([0u8; 20]);
    aad(
        "hirz gen info v1",
        &[&[FORMAT_VERSION], vault_id, &gen_id.bytes(), &parent_bytes],
    )
}

fn gen_info_signed_message(
    vault_id: &[u8; 16],
    gen_id: &GenId,
    parent: Option<&GenId>,
    body: &[u8],
) -> Vec<u8> {
    let parent_bytes = parent.map(GenId::bytes).unwrap_or([0u8; 20]);
    aad(
        "hirz gen info signature v1",
        &[vault_id, &gen_id.bytes(), &parent_bytes, body],
    )
}

impl GenInfo {
    pub(crate) fn member(&self, id: &DeviceId) -> Option<&Member> {
        self.members.iter().find(|m| m.device_id == *id)
    }
}

impl GenInfo {
    /// Sealed under the parent generation's key, or under its own key for the genesis, and
    /// signed inside the ciphertext by the rotator (`signer_seed`).
    pub(crate) fn seal(
        &self,
        key: &[u8; 32],
        vault_id: &[u8; 16],
        gen_id: &GenId,
        parent: Option<&GenId>,
        signer_seed: &[u8; 32],
    ) -> Result<Vec<u8>, VaultError> {
        if self.members.len() > MAX_MEMBERS
            || self.chain.len() > MAX_ENDORSEMENT_CHAIN
            || !self
                .members
                .windows(2)
                .all(|w| matches!(w, [a, b] if a.device_id < b.device_id))
        {
            return Err(VaultError::Encode);
        }
        let mut w = Writer::new(GEN_INFO_VERSION);
        w.field(0x01, &self.commitment)?;
        w.field(0x02, &self.recovery_pub)?;
        w.u64_field(0x04, self.created_at)?;
        w.u64_field(0x05, self.reemit_first)?;
        w.u64_field(0x06, self.reemit_count)?;
        if let Some(tag) = &self.recovery_tag {
            w.field(0x07, tag)?;
        }
        w.field(0x08, &self.recovery_signing_pub)?;
        let mut members = Vec::with_capacity(self.members.len().saturating_mul(MEMBER_LEN));
        for m in &self.members {
            members.extend_from_slice(&m.device_id);
            members.extend_from_slice(&m.signing_public);
            members.extend_from_slice(&m.x25519_public);
        }
        w.field(0x09, &members)?;
        if !self.chain.is_empty() {
            let mut chain = Vec::new();
            for a in &self.chain {
                let enc = a.encode()?;
                let len = u16::try_from(enc.len()).map_err(|_| VaultError::Encode)?;
                chain.extend_from_slice(&len.to_be_bytes());
                chain.extend_from_slice(&enc);
            }
            w.field(0x0a, &chain)?;
        }
        if !self.removed.is_empty() {
            let blob = encode_removals(&self.removed)?;
            let mut tags = REMOVAL_CHUNK_TAGS;
            for chunk in blob.chunks(usize::from(u16::MAX)) {
                w.field(tags.next().ok_or(VaultError::Encode)?, chunk)?;
            }
        }
        let mut body = w.finish();
        let sig = hirz_crypto::ed25519::sign_with_seed(
            signer_seed,
            &gen_info_signed_message(vault_id, gen_id, parent, &body),
        )?;
        body.push(0x7f);
        body.extend_from_slice(&64u16.to_be_bytes());
        body.extend_from_slice(&sig);
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
        GenInfo::open_hashed(data, key, vault_id, gen_id).map(|(info, _)| info)
    }

    /// Also returns SHA-256 of the authenticated plaintext (signed body and signature), which
    /// stays the same when a key holder re-encrypts the same body under a new nonce.
    pub(crate) fn open_hashed(
        data: &[u8],
        key: &[u8; 32],
        vault_id: &[u8; 16],
        gen_id: &GenId,
    ) -> Result<(GenInfo, [u8; 32]), VaultError> {
        let parent = GenInfo::parent_of(data)?;
        let mut r = Reader::new(strip_prefix(data, FileType::GenInfo)?);
        r.take(21)?;
        let body = aead::open(
            key,
            &gen_info_aad(vault_id, gen_id, parent.as_ref()),
            r.rest(),
        )
        .map_err(|_| VaultError::Corrupt("gen.info authentication"))?;
        let mut f = Fields::new(&body, GEN_INFO_VERSION)?;
        let mut commitment = None;
        let mut recovery_pub = None;
        let mut removed_blob: Vec<u8> = Vec::new();
        let mut created_at = None;
        let mut reemit_first = None;
        let mut reemit_count = None;
        let mut recovery_tag = None;
        let mut recovery_signing_pub = None;
        let mut members = None;
        let mut chain = Vec::new();
        let mut signature = None;
        loop {
            let before = f.remaining();
            let Some((tag, v)) = f.next_field()? else {
                break;
            };
            match tag {
                0x01 => commitment = Some(codec::fixed::<32>(v)?),
                0x02 => recovery_pub = Some(codec::fixed::<32>(v)?),
                0x04 => created_at = Some(codec::u64_value(v)?),
                0x05 => reemit_first = Some(codec::u64_value(v)?),
                0x06 => reemit_count = Some(codec::u64_value(v)?),
                0x07 => recovery_tag = Some(codec::fixed::<32>(v)?),
                0x08 => recovery_signing_pub = Some(codec::fixed::<32>(v)?),
                0x09 => members = Some(decode_members(v)?),
                0x0a => chain = decode_chain(v)?,
                t if REMOVAL_CHUNK_TAGS.contains(&t) => removed_blob.extend_from_slice(v),
                0x7f => {
                    let sig = codec::fixed::<64>(v)?;
                    if f.remaining() != 0 {
                        return Err(VaultError::Corrupt("data after gen.info signature"));
                    }
                    let signed = body
                        .get(..body.len().saturating_sub(before))
                        .ok_or(VaultError::Corrupt("gen.info signature"))?;
                    signature = Some((sig, signed.to_vec()));
                }
                t if t >= 0x40 => {}
                _ => return Err(VaultError::Corrupt("gen.info field")),
            }
        }
        let missing = VaultError::Corrupt("gen.info missing field");
        let info = GenInfo {
            commitment: commitment.ok_or(missing.clone())?,
            recovery_pub: recovery_pub.ok_or(missing.clone())?,
            removed: if removed_blob.is_empty() {
                Vec::new()
            } else {
                decode_removals(&removed_blob)?
            },
            created_at: created_at.ok_or(missing.clone())?,
            reemit_first: reemit_first.ok_or(missing.clone())?,
            reemit_count: reemit_count.ok_or(missing.clone())?,
            recovery_tag,
            recovery_signing_pub: recovery_signing_pub.ok_or(missing.clone())?,
            members: members.ok_or(missing.clone())?,
            chain,
        };
        let (sig, signed) = signature.ok_or(missing)?;
        let rotator = info
            .member(&gen_id.rotator)
            .ok_or(VaultError::Corrupt("gen.info rotator is not a member"))?;
        hirz_crypto::ed25519::verify(
            &rotator.signing_public,
            &gen_info_signed_message(vault_id, gen_id, parent.as_ref(), &signed),
            &sig,
        )
        .map_err(|_| VaultError::Corrupt("gen.info signature"))?;
        let hash = hirz_crypto::sha256(&body);
        Ok((info, hash))
    }
}

fn decode_members(v: &[u8]) -> Result<Vec<Member>, VaultError> {
    if !v.len().is_multiple_of(MEMBER_LEN) || v.len() / MEMBER_LEN > MAX_MEMBERS {
        return Err(VaultError::Corrupt("member list"));
    }
    let mut out: Vec<Member> = Vec::new();
    for c in v.as_chunks::<MEMBER_LEN>().0 {
        let mut r = Reader::new(c);
        let m = Member {
            device_id: r.array::<16>()?,
            signing_public: r.array::<32>()?,
            x25519_public: r.array::<32>()?,
        };
        if device_id_for(&m.signing_public) != m.device_id
            || out.last().is_some_and(|p| p.device_id >= m.device_id)
        {
            return Err(VaultError::Corrupt("member list"));
        }
        out.push(m);
    }
    Ok(out)
}

fn decode_chain(v: &[u8]) -> Result<Vec<DeviceAnnouncement>, VaultError> {
    let mut r = Reader::new(v);
    let mut out = Vec::new();
    while !r.rest().is_empty() {
        if out.len() >= MAX_ENDORSEMENT_CHAIN {
            return Err(VaultError::Corrupt("endorsement chain"));
        }
        let len = usize::from(r.u16()?);
        out.push(DeviceAnnouncement::decode(r.take(len)?)?);
    }
    Ok(out)
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
    /// Ed25519 seed; the device id is derived from its public key.
    pub(crate) signing_seed: VaultKey,
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
        w.field(0x06, self.signing_seed.as_slice())?;
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
        let signing_seed = Zeroizing::new(codec::fixed::<32>(get(0x06)?)?);
        if f.next_field()?.is_some() {
            return Err(VaultError::Corrupt("device state"));
        }
        let dev = LocalDevice {
            vault_id,
            device_id,
            secret,
            x25519_private,
            name,
            signing_seed,
        };
        if device_id_for(&dev.signing_public()?) != dev.device_id {
            return Err(VaultError::Corrupt(
                "device id does not match its signing key",
            ));
        }
        Ok(dev)
    }

    pub(crate) fn signing_public(&self) -> Result<[u8; 32], VaultError> {
        Ok(hirz_crypto::ed25519::public_from_seed(&self.signing_seed)?)
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
const KEYRING_VERSION: u8 = 2;

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
        if self.entries.len() > MAX_GENERATIONS {
            return Err(VaultError::Encode);
        }
        let count = u32::try_from(self.entries.len()).map_err(|_| VaultError::Encode)?;
        let mut body = Zeroizing::new(Vec::with_capacity(
            self.entries
                .len()
                .saturating_mul(KEYRING_ENTRY_LEN)
                .saturating_add(37),
        ));
        body.push(KEYRING_VERSION);
        body.extend_from_slice(&self.recovery_pub);
        body.extend_from_slice(&count.to_be_bytes());
        for e in &self.entries {
            body.extend_from_slice(&e.gen_id.bytes());
            body.extend_from_slice(e.key.as_slice());
            body.push(u8::from(e.root));
        }
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
        let mut r = Reader::new(&body);
        if r.u8()? != KEYRING_VERSION {
            return Err(VaultError::UnsupportedVersion);
        }
        let recovery_pub = r.array::<32>()?;
        let count = usize::try_from(r.u32()?).map_err(|_| VaultError::Corrupt("keyring"))?;
        let raw = r.rest();
        if count > MAX_GENERATIONS || raw.len() != count.saturating_mul(KEYRING_ENTRY_LEN) {
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

/// One generation of the line this device follows (docs/vault-format.md, 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LineEntry {
    pub(crate) gen_id: GenId,
    pub(crate) info_hash: [u8; 32],
    /// Local time at which this device first made the generation current.
    pub(crate) first_seen: u64,
}

const LINE_ENTRY_LEN: usize = 60;
const LINE_VERSION: u8 = 3;

/// Genesis first, the generation this device currently follows last, plus every device a
/// generation of the line ever removed. The removed set outlives the entries: it is kept when the
/// device moves to another branch or accepts a fork (docs/vault-format.md, 7 and 9.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Line {
    pub(crate) entries: Vec<LineEntry>,
    /// Keyed by `Removal::key`.
    pub(crate) removed: BTreeMap<RemovalKey, Removal>,
}

impl Line {
    pub(crate) fn pin(&self) -> Option<&LineEntry> {
        self.entries.last()
    }

    pub(crate) fn get(&self, id: &GenId) -> Option<&LineEntry> {
        self.entries.iter().find(|e| e.gen_id == *id)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, VaultError> {
        if self.entries.len() > MAX_GENERATIONS {
            return Err(VaultError::Encode);
        }
        let count = u32::try_from(self.entries.len()).map_err(|_| VaultError::Encode)?;
        let list: Vec<Removal> = self.removed.values().cloned().collect();
        let removed = encode_removals(&list)?;
        let mut out = prefix(FileType::LocalLine).to_vec();
        out.push(LINE_VERSION);
        out.extend_from_slice(&count.to_be_bytes());
        for e in &self.entries {
            out.extend_from_slice(&e.gen_id.bytes());
            out.extend_from_slice(&e.info_hash);
            out.extend_from_slice(&e.first_seen.to_be_bytes());
        }
        out.extend_from_slice(&removed);
        Ok(out)
    }

    pub(crate) fn decode(data: &[u8]) -> Result<Line, VaultError> {
        let mut r = Reader::new(strip_prefix(data, FileType::LocalLine)?);
        if r.u8()? != LINE_VERSION {
            return Err(VaultError::UnsupportedVersion);
        }
        let count = usize::try_from(r.u32()?).map_err(|_| VaultError::Corrupt("line"))?;
        if count > MAX_GENERATIONS || r.rest().len() < count.saturating_mul(LINE_ENTRY_LEN) {
            return Err(VaultError::Corrupt("line"));
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(LineEntry {
                gen_id: GenId::from_bytes(r.take(20)?)?,
                info_hash: r.array::<32>()?,
                first_seen: r.u64()?,
            });
        }
        let removed = decode_removals(r.rest())?
            .into_iter()
            .map(|x| (x.key(), x))
            .collect();
        Ok(Line { entries, removed })
    }
}
