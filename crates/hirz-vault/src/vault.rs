//! Vault operations: key generations, scanning, merging, writing, rotation.

use crate::DeviceId;
use crate::codec::hex;
use crate::error::VaultError;
use crate::format::{
    self, Counter, GEN_INFO_NAME, GenId, GenInfo, HEADER_NAME, Header, KEYS_DIR, Keyring,
    KeyringEntry, Line, LineEntry, LocalDevice, MAX_ENDORSEMENT_CHAIN, MAX_GENERATIONS, Member,
    RECORDS_DIR, RECOVERY_SLOT_NAME, RecordName, Removal, RemovalKey, STATE_COUNTER, STATE_DEVICE,
    STATE_KEYRING, STATE_LINE, VaultKey,
};
use crate::fsutil::{self, MAX_FILE_LEN, StateLock};
use crate::pairing::{self, PairingRequest};
use crate::record::{
    CredentialRecord, DeviceAnnouncement, Event, EventId, EventKind, MAX_DEVICE_NAME_LEN,
    RECOVERY_ENDORSER, append_tag, device_id_for,
};
use crate::recovery::RecoveryPhrase;
use hirz_crypto::Zeroizing;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const GC_GRACE_SECS: u64 = 24 * 60 * 60;

/// Counters more than this far above the highest one this device accepted are ignored, so one
/// event numbered near `u64::MAX` cannot exhaust the counter space (docs/vault-format.md, 6.1).
pub(crate) const COUNTER_WINDOW: u64 = 1 << 32;

pub(crate) use hirz_proto::time::unix_now as now;

pub(crate) fn random16() -> Result<[u8; 16], VaultError> {
    let mut out = [0u8; 16];
    hirz_crypto::random_fill(&mut out)?;
    Ok(out)
}

fn random_key() -> Result<VaultKey, VaultError> {
    let mut out = Zeroizing::new([0u8; 32]);
    hirz_crypto::random_fill(out.as_mut_slice())?;
    Ok(out)
}

fn to_key(secret: &[u8]) -> Result<VaultKey, VaultError> {
    let arr: [u8; 32] = secret.try_into().map_err(|_| VaultError::Crypto)?;
    Ok(Zeroizing::new(arr))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedFile {
    pub path: String,
    pub reason: &'static str,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanReport {
    pub generation: u32,
    pub credentials: usize,
    pub events: usize,
    /// Temp files, sync-tool conflict copies and unknown names; ignored.
    pub ignored_files: usize,
    /// Valid name but corrupt, failing authentication, a symlink, or numbered out of range; ignored.
    pub skipped: Vec<SkippedFile>,
    pub other_generation_files: usize,
    pub rejected_generations: usize,
    /// Key generations this device does not follow: lost a conflict, or rest on a device this
    /// device's line removed. Candidates for `Vault::discard_generation`. Generations that are
    /// not followed only because a device this line removed still holds a slot in them (made by a
    /// device that has not seen the removal yet) are not listed: they settle by themselves.
    pub rejected: Vec<GenId>,
    /// Rotations removed each other's creators and nothing settles it. Content writes and
    /// automatic maintenance stop until the user removes the untrusted device again.
    pub rotation_conflict: bool,
    /// A key generation this device already followed is missing or was rewritten in the folder.
    /// Content writes and automatic maintenance stop; existing passkeys stay readable.
    pub fork_detected: bool,
    /// A newer key generation descending from the current one exists that this device holds no
    /// key for.
    pub locked_out: bool,
    /// The generation this device follows, or a newer generation built on it that this device
    /// holds no key for, removes it; an honest frontend stops using the vault. Generations that
    /// rest on a device this device's line removed are void and never set it.
    pub this_device_removed: bool,
    /// The highest event counter in the folder is lower than one seen before, or files of the
    /// current generation are missing: files were withheld or rolled back.
    pub rollback_suspected: bool,
    pub migrated: usize,
    pub rotated: bool,
    pub collected: usize,
    /// Maintenance writes failed (for example a read-only folder); reading still worked.
    pub maintenance_error: Option<VaultError>,
}

impl ScanReport {
    fn skip(&mut self, path: String, reason: &'static str) {
        self.skipped.push(SkippedFile { path, reason });
    }

    fn ignore(&mut self) {
        self.ignored_files = self.ignored_files.saturating_add(1);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub id: DeviceId,
    pub name: String,
    pub added_at: u64,
    pub removed: bool,
    pub this_device: bool,
    /// The device that approved this one; `None` when it was added with the recovery phrase
    /// (including the device that created the vault).
    pub added_by: Option<DeviceId>,
}

#[derive(Debug)]
struct GenNode {
    id: GenId,
    key: Option<VaultKey>,
    parent: Option<GenId>,
    info: GenInfo,
    removed_cum: BTreeSet<DeviceId>,
    /// The rotator and the devices its membership in the parent generation rests on.
    path: BTreeSet<DeviceId>,
    info_hash: [u8; 32],
}

enum Opener<'a> {
    Device {
        dev: &'a LocalDevice,
        keyring: &'a Keyring,
    },
    Recovery {
        private: &'a [u8; 32],
        auth: &'a [u8; 32],
        public: [u8; 32],
        signing_public: [u8; 32],
    },
}

#[derive(Debug, Clone)]
struct Loaded {
    rel: String,
    writer: DeviceId,
    name: RecordName,
    gen_id: GenId,
    event: Event,
    /// The author tag verifies with this device's secret.
    own: bool,
    /// Opened with a key this device held for `gen_id` before the generation was rewritten
    /// under a new key (docs/vault-format.md, 9.4): never part of the current view.
    retired: bool,
    id: EventId,
}

/// The key of each generation records may be under, and keys this device held for a generation
/// before it was rewritten under a new key.
struct GenKeys {
    keys: BTreeMap<GenId, VaultKey>,
    retired: BTreeMap<GenId, VaultKey>,
}

/// Events whose signature already verified, as (id, signature).
type VerifyCache = BTreeSet<(EventId, [u8; 64])>;
const MAX_VERIFY_CACHE: usize = 100_000;

/// Merge order: origin counter, origin device, tombstone over put, then file path, so even exact
/// duplicates resolve deterministically.
type OrderKey = (u64, DeviceId, u8, String);

fn order_key(event: &Event, rel: &str) -> OrderKey {
    let rank = u8::from(matches!(event.kind, EventKind::Tombstone(_)));
    (
        event.origin_lamport,
        event.origin_author,
        rank,
        rel.to_string(),
    )
}

fn base_key(k: &OrderKey) -> (u64, DeviceId, u8) {
    (k.0, k.1, k.2)
}

#[derive(Debug, Default, Clone)]
struct View {
    /// Keyed by the full credential id, so lookups are exact matches of any length.
    creds: BTreeMap<Vec<u8>, (OrderKey, Event)>,
    devices: BTreeMap<DeviceId, (OrderKey, Event)>,
    removals: BTreeMap<DeviceId, (OrderKey, Event)>,
    backup: Option<(OrderKey, Event)>,
    removed_by_gen: BTreeSet<DeviceId>,
    max_lamport: u64,
    events: usize,
}

fn keep_max(slot: &mut Option<(OrderKey, Event)>, key: OrderKey, event: &Event) {
    if slot.as_ref().is_none_or(|(k, _)| key > *k) {
        *slot = Some((key, event.clone()));
    }
}

fn keep_max_in<K: Ord>(
    map: &mut BTreeMap<K, (OrderKey, Event)>,
    id: K,
    key: OrderKey,
    event: &Event,
) {
    let mut slot = map.remove(&id);
    keep_max(&mut slot, key, event);
    if let Some(v) = slot {
        map.insert(id, v);
    }
}

impl View {
    fn apply(&mut self, event: &Event, rel: &str, file_lamport: u64) {
        let key = order_key(event, rel);
        self.events = self.events.saturating_add(1);
        self.max_lamport = self.max_lamport.max(file_lamport).max(event.origin_lamport);
        match &event.kind {
            EventKind::Put(rec) => {
                keep_max_in(&mut self.creds, rec.credential_id.clone(), key, event)
            }
            EventKind::Tombstone(id) => keep_max_in(&mut self.creds, id.clone(), key, event),
            EventKind::DeviceAdded(d) => keep_max_in(&mut self.devices, d.device_id, key, event),
            EventKind::DeviceRemoved { device_id, .. } => {
                keep_max_in(&mut self.removals, *device_id, key, event)
            }
            EventKind::BackupConfirmed { .. } => keep_max(&mut self.backup, key, event),
        }
    }

    fn existing_key(&self, event: &Event) -> Option<(u64, DeviceId, u8)> {
        let found = match &event.kind {
            EventKind::Put(rec) => self.creds.get(&rec.credential_id),
            EventKind::Tombstone(id) => self.creds.get(id),
            EventKind::DeviceAdded(d) => self.devices.get(&d.device_id),
            EventKind::DeviceRemoved { device_id, .. } => self.removals.get(device_id),
            EventKind::BackupConfirmed { .. } => self.backup.as_ref(),
        };
        found.map(|(k, _)| base_key(k))
    }

    fn removed(&self) -> BTreeSet<DeviceId> {
        let mut out = self.removed_by_gen.clone();
        out.extend(self.removals.keys().copied());
        out
    }

    fn announcement(&self, id: &DeviceId) -> Option<&DeviceAnnouncement> {
        match self.devices.get(id) {
            Some((
                _,
                Event {
                    kind: EventKind::DeviceAdded(d),
                    ..
                },
            )) => Some(d),
            _ => None,
        }
    }

    fn record(&self, id: &[u8]) -> Option<&CredentialRecord> {
        match self.creds.get(id) {
            Some((
                _,
                Event {
                    kind: EventKind::Put(rec),
                    ..
                },
            )) => Some(rec),
            _ => None,
        }
    }

    fn records(&self) -> impl Iterator<Item = &CredentialRecord> {
        self.creds.values().filter_map(|(_, e)| match &e.kind {
            EventKind::Put(rec) => Some(rec.as_ref()),
            _ => None,
        })
    }

    fn winners(&self) -> Vec<Event> {
        let mut out: Vec<Event> = Vec::new();
        out.extend(self.creds.values().map(|(_, e)| e.clone()));
        out.extend(self.devices.values().map(|(_, e)| e.clone()));
        out.extend(self.removals.values().map(|(_, e)| e.clone()));
        if let Some((_, e)) = &self.backup {
            out.push(e.clone());
        }
        out
    }
}

fn rel_gen_file(id: &GenId, name: &str) -> String {
    format!("{KEYS_DIR}/{}/{name}", id.dir_name())
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, VaultError> {
    match fsutil::read_capped(path, MAX_FILE_LEN) {
        Ok(d) => Ok(Some(d)),
        Err(VaultError::Io(std::io::ErrorKind::NotFound, _)) => Ok(None),
        Err(e) => Err(e),
    }
}

#[derive(Debug, Default)]
struct Resolved {
    /// Every authentic, authorized generation; `key` is None where this device has no slot.
    nodes: BTreeMap<GenId, GenNode>,
    /// Lost the conflict rule (9.3), or the rotator rests on a device its own line removed.
    rejected: BTreeSet<GenId>,
    /// Rest on a device that the line this device follows removed (9.4); never followed and
    /// their accusations do not count here.
    void: BTreeSet<GenId>,
    /// Outside the line, and a removed device holds a slot in them (4.3). Never followed, but
    /// their accusations count and their removals are applied by rotating.
    exposed: BTreeSet<GenId>,
    /// Rejected generations whose rejection an accepted generation explains.
    settled: BTreeSet<GenId>,
    /// Their rotator rests on a device their own parent removed.
    pre_rejected: BTreeSet<GenId>,
    /// Removals voided because the removed device's own removal came first (9.5).
    voided: BTreeSet<RemovalKey>,
    /// Generations that list a voided removal, and everything built on them: the device whose
    /// removal was voided holds no key to them, so they are left when another line exists.
    tainted: BTreeSet<GenId>,
    /// Every removal in force: from generations neither void nor rejected, and from the line.
    removals: BTreeMap<RemovalKey, Removal>,
    /// For each device in `removals`: the events of it that every removal's cutoff holds.
    allowed: BTreeMap<DeviceId, BTreeSet<EventId>>,
}

impl Resolved {
    fn accepted(&self, id: &GenId) -> bool {
        self.followable(id) && !self.exposed.contains(id) && !self.tainted.contains(id)
    }

    fn followable(&self, id: &GenId) -> bool {
        self.nodes.contains_key(id) && !self.rejected.contains(id) && !self.void.contains(id)
    }

    fn keyed(&self) -> impl Iterator<Item = (&GenNode, &VaultKey)> {
        self.nodes
            .values()
            .filter(|n| self.accepted(&n.id))
            .filter_map(|n| n.key.as_ref().map(|k| (n, k)))
    }

    fn is_descendant(&self, id: GenId, of: GenId) -> bool {
        id != of && ancestors(&self.nodes, id).contains(&of)
    }

    fn removed_devices(&self) -> BTreeSet<DeviceId> {
        self.removals.values().map(|r| r.device).collect()
    }
}

/// The events of each removed device that every removal of it holds in its cutoff.
fn allowed_sets<'a>(
    removals: impl Iterator<Item = &'a Removal>,
) -> BTreeMap<DeviceId, BTreeSet<EventId>> {
    let mut out: BTreeMap<DeviceId, BTreeSet<EventId>> = BTreeMap::new();
    for r in removals {
        let cut: BTreeSet<EventId> = r.cutoff.iter().copied().collect();
        match out.get_mut(&r.device) {
            Some(a) => a.retain(|id| cut.contains(id)),
            None => {
                out.insert(r.device, cut);
            }
        }
    }
    out
}

/// Decides which removals are in force once the generations are known (docs/vault-format.md,
/// 9.5). A removal is void when its cause is an event of a device that another removal in force
/// removed (other than a removal of the removed device itself: that is a mutual race, left to the
/// conflict rule) and that removal's cutoff lacks the cause. The removed sets, conflicts, exposed
/// generations and the events allowed from removed devices then follow from what is left.
fn settle(res: &mut Resolved, line: Option<&Line>, me: Option<&DeviceId>, report: &mut ScanReport) {
    let mut candidates: BTreeMap<RemovalKey, Removal> = BTreeMap::new();
    for n in res.nodes.values() {
        if res.void.contains(&n.id) || res.rejected.contains(&n.id) {
            continue;
        }
        for r in &n.info.removed {
            candidates.entry(r.key()).or_insert_with(|| r.clone());
        }
    }
    if let Some(line) = line {
        for (k, r) in &line.removed {
            candidates.entry(*k).or_insert_with(|| r.clone());
        }
    }
    let mut voided: BTreeSet<RemovalKey> = BTreeSet::new();
    for _ in 0..2 {
        let live: Vec<&Removal> = candidates
            .values()
            .filter(|r| !voided.contains(&r.key()))
            .collect();
        let allowed = allowed_sets(live.iter().copied());
        voided = candidates
            .values()
            .filter(|r| {
                live.iter()
                    .any(|w| w.device == r.cause_author && w.cause_author != r.device)
                    && !allowed
                        .get(&r.cause_author)
                        .is_some_and(|a| a.contains(&r.cause))
            })
            .map(Removal::key)
            .collect();
    }
    let ids: Vec<GenId> = res.nodes.keys().copied().collect();
    for id in ids {
        let parent_cum = res
            .nodes
            .get(&id)
            .and_then(|n| n.parent)
            .and_then(|p| res.nodes.get(&p))
            .map(|p| p.removed_cum.clone())
            .unwrap_or_default();
        if let Some(n) = res.nodes.get_mut(&id) {
            let mut cum = parent_cum;
            cum.extend(
                n.info
                    .removed
                    .iter()
                    .filter(|r| !voided.contains(&r.key()))
                    .map(|r| r.device),
            );
            n.removed_cum = cum;
        }
    }
    res.rejected.clear();
    res.settled.clear();
    reject_conflicting(res);
    res.settled.extend(res.pre_rejected.iter().copied());
    res.rejected.extend(res.pre_rejected.iter().copied());

    let mut in_force: BTreeSet<RemovalKey> = BTreeSet::new();
    for n in res.nodes.values() {
        if !res.void.contains(&n.id) && !res.rejected.contains(&n.id) {
            in_force.extend(n.info.removed.iter().map(Removal::key));
        }
    }
    if let Some(line) = line {
        in_force.extend(line.removed.keys().copied());
    }
    res.removals = candidates
        .into_iter()
        .filter(|(k, _)| in_force.contains(k) && !voided.contains(k))
        .collect();
    let roots: BTreeSet<GenId> = res
        .nodes
        .values()
        .filter(|n| n.info.removed.iter().any(|r| voided.contains(&r.key())))
        .map(|n| n.id)
        .collect();
    res.tainted = res
        .nodes
        .keys()
        .copied()
        .filter(|id| ancestors(&res.nodes, *id).iter().any(|a| roots.contains(a)))
        .collect();
    res.voided = voided;
    res.allowed = allowed_sets(res.removals.values());
    let removed = res.removed_devices();
    let in_line: BTreeSet<GenId> = line
        .map(|l| l.entries.iter().map(|e| e.gen_id).collect())
        .unwrap_or_default();
    res.exposed = res
        .nodes
        .values()
        .filter(|n| n.parent.is_some() && !in_line.contains(&n.id) && !res.void.contains(&n.id))
        .filter(|n| {
            n.info
                .members
                .iter()
                .any(|m| removed.contains(&m.device_id) && Some(&m.device_id) != me)
        })
        .map(|n| n.id)
        .collect();
    let mut listed: Vec<GenId> = res.rejected.union(&res.void).copied().collect();
    listed.sort();
    report.rejected_generations = listed.len();
    report.rejected = listed;
}

/// A keyring entry that does not match `commitment` belongs to an earlier generation of the same
/// id that was rewritten (9.4); the slot is tried instead.
fn open_candidate_key(
    opener: &Opener<'_>,
    vault_dir: &Path,
    vault_id: &[u8; 16],
    id: &GenId,
    commitment: Option<&[u8; 32]>,
    report: &mut ScanReport,
) -> Option<VaultKey> {
    let dir = vault_dir.join(KEYS_DIR).join(id.dir_name());
    match opener {
        Opener::Device { dev, keyring } => {
            if let Some(e) = keyring.get(id)
                && commitment.is_none_or(|c| {
                    hirz_crypto::ct_eq(c, &format::commitment(&e.key, vault_id, id))
                })
            {
                return Some(e.key.clone());
            }
            let name = format::slot_name(&dev.device_id);
            match read_optional(&dir.join(&name)) {
                Ok(Some(data)) => match format::open_device_slot(
                    &data,
                    vault_id,
                    id,
                    &dev.device_id,
                    &dev.x25519_private,
                ) {
                    Ok(k) => Some(k),
                    Err(_) => {
                        report.skip(rel_gen_file(id, &name), "device slot does not open");
                        None
                    }
                },
                Ok(None) => None,
                Err(_) => {
                    report.skip(rel_gen_file(id, &name), "unreadable device slot");
                    None
                }
            }
        }
        Opener::Recovery { private, .. } => match read_optional(&dir.join(RECOVERY_SLOT_NAME)) {
            Ok(Some(data)) => format::open_recovery_slot(&data, vault_id, id, private).ok(),
            _ => None,
        },
    }
}

/// The devices a child generation's rotator rests on in its parent (docs/vault-format.md, 4.3):
/// itself, then each endorser up to a member listed by the parent or the recovery key.
fn authority_path(
    vault_id: &[u8; 16],
    child: &GenInfo,
    parent: &GenInfo,
    rotator: &DeviceId,
) -> Option<BTreeSet<DeviceId>> {
    let mut path = BTreeSet::new();
    path.insert(*rotator);
    if parent.member(rotator).is_some() {
        return Some(path);
    }
    let chain: BTreeMap<DeviceId, &DeviceAnnouncement> =
        child.chain.iter().map(|a| (a.device_id, a)).collect();
    let mut cur = *rotator;
    for _ in 0..=MAX_ENDORSEMENT_CHAIN {
        let ann = chain.get(&cur)?;
        if ann.endorser == RECOVERY_ENDORSER {
            return ann
                .endorsement_valid(vault_id, &parent.recovery_signing_pub)
                .then_some(path);
        }
        let endorser_pub = match parent.member(&ann.endorser) {
            Some(m) => m.signing_public,
            None => chain.get(&ann.endorser)?.signing_public,
        };
        if !ann.endorsement_valid(vault_id, &endorser_pub) || !path.insert(ann.endorser) {
            return None;
        }
        if parent.member(&ann.endorser).is_some() {
            return Some(path);
        }
        cur = ann.endorser;
    }
    None
}

/// Authentic means gen.info opens under the parent's key (genesis: anchored in the keyring or the
/// recovery key) and carries a valid signature by a rotator that was a member of the parent.
/// Generations without a key for this device still take part in conflict detection, so every
/// device holding the parent key reaches the same decision. `line` is the line this device
/// follows; generations resting on a device it removed are void here (9.4).
fn resolve(
    vault_dir: &Path,
    vault_id: &[u8; 16],
    opener: &Opener<'_>,
    line: Option<&Line>,
    report: &mut ScanReport,
) -> Result<Resolved, VaultError> {
    let keys_dir = vault_dir.join(KEYS_DIR);
    let mut ids = BTreeSet::new();
    for name in fsutil::list(&keys_dir)? {
        match GenId::parse_dir(&name) {
            Some(id) if fsutil::is_real_dir(&keys_dir.join(&name)) => {
                ids.insert(id);
            }
            Some(_) => report.skip(format!("{KEYS_DIR}/{name}"), "not a directory"),
            None => report.ignore(),
        }
    }
    let mut out = Resolved::default();
    let mut pre_rejected = BTreeSet::new();
    for id in ids {
        let info_rel = rel_gen_file(&id, GEN_INFO_NAME);
        let data = match read_optional(&keys_dir.join(id.dir_name()).join(GEN_INFO_NAME)) {
            Ok(Some(d)) => d,
            // Still being written, or abandoned: not a generation yet.
            Ok(None) => continue,
            Err(_) => {
                report.skip(info_rel, "unreadable gen.info");
                continue;
            }
        };
        let parent = match GenInfo::parent_of(&data) {
            Ok(p) => p,
            Err(_) => {
                report.skip(info_rel, "malformed gen.info");
                continue;
            }
        };
        let node = match parent {
            None => resolve_genesis(opener, vault_dir, vault_id, &id, &data, report),
            Some(pid) => {
                let Some(pnode) = out.nodes.get(&pid) else {
                    if pre_rejected.contains(&pid) {
                        pre_rejected.insert(id);
                    }
                    continue;
                };
                let Some(pkey) = pnode.key.as_ref() else {
                    continue;
                };
                if pid.number.checked_add(1) != Some(id.number) {
                    report.skip(info_rel, "generation number does not follow its parent");
                    continue;
                }
                let (info, info_hash) = match GenInfo::open_hashed(&data, pkey, vault_id, &id) {
                    Ok(i) => i,
                    Err(_) => {
                        report.skip(info_rel, "gen.info does not authenticate");
                        continue;
                    }
                };
                if info.recovery_pub != pnode.info.recovery_pub
                    || info.recovery_signing_pub != pnode.info.recovery_signing_pub
                {
                    report.skip(info_rel, "recovery key changed");
                    continue;
                }
                let Some(path) = authority_path(vault_id, &info, &pnode.info, &id.rotator) else {
                    report.skip(
                        info_rel,
                        "rotator was not a member of the parent generation",
                    );
                    continue;
                };
                if path.iter().any(|d| pnode.removed_cum.contains(d)) {
                    pre_rejected.insert(id);
                    continue;
                }
                let mut key = open_candidate_key(
                    opener,
                    vault_dir,
                    vault_id,
                    &id,
                    Some(&info.commitment),
                    report,
                );
                if key.as_ref().is_some_and(|k| {
                    !hirz_crypto::ct_eq(&info.commitment, &format::commitment(k, vault_id, &id))
                }) {
                    report.skip(info_rel, "key does not match the generation commitment");
                    key = None;
                }
                let mut removed_cum = pnode.removed_cum.clone();
                removed_cum.extend(info.removed.iter().map(|r| r.device));
                Some(GenNode {
                    id,
                    key,
                    parent,
                    info,
                    removed_cum,
                    path,
                    info_hash,
                })
            }
        };
        if let Some(n) = node {
            out.nodes.insert(id, n);
        }
    }
    if let Some(line) = line {
        mark_void(&mut out, line);
    }
    reject_conflicting(&mut out);
    out.settled.extend(pre_rejected.iter().copied());
    out.rejected.extend(pre_rejected.iter().copied());
    out.pre_rejected = pre_rejected;
    Ok(out)
}

fn resolve_genesis(
    opener: &Opener<'_>,
    vault_dir: &Path,
    vault_id: &[u8; 16],
    id: &GenId,
    data: &[u8],
    report: &mut ScanReport,
) -> Option<GenNode> {
    let info_rel = rel_gen_file(id, GEN_INFO_NAME);
    if id.number != 1 {
        report.skip(info_rel, "genesis with a number other than 1");
        return None;
    }
    if let Opener::Device { keyring, .. } = opener
        && !keyring.get(id).is_some_and(|e| e.root)
    {
        return None;
    }
    let key = open_candidate_key(opener, vault_dir, vault_id, id, None, report)?;
    let Ok((info, info_hash)) = GenInfo::open_hashed(data, &key, vault_id, id) else {
        report.skip(info_rel, "gen.info does not authenticate");
        return None;
    };
    if !hirz_crypto::ct_eq(&info.commitment, &format::commitment(&key, vault_id, id)) {
        report.skip(info_rel, "key does not match the generation commitment");
        return None;
    }
    if let Opener::Recovery {
        auth,
        public,
        signing_public,
        ..
    } = opener
    {
        let expected = format::genesis_tag(
            auth,
            vault_id,
            id,
            &info.commitment,
            &info.recovery_pub,
            &info.recovery_signing_pub,
        );
        let tag_ok = info
            .recovery_tag
            .is_some_and(|t| hirz_crypto::ct_eq(&t, &expected));
        if !tag_ok || info.recovery_pub != *public || info.recovery_signing_pub != *signing_public {
            report.skip(info_rel, "genesis not authenticated by the recovery key");
            return None;
        }
    }
    let mut path = BTreeSet::new();
    path.insert(id.rotator);
    Some(GenNode {
        id: *id,
        key: Some(key),
        parent: None,
        removed_cum: info.removed.iter().map(|r| r.device).collect(),
        info,
        path,
        info_hash,
    })
}

fn ancestors(nodes: &BTreeMap<GenId, GenNode>, id: GenId) -> BTreeSet<GenId> {
    let mut out = BTreeSet::new();
    let mut cur = Some(id);
    while let Some(c) = cur {
        if !out.insert(c) {
            break;
        }
        cur = nodes.get(&c).and_then(|n| n.parent);
    }
    out
}

/// Genesis first.
fn chain_to(nodes: &BTreeMap<GenId, GenNode>, id: GenId) -> Vec<GenId> {
    let mut out = Vec::new();
    let mut cur = Some(id);
    while let Some(c) = cur {
        if out.contains(&c) || out.len() > MAX_GENERATIONS {
            break;
        }
        out.push(c);
        cur = nodes.get(&c).and_then(|n| n.parent);
    }
    out.reverse();
    out
}

/// Generations outside the line that rest on a device the line removed, and their descendants:
/// the line already decided that device is untrusted. The removed set is kept in the local line
/// file, so it holds even when a generation of the line is missing from the folder.
fn mark_void(res: &mut Resolved, line: &Line) {
    let removed: BTreeSet<DeviceId> = line.removed.values().map(|r| r.device).collect();
    let in_line: BTreeSet<GenId> = line.entries.iter().map(|e| e.gen_id).collect();
    let outside = |n: &&GenNode| n.parent.is_some() && !in_line.contains(&n.id);
    let roots: BTreeSet<GenId> = res
        .nodes
        .values()
        .filter(outside)
        .filter(|n| n.path.iter().any(|d| removed.contains(d)))
        .map(|n| n.id)
        .collect();
    for id in res.nodes.keys() {
        if ancestors(&res.nodes, *id).iter().any(|a| roots.contains(a)) {
            res.void.insert(*id);
        }
    }
}

/// Rejects a generation whose rotator, or a device its membership rests on, was removed by a
/// generation outside its line of descent, and everything built on it; all accusations count
/// at once. See docs/vault-format.md, 9.3.
fn reject_conflicting(res: &mut Resolved) {
    let nodes = &res.nodes;
    let live: Vec<GenId> = nodes
        .keys()
        .copied()
        .filter(|id| !res.void.contains(id))
        .collect();
    let anc: BTreeMap<GenId, BTreeSet<GenId>> =
        live.iter().map(|d| (*d, ancestors(nodes, *d))).collect();
    let mut accusers: BTreeMap<GenId, Vec<GenId>> = BTreeMap::new();
    for c in &live {
        let Some(cn) = nodes.get(c).filter(|n| n.parent.is_some()) else {
            continue;
        };
        let by: Vec<GenId> = live
            .iter()
            .copied()
            .filter(|d| {
                d != c
                    && !anc.get(d).is_some_and(|a| a.contains(c))
                    && nodes
                        .get(d)
                        .is_some_and(|n| cn.path.iter().any(|p| n.removed_cum.contains(p)))
            })
            .collect();
        if !by.is_empty() {
            accusers.insert(*c, by);
        }
    }
    let mut rejected = BTreeSet::new();
    for d in &live {
        if anc
            .get(d)
            .is_some_and(|a| a.iter().any(|x| accusers.contains_key(x)))
        {
            rejected.insert(*d);
        }
    }
    let settled_roots: BTreeSet<GenId> = accusers
        .iter()
        .filter(|(_, by)| by.iter().any(|d| !rejected.contains(d)))
        .map(|(c, _)| *c)
        .collect();
    for d in &rejected {
        let roots: Vec<&GenId> = anc
            .get(d)
            .map(|a| a.iter().filter(|x| accusers.contains_key(x)).collect())
            .unwrap_or_default();
        if !roots.is_empty() && roots.iter().all(|r| settled_roots.contains(r)) {
            res.settled.insert(*d);
        }
    }
    res.rejected.extend(rejected);
}

/// The highest counter a scan accepts: `start + COUNTER_WINDOW`, raised by every counter named in
/// the folder that lies within the window so far, so a counter can only raise the bound by the
/// window from one already in range (docs/vault-format.md, 6.1). A device that has seen nothing
/// yet (joining) starts at 0 and still reaches the counters honest devices use.
fn counter_bound(start: u64, mut named: Vec<u64>) -> u64 {
    named.sort_unstable();
    let mut bound = start.saturating_add(COUNTER_WINDOW);
    for l in named {
        if l > bound {
            break;
        }
        bound = bound.max(l.saturating_add(COUNTER_WINDOW));
    }
    bound
}

fn load_records(
    vault_dir: &Path,
    vault_id: &[u8; 16],
    me: Option<&LocalDevice>,
    keys: &GenKeys,
    counter_start: u64,
    cache: &mut VerifyCache,
    report: &mut ScanReport,
) -> Result<Vec<Loaded>, VaultError> {
    let GenKeys { keys, retired } = keys;
    let records_dir = vault_dir.join(RECORDS_DIR);
    let mut found = Vec::new();
    for dir_name in fsutil::list(&records_dir)? {
        let dir = records_dir.join(&dir_name);
        let Some(writer) = format::parse_device_dir(&dir_name) else {
            report.ignore();
            continue;
        };
        if !fsutil::is_real_dir(&dir) {
            report.skip(format!("{RECORDS_DIR}/{dir_name}"), "not a directory");
            continue;
        }
        for name in fsutil::list(&dir)? {
            match RecordName::parse(&name) {
                Some(rn) => found.push((writer, dir.join(&name), rn)),
                None => report.ignore(),
            }
        }
    }
    let counter_bound = counter_bound(counter_start, found.iter().map(|f| f.2.lamport).collect());
    let mut out = Vec::new();
    for (writer, path, rn) in found {
        let rel = format::record_rel_path(&writer, &rn);
        if rn.lamport > counter_bound {
            report.skip(rel, "counter out of range");
            continue;
        }
        let data = match fsutil::read_capped(&path, MAX_FILE_LEN) {
            Ok(d) => d,
            Err(VaultError::Io(std::io::ErrorKind::NotFound, _)) => continue,
            Err(_) => {
                report.skip(rel, "unreadable");
                continue;
            }
        };
        let gen_id = match format::record_gen(&data) {
            Ok(g) => g,
            Err(_) => {
                report.skip(rel, "malformed record header");
                continue;
            }
        };
        let Some(key) = keys.get(&gen_id) else {
            report.other_generation_files = report.other_generation_files.saturating_add(1);
            continue;
        };
        let mut retired_key = false;
        let opened = format::open_record(&data, key, vault_id, &gen_id, &rel).or_else(|e| {
            retired_key = true;
            match retired.get(&gen_id) {
                Some(old) => format::open_record(&data, old, vault_id, &gen_id, &rel),
                None => Err(e),
            }
        });
        let pt = match opened {
            Ok(p) => p,
            Err(_) => {
                report.skip(rel, "record does not authenticate");
                continue;
            }
        };
        let (event, body_len, tag) = match Event::decode(&pt) {
            Ok(v) => v,
            Err(_) => {
                report.skip(rel, "malformed record body");
                continue;
            }
        };
        if event.origin_lamport > counter_bound {
            report.skip(rel, "counter out of range");
            continue;
        }
        let Ok(digest) = event.digest() else {
            report.skip(rel, "malformed record body");
            continue;
        };
        let id = crate::record::event_id(vault_id, &digest);
        if !cache.contains(&(id, event.signature)) {
            if !event.signature_valid(vault_id, &digest) {
                report.skip(rel, "event signature does not verify");
                continue;
            }
            if cache.len() >= MAX_VERIFY_CACHE {
                cache.clear();
            }
            cache.insert((id, event.signature));
        }
        let own = match (me, pt.get(..body_len)) {
            (Some(dev), Some(body)) if dev.device_id == writer => {
                hirz_crypto::ct_eq(&tag, &format::author_tag(&dev.secret, vault_id, &rel, body))
            }
            _ => false,
        };
        out.push(Loaded {
            rel,
            writer,
            name: rn,
            gen_id,
            event,
            own,
            retired: retired_key,
            id,
        });
    }
    Ok(out)
}

fn is_complete(node: &GenNode, loaded: &[Loaded]) -> bool {
    if node.parent.is_none() {
        return true;
    }
    let first = node.info.reemit_first;
    let Some(end) = first.checked_add(node.info.reemit_count) else {
        return false;
    };
    let found: BTreeSet<u64> = loaded
        .iter()
        .filter(|l| {
            l.gen_id == node.id
                && !l.retired
                && l.writer == node.id.rotator
                && l.name.lamport >= first
                && l.name.lamport < end
        })
        .map(|l| l.name.lamport)
        .collect();
    u64::try_from(found.len()).is_ok_and(|n| n == node.info.reemit_count)
}

#[derive(Debug)]
struct Snapshot {
    resolved: Resolved,
    loaded: Vec<Loaded>,
    current: GenId,
    report: ScanReport,
}

/// Picks the generation to follow. Without a line (joining) it is the highest accepted, complete
/// generation this device has a key for. With a line, the device never falls back below the
/// generation it follows, and a rewritten or missing generation of its line is a fork.
fn snapshot(
    vault_dir: &Path,
    vault_id: &[u8; 16],
    opener: &Opener<'_>,
    me: Option<&LocalDevice>,
    line: Option<&Line>,
    counter_start: u64,
    cache: &mut VerifyCache,
) -> Result<Snapshot, VaultError> {
    let mut report = ScanReport::default();
    let pin = line.and_then(Line::pin).map(|e| e.gen_id);
    let mut resolved = resolve(vault_dir, vault_id, opener, line, &mut report)?;
    settle(&mut resolved, line, me.map(|d| &d.device_id), &mut report);
    let mut keys: BTreeMap<GenId, VaultKey> = resolved
        .nodes
        .values()
        .filter(|n| !resolved.void.contains(&n.id))
        .filter_map(|n| n.key.as_ref().map(|k| (n.id, k.clone())))
        .collect();
    let mut retired = BTreeMap::new();
    if let Opener::Device { keyring, .. } = opener {
        for e in &keyring.entries {
            match keys.get(&e.gen_id) {
                None => {
                    keys.insert(e.gen_id, e.key.clone());
                }
                Some(k) if !hirz_crypto::ct_eq(k.as_slice(), e.key.as_slice()) => {
                    retired.insert(e.gen_id, e.key.clone());
                }
                Some(_) => {}
            }
        }
    }
    let loaded = load_records(
        vault_dir,
        vault_id,
        me,
        &GenKeys { keys, retired },
        counter_start,
        cache,
        &mut report,
    )?;
    let complete = |id: &GenId| {
        resolved
            .nodes
            .get(id)
            .is_some_and(|n| n.key.is_some() && is_complete(n, &loaded))
    };
    let winner = resolved
        .keyed()
        .filter(|(n, _)| is_complete(n, &loaded))
        .map(|(n, _)| n.id)
        .max();
    // The pin lost a conflict, or rests on a voided removal: another line is followed even
    // when a removed device still holds a slot there; the device then rotates before writing
    // (9.4, 9.5).
    let fallback = |pin: GenId| {
        resolved
            .nodes
            .keys()
            .copied()
            .filter(|id| {
                *id != pin
                    && resolved.followable(id)
                    && !resolved.tainted.contains(id)
                    && complete(id)
                    && !resolved.is_descendant(pin, *id)
            })
            .max()
    };
    let present = |e: &LineEntry| {
        resolved
            .nodes
            .get(&e.gen_id)
            .is_some_and(|n| n.key.is_some() && n.info_hash == e.info_hash)
    };
    let mut kept_rejected = false;
    let current = match (line, pin) {
        (Some(line), Some(pin)) => {
            if !line.entries.iter().all(present) {
                report.fork_detected = true;
                line.entries
                    .iter()
                    .rev()
                    .find(|e| present(e))
                    .map(|e| e.gen_id)
                    .ok_or(VaultError::NoAccess)?
            } else {
                match winner {
                    Some(w) if w == pin || !resolved.is_descendant(pin, w) => w,
                    _ => {
                        let lost = resolved.rejected.contains(&pin);
                        if resolved.accepted(&pin) {
                            report.rollback_suspected = true;
                            pin
                        } else if let Some(f) = fallback(pin).filter(|_| {
                            if lost {
                                resolved.settled.contains(&pin)
                            } else {
                                resolved.tainted.contains(&pin)
                            }
                        }) {
                            f
                        } else {
                            kept_rejected = lost;
                            pin
                        }
                    }
                }
            }
        }
        _ => winner.ok_or(VaultError::NoAccess)?,
    };
    report.generation = current.number;
    report.locked_out = resolved.nodes.values().any(|n| {
        n.key.is_none() && resolved.accepted(&n.id) && resolved.is_descendant(n.id, current)
    });
    report.rotation_conflict = kept_rejected
        || resolved
            .rejected
            .iter()
            .any(|g| g.number > current.number && !resolved.settled.contains(g));
    Ok(Snapshot {
        resolved,
        loaded,
        current,
        report,
    })
}

pub(crate) fn read_header(vault_dir: &Path) -> Result<Header, VaultError> {
    match read_optional(&vault_dir.join(HEADER_NAME))? {
        Some(d) => Header::decode(&d),
        None => Err(VaultError::NotFound),
    }
}

fn read_counter(state_dir: &Path) -> Result<Counter, VaultError> {
    match read_optional(&state_dir.join(STATE_COUNTER))? {
        Some(d) => Counter::decode(&d),
        None => Ok(Counter::default()),
    }
}

fn read_line(state_dir: &Path) -> Result<Option<Line>, VaultError> {
    read_optional(&state_dir.join(STATE_LINE))?
        .map(|d| Line::decode(&d))
        .transpose()
}

fn counter_start(c: &Counter) -> u64 {
    c.max_seen.max(c.next)
}

/// `(device id, signature)` of the `device added` announcements under a generation that count
/// (docs/vault-format.md, 6.2): a member's must carry the keys the rotator signed for it; any
/// other must be endorsed by the recovery key or by a member or counted device that `removed`
/// does not hold. Announcements of removed devices count for display only.
fn valid_announcements<'a>(
    vault_id: &[u8; 16],
    info: &GenInfo,
    removed: &BTreeSet<DeviceId>,
    anns: impl Iterator<Item = &'a DeviceAnnouncement>,
) -> BTreeSet<(DeviceId, [u8; 64])> {
    let mut valid = BTreeSet::new();
    let mut signers: BTreeMap<DeviceId, [u8; 32]> = BTreeMap::new();
    let mut queue: Vec<DeviceId> = Vec::new();
    let mut by_endorser: BTreeMap<DeviceId, Vec<&DeviceAnnouncement>> = BTreeMap::new();
    for m in &info.members {
        if !removed.contains(&m.device_id)
            && signers.insert(m.device_id, m.signing_public).is_none()
        {
            queue.push(m.device_id);
        }
    }
    let accept = |a: &DeviceAnnouncement,
                  valid: &mut BTreeSet<(DeviceId, [u8; 64])>,
                  signers: &mut BTreeMap<DeviceId, [u8; 32]>,
                  queue: &mut Vec<DeviceId>| {
        valid.insert((a.device_id, a.signature));
        if !removed.contains(&a.device_id) && !signers.contains_key(&a.device_id) {
            signers.insert(a.device_id, a.signing_public);
            queue.push(a.device_id);
        }
    };
    for a in anns {
        if let Some(m) = info.member(&a.device_id) {
            if m.signing_public == a.signing_public && m.x25519_public == a.x25519_public {
                valid.insert((a.device_id, a.signature));
            }
        } else if removed.contains(&a.device_id) {
            valid.insert((a.device_id, a.signature));
        } else if a.endorser == RECOVERY_ENDORSER {
            if a.endorsement_valid(vault_id, &info.recovery_signing_pub) {
                accept(a, &mut valid, &mut signers, &mut queue);
            }
        } else if !removed.contains(&a.endorser) {
            by_endorser.entry(a.endorser).or_default().push(a);
        }
    }
    while let Some(d) = queue.pop() {
        let Some(key) = signers.get(&d).copied() else {
            continue;
        };
        for a in by_endorser.remove(&d).unwrap_or_default() {
            if !valid.contains(&(a.device_id, a.signature)) && a.endorsement_valid(vault_id, &key) {
                accept(a, &mut valid, &mut signers, &mut queue);
            }
        }
    }
    valid
}

#[derive(Debug, Clone)]
struct TreeNode {
    parent: Option<GenId>,
    path: BTreeSet<DeviceId>,
}

pub struct Vault {
    vault_dir: PathBuf,
    state_dir: PathBuf,
    header: Header,
    pub(crate) device: LocalDevice,
    pub(crate) keyring: Keyring,
    current: GenId,
    current_key: VaultKey,
    current_info: Option<GenInfo>,
    /// Devices holding an authenticated slot in the current generation: the members its
    /// rotator signed, plus devices added to it afterwards by an event under its key.
    slot_holders: BTreeSet<DeviceId>,
    current_first_seen: u64,
    current_chain: BTreeSet<GenId>,
    /// A removed device holds a slot in the current generation.
    exposed: bool,
    /// Removals in force that the current generation has not applied yet; the next rotation
    /// copies them (docs/vault-format.md, 9.1).
    pending_removals: BTreeMap<RemovalKey, Removal>,
    /// Every device a removal in force removed.
    removed_known: BTreeSet<DeviceId>,
    /// Events of removed devices that count (`Resolved::allowed`).
    allowed: BTreeMap<DeviceId, BTreeSet<EventId>>,
    verified: VerifyCache,
    computed_line: Line,
    tree: BTreeMap<GenId, TreeNode>,
    old_files: Vec<Loaded>,
    /// Seconds a generation must be current on this device before superseded files are deleted,
    /// so a device that receives the deletions before the new files never sees an empty vault.
    pub(crate) gc_grace: u64,
    stale_own: Vec<Loaded>,
    view: View,
    report: ScanReport,
    hidden_requests: usize,
}

impl core::fmt::Debug for Vault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vault")
            .field("vault_id", &hex(&self.header.vault_id))
            .field("device", &self.device)
            .field("generation", &self.current)
            .field("credentials", &self.view.records().count())
            .finish_non_exhaustive()
    }
}

/// A new event of this device, or an event re-written as it is (origin and signature kept).
enum Origin {
    Fresh(EventKind),
    Keep(Event),
}

fn member_of(d: &DeviceAnnouncement) -> Member {
    Member {
        device_id: d.device_id,
        signing_public: d.signing_public,
        x25519_public: d.x25519_public,
    }
}

impl Vault {
    /// Says nothing about whether the header is valid.
    pub fn exists(vault_dir: &Path) -> bool {
        vault_dir.join(HEADER_NAME).exists()
    }

    pub fn is_set_up(state_dir: &Path) -> bool {
        state_dir.join(STATE_DEVICE).exists()
    }

    /// The vault folder is never touched, and other files in `state_dir` stay.
    pub fn forget_local(state_dir: &Path) -> Result<bool, VaultError> {
        if !state_dir.is_dir() {
            return Ok(false);
        }
        let _lock = StateLock::acquire(state_dir)?;
        let mut found = false;
        for name in [STATE_KEYRING, STATE_DEVICE, STATE_COUNTER, STATE_LINE] {
            let path = state_dir.join(name);
            if path.exists() {
                found = true;
            }
            fsutil::remove_file(&path)?;
        }
        Ok(found)
    }

    /// Walks the key generations with the recovery key, as joining does, without local device state
    /// or reading any credential. Errors only when the header is missing or unreadable.
    pub fn check_recovery_phrase(
        vault_dir: &Path,
        phrase: &RecoveryPhrase,
    ) -> Result<bool, VaultError> {
        let header = read_header(vault_dir)?;
        let private = phrase.x25519_private()?;
        let auth = phrase.auth_key()?;
        let opener = Opener::Recovery {
            private: &private,
            auth: &auth,
            public: phrase.x25519_public()?,
            signing_public: phrase.signing_public()?,
        };
        let mut report = ScanReport::default();
        let resolved = resolve(vault_dir, &header.vault_id, &opener, None, &mut report)?;
        Ok(resolved.keyed().next().is_some())
    }

    /// Returns the recovery phrase, which must be shown to the user once.
    pub fn create(
        vault_dir: &Path,
        state_dir: &Path,
        device_name: &str,
    ) -> Result<(Vault, RecoveryPhrase), VaultError> {
        if device_name.len() > MAX_DEVICE_NAME_LEN {
            return Err(VaultError::InvalidParameters);
        }
        if Vault::exists(vault_dir) || Vault::is_set_up(state_dir) {
            return Err(VaultError::AlreadyExists);
        }
        fsutil::private_dir(vault_dir)?;
        fsutil::state_dir(state_dir)?;
        let header = Header {
            vault_id: random16()?,
            created_at: now(),
        };
        let device = new_device(header.vault_id, device_name)?;
        let phrase = RecoveryPhrase::generate()?;
        let recovery_pub = phrase.x25519_public()?;
        let recovery_signing_pub = phrase.signing_public()?;
        let genesis = GenId {
            number: 1,
            rotator: device.device_id,
        };
        let key = random_key()?;
        let gen_dir = fsutil::vault_subdir(vault_dir, &[KEYS_DIR, &genesis.dir_name()])?;
        let device_pub = hirz_crypto::x25519::public_key(&device.x25519_private)?;
        fsutil::write_atomic(
            &gen_dir,
            &format::slot_name(&device.device_id),
            &format::seal_device_slot(
                &header.vault_id,
                &genesis,
                &device.device_id,
                &device_pub,
                &key,
            )?,
        )?;
        fsutil::write_atomic(
            &gen_dir,
            RECOVERY_SLOT_NAME,
            &format::seal_recovery_slot(&header.vault_id, &genesis, &recovery_pub, &key)?,
        )?;
        let commitment = format::commitment(&key, &header.vault_id, &genesis);
        let info = GenInfo {
            commitment,
            recovery_pub,
            removed: Vec::new(),
            created_at: header.created_at,
            reemit_first: 0,
            reemit_count: 0,
            recovery_tag: Some(format::genesis_tag(
                &*phrase.auth_key()?,
                &header.vault_id,
                &genesis,
                &commitment,
                &recovery_pub,
                &recovery_signing_pub,
            )),
            recovery_signing_pub,
            members: vec![Member {
                device_id: device.device_id,
                signing_public: device.signing_public()?,
                x25519_public: device_pub,
            }],
            chain: Vec::new(),
        };
        let keyring = Keyring {
            recovery_pub,
            entries: vec![KeyringEntry {
                gen_id: genesis,
                key: key.clone(),
                root: true,
            }],
        };
        save_device(state_dir, &device)?;
        save_keyring(state_dir, &keyring, &device)?;
        fsutil::write_atomic(
            &gen_dir,
            GEN_INFO_NAME,
            &info.seal(&key, &header.vault_id, &genesis, None, &device.signing_seed)?,
        )?;
        fsutil::write_atomic(vault_dir, HEADER_NAME, &header.encode())?;
        let mut vault = Vault::assemble(vault_dir, state_dir, header, device, keyring)?;
        vault.announce_self(device_pub, &phrase)?;
        Ok((vault, phrase))
    }

    pub fn open(vault_dir: &Path, state_dir: &Path) -> Result<Vault, VaultError> {
        let header = read_header(vault_dir)?;
        let device = match read_optional(&state_dir.join(STATE_DEVICE))? {
            Some(d) => LocalDevice::decode(&d)?,
            None => return Err(VaultError::NotFound),
        };
        if device.vault_id != header.vault_id {
            return Err(VaultError::WrongVault);
        }
        fsutil::state_dir(state_dir)?;
        let keyring = match read_optional(&state_dir.join(STATE_KEYRING))? {
            Some(d) => Keyring::open(&d, &device)?,
            None => return Err(VaultError::NotFound),
        };
        let mut vault = Vault::assemble(vault_dir, state_dir, header, device, keyring)?;
        vault.maintain();
        Ok(vault)
    }

    /// Works during a rotation conflict too, so a user who lost every device can still get in
    /// and settle the conflict from the new one.
    pub fn join_with_recovery(
        vault_dir: &Path,
        state_dir: &Path,
        phrase: &RecoveryPhrase,
        device_name: &str,
    ) -> Result<Vault, VaultError> {
        if device_name.len() > MAX_DEVICE_NAME_LEN {
            return Err(VaultError::InvalidParameters);
        }
        let header = read_header(vault_dir)?;
        if state_dir.join(STATE_DEVICE).exists() {
            return Err(VaultError::AlreadyExists);
        }
        let private = phrase.x25519_private()?;
        let auth = phrase.auth_key()?;
        let public = phrase.x25519_public()?;
        let opener = Opener::Recovery {
            private: &private,
            auth: &auth,
            public,
            signing_public: phrase.signing_public()?,
        };
        let snap = match snapshot(
            vault_dir,
            &header.vault_id,
            &opener,
            None,
            None,
            0,
            &mut VerifyCache::new(),
        ) {
            Ok(s) => s,
            Err(VaultError::NoAccess) => return Err(VaultError::WrongRecoveryKey),
            Err(e) => return Err(e),
        };
        fsutil::state_dir(state_dir)?;
        let device = new_device(header.vault_id, device_name)?;
        // Generations of an unsettled conflict too: the new device settles it by discarding one
        // side, and the other side must then be readable (9.3).
        let keyring = Keyring {
            recovery_pub: public,
            entries: snap
                .resolved
                .nodes
                .values()
                .filter(|n| {
                    snap.resolved.accepted(&n.id)
                        || (snap.resolved.rejected.contains(&n.id)
                            && !snap.resolved.settled.contains(&n.id))
                })
                .filter_map(|n| {
                    n.key.as_ref().map(|k| KeyringEntry {
                        gen_id: n.id,
                        key: k.clone(),
                        root: n.parent.is_none(),
                    })
                })
                .collect(),
        };
        let current_key = snap
            .resolved
            .nodes
            .get(&snap.current)
            .and_then(|n| n.key.clone())
            .ok_or(VaultError::NoAccess)?;
        let device_pub = hirz_crypto::x25519::public_key(&device.x25519_private)?;
        save_device(state_dir, &device)?;
        save_keyring(state_dir, &keyring, &device)?;
        fsutil::write_atomic(
            &fsutil::vault_subdir(vault_dir, &[KEYS_DIR, &snap.current.dir_name()])?,
            &format::slot_name(&device.device_id),
            &format::seal_device_slot(
                &header.vault_id,
                &snap.current,
                &device.device_id,
                &device_pub,
                &current_key,
            )?,
        )?;
        let mut vault = Vault::assemble(vault_dir, state_dir, header, device, keyring)?;
        vault.announce_self(device_pub, phrase)?;
        Ok(vault)
    }

    fn assemble(
        vault_dir: &Path,
        state_dir: &Path,
        header: Header,
        device: LocalDevice,
        keyring: Keyring,
    ) -> Result<Vault, VaultError> {
        let mut vault = Vault {
            vault_dir: vault_dir.to_path_buf(),
            state_dir: state_dir.to_path_buf(),
            header,
            device,
            keyring,
            current: GenId {
                number: 0,
                rotator: [0u8; 16],
            },
            current_key: Zeroizing::new([0u8; 32]),
            current_info: None,
            slot_holders: BTreeSet::new(),
            current_first_seen: 0,
            current_chain: BTreeSet::new(),
            exposed: false,
            pending_removals: BTreeMap::new(),
            removed_known: BTreeSet::new(),
            allowed: BTreeMap::new(),
            verified: VerifyCache::new(),
            computed_line: Line::default(),
            tree: BTreeMap::new(),
            old_files: Vec::new(),
            gc_grace: GC_GRACE_SECS,
            stale_own: Vec::new(),
            view: View::default(),
            report: ScanReport::default(),
            hidden_requests: 0,
        };
        vault.scan()?;
        Ok(vault)
    }

    /// The recovery key endorses the device: only someone holding the phrase can add a device
    /// that does not rest on another device's approval.
    fn announce_self(
        &mut self,
        device_pub: [u8; 32],
        phrase: &RecoveryPhrase,
    ) -> Result<(), VaultError> {
        let mut ann = DeviceAnnouncement {
            device_id: self.device.device_id,
            name: self.device.name.clone(),
            x25519_public: device_pub,
            added_at: now(),
            signing_public: self.device.signing_public()?,
            endorser: RECOVERY_ENDORSER,
            signature: [0u8; 64],
        };
        ann.endorse(&self.header.vault_id, &*phrase.signing_seed()?)?;
        self.write(vec![Origin::Fresh(EventKind::DeviceAdded(ann))])
    }

    /// Re-reads the folder, carries own events forward to the current generation and finishes a pending rotation.
    pub fn reload(&mut self) -> Result<&ScanReport, VaultError> {
        self.scan()?;
        self.maintain();
        Ok(&self.report)
    }

    fn maintain(&mut self) {
        // During a rotation conflict the current key may be held by the device being removed, and
        // during a fork the folder no longer matches what this device followed, so nothing is
        // automatic until the user decides.
        if self.report.rotation_conflict || self.report.fork_detected {
            return;
        }
        let mut migrated = 0usize;
        let mut rotated = false;
        let mut collected = 0usize;
        let mut error = None;
        // Rotating first means nothing this device carries forward is ever written under a key
        // that a removed device may hold; the rotation carries its own stale events itself.
        if self.needs_rotation() {
            match self.rotate(&[]) {
                Ok(()) => rotated = true,
                Err(e) => error = Some(e),
            }
        }
        if error.is_none() && !self.stale_own.is_empty() {
            match self.migrate_stale() {
                Ok(n) => migrated = n,
                Err(e) => error = Some(e),
            }
        }
        if error.is_none() && !rotated {
            match self.collect_garbage() {
                Ok(n) => collected = n,
                Err(e) => error = Some(e),
            }
        }
        if (migrated > 0 || rotated || collected > 0)
            && let Err(e) = self.scan()
        {
            error = Some(e);
        }
        self.report.migrated = migrated;
        self.report.rotated = rotated;
        self.report.collected = collected;
        self.report.maintenance_error = error;
    }

    fn scan(&mut self) -> Result<(), VaultError> {
        let counter = read_counter(&self.state_dir)?;
        let line = read_line(&self.state_dir)?;
        let opener = Opener::Device {
            dev: &self.device,
            keyring: &self.keyring,
        };
        let snap = snapshot(
            &self.vault_dir,
            &self.header.vault_id,
            &opener,
            Some(&self.device),
            line.as_ref(),
            counter_start(&counter),
            &mut self.verified,
        )?;
        let Snapshot {
            resolved,
            loaded,
            current,
            mut report,
        } = snap;
        let node = resolved.nodes.get(&current).ok_or(VaultError::NoAccess)?;
        let me = self.device.device_id;
        let removed_known = resolved.removed_devices();
        let mut ignored = node.removed_cum.clone();
        ignored.extend(removed_known.iter().copied());
        let reemit_end = node
            .info
            .reemit_first
            .saturating_add(node.info.reemit_count);
        let held = |l: &Loaded| {
            resolved
                .allowed
                .get(&l.event.origin_author)
                .is_none_or(|a| a.contains(&l.id))
        };
        let in_current: Vec<&Loaded> = loaded
            .iter()
            .filter(|l| {
                l.gen_id == current && !l.retired && !ignored.contains(&l.writer) && held(l)
            })
            .collect();
        let valid = valid_announcements(
            &self.header.vault_id,
            &node.info,
            &ignored,
            in_current.iter().filter_map(|l| match &l.event.kind {
                EventKind::DeviceAdded(d) => Some(d),
                _ => None,
            }),
        );
        let mut known: BTreeSet<DeviceId> = node.info.members.iter().map(|m| m.device_id).collect();
        known.extend(in_current.iter().filter_map(|l| match &l.event.kind {
            EventKind::DeviceAdded(d) if valid.contains(&(d.device_id, d.signature)) => {
                Some(d.device_id)
            }
            _ => None,
        }));
        let mut view = View {
            removed_by_gen: node.removed_cum.clone(),
            ..View::default()
        };
        let mut old_files = Vec::new();
        let mut stale_own = Vec::new();
        let mut folder_max = 0u64;
        let mut slot_holders: BTreeSet<DeviceId> =
            node.info.members.iter().map(|m| m.device_id).collect();
        // Who may hold the current key, whoever wrote the announcement: a removed device's own
        // announcement under a generation shows that it joined it.
        let mut holders = slot_holders.clone();
        for l in &loaded {
            folder_max = folder_max.max(l.name.lamport);
            if l.gen_id == current && !l.retired {
                let reemitted = l.writer == current.rotator
                    && (node.info.reemit_first..reemit_end).contains(&l.name.lamport);
                if let EventKind::DeviceAdded(d) = &l.event.kind
                    && !reemitted
                {
                    holders.insert(d.device_id);
                }
                if ignored.contains(&l.writer) {
                    continue;
                }
                if !held(l) {
                    report.skip(l.rel.clone(), "event of a removed device after its removal");
                    continue;
                }
                if let EventKind::DeviceAdded(d) = &l.event.kind {
                    if !valid.contains(&(d.device_id, d.signature)) {
                        report.skip(l.rel.clone(), "device added without a valid endorsement");
                        continue;
                    }
                    if !reemitted {
                        slot_holders.insert(d.device_id);
                    }
                }
                if !known.contains(&l.event.origin_author) {
                    report.skip(
                        l.rel.clone(),
                        "event of a device the generation does not know",
                    );
                    continue;
                }
                view.apply(&l.event, &l.rel, l.name.lamport);
            } else {
                report.other_generation_files = report.other_generation_files.saturating_add(1);
                if l.own
                    && (l.gen_id.number <= current.number
                        || l.retired
                        || !resolved.accepted(&l.gen_id))
                {
                    stale_own.push(l.clone());
                }
                if l.gen_id.number <= current.number {
                    old_files.push(l.clone());
                }
            }
        }
        view.max_lamport = view.max_lamport.max(folder_max);

        let chain = chain_to(&resolved.nodes, current);
        let chain_set: BTreeSet<GenId> = chain.iter().copied().collect();
        let new_entries: Vec<KeyringEntry> = resolved
            .nodes
            .values()
            .filter(|n| resolved.accepted(&n.id) || chain_set.contains(&n.id))
            .filter_map(|n| n.key.as_ref().map(|k| (n, k)))
            .filter(|(n, k)| {
                self.keyring
                    .get(&n.id)
                    .is_none_or(|e| !hirz_crypto::ct_eq(e.key.as_slice(), k.as_slice()))
            })
            .map(|(n, k)| KeyringEntry {
                gen_id: n.id,
                key: k.clone(),
                root: n.parent.is_none(),
            })
            .collect();
        let at = now();
        let mut line_removed: BTreeMap<RemovalKey, Removal> =
            line.as_ref().map(|l| l.removed.clone()).unwrap_or_default();
        if !report.fork_detected {
            for n in chain.iter().filter_map(|id| resolved.nodes.get(id)) {
                for r in &n.info.removed {
                    line_removed.entry(r.key()).or_insert_with(|| r.clone());
                }
            }
        }
        line_removed.retain(|k, _| !resolved.voided.contains(k));
        let new_line = Line {
            entries: chain
                .iter()
                .filter_map(|id| resolved.nodes.get(id))
                .map(|n| LineEntry {
                    gen_id: n.id,
                    info_hash: n.info_hash,
                    first_seen: line
                        .as_ref()
                        .and_then(|l| l.get(&n.id))
                        .filter(|e| e.info_hash == n.info_hash)
                        .map_or(at, |e| e.first_seen),
                })
                .collect(),
            removed: line_removed,
        };
        let line_changed = !report.fork_detected && line.as_ref() != Some(&new_line);
        report.rollback_suspected |= folder_max < counter.max_seen;
        if !new_entries.is_empty() || folder_max > counter.max_seen || line_changed {
            let _lock = StateLock::acquire(&self.state_dir)?;
            if !new_entries.is_empty() {
                let mut keyring = match read_optional(&self.state_dir.join(STATE_KEYRING))? {
                    Some(d) => Keyring::open(&d, &self.device)?,
                    None => self.keyring.clone(),
                };
                for e in new_entries {
                    keyring.entries.retain(|k| {
                        k.gen_id != e.gen_id
                            || hirz_crypto::ct_eq(k.key.as_slice(), e.key.as_slice())
                    });
                    if keyring.get(&e.gen_id).is_none() && keyring.entries.len() < MAX_GENERATIONS {
                        keyring.entries.push(e);
                    }
                }
                save_keyring(&self.state_dir, &keyring, &self.device)?;
                self.keyring = keyring;
            }
            let mut c = read_counter(&self.state_dir)?;
            if folder_max > c.max_seen {
                c.max_seen = folder_max;
                fsutil::write_atomic(&self.state_dir, STATE_COUNTER, &c.encode())?;
            }
            if line_changed {
                fsutil::write_atomic(&self.state_dir, STATE_LINE, &new_line.encode()?)?;
            }
        }
        let first_seen = if report.fork_detected {
            at
        } else {
            new_line.pin().map_or(at, |e| e.first_seen)
        };

        report.this_device_removed = node.removed_cum.contains(&me)
            || resolved.nodes.values().any(|n| {
                n.key.is_none()
                    && resolved.accepted(&n.id)
                    && resolved.is_descendant(n.id, current)
                    && n.removed_cum.contains(&me)
            });
        report.credentials = view.records().count();
        report.events = view.events;
        let pending: BTreeMap<RemovalKey, Removal> = resolved
            .removals
            .iter()
            .filter(|(_, r)| r.device != me && !node.removed_cum.contains(&r.device))
            .map(|(k, r)| (*k, r.clone()))
            .collect();
        self.exposed = holders
            .iter()
            .any(|d| removed_known.contains(d) && *d != me);
        self.allowed = resolved.allowed.clone();
        self.removed_known = removed_known;
        self.current = current;
        self.current_key = node.key.clone().ok_or(VaultError::NoAccess)?;
        self.current_info = Some(node.info.clone());
        self.slot_holders = slot_holders;
        self.pending_removals = pending;
        self.current_first_seen = first_seen;
        self.current_chain = chain.into_iter().collect();
        self.tree = resolved
            .nodes
            .values()
            .map(|n| {
                (
                    n.id,
                    TreeNode {
                        parent: n.parent,
                        path: n.path.clone(),
                    },
                )
            })
            .collect();
        self.old_files = old_files;
        self.stale_own = stale_own;
        self.view = view;
        self.report = report;
        self.computed_line = new_line;
        Ok(())
    }

    fn writable(&self) -> Result<(), VaultError> {
        if self.report.fork_detected {
            return Err(VaultError::Fork);
        }
        if self.report.locked_out || self.view.removed().contains(&self.device.device_id) {
            return Err(VaultError::NoAccess);
        }
        Ok(())
    }

    /// Rotations stop during a rotation conflict: they would build on a generation other devices
    /// reject.
    fn rotatable(&self) -> Result<(), VaultError> {
        self.writable()?;
        if self.report.rotation_conflict {
            return Err(VaultError::RotationConflict);
        }
        Ok(())
    }

    /// Content writes also stop during a rotation conflict (the current key may be held by the
    /// device being removed) and while a device this device's line removed holds a slot in the
    /// current generation, until a rotation leaves it out (9.4).
    fn content_writable(&self) -> Result<(), VaultError> {
        self.rotatable()?;
        if self.exposed {
            return Err(VaultError::NoAccess);
        }
        Ok(())
    }

    /// Only this device's own counter can run out; counters from the folder are bounded on read.
    fn allocate(&self, n: u64) -> Result<u64, VaultError> {
        let _lock = StateLock::acquire(&self.state_dir)?;
        let mut c = read_counter(&self.state_dir)?;
        let floor = self.view.max_lamport.max(c.max_seen).saturating_add(1);
        let start = c.next.max(floor).max(1);
        c.next = start.checked_add(n).ok_or(VaultError::InvalidParameters)?;
        fsutil::write_atomic(&self.state_dir, STATE_COUNTER, &c.encode())?;
        Ok(start)
    }

    fn write_under(
        &self,
        gen_id: &GenId,
        key: &[u8; 32],
        events: Vec<Origin>,
        start: u64,
    ) -> Result<Vec<(Event, String, u64)>, VaultError> {
        let dir = fsutil::vault_subdir(
            &self.vault_dir,
            &[
                RECORDS_DIR,
                &format::device_dir_name(&self.device.device_id),
            ],
        )?;
        let mut written = Vec::with_capacity(events.len());
        let mut lamport = start;
        for origin in events {
            let event = match origin {
                Origin::Fresh(kind) => Event::signed(
                    kind,
                    self.device.device_id,
                    lamport,
                    &self.device.signing_seed,
                    &self.header.vault_id,
                )?,
                Origin::Keep(e) => e,
            };
            let name = RecordName::new(lamport)?;
            let rel = format::record_rel_path(&self.device.device_id, &name);
            let mut body = event.encode_body()?;
            let tag = format::author_tag(&self.device.secret, &self.header.vault_id, &rel, &body);
            append_tag(&mut body, &tag);
            let data = format::seal_record(key, &self.header.vault_id, gen_id, &rel, &body)?;
            fsutil::write_atomic(&dir, &name.file_name(), &data)?;
            written.push((event, rel, lamport));
            lamport = lamport
                .checked_add(1)
                .ok_or(VaultError::InvalidParameters)?;
        }
        Ok(written)
    }

    fn write(&mut self, events: Vec<Origin>) -> Result<(), VaultError> {
        self.writable()?;
        if self.exposed {
            return Err(VaultError::NoAccess);
        }
        let n = u64::try_from(events.len()).map_err(|_| VaultError::InvalidParameters)?;
        let start = self.allocate(n)?;
        let current = self.current;
        let key = self.current_key.clone();
        let written = self.write_under(&current, &key, events, start)?;
        for (event, rel, lamport) in written {
            self.view.apply(&event, &rel, lamport);
        }
        self.report.credentials = self.view.records().count();
        self.report.events = self.view.events;
        Ok(())
    }

    fn superseded(&self, l: &Loaded) -> bool {
        let key = base_key(&order_key(&l.event, &l.rel));
        self.view
            .existing_key(&l.event)
            .is_some_and(|existing| existing >= key)
    }

    /// Only events whose author tag verifies are carried, so a removed device holding an old key
    /// cannot plant events for this device to adopt.
    fn migrate_stale(&mut self) -> Result<usize, VaultError> {
        self.writable()?;
        let stale = core::mem::take(&mut self.stale_own);
        let mut carry = Vec::new();
        for l in &stale {
            if !self.superseded(l) && self.carriable(&l.event, &l.id) {
                carry.push(Origin::Keep(l.event.clone()));
            }
        }
        let n = carry.len();
        if !carry.is_empty() {
            self.write(carry)?;
        }
        Ok(n)
    }

    /// A carried event must count under the current generation as it would there (6.2): an event
    /// of a removed device only when every removal's cutoff holds it, an event of a device the
    /// generation knows, and a `device added` only with a valid endorsement. So what a removed
    /// device made a lagging device write is not carried into a generation that left it out.
    fn carriable(&self, event: &Event, id: &EventId) -> bool {
        if self
            .allowed
            .get(&event.origin_author)
            .is_some_and(|a| !a.contains(id))
        {
            return false;
        }
        let Some(info) = self.current_info.as_ref() else {
            return false;
        };
        let author = event.origin_author;
        let EventKind::DeviceAdded(d) = &event.kind else {
            return author == self.device.device_id
                || info.member(&author).is_some()
                || self.view.devices.contains_key(&author);
        };
        if author != d.device_id
            && author != self.device.device_id
            && info.member(&author).is_none()
            && !self.view.devices.contains_key(&author)
        {
            return false;
        }
        let mut removed = self.view.removed();
        removed.extend(self.removed_known.iter().copied());
        let known = self
            .view
            .devices
            .values()
            .filter_map(|(_, e)| match &e.kind {
                EventKind::DeviceAdded(a) => Some(a),
                _ => None,
            })
            .chain(core::iter::once(d));
        valid_announcements(&self.header.vault_id, info, &removed, known)
            .contains(&(d.device_id, d.signature))
    }

    /// Deletes older-generation files the current generation already holds or supersedes, and old
    /// device slots, once the generation has been current here for the grace period. The time is
    /// this device's own, never one written into the folder.
    fn collect_garbage(&mut self) -> Result<usize, VaultError> {
        if self.current.number <= 1 || now() < self.current_first_seen.saturating_add(self.gc_grace)
        {
            return Ok(0);
        }
        let mut n = 0usize;
        for l in &self.old_files {
            if self.superseded(l) {
                fsutil::remove_in(
                    &self.vault_dir,
                    &[RECORDS_DIR, &format::device_dir_name(&l.writer)],
                    &l.name.file_name(),
                )?;
                n = n.saturating_add(1);
            }
        }
        self.remove_old_slots(&self.current)?;
        Ok(n)
    }

    fn needs_rotation(&self) -> bool {
        let mut removed = self.view.removed();
        if removed.contains(&self.device.device_id) || self.report.locked_out {
            return false;
        }
        removed.extend(self.pending_removals.values().map(|r| r.device));
        self.exposed || self.slot_holders.iter().any(|d| removed.contains(d))
    }

    /// The announcements that prove this device's membership in the current generation when its
    /// rotator did not list it: this device's, then each approver's, up to a listed member or the
    /// recovery key.
    fn endorsement_chain(&self, parent: &GenInfo) -> Result<Vec<DeviceAnnouncement>, VaultError> {
        let mut out = Vec::new();
        let mut cur = self.device.device_id;
        while parent.member(&cur).is_none() {
            if out.len() >= MAX_ENDORSEMENT_CHAIN {
                return Err(VaultError::NoAccess);
            }
            let ann = self.view.announcement(&cur).ok_or(VaultError::NoAccess)?;
            out.push(ann.clone());
            if ann.endorser == RECOVERY_ENDORSER {
                break;
            }
            cur = ann.endorser;
        }
        Ok(out)
    }

    /// The next generation excludes `extra_removed`, every already removed device and the pending
    /// removals. This device's own events from other generations that the view does not hold yet
    /// are re-written in it too, so they never pass through a generation a removed device can
    /// open. Never during a conflict: it would build on a generation other devices reject.
    fn rotate(&mut self, extra_removed: &[DeviceId]) -> Result<(), VaultError> {
        self.rotatable()?;
        let me = self.device.device_id;
        let vault_id = self.header.vault_id;
        let parent = self.current;
        let parent_key = self.current_key.clone();
        let parent_info = self.current_info.clone().ok_or(VaultError::NoAccess)?;
        let removed_before = self.view.removed_by_gen.clone();
        let mut removed_all = self.view.removed();
        removed_all.extend(extra_removed.iter().copied());
        if removed_all.contains(&me) {
            return Err(VaultError::CannotRemoveSelf);
        }
        let pending: Vec<Removal> = self.pending_removals.values().cloned().collect();
        removed_all.extend(pending.iter().map(|r| r.device));
        let chain = self.endorsement_chain(&parent_info)?;
        let mut merged = self.view.clone();
        for l in &self.stale_own {
            if !self.superseded(l) && self.carriable(&l.event, &l.id) {
                merged.apply(&l.event, &l.rel, l.name.lamport);
            }
        }
        let members: Vec<Member> = merged
            .devices
            .keys()
            .filter(|id| !removed_all.contains(*id))
            .filter_map(|id| merged.announcement(id))
            .map(member_of)
            .collect();
        if !members.iter().any(|m| m.device_id == me) {
            return Err(VaultError::NoAccess);
        }
        let new_id = GenId {
            number: parent
                .number
                .checked_add(1)
                .ok_or(VaultError::InvalidParameters)?,
            rotator: me,
        };
        // An earlier generation with this id that is not current: an attempt that never became
        // current, or one whose gen.info was deleted. Its key is replaced; this device's records
        // under it are carried above and deleted below.
        let replaced = self.keyring.get(&new_id).is_some();
        if !replaced && self.keyring.entries.len() >= MAX_GENERATIONS {
            return Err(VaultError::InvalidParameters);
        }
        let superseded_own: Vec<(DeviceId, String)> = self
            .stale_own
            .iter()
            .filter(|l| l.gen_id == new_id)
            .map(|l| (l.writer, l.name.file_name()))
            .collect();
        fsutil::vault_subdir(&self.vault_dir, &[KEYS_DIR])?.remove_tree(&new_id.dir_name())?;
        let gen_dir = fsutil::vault_subdir(&self.vault_dir, &[KEYS_DIR, &new_id.dir_name()])?;
        let key = random_key()?;

        let mut events: Vec<Origin> = merged.winners().into_iter().map(Origin::Keep).collect();
        let at = now();
        for d in extra_removed {
            if !merged.removals.contains_key(d) && !pending.iter().any(|r| r.device == *d) {
                events.push(Origin::Fresh(EventKind::DeviceRemoved {
                    device_id: *d,
                    at,
                }));
            }
        }
        let n = u64::try_from(events.len()).map_err(|_| VaultError::InvalidParameters)?;
        let start = self.allocate(n)?;

        for m in &members {
            fsutil::write_atomic(
                &gen_dir,
                &format::slot_name(&m.device_id),
                &format::seal_device_slot(
                    &vault_id,
                    &new_id,
                    &m.device_id,
                    &m.x25519_public,
                    &key,
                )?,
            )?;
        }
        fsutil::write_atomic(
            &gen_dir,
            RECOVERY_SLOT_NAME,
            &format::seal_recovery_slot(&vault_id, &new_id, &self.keyring.recovery_pub, &key)?,
        )?;
        let written = self.write_under(&new_id, &key, events, start)?;
        let mut by_origin: BTreeMap<DeviceId, BTreeSet<EventId>> = BTreeMap::new();
        let mut ids = Vec::with_capacity(written.len());
        for (e, _, _) in &written {
            let id = e.id(&vault_id)?;
            by_origin.entry(e.origin_author).or_default().insert(id);
            ids.push(id);
        }
        let mut removals: Vec<Removal> = Vec::new();
        for d in removed_all.difference(&removed_before) {
            let copied: Vec<&Removal> = pending.iter().filter(|r| r.device == *d).collect();
            if !copied.is_empty() {
                removals.extend(copied.into_iter().cloned());
                continue;
            }
            let (cause, cause_id) = written
                .iter()
                .zip(ids.iter())
                .find(|((e, _, _), _)| {
                    matches!(e.kind, EventKind::DeviceRemoved { device_id, .. } if device_id == *d)
                })
                .map(|((e, _, _), id)| (e.origin_author, *id))
                .ok_or(VaultError::InvalidParameters)?;
            removals.push(Removal {
                device: *d,
                cause_author: cause,
                cause: cause_id,
                cutoff: by_origin
                    .get(d)
                    .map(|s| s.iter().copied().collect())
                    .unwrap_or_default(),
            });
        }
        removals.sort_by_key(Removal::key);
        let info = GenInfo {
            commitment: format::commitment(&key, &vault_id, &new_id),
            recovery_pub: self.keyring.recovery_pub,
            removed: removals,
            created_at: at,
            reemit_first: start,
            reemit_count: n,
            recovery_tag: None,
            recovery_signing_pub: parent_info.recovery_signing_pub,
            members,
            chain,
        };
        {
            let _lock = StateLock::acquire(&self.state_dir)?;
            let mut keyring = match read_optional(&self.state_dir.join(STATE_KEYRING))? {
                Some(d) => Keyring::open(&d, &self.device)?,
                None => self.keyring.clone(),
            };
            keyring.entries.retain(|e| e.gen_id != new_id);
            keyring.entries.push(KeyringEntry {
                gen_id: new_id,
                key: key.clone(),
                root: false,
            });
            save_keyring(&self.state_dir, &keyring, &self.device)?;
            self.keyring = keyring;
        }
        fsutil::write_atomic(
            &gen_dir,
            GEN_INFO_NAME,
            &info.seal(
                &parent_key,
                &vault_id,
                &new_id,
                Some(&parent),
                &self.device.signing_seed,
            )?,
        )?;
        for (writer, file) in &superseded_own {
            fsutil::remove_in(
                &self.vault_dir,
                &[RECORDS_DIR, &format::device_dir_name(writer)],
                file,
            )?;
        }
        self.scan()
    }

    /// gen.info and recovery.slot stay: they form the chain a recovery walks.
    fn remove_old_slots(&self, newest: &GenId) -> Result<(), VaultError> {
        let keys_dir = self.vault_dir.join(KEYS_DIR);
        for name in fsutil::list(&keys_dir)? {
            let Some(id) = GenId::parse_dir(&name) else {
                continue;
            };
            if id.number >= newest.number || self.keyring.get(&id).is_none() {
                continue;
            }
            let Some(dir) = fsutil::existing_subdir(&self.vault_dir, &[KEYS_DIR, &name])
                .ok()
                .flatten()
            else {
                continue;
            };
            for f in dir.list()? {
                if f != RECOVERY_SLOT_NAME && f.ends_with(format::SLOT_SUFFIX) {
                    dir.remove(&f)?;
                }
            }
        }
        Ok(())
    }

    /// Deletes key generation directories outside this device's line: `targets`, every generation
    /// that rests on a device in `untrusted`, and everything built on them.
    fn discard_generations(
        &mut self,
        targets: &BTreeSet<GenId>,
        untrusted: &BTreeSet<DeviceId>,
    ) -> Result<usize, VaultError> {
        let mut doomed: BTreeSet<GenId> = targets
            .iter()
            .copied()
            .filter(|g| !self.current_chain.contains(g))
            .collect();
        for (id, t) in &self.tree {
            if !self.current_chain.contains(id) && t.path.iter().any(|d| untrusted.contains(d)) {
                doomed.insert(*id);
            }
        }
        loop {
            let more: Vec<GenId> = self
                .tree
                .iter()
                .filter(|(id, t)| {
                    !doomed.contains(id) && t.parent.is_some_and(|p| doomed.contains(&p))
                })
                .map(|(id, _)| *id)
                .collect();
            if more.is_empty() {
                break;
            }
            doomed.extend(more);
        }
        let mut n = 0usize;
        let Some(keys) = fsutil::existing_subdir(&self.vault_dir, &[KEYS_DIR])? else {
            return Ok(0);
        };
        for name in keys.list()? {
            let Some(id) = GenId::parse_dir(&name) else {
                continue;
            };
            if self.current_chain.contains(&id)
                || !(doomed.contains(&id) || untrusted.contains(&id.rotator))
            {
                continue;
            }
            keys.remove_tree(&name)?;
            n = n.saturating_add(1);
        }
        Ok(n)
    }

    /// Deletes the named key generation directory and everything built on it, after the user
    /// decided it is not theirs (for example one listed in `ScanReport::rejected`). Generations
    /// this device follows are refused. Returns false when the generation was not there.
    pub fn discard_generation(&mut self, gen_id: &GenId) -> Result<bool, VaultError> {
        self.scan()?;
        if self.current_chain.contains(gen_id) {
            return Err(VaultError::InvalidParameters);
        }
        let mut targets = BTreeSet::new();
        targets.insert(*gen_id);
        let present =
            fsutil::exists_no_follow(&self.vault_dir.join(KEYS_DIR).join(gen_id.dir_name()));
        self.discard_generations(&targets, &BTreeSet::new())?;
        self.scan()?;
        Ok(present)
    }

    /// Ends a reported fork by following the folder as it is now. Only for after the user
    /// checked that the folder is theirs (sync history restored, no untrusted device left with
    /// access): the line is cut back to the generation still present that this device serves,
    /// as the folder holds it now. Every removal the line made stays in force: generations that
    /// rest on a removed device stay void, and when a removed device holds a slot in the
    /// generation followed now, this device rotates before it writes anything (9.4).
    pub fn accept_fork(&mut self) -> Result<(), VaultError> {
        self.scan()?;
        {
            let _lock = StateLock::acquire(&self.state_dir)?;
            let mut line = self.computed_line.clone();
            if let Some(old) = read_line(&self.state_dir)? {
                for (k, r) in old.removed {
                    line.removed.entry(k).or_insert(r);
                }
            }
            fsutil::write_atomic(&self.state_dir, STATE_LINE, &line.encode()?)?;
        }
        self.scan()?;
        self.maintain();
        Ok(())
    }

    pub fn device_id(&self) -> DeviceId {
        self.device.device_id
    }

    #[cfg(test)]
    pub(crate) fn current_gen(&self) -> GenId {
        self.current
    }

    #[cfg(test)]
    pub(crate) fn announcement_of(&self, id: &DeviceId) -> Option<DeviceAnnouncement> {
        self.view.announcement(id).cloned()
    }

    pub fn vault_id(&self) -> [u8; 16] {
        self.header.vault_id
    }

    pub fn report(&self) -> &ScanReport {
        &self.report
    }

    /// `Err(VaultError::Removed)` once the line this device follows removed it. Commands that
    /// read or change passkeys (export, import, PIN reset) call this before doing anything.
    pub fn ensure_active(&self) -> Result<(), VaultError> {
        if self.report.this_device_removed {
            return Err(VaultError::Removed);
        }
        Ok(())
    }

    /// Nothing is served once this device was removed.
    pub fn get(&self, credential_id: &[u8]) -> Option<&CredentialRecord> {
        if self.report.this_device_removed {
            return None;
        }
        self.view.record(credential_id)
    }

    pub fn credentials_for_rp(&self, rp_id: &str) -> Vec<&CredentialRecord> {
        if self.report.this_device_removed {
            return Vec::new();
        }
        self.view.records().filter(|r| r.rp_id == rp_id).collect()
    }

    pub fn list_all(&self) -> Vec<&CredentialRecord> {
        if self.report.this_device_removed {
            return Vec::new();
        }
        self.view.records().collect()
    }

    pub fn devices(&self) -> Vec<DeviceInfo> {
        let mut removed = self.view.removed();
        removed.extend(self.removed_known.iter().copied());
        self.view
            .devices
            .values()
            .filter_map(|(_, e)| match &e.kind {
                EventKind::DeviceAdded(d) => Some(DeviceInfo {
                    id: d.device_id,
                    name: d.name.clone(),
                    added_at: d.added_at,
                    removed: removed.contains(&d.device_id),
                    this_device: d.device_id == self.device.device_id,
                    added_by: (d.endorser != RECOVERY_ENDORSER).then_some(d.endorser),
                }),
                _ => None,
            })
            .collect()
    }

    /// Active devices whose approval rests on `device_id`, directly or through other approved
    /// devices. Removing `device_id` keeps them (docs/vault-format.md, 9.2): each was approved
    /// while it was trusted, so the user has to decide about them one by one.
    pub fn devices_resting_on(&self, device_id: &DeviceId) -> Vec<DeviceInfo> {
        let all = self.devices();
        let endorser = |id: &DeviceId| self.view.announcement(id).map(|a| a.endorser);
        all.iter()
            .filter(|d| !d.removed && d.id != *device_id)
            .filter(|d| {
                let mut cur = d.id;
                for _ in 0..=MAX_ENDORSEMENT_CHAIN {
                    match endorser(&cur) {
                        Some(e) if e == *device_id => return true,
                        Some(e) if e != RECOVERY_ENDORSER => cur = e,
                        _ => return false,
                    }
                }
                false
            })
            .cloned()
            .collect()
    }

    /// WebAuthn BS flag: true once a second active device or a confirmed backup exists.
    pub fn backup_state(&self) -> bool {
        self.view.backup.is_some() || self.devices().iter().filter(|d| !d.removed).count() >= 2
    }

    pub fn put(&mut self, record: CredentialRecord) -> Result<(), VaultError> {
        record.validate()?;
        self.content_writable()?;
        self.write(vec![Origin::Fresh(EventKind::Put(Box::new(record)))])
    }

    /// Returns false if it does not exist.
    pub fn delete(&mut self, credential_id: &[u8]) -> Result<bool, VaultError> {
        let Some(id) = self
            .view
            .record(credential_id)
            .map(|r| r.credential_id.clone())
        else {
            return Ok(false);
        };
        self.content_writable()?;
        self.write(vec![Origin::Fresh(EventKind::Tombstone(id))])?;
        Ok(true)
    }

    pub fn confirm_backup(&mut self) -> Result<(), VaultError> {
        self.content_writable()?;
        self.write(vec![Origin::Fresh(EventKind::BackupConfirmed {
            at: now(),
        })])
    }

    /// Rotates the vault key so the device cannot read anything written from now on; it keeps
    /// whatever it already decrypted.
    pub fn remove_device(&mut self, device_id: &DeviceId) -> Result<(), VaultError> {
        self.scan()?;
        if *device_id == self.device.device_id {
            return Err(VaultError::CannotRemoveSelf);
        }
        if !self.view.devices.contains_key(device_id) {
            return Err(VaultError::UnknownDevice);
        }
        // The user decided this device is untrusted: discard key generations outside the current
        // line that it created or that rest on it, which resolves a conflict or fork it caused.
        let mut untrusted = BTreeSet::new();
        untrusted.insert(*device_id);
        if self.discard_generations(&BTreeSet::new(), &untrusted)? > 0 {
            self.scan()?;
        }
        if !self.view.removed_by_gen.contains(device_id) {
            self.rotate(&[*device_id])?;
        }
        // Carries this device's own events (its announcement among them, after a recovery join
        // during a conflict) into the generation it follows now.
        self.maintain();
        Ok(())
    }

    pub fn pairing_requests(&mut self) -> Result<Vec<PairingRequest>, VaultError> {
        self.pairing_requests_at(now())
    }

    /// Requests left out of the last `pairing_requests` list because it is capped
    /// (`pairing::MAX_LISTED_REQUESTS`).
    pub fn hidden_pairing_requests(&self) -> usize {
        self.hidden_requests
    }

    pub(crate) fn pairing_requests_at(
        &mut self,
        at: u64,
    ) -> Result<Vec<PairingRequest>, VaultError> {
        self.scan()?;
        let mut known: BTreeSet<DeviceId> = self.view.devices.keys().copied().collect();
        known.extend(self.view.removed());
        known.insert(self.device.device_id);
        let (list, hidden) = pairing::list_requests(&self.vault_dir, at, &known)?;
        self.hidden_requests = hidden;
        Ok(list)
    }

    /// Computed from this device's own view of the vault, never from claims in the request.
    pub fn pairing_words(&self, req: &PairingRequest) -> Result<String, VaultError> {
        let genesis = self.genesis()?;
        let fingerprint = pairing::genesis_fingerprint(&self.vault_dir, &genesis)?;
        pairing::words_text(&self.header.vault_id, &fingerprint, req)
    }

    fn genesis(&self) -> Result<GenId, VaultError> {
        self.keyring
            .entries
            .iter()
            .find(|e| e.root && e.gen_id.number == 1)
            .map(|e| e.gen_id)
            .ok_or(VaultError::NoAccess)
    }

    /// Approves `req` exactly as shown to the user; the caller must have had the user compare the words.
    pub fn approve_pairing(&mut self, req: &PairingRequest) -> Result<(), VaultError> {
        self.approve_pairing_at(req, now())
    }

    pub(crate) fn approve_pairing_at(
        &mut self,
        req: &PairingRequest,
        at: u64,
    ) -> Result<(), VaultError> {
        self.scan()?;
        self.content_writable()?;
        pairing::check_unchanged(&self.vault_dir, req, at)?;
        if req.device_id == self.device.device_id
            || self.view.devices.contains_key(&req.device_id)
            || self.view.removed().contains(&req.device_id)
        {
            return Err(VaultError::AlreadyExists);
        }
        let mut chain = Vec::with_capacity(self.current_chain.len());
        for id in &self.current_chain {
            let e = self.keyring.get(id).ok_or(VaultError::NoAccess)?;
            chain.push(KeyringEntry {
                gen_id: *id,
                key: e.key.clone(),
                root: e.root,
            });
        }
        if chain.first().map(|e| e.gen_id) != Some(self.genesis()?) {
            return Err(VaultError::NoAccess);
        }
        let vault_id = self.header.vault_id;
        let current = self.current;
        fsutil::write_atomic(
            &fsutil::vault_subdir(&self.vault_dir, &[KEYS_DIR, &current.dir_name()])?,
            &format::slot_name(&req.device_id),
            &format::seal_device_slot(
                &vault_id,
                &current,
                &req.device_id,
                &req.public_key,
                &self.current_key,
            )?,
        )?;
        pairing::write_approval(
            &self.vault_dir,
            req,
            &pairing::seal_approval(&vault_id, req, &chain)?,
        )?;
        let mut ann = DeviceAnnouncement {
            device_id: req.device_id,
            name: req.name.clone(),
            x25519_public: req.public_key,
            added_at: at,
            signing_public: req.signing_key,
            endorser: self.device.device_id,
            signature: [0u8; 64],
        };
        ann.endorse(&vault_id, &self.device.signing_seed)?;
        self.write(vec![Origin::Fresh(EventKind::DeviceAdded(ann))])?;
        pairing::remove_request(&self.vault_dir, &req.request_id)?;
        Ok(())
    }

    pub fn deny_pairing(&self, request_id: &[u8; 16]) -> Result<bool, VaultError> {
        pairing::remove_request(&self.vault_dir, request_id)
    }
}

pub(crate) enum KeyedJoin {
    Joined(Box<Vault>),
    /// The keys are genuine but the sync tool has not delivered everything yet.
    NotReady,
    Rejected(&'static str),
}

/// Every entry of `keyring` must be an authentic key generation of this folder whose key matches
/// its commitment, so keys made up by someone without the vault key are rejected.
pub(crate) fn join_with_keys(
    vault_dir: &Path,
    state_dir: &Path,
    header: Header,
    device: LocalDevice,
    keyring: Keyring,
) -> Result<KeyedJoin, VaultError> {
    let opener = Opener::Device {
        dev: &device,
        keyring: &keyring,
    };
    let snap = match snapshot(
        vault_dir,
        &header.vault_id,
        &opener,
        Some(&device),
        None,
        0,
        &mut VerifyCache::new(),
    ) {
        Ok(s) => s,
        Err(VaultError::NoAccess) => {
            return Ok(KeyedJoin::Rejected(
                "the approved keys do not open this vault",
            ));
        }
        Err(e) => return Err(e),
    };
    for e in &keyring.entries {
        let genuine = snap.resolved.accepted(&e.gen_id)
            && snap
                .resolved
                .nodes
                .get(&e.gen_id)
                .and_then(|n| n.key.as_ref())
                .is_some_and(|k| hirz_crypto::ct_eq(k.as_slice(), e.key.as_slice()));
        if !genuine {
            return Ok(KeyedJoin::Rejected(
                "the approved keys do not match the vault's key generations",
            ));
        }
    }
    if snap.report.locked_out || snap.report.rotation_conflict {
        return Ok(KeyedJoin::NotReady);
    }
    let node = snap
        .resolved
        .nodes
        .get(&snap.current)
        .ok_or(VaultError::NoAccess)?;
    let public = hirz_crypto::x25519::public_key(&device.x25519_private)?;
    let signing = device.signing_public()?;
    let announced = snap.loaded.iter().any(|l| {
        l.gen_id == snap.current
            && !node.removed_cum.contains(&l.writer)
            && matches!(&l.event.kind, EventKind::DeviceAdded(d)
                if d.device_id == device.device_id
                    && d.x25519_public == public
                    && d.signing_public == signing)
    });
    if !announced {
        return Ok(KeyedJoin::NotReady);
    }
    if Vault::is_set_up(state_dir) {
        return Err(VaultError::AlreadyExists);
    }
    fsutil::state_dir(state_dir)?;
    let full = Keyring {
        recovery_pub: keyring.recovery_pub,
        entries: snap
            .resolved
            .keyed()
            .map(|(n, k)| KeyringEntry {
                gen_id: n.id,
                key: k.clone(),
                root: n.parent.is_none(),
            })
            .collect(),
    };
    save_device(state_dir, &device)?;
    save_keyring(state_dir, &full, &device)?;
    let vault = Vault::assemble(vault_dir, state_dir, header, device, full)?;
    Ok(KeyedJoin::Joined(Box::new(vault)))
}

/// The device id is derived from the signing key (docs/vault-format.md, 5.2).
pub(crate) fn new_device(vault_id: [u8; 16], name: &str) -> Result<LocalDevice, VaultError> {
    let (x_private, _) = hirz_crypto::x25519::generate()?;
    let signing_seed = random_key()?;
    let signing_public = hirz_crypto::ed25519::public_from_seed(&signing_seed)?;
    Ok(LocalDevice {
        vault_id,
        device_id: device_id_for(&signing_public),
        secret: random_key()?,
        x25519_private: to_key(&x_private)?,
        name: name.to_string(),
        signing_seed,
    })
}

fn save_device(state_dir: &Path, device: &LocalDevice) -> Result<(), VaultError> {
    fsutil::write_atomic(state_dir, STATE_DEVICE, &device.encode()?)
}

fn save_keyring(
    state_dir: &Path,
    keyring: &Keyring,
    device: &LocalDevice,
) -> Result<(), VaultError> {
    fsutil::write_atomic(state_dir, STATE_KEYRING, &keyring.seal(device)?)
}

#[cfg(test)]
mod merge_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn tombstone_wins_tie_and_order_is_total() {
        let rec = crate::record::CredentialRecord {
            credential_id: vec![1; 32],
            rp_id: "example.com".into(),
            rp_name: None,
            user_id: vec![1],
            user_name: None,
            user_display_name: None,
            algorithm: -8,
            private_key_pkcs8: Zeroizing::new(vec![1, 2, 3]),
            created_at: 0,
            cred_protect: None,
            hmac_secret: None,
            discoverable: true,
            backup_eligible: true,
        };
        let put = Event {
            kind: EventKind::Put(Box::new(rec)),
            origin_author: [5; 16],
            origin_lamport: 7,
            signer: [0; 32],
            signature: [0; 64],
        };
        let tomb = Event {
            kind: EventKind::Tombstone(vec![1; 32]),
            origin_author: [5; 16],
            origin_lamport: 7,
            signer: [0; 32],
            signature: [0; 64],
        };
        for order in [[&put, &tomb], [&tomb, &put]] {
            let mut v = View::default();
            v.apply(order[0], "records/x/a", 7);
            v.apply(order[1], "records/x/b", 7);
            assert!(v.record(&[1; 32]).is_none());
        }
        let mut newer = put.clone();
        newer.origin_lamport = 8;
        let mut v = View::default();
        v.apply(&tomb, "records/x/b", 7);
        v.apply(&newer, "records/x/c", 8);
        assert!(v.record(&[1; 32]).is_some());
        let mut higher_device = put.clone();
        higher_device.origin_author = [6; 16];
        let mut v = View::default();
        v.apply(&higher_device, "records/y/a", 7);
        v.apply(&tomb, "records/x/b", 7);
        assert!(
            v.record(&[1; 32]).is_some(),
            "(lamport, device) decides before kind"
        );
    }
}
