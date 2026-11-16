//! Vault operations: key generations, scanning, merging, writing, rotation.

use crate::DeviceId;
use crate::codec::hex;
use crate::error::{VaultError, io};
use crate::format::{
    self, Counter, GEN_INFO_NAME, GenId, GenInfo, HEADER_NAME, Header, KEYS_DIR, Keyring,
    KeyringEntry, LocalDevice, RECORDS_DIR, RECOVERY_SLOT_NAME, RecordName, SLOT_SUFFIX,
    STATE_COUNTER, STATE_DEVICE, STATE_KEYRING, VaultKey,
};
use crate::fsutil::{self, MAX_FILE_LEN, StateLock};
use crate::record::{
    CredentialRecord, DeviceAnnouncement, Event, EventKind, MAX_DEVICE_NAME_LEN, append_tag,
};
use crate::recovery::RecoveryPhrase;
use hirz_crypto::Zeroizing;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const GC_GRACE_SECS: u64 = 24 * 60 * 60;

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random16() -> Result<[u8; 16], VaultError> {
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

/// A file the scan could not use, with the reason. Never fatal for the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedFile {
    /// Path relative to the vault directory.
    pub path: String,
    pub reason: &'static str,
}

/// What the last `reload` found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanReport {
    /// Number of the key generation in use.
    pub generation: u32,
    /// Live credentials.
    pub credentials: usize,
    /// Events merged into the view.
    pub events: usize,
    /// Files and directories that are not part of the format (temp files, sync-tool conflict
    /// copies, unknown names). Ignored.
    pub ignored_files: usize,
    /// Files with a valid name that are corrupt or fail authentication. Ignored.
    pub skipped: Vec<SkippedFile>,
    /// Record files under a key generation other than the current one.
    pub other_generation_files: usize,
    /// Key generations rejected because they conflict with a device removal.
    pub rejected_generations: usize,
    /// Rejected generations exist above the current one: two rotations removed each other's
    /// creators. Content writes are refused until the user removes the untrusted device
    /// again (after revoking its access to the synced folder).
    pub rotation_conflict: bool,
    /// A newer key generation exists that this device holds no key for (it was removed, or
    /// was not yet known when the vault key was rotated).
    pub locked_out: bool,
    /// The highest event counter in the folder is lower than one this device saw before:
    /// files were withheld or rolled back.
    pub rollback_suspected: bool,
    /// Own events re-written under the current generation during this reload.
    pub migrated: usize,
    /// This reload rotated the vault key (a removed device still held a key slot).
    pub rotated: bool,
    /// Superseded files of older generations deleted during this reload.
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

/// A device of the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub id: DeviceId,
    pub name: String,
    pub added_at: u64,
    pub removed: bool,
    pub this_device: bool,
}

#[derive(Debug)]
struct GenNode {
    id: GenId,
    key: Option<VaultKey>,
    parent: Option<GenId>,
    info: GenInfo,
    removed_cum: BTreeSet<DeviceId>,
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
    },
}

#[derive(Debug, Clone)]
struct Loaded {
    path: PathBuf,
    rel: String,
    writer: DeviceId,
    name: RecordName,
    gen_id: GenId,
    event: Event,
    /// The author tag verifies with this device's secret.
    own: bool,
}

/// Merge order: origin counter, origin device, tombstone over put, then the file path so the
/// result is deterministic even for exact duplicates.
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

#[derive(Debug, Default)]
struct View {
    /// Keyed by the full credential id, so lookups are exact matches of any length.
    creds: BTreeMap<Vec<u8>, (OrderKey, Event)>,
    devices: BTreeMap<DeviceId, (OrderKey, Event)>,
    removals: BTreeMap<DeviceId, (OrderKey, Event)>,
    backup: Option<(OrderKey, Event)>,
    /// Removed per the key generation chain.
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

    /// The order key the view already holds for the entity this event is about.
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

    /// Every winning event, for re-writing under a new generation.
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

/// Result of resolving the key generation chain.
#[derive(Debug, Default)]
struct Resolved {
    /// Authentic, non-rejected generations. `key` is None where this device has no slot.
    nodes: BTreeMap<GenId, GenNode>,
    rejected: BTreeSet<GenId>,
}

impl Resolved {
    fn keyed(&self) -> impl Iterator<Item = (&GenNode, &VaultKey)> {
        self.nodes
            .values()
            .filter_map(|n| n.key.as_ref().map(|k| (n, k)))
    }
}

fn open_candidate_key(
    opener: &Opener<'_>,
    vault_dir: &Path,
    vault_id: &[u8; 16],
    id: &GenId,
    report: &mut ScanReport,
) -> Option<VaultKey> {
    let dir = vault_dir.join(KEYS_DIR).join(id.dir_name());
    match opener {
        Opener::Device { dev, keyring } => {
            if let Some(e) = keyring.get(id) {
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

/// Builds the generation graph. A generation is authentic when its gen.info opens under its
/// parent's key (or, for the genesis, is anchored in the keyring or the recovery key). Its
/// own key comes from the keyring or this device's slot and must match the commitment.
/// Generations without a key for this device still take part in conflict detection, so all
/// devices that hold the parent key reach the same decision.
fn resolve(
    vault_dir: &Path,
    vault_id: &[u8; 16],
    opener: &Opener<'_>,
    report: &mut ScanReport,
) -> Result<Resolved, VaultError> {
    let keys_dir = vault_dir.join(KEYS_DIR);
    let mut ids = BTreeSet::new();
    for name in fsutil::list(&keys_dir)? {
        match GenId::parse_dir(&name) {
            Some(id) if keys_dir.join(&name).is_dir() => {
                ids.insert(id);
            }
            _ => report.ignore(),
        }
    }
    let mut out = Resolved::default();
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
                    continue;
                };
                let Some(pkey) = pnode.key.as_ref() else {
                    continue;
                };
                if pid.number.checked_add(1) != Some(id.number) {
                    report.skip(info_rel, "generation number does not follow its parent");
                    continue;
                }
                if pnode.removed_cum.contains(&id.rotator) {
                    out.rejected.insert(id);
                    continue;
                }
                let info = match GenInfo::open(&data, pkey, vault_id, &id) {
                    Ok(i) => i,
                    Err(_) => {
                        report.skip(info_rel, "gen.info does not authenticate");
                        continue;
                    }
                };
                if info.recovery_pub != pnode.info.recovery_pub {
                    report.skip(info_rel, "recovery key changed");
                    continue;
                }
                let mut key = open_candidate_key(opener, vault_dir, vault_id, &id, report);
                if key.as_ref().is_some_and(|k| {
                    !hirz_crypto::ct_eq(&info.commitment, &format::commitment(k, vault_id, &id))
                }) {
                    report.skip(info_rel, "key does not match the generation commitment");
                    key = None;
                }
                let mut removed_cum = pnode.removed_cum.clone();
                removed_cum.extend(info.removed.iter().copied());
                Some(GenNode {
                    id,
                    key,
                    parent,
                    info,
                    removed_cum,
                })
            }
        };
        if let Some(n) = node {
            out.nodes.insert(id, n);
        }
    }
    reject_conflicting(&mut out);
    report.rejected_generations = out.rejected.len();
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
    let key = open_candidate_key(opener, vault_dir, vault_id, id, report)?;
    let Ok(info) = GenInfo::open(data, &key, vault_id, id) else {
        report.skip(info_rel, "gen.info does not authenticate");
        return None;
    };
    if !hirz_crypto::ct_eq(&info.commitment, &format::commitment(&key, vault_id, id)) {
        report.skip(info_rel, "key does not match the generation commitment");
        return None;
    }
    if let Opener::Recovery { auth, public, .. } = opener {
        let expected =
            format::genesis_tag(auth, vault_id, id, &info.commitment, &info.recovery_pub);
        let tag_ok = info
            .recovery_tag
            .is_some_and(|t| hirz_crypto::ct_eq(&t, &expected));
        if !tag_ok || info.recovery_pub != *public {
            report.skip(info_rel, "genesis not authenticated by the recovery key");
            return None;
        }
    }
    Some(GenNode {
        id: *id,
        key: Some(key),
        parent: None,
        removed_cum: info.removed.iter().copied().collect(),
        info,
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

/// A generation is rejected when a generation outside its own line of descent removed the
/// device that created it (a removed device racing the rotation that removed it), and so is
/// everything built on top of a rejected generation. All accusations count at once, so two
/// generations that remove each other's creators are both rejected: hirz cannot tell which
/// device is the legitimate one, and the user has to decide.
fn reject_conflicting(res: &mut Resolved) {
    let nodes = &res.nodes;
    let ids: Vec<GenId> = nodes.keys().copied().collect();
    let anc: BTreeMap<GenId, BTreeSet<GenId>> =
        ids.iter().map(|d| (*d, ancestors(nodes, *d))).collect();
    let mut rejected = BTreeSet::new();
    for c in &ids {
        if nodes.get(c).is_none_or(|n| n.parent.is_none()) {
            continue;
        }
        let accused = ids.iter().any(|d| {
            d != c
                && !anc.get(d).is_some_and(|a| a.contains(c))
                && nodes
                    .get(d)
                    .is_some_and(|n| n.removed_cum.contains(&c.rotator))
        });
        if accused {
            rejected.insert(*c);
        }
    }
    for d in &ids {
        if anc
            .get(d)
            .is_some_and(|a| a.iter().any(|x| rejected.contains(x)))
        {
            rejected.insert(*d);
        }
    }
    for r in &rejected {
        res.nodes.remove(r);
    }
    res.rejected.extend(rejected);
}

fn load_records(
    vault_dir: &Path,
    vault_id: &[u8; 16],
    me: Option<&LocalDevice>,
    keys: &BTreeMap<GenId, VaultKey>,
    report: &mut ScanReport,
) -> Result<Vec<Loaded>, VaultError> {
    let records_dir = vault_dir.join(RECORDS_DIR);
    let mut out = Vec::new();
    for dir_name in fsutil::list(&records_dir)? {
        let dir = records_dir.join(&dir_name);
        let Some(writer) = format::parse_device_dir(&dir_name).filter(|_| dir.is_dir()) else {
            report.ignore();
            continue;
        };
        for name in fsutil::list(&dir)? {
            let Some(rn) = RecordName::parse(&name) else {
                report.ignore();
                continue;
            };
            let rel = format::record_rel_path(&writer, &rn);
            let path = dir.join(&name);
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
            let pt = match format::open_record(&data, key, vault_id, &gen_id, &rel) {
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
            let own = match (me, pt.get(..body_len)) {
                (Some(dev), Some(body)) if dev.device_id == writer => {
                    hirz_crypto::ct_eq(&tag, &format::author_tag(&dev.secret, vault_id, &rel, body))
                }
                _ => false,
            };
            out.push(Loaded {
                path,
                rel,
                writer,
                name: rn,
                gen_id,
                event,
                own,
            });
        }
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
                && l.writer == node.id.rotator
                && l.name.lamport >= first
                && l.name.lamport < end
        })
        .map(|l| l.name.lamport)
        .collect();
    u64::try_from(found.len()).is_ok_and(|n| n == node.info.reemit_count)
}

/// Everything a scan learned, before it becomes the vault's view.
#[derive(Debug)]
struct Snapshot {
    resolved: Resolved,
    loaded: Vec<Loaded>,
    current: GenId,
    report: ScanReport,
}

fn snapshot(
    vault_dir: &Path,
    vault_id: &[u8; 16],
    opener: &Opener<'_>,
    me: Option<&LocalDevice>,
) -> Result<Snapshot, VaultError> {
    let mut report = ScanReport::default();
    let resolved = resolve(vault_dir, vault_id, opener, &mut report)?;
    let mut keys: BTreeMap<GenId, VaultKey> =
        resolved.keyed().map(|(n, k)| (n.id, k.clone())).collect();
    if let Opener::Device { keyring, .. } = opener {
        for e in &keyring.entries {
            keys.entry(e.gen_id).or_insert_with(|| e.key.clone());
        }
    }
    let loaded = load_records(vault_dir, vault_id, me, &keys, &mut report)?;
    let current = resolved
        .keyed()
        .filter(|(n, _)| is_complete(n, &loaded))
        .map(|(n, _)| n.id)
        .max()
        .ok_or(VaultError::NoAccess)?;
    report.generation = current.number;
    report.locked_out = resolved
        .nodes
        .values()
        .any(|n| n.key.is_none() && n.id.number > current.number);
    report.rotation_conflict = resolved.rejected.iter().any(|g| g.number > current.number);
    Ok(Snapshot {
        resolved,
        loaded,
        current,
        report,
    })
}

fn read_header(vault_dir: &Path) -> Result<Header, VaultError> {
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

/// An encrypted, folder-synced credential vault opened by one device.
pub struct Vault {
    vault_dir: PathBuf,
    state_dir: PathBuf,
    header: Header,
    pub(crate) device: LocalDevice,
    pub(crate) keyring: Keyring,
    current: GenId,
    current_key: VaultKey,
    /// Devices that hold a slot in the current generation.
    slot_holders: BTreeSet<DeviceId>,
    current_created_at: u64,
    /// The current generation and its ancestors.
    current_chain: BTreeSet<GenId>,
    /// Record files under older or sibling generations, candidates for garbage collection.
    old_files: Vec<Loaded>,
    /// Seconds a generation must be current before superseded older files are deleted, so a
    /// device that receives the deletions before the new files never sees an empty vault.
    pub(crate) gc_grace: u64,
    /// Own events under other generations that may need to be carried forward.
    stale_own: Vec<Loaded>,
    view: View,
    report: ScanReport,
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

enum Origin {
    Fresh,
    Keep(DeviceId, u64),
}

impl Vault {
    /// True when `vault_dir` holds a vault header. Says nothing about whether it is valid.
    pub fn exists(vault_dir: &Path) -> bool {
        vault_dir.join(HEADER_NAME).exists()
    }

    /// True when `state_dir` holds the local state of a device (this machine joined a vault).
    pub fn is_set_up(state_dir: &Path) -> bool {
        state_dir.join(STATE_DEVICE).exists()
    }

    /// Checks that `phrase` is the recovery phrase of the vault in `vault_dir`, without local
    /// device state and without reading any credential: it walks the key generations with
    /// the recovery key, as joining does. Errors only when the header is missing or unreadable.
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
        };
        let mut report = ScanReport::default();
        let resolved = resolve(vault_dir, &header.vault_id, &opener, &mut report)?;
        Ok(resolved.keyed().next().is_some())
    }

    /// Creates a new vault in `vault_dir` and registers this device with its local state in
    /// `state_dir`. Returns the recovery phrase, which must be shown to the user once.
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
        let genesis = GenId {
            number: 1,
            rotator: device.device_id,
        };
        let key = random_key()?;
        let gen_dir = vault_dir.join(KEYS_DIR).join(genesis.dir_name());
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
            )),
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
            &info.seal(&key, &header.vault_id, &genesis, None)?,
        )?;
        fsutil::write_atomic(vault_dir, HEADER_NAME, &header.encode())?;
        let mut vault = Vault::assemble(vault_dir, state_dir, header, device, keyring)?;
        vault.announce_self(device_pub)?;
        Ok((vault, phrase))
    }

    /// Opens an existing vault with this device's local state.
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

    /// Adds this machine as a new device of an existing vault, using the recovery phrase.
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
        };
        let snap = match snapshot(vault_dir, &header.vault_id, &opener, None) {
            Ok(s) => s,
            Err(VaultError::NoAccess) => return Err(VaultError::WrongRecoveryKey),
            Err(e) => return Err(e),
        };
        fsutil::state_dir(state_dir)?;
        let device = new_device(header.vault_id, device_name)?;
        let keyring = Keyring {
            recovery_pub: public,
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
            &vault_dir.join(KEYS_DIR).join(snap.current.dir_name()),
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
        vault.announce_self(device_pub)?;
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
            slot_holders: BTreeSet::new(),
            current_created_at: 0,
            current_chain: BTreeSet::new(),
            old_files: Vec::new(),
            gc_grace: GC_GRACE_SECS,
            stale_own: Vec::new(),
            view: View::default(),
            report: ScanReport::default(),
        };
        vault.scan()?;
        Ok(vault)
    }

    fn announce_self(&mut self, device_pub: [u8; 32]) -> Result<(), VaultError> {
        let ann = DeviceAnnouncement {
            device_id: self.device.device_id,
            name: self.device.name.clone(),
            x25519_public: device_pub,
            added_at: now(),
        };
        self.write(vec![(EventKind::DeviceAdded(ann), Origin::Fresh)])
    }

    /// Re-reads the folder (after the sync tool brought new files), then carries this device's
    /// own events forward to the current key generation and finishes a pending rotation.
    pub fn reload(&mut self) -> Result<&ScanReport, VaultError> {
        self.scan()?;
        self.maintain();
        Ok(&self.report)
    }

    fn maintain(&mut self) {
        // During a rotation conflict the current key may be held by the device being
        // removed, so nothing is done automatically until the user removes it again.
        if self.report.rotation_conflict {
            return;
        }
        let mut migrated = 0usize;
        let mut rotated = false;
        let mut collected = 0usize;
        let mut error = None;
        if !self.stale_own.is_empty() {
            match self.migrate_stale() {
                Ok(n) => migrated = n,
                Err(e) => error = Some(e),
            }
        }
        if error.is_none() && self.needs_rotation() {
            match self.rotate(&[]) {
                Ok(()) => rotated = true,
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
        let opener = Opener::Device {
            dev: &self.device,
            keyring: &self.keyring,
        };
        let snap = snapshot(
            &self.vault_dir,
            &self.header.vault_id,
            &opener,
            Some(&self.device),
        )?;
        let Snapshot {
            resolved,
            loaded,
            current,
            mut report,
        } = snap;
        let node = resolved.nodes.get(&current).ok_or(VaultError::NoAccess)?;
        let mut view = View {
            removed_by_gen: node.removed_cum.clone(),
            ..View::default()
        };
        let mut old_files = Vec::new();
        let mut stale_own = Vec::new();
        let mut folder_max = 0u64;
        for l in &loaded {
            if resolved.nodes.contains_key(&l.gen_id) {
                folder_max = folder_max.max(l.name.lamport);
            }
            if l.gen_id == current {
                if !node.removed_cum.contains(&l.writer) {
                    view.apply(&l.event, &l.rel, l.name.lamport);
                }
            } else {
                report.other_generation_files = report.other_generation_files.saturating_add(1);
                if l.own
                    && (l.gen_id.number <= current.number
                        || !resolved.nodes.contains_key(&l.gen_id))
                {
                    stale_own.push(l.clone());
                }
                if l.gen_id.number <= current.number {
                    old_files.push(l.clone());
                }
            }
        }
        view.max_lamport = view.max_lamport.max(folder_max);

        let mut slot_holders = BTreeSet::new();
        for name in fsutil::list(&self.vault_dir.join(KEYS_DIR).join(current.dir_name()))? {
            if let Some(id) = name
                .strip_suffix(SLOT_SUFFIX)
                .and_then(format::parse_device_dir)
            {
                slot_holders.insert(id);
            }
        }

        let new_entries: Vec<KeyringEntry> = resolved
            .keyed()
            .filter(|(n, _)| self.keyring.get(&n.id).is_none())
            .map(|(n, k)| KeyringEntry {
                gen_id: n.id,
                key: k.clone(),
                root: false,
            })
            .collect();
        let counter = read_counter(&self.state_dir)?;
        report.rollback_suspected = folder_max < counter.max_seen;
        if !new_entries.is_empty() || folder_max > counter.max_seen {
            let _lock = StateLock::acquire(&self.state_dir)?;
            if !new_entries.is_empty() {
                let mut keyring = match read_optional(&self.state_dir.join(STATE_KEYRING))? {
                    Some(d) => Keyring::open(&d, &self.device)?,
                    None => self.keyring.clone(),
                };
                for e in new_entries {
                    if keyring.get(&e.gen_id).is_none() {
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
        }

        report.credentials = view.records().count();
        report.events = view.events;
        self.current = current;
        self.current_key = node.key.clone().ok_or(VaultError::NoAccess)?;
        self.slot_holders = slot_holders;
        self.current_created_at = node.info.created_at;
        self.current_chain = ancestors(&resolved.nodes, current);
        self.old_files = old_files;
        self.stale_own = stale_own;
        self.view = view;
        self.report = report;
        Ok(())
    }

    fn writable(&self) -> Result<(), VaultError> {
        if self.report.locked_out || self.view.removed().contains(&self.device.device_id) {
            return Err(VaultError::NoAccess);
        }
        Ok(())
    }

    /// Content writes also stop during a rotation conflict: the current key may be held by
    /// the device the user is trying to remove.
    fn content_writable(&self) -> Result<(), VaultError> {
        self.writable()?;
        if self.report.rotation_conflict {
            return Err(VaultError::RotationConflict);
        }
        Ok(())
    }

    /// Reserves `n` consecutive event counters under the state lock.
    fn allocate(&self, n: u64) -> Result<u64, VaultError> {
        let _lock = StateLock::acquire(&self.state_dir)?;
        let mut c = read_counter(&self.state_dir)?;
        let floor = self.view.max_lamport.max(c.max_seen).saturating_add(1);
        let start = c.next.max(floor).max(1);
        c.next = start.checked_add(n).ok_or(VaultError::InvalidParameters)?;
        fsutil::write_atomic(&self.state_dir, STATE_COUNTER, &c.encode())?;
        Ok(start)
    }

    /// Writes events under `gen_id`, consuming counters from `start`.
    fn write_under(
        &self,
        gen_id: &GenId,
        key: &[u8; 32],
        events: Vec<(EventKind, Origin)>,
        start: u64,
    ) -> Result<Vec<(Event, String, u64)>, VaultError> {
        let dir = self
            .vault_dir
            .join(RECORDS_DIR)
            .join(format::device_dir_name(&self.device.device_id));
        let mut written = Vec::with_capacity(events.len());
        let mut lamport = start;
        for (kind, origin) in events {
            let (origin_author, origin_lamport) = match origin {
                Origin::Fresh => (self.device.device_id, lamport),
                Origin::Keep(a, l) => (a, l),
            };
            let event = Event {
                kind,
                origin_author,
                origin_lamport,
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

    /// Writes events under the current generation and merges them into the view.
    fn write(&mut self, events: Vec<(EventKind, Origin)>) -> Result<(), VaultError> {
        self.writable()?;
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

    /// Carries this device's own events from other generations into the current one, keeping
    /// their merge identity. Only events whose author tag verifies are carried, so a removed
    /// device holding an old key cannot plant events for this device to adopt.
    fn migrate_stale(&mut self) -> Result<usize, VaultError> {
        self.writable()?;
        let stale = core::mem::take(&mut self.stale_own);
        let mut carry = Vec::new();
        for l in &stale {
            if !self.superseded(l) {
                carry.push((
                    l.event.kind.clone(),
                    Origin::Keep(l.event.origin_author, l.event.origin_lamport),
                ));
            }
        }
        let n = carry.len();
        if !carry.is_empty() {
            self.write(carry)?;
        }
        Ok(n)
    }

    /// Deletes files of older generations whose content the current generation already holds
    /// (or supersedes), and device slots of older generations, once the grace period passed.
    fn collect_garbage(&mut self) -> Result<usize, VaultError> {
        if self.current.number <= 1 || now() < self.current_created_at.saturating_add(self.gc_grace)
        {
            return Ok(0);
        }
        let mut n = 0usize;
        for l in &self.old_files {
            if self.superseded(l) {
                fsutil::remove_file(&l.path)?;
                n = n.saturating_add(1);
            }
        }
        self.remove_old_slots(&self.current)?;
        Ok(n)
    }

    fn needs_rotation(&self) -> bool {
        let removed = self.view.removed();
        !removed.contains(&self.device.device_id)
            && !self.report.locked_out
            && self.slot_holders.iter().any(|d| removed.contains(d))
    }

    /// Creates the next key generation without `extra_removed` and every device already
    /// removed, re-writes every winning event under it, then deletes the superseded files.
    fn rotate(&mut self, extra_removed: &[DeviceId]) -> Result<(), VaultError> {
        self.writable()?;
        let vault_id = self.header.vault_id;
        let parent = self.current;
        let parent_key = self.current_key.clone();
        let removed_before = self.view.removed_by_gen.clone();
        let mut removed_all = self.view.removed();
        removed_all.extend(extra_removed.iter().copied());
        if removed_all.contains(&self.device.device_id) {
            return Err(VaultError::CannotRemoveSelf);
        }
        let new_id = GenId {
            number: parent
                .number
                .checked_add(1)
                .ok_or(VaultError::InvalidParameters)?,
            rotator: self.device.device_id,
        };
        let gen_dir = self.vault_dir.join(KEYS_DIR).join(new_id.dir_name());
        if gen_dir.exists() {
            // An earlier attempt of this device that never became current.
            std::fs::remove_dir_all(&gen_dir).map_err(io("remove abandoned generation"))?;
        }
        let key = random_key()?;

        let mut events: Vec<(EventKind, Origin)> = self
            .view
            .winners()
            .into_iter()
            .map(|e| (e.kind, Origin::Keep(e.origin_author, e.origin_lamport)))
            .collect();
        let at = now();
        for d in extra_removed {
            if !self.view.removals.contains_key(d) {
                events.push((
                    EventKind::DeviceRemoved { device_id: *d, at },
                    Origin::Fresh,
                ));
            }
        }
        let n = u64::try_from(events.len()).map_err(|_| VaultError::InvalidParameters)?;
        let start = self.allocate(n)?;

        for (id, (_, e)) in &self.view.devices {
            if removed_all.contains(id) {
                continue;
            }
            if let EventKind::DeviceAdded(d) = &e.kind {
                fsutil::write_atomic(
                    &gen_dir,
                    &format::slot_name(id),
                    &format::seal_device_slot(&vault_id, &new_id, id, &d.x25519_public, &key)?,
                )?;
            }
        }
        fsutil::write_atomic(
            &gen_dir,
            RECOVERY_SLOT_NAME,
            &format::seal_recovery_slot(&vault_id, &new_id, &self.keyring.recovery_pub, &key)?,
        )?;
        self.write_under(&new_id, &key, events, start)?;
        let info = GenInfo {
            commitment: format::commitment(&key, &vault_id, &new_id),
            recovery_pub: self.keyring.recovery_pub,
            removed: removed_all.difference(&removed_before).copied().collect(),
            created_at: at,
            reemit_first: start,
            reemit_count: n,
            recovery_tag: None,
        };
        {
            let _lock = StateLock::acquire(&self.state_dir)?;
            let mut keyring = match read_optional(&self.state_dir.join(STATE_KEYRING))? {
                Some(d) => Keyring::open(&d, &self.device)?,
                None => self.keyring.clone(),
            };
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
            &info.seal(&parent_key, &vault_id, &new_id, Some(&parent))?,
        )?;
        self.scan()
    }

    /// Device slots of older generations are no longer needed once a newer one exists;
    /// gen.info and recovery.slot stay because they form the chain a recovery walks.
    fn remove_old_slots(&self, newest: &GenId) -> Result<(), VaultError> {
        let keys_dir = self.vault_dir.join(KEYS_DIR);
        for name in fsutil::list(&keys_dir)? {
            let Some(id) = GenId::parse_dir(&name) else {
                continue;
            };
            if id.number >= newest.number || self.keyring.get(&id).is_none() {
                continue;
            }
            let dir = keys_dir.join(&name);
            for f in fsutil::list(&dir)? {
                if f != RECOVERY_SLOT_NAME && f.ends_with(SLOT_SUFFIX) {
                    fsutil::remove_file(&dir.join(&f))?;
                }
            }
        }
        Ok(())
    }

    // ---- public queries ----

    pub fn device_id(&self) -> DeviceId {
        self.device.device_id
    }

    pub fn vault_id(&self) -> [u8; 16] {
        self.header.vault_id
    }

    /// The report of the last scan.
    pub fn report(&self) -> &ScanReport {
        &self.report
    }

    pub fn get(&self, credential_id: &[u8]) -> Option<&CredentialRecord> {
        self.view.record(credential_id)
    }

    pub fn credentials_for_rp(&self, rp_id: &str) -> Vec<&CredentialRecord> {
        self.view.records().filter(|r| r.rp_id == rp_id).collect()
    }

    pub fn list_all(&self) -> Vec<&CredentialRecord> {
        self.view.records().collect()
    }

    pub fn devices(&self) -> Vec<DeviceInfo> {
        let removed = self.view.removed();
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
                }),
                _ => None,
            })
            .collect()
    }

    /// WebAuthn BS flag: true once a second active device or a confirmed backup exists.
    pub fn backup_state(&self) -> bool {
        self.view.backup.is_some() || self.devices().iter().filter(|d| !d.removed).count() >= 2
    }

    // ---- public writes ----

    /// Stores a credential (new, or replacing the one with the same credential id).
    pub fn put(&mut self, record: CredentialRecord) -> Result<(), VaultError> {
        record.validate()?;
        self.content_writable()?;
        self.write(vec![(EventKind::Put(Box::new(record)), Origin::Fresh)])
    }

    /// Deletes a credential. Returns false if it does not exist.
    pub fn delete(&mut self, credential_id: &[u8]) -> Result<bool, VaultError> {
        let Some(id) = self
            .view
            .record(credential_id)
            .map(|r| r.credential_id.clone())
        else {
            return Ok(false);
        };
        self.content_writable()?;
        self.write(vec![(EventKind::Tombstone(id), Origin::Fresh)])?;
        Ok(true)
    }

    /// Records that the user completed a backup (for example wrote down the recovery phrase
    /// and re-entered it, or exported a backup file).
    pub fn confirm_backup(&mut self) -> Result<(), VaultError> {
        self.content_writable()?;
        self.write(vec![(
            EventKind::BackupConfirmed { at: now() },
            Origin::Fresh,
        )])
    }

    /// Removes a device and rotates the vault key so it cannot read anything written from now
    /// on. It keeps whatever it already decrypted.
    pub fn remove_device(&mut self, device_id: &DeviceId) -> Result<(), VaultError> {
        self.scan()?;
        if *device_id == self.device.device_id {
            return Err(VaultError::CannotRemoveSelf);
        }
        if !self.view.devices.contains_key(device_id) {
            return Err(VaultError::UnknownDevice);
        }
        // The user has decided this device is untrusted: discard key generations it created
        // outside the current line, which resolves a rotation conflict it caused.
        let keys_dir = self.vault_dir.join(KEYS_DIR);
        let mut discarded = false;
        for name in fsutil::list(&keys_dir)? {
            if let Some(id) = GenId::parse_dir(&name)
                && id.rotator == *device_id
                && !self.current_chain.contains(&id)
            {
                std::fs::remove_dir_all(keys_dir.join(&name))
                    .map_err(io("remove generation of removed device"))?;
                discarded = true;
            }
        }
        if discarded {
            self.scan()?;
        }
        if self.view.removed_by_gen.contains(device_id) {
            return Ok(());
        }
        self.rotate(&[*device_id])
    }

    // ---- crate internals for backup.rs ----

    pub(crate) fn recovery_pub(&self) -> [u8; 32] {
        self.keyring.recovery_pub
    }
}

fn new_device(vault_id: [u8; 16], name: &str) -> Result<LocalDevice, VaultError> {
    let (x_private, _) = hirz_crypto::x25519::generate()?;
    Ok(LocalDevice {
        vault_id,
        device_id: random16()?,
        secret: random_key()?,
        x25519_private: to_key(&x_private)?,
        name: name.to_string(),
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
        };
        let tomb = Event {
            kind: EventKind::Tombstone(vec![1; 32]),
            origin_author: [5; 16],
            origin_lamport: 7,
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
