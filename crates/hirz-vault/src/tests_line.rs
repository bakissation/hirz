//! Regression tests for authenticated rotations, the pinned line, bounded counters and the
//! folder hardening (docs/vault-format.md, 4.3, 6.1, 7, 9.3, 9.4).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use crate::DeviceId;
use crate::codec::hex;
use crate::format::{
    self, Counter, GEN_INFO_NAME, GenId, GenInfo, KEYS_DIR, Keyring, KeyringEntry, Line, Member,
    RECORDS_DIR, RecordName,
};
use crate::pairing::{PAIRING_DIR, PendingJoin, seal_approval};
use crate::record::{DeviceAnnouncement, Event, EventKind, append_tag, device_id_for};
use crate::tests::{TempDir, cred, hide, record_files};
use crate::vault::COUNTER_WINDOW;
use crate::{PAIRING_LIFETIME_SECS, PairingPoll, PairingRequest, Vault, VaultError};
use hirz_crypto::Zeroizing;
use std::fs;
use std::path::Path;

/// A device identity made up by an attacker.
pub(crate) struct Forger {
    pub(crate) seed: [u8; 32],
    pub(crate) id: DeviceId,
    signing_public: [u8; 32],
    x25519_public: [u8; 32],
}

impl Forger {
    pub(crate) fn new(tag: u8) -> Forger {
        let seed = [tag; 32];
        let signing_public = hirz_crypto::ed25519::public_from_seed(&seed).unwrap();
        Forger {
            seed,
            id: device_id_for(&signing_public),
            signing_public,
            x25519_public: hirz_crypto::x25519::public_key(&[tag ^ 0x5a; 32]).unwrap(),
        }
    }

    pub(crate) fn member(&self) -> Member {
        Member {
            device_id: self.id,
            signing_public: self.signing_public,
            x25519_public: self.x25519_public,
        }
    }

    fn endorsed_by(
        &self,
        vault_id: &[u8; 16],
        endorser: DeviceId,
        seed: &[u8; 32],
    ) -> DeviceAnnouncement {
        let mut a = DeviceAnnouncement {
            device_id: self.id,
            name: "laptop".into(),
            x25519_public: self.x25519_public,
            added_at: 1,
            signing_public: self.signing_public,
            endorser,
            signature: [0; 64],
        };
        a.endorse(vault_id, seed).unwrap();
        a
    }
}

pub(crate) fn member_of(v: &Vault) -> Member {
    Member {
        device_id: v.device_id(),
        signing_public: v.device.signing_public().unwrap(),
        x25519_public: hirz_crypto::x25519::public_key(&v.device.x25519_private).unwrap(),
    }
}

pub(crate) fn key_of(v: &Vault, id: &GenId) -> [u8; 32] {
    *v.keyring.get(id).unwrap().key
}

pub(crate) fn info_of(
    vdir: &Path,
    vault_id: &[u8; 16],
    id: &GenId,
    parent_key: &[u8; 32],
) -> GenInfo {
    let data = fs::read(vdir.join(KEYS_DIR).join(id.dir_name()).join(GEN_INFO_NAME)).unwrap();
    GenInfo::open(&data, parent_key, vault_id, id).unwrap()
}

/// A child of `parent` written by someone who holds the parent key: gen.info signed by
/// `rotator`, slots for `victims` and the recovery key, all under a key of the forger's choice.
#[allow(clippy::too_many_arguments)]
pub(crate) fn forge(
    vdir: &Path,
    vault_id: &[u8; 16],
    parent: GenId,
    parent_key: &[u8; 32],
    parent_info: &GenInfo,
    rotator: &Forger,
    chain: Vec<DeviceAnnouncement>,
    removed: Vec<DeviceId>,
    victims: &[Member],
) -> (GenId, [u8; 32], GenInfo) {
    let id = GenId {
        number: parent.number + 1,
        rotator: rotator.id,
    };
    let key = [rotator.seed[0] ^ id.number.to_be_bytes()[3]; 32];
    let dir = vdir.join(KEYS_DIR).join(id.dir_name());
    fs::create_dir_all(&dir).unwrap();
    let mut members = vec![rotator.member()];
    for v in victims {
        fs::write(
            dir.join(format::slot_name(&v.device_id)),
            format::seal_device_slot(vault_id, &id, &v.device_id, &v.x25519_public, &key).unwrap(),
        )
        .unwrap();
        members.push(v.clone());
    }
    members.sort_by_key(|m| m.device_id);
    fs::write(
        dir.join("recovery.slot"),
        format::seal_recovery_slot(vault_id, &id, &parent_info.recovery_pub, &key).unwrap(),
    )
    .unwrap();
    let info = GenInfo {
        commitment: format::commitment(&key, vault_id, &id),
        recovery_pub: parent_info.recovery_pub,
        removed: removed
            .into_iter()
            .map(|device| format::Removal {
                device,
                cause_author: rotator.id,
                cause: [0x99; 16],
                cutoff: Vec::new(),
            })
            .collect(),
        created_at: 0,
        reemit_first: 0,
        reemit_count: 0,
        recovery_tag: None,
        recovery_signing_pub: parent_info.recovery_signing_pub,
        members,
        chain,
    };
    fs::write(
        dir.join(GEN_INFO_NAME),
        info.seal(parent_key, vault_id, &id, Some(&parent), &rotator.seed)
            .unwrap(),
    )
    .unwrap();
    (id, key, info)
}

pub(crate) fn plant_event(
    vdir: &Path,
    vault_id: &[u8; 16],
    writer: &DeviceId,
    gen_id: &GenId,
    key: &[u8; 32],
    lamport: u64,
    event: &Event,
) {
    let name = RecordName::new(lamport).unwrap();
    let rel = format::record_rel_path(writer, &name);
    let mut body = event.encode_body().unwrap();
    append_tag(&mut body, &[0; 32]);
    let data = format::seal_record(key, vault_id, gen_id, &rel, &body).unwrap();
    let dir = vdir.join(RECORDS_DIR).join(hex(writer));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(name.file_name()), data).unwrap();
}

pub(crate) fn newest_record(vdir: &Path) -> std::path::PathBuf {
    record_files(vdir)
        .into_iter()
        .max_by_key(|p| fs::metadata(p).unwrap().modified().unwrap())
        .unwrap()
}

pub(crate) fn record_gen_of(path: &Path) -> GenId {
    format::record_gen(&fs::read(path).unwrap()).unwrap()
}

/// A vault with devices A (creator), B and X (both joined with the phrase); A removed X and
/// wrote a passkey afterwards. B has not reloaded since it joined.
pub(crate) struct Removed {
    pub(crate) t: TempDir,
    pub(crate) a: Vault,
    pub(crate) b: Vault,
    pub(crate) x: Vault,
    pub(crate) phrase: crate::RecoveryPhrase,
    pub(crate) gen1: GenId,
    pub(crate) k1: [u8; 32],
    pub(crate) info1: GenInfo,
    pub(crate) gen2: GenId,
}

pub(crate) fn removed_x() -> Removed {
    let t = TempDir::new("line");
    let vdir = t.path("vault");
    let (mut a, phrase) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    let mut x = Vault::join_with_recovery(&vdir, &t.path("x"), &phrase, "x").unwrap();
    let b = Vault::join_with_recovery(&vdir, &t.path("b"), &phrase, "b").unwrap();
    a.put(cred(1, "example.com")).unwrap();
    x.reload().unwrap();
    let gen1 = a.current_gen();
    let k1 = key_of(&a, &gen1);
    let info1 = info_of(&vdir, &a.vault_id(), &gen1, &k1);
    a.remove_device(&x.device_id()).unwrap();
    let gen2 = a.current_gen();
    assert_eq!(gen2.number, 2);
    a.put(cred(2, "after-removal.example")).unwrap();
    Removed {
        t,
        a,
        b,
        x,
        phrase,
        gen1,
        k1,
        info1,
        gen2,
    }
}

impl Removed {
    pub(crate) fn vdir(&self) -> std::path::PathBuf {
        self.t.path("vault")
    }

    /// R, made up by X and endorsed by X's own key, with the chain that proves it.
    pub(crate) fn minted(&self, tag: u8) -> (Forger, Vec<DeviceAnnouncement>) {
        let r = Forger::new(tag);
        let vault_id = self.a.vault_id();
        let x_ann = self.x.announcement_of(&self.x.device_id()).unwrap();
        let r_ann = r.endorsed_by(&vault_id, self.x.device_id(), &self.x.device.signing_seed);
        (r, vec![r_ann, x_ann])
    }
}

pub(crate) fn assert_follows(v: &Vault, gen_id: GenId) {
    let r = v.report();
    assert_eq!(v.current_gen(), gen_id, "{r:?}");
    assert!(
        !r.rotation_conflict && !r.fork_detected && !r.this_device_removed && !r.locked_out,
        "{r:?}"
    );
}

#[test]
fn forged_sibling_by_removed_device_is_never_followed() {
    for victim_slot in [true, false] {
        let mut s = removed_x();
        let vdir = s.vdir();
        let vault_id = s.a.vault_id();
        let (r, chain) = s.minted(0x31);
        let victims = if victim_slot {
            vec![member_of(&s.a), member_of(&s.b)]
        } else {
            vec![]
        };
        let (forged, forged_key, _) = forge(
            &vdir,
            &vault_id,
            s.gen1,
            &s.k1,
            &s.info1,
            &r,
            chain,
            vec![],
            &victims,
        );
        assert_ne!(forged, s.gen2);

        let report = s.a.reload().unwrap().clone();
        assert_follows(&s.a, s.gen2);
        assert!(report.rejected.contains(&forged), "{report:?}");
        assert_eq!(report.migrated, 0);
        assert_eq!(s.a.list_all().len(), 2);
        s.a.put(cred(3, "after-takeover.example")).unwrap();
        let newest = newest_record(&vdir);
        assert_eq!(record_gen_of(&newest), s.gen2);
        let rel = newest.strip_prefix(&vdir).unwrap().to_str().unwrap();
        let data = fs::read(&newest).unwrap();
        assert!(format::open_record(&data, &forged_key, &vault_id, &forged, rel).is_err());
        assert!(format::open_record(&data, &forged_key, &vault_id, &s.gen2, rel).is_err());

        s.b.reload().unwrap();
        assert_follows(&s.b, s.gen2);
        assert!(s.b.get(&[3; 32]).is_some());
        assert!(s.b.keyring.get(&forged).is_none());

        let d = Vault::join_with_recovery(&vdir, &s.t.path("d"), &s.phrase, "d").unwrap();
        assert_follows(&d, s.gen2);
        assert!(d.keyring.get(&forged).is_none());
    }
}

#[test]
fn forged_chain_longer_than_the_honest_one_is_never_followed() {
    for victim_slot in [true, false] {
        let mut s = removed_x();
        let vdir = s.vdir();
        let vault_id = s.a.vault_id();
        let (r, chain) = s.minted(0x41);
        let victims = if victim_slot {
            vec![member_of(&s.a), member_of(&s.b)]
        } else {
            vec![]
        };
        let (mut parent, mut pkey, mut pinfo) = forge(
            &vdir,
            &vault_id,
            s.gen1,
            &s.k1,
            &s.info1,
            &r,
            chain,
            vec![],
            &victims,
        );
        let mut forged = vec![parent];
        for _ in 0..3 {
            let next = forge(
                &vdir,
                &vault_id,
                parent,
                &pkey,
                &pinfo,
                &r,
                vec![],
                vec![],
                &victims,
            );
            (parent, pkey, pinfo) = next;
            forged.push(parent);
        }

        s.a.reload().unwrap();
        assert_follows(&s.a, s.gen2);
        s.b.reload().unwrap();
        assert_follows(&s.b, s.gen2);
        assert!(s.a.report().rejected.contains(&forged[0]));
        for g in &forged {
            // Without a slot for A the later forged generations cannot even be opened.
            assert_eq!(
                s.a.report().rejected.contains(g),
                victim_slot || *g == forged[0]
            );
            assert!(s.b.keyring.get(g).is_none());
        }
        s.a.put(cred(3, "example.org")).unwrap();
        assert_eq!(record_gen_of(&newest_record(&vdir)), s.gen2);

        let d = Vault::join_with_recovery(&vdir, &s.t.path("d"), &s.phrase, "d").unwrap();
        assert_follows(&d, s.gen2);
        for g in &forged {
            assert!(d.keyring.get(g).is_none());
        }
        assert!(d.get(&[3; 32]).is_some());
    }
}

#[test]
fn pairing_is_never_completed_along_a_forged_chain() {
    let s = removed_x();
    let vdir = s.vdir();
    let vault_id = s.a.vault_id();
    let (r, chain) = s.minted(0x51);
    let pending = PendingJoin::start(&vdir, &s.t.path("n"), "new").unwrap();
    let req = pending.request().clone();
    let newcomer = Member {
        device_id: req.device_id,
        signing_public: req.signing_key,
        x25519_public: req.public_key,
    };
    let (forged, forged_key, _) = forge(
        &vdir,
        &vault_id,
        s.gen1,
        &s.k1,
        &s.info1,
        &r,
        chain,
        vec![],
        std::slice::from_ref(&newcomer),
    );
    let mut ann = DeviceAnnouncement {
        device_id: req.device_id,
        name: req.name.clone(),
        x25519_public: req.public_key,
        added_at: 1,
        signing_public: req.signing_key,
        endorser: r.id,
        signature: [0; 64],
    };
    ann.endorse(&vault_id, &r.seed).unwrap();
    let added = Event::signed(
        EventKind::DeviceAdded(ann.clone()),
        r.id,
        50,
        &r.seed,
        &vault_id,
    )
    .unwrap();
    plant_event(&vdir, &vault_id, &r.id, &forged, &forged_key, 50, &added);
    let ok = vdir
        .join(PAIRING_DIR)
        .join(format!("{}.ok", hex(&req.request_id)));
    let chain_keys = |ids: &[(GenId, [u8; 32])]| -> Vec<KeyringEntry> {
        ids.iter()
            .enumerate()
            .map(|(i, (g, k))| KeyringEntry {
                gen_id: *g,
                key: Zeroizing::new(*k),
                root: i == 0,
            })
            .collect()
    };
    fs::write(
        &ok,
        seal_approval(
            &vault_id,
            &req,
            &chain_keys(&[(s.gen1, s.k1), (forged, forged_key)]),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        pending.poll(&s.t.path("n")).unwrap(),
        PairingPoll::Invalid(_)
    ));

    // The old key alone: the newcomer sees the honest rotation it holds no key for and waits.
    let mut ann1 = ann.clone();
    ann1.endorser = s.x.device_id();
    ann1.endorse(&vault_id, &s.x.device.signing_seed).unwrap();
    let added1 = Event::signed(
        EventKind::DeviceAdded(ann1),
        s.x.device_id(),
        60,
        &s.x.device.signing_seed,
        &vault_id,
    )
    .unwrap();
    plant_event(
        &vdir,
        &vault_id,
        &s.x.device_id(),
        &s.gen1,
        &s.k1,
        60,
        &added1,
    );
    fs::write(
        &ok,
        seal_approval(&vault_id, &req, &chain_keys(&[(s.gen1, s.k1)])).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        pending.poll(&s.t.path("n")).unwrap(),
        PairingPoll::Waiting
    ));
    assert!(!Vault::is_set_up(&s.t.path("n")));
}

#[test]
fn forged_removal_of_honest_devices_neither_removes_them_nor_sticks() {
    let mut s = removed_x();
    let vdir = s.vdir();
    let vault_id = s.a.vault_id();
    let (r, chain) = s.minted(0x61);
    let (forged, _, _) = forge(
        &vdir,
        &vault_id,
        s.gen1,
        &s.k1,
        &s.info1,
        &r,
        chain,
        vec![s.a.device_id(), s.b.device_id()],
        &[],
    );

    // A followed the honest rotation: the forged one rests on X, which A's line removed.
    s.a.reload().unwrap();
    assert_follows(&s.a, s.gen2);
    s.a.put(cred(3, "example.org")).unwrap();

    // B never followed either rotation: it cannot tell who is right, but is not removed.
    let r_b = s.b.reload().unwrap().clone();
    assert!(r_b.rotation_conflict, "{r_b:?}");
    assert!(!r_b.this_device_removed && !r_b.locked_out);
    assert!(r_b.rejected.contains(&forged) && r_b.rejected.contains(&s.gen2));
    assert_eq!(s.b.list_all().len(), 1, "existing passkeys stay readable");
    assert!(s.b.ensure_active().is_ok());
    assert!(matches!(
        s.b.put(cred(4, "example.net")),
        Err(VaultError::RotationConflict)
    ));
    let reopened = Vault::open(&vdir, &s.t.path("b")).unwrap();
    assert!(!reopened.report().this_device_removed);

    // The user removes X again on B: everything resting on X is discarded.
    s.b.remove_device(&s.x.device_id()).unwrap();
    assert_follows(&s.b, s.gen2);
    assert!(!vdir.join(KEYS_DIR).join(forged.dir_name()).exists());
    s.b.put(cred(4, "example.net")).unwrap();
    s.a.reload().unwrap();
    assert!(s.a.get(&[4; 32]).is_some());
}

#[test]
fn a_named_foreign_generation_can_be_discarded() {
    let mut s = removed_x();
    let vdir = s.vdir();
    let vault_id = s.a.vault_id();
    let (r, chain) = s.minted(0x62);
    let (forged, _, _) = forge(
        &vdir,
        &vault_id,
        s.gen1,
        &s.k1,
        &s.info1,
        &r,
        chain,
        vec![s.a.device_id(), s.b.device_id()],
        &[],
    );
    assert!(s.b.reload().unwrap().rotation_conflict);
    assert!(matches!(
        s.b.discard_generation(&s.gen1),
        Err(VaultError::InvalidParameters)
    ));
    assert!(s.b.discard_generation(&forged).unwrap());
    assert_follows(&s.b, s.gen2);
    assert!(!s.b.discard_generation(&forged).unwrap());
}

#[test]
fn counters_far_above_the_highest_accepted_are_ignored() {
    let t = TempDir::new("counter");
    let vdir = t.path("vault");
    let (mut a, phrase) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    let x = Vault::join_with_recovery(&vdir, &t.path("x"), &phrase, "x").unwrap();
    a.put(cred(1, "example.com")).unwrap();
    let vault_id = a.vault_id();
    let gen1 = a.current_gen();
    let k1 = key_of(&a, &gen1);
    let put = |lamport| {
        Event::signed(
            EventKind::Put(Box::new(cred(7, "planted.example"))),
            x.device_id(),
            lamport,
            &x.device.signing_seed,
            &vault_id,
        )
        .unwrap()
    };
    plant_event(
        &vdir,
        &vault_id,
        &x.device_id(),
        &gen1,
        &k1,
        u64::MAX,
        &put(u64::MAX),
    );
    plant_event(
        &vdir,
        &vault_id,
        &x.device_id(),
        &gen1,
        &k1,
        1000,
        &put(u64::MAX - 1),
    );

    let report = a.reload().unwrap().clone();
    let out_of_range = report
        .skipped
        .iter()
        .filter(|f| f.reason == "counter out of range")
        .count();
    assert_eq!(out_of_range, 2, "{report:?}");
    assert!(a.get(&[7; 32]).is_none());
    a.put(cred(2, "example.com")).unwrap();
    a.delete(&[1; 32]).unwrap();
    a.remove_device(&x.device_id()).unwrap();
    assert_eq!(a.report().generation, 2);
    a.put(cred(3, "example.com")).unwrap();
    let c = Counter::decode(&fs::read(t.path("a").join("counter")).unwrap()).unwrap();
    assert!(
        c.max_seen < COUNTER_WINDOW && c.next < COUNTER_WINDOW,
        "{c:?}"
    );
    assert!(!a.report().rollback_suspected);
}

#[test]
fn a_planted_slot_file_does_not_rotate() {
    let t = TempDir::new("slotfile");
    let vdir = t.path("vault");
    let (mut a, phrase) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    let c = Vault::join_with_recovery(&vdir, &t.path("c"), &phrase, "c").unwrap();
    a.reload().unwrap();
    a.remove_device(&c.device_id()).unwrap();
    let gen2 = a.current_gen();
    let records = record_files(&vdir).len();
    for _ in 0..3 {
        let dir = vdir.join(KEYS_DIR).join(a.current_gen().dir_name());
        fs::write(dir.join(format::slot_name(&c.device_id())), b"").unwrap();
        let r = a.reload().unwrap().clone();
        assert!(!r.rotated, "{r:?}");
    }
    assert_eq!(a.current_gen(), gen2);
    assert_eq!(record_files(&vdir).len(), records);
}

#[test]
fn keyring_is_not_limited_by_a_16_bit_length() {
    let dev = crate::vault::new_device([1; 16], "a").unwrap();
    let entries = |n: usize| -> Vec<KeyringEntry> {
        (0..n)
            .map(|i| KeyringEntry {
                gen_id: GenId {
                    number: u32::try_from(i + 1).unwrap(),
                    rotator: [2; 16],
                },
                key: Zeroizing::new([3; 32]),
                root: i == 0,
            })
            .collect()
    };
    let big = Keyring {
        recovery_pub: [4; 32],
        entries: entries(format::MAX_GENERATIONS),
    };
    let sealed = big.seal(&dev).unwrap();
    assert_eq!(
        Keyring::open(&sealed, &dev).unwrap().entries.len(),
        format::MAX_GENERATIONS
    );
    let too_big = Keyring {
        recovery_pub: [4; 32],
        entries: entries(format::MAX_GENERATIONS + 1),
    };
    assert!(matches!(too_big.seal(&dev), Err(VaultError::Encode)));
}

#[test]
fn garbage_collection_waits_from_local_first_sight() {
    let t = TempDir::new("firstseen");
    let vdir = t.path("vault");
    let (mut a, phrase) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    let c = Vault::join_with_recovery(&vdir, &t.path("c"), &phrase, "c").unwrap();
    a.reload().unwrap();
    a.put(cred(1, "example.com")).unwrap();
    a.remove_device(&c.device_id()).unwrap();
    a.gc_grace = 3600;
    assert_eq!(a.reload().unwrap().collected, 0);
    let path = t.path("a").join("line");
    let mut line = Line::decode(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(line.entries.len(), 2);
    for e in &mut line.entries {
        e.first_seen = 0;
    }
    fs::write(&path, line.encode().unwrap()).unwrap();
    assert!(a.reload().unwrap().collected > 0);
}

#[test]
fn a_missing_or_rewritten_generation_of_the_line_is_a_fork() {
    let t = TempDir::new("fork");
    let vdir = t.path("vault");
    let (mut a, phrase) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    let mut b = Vault::join_with_recovery(&vdir, &t.path("b"), &phrase, "b").unwrap();
    let c = Vault::join_with_recovery(&vdir, &t.path("c"), &phrase, "c").unwrap();
    a.put(cred(1, "example.com")).unwrap();
    a.reload().unwrap();
    let gen1 = a.current_gen();
    a.remove_device(&c.device_id()).unwrap();
    let gen2 = a.current_gen();
    b.reload().unwrap();
    assert_follows(&b, gen2);

    let (hidden, back) = hide(&vdir, 2);
    let r = a.reload().unwrap().clone();
    assert!(r.fork_detected, "{r:?}");
    assert!(!r.this_device_removed);
    assert_eq!(a.list_all().len(), 1, "existing passkeys stay readable");
    assert!(matches!(
        a.put(cred(2, "example.com")),
        Err(VaultError::Fork)
    ));
    fs::rename(&hidden, &back).unwrap();
    a.reload().unwrap();
    assert_follows(&a, gen2);

    // The same signed content encrypted again under a new nonce, as any key holder can: the
    // line compares the authenticated content, so this is not a fork.
    let vault_id = a.vault_id();
    let k1 = key_of(&a, &gen1);
    let info_path = vdir
        .join(KEYS_DIR)
        .join(gen1.dir_name())
        .join(GEN_INFO_NAME);
    let mut info = info_of(&vdir, &vault_id, &gen1, &k1);
    let before = fs::read(&info_path).unwrap();
    let resealed = info
        .seal(&k1, &vault_id, &gen1, None, &a.device.signing_seed)
        .unwrap();
    assert_ne!(before, resealed);
    fs::write(&info_path, resealed).unwrap();
    for v in [&mut a, &mut b] {
        let r = v.reload().unwrap().clone();
        assert!(!r.fork_detected, "{r:?}");
        assert_follows(v, gen2);
    }

    // Different content, signed by its rotator: the line notices.
    info.created_at += 1;
    fs::write(
        &info_path,
        info.seal(&k1, &vault_id, &gen1, None, &a.device.signing_seed)
            .unwrap(),
    )
    .unwrap();
    for v in [&mut a, &mut b] {
        let r = v.reload().unwrap().clone();
        assert!(r.fork_detected, "{r:?}");
        assert_eq!(r.collected + r.migrated, 0);
    }
    a.accept_fork().unwrap();
    assert_follows(&a, gen2);
    a.put(cred(2, "example.com")).unwrap();
}

#[test]
fn symlinks_in_the_folder_are_never_followed() {
    let t = TempDir::new("symlink");
    let vdir = t.path("vault");
    let (mut a, phrase) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    let c = Vault::join_with_recovery(&vdir, &t.path("c"), &phrase, "c").unwrap();
    a.put(cred(1, "example.com")).unwrap();

    let fifo = t.path("fifo");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .is_ok_and(|s| s.success());
    let own = vdir.join(RECORDS_DIR).join(hex(&a.device_id()));
    let link = own.join(format!("{:020}-{}.rec", 99, "00".repeat(8)));
    std::os::unix::fs::symlink(if made { &fifo } else { &own }, &link).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let r = a.reload().cloned();
        let _ = tx.send(());
        (a, r)
    });
    rx.recv_timeout(std::time::Duration::from_secs(20))
        .expect("reload blocked on a symlinked record");
    let (mut a, r) = handle.join().unwrap();
    let r = r.unwrap();
    assert!(r.skipped.iter().any(|f| f.reason == "unreadable"), "{r:?}");
    fs::remove_file(&link).unwrap();

    a.remove_device(&c.device_id()).unwrap();
    let outside = t.path("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("precious.slot"), b"x").unwrap();
    let decoy = GenId {
        number: 1,
        rotator: [0x77; 16],
    };
    std::os::unix::fs::symlink(&outside, vdir.join(KEYS_DIR).join(decoy.dir_name())).unwrap();
    a.gc_grace = 0;
    a.reload().unwrap();
    assert!(outside.join("precious.slot").exists());

    let target = t.path("elsewhere");
    fs::create_dir_all(&target).unwrap();
    fs::rename(&own, t.path("own-moved")).unwrap();
    std::os::unix::fs::symlink(&target, &own).unwrap();
    assert!(a.put(cred(2, "example.com")).is_err());
    assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
}

#[test]
fn junk_genesis_does_not_block_pairing_and_requests_are_capped() {
    let t = TempDir::new("junk");
    let vdir = t.path("vault");
    let (mut a, _) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    let junk = vdir.join(KEYS_DIR).join(
        GenId {
            number: 1,
            rotator: [0x13; 16],
        }
        .dir_name(),
    );
    fs::create_dir_all(&junk).unwrap();
    fs::write(junk.join(GEN_INFO_NAME), b"not a generation").unwrap();
    PendingJoin::start(&vdir, &t.path("n"), "new").unwrap();

    let now = crate::vault::now();
    let dir = vdir.join(PAIRING_DIR);
    for i in 0..20u8 {
        let signing_key = hirz_crypto::ed25519::public_from_seed(&[i; 32]).unwrap();
        let req = PairingRequest {
            request_id: [i; 16],
            device_id: device_id_for(&signing_key),
            name: format!("planted {i}"),
            public_key: [i; 32],
            signing_key,
            created_at: now,
            expires_at: now + PAIRING_LIFETIME_SECS,
        };
        fs::write(
            dir.join(format!("{}.req", hex(&req.request_id))),
            req.encode().unwrap(),
        )
        .unwrap();
    }
    let listed = a.pairing_requests().unwrap();
    assert_eq!(listed.len(), crate::MAX_LISTED_REQUESTS);
    assert_eq!(a.hidden_pairing_requests(), 21 - crate::MAX_LISTED_REQUESTS);
}

#[test]
fn a_device_approved_by_a_removed_device_still_rotates() {
    let t = TempDir::new("endorsed");
    let vdir = t.path("vault");
    let (mut a, phrase) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    let mut x = Vault::join_with_recovery(&vdir, &t.path("x"), &phrase, "x").unwrap();
    let z = Vault::join_with_recovery(&vdir, &t.path("z"), &phrase, "z").unwrap();
    let pending = PendingJoin::start(&vdir, &t.path("y"), "y").unwrap();
    let req = x
        .pairing_requests()
        .unwrap()
        .into_iter()
        .find(|r| r.request_id == pending.request().request_id)
        .unwrap();
    x.approve_pairing(&req).unwrap();
    let mut y = match pending.poll(&t.path("y")).unwrap() {
        PairingPoll::Joined(v) => *v,
        other => panic!("{other:?}"),
    };
    a.put(cred(1, "example.com")).unwrap();
    a.reload().unwrap();
    assert_eq!(
        a.devices()
            .iter()
            .find(|d| d.id == y.device_id())
            .unwrap()
            .added_by,
        Some(x.device_id())
    );

    a.remove_device(&x.device_id()).unwrap();
    let (hidden, back) = hide(&vdir, 2);
    y.reload().unwrap();
    y.remove_device(&z.device_id()).unwrap();
    fs::rename(&hidden, &back).unwrap();

    for _ in 0..3 {
        a.reload().unwrap();
        y.reload().unwrap();
    }
    for v in [&a, &y] {
        assert_eq!(v.report().generation, 3, "{:?}", v.report());
        assert!(!v.report().rotation_conflict && !v.report().fork_detected);
        let devs = v.devices();
        assert!(devs.iter().any(|d| d.id == x.device_id() && d.removed));
        assert!(devs.iter().any(|d| d.id == z.device_id() && d.removed));
        assert!(devs.iter().any(|d| d.id == y.device_id() && !d.removed));
    }
    assert_eq!(a.current_gen(), y.current_gen());
    assert_eq!(a.current_gen().rotator, y.device_id());
}

#[test]
fn device_ids_are_bound_to_signing_keys() {
    let dev = crate::vault::new_device([1; 16], "a").unwrap();
    assert_eq!(device_id_for(&dev.signing_public().unwrap()), dev.device_id);
    let mut other = dev.clone();
    other.device_id = [9; 16];
    let enc = other.encode().unwrap();
    assert!(format::LocalDevice::decode(&enc).is_err());
    assert!(format::LocalDevice::decode(&dev.encode().unwrap()).is_ok());

    let r = Forger::new(3);
    let e = Forger::new(4);
    let mut ann = r.endorsed_by(&[1; 16], e.id, &e.seed);
    let enc = ann.encode().unwrap();
    assert_eq!(DeviceAnnouncement::decode(&enc).unwrap(), ann);
    assert!(ann.endorsement_valid(&[1; 16], &e.signing_public));
    assert!(!ann.endorsement_valid(&[2; 16], &e.signing_public));
    ann.device_id = e.id;
    assert!(DeviceAnnouncement::decode(&ann.encode().unwrap()).is_err());
}
