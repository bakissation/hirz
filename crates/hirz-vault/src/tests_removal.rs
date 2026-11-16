//! Regression tests for device removal: a removal stays in force when the folder is rewritten
//! (docs/vault-format.md, 4.3, 6.1, 9.2 to 9.4, 11.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use crate::codec::hex;
use crate::format::{self, FileType, GEN_INFO_NAME, GenId, KEYS_DIR, RECORDS_DIR};
use crate::pairing::PendingJoin;
use crate::record::{Event, EventKind};
use crate::tests::{TempDir, cred, hide, record_files};
use crate::tests_line::{
    assert_follows, forge, key_of, member_of, newest_record, plant_event, record_gen_of, removed_x,
};
use crate::vault::COUNTER_WINDOW;
use crate::{DeviceId, PairingPoll, Vault, VaultError};
use std::fs;
use std::path::Path;

/// Every key a device can get from the folder with its own X25519 key, plus `known`.
fn keys_of(
    vdir: &Path,
    vault_id: &[u8; 16],
    v: &Vault,
    known: &[[u8; 32]],
) -> Vec<(GenId, [u8; 32])> {
    let mut out = Vec::new();
    for e in fs::read_dir(vdir.join(KEYS_DIR)).unwrap() {
        let name = e.unwrap().file_name().into_string().unwrap();
        let Some(id) = GenId::parse_dir(&name) else {
            continue;
        };
        for k in known {
            out.push((id, *k));
        }
        let slot = vdir
            .join(KEYS_DIR)
            .join(&name)
            .join(format::slot_name(&v.device_id()));
        if let Ok(data) = fs::read(slot)
            && let Ok(k) = format::open_device_slot(
                &data,
                vault_id,
                &id,
                &v.device_id(),
                &v.device.x25519_private,
            )
        {
            out.push((id, *k));
        }
    }
    out
}

/// Credential ids of every passkey whose record opens with one of `keys`.
fn readable_with(vdir: &Path, vault_id: &[u8; 16], keys: &[(GenId, [u8; 32])]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for path in record_files(vdir) {
        let data = fs::read(&path).unwrap();
        let Ok(gen_id) = format::record_gen(&data) else {
            continue;
        };
        let rel = path.strip_prefix(vdir).unwrap().to_str().unwrap();
        for (g, k) in keys.iter().filter(|(g, _)| *g == gen_id) {
            if let Ok(pt) = format::open_record(&data, k, vault_id, g, rel)
                && let Ok((
                    Event {
                        kind: EventKind::Put(rec),
                        ..
                    },
                    _,
                    _,
                )) = Event::decode(&pt)
            {
                out.push(rec.credential_id.clone());
            }
        }
    }
    out
}

fn own_record_gens(vdir: &Path, id: &DeviceId) -> Vec<GenId> {
    let dir = vdir.join(RECORDS_DIR).join(hex(id));
    fs::read_dir(dir)
        .unwrap()
        .map(|e| record_gen_of(&e.unwrap().path()))
        .collect()
}

/// The removed device deletes the removing generation's gen.info and forges a sibling that
/// removes the honest devices.
#[test]
fn a_deleted_removal_and_a_forged_removal_never_remove_the_device_that_followed_it() {
    let mut s = removed_x();
    let vdir = s.vdir();
    let vault_id = s.a.vault_id();
    let (r, chain) = s.minted(0x71);
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
    fs::remove_file(
        vdir.join(KEYS_DIR)
            .join(s.gen2.dir_name())
            .join(GEN_INFO_NAME),
    )
    .unwrap();
    for _ in 0..2 {
        let rep = s.a.reload().unwrap().clone();
        assert!(rep.fork_detected, "{rep:?}");
        assert!(!rep.this_device_removed && !rep.locked_out, "{rep:?}");
        assert!(rep.rejected.contains(&forged), "{rep:?}");
        assert!(s.a.ensure_active().is_ok());
        assert!(!s.a.list_all().is_empty());
    }
    let reopened = Vault::open(&vdir, &s.t.path("a")).unwrap();
    let rep = reopened.report();
    assert!(rep.fork_detected && !rep.this_device_removed && !rep.locked_out);
}

/// As above, but the forged sibling holds slots for the honest devices and removes nobody; the
/// user then accepts the fork.
#[test]
fn accepting_a_fork_keeps_every_removal_the_line_made() {
    let mut s = removed_x();
    let vdir = s.vdir();
    let vault_id = s.a.vault_id();
    let (r, chain) = s.minted(0x72);
    let (forged, forged_key, _) = forge(
        &vdir,
        &vault_id,
        s.gen1,
        &s.k1,
        &s.info1,
        &r,
        chain,
        vec![],
        &[member_of(&s.a), member_of(&s.b)],
    );
    fs::remove_file(
        vdir.join(KEYS_DIR)
            .join(s.gen2.dir_name())
            .join(GEN_INFO_NAME),
    )
    .unwrap();
    let rep = s.a.reload().unwrap().clone();
    assert!(rep.fork_detected && rep.generation == 1, "{rep:?}");

    s.a.accept_fork().unwrap();
    let rep = s.a.report().clone();
    assert!(!rep.fork_detected && !rep.rotation_conflict, "{rep:?}");
    assert_ne!(s.a.current_gen(), forged);
    assert_eq!(s.a.current_gen().number, 2);
    assert!(rep.rejected.contains(&forged), "{rep:?}");
    let x_slot = vdir
        .join(KEYS_DIR)
        .join(s.a.current_gen().dir_name())
        .join(format::slot_name(&s.x.device_id()));
    assert!(!x_slot.exists());
    assert!(
        s.a.get(&[2; 32]).is_some(),
        "the passkey made after the removal is kept"
    );
    assert!(
        s.a.devices()
            .iter()
            .any(|d| d.id == s.x.device_id() && d.removed)
    );

    s.a.put(cred(3, "after-accept.example")).unwrap();
    assert_eq!(record_gen_of(&newest_record(&vdir)), s.a.current_gen());
    assert!(!own_record_gens(&vdir, &s.a.device_id()).contains(&forged));
    let x_keys = keys_of(&vdir, &vault_id, &s.x, &[s.k1, forged_key]);
    let readable = readable_with(&vdir, &vault_id, &x_keys);
    assert!(!readable.contains(&vec![2; 32]), "{readable:?}");
    assert!(!readable.contains(&vec![3; 32]), "{readable:?}");

    let reopened = Vault::open(&vdir, &s.t.path("a")).unwrap();
    assert_follows(&reopened, s.a.current_gen());
    assert!(reopened.get(&[3; 32]).is_some());
}

/// A device approved by the removed device is kept, and is listed so the user can remove it too.
#[test]
fn devices_approved_by_a_removed_device_are_listed_when_it_is_removed() {
    let t = TempDir::new("approved");
    let vdir = t.path("vault");
    let (mut a, phrase) = Vault::create(&vdir, &t.path("a"), "laptop").unwrap();
    let mut x = Vault::join_with_recovery(&vdir, &t.path("x"), &phrase, "x").unwrap();
    let pending = PendingJoin::start(&vdir, &t.path("y"), "laptop").unwrap();
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
    a.reload().unwrap();

    let resting = a.devices_resting_on(&x.device_id());
    assert_eq!(resting.len(), 1, "{resting:?}");
    assert_eq!(resting[0].id, y.device_id());
    assert_eq!(resting[0].name, "laptop");
    assert_eq!(resting[0].added_by, Some(x.device_id()));
    assert!(a.devices_resting_on(&a.device_id()).is_empty());
    let laptops = a.devices().iter().filter(|d| d.name == "laptop").count();
    assert_eq!(laptops, 2);

    a.remove_device(&x.device_id()).unwrap();
    a.put(cred(2, "after-removal.example")).unwrap();
    y.reload().unwrap();
    assert!(
        y.get(&[2; 32]).is_some(),
        "kept, as docs/vault-format.md 9.2 says"
    );
    assert_eq!(a.devices_resting_on(&x.device_id()).len(), 1);
    a.remove_device(&y.device_id()).unwrap();
    assert!(a.devices_resting_on(&x.device_id()).is_empty());
}

/// A device that joins with the phrase during a conflict settles it.
#[test]
fn a_recovery_join_during_a_conflict_can_settle_it() {
    let mut s = removed_x();
    let vdir = s.vdir();
    let vault_id = s.a.vault_id();
    let (r, chain) = s.minted(0x74);
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
    let mut d = Vault::join_with_recovery(&vdir, &s.t.path("d"), &s.phrase, "d").unwrap();
    assert!(d.report().rotation_conflict, "{:?}", d.report());
    assert_eq!(d.report().generation, 1);

    d.remove_device(&s.x.device_id()).unwrap();
    assert_follows(&d, s.gen2);
    assert!(!vdir.join(KEYS_DIR).join(forged.dir_name()).exists());
    d.put(cred(4, "example.net")).unwrap();
    assert!(d.get(&[2; 32]).is_some());
    s.a.reload().unwrap();
    assert!(s.a.get(&[4; 32]).is_some());
}

/// One event numbered 2^32 - 1 by a member must not stop pairing or make a recovery join land on
/// an older generation.
#[test]
fn a_counter_at_the_window_edge_does_not_stop_joining() {
    let t = TempDir::new("edge");
    let vdir = t.path("vault");
    let (mut a, phrase) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    let x = Vault::join_with_recovery(&vdir, &t.path("x"), &phrase, "x").unwrap();
    a.put(cred(1, "example.com")).unwrap();
    let vault_id = a.vault_id();
    let gen1 = a.current_gen();
    let k1 = key_of(&a, &gen1);
    let edge = COUNTER_WINDOW - 1;
    let put = Event::signed(
        EventKind::Put(Box::new(cred(7, "edge.example"))),
        x.device_id(),
        edge,
        &x.device.signing_seed,
        &vault_id,
    )
    .unwrap();
    plant_event(&vdir, &vault_id, &x.device_id(), &gen1, &k1, edge, &put);
    a.reload().unwrap();
    a.remove_device(&x.device_id()).unwrap();
    a.put(cred(2, "after-removal.example")).unwrap();

    let pending = PendingJoin::start(&vdir, &t.path("n"), "new").unwrap();
    let req = a
        .pairing_requests()
        .unwrap()
        .into_iter()
        .find(|r| r.request_id == pending.request().request_id)
        .unwrap();
    a.approve_pairing(&req).unwrap();
    let n = match pending.poll(&t.path("n")).unwrap() {
        PairingPoll::Joined(v) => *v,
        other => panic!("{other:?}"),
    };
    assert_eq!(n.current_gen(), a.current_gen());
    assert!(n.get(&[2; 32]).is_some());

    let d = Vault::join_with_recovery(&vdir, &t.path("d"), &phrase, "d").unwrap();
    assert_eq!(d.current_gen(), a.current_gen(), "{:?}", d.report());
    assert!(
        !d.report()
            .skipped
            .iter()
            .any(|f| f.reason == "counter out of range"),
        "{:?}",
        d.report()
    );
    assert!(d.get(&[2; 32]).is_some());
}

/// A short file with the genesis prefix does not block pairing.
#[test]
fn a_planted_genesis_prefix_does_not_block_pairing() {
    let t = TempDir::new("prefix");
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
    let mut planted = format::prefix(FileType::GenInfo).to_vec();
    planted.push(0);
    planted.extend_from_slice(&[0u8; 20]);
    assert_eq!(planted.len(), 27);
    fs::write(junk.join(GEN_INFO_NAME), &planted).unwrap();
    let genuine = vdir.join(KEYS_DIR).join(a.current_gen().dir_name());
    let real_len = fs::metadata(genuine.join(GEN_INFO_NAME)).unwrap().len();
    let mut padded = planted.clone();
    padded.resize(usize::try_from(real_len).unwrap(), 0);
    let junk2 = vdir.join(KEYS_DIR).join(
        GenId {
            number: 1,
            rotator: [0x14; 16],
        }
        .dir_name(),
    );
    fs::create_dir_all(&junk2).unwrap();
    fs::write(junk2.join(GEN_INFO_NAME), &padded).unwrap();

    let pending = PendingJoin::start(&vdir, &t.path("n"), "new").unwrap();
    let req = a
        .pairing_requests()
        .unwrap()
        .into_iter()
        .find(|r| r.request_id == pending.request().request_id)
        .unwrap();
    assert_eq!(a.pairing_words(&req).unwrap(), pending.words());
}

/// The removed device makes a device that has not seen its removal rotate a generation that
/// still holds a slot for it. The device that removed it must never write into that generation.
#[test]
fn a_lagging_device_cannot_hand_new_passkeys_to_a_removed_device() {
    let t = TempDir::new("lagging");
    let vdir = t.path("vault");
    let (mut c0, phrase) = Vault::create(&vdir, &t.path("c0"), "c0").unwrap();
    let p = Vault::join_with_recovery(&vdir, &t.path("p"), &phrase, "p").unwrap();
    let q = Vault::join_with_recovery(&vdir, &t.path("q"), &phrase, "q").unwrap();
    let x = Vault::join_with_recovery(&vdir, &t.path("x"), &phrase, "x").unwrap();
    let z = Vault::join_with_recovery(&vdir, &t.path("z"), &phrase, "z").unwrap();
    // B must sort above A, so B's sibling generation would win the old rule.
    let (mut a, mut b) = if p.device_id() < q.device_id() {
        (p, q)
    } else {
        (q, p)
    };
    c0.put(cred(1, "example.com")).unwrap();
    a.reload().unwrap();
    b.reload().unwrap();
    let vault_id = a.vault_id();
    let gen1 = a.current_gen();
    let k1 = key_of(&a, &gen1);

    a.remove_device(&x.device_id()).unwrap();
    let gen2a = a.current_gen();
    a.put(cred(2, "after-removal.example")).unwrap();

    let removal = Event::signed(
        EventKind::DeviceRemoved {
            device_id: z.device_id(),
            at: 1,
        },
        x.device_id(),
        500,
        &x.device.signing_seed,
        &vault_id,
    )
    .unwrap();
    plant_event(&vdir, &vault_id, &x.device_id(), &gen1, &k1, 500, &removal);
    let (hidden, back) = hide(&vdir, 2);
    b.reload().unwrap();
    let gen2b = b.current_gen();
    assert_eq!(
        (gen2b.number, gen2b.rotator),
        (2, b.device_id()),
        "{:?}",
        b.report()
    );
    assert!(
        vdir.join(KEYS_DIR)
            .join(gen2b.dir_name())
            .join(format::slot_name(&x.device_id()))
            .exists()
    );
    fs::rename(&hidden, &back).unwrap();

    for _ in 0..3 {
        a.reload().unwrap();
        b.reload().unwrap();
    }
    a.put(cred(3, "after-convergence.example")).unwrap();
    b.reload().unwrap();

    for v in [&a, &b] {
        let r = v.report();
        assert!(
            !r.rotation_conflict && !r.fork_detected && !r.locked_out,
            "{r:?}"
        );
        assert!(
            v.devices()
                .iter()
                .any(|d| d.id == x.device_id() && d.removed)
        );
    }
    assert_eq!(a.current_gen(), b.current_gen());
    assert!(b.get(&[2; 32]).is_some() && b.get(&[3; 32]).is_some());
    assert!(!own_record_gens(&vdir, &a.device_id()).contains(&gen2b));
    assert!(!own_record_gens(&vdir, &a.device_id()).is_empty());
    assert_ne!(gen2a, gen2b);

    let x_keys = keys_of(&vdir, &vault_id, &x, &[k1]);
    let readable = readable_with(&vdir, &vault_id, &x_keys);
    assert!(readable.contains(&vec![1; 32]), "X keeps what it had");
    assert!(!readable.contains(&vec![2; 32]), "{readable:?}");
    assert!(!readable.contains(&vec![3; 32]), "{readable:?}");
}

/// A `device added` the removed device planted through a device that had not seen its removal is
/// not carried into a generation that left it out.
#[test]
fn a_device_planted_by_a_removed_device_is_not_carried_forward() {
    let t = TempDir::new("planted-device");
    let vdir = t.path("vault");
    let (mut a, phrase) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    let mut b = Vault::join_with_recovery(&vdir, &t.path("b"), &phrase, "b").unwrap();
    let x = Vault::join_with_recovery(&vdir, &t.path("x"), &phrase, "x").unwrap();
    let z = Vault::join_with_recovery(&vdir, &t.path("z"), &phrase, "z").unwrap();
    a.reload().unwrap();
    b.reload().unwrap();
    let vault_id = a.vault_id();
    let gen1 = a.current_gen();
    let k1 = key_of(&a, &gen1);
    a.remove_device(&x.device_id()).unwrap();

    let puppet = crate::tests_line::Forger::new(0x75);
    let mut ann = crate::record::DeviceAnnouncement {
        device_id: puppet.id,
        name: "puppet".into(),
        x25519_public: puppet.member().x25519_public,
        added_at: 1,
        signing_public: puppet.member().signing_public,
        endorser: x.device_id(),
        signature: [0; 64],
    };
    ann.endorse(&vault_id, &x.device.signing_seed).unwrap();
    let added = Event::signed(
        EventKind::DeviceAdded(ann),
        x.device_id(),
        600,
        &x.device.signing_seed,
        &vault_id,
    )
    .unwrap();
    plant_event(&vdir, &vault_id, &x.device_id(), &gen1, &k1, 600, &added);
    let removal = Event::signed(
        EventKind::DeviceRemoved {
            device_id: z.device_id(),
            at: 1,
        },
        x.device_id(),
        601,
        &x.device.signing_seed,
        &vault_id,
    )
    .unwrap();
    plant_event(&vdir, &vault_id, &x.device_id(), &gen1, &k1, 601, &removal);
    let (hidden, back) = hide(&vdir, 2);
    b.reload().unwrap();
    assert!(b.devices().iter().any(|d| d.id == puppet.id && !d.removed));
    fs::rename(&hidden, &back).unwrap();
    for _ in 0..3 {
        a.reload().unwrap();
        b.reload().unwrap();
    }
    assert_eq!(a.current_gen(), b.current_gen());
    for v in [&a, &b] {
        assert!(
            !v.devices().iter().any(|d| d.id == puppet.id && !d.removed),
            "{:?}",
            v.devices()
        );
        let slot = vdir
            .join(KEYS_DIR)
            .join(v.current_gen().dir_name())
            .join(format::slot_name(&puppet.id));
        assert!(!slot.exists());
    }
    assert!(matches!(
        a.remove_device(&puppet.id),
        Err(VaultError::UnknownDevice)
    ));
}

/// A directory swapped for a symlink after it was opened does not redirect writes or deletions.
#[test]
fn a_directory_swapped_after_it_was_opened_does_not_redirect_writes() {
    let t = TempDir::new("pinned");
    let root = t.path("vault");
    let elsewhere = t.path("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    fs::create_dir_all(&root).unwrap();
    fs::write(elsewhere.join("victim.rec"), b"keep").unwrap();
    let dir = crate::fsutil::vault_subdir(&root, &[RECORDS_DIR, "aa"]).unwrap();
    fs::write(root.join(RECORDS_DIR).join("aa").join("victim.rec"), b"x").unwrap();
    fs::rename(
        root.join(RECORDS_DIR).join("aa"),
        root.join(RECORDS_DIR).join("moved"),
    )
    .unwrap();
    std::os::unix::fs::symlink(&elsewhere, root.join(RECORDS_DIR).join("aa")).unwrap();

    crate::fsutil::write_atomic(&dir, "new.rec", b"data").unwrap();
    assert!(
        root.join(RECORDS_DIR)
            .join("moved")
            .join("new.rec")
            .exists()
    );
    assert!(!elsewhere.join("new.rec").exists());
    dir.remove("victim.rec").unwrap();
    assert!(elsewhere.join("victim.rec").exists());
    assert!(
        !root
            .join(RECORDS_DIR)
            .join("moved")
            .join("victim.rec")
            .exists()
    );
    assert!(crate::fsutil::vault_subdir(&root, &[RECORDS_DIR, "aa"]).is_err());
    crate::fsutil::remove_in(&root, &[RECORDS_DIR, "aa"], "victim.rec").unwrap_err();
    assert!(elsewhere.join("victim.rec").exists());
}

/// A vault made by `c0`, with `a`, `b`, `x` and `z` joined by the phrase and two passkeys of
/// `c0`; `b` sorts above `a`, so the old rule would have made `b`'s sibling generation win.
fn lagging(tag: &str) -> (TempDir, Vault, Vault, Vault, Vault, Vault) {
    let t = TempDir::new(tag);
    let vdir = t.path("vault");
    let (mut c0, phrase) = Vault::create(&vdir, &t.path("c0"), "c0").unwrap();
    let p = Vault::join_with_recovery(&vdir, &t.path("p"), &phrase, "p").unwrap();
    let q = Vault::join_with_recovery(&vdir, &t.path("q"), &phrase, "q").unwrap();
    let x = Vault::join_with_recovery(&vdir, &t.path("x"), &phrase, "x").unwrap();
    let z = Vault::join_with_recovery(&vdir, &t.path("z"), &phrase, "z").unwrap();
    let (mut a, mut b) = if p.device_id() < q.device_id() {
        (p, q)
    } else {
        (q, p)
    };
    c0.put(cred(1, "example.com")).unwrap();
    c0.put(cred(5, "example.org")).unwrap();
    a.reload().unwrap();
    b.reload().unwrap();
    (t, c0, a, b, x, z)
}

fn signed_by(x: &Vault, origin: DeviceId, lamport: u64, kind: EventKind) -> Event {
    Event::signed(kind, origin, lamport, &x.device.signing_seed, &x.vault_id()).unwrap()
}

fn converge(vs: &mut [&mut Vault]) {
    for _ in 0..3 {
        for v in vs.iter_mut() {
            v.reload().unwrap();
        }
    }
}

/// Lagging device, removal: the removed device makes a device that has not seen its removal
/// remove another device. Once the lagging device catches up, that removal is void everywhere and
/// the device keeps its access.
#[test]
fn a_removed_device_cannot_remove_another_device_through_a_lagging_one() {
    let (t, mut c0, mut a, mut b, x, mut z) = lagging("lag-removal");
    let vdir = t.path("vault");
    let vault_id = a.vault_id();
    let gen1 = a.current_gen();
    let k1 = key_of(&a, &gen1);
    a.remove_device(&x.device_id()).unwrap();

    let removal = signed_by(
        &x,
        x.device_id(),
        500,
        EventKind::DeviceRemoved {
            device_id: z.device_id(),
            at: 1,
        },
    );
    plant_event(&vdir, &vault_id, &x.device_id(), &gen1, &k1, 500, &removal);
    let (hidden, back) = hide(&vdir, 2);
    b.reload().unwrap();
    assert_eq!(b.current_gen().rotator, b.device_id(), "{:?}", b.report());
    assert!(
        b.devices()
            .iter()
            .any(|d| d.id == z.device_id() && d.removed)
    );
    fs::rename(&hidden, &back).unwrap();

    converge(&mut [&mut a, &mut b, &mut z, &mut c0]);
    a.put(cred(3, "after-convergence.example")).unwrap();
    converge(&mut [&mut a, &mut b, &mut z, &mut c0]);
    for v in [&a, &b, &z, &c0] {
        let r = v.report();
        assert!(!r.rotation_conflict && !r.fork_detected, "{r:?}");
        assert!(!r.this_device_removed && !r.locked_out, "{r:?}");
        assert_eq!(v.current_gen(), a.current_gen(), "{r:?} {:?}", v.devices());
        let devs = v.devices();
        assert!(
            devs.iter().any(|d| d.id == z.device_id() && !d.removed),
            "{devs:?}"
        );
        assert!(devs.iter().any(|d| d.id == x.device_id() && d.removed));
        assert!(v.get(&[3; 32]).is_some());
    }
    let slot = vdir
        .join(KEYS_DIR)
        .join(a.current_gen().dir_name())
        .join(format::slot_name(&z.device_id()));
    assert!(slot.exists());
    let x_keys = keys_of(&vdir, &vault_id, &x, &[k1]);
    assert!(!readable_with(&vdir, &vault_id, &x_keys).contains(&vec![3; 32]));
    let reopened = Vault::open(&vdir, &t.path("z")).unwrap();
    assert!(reopened.ensure_active().is_ok());
    assert_eq!(reopened.current_gen(), a.current_gen());
}

/// Lagging device, passkeys: the removed device changes and deletes passkeys through a
/// device that has not seen its removal, adds one with a backdated counter, and signs an event in
/// another device's name. None of it survives once that device catches up.
#[test]
fn a_removed_device_cannot_change_passkeys_through_a_lagging_one() {
    let (t, mut c0, mut a, mut b, x, mut z) = lagging("lag-passkey");
    let vdir = t.path("vault");
    let vault_id = a.vault_id();
    let gen1 = a.current_gen();
    let k1 = key_of(&a, &gen1);
    a.remove_device(&x.device_id()).unwrap();

    let me = x.device_id();
    let plant = |lamport, e: &Event| plant_event(&vdir, &vault_id, &me, &gen1, &k1, lamport, e);
    plant(
        700,
        &signed_by(
            &x,
            me,
            700,
            EventKind::Put(Box::new(cred(1, "evil.example"))),
        ),
    );
    plant(
        701,
        &signed_by(&x, me, 701, EventKind::Tombstone(vec![5; 32])),
    );
    plant(
        2,
        &signed_by(
            &x,
            me,
            2,
            EventKind::Put(Box::new(cred(9, "backdated.example"))),
        ),
    );
    plant(
        702,
        &signed_by(
            &x,
            b.device_id(),
            702,
            EventKind::Put(Box::new(cred(8, "impersonated.example"))),
        ),
    );
    plant(
        703,
        &signed_by(
            &x,
            me,
            703,
            EventKind::DeviceRemoved {
                device_id: z.device_id(),
                at: 1,
            },
        ),
    );
    let (hidden, back) = hide(&vdir, 2);
    let r = b.reload().unwrap().clone();
    assert_eq!(b.get(&[1; 32]).unwrap().rp_id, "evil.example");
    assert!(b.get(&[5; 32]).is_none());
    assert!(b.get(&[9; 32]).is_some());
    assert!(
        b.get(&[8; 32]).is_none(),
        "nobody can sign in another device's name"
    );
    assert!(
        r.skipped
            .iter()
            .any(|f| f.reason == "event signature does not verify"),
        "{r:?}"
    );
    assert_eq!(b.current_gen().rotator, b.device_id());
    fs::rename(&hidden, &back).unwrap();

    converge(&mut [&mut a, &mut b, &mut z, &mut c0]);
    for v in [&a, &b, &z, &c0] {
        let r = v.report();
        assert!(!r.rotation_conflict && !r.fork_detected, "{r:?}");
        assert_eq!(v.current_gen(), a.current_gen());
        assert_eq!(v.get(&[1; 32]).unwrap().rp_id, "example.com", "{r:?}");
        assert!(v.get(&[5; 32]).is_some(), "{r:?}");
        assert!(v.get(&[9; 32]).is_none(), "{r:?}");
        assert!(v.get(&[8; 32]).is_none());
        assert!(
            v.devices()
                .iter()
                .any(|d| d.id == z.device_id() && !d.removed)
        );
    }
    let reopened = Vault::open(&vdir, &t.path("c0")).unwrap();
    assert_eq!(reopened.get(&[1; 32]).unwrap().rp_id, "example.com");
    assert!(reopened.get(&[9; 32]).is_none());
}

/// Two devices that remove each other stay a conflict: neither removal voids the other.
#[test]
fn mutual_removals_do_not_void_each_other() {
    let t = TempDir::new("mutual");
    let vdir = t.path("vault");
    let (mut a, phrase) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    let mut x = Vault::join_with_recovery(&vdir, &t.path("x"), &phrase, "x").unwrap();
    let mut b = Vault::join_with_recovery(&vdir, &t.path("b"), &phrase, "b").unwrap();
    a.reload().unwrap();
    x.reload().unwrap();
    a.remove_device(&x.device_id()).unwrap();
    let (hidden, back) = hide(&vdir, 2);
    x.remove_device(&a.device_id()).unwrap();
    fs::rename(&hidden, &back).unwrap();
    let r = b.reload().unwrap().clone();
    assert!(r.rotation_conflict, "{r:?}");
    assert!(!r.this_device_removed);
}
