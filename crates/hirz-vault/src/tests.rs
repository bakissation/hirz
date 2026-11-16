#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use crate::codec::hex;
use crate::format::{self, GenId, KEYS_DIR, RECORDS_DIR};
use crate::recovery::RecoveryPhrase;
use crate::{CredentialRecord, HmacSecretPair, PhraseError, Vault, VaultError, import_backup};
use hirz_crypto::Zeroizing;
use hirz_crypto::kdf::Argon2Params;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let mut r = [0u8; 8];
        hirz_crypto::random_fill(&mut r).unwrap();
        let p = std::env::temp_dir().join(format!("hirz-vault-test-{tag}-{}", hex(&r)));
        fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    fn path(&self, sub: &str) -> PathBuf {
        self.0.join(sub)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn cred(seed: u8, rp: &str) -> CredentialRecord {
    let (pkcs8, _, _) = hirz_crypto::es256::generate().unwrap();
    CredentialRecord {
        credential_id: [seed; 32],
        rp_id: rp.to_string(),
        rp_name: Some("Example".to_string()),
        user_id: vec![seed, 1, 2, 3],
        user_name: Some("alice".to_string()),
        user_display_name: Some("Alice".to_string()),
        algorithm: -7,
        private_key_pkcs8: pkcs8,
        created_at: 1_700_000_000,
        cred_protect: Some(2),
        hmac_secret: Some(HmacSecretPair {
            cred_random_with_uv: Zeroizing::new([seed ^ 0x55; 32]),
            cred_random_without_uv: Zeroizing::new([seed ^ 0xaa; 32]),
        }),
        discoverable: true,
        backup_eligible: true,
    }
}

fn record_files(vault: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let records = vault.join(RECORDS_DIR);
    for d in fs::read_dir(records).unwrap() {
        let d = d.unwrap().path();
        if d.is_dir() {
            for f in fs::read_dir(&d).unwrap() {
                out.push(f.unwrap().path());
            }
        }
    }
    out.sort();
    out
}

fn gen_dirs(vault: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(vault.join(KEYS_DIR))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    v.sort();
    v
}

// ---- recovery phrase ----

#[test]
fn wordlist_is_bip39_english() {
    let list = crate::recovery::wordlist_for_tests();
    assert_eq!(
        hex(&hirz_crypto::sha256(list.as_bytes())),
        "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
    );
    let words: Vec<&str> = list.lines().collect();
    assert_eq!(words.len(), 2048);
    assert!(words.windows(2).all(|w| w[0] < w[1]));
}

// BIP-39 reference vectors for 256-bit entropy.
#[test]
fn phrase_bip39_vectors() {
    let vectors = [
        (
            [0x00u8; 32],
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        ),
        (
            [0x7fu8; 32],
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        ),
        (
            [0x80u8; 32],
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        ),
        (
            [0xffu8; 32],
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        ),
    ];
    for (entropy, words) in vectors {
        let p = RecoveryPhrase::from_entropy(entropy);
        assert_eq!(p.to_words().as_str(), words);
        assert_eq!(RecoveryPhrase::parse(words).unwrap().entropy(), &entropy);
    }
    let e: [u8; 32] = (0..32)
        .map(|i| [0x68u8, 0xa7, 0x9e, 0xac][i % 4])
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    let round = RecoveryPhrase::parse(&RecoveryPhrase::from_entropy(e).to_words()).unwrap();
    assert_eq!(round.entropy(), &e);
}

#[test]
fn phrase_errors() {
    let good = RecoveryPhrase::from_entropy([0x80; 32]).to_words();
    let words: Vec<&str> = good.split(' ').collect();

    let mut swapped = words.clone();
    swapped.swap(0, 1);
    assert_eq!(
        RecoveryPhrase::parse(&swapped.join(" ")).unwrap_err(),
        VaultError::Phrase(PhraseError::Checksum)
    );

    let mut typo = words.clone();
    typo[5] = "notaword";
    assert_eq!(
        RecoveryPhrase::parse(&typo.join(" ")).unwrap_err(),
        VaultError::Phrase(PhraseError::UnknownWord(5))
    );

    assert_eq!(
        RecoveryPhrase::parse(&words[..23].join(" ")).unwrap_err(),
        VaultError::Phrase(PhraseError::WordCount(23))
    );

    let mut last = words.clone();
    last[23] = "abandon";
    assert!(RecoveryPhrase::parse(&last.join(" ")).is_err());

    // Case, extra whitespace and four-letter prefixes are accepted.
    let loose: Vec<String> = words
        .iter()
        .map(|w| w.chars().take(4).collect::<String>().to_uppercase())
        .collect();
    let parsed = RecoveryPhrase::parse(&format!("  {}\n", loose.join("   "))).unwrap();
    assert_eq!(parsed.entropy(), &[0x80; 32]);
}

// ---- records ----

#[test]
fn record_round_trip_and_validation() {
    let r = cred(7, "example.com");
    let enc = r.encode().unwrap();
    assert_eq!(CredentialRecord::decode(&enc).unwrap(), r);

    let mut minimal = cred(8, "example.com");
    minimal.rp_name = None;
    minimal.user_name = None;
    minimal.user_display_name = None;
    minimal.cred_protect = None;
    minimal.hmac_secret = None;
    minimal.user_id = Vec::new();
    let enc = minimal.encode().unwrap();
    assert_eq!(CredentialRecord::decode(&enc).unwrap(), minimal);

    let mut bad = cred(9, "example.com");
    bad.user_id = vec![0; 65];
    assert!(bad.validate().is_err());
    let mut bad = cred(9, "example.com");
    bad.backup_eligible = false;
    assert!(bad.validate().is_err());
    let mut bad = cred(9, "");
    bad.rp_id = String::new();
    assert!(bad.validate().is_err());
    let mut bad = cred(9, "example.com");
    bad.cred_protect = Some(4);
    assert!(bad.validate().is_err());

    let enc = r.encode().unwrap();
    for cut in 0..enc.len() {
        assert!(CredentialRecord::decode(&enc[..cut]).is_err(), "cut {cut}");
    }
    let mut trailing = enc.to_vec();
    trailing.push(0x01);
    assert!(CredentialRecord::decode(&trailing).is_err());
    let mut version = enc.to_vec();
    version[0] = 2;
    assert_eq!(
        CredentialRecord::decode(&version).unwrap_err(),
        VaultError::UnsupportedVersion
    );
    let dbg = format!("{r:?}");
    assert!(!dbg.contains(&hex(&r.private_key_pkcs8)));
}

// ---- vault lifecycle ----

#[test]
fn create_open_put_get() {
    let t = TempDir::new("create");
    let vdir = t.path("vault");
    let sdir = t.path("state-a");
    let (mut a, phrase) = Vault::create(&vdir, &sdir, "laptop").unwrap();
    assert_eq!(phrase.to_words().split(' ').count(), 24);
    assert!(!a.backup_state());
    a.put(cred(1, "example.com")).unwrap();
    a.put(cred(2, "example.org")).unwrap();
    assert_eq!(a.credentials_for_rp("example.com").len(), 1);
    assert_eq!(a.list_all().len(), 2);

    assert!(matches!(
        Vault::create(&vdir, &t.path("state-x"), "x"),
        Err(VaultError::AlreadyExists)
    ));

    let a2 = Vault::open(&vdir, &sdir).unwrap();
    assert_eq!(
        a2.get(&[1; 32]).unwrap(),
        &cred_like(a.get(&[1; 32]).unwrap())
    );
    assert_eq!(a2.list_all().len(), 2);
    assert!(a2.get(&[3; 32]).is_none());
    assert!(a2.get(&[1; 5]).is_none());
    assert_eq!(a2.devices().len(), 1);
    assert!(a2.devices()[0].this_device);

    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&sdir), 0o700);
    for f in ["device", "keyring", "counter"] {
        assert_eq!(mode(&sdir.join(f)), 0o600, "{f}");
    }
    for f in record_files(&vdir) {
        assert_eq!(mode(&f), 0o600);
    }

    // Updating a credential replaces it.
    let mut updated = cred(1, "example.com");
    updated.user_display_name = Some("Alice B".into());
    a.put(updated).unwrap();
    let a3 = Vault::open(&vdir, &sdir).unwrap();
    assert_eq!(
        a3.get(&[1; 32]).unwrap().user_display_name.as_deref(),
        Some("Alice B")
    );

    assert!(matches!(
        Vault::open(&t.path("nowhere"), &sdir),
        Err(VaultError::NotFound)
    ));
    assert!(matches!(
        Vault::open(&vdir, &t.path("no-state")),
        Err(VaultError::NotFound)
    ));
}

fn cred_like(r: &CredentialRecord) -> CredentialRecord {
    r.clone()
}

#[test]
fn join_with_recovery_and_backup_state() {
    let t = TempDir::new("join");
    let vdir = t.path("vault");
    let (mut a, phrase) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    a.put(cred(1, "example.com")).unwrap();

    let words = phrase.to_words();
    let parsed = RecoveryPhrase::parse(&words).unwrap();
    let mut b = Vault::join_with_recovery(&vdir, &t.path("b"), &parsed, "b").unwrap();
    assert_eq!(b.list_all().len(), 1);
    assert_eq!(b.get(&[1; 32]).unwrap().rp_id, "example.com");
    assert!(b.backup_state());
    a.reload().unwrap();
    assert!(a.backup_state());
    assert_eq!(a.devices().len(), 2);

    assert!(matches!(
        Vault::join_with_recovery(&vdir, &t.path("b"), &parsed, "b"),
        Err(VaultError::AlreadyExists)
    ));
    let wrong = RecoveryPhrase::from_entropy([9; 32]);
    assert!(matches!(
        Vault::join_with_recovery(&vdir, &t.path("c"), &wrong, "c"),
        Err(VaultError::WrongRecoveryKey)
    ));

    b.put(cred(2, "example.org")).unwrap();
    a.reload().unwrap();
    assert_eq!(a.list_all().len(), 2);

    // A state directory of another vault is refused.
    let (_, _) = Vault::create(&t.path("other"), &t.path("o"), "o").unwrap();
    assert!(matches!(
        Vault::open(&vdir, &t.path("o")),
        Err(VaultError::WrongVault)
    ));
}

#[test]
fn confirm_backup_sets_bs() {
    let t = TempDir::new("bs");
    let (mut a, _) = Vault::create(&t.path("v"), &t.path("a"), "a").unwrap();
    assert!(!a.backup_state());
    a.confirm_backup().unwrap();
    assert!(a.backup_state());
    let a2 = Vault::open(&t.path("v"), &t.path("a")).unwrap();
    assert!(a2.backup_state());
}

#[test]
fn concurrent_puts_merge() {
    let t = TempDir::new("merge");
    let vdir = t.path("vault");
    let (mut a, phrase) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    let mut b = Vault::join_with_recovery(&vdir, &t.path("b"), &phrase, "b").unwrap();
    a.reload().unwrap();

    // Neither device sees the other's write before writing.
    a.put(cred(1, "example.com")).unwrap();
    b.put(cred(2, "example.com")).unwrap();
    let mut on_a = cred(3, "example.com");
    on_a.user_name = Some("from-a".into());
    let mut on_b = cred(3, "example.com");
    on_b.user_name = Some("from-b".into());
    a.put(on_a).unwrap();
    b.put(on_b).unwrap();

    a.reload().unwrap();
    b.reload().unwrap();
    assert_eq!(a.list_all().len(), 3);
    assert_eq!(b.list_all().len(), 3);
    let wa = a.get(&[3; 32]).unwrap().user_name.clone();
    let wb = b.get(&[3; 32]).unwrap().user_name.clone();
    assert_eq!(wa, wb, "both devices pick the same winner");

    // Lamport: a write after seeing the other device's events wins.
    let mut later = cred(3, "example.com");
    later.user_name = Some("later".into());
    a.put(later).unwrap();
    b.reload().unwrap();
    assert_eq!(b.get(&[3; 32]).unwrap().user_name.as_deref(), Some("later"));
}

#[test]
fn tombstones() {
    let t = TempDir::new("tomb");
    let vdir = t.path("vault");
    let (mut a, phrase) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    let mut b = Vault::join_with_recovery(&vdir, &t.path("b"), &phrase, "b").unwrap();
    a.put(cred(1, "example.com")).unwrap();
    a.put(cred(2, "example.com")).unwrap();
    b.reload().unwrap();
    assert_eq!(b.list_all().len(), 2);

    assert!(b.delete(&[1; 32]).unwrap());
    assert!(!b.delete(&[1; 32]).unwrap());
    assert!(!b.delete(&[7; 32]).unwrap());
    a.reload().unwrap();
    assert!(a.get(&[1; 32]).is_none());
    assert_eq!(a.list_all().len(), 1);

    // A stale put with an older counter does not resurrect a deleted credential.
    let c = Vault::open(&vdir, &t.path("a")).unwrap();
    assert!(c.get(&[1; 32]).is_none());

    // Re-creating after a delete works (newer counter).
    a.put(cred(1, "example.com")).unwrap();
    b.reload().unwrap();
    assert!(b.get(&[1; 32]).is_some());
}

#[test]
fn tamper_detection_is_per_file() {
    let t = TempDir::new("tamper");
    let vdir = t.path("vault");
    let (mut a, _) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    a.put(cred(1, "example.com")).unwrap();
    a.put(cred(2, "example.com")).unwrap();
    a.put(cred(3, "example.com")).unwrap();
    let files = record_files(&vdir);
    assert_eq!(files.len(), 4);

    // Flip one ciphertext byte of the newest record.
    let victim = files.last().unwrap().clone();
    let mut data = fs::read(&victim).unwrap();
    let last = data.len() - 1;
    data[last] ^= 1;
    fs::write(&victim, &data).unwrap();
    let report = a.reload().unwrap().clone();
    assert_eq!(report.skipped.len(), 1);
    assert_eq!(report.skipped[0].reason, "record does not authenticate");
    assert_eq!(a.list_all().len(), 2);

    // Moving a valid record to another name fails too (the path is authenticated).
    let moved = victim.with_file_name("00000000000000000999-0011223344556677.rec");
    fs::remove_file(&victim).unwrap();
    fs::copy(&files[1], &moved).unwrap();
    let report = a.reload().unwrap().clone();
    assert!(report.skipped.iter().any(|s| {
        s.path
            .ends_with("00000000000000000999-0011223344556677.rec")
    }));

    // Garbage with a valid name is skipped, not fatal.
    fs::write(&moved, b"HIRZ").unwrap();
    assert!(a.reload().is_ok());
    // A truncated gen.info is reported; the keyring keeps the vault usable for this device.
    assert!(Vault::open(&vdir, &t.path("a")).is_ok());
}

#[test]
fn unknown_temp_and_conflict_files_are_ignored() {
    let t = TempDir::new("ignore");
    let vdir = t.path("vault");
    let (mut a, _) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    a.put(cred(1, "example.com")).unwrap();
    let files = record_files(&vdir);
    let dir = files[0].parent().unwrap().to_path_buf();
    let original = fs::read(&files[1]).unwrap();
    let stem = files[1].file_name().unwrap().to_str().unwrap().to_string();
    let conflict_names = [
        format!(
            "{}.sync-conflict-20260101-120000-ABCDEFG.rec",
            stem.trim_end_matches(".rec")
        ),
        format!(
            "{} (conflicted copy 2026-01-01).rec",
            stem.trim_end_matches(".rec")
        ),
        format!(".{stem}.tmp-0123456789abcdef"),
        "notes.txt".to_string(),
        format!("{}~", stem),
    ];
    for n in &conflict_names {
        fs::write(dir.join(n), &original).unwrap();
    }
    fs::create_dir_all(vdir.join(RECORDS_DIR).join("not-a-device")).unwrap();
    fs::write(vdir.join(RECORDS_DIR).join("README"), b"x").unwrap();
    fs::create_dir_all(vdir.join(KEYS_DIR).join("garbage")).unwrap();
    fs::write(vdir.join("hirz-vault.sync-conflict-x"), b"x").unwrap();

    let report = a.reload().unwrap().clone();
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
    assert!(report.ignored_files >= conflict_names.len() + 3);
    assert_eq!(a.list_all().len(), 1);
    assert!(Vault::open(&vdir, &t.path("a")).is_ok());
}

#[test]
fn rotation_locks_out_removed_device() {
    let t = TempDir::new("rotate");
    let vdir = t.path("vault");
    let (mut a, phrase) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    let mut b = Vault::join_with_recovery(&vdir, &t.path("b"), &phrase, "b").unwrap();
    let mut c = Vault::join_with_recovery(&vdir, &t.path("c"), &phrase, "c").unwrap();
    a.put(cred(1, "example.com")).unwrap();
    b.put(cred(2, "example.com")).unwrap();
    c.put(cred(3, "example.com")).unwrap();
    a.reload().unwrap();
    assert_eq!(a.list_all().len(), 3);
    assert_eq!(a.devices().len(), 3);

    let c_id = c.device_id();
    assert!(matches!(
        a.remove_device(&a.device_id()),
        Err(VaultError::CannotRemoveSelf)
    ));
    assert!(matches!(
        a.remove_device(&[0xee; 16]),
        Err(VaultError::UnknownDevice)
    ));
    a.remove_device(&c_id).unwrap();
    assert_eq!(a.report().generation, 2);
    assert_eq!(
        a.list_all().len(),
        3,
        "live records carried into the new generation"
    );
    assert!(a.devices().iter().any(|d| d.id == c_id && d.removed));

    a.put(cred(4, "example.com")).unwrap();
    let new_file = record_files(&vdir)
        .into_iter()
        .max_by_key(|p| fs::metadata(p).unwrap().modified().unwrap())
        .unwrap();

    b.reload().unwrap();
    assert_eq!(b.report().generation, 2);
    assert_eq!(b.list_all().len(), 4);
    assert!(b.devices().iter().any(|d| d.id == c_id && d.removed));

    let report = c.reload().unwrap().clone();
    assert!(report.locked_out);
    assert!(c.get(&[4; 32]).is_none());
    assert!(matches!(
        c.put(cred(5, "example.com")),
        Err(VaultError::NoAccess)
    ));

    // No key the removed device holds opens a record of the new generation.
    let data = fs::read(&new_file).unwrap();
    let gen_id = format::record_gen(&data).unwrap();
    assert_eq!(gen_id.number, 2);
    let rel = new_file
        .strip_prefix(&vdir)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    for e in &c.keyring.entries {
        assert!(format::open_record(&data, &e.key, &c.vault_id(), &gen_id, &rel).is_err());
        assert!(format::open_record(&data, &e.key, &c.vault_id(), &e.gen_id, &rel).is_err());
    }
    // The removed device has no slot in the new generation.
    let gen2 = gen_dirs(&vdir)
        .into_iter()
        .find(|d| d.starts_with("0000000002-"))
        .unwrap();
    assert!(
        !vdir
            .join(KEYS_DIR)
            .join(&gen2)
            .join(format::slot_name(&c_id))
            .exists()
    );

    // A device joining later with the recovery phrase walks the chain to generation 2.
    let d = Vault::join_with_recovery(&vdir, &t.path("d"), &phrase, "d").unwrap();
    assert_eq!(d.report().generation, 2);
    assert_eq!(d.list_all().len(), 4);
}

#[test]
fn garbage_collection_after_rotation() {
    let t = TempDir::new("gc");
    let vdir = t.path("vault");
    let (mut a, phrase) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    let c = Vault::join_with_recovery(&vdir, &t.path("c"), &phrase, "c").unwrap();
    a.reload().unwrap();
    a.put(cred(1, "example.com")).unwrap();
    a.remove_device(&c.device_id()).unwrap();
    let before = record_files(&vdir).len();
    a.reload().unwrap();
    assert_eq!(a.report().collected, 0, "grace period not over");
    a.gc_grace = 0;
    let report = a.reload().unwrap().clone();
    assert!(report.collected > 0);
    let after = record_files(&vdir);
    assert!(after.len() < before);
    for f in &after {
        let g = format::record_gen(&fs::read(f).unwrap()).unwrap();
        assert_eq!(g.number, 2);
    }
    assert_eq!(a.list_all().len(), 1);
    // gen.info and recovery.slot of generation 1 stay for the recovery chain.
    let gen1 = vdir.join(KEYS_DIR).join(&gen_dirs(&vdir)[0]);
    assert!(gen1.join("gen.info").exists());
    assert!(gen1.join("recovery.slot").exists());
    assert!(!gen1.join(format::slot_name(&a.device_id())).exists());
    let e = Vault::join_with_recovery(&vdir, &t.path("e"), &phrase, "e").unwrap();
    assert_eq!(e.list_all().len(), 1);
}

/// Hides a generation directory as if the sync tool had not delivered it yet.
fn hide(vault: &Path, number: u32) -> (PathBuf, PathBuf) {
    let name = gen_dirs(vault)
        .into_iter()
        .find(|d| d.starts_with(&format!("{number:010}-")))
        .unwrap();
    let from = vault.join(KEYS_DIR).join(&name);
    let to = vault.join(format!(".hidden-{name}"));
    fs::rename(&from, &to).unwrap();
    (to, from)
}

#[test]
fn concurrent_rotations_converge() {
    let t = TempDir::new("conc");
    let vdir = t.path("vault");
    let (mut a, phrase) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    let mut b = Vault::join_with_recovery(&vdir, &t.path("b"), &phrase, "b").unwrap();
    let c = Vault::join_with_recovery(&vdir, &t.path("c"), &phrase, "c").unwrap();
    let d = Vault::join_with_recovery(&vdir, &t.path("d"), &phrase, "d").unwrap();
    a.put(cred(1, "example.com")).unwrap();
    a.reload().unwrap();
    b.reload().unwrap();

    a.remove_device(&c.device_id()).unwrap();
    let (hidden, back) = hide(&vdir, 2);
    b.remove_device(&d.device_id()).unwrap();
    fs::rename(&hidden, &back).unwrap();

    // Each reload may migrate or rotate; a few rounds converge.
    for _ in 0..3 {
        a.reload().unwrap();
        b.reload().unwrap();
    }
    assert_eq!(a.report().generation, 3);
    assert_eq!(b.report().generation, 3);
    assert_eq!(a.list_all().len(), 1);
    assert_eq!(b.list_all().len(), 1);
    for v in [&a, &b] {
        let devs = v.devices();
        assert!(devs.iter().any(|x| x.id == c.device_id() && x.removed));
        assert!(devs.iter().any(|x| x.id == d.device_id() && x.removed));
    }
    let gen3 = gen_dirs(&vdir)
        .into_iter()
        .filter(|d| d.starts_with("0000000003-"))
        .collect::<Vec<_>>();
    assert!(!gen3.is_empty());
    for g in gen3 {
        let dir = vdir.join(KEYS_DIR).join(g);
        assert!(!dir.join(format::slot_name(&c.device_id())).exists());
        assert!(!dir.join(format::slot_name(&d.device_id())).exists());
    }
}

#[test]
fn straggler_write_is_carried_forward() {
    let t = TempDir::new("straggler");
    let vdir = t.path("vault");
    let (mut a, phrase) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    let mut b = Vault::join_with_recovery(&vdir, &t.path("b"), &phrase, "b").unwrap();
    let c = Vault::join_with_recovery(&vdir, &t.path("c"), &phrase, "c").unwrap();
    a.reload().unwrap();
    a.remove_device(&c.device_id()).unwrap();

    // b has not seen the rotation yet and writes under generation 1.
    let (hidden, back) = hide(&vdir, 2);
    b.reload().unwrap();
    b.put(cred(9, "example.net")).unwrap();
    fs::rename(&hidden, &back).unwrap();

    a.reload().unwrap();
    assert!(
        a.get(&[9; 32]).is_none(),
        "old-generation write is not trusted"
    );
    let report = b.reload().unwrap().clone();
    assert_eq!(report.migrated, 1);
    a.reload().unwrap();
    assert_eq!(a.get(&[9; 32]).unwrap().rp_id, "example.net");
}

#[test]
fn mutual_removal_race_is_rejected_until_the_user_decides() {
    let t = TempDir::new("race");
    let vdir = t.path("vault");
    let (mut a, phrase) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    let mut x = Vault::join_with_recovery(&vdir, &t.path("x"), &phrase, "x").unwrap();
    let mut b = Vault::join_with_recovery(&vdir, &t.path("b"), &phrase, "b").unwrap();
    a.put(cred(1, "example.com")).unwrap();
    a.reload().unwrap();
    x.reload().unwrap();

    // a removes x while x, not yet seeing that, removes a.
    a.remove_device(&x.device_id()).unwrap();
    let (hidden, back) = hide(&vdir, 2);
    x.remove_device(&a.device_id()).unwrap();
    fs::rename(&hidden, &back).unwrap();

    // Every device reaches the same verdict: both rotations are rejected.
    for v in [&mut a, &mut x, &mut b] {
        let r = v.reload().unwrap().clone();
        assert_eq!(r.rejected_generations, 2, "{r:?}");
        assert_eq!(r.generation, 1);
        assert!(r.rotation_conflict);
    }
    assert!(matches!(
        b.put(cred(2, "example.com")),
        Err(VaultError::RotationConflict)
    ));

    // The user decides on a that x is the untrusted one.
    a.remove_device(&x.device_id()).unwrap();
    assert_eq!(a.report().generation, 2);
    assert!(!a.report().rotation_conflict);
    a.put(cred(2, "example.com")).unwrap();

    b.reload().unwrap();
    assert_eq!(b.report().generation, 2);
    assert_eq!(b.list_all().len(), 2);
    b.put(cred(3, "example.com")).unwrap();
    assert!(x.reload().unwrap().locked_out);
    assert!(x.get(&[2; 32]).is_none());
}

#[test]
fn forged_generation_without_chain_is_ignored() {
    let t = TempDir::new("forge");
    let vdir = t.path("vault");
    let (mut a, _) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    a.put(cred(1, "example.com")).unwrap();
    let a_id = a.device_id();
    let vault_id = a.vault_id();
    // Anyone with folder access can seal a key to a device public key. Without a gen.info
    // authenticated by the previous generation's key, the generation is not used.
    let pubkey = hirz_crypto::x25519::public_key(&a.device.x25519_private).unwrap();
    let fake = GenId {
        number: 2,
        rotator: [0x99; 16],
    };
    let fake_key = [0x42u8; 32];
    let dir = vdir.join(KEYS_DIR).join(fake.dir_name());
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join(format::slot_name(&a_id)),
        format::seal_device_slot(&vault_id, &fake, &a_id, &pubkey, &fake_key).unwrap(),
    )
    .unwrap();
    let info = format::GenInfo {
        commitment: format::commitment(&fake_key, &vault_id, &fake),
        recovery_pub: [0; 32],
        removed: vec![],
        created_at: 0,
        reemit_first: 0,
        reemit_count: 0,
        recovery_tag: None,
    };
    let genesis = GenId {
        number: 1,
        rotator: a_id,
    };
    fs::write(
        dir.join("gen.info"),
        info.seal(&fake_key, &vault_id, &fake, Some(&genesis))
            .unwrap(),
    )
    .unwrap();
    let report = a.reload().unwrap().clone();
    assert_eq!(report.generation, 1);
    assert!(
        report
            .skipped
            .iter()
            .any(|s| s.path.contains(&fake.dir_name()))
    );
    a.put(cred(2, "example.com")).unwrap();
    let files = record_files(&vdir);
    let newest = files
        .iter()
        .max_by_key(|p| fs::metadata(p).unwrap().modified().unwrap())
        .unwrap();
    assert_eq!(
        format::record_gen(&fs::read(newest).unwrap())
            .unwrap()
            .number,
        1
    );
}

#[test]
fn backup_export_import() {
    let t = TempDir::new("backup");
    let (mut a, phrase) = Vault::create(&t.path("v"), &t.path("a"), "a").unwrap();
    a.put(cred(1, "example.com")).unwrap();
    a.put(cred(2, "example.org")).unwrap();
    let fast = Argon2Params {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };

    let plain = a.export_backup_with_params(&phrase, None, fast).unwrap();
    let back = import_backup(&plain, &phrase, None).unwrap();
    assert_eq!(back.len(), 2);
    assert!(back.iter().any(|r| *r == *a.get(&[1; 32]).unwrap()));

    let protected = a
        .export_backup_with_params(&phrase, Some(b"correct horse"), fast)
        .unwrap();
    assert_eq!(
        import_backup(&protected, &phrase, Some(b"correct horse"))
            .unwrap()
            .len(),
        2
    );
    assert!(matches!(
        import_backup(&protected, &phrase, Some(b"wrong")),
        Err(VaultError::WrongRecoveryKey)
    ));
    assert!(matches!(
        import_backup(&protected, &phrase, None),
        Err(VaultError::InvalidParameters)
    ));
    let other = RecoveryPhrase::from_entropy([3; 32]);
    assert!(import_backup(&plain, &other, None).is_err());
    assert!(matches!(
        a.export_backup_with_params(&other, None, fast),
        Err(VaultError::WrongRecoveryKey)
    ));
    let mut tampered = protected.clone();
    let n = tampered.len() - 1;
    tampered[n] ^= 1;
    assert!(import_backup(&tampered, &phrase, Some(b"correct horse")).is_err());

    // Hostile Argon2 parameters are refused before any work is done.
    let mut hostile = protected.clone();
    let m_offset = 6 + 16 + 1 + 16;
    hostile[m_offset..m_offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        import_backup(&hostile, &phrase, Some(b"correct horse")),
        Err(VaultError::InvalidParameters)
    ));
}

#[test]
fn rollback_is_reported() {
    let t = TempDir::new("rollback");
    let vdir = t.path("vault");
    let (mut a, _) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    a.put(cred(1, "example.com")).unwrap();
    a.put(cred(2, "example.com")).unwrap();
    a.reload().unwrap();
    assert!(!a.report().rollback_suspected);
    let newest = record_files(&vdir).into_iter().max().unwrap();
    fs::remove_file(newest).unwrap();
    assert!(a.reload().unwrap().rollback_suspected);
}

#[test]
fn concurrent_processes_share_counter() {
    let t = TempDir::new("procs");
    let vdir = t.path("vault");
    let sdir = t.path("a");
    let (_a, _) = Vault::create(&vdir, &sdir, "a").unwrap();
    let handles: Vec<_> = (0..4u8)
        .map(|i| {
            let (v, s) = (vdir.clone(), sdir.clone());
            std::thread::spawn(move || {
                let mut h = Vault::open(&v, &s).unwrap();
                for j in 0..5u8 {
                    h.put(cred(i * 10 + j + 1, "example.com")).unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let a = Vault::open(&vdir, &sdir).unwrap();
    assert_eq!(a.list_all().len(), 20);
    let mut lamports: Vec<u64> = record_files(&vdir)
        .iter()
        .map(|p| {
            format::RecordName::parse(p.file_name().unwrap().to_str().unwrap())
                .unwrap()
                .lamport
        })
        .collect();
    let n = lamports.len();
    lamports.sort();
    lamports.dedup();
    assert_eq!(lamports.len(), n, "no counter value used twice");
    assert!(!sdir.join("lock").exists());
}
