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
use crate::tests_line::Forger;
use crate::{CredentialRecord, HmacSecretPair, PhraseError, Vault, VaultError};
use hirz_crypto::Zeroizing;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new(tag: &str) -> TempDir {
        let mut r = [0u8; 8];
        hirz_crypto::random_fill(&mut r).unwrap();
        let p = std::env::temp_dir().join(format!("hirz-vault-test-{tag}-{}", hex(&r)));
        fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    pub(crate) fn path(&self, sub: &str) -> PathBuf {
        self.0.join(sub)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn cred(seed: u8, rp: &str) -> CredentialRecord {
    let (pkcs8, _, _) = hirz_crypto::es256::generate().unwrap();
    CredentialRecord {
        credential_id: vec![seed; 32],
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

pub(crate) fn record_files(vault: &Path) -> Vec<PathBuf> {
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

pub(crate) fn gen_dirs(vault: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(vault.join(KEYS_DIR))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    v.sort();
    v
}

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

    let loose: Vec<String> = words
        .iter()
        .map(|w| w.chars().take(4).collect::<String>().to_uppercase())
        .collect();
    let parsed = RecoveryPhrase::parse(&format!("  {}\n", loose.join("   "))).unwrap();
    assert_eq!(parsed.entropy(), &[0x80; 32]);
}

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
    version[0] = 3;
    assert_eq!(
        CredentialRecord::decode(&version).unwrap_err(),
        VaultError::UnsupportedVersion
    );
    let dbg = format!("{r:?}");
    assert!(!dbg.contains(&hex(&r.private_key_pkcs8)));
}

#[test]
fn record_credential_id_lengths() {
    for len in [1usize, 16, 32, 64, 1023] {
        let mut r = cred(4, "example.com");
        r.credential_id = (0..len).map(|i| i as u8).collect();
        let enc = r.encode().unwrap();
        let len16 = (len as u16).to_be_bytes();
        assert_eq!(&enc[..4], &[0x02, 0x01, len16[0], len16[1]], "len {len}");
        assert_eq!(&enc[4..4 + len], r.credential_id.as_slice());
        assert_eq!(CredentialRecord::decode(&enc).unwrap(), r);
    }
    for len in [0usize, 1024] {
        let mut r = cred(4, "example.com");
        r.credential_id = vec![1; len];
        assert!(matches!(r.validate(), Err(VaultError::InvalidRecord(_))));
        assert!(r.encode().is_err());
    }
    let mut r = cred(4, "example.com");
    r.credential_id = vec![1; 1023];
    let mut enc = r.encode().unwrap().to_vec();
    enc[2..4].copy_from_slice(&1024u16.to_be_bytes());
    enc.insert(4, 1);
    assert_eq!(
        CredentialRecord::decode(&enc).unwrap_err(),
        VaultError::Corrupt("credential_id")
    );
}

#[test]
fn version_1_records_and_tombstones_still_read() {
    use crate::codec::Writer;
    use crate::record::{Event, EventKind};

    let r = cred(5, "example.com");
    let mut v1 = r.encode().unwrap().to_vec();
    v1[0] = 1;
    assert_eq!(CredentialRecord::decode(&v1).unwrap(), r);

    let mut short = cred(5, "example.com");
    short.credential_id = vec![5; 16];
    let mut v1_short = short.encode().unwrap().to_vec();
    v1_short[0] = 1;
    assert_eq!(
        CredentialRecord::decode(&v1_short).unwrap_err(),
        VaultError::Corrupt("credential_id")
    );

    let event_with = |payload: &[u8], kind: u8| {
        let mut w = Writer::new(2);
        w.u8_field(0x01, kind).unwrap();
        w.field(0x02, &[7; 16]).unwrap();
        w.u64_field(0x03, 9).unwrap();
        w.field(0x04, payload).unwrap();
        w.field(0x05, &[0; 32]).unwrap();
        w.field(0x06, &[0; 64]).unwrap();
        let mut body = w.finish();
        crate::record::append_tag(&mut body, &[0; 32]);
        body
    };
    let put = event_with(&v1, 1);
    match Event::decode(&put).unwrap().0.kind {
        EventKind::Put(got) => assert_eq!(*got, r),
        other => panic!("{other:?}"),
    }

    let tomb_payload = |version: u8, id: &[u8]| {
        let mut w = Writer::new(version);
        w.field(0x01, id).unwrap();
        w.finish()
    };
    let v1_tomb = event_with(&tomb_payload(1, &[5; 32]), 2);
    assert_eq!(
        Event::decode(&v1_tomb).unwrap().0.kind,
        EventKind::Tombstone(vec![5; 32])
    );
    assert!(Event::decode(&event_with(&tomb_payload(1, &[5; 16]), 2)).is_err());
    let v2_tomb = event_with(&tomb_payload(2, &[5; 16]), 2);
    assert_eq!(
        Event::decode(&v2_tomb).unwrap().0.kind,
        EventKind::Tombstone(vec![5; 16])
    );
    assert!(Event::decode(&event_with(&tomb_payload(2, &[]), 2)).is_err());
    assert!(Event::decode(&event_with(&tomb_payload(2, &[5; 1024]), 2)).is_err());
    assert_eq!(
        Event::decode(&event_with(&tomb_payload(3, &[5; 16]), 2)).unwrap_err(),
        VaultError::UnsupportedVersion
    );

    let signer = hirz_crypto::ed25519::public_from_seed(&[7; 32]).unwrap();
    let author = crate::record::device_id_for(&signer);
    let fresh = Event::signed(
        EventKind::Tombstone(vec![5; 16]),
        author,
        9,
        &[7; 32],
        &[1; 16],
    )
    .unwrap();
    assert!(fresh.signature_valid(&[1; 16], &fresh.digest().unwrap()));
    assert!(!fresh.signature_valid(&[2; 16], &fresh.digest().unwrap()));
    let mut forged = fresh.clone();
    forged.origin_lamport = 10;
    assert!(!forged.signature_valid(&[1; 16], &forged.digest().unwrap()));
    forged.origin_author = [7; 16];
    forged.origin_lamport = 9;
    assert!(!forged.signature_valid(&[1; 16], &forged.digest().unwrap()));
    let mut body = fresh.encode_body().unwrap();
    crate::record::append_tag(&mut body, &[0; 32]);
    assert_eq!(Event::decode(&body).unwrap().0, fresh);
}

#[test]
fn imported_ids_of_other_lengths_merge_by_exact_id() {
    let t = TempDir::new("varid");
    let vdir = t.path("vault");
    let (mut a, phrase) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    let mut b = Vault::join_with_recovery(&vdir, &t.path("b"), &phrase, "b").unwrap();

    let long_id: Vec<u8> = (0..32u8).collect();
    let prefix_id = long_id[..16].to_vec();
    let max_id = vec![0xab; 1023];
    for (seed, id) in [(1, &long_id), (2, &prefix_id), (3, &max_id)] {
        let mut r = cred(seed, "example.com");
        r.credential_id = id.clone();
        a.put(r).unwrap();
    }
    b.reload().unwrap();
    assert_eq!(b.list_all().len(), 3);
    assert_eq!(b.get(&long_id).unwrap().user_id[0], 1);
    assert_eq!(b.get(&prefix_id).unwrap().user_id[0], 2);
    assert_eq!(b.get(&max_id).unwrap().user_id[0], 3);
    assert!(b.get(&long_id[..15]).is_none());
    assert!(b.get(&long_id[..31]).is_none());
    assert!(b.get(&[0xab; 1022]).is_none());
    assert!(b.get(&[]).is_none());

    assert!(b.delete(&prefix_id).unwrap());
    assert!(!b.delete(&long_id[..8]).unwrap());
    a.reload().unwrap();
    assert!(a.get(&prefix_id).is_none());
    assert!(a.get(&long_id).is_some());
    assert_eq!(a.list_all().len(), 2);

    for f in record_files(&vdir) {
        let name = f.file_name().unwrap().to_str().unwrap().to_string();
        assert!(!name.contains(&hex(&prefix_id)), "{name}");
        assert!(!name.contains(&hex(&max_id[..8])), "{name}");
    }

    let b_id = b.device_id();
    a.remove_device(&b_id).unwrap();
    let a2 = Vault::open(&vdir, &t.path("a")).unwrap();
    assert_eq!(a2.list_all().len(), 2);
    assert!(a2.get(&max_id).is_some());
    assert!(a2.get(&prefix_id).is_none());
}

#[test]
fn presence_helpers_and_recovery_check() {
    let t = TempDir::new("helpers");
    let vdir = t.path("vault");
    let sdir = t.path("state");
    assert!(!Vault::exists(&vdir));
    assert!(!Vault::is_set_up(&sdir));
    assert_eq!(
        Vault::check_recovery_phrase(&vdir, &RecoveryPhrase::from_entropy([1; 32])).unwrap_err(),
        VaultError::NotFound
    );
    let (mut a, phrase) = Vault::create(&vdir, &sdir, "a").unwrap();
    assert!(Vault::exists(&vdir));
    assert!(Vault::is_set_up(&sdir));
    assert!(vdir.join(crate::HEADER_FILE).is_file());
    assert!(sdir.join(crate::DEVICE_STATE_FILE).is_file());
    assert!(!Vault::is_set_up(&vdir));
    assert!(!Vault::exists(&sdir));

    assert!(Vault::check_recovery_phrase(&vdir, &phrase).unwrap());
    let wrong = RecoveryPhrase::from_entropy([9; 32]);
    assert!(!Vault::check_recovery_phrase(&vdir, &wrong).unwrap());

    let b = Vault::join_with_recovery(&vdir, &t.path("b"), &phrase, "b").unwrap();
    a.remove_device(&b.device_id()).unwrap();
    assert!(Vault::check_recovery_phrase(&vdir, &phrase).unwrap());
    let (_, other) = Vault::create(&t.path("other"), &t.path("o"), "o").unwrap();
    assert!(!Vault::check_recovery_phrase(&vdir, &other).unwrap());
    assert!(Vault::check_recovery_phrase(&t.path("other"), &other).unwrap());
}

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

    let c = Vault::open(&vdir, &t.path("a")).unwrap();
    assert!(c.get(&[1; 32]).is_none());

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

    let victim = files.last().unwrap().clone();
    let mut data = fs::read(&victim).unwrap();
    let last = data.len() - 1;
    data[last] ^= 1;
    fs::write(&victim, &data).unwrap();
    let report = a.reload().unwrap().clone();
    assert_eq!(report.skipped.len(), 1);
    assert_eq!(report.skipped[0].reason, "record does not authenticate");
    assert_eq!(a.list_all().len(), 2);

    let moved = victim.with_file_name("00000000000000000999-0011223344556677.rec");
    fs::remove_file(&victim).unwrap();
    fs::copy(&files[1], &moved).unwrap();
    let report = a.reload().unwrap().clone();
    assert!(report.skipped.iter().any(|s| {
        s.path
            .ends_with("00000000000000000999-0011223344556677.rec")
    }));

    fs::write(&moved, b"HIRZ").unwrap();
    assert!(a.reload().is_ok());
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

    assert!(!a.report().this_device_removed);
    assert!(!b.report().this_device_removed);
    let report = c.reload().unwrap().clone();
    assert!(report.locked_out);
    assert!(report.this_device_removed);
    assert!(
        Vault::open(&vdir, &t.path("c"))
            .unwrap()
            .report()
            .this_device_removed
    );
    assert!(c.get(&[4; 32]).is_none());
    assert!(matches!(
        c.put(cred(5, "example.com")),
        Err(VaultError::NoAccess)
    ));

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

    let d = Vault::join_with_recovery(&vdir, &t.path("d"), &phrase, "d").unwrap();
    assert_eq!(d.report().generation, 2);
    assert_eq!(d.list_all().len(), 4);
    assert!(!d.report().this_device_removed);

    let before = record_files(&vdir).len();
    fs::write(t.path("c").join("unrelated"), b"x").unwrap();
    assert!(Vault::forget_local(&t.path("c")).unwrap());
    assert!(!Vault::is_set_up(&t.path("c")));
    assert!(t.path("c").join("unrelated").exists());
    assert!(!t.path("c").join(format::STATE_KEYRING).exists());
    assert!(!Vault::forget_local(&t.path("c")).unwrap());
    assert!(!Vault::forget_local(&t.path("missing")).unwrap());
    assert_eq!(record_files(&vdir).len(), before);
    assert_eq!(
        Vault::open(&vdir, &t.path("a")).unwrap().list_all().len(),
        4
    );
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
    let gen1 = vdir.join(KEYS_DIR).join(&gen_dirs(&vdir)[0]);
    assert!(gen1.join("gen.info").exists());
    assert!(gen1.join("recovery.slot").exists());
    assert!(!gen1.join(format::slot_name(&a.device_id())).exists());
    let e = Vault::join_with_recovery(&vdir, &t.path("e"), &phrase, "e").unwrap();
    assert_eq!(e.list_all().len(), 1);
}

pub(crate) fn hide(vault: &Path, number: u32) -> (PathBuf, PathBuf) {
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

    a.remove_device(&x.device_id()).unwrap();
    let (hidden, back) = hide(&vdir, 2);
    x.remove_device(&a.device_id()).unwrap();
    fs::rename(&hidden, &back).unwrap();

    // Each rotator keeps the line it chose: the other generation rests on a device its own line
    // removed. A device that followed neither cannot tell who is right.
    for v in [&mut a, &mut x] {
        let r = v.reload().unwrap().clone();
        assert_eq!(r.generation, 2, "{r:?}");
        assert_eq!(r.rejected_generations, 1);
        assert!(!r.rotation_conflict && !r.this_device_removed && !r.fork_detected);
    }
    let r = b.reload().unwrap().clone();
    assert_eq!(r.rejected_generations, 2, "{r:?}");
    assert_eq!(r.generation, 1);
    assert!(r.rotation_conflict);
    assert!(!r.this_device_removed);
    assert_eq!(b.list_all().len(), 1, "existing passkeys stay readable");
    assert!(matches!(
        b.put(cred(2, "example.com")),
        Err(VaultError::RotationConflict)
    ));

    a.remove_device(&x.device_id()).unwrap();
    assert_eq!(a.report().generation, 2);
    assert!(!a.report().rotation_conflict);
    a.put(cred(2, "example.com")).unwrap();

    b.reload().unwrap();
    assert_eq!(b.report().generation, 2);
    assert_eq!(b.list_all().len(), 2);
    b.put(cred(3, "example.com")).unwrap();
    // X's own removal of A was deleted under it: a fork. A's generation rests on a device X's
    // line removed, so X cannot tell it from a forgery and never treats it as its removal.
    let r = x.reload().unwrap().clone();
    assert!(r.fork_detected && !r.this_device_removed, "{r:?}");
    assert!(x.get(&[2; 32]).is_none());
    assert!(matches!(
        x.put(cred(4, "example.com")),
        Err(VaultError::Fork)
    ));
}

#[test]
fn forged_generation_without_chain_is_ignored() {
    let t = TempDir::new("forge");
    let vdir = t.path("vault");
    let (mut a, _) = Vault::create(&vdir, &t.path("a"), "a").unwrap();
    a.put(cred(1, "example.com")).unwrap();
    let a_id = a.device_id();
    let vault_id = a.vault_id();
    let pubkey = hirz_crypto::x25519::public_key(&a.device.x25519_private).unwrap();
    let r = Forger::new(0x99);
    let fake = GenId {
        number: 2,
        rotator: r.id,
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
        recovery_signing_pub: [0; 32],
        members: vec![r.member()],
        chain: vec![],
    };
    let genesis = GenId {
        number: 1,
        rotator: a_id,
    };
    fs::write(
        dir.join("gen.info"),
        info.seal(&fake_key, &vault_id, &fake, Some(&genesis), &r.seed)
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

use crate::pairing::{PAIRING_DIR, PendingJoin, seal_approval};
use crate::{PAIRING_LIFETIME_SECS, PairingPoll, PairingRequest};

fn pairing_files(vault: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(vault.join(PAIRING_DIR))
        .map(|rd| {
            rd.map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

fn joined(p: PairingPoll) -> Vault {
    match p {
        PairingPoll::Joined(v) => *v,
        other => panic!("not joined: {other:?}"),
    }
}

#[test]
fn pairing_joins_and_shares_credentials() {
    let t = TempDir::new("pair");
    let vdir = t.path("vault");
    let (mut a, phrase) = Vault::create(&vdir, &t.path("a"), "laptop").unwrap();
    a.put(cred(1, "example.com")).unwrap();
    let c = Vault::join_with_recovery(&vdir, &t.path("c"), &phrase, "old").unwrap();
    a.reload().unwrap();
    a.remove_device(&c.device_id()).unwrap();
    assert_eq!(a.report().generation, 2);

    let sb = t.path("b");
    let pending = PendingJoin::start(&vdir, &sb, "desk").unwrap();
    assert!(!Vault::is_set_up(&sb));
    let words: Vec<&str> = pending.words().split(' ').collect();
    assert_eq!(words.len(), 4);
    let list = crate::recovery::wordlist_for_tests();
    assert!(words.iter().all(|w| list.lines().any(|l| l == *w)));
    assert!(matches!(pending.poll(&sb).unwrap(), PairingPoll::Waiting));

    let reqs = a.pairing_requests().unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0], *pending.request());
    assert_eq!(reqs[0].name, "desk");
    assert_eq!(a.pairing_words(&reqs[0]).unwrap(), pending.words());
    a.approve_pairing(&reqs[0]).unwrap();
    assert!(a.devices().iter().any(|d| d.name == "desk" && !d.removed));
    assert!(a.pairing_requests().unwrap().is_empty());

    let mut b = joined(pending.poll(&sb).unwrap());
    assert!(
        pairing_files(&vdir).is_empty(),
        "{:?}",
        pairing_files(&vdir)
    );
    assert_eq!(b.report().generation, 2);
    assert_eq!(b.get(&[1; 32]).unwrap().rp_id, "example.com");
    assert!(b.backup_state());
    b.put(cred(2, "example.org")).unwrap();
    a.reload().unwrap();
    assert_eq!(a.get(&[2; 32]).unwrap().rp_id, "example.org");

    let b2 = Vault::open(&vdir, &sb).unwrap();
    assert_eq!(b2.list_all().len(), 2);
    let d = Vault::join_with_recovery(&vdir, &t.path("d"), &phrase, "spare").unwrap();
    a.reload().unwrap();
    a.remove_device(&d.device_id()).unwrap();
    let mut b3 = Vault::open(&vdir, &sb).unwrap();
    b3.reload().unwrap();
    assert_eq!(b3.report().generation, 3);
    assert!(!b3.report().locked_out);
    assert_eq!(b3.list_all().len(), 2);
}

#[test]
fn pairing_request_is_approved_once_and_can_be_denied() {
    let t = TempDir::new("pair-once");
    let vdir = t.path("vault");
    let (mut a, _) = Vault::create(&vdir, &t.path("a"), "laptop").unwrap();
    let pending = PendingJoin::start(&vdir, &t.path("b"), "desk").unwrap();
    let req = a.pairing_requests().unwrap().remove(0);
    a.approve_pairing(&req).unwrap();
    assert!(matches!(a.approve_pairing(&req), Err(VaultError::NotFound)));
    let req_file = format!("{}.req", hex(&req.request_id));
    fs::write(
        vdir.join(PAIRING_DIR).join(&req_file),
        req.encode().unwrap(),
    )
    .unwrap();
    assert!(a.pairing_requests().unwrap().is_empty());
    assert!(!pairing_files(&vdir).contains(&req_file));
    joined(pending.poll(&t.path("b")).unwrap());
    assert!(matches!(
        pending.poll(&t.path("b")),
        Err(VaultError::AlreadyExists)
    ));

    let other = PendingJoin::start(&vdir, &t.path("e"), "tablet").unwrap();
    let r = a.pairing_requests().unwrap();
    assert_eq!(r.len(), 1);
    assert!(a.deny_pairing(&r[0].request_id).unwrap());
    assert!(!a.deny_pairing(&r[0].request_id).unwrap());
    assert!(a.pairing_requests().unwrap().is_empty());
    assert!(matches!(
        a.approve_pairing(&r[0]),
        Err(VaultError::NotFound)
    ));
    assert!(matches!(
        other.poll(&t.path("e")).unwrap(),
        PairingPoll::Waiting
    ));
    assert!(!Vault::is_set_up(&t.path("e")));
}

#[test]
fn pairing_requests_expire_and_junk_is_cleaned() {
    let t = TempDir::new("pair-exp");
    let vdir = t.path("vault");
    let (mut a, _) = Vault::create(&vdir, &t.path("a"), "laptop").unwrap();
    let now = crate::vault::now();
    let old = PendingJoin::start_at(&vdir, &t.path("b"), "desk", now - PAIRING_LIFETIME_SECS - 1)
        .unwrap();
    let future = PendingJoin::start_at(&vdir, &t.path("f"), "clock", now + 3600).unwrap();
    let junk = vdir
        .join(PAIRING_DIR)
        .join(format!("{}.req", "ab".repeat(16)));
    fs::write(&junk, b"HIRZ junk").unwrap();
    let fresh_junk = vdir
        .join(PAIRING_DIR)
        .join(format!("{}.ok", "cd".repeat(16)));
    fs::write(&fresh_junk, b"junk").unwrap();
    let past = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    fs::File::options()
        .write(true)
        .open(&junk)
        .unwrap()
        .set_modified(past)
        .unwrap();

    assert!(a.pairing_requests_at(now).unwrap().is_empty());
    let left = pairing_files(&vdir);
    // Two files survive: a request from a device whose clock runs ahead, and one still syncing.
    assert_eq!(left.len(), 2, "{left:?}");
    assert!(left.contains(&format!("{}.req", hex(&future.request().request_id))));
    assert!(fresh_junk.exists());
    assert!(matches!(
        a.approve_pairing_at(old.request(), now),
        Err(VaultError::NotFound)
    ));
    assert!(matches!(
        a.approve_pairing_at(future.request(), now),
        Err(VaultError::NotFound)
    ));
    assert!(matches!(
        old.poll(&t.path("b")).unwrap(),
        PairingPoll::Waiting
    ));
}

#[test]
fn tampered_pairing_request_changes_the_words() {
    let t = TempDir::new("pair-tamper");
    let vdir = t.path("vault");
    let (mut a, _) = Vault::create(&vdir, &t.path("a"), "laptop").unwrap();
    let pending = PendingJoin::start(&vdir, &t.path("b"), "desk").unwrap();
    let path = vdir
        .join(PAIRING_DIR)
        .join(format!("{}.req", hex(&pending.request().request_id)));
    let seen = a.pairing_requests().unwrap().remove(0);
    assert_eq!(a.pairing_words(&seen).unwrap(), pending.words());

    let (_, attacker_pub) = hirz_crypto::x25519::generate().unwrap();
    let mut forged = pending.request().clone();
    forged.public_key = attacker_pub;
    fs::write(&path, forged.encode().unwrap()).unwrap();
    let listed = a.pairing_requests().unwrap().remove(0);
    assert_eq!(listed.public_key, attacker_pub);
    assert_ne!(a.pairing_words(&listed).unwrap(), pending.words());
    assert!(matches!(
        a.approve_pairing(&seen),
        Err(VaultError::Corrupt(_))
    ));

    let mut renamed = pending.request().clone();
    renamed.name = "desk2".into();
    assert_ne!(a.pairing_words(&renamed).unwrap(), pending.words());

    let mut takeover = pending.request().clone();
    takeover.device_id = a.device_id();
    takeover.signing_key = a.device.signing_public().unwrap();
    fs::write(&path, takeover.encode().unwrap()).unwrap();
    assert!(a.pairing_requests().unwrap().is_empty());
    assert!(matches!(
        a.approve_pairing(&takeover),
        Err(VaultError::NotFound)
    ));
}

#[test]
fn forged_or_replayed_approval_is_rejected() {
    let t = TempDir::new("pair-forge");
    let vdir = t.path("vault");
    let (mut a, _) = Vault::create(&vdir, &t.path("a"), "laptop").unwrap();
    a.put(cred(1, "example.com")).unwrap();
    let sb = t.path("b");
    let pending = PendingJoin::start(&vdir, &sb, "desk").unwrap();
    let req = pending.request().clone();
    let genesis = GenId {
        number: 1,
        rotator: a.device_id(),
    };
    let ok_path = vdir
        .join(PAIRING_DIR)
        .join(format!("{}.ok", hex(&req.request_id)));
    let entry = |gen_id, key: [u8; 32]| crate::format::KeyringEntry {
        gen_id,
        key: Zeroizing::new(key),
        root: true,
    };

    fs::write(
        &ok_path,
        seal_approval(&a.vault_id(), &req, &[entry(genesis, [0x42; 32])]).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        pending.poll(&sb).unwrap(),
        PairingPoll::Invalid(_)
    ));
    assert!(!Vault::is_set_up(&sb));

    let fake = GenId {
        number: 1,
        rotator: [0x77; 16],
    };
    fs::write(
        &ok_path,
        seal_approval(&a.vault_id(), &req, &[entry(fake, [0x42; 32])]).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        pending.poll(&sb).unwrap(),
        PairingPoll::Invalid(_)
    ));

    let other = PendingJoin::start(&vdir, &t.path("e"), "tablet").unwrap();
    let other_req = a
        .pairing_requests()
        .unwrap()
        .into_iter()
        .find(|r| r.request_id == other.request().request_id)
        .unwrap();
    a.approve_pairing(&other_req).unwrap();
    let other_ok = vdir
        .join(PAIRING_DIR)
        .join(format!("{}.ok", hex(&other_req.request_id)));
    fs::copy(&other_ok, &ok_path).unwrap();
    assert!(matches!(
        pending.poll(&sb).unwrap(),
        PairingPoll::Invalid(_)
    ));
    assert!(!Vault::is_set_up(&sb));

    a.approve_pairing(&req).unwrap();
    let b = joined(pending.poll(&sb).unwrap());
    assert_eq!(b.list_all().len(), 1);
    joined(other.poll(&t.path("e")).unwrap());
}

#[test]
fn pairing_request_encoding() {
    let signing_key = hirz_crypto::ed25519::public_from_seed(&[9; 32]).unwrap();
    let req = PairingRequest {
        request_id: [1; 16],
        device_id: crate::record::device_id_for(&signing_key),
        name: "desk".into(),
        public_key: [3; 32],
        signing_key,
        created_at: 1000,
        expires_at: 1000 + PAIRING_LIFETIME_SECS,
    };
    let enc = req.encode().unwrap();
    assert_eq!(PairingRequest::decode(&enc).unwrap(), req);
    for bad in [
        PairingRequest {
            expires_at: 1000 + PAIRING_LIFETIME_SECS + 1,
            ..req.clone()
        },
        PairingRequest {
            expires_at: 999,
            ..req.clone()
        },
        PairingRequest {
            device_id: [2; 16],
            ..req.clone()
        },
    ] {
        let mut w = crate::codec::Writer::new(1);
        w.field(0x01, &bad.request_id).unwrap();
        w.field(0x02, &bad.device_id).unwrap();
        w.field(0x03, bad.name.as_bytes()).unwrap();
        w.field(0x04, &bad.public_key).unwrap();
        w.u64_field(0x05, bad.created_at).unwrap();
        w.u64_field(0x06, bad.expires_at).unwrap();
        w.field(0x07, &bad.signing_key).unwrap();
        let mut data = format::prefix(format::FileType::PairingRequest).to_vec();
        data.extend_from_slice(&w.finish());
        assert!(PairingRequest::decode(&data).is_err());
    }
    for n in 0..enc.len() {
        assert!(PairingRequest::decode(&enc[..n]).is_err());
    }
    let mut extra = enc.clone();
    extra.extend_from_slice(&[0x08, 0, 0]);
    assert!(PairingRequest::decode(&extra).is_err());
}
