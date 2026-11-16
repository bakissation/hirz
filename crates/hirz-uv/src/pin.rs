//! The hirz PIN: a verifier kept in the state directory and checked by the host.
//!
//! File `<state_dir>/pin` (mode 0600, directory 0700), rewritten atomically:
//!
//! ```text
//! hirz-pin 1
//! kdf argon2id <m_cost_kib> <t_cost> <p_cost>
//! salt <hex>
//! hash <hex>
//! failures <n>
//! ```
//!
//! The failure counter is incremented and written to disk before the PIN is checked, so
//! killing the process mid-check never yields a free guess. After [`MAX_FAILURES`] wrong PINs
//! the PIN is locked until [`PinStore::reset`]. From [`FREE_FAILURES`] failures on, each check
//! waits [`failure_delay`] first.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use hirz_crypto::kdf::{self, Argon2Params};
use hirz_proto::hex::encode as hex_encode;

pub const MIN_PIN_CODE_POINTS: usize = 4;
pub const MAX_PIN_BYTES: usize = 63;
pub const MAX_FAILURES: u32 = 8;
pub const FREE_FAILURES: u32 = 3;
pub const MAX_DELAY: Duration = Duration::from_secs(30);

const FILE_NAME: &str = "pin";
const TMP_NAME: &str = "pin.tmp";
const HEADER: &str = "hirz-pin 1";
const SALT_LEN: usize = 16;
const MAX_FILE_BYTES: usize = 1024;
const MIN_HASH_LEN: usize = 16;
const MAX_HASH_LEN: usize = 64;
const MAX_M_COST_KIB: u32 = 4 * 1024 * 1024;
const MAX_T_COST: u32 = 16;
const MAX_P_COST: u32 = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinError {
    /// Fewer than [`MIN_PIN_CODE_POINTS`] Unicode code points.
    TooShort,
    /// More than [`MAX_PIN_BYTES`] bytes of UTF-8.
    TooLong,
    NotUtf8,
    NotSet,
    AlreadySet,
    /// Wrong PIN; `remaining` attempts before the lock.
    Wrong {
        remaining: u32,
    },
    Locked,
    /// The verifier file does not parse or has out-of-range parameters.
    Corrupt,
    Io(std::io::ErrorKind),
    Crypto,
}

/// CTAP rules: at least 4 code points, at most 63 bytes.
pub fn validate_pin(pin: &[u8]) -> Result<(), PinError> {
    let s = core::str::from_utf8(pin).map_err(|_| PinError::NotUtf8)?;
    if s.len() > MAX_PIN_BYTES {
        return Err(PinError::TooLong);
    }
    if s.chars().count() < MIN_PIN_CODE_POINTS {
        return Err(PinError::TooShort);
    }
    Ok(())
}

/// Delay before checking a PIN when `failures` wrong attempts are already recorded:
/// none below [`FREE_FAILURES`], then 1, 2, 4, 8, 16 seconds, capped at [`MAX_DELAY`].
pub fn failure_delay(failures: u32) -> Duration {
    let Some(step) = failures.checked_sub(FREE_FAILURES) else {
        return Duration::ZERO;
    };
    let secs = 1u64.checked_shl(step).unwrap_or(u64::MAX);
    Duration::from_secs(secs).min(MAX_DELAY)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verifier {
    pub params: Argon2Params,
    pub salt: Vec<u8>,
    pub hash: Vec<u8>,
    pub failures: u32,
}

fn hex_decode(s: &str, min: usize, max: usize) -> Option<Vec<u8>> {
    if s.len() < min.saturating_mul(2) || s.len() > max.saturating_mul(2) {
        return None;
    }
    hirz_proto::hex::decode(s).ok()
}

fn parse_u32(s: &str) -> Option<u32> {
    if s.is_empty() || s.len() > 10 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    s.parse().ok()
}

fn params_in_range(p: &Argon2Params) -> bool {
    (1..=MAX_T_COST).contains(&p.t_cost)
        && (1..=MAX_P_COST).contains(&p.p_cost)
        && p.m_cost_kib <= MAX_M_COST_KIB
        && p.m_cost_kib >= p.p_cost.saturating_mul(8)
}

pub fn parse_verifier(input: &[u8]) -> Result<Verifier, PinError> {
    if input.len() > MAX_FILE_BYTES {
        return Err(PinError::Corrupt);
    }
    let text = core::str::from_utf8(input).map_err(|_| PinError::Corrupt)?;
    let body = text.strip_suffix('\n').ok_or(PinError::Corrupt)?;
    let lines: Vec<&str> = body.split('\n').collect();
    let [header, kdf_line, salt_line, hash_line, failures_line] = lines.as_slice() else {
        return Err(PinError::Corrupt);
    };
    if *header != HEADER {
        return Err(PinError::Corrupt);
    }
    let params = match kdf_line.split(' ').collect::<Vec<_>>().as_slice() {
        ["kdf", "argon2id", m, t, p] => Argon2Params {
            m_cost_kib: parse_u32(m).ok_or(PinError::Corrupt)?,
            t_cost: parse_u32(t).ok_or(PinError::Corrupt)?,
            p_cost: parse_u32(p).ok_or(PinError::Corrupt)?,
        },
        _ => return Err(PinError::Corrupt),
    };
    if !params_in_range(&params) {
        return Err(PinError::Corrupt);
    }
    let salt = salt_line
        .strip_prefix("salt ")
        .and_then(|h| hex_decode(h, SALT_LEN, SALT_LEN))
        .ok_or(PinError::Corrupt)?;
    let hash = hash_line
        .strip_prefix("hash ")
        .and_then(|h| hex_decode(h, MIN_HASH_LEN, MAX_HASH_LEN))
        .ok_or(PinError::Corrupt)?;
    let failures = failures_line
        .strip_prefix("failures ")
        .and_then(parse_u32)
        .filter(|f| *f <= MAX_FAILURES)
        .ok_or(PinError::Corrupt)?;
    Ok(Verifier {
        params,
        salt,
        hash,
        failures,
    })
}

pub fn serialize_verifier(v: &Verifier) -> String {
    format!(
        "{HEADER}\nkdf argon2id {} {} {}\nsalt {}\nhash {}\nfailures {}\n",
        v.params.m_cost_kib,
        v.params.t_cost,
        v.params.p_cost,
        hex_encode(&v.salt),
        hex_encode(&v.hash),
        v.failures
    )
}

/// Status for `hirz status` and similar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinStatus {
    pub failures: u32,
    pub locked: bool,
}

#[derive(Debug, Clone)]
pub struct PinStore {
    dir: PathBuf,
    /// Used for new verifiers, and the floor accepted when reading one.
    params: Argon2Params,
    sleep: fn(Duration),
}

impl PinStore {
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        Self::with_params(state_dir, kdf::DEFAULT)
    }

    pub fn with_params(state_dir: impl Into<PathBuf>, params: Argon2Params) -> Self {
        PinStore {
            dir: state_dir.into(),
            params,
            sleep: std::thread::sleep,
        }
    }

    /// Replaces the function used for the failure delay (tests).
    pub fn with_sleep(mut self, sleep: fn(Duration)) -> Self {
        self.sleep = sleep;
        self
    }

    pub fn path(&self) -> PathBuf {
        self.dir.join(FILE_NAME)
    }

    pub fn is_set(&self) -> bool {
        self.path().is_file()
    }

    pub fn status(&self) -> Result<Option<PinStatus>, PinError> {
        match self.load() {
            Ok(v) => Ok(Some(PinStatus {
                failures: v.failures,
                locked: v.failures >= MAX_FAILURES,
            })),
            Err(PinError::NotSet) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Sets the first PIN. Fails with `AlreadySet` when one exists; use `change_pin`.
    pub fn set_pin(&self, new_pin: &[u8]) -> Result<(), PinError> {
        validate_pin(new_pin)?;
        if self.path().exists() {
            return Err(PinError::AlreadySet);
        }
        self.write_new(new_pin)
    }

    /// Checks `old_pin` (counting a failure like any other check), then replaces the PIN.
    pub fn change_pin(&self, old_pin: &[u8], new_pin: &[u8]) -> Result<(), PinError> {
        validate_pin(new_pin)?;
        self.verify(old_pin)?;
        self.write_new(new_pin)
    }

    /// Removes the verifier, which also clears a lock. The caller decides what proof the user
    /// must give first.
    pub fn reset(&self) -> Result<(), PinError> {
        match fs::remove_file(self.path()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(PinError::Io(e.kind())),
        }
    }

    pub fn verify(&self, pin: &[u8]) -> Result<(), PinError> {
        validate_pin(pin)?;
        let mut v = self.load()?;
        if v.failures >= MAX_FAILURES {
            return Err(PinError::Locked);
        }
        let before = v.failures;
        v.failures = before.saturating_add(1);
        self.store(&v)?;
        let delay = failure_delay(before);
        if !delay.is_zero() {
            (self.sleep)(delay);
        }
        let derived = kdf::argon2id(pin, &v.salt, v.params).map_err(|_| PinError::Crypto)?;
        if hirz_crypto::ct_eq(&derived, &v.hash) {
            v.failures = 0;
            self.store(&v)?;
            Ok(())
        } else {
            Err(PinError::Wrong {
                remaining: MAX_FAILURES.saturating_sub(v.failures),
            })
        }
    }

    fn write_new(&self, pin: &[u8]) -> Result<(), PinError> {
        let mut salt = vec![0u8; SALT_LEN];
        hirz_crypto::random_fill(&mut salt).map_err(|_| PinError::Crypto)?;
        let hash = kdf::argon2id(pin, &salt, self.params).map_err(|_| PinError::Crypto)?;
        if !(MIN_HASH_LEN..=MAX_HASH_LEN).contains(&hash.len()) {
            return Err(PinError::Crypto);
        }
        self.store(&Verifier {
            params: self.params,
            salt,
            hash: hash.to_vec(),
            failures: 0,
        })
    }

    fn load(&self) -> Result<Verifier, PinError> {
        let f = match fs::File::open(self.path()) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(PinError::NotSet),
            Err(e) => return Err(PinError::Io(e.kind())),
        };
        let mut buf = Vec::new();
        let cap = u64::try_from(MAX_FILE_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        f.take(cap)
            .read_to_end(&mut buf)
            .map_err(|e| PinError::Io(e.kind()))?;
        let v = parse_verifier(&buf)?;
        let floor = self.params;
        if v.params.m_cost_kib < floor.m_cost_kib
            || v.params.t_cost < floor.t_cost
            || v.params.p_cost < floor.p_cost
        {
            return Err(PinError::Corrupt);
        }
        Ok(v)
    }

    pub(crate) fn store(&self, v: &Verifier) -> Result<(), PinError> {
        ensure_private_dir(&self.dir).map_err(|e| PinError::Io(e.kind()))?;
        write_atomic(&self.dir, &serialize_verifier(v)).map_err(|e| PinError::Io(e.kind()))
    }
}

/// Creates the state directory with mode 0700 and tightens an existing one.
pub fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let md = fs::metadata(dir)?;
    if md.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_atomic(dir: &Path, content: &str) -> std::io::Result<()> {
    let tmp = dir.join(TMP_NAME);
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
    f.write_all(content.as_bytes())?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, dir.join(FILE_NAME))?;
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    pub(crate) const TEST_PARAMS: Argon2Params = Argon2Params {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };

    pub(crate) struct TempDir(pub PathBuf);
    impl TempDir {
        pub(crate) fn new(tag: &str) -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let p =
                std::env::temp_dir().join(format!("hirz-uv-test-{}-{tag}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// True once hirz-crypto has real implementations (the placeholder returns errors).
    pub(crate) fn crypto_ready() -> bool {
        let mut b = [0u8; 4];
        hirz_crypto::random_fill(&mut b).is_ok()
            && kdf::argon2id(b"1234", &[0u8; 16], TEST_PARAMS).is_ok()
            && hirz_crypto::ct_eq(b"ab", b"ab")
    }

    fn no_sleep(_: Duration) {}

    fn sample(failures: u32) -> Verifier {
        Verifier {
            params: TEST_PARAMS,
            salt: vec![0x11; 16],
            hash: vec![0xab; 32],
            failures,
        }
    }

    fn store(dir: &TempDir) -> PinStore {
        PinStore::with_params(dir.0.join("state"), TEST_PARAMS).with_sleep(no_sleep)
    }

    #[test]
    fn pin_rules() {
        assert_eq!(validate_pin(b"1234"), Ok(()));
        assert_eq!(validate_pin(b"123"), Err(PinError::TooShort));
        assert_eq!(
            validate_pin("\u{00E9}\u{00E9}\u{00E9}".as_bytes()),
            Err(PinError::TooShort)
        );
        assert_eq!(
            validate_pin("\u{00E9}\u{00E9}\u{00E9}\u{00E9}".as_bytes()),
            Ok(())
        );
        assert_eq!(validate_pin(&[b'1'; 63]), Ok(()));
        assert_eq!(validate_pin(&[b'1'; 64]), Err(PinError::TooLong));
        assert_eq!(
            validate_pin("\u{1F600}".repeat(16).as_bytes()),
            Err(PinError::TooLong)
        );
        assert_eq!(validate_pin(b"\xff\xfe\xfd\xfc"), Err(PinError::NotUtf8));
    }

    #[test]
    fn delays() {
        assert_eq!(failure_delay(0), Duration::ZERO);
        assert_eq!(failure_delay(2), Duration::ZERO);
        assert_eq!(failure_delay(3), Duration::from_secs(1));
        assert_eq!(failure_delay(4), Duration::from_secs(2));
        assert_eq!(failure_delay(7), Duration::from_secs(16));
        assert_eq!(failure_delay(8), MAX_DELAY);
        assert_eq!(failure_delay(u32::MAX), MAX_DELAY);
    }

    #[test]
    fn verifier_roundtrip() {
        let v = sample(2);
        let s = serialize_verifier(&v);
        assert_eq!(
            s,
            format!(
                "hirz-pin 1\nkdf argon2id 64 1 1\nsalt {}\nhash {}\nfailures 2\n",
                "11".repeat(16),
                "ab".repeat(32)
            )
        );
        assert_eq!(parse_verifier(s.as_bytes()).unwrap(), v);
    }

    #[test]
    fn verifier_rejects_malformed() {
        let good = serialize_verifier(&sample(0));
        let bad = [
            good.replace("hirz-pin 1", "hirz-pin 2"),
            good.replace("argon2id", "argon2i"),
            good.replace("kdf argon2id 64 1 1", "kdf argon2id 64 1"),
            good.replace("kdf argon2id 64 1 1", "kdf argon2id 99999999 1 1"),
            good.replace("kdf argon2id 64 1 1", "kdf argon2id 64 0 1"),
            good.replace("kdf argon2id 64 1 1", "kdf argon2id 64 1 17"),
            good.replace("kdf argon2id 64 1 1", "kdf argon2id 7 1 1"),
            good.replace("kdf argon2id 64 1 1", "kdf  argon2id 64 1 1"),
            good.replace(&"11".repeat(16), &"11".repeat(15)),
            good.replace(&"11".repeat(16), &format!("{}1", "11".repeat(15))),
            good.replace(&"ab".repeat(32), &"AB".repeat(32)),
            good.replace(&"ab".repeat(32), &"ab".repeat(8)),
            good.replace(&"ab".repeat(32), &"ab".repeat(65)),
            good.replace("failures 0", "failures 9"),
            good.replace("failures 0", "failures -1"),
            good.replace("failures 0", "failures"),
            good.trim_end().to_owned(),
            format!("{good}\n"),
            format!("{good}extra\n"),
            good.replace('\n', "\r\n"),
            String::new(),
        ];
        for b in &bad {
            assert_eq!(
                parse_verifier(b.as_bytes()),
                Err(PinError::Corrupt),
                "{b:?}"
            );
        }
        assert_eq!(
            parse_verifier(&vec![b'a'; MAX_FILE_BYTES + 1]),
            Err(PinError::Corrupt)
        );
    }

    #[test]
    fn hex() {
        assert_eq!(hex_encode(&[0, 1, 0xfe, 0xff]), "0001feff");
        assert_eq!(hex_decode("0001feff", 1, 8), Some(vec![0, 1, 0xfe, 0xff]));
        assert_eq!(hex_decode("0g", 1, 8), None);
        assert_eq!(hex_decode("abc", 1, 8), None);
        assert_eq!(hex_decode("", 1, 8), None);
    }

    #[test]
    fn not_set() {
        let d = TempDir::new("notset");
        let s = store(&d);
        assert!(!s.is_set());
        assert_eq!(s.status(), Ok(None));
        assert_eq!(s.verify(b"1234"), Err(PinError::NotSet));
        assert_eq!(s.reset(), Ok(()));
    }

    #[test]
    fn counter_persisted_before_check() {
        let d = TempDir::new("counter");
        let s = store(&d);
        s.store(&sample(0)).unwrap();
        // Wrong PIN with real crypto, or a KDF error with the placeholder: either way the
        // attempt is counted on disk.
        let r = s.verify(b"0000");
        assert!(
            matches!(
                r,
                Err(PinError::Wrong { remaining: 7 }) | Err(PinError::Crypto)
            ),
            "{r:?}"
        );
        assert_eq!(
            s.status(),
            Ok(Some(PinStatus {
                failures: 1,
                locked: false
            }))
        );
    }

    #[test]
    fn delay_applied_from_third_failure() {
        static SLEPT: AtomicU32 = AtomicU32::new(0);
        fn record(d: Duration) {
            SLEPT.fetch_add(u32::try_from(d.as_secs()).unwrap(), Ordering::Relaxed);
        }
        let d = TempDir::new("delay");
        let s = PinStore::with_params(d.0.join("state"), TEST_PARAMS).with_sleep(record);
        s.store(&sample(2)).unwrap();
        let _ = s.verify(b"0000");
        assert_eq!(SLEPT.load(Ordering::Relaxed), 0);
        let _ = s.verify(b"0000");
        assert_eq!(SLEPT.load(Ordering::Relaxed), 1);
        let _ = s.verify(b"0000");
        assert_eq!(SLEPT.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn locked_after_max_failures() {
        let d = TempDir::new("locked");
        let s = store(&d);
        s.store(&sample(MAX_FAILURES)).unwrap();
        assert_eq!(s.verify(b"1234"), Err(PinError::Locked));
        assert_eq!(
            s.status(),
            Ok(Some(PinStatus {
                failures: MAX_FAILURES,
                locked: true
            }))
        );
        assert_eq!(s.change_pin(b"1234", b"5678"), Err(PinError::Locked));
        s.reset().unwrap();
        assert!(!s.is_set());
    }

    #[test]
    fn format_errors_do_not_count() {
        let d = TempDir::new("format");
        let s = store(&d);
        s.store(&sample(0)).unwrap();
        assert_eq!(s.verify(b"12"), Err(PinError::TooShort));
        assert_eq!(
            s.status(),
            Ok(Some(PinStatus {
                failures: 0,
                locked: false
            }))
        );
    }

    #[test]
    fn weaker_params_rejected() {
        let d = TempDir::new("floor");
        let s = PinStore::with_params(
            d.0.join("state"),
            Argon2Params {
                m_cost_kib: 128,
                t_cost: 1,
                p_cost: 1,
            },
        );
        s.store(&sample(0)).unwrap();
        assert_eq!(s.verify(b"1234"), Err(PinError::Corrupt));
    }

    #[test]
    fn file_and_dir_modes() {
        let d = TempDir::new("modes");
        let s = store(&d);
        fs::create_dir_all(d.0.join("state")).unwrap();
        fs::set_permissions(d.0.join("state"), fs::Permissions::from_mode(0o755)).unwrap();
        s.store(&sample(0)).unwrap();
        let dm = fs::metadata(d.0.join("state"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let fm = fs::metadata(s.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!((dm, fm), (0o700, 0o600));
        assert!(!d.0.join("state").join(TMP_NAME).exists());
    }

    #[test]
    fn set_verify_change_with_real_crypto() {
        if !crypto_ready() {
            eprintln!("skipped: hirz-crypto placeholder");
            return;
        }
        let d = TempDir::new("real");
        let s = store(&d);
        s.set_pin(b"1234").unwrap();
        assert_eq!(s.set_pin(b"5678"), Err(PinError::AlreadySet));
        assert_eq!(s.verify(b"1234"), Ok(()));
        assert_eq!(s.verify(b"9999"), Err(PinError::Wrong { remaining: 7 }));
        assert_eq!(s.verify(b"1234"), Ok(()));
        assert_eq!(
            s.status(),
            Ok(Some(PinStatus {
                failures: 0,
                locked: false
            }))
        );
        assert_eq!(
            s.change_pin(b"0000", b"5678"),
            Err(PinError::Wrong { remaining: 7 })
        );
        s.change_pin(b"1234", "p\u{00EF}n\u{1F600}".as_bytes())
            .unwrap();
        assert_eq!(s.verify(b"1234"), Err(PinError::Wrong { remaining: 7 }));
        assert_eq!(s.verify("p\u{00EF}n\u{1F600}".as_bytes()), Ok(()));
        for left in (0..MAX_FAILURES).rev() {
            assert_eq!(s.verify(b"9999"), Err(PinError::Wrong { remaining: left }));
        }
        assert_eq!(
            s.verify("p\u{00EF}n\u{1F600}".as_bytes()),
            Err(PinError::Locked)
        );
    }
}
