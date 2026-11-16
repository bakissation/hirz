//! Who may get a device: only users with an active login session on a seat, and only while all
//! three hirz udev rule files are in effect. The session state comes from the files
//! systemd-logind (or elogind) keeps in `/run/systemd/users`, the same files libsystemd reads
//! for `sd_uid_get_state` and `sd_uid_get_seats`. Only root can write there.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const DEFAULT_SESSIONS_DIR: &str = "/run/systemd/users";
/// The hirz rule files, in the order udev runs them (docs/uhid.md, "hidraw access").
pub const UDEV_RULES_FILES: [&str; 3] = ["70-hirz.rules", "72-hirz.rules", "99-zzz-hirz.rules"];
const DEFAULT_UDEV_DIRS: [&str; 5] = [
    "/etc/udev/rules.d",
    "/run/udev/rules.d",
    "/usr/local/lib/udev/rules.d",
    "/usr/lib/udev/rules.d",
    "/lib/udev/rules.d",
];
const MAX_STATE_FILE: u64 = 256 * 1024;
const MAX_RULES_FILE: u64 = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    NoSession,
    SessionNotActive,
    NoSeat,
    StateUnreadable,
    UdevRulesMissing,
}

impl Denied {
    pub fn reason(self) -> &'static str {
        match self {
            Self::NoSession => "no login session",
            Self::SessionNotActive => "no active login session",
            Self::NoSeat => "active session is not on a seat",
            Self::StateUnreadable => "cannot read the logind state",
            Self::UdevRulesMissing => "the hirz udev rules are not installed or are masked",
        }
    }
}

#[derive(Debug, Clone)]
pub struct HostPolicy {
    sessions_dir: PathBuf,
    udev_dirs: Vec<PathBuf>,
}

impl HostPolicy {
    pub fn new(sessions_dir: PathBuf, udev_dir: Option<PathBuf>) -> Self {
        let udev_dirs = match udev_dir {
            Some(dir) => vec![dir],
            None => DEFAULT_UDEV_DIRS.iter().map(PathBuf::from).collect(),
        };
        Self::with_udev_dirs(sessions_dir, udev_dirs)
    }

    fn with_udev_dirs(sessions_dir: PathBuf, udev_dirs: Vec<PathBuf>) -> Self {
        Self {
            sessions_dir,
            udev_dirs,
        }
    }

    pub fn sessions_dir(&self) -> &Path {
        &self.sessions_dir
    }

    /// The hirz rule files that udev would not apply. udev takes a file name from the first
    /// directory in its search order that has it, and a link to `/dev/null` or an empty file
    /// there masks the same name further down, so the first entry decides for each name.
    pub fn missing_rules(&self) -> Vec<&'static str> {
        UDEV_RULES_FILES
            .iter()
            .copied()
            .filter(|name| !self.rule_in_effect(name))
            .collect()
    }

    pub fn udev_rules_installed(&self) -> bool {
        self.missing_rules().is_empty()
    }

    fn rule_in_effect(&self, name: &str) -> bool {
        for dir in &self.udev_dirs {
            let path = dir.join(name);
            match fs::symlink_metadata(&path) {
                Ok(_) => return has_rules(&path),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return false,
            }
        }
        false
    }

    /// Whether `uid` may have a device right now. Called when it connects and again while its
    /// device exists, so a device does not outlive the session.
    pub fn check(&self, uid: u32) -> Result<(), Denied> {
        if !self.udev_rules_installed() {
            return Err(Denied::UdevRulesMissing);
        }
        let path = self.sessions_dir.join(uid.to_string());
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Denied::NoSession),
            Err(_) => return Err(Denied::StateUnreadable),
        };
        if !meta.is_file() || meta.len() > MAX_STATE_FILE {
            return Err(Denied::StateUnreadable);
        }
        let mut raw = Vec::new();
        fs::File::open(&path)
            .and_then(|f| f.take(MAX_STATE_FILE).read_to_end(&mut raw))
            .map_err(|_| Denied::StateUnreadable)?;
        evaluate(&String::from_utf8_lossy(&raw))
    }
}

/// A regular file (a link to one is fine; `/dev/null` is not) with at least one line that is
/// neither blank nor a comment.
fn has_rules(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_RULES_FILE {
        return false;
    }
    let mut raw = Vec::new();
    if fs::File::open(path)
        .and_then(|f| f.take(MAX_RULES_FILE).read_to_end(&mut raw))
        .is_err()
    {
        return false;
    }
    String::from_utf8_lossy(&raw).lines().any(|line| {
        let line = line.trim();
        !line.is_empty() && !line.starts_with('#')
    })
}

/// The first `STATE` and `ACTIVE_SEATS` lines count. `STATE=active` alone is not enough:
/// logind also calls a user active for a remote session without a seat (ssh), which has no
/// business holding a security key in front of the console.
fn evaluate(text: &str) -> Result<(), Denied> {
    let mut state = None;
    let mut active_seats = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "STATE" if state.is_none() => state = Some(value.trim()),
            "ACTIVE_SEATS" if active_seats.is_none() => active_seats = Some(value.trim()),
            _ => {}
        }
    }
    if state != Some("active") {
        return Err(Denied::SessionNotActive);
    }
    match active_seats {
        Some(seats) if !seats.is_empty() => Ok(()),
        _ => Err(Denied::NoSeat),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    // The umask is process wide and the broker's socket code briefly changes it, so test
    // directories get their mode explicitly instead of from the umask.
    fn make_dir(path: &Path) {
        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            make_dir(parent);
        }
        if !path.exists() {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    const ACTIVE: &str = "# This is private data. Do not parse.\nNAME=alice\nSTATE=active\n\
        RUNTIME=/run/user/1000\nSESSIONS=2 c1\nSEATS=seat0\nACTIVE_SESSIONS=2\n\
        ONLINE_SESSIONS=2\nACTIVE_SEATS=seat0\nONLINE_SEATS=seat0\n";

    struct Fixture {
        root: PathBuf,
        policy: HostPolicy,
    }

    fn write_rules(dir: &Path, name: &str) {
        make_dir(dir);
        fs::write(dir.join(name), "# part of hirz\nTAG-=\"uaccess\"\n").unwrap();
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("hirz-policy-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            make_dir(&root.join("users"));
            make_dir(&root.join("udev"));
            for name in UDEV_RULES_FILES {
                write_rules(&root.join("udev"), name);
            }
            let policy = HostPolicy::new(root.join("users"), Some(root.join("udev")));
            Self { root, policy }
        }

        fn state(&self, uid: u32, text: &str) {
            fs::write(self.root.join("users").join(uid.to_string()), text).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn active_session_on_a_seat_is_admitted() {
        let f = Fixture::new("ok");
        f.state(1000, ACTIVE);
        assert_eq!(f.policy.check(1000), Ok(()));
    }

    #[test]
    fn users_without_a_state_file_are_refused() {
        let f = Fixture::new("none");
        f.state(1000, ACTIVE);
        assert_eq!(f.policy.check(1001), Err(Denied::NoSession));
        assert_eq!(f.policy.check(65534), Err(Denied::NoSession));
    }

    #[test]
    fn only_state_active_counts() {
        let f = Fixture::new("states");
        for state in ["offline", "opening", "lingering", "online", "closing", ""] {
            f.state(
                1000,
                &ACTIVE.replace("STATE=active", &format!("STATE={state}")),
            );
            assert_eq!(
                f.policy.check(1000),
                Err(Denied::SessionNotActive),
                "state {state:?}"
            );
        }
        f.state(1000, "NAME=alice\nACTIVE_SEATS=seat0\n");
        assert_eq!(f.policy.check(1000), Err(Denied::SessionNotActive));
    }

    #[test]
    fn a_session_without_a_seat_is_refused() {
        let f = Fixture::new("seat");
        f.state(
            1000,
            "STATE=active\nSEATS=seat0\nACTIVE_SEATS=\nONLINE_SEATS=seat0\n",
        );
        assert_eq!(f.policy.check(1000), Err(Denied::NoSeat));
        f.state(1000, "STATE=active\nSESSIONS=4\n");
        assert_eq!(f.policy.check(1000), Err(Denied::NoSeat));
    }

    #[test]
    fn a_device_ends_with_the_session() {
        let f = Fixture::new("end");
        f.state(1000, ACTIVE);
        assert_eq!(f.policy.check(1000), Ok(()));
        f.state(1000, &ACTIVE.replace("STATE=active", "STATE=closing"));
        assert!(f.policy.check(1000).is_err());
        fs::remove_file(f.root.join("users/1000")).unwrap();
        assert_eq!(f.policy.check(1000), Err(Denied::NoSession));
    }

    #[test]
    fn the_first_state_line_wins() {
        let f = Fixture::new("dup");
        f.state(1000, "STATE=online\nSTATE=active\nACTIVE_SEATS=seat0\n");
        assert_eq!(f.policy.check(1000), Err(Denied::SessionNotActive));
    }

    #[test]
    fn not_a_regular_file_is_refused() {
        let f = Fixture::new("kind");
        fs::create_dir(f.root.join("users/1000")).unwrap();
        assert_eq!(f.policy.check(1000), Err(Denied::StateUnreadable));
        fs::write(f.root.join("target"), ACTIVE).unwrap();
        std::os::unix::fs::symlink(f.root.join("target"), f.root.join("users/1001")).unwrap();
        assert_eq!(f.policy.check(1001), Err(Denied::StateUnreadable));
    }

    #[test]
    fn an_oversized_file_is_refused() {
        let f = Fixture::new("big");
        let mut text = ACTIVE.to_owned();
        text.push_str(&"X".repeat(300 * 1024));
        f.state(1000, &text);
        assert_eq!(f.policy.check(1000), Err(Denied::StateUnreadable));
    }

    #[test]
    fn missing_udev_rules_refuse_everyone() {
        let f = Fixture::new("udev");
        f.state(1000, ACTIVE);
        for name in UDEV_RULES_FILES {
            let path = f.root.join("udev").join(name);
            let kept = fs::read(&path).unwrap();
            fs::remove_file(&path).unwrap();
            assert!(!f.policy.udev_rules_installed(), "{name}");
            assert_eq!(f.policy.missing_rules(), vec![name]);
            assert_eq!(
                f.policy.check(1000),
                Err(Denied::UdevRulesMissing),
                "{name}"
            );
            fs::write(&path, kept).unwrap();
        }
        assert_eq!(f.policy.check(1000), Ok(()));
    }

    #[test]
    fn a_rule_file_that_udev_would_not_apply_does_not_count() {
        let f = Fixture::new("masked");
        let dir = f.root.join("udev");
        let name = UDEV_RULES_FILES[2];
        type Mask = (&'static str, fn(&Path));
        let cases: [Mask; 5] = [
            ("empty", |p| fs::write(p, b"").unwrap()),
            ("comments only", |p| {
                fs::write(p, "# nothing\n\n  # more\n").unwrap();
            }),
            ("link to /dev/null", |p| {
                std::os::unix::fs::symlink("/dev/null", p).unwrap();
            }),
            ("dangling link", |p| {
                std::os::unix::fs::symlink("/nonexistent/hirz", p).unwrap();
            }),
            ("directory", |p| fs::create_dir(p).unwrap()),
        ];
        for (label, setup) in cases {
            let path = dir.join(name);
            fs::remove_file(&path).unwrap();
            setup(&path);
            assert_eq!(f.policy.missing_rules(), vec![name], "{label}");
            let _ = fs::remove_file(&path);
            let _ = fs::remove_dir(&path);
            write_rules(&dir, name);
        }
        assert!(f.policy.udev_rules_installed());
    }

    #[test]
    fn a_link_to_a_real_rule_file_counts() {
        let f = Fixture::new("link");
        let dir = f.root.join("udev");
        let name = UDEV_RULES_FILES[0];
        fs::rename(dir.join(name), f.root.join("real.rules")).unwrap();
        std::os::unix::fs::symlink(f.root.join("real.rules"), dir.join(name)).unwrap();
        assert!(f.policy.udev_rules_installed());
    }

    // A link to /dev/null in a directory that udev reads first hides the packaged file of the
    // same name further down: the broker used to look past it and see the packaged file.
    #[test]
    fn a_mask_in_an_earlier_directory_hides_the_packaged_file() {
        let root = std::env::temp_dir().join(format!("hirz-policy-order-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let (etc, lib) = (root.join("etc"), root.join("lib"));
        for name in UDEV_RULES_FILES {
            write_rules(&lib, name);
        }
        make_dir(&etc);
        let policy = HostPolicy::with_udev_dirs(root.join("users"), vec![etc.clone(), lib.clone()]);
        assert!(policy.udev_rules_installed());

        std::os::unix::fs::symlink("/dev/null", etc.join(UDEV_RULES_FILES[0])).unwrap();
        assert_eq!(policy.missing_rules(), vec![UDEV_RULES_FILES[0]]);
        assert_eq!(policy.check(1000), Err(Denied::UdevRulesMissing));

        fs::remove_file(etc.join(UDEV_RULES_FILES[0])).unwrap();
        fs::write(etc.join(UDEV_RULES_FILES[1]), b"").unwrap();
        assert_eq!(policy.missing_rules(), vec![UDEV_RULES_FILES[1]]);

        // A real file of the same name in the earlier directory replaces the packaged one.
        write_rules(&etc, UDEV_RULES_FILES[1]);
        assert!(policy.udev_rules_installed());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rules_from_different_directories_add_up() {
        let root = std::env::temp_dir().join(format!("hirz-policy-split-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let (etc, lib) = (root.join("etc"), root.join("lib"));
        write_rules(&lib, UDEV_RULES_FILES[0]);
        write_rules(&lib, UDEV_RULES_FILES[1]);
        write_rules(&etc, UDEV_RULES_FILES[2]);
        let policy = HostPolicy::with_udev_dirs(root.join("users"), vec![etc, lib]);
        assert!(policy.udev_rules_installed());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn default_policy_looks_in_the_system_directories() {
        let p = HostPolicy::new(PathBuf::from(DEFAULT_SESSIONS_DIR), None);
        assert_eq!(p.sessions_dir(), Path::new("/run/systemd/users"));
        assert_eq!(p.udev_dirs.len(), DEFAULT_UDEV_DIRS.len());
    }
}
