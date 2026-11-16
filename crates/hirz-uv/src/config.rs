//! The approval configuration file and the default locations of config and state. Format: one
//! `key = value` per line; unknown keys, repeated keys and malformed values are errors, so a typo
//! cannot silently weaken approval (docs/approval.md, "Configuration").

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UvMethod {
    Polkit,
    Fingerprint,
    Pin,
}

impl UvMethod {
    pub fn name(self) -> &'static str {
        match self {
            UvMethod::Polkit => "polkit",
            UvMethod::Fingerprint => "fingerprint",
            UvMethod::Pin => "pin",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "polkit" => Some(UvMethod::Polkit),
            "fingerprint" => Some(UvMethod::Fingerprint),
            "pin" => Some(UvMethod::Pin),
            _ => None,
        }
    }
}

pub const DEFAULT_METHODS: [UvMethod; 3] = [UvMethod::Polkit, UvMethod::Fingerprint, UvMethod::Pin];
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
pub const DEFAULT_PROMPTS_PER_MINUTE: u32 = 5;
pub const MIN_TIMEOUT_SECS: u64 = 10;
pub const MAX_TIMEOUT_SECS: u64 = 600;
pub const MAX_PROMPTS_PER_MINUTE: u32 = 60;
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;
const MAX_CLICK_TO_ALLOW: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub methods: Vec<UvMethod>,
    /// Lowercase RP ids for which a click is enough when the RP does not require UV.
    pub click_to_allow: Vec<String>,
    /// Whole ceremony, all dialogs included.
    pub timeout: Duration,
    /// Approval prompts allowed per RP id in any 60 second window.
    pub prompts_per_minute: u32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            methods: DEFAULT_METHODS.to_vec(),
            click_to_allow: Vec::new(),
            timeout: DEFAULT_TIMEOUT,
            prompts_per_minute: DEFAULT_PROMPTS_PER_MINUTE,
        }
    }
}

impl Config {
    pub fn click_to_allow_for(&self, rp_id: &str) -> bool {
        self.click_to_allow
            .iter()
            .any(|r| r.eq_ignore_ascii_case(rp_id))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// 1-based line number, 0 for whole-file problems.
    pub line: usize,
    pub message: &'static str,
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.line == 0 {
            write!(f, "config: {}", self.message)
        } else {
            write!(f, "config line {}: {}", self.line, self.message)
        }
    }
}

fn err(line: usize, message: &'static str) -> ConfigError {
    ConfigError { line, message }
}

pub fn parse_config(input: &[u8]) -> Result<Config, ConfigError> {
    if input.len() > MAX_CONFIG_BYTES {
        return Err(err(0, "file too large"));
    }
    let text = core::str::from_utf8(input).map_err(|_| err(0, "not valid UTF-8"))?;
    let mut cfg = Config::default();
    let mut seen: Vec<&str> = Vec::new();
    for (idx, raw) in text.split('\n').enumerate() {
        let n = idx.saturating_add(1);
        let line = raw.strip_suffix('\r').unwrap_or(raw).trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or(err(n, "expected key = value"))?;
        let key = key.trim();
        let value = value.trim();
        if seen.contains(&key) {
            return Err(err(n, "key given twice"));
        }
        match key {
            "methods" => cfg.methods = parse_methods(value).map_err(|m| err(n, m))?,
            "click_to_allow" => cfg.click_to_allow = parse_rp_list(value).map_err(|m| err(n, m))?,
            "timeout" => {
                let secs = parse_number(value, MIN_TIMEOUT_SECS, MAX_TIMEOUT_SECS)
                    .ok_or(err(n, "timeout must be a number of seconds from 10 to 600"))?;
                cfg.timeout = Duration::from_secs(secs);
            }
            "prompts_per_minute" => {
                let v = parse_number(value, 1, u64::from(MAX_PROMPTS_PER_MINUTE))
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or(err(n, "prompts_per_minute must be a number from 1 to 60"))?;
                cfg.prompts_per_minute = v;
            }
            _ => return Err(err(n, "unknown key")),
        }
        seen.push(key);
    }
    Ok(cfg)
}

fn list_items(value: &str) -> Result<Vec<&str>, &'static str> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(|item| {
            let item = item.trim();
            if item.is_empty() {
                Err("empty list item")
            } else {
                Ok(item)
            }
        })
        .collect()
}

fn parse_methods(value: &str) -> Result<Vec<UvMethod>, &'static str> {
    let mut out = Vec::new();
    for item in list_items(value)? {
        let m = UvMethod::parse(item).ok_or("unknown method (use polkit, fingerprint, pin)")?;
        if out.contains(&m) {
            return Err("method listed twice");
        }
        out.push(m);
    }
    if out.is_empty() {
        return Err("methods needs at least one method");
    }
    Ok(out)
}

fn parse_rp_list(value: &str) -> Result<Vec<String>, &'static str> {
    let mut out: Vec<String> = Vec::new();
    for item in list_items(value)? {
        let rp = item.to_ascii_lowercase();
        if !valid_rp_id(&rp) {
            return Err("invalid RP id (use a host name such as example.com, IDNs in xn-- form)");
        }
        if !out.contains(&rp) {
            out.push(rp);
        }
        if out.len() > MAX_CLICK_TO_ALLOW {
            return Err("too many RP ids");
        }
    }
    Ok(out)
}

/// Lowercase ASCII host name: labels of 1 to 63 `[a-z0-9-]` not starting or ending with `-`.
pub fn valid_rp_id(rp: &str) -> bool {
    !rp.is_empty()
        && rp.len() <= 253
        && rp.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn parse_number(value: &str, min: u64, max: u64) -> Option<u64> {
    if value.is_empty() || value.len() > 6 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let v: u64 = value.parse().ok()?;
    (min..=max).contains(&v).then_some(v)
}

pub fn load_config(path: &Path) -> Result<Config, ConfigError> {
    use std::io::Read;
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(_) => return Err(err(0, "cannot read the file")),
    };
    let mut buf = Vec::new();
    let cap = u64::try_from(MAX_CONFIG_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    f.take(cap)
        .read_to_end(&mut buf)
        .map_err(|_| err(0, "cannot read the file"))?;
    parse_config(&buf)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub config_file: PathBuf,
    pub state_dir: PathBuf,
}

impl Paths {
    pub fn from_env() -> Result<Self, &'static str> {
        Self::from_vars(|k| std::env::var_os(k))
    }

    /// Relative or empty XDG values are ignored, as the XDG base directory spec requires.
    pub fn from_vars(get: impl Fn(&str) -> Option<OsString>) -> Result<Self, &'static str> {
        let abs = |k: &str| get(k).map(PathBuf::from).filter(|p| p.is_absolute());
        let home = abs("HOME");
        let config_base = abs("XDG_CONFIG_HOME")
            .or_else(|| home.as_ref().map(|h| h.join(".config")))
            .ok_or("HOME is not set")?;
        let state_base = abs("XDG_STATE_HOME")
            .or_else(|| home.as_ref().map(|h| h.join(".local").join("state")))
            .ok_or("HOME is not set")?;
        Ok(Paths {
            config_file: config_base.join("hirz").join("config"),
            state_dir: state_base.join("hirz"),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_default() {
        assert_eq!(parse_config(b"").unwrap(), Config::default());
        assert_eq!(
            parse_config(b"\n# comment\n   \n").unwrap(),
            Config::default()
        );
        let d = Config::default();
        assert_eq!(d.methods, DEFAULT_METHODS);
        assert!(d.click_to_allow.is_empty());
        assert_eq!(d.timeout, Duration::from_secs(120));
    }

    #[test]
    fn full_file() {
        let c = parse_config(
            b"# hirz\nmethods = pin, polkit\r\nclick_to_allow = Example.com, other.example ,example.com\ntimeout=60\nprompts_per_minute = 3\n",
        )
        .unwrap();
        assert_eq!(c.methods, [UvMethod::Pin, UvMethod::Polkit]);
        assert_eq!(c.click_to_allow, ["example.com", "other.example"]);
        assert_eq!(c.timeout, Duration::from_secs(60));
        assert_eq!(c.prompts_per_minute, 3);
        assert!(c.click_to_allow_for("example.com"));
        assert!(c.click_to_allow_for("EXAMPLE.COM"));
        assert!(!c.click_to_allow_for("sub.example.com"));
        assert!(!c.click_to_allow_for("example.co"));
    }

    #[test]
    fn empty_click_list_allowed() {
        assert!(
            parse_config(b"click_to_allow =\n")
                .unwrap()
                .click_to_allow
                .is_empty()
        );
    }

    #[test]
    fn strict_errors() {
        let cases: &[(&[u8], usize)] = &[
            (b"methods\n", 1),
            (b"\nmethod = pin\n", 2),
            (b"methods = pin, retina\n", 1),
            (b"methods = pin, pin\n", 1),
            (b"methods =\n", 1),
            (b"methods = pin,\n", 1),
            (b"methods = ,pin\n", 1),
            (b"methods = pin\nmethods = polkit\n", 2),
            (b"timeout = 5\n", 1),
            (b"timeout = 601\n", 1),
            (b"timeout = -1\n", 1),
            (b"timeout = 1e2\n", 1),
            (b"timeout = 120s\n", 1),
            (b"timeout =\n", 1),
            (b"timeout = 99999999999999999999\n", 1),
            (b"prompts_per_minute = 0\n", 1),
            (b"prompts_per_minute = 61\n", 1),
            (b"click_to_allow = https://example.com\n", 1),
            (b"click_to_allow = example..com\n", 1),
            (b"click_to_allow = -example.com\n", 1),
            (b"click_to_allow = exa mple.com\n", 1),
            (b"click_to_allow = \xc3\xa9xample.com\n", 1),
            (b"click_to_allow = example.com.\n", 1),
            (b"  # ok\n= value\n", 2),
        ];
        for (input, line) in cases {
            let e = parse_config(input).unwrap_err();
            assert_eq!(e.line, *line, "{:?}", String::from_utf8_lossy(input));
        }
        assert_eq!(parse_config(b"\xff").unwrap_err().line, 0);
        assert_eq!(
            parse_config(&vec![b'#'; MAX_CONFIG_BYTES + 1])
                .unwrap_err()
                .line,
            0
        );
    }

    #[test]
    fn rp_ids() {
        assert!(valid_rp_id("example.com"));
        assert!(valid_rp_id("localhost"));
        assert!(valid_rp_id("xn--bcher-kva.example"));
        assert!(!valid_rp_id(""));
        assert!(!valid_rp_id("Example.com"));
        assert!(!valid_rp_id("a_b.com"));
        assert!(!valid_rp_id(&format!("{}.com", "a".repeat(64))));
        assert!(!valid_rp_id(&"a.".repeat(127)));
    }

    #[test]
    fn display_error() {
        assert_eq!(
            err(3, "unknown key").to_string(),
            "config line 3: unknown key"
        );
        assert_eq!(
            err(0, "not valid UTF-8").to_string(),
            "config: not valid UTF-8"
        );
    }

    #[test]
    fn paths() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| OsString::from(v))
            }
        };
        let p = Paths::from_vars(env(&[("HOME", "/u/alice")])).unwrap();
        assert_eq!(p.config_file, Path::new("/u/alice/.config/hirz/config"));
        assert_eq!(p.state_dir, Path::new("/u/alice/.local/state/hirz"));
        let p = Paths::from_vars(env(&[
            ("HOME", "/u/alice"),
            ("XDG_CONFIG_HOME", "/cfg"),
            ("XDG_STATE_HOME", "/st"),
        ]))
        .unwrap();
        assert_eq!(p.config_file, Path::new("/cfg/hirz/config"));
        assert_eq!(p.state_dir, Path::new("/st/hirz"));
        let p = Paths::from_vars(env(&[("HOME", "/h"), ("XDG_STATE_HOME", "relative")])).unwrap();
        assert_eq!(p.state_dir, Path::new("/h/.local/state/hirz"));
        assert!(Paths::from_vars(env(&[])).is_err());
        assert!(Paths::from_vars(env(&[("HOME", "relative")])).is_err());
    }

    #[test]
    fn load_missing_file_is_default() {
        let c = load_config(Path::new("/nonexistent/hirz/config")).unwrap();
        assert_eq!(c, Config::default());
    }
}
