#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use crate::app::{self, Ctx};
use crate::args::{self, Command, DeleteTarget, Invocation, PinAction};
use crate::env::{Env, System};
use crate::error::{CliError, Exit};
use crate::prompt::Prompter;
use hirz_crypto::Zeroizing;
use hirz_crypto::kdf::Argon2Params;
use hirz_uv::UvMethod;
use hirz_vault::{CredentialRecord, HmacSecretPair, RecoveryPhrase, Vault};
use serde_json::Value;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

const FAST: Argon2Params = Argon2Params {
    m_cost_kib: 64,
    t_cost: 1,
    p_cost: 1,
};
const PASS: &str = "correct horse battery staple";
const FIXTURE: &str = include_str!("../tests/fixtures/provider-export.json");

struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Tmp {
        let mut r = [0u8; 8];
        hirz_crypto::random_fill(&mut r).unwrap();
        let p = std::env::temp_dir().join(format!("hirz-cli-test-{tag}-{}", crate::ui::hex(&r)));
        fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
    fn path(&self, sub: &str) -> PathBuf {
        self.0.join(sub)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// One simulated computer: its own home, state and config directories.
struct Machine {
    tmp: Tmp,
    env: Env,
}

impl Machine {
    fn new(tag: &str) -> Machine {
        let tmp = Tmp::new(tag);
        let home = tmp.0.clone();
        let mut env = Env::from_vars(|k| match k {
            "HOME" => Some(home.clone().into_os_string()),
            "XDG_DATA_HOME" => Some(home.join("data").into_os_string()),
            "XDG_STATE_HOME" => Some(home.join("state").into_os_string()),
            "XDG_CONFIG_HOME" => Some(home.join("config").into_os_string()),
            _ => None,
        })
        .unwrap();
        env.root = home.join("root");
        env.broker_socket = home.join("root/run/hirz/uhid.sock");
        env.cwd = Some(home.clone());
        env.exe_dir = Some(home.join("bin"));
        Machine { tmp, env }
    }
    fn state(&self) -> PathBuf {
        self.env.state_dir().to_path_buf()
    }
    fn default_vault(&self) -> PathBuf {
        self.env.default_vault()
    }
}

struct FakeSys;

impl System for FakeSys {
    fn uv_methods(&self, _env: &Env) -> Result<Vec<UvMethod>, String> {
        Ok(vec![UvMethod::Pin])
    }
    fn zenity(&self) -> bool {
        true
    }
    fn hostname(&self) -> Option<String> {
        Some("test-host".into())
    }
}

#[derive(Clone, Default)]
struct SharedBuf(Rc<RefCell<Vec<u8>>>);

impl Write for SharedBuf {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl SharedBuf {
    fn text(&self) -> String {
        String::from_utf8(self.0.borrow().clone()).unwrap()
    }
}

/// Scripted answers. "Press Enter" prompts get an empty line, and "Word N" prompts are
/// answered from the recovery phrase printed so far (or wrongly when `wrong_words`).
struct Script {
    answers: VecDeque<String>,
    out: SharedBuf,
    wrong_words: bool,
    prompts: Vec<String>,
}

impl Script {
    fn next(&mut self, prompt: &str) -> Option<String> {
        self.prompts.push(prompt.to_string());
        if prompt.starts_with("Press Enter") {
            return Some(String::new());
        }
        if let Some(n) = prompt
            .strip_prefix("Word ")
            .and_then(|r| r.trim_end_matches(": ").parse::<usize>().ok())
        {
            if self.wrong_words {
                return Some("zzzz".into());
            }
            let words = phrase_words(&self.out.text());
            return Some(words[n - 1].clone());
        }
        self.answers.pop_front()
    }
}

impl Prompter for Script {
    fn line(&mut self, prompt: &str) -> io::Result<Option<String>> {
        Ok(self.next(prompt))
    }
    fn secret(&mut self, prompt: &str) -> io::Result<Option<Zeroizing<String>>> {
        Ok(self.next(prompt).map(Zeroizing::new))
    }
}

/// Reads the 24 numbered words of the first phrase shown in `out`.
fn phrase_words(out: &str) -> Vec<String> {
    let start = out.find("RECOVERY PHRASE").expect("phrase shown");
    let tokens: Vec<&str> = out[start..].split_whitespace().collect();
    let mut words = vec![String::new(); 24];
    for pair in tokens.windows(2) {
        if let Some(n) = pair[0]
            .strip_suffix('.')
            .and_then(|n| n.parse::<usize>().ok())
            && (1..=24).contains(&n)
            && words[n - 1].is_empty()
        {
            words[n - 1] = pair[1].to_string();
        }
    }
    assert!(words.iter().all(|w| !w.is_empty()), "{out}");
    words
}

struct Run {
    result: Result<Exit, CliError>,
    out: String,
    prompts: Vec<String>,
}

impl Run {
    fn ok(&self) -> &str {
        assert_eq!(self.result, Ok(Exit::Ok), "output:\n{}", self.out);
        &self.out
    }
    fn exit(&self) -> Exit {
        match &self.result {
            Ok(e) => *e,
            Err(e) => e.exit,
        }
    }
    fn message(&self) -> String {
        match &self.result {
            Ok(_) => String::new(),
            Err(e) => e.message.clone(),
        }
    }
}

fn os(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

fn run_with(m: &Machine, args: &[&str], answers: &[&str], wrong_words: bool) -> Run {
    let inv = args::parse(&os(args)).unwrap();
    let out = SharedBuf::default();
    let mut writer = out.clone();
    let mut script = Script {
        answers: answers.iter().map(|s| s.to_string()).collect(),
        out: out.clone(),
        wrong_words,
        prompts: Vec::new(),
    };
    let mut ctx = Ctx {
        out: &mut writer,
        prompt: &mut script,
        env: &m.env,
        sys: &FakeSys,
        kdf: FAST,
        vault_flag: None,
    };
    let result = app::run(inv, &mut ctx);
    Run {
        result,
        out: out.text(),
        prompts: script.prompts,
    }
}

fn run(m: &Machine, args: &[&str], answers: &[&str]) -> Run {
    run_with(m, args, answers, false)
}

/// `hirz init --yes-i-saved-it`, returning the recovery phrase.
fn init(m: &Machine) -> String {
    let r = run(m, &["init", "--yes-i-saved-it"], &[]);
    r.ok();
    phrase_words(&r.out).join(" ")
}

fn record(rp: &str, user: &str, ed25519: bool, seed: u8) -> CredentialRecord {
    let (key, algorithm) = if ed25519 {
        (hirz_crypto::ed25519::generate().unwrap().0, -8)
    } else {
        (hirz_crypto::es256::generate().unwrap().0, -7)
    };
    CredentialRecord {
        credential_id: vec![seed; 32],
        rp_id: rp.into(),
        rp_name: Some(format!("{rp} site")),
        user_id: vec![seed; 16],
        user_name: Some(user.into()),
        user_display_name: Some(format!("{user} display")),
        algorithm,
        private_key_pkcs8: key,
        created_at: 1_700_000_000 + u64::from(seed),
        cred_protect: if ed25519 { Some(3) } else { None },
        hmac_secret: (!ed25519).then(|| HmacSecretPair {
            cred_random_with_uv: Zeroizing::new([seed; 32]),
            cred_random_without_uv: Zeroizing::new([seed ^ 0xff; 32]),
        }),
        discoverable: !ed25519,
        backup_eligible: true,
    }
}

fn put(m: &Machine, vault: &Path, records: Vec<CredentialRecord>) {
    let mut v = Vault::open(vault, &m.state()).unwrap();
    for r in records {
        v.put(r).unwrap();
    }
}

fn records(m: &Machine, vault: &Path) -> Vec<CredentialRecord> {
    let v = Vault::open(vault, &m.state()).unwrap();
    let mut all: Vec<CredentialRecord> = v.list_all().into_iter().cloned().collect();
    all.sort_by(|a, b| a.credential_id.cmp(&b.credential_id));
    all
}

// ---- argument parsing ----

fn inv(vault: Option<&str>, command: Command) -> Invocation {
    Invocation {
        vault: vault.map(PathBuf::from),
        command,
    }
}

#[test]
fn parse_table() {
    let ok: Vec<(&[&str], Invocation)> = vec![
        (&[], inv(None, Command::Help(None))),
        (&["--help"], inv(None, Command::Help(None))),
        (
            &["help", "init"],
            inv(None, Command::Help(Some("init".into()))),
        ),
        (
            &["list", "-h"],
            inv(None, Command::Help(Some("list".into()))),
        ),
        (&["--version"], inv(None, Command::Version)),
        (&["version"], inv(None, Command::Version)),
        (
            &["init"],
            inv(
                None,
                Command::Init {
                    name: None,
                    saved: false,
                },
            ),
        ),
        (
            &["--vault", "/v", "init", "--name=laptop", "--yes-i-saved-it"],
            inv(
                Some("/v"),
                Command::Init {
                    name: Some("laptop".into()),
                    saved: true,
                },
            ),
        ),
        (
            &["init", "--vault=/v"],
            inv(
                Some("/v"),
                Command::Init {
                    name: None,
                    saved: false,
                },
            ),
        ),
        (
            &["join", "--vault", "/v", "--name", "desk"],
            inv(
                Some("/v"),
                Command::Join {
                    name: Some("desk".into()),
                },
            ),
        ),
        (&["status"], inv(None, Command::Status { json: false })),
        (
            &["status", "--json"],
            inv(None, Command::Status { json: true }),
        ),
        (
            &["list", "--site", "example.com", "--json"],
            inv(
                None,
                Command::List {
                    site: Some("example.com".into()),
                    json: true,
                },
            ),
        ),
        (
            &["delete", "abcd12"],
            inv(
                None,
                Command::Delete {
                    target: DeleteTarget::IdPrefix("abcd12".into()),
                    yes: false,
                },
            ),
        ),
        (
            &["delete", "--yes", "example.com", "alice"],
            inv(
                None,
                Command::Delete {
                    target: DeleteTarget::Account {
                        site: "example.com".into(),
                        account: "alice".into(),
                    },
                    yes: true,
                },
            ),
        ),
        (
            &["delete", "--", "example.com", "--alice"],
            inv(
                None,
                Command::Delete {
                    target: DeleteTarget::Account {
                        site: "example.com".into(),
                        account: "--alice".into(),
                    },
                    yes: false,
                },
            ),
        ),
        (&["devices"], inv(None, Command::Devices { json: false })),
        (
            &["remove-device", "0a1b", "--yes"],
            inv(
                None,
                Command::RemoveDevice {
                    prefix: "0a1b".into(),
                    yes: true,
                },
            ),
        ),
        (&["pin", "set"], inv(None, Command::Pin(PinAction::Set))),
        (
            &["pin", "change"],
            inv(None, Command::Pin(PinAction::Change)),
        ),
        (&["pin", "reset"], inv(None, Command::Pin(PinAction::Reset))),
        (
            &["pin", "status"],
            inv(None, Command::Pin(PinAction::Status)),
        ),
        (
            &["export", "--cxf", "out.cxf"],
            inv(
                None,
                Command::Export {
                    file: "out.cxf".into(),
                    plain: false,
                },
            ),
        ),
        (
            &["export", "--plain", "--cxf=out.json"],
            inv(
                None,
                Command::Export {
                    file: "out.json".into(),
                    plain: true,
                },
            ),
        ),
        (
            &["import", "--cxf", "in.json"],
            inv(
                None,
                Command::Import {
                    file: "in.json".into(),
                },
            ),
        ),
        (
            &["backup", "confirm"],
            inv(None, Command::BackupConfirm { yes: false }),
        ),
        (
            &["setup", "firefox", "--nmh-path", "/opt/hirz-nmh", "--force"],
            inv(
                None,
                Command::SetupFirefox {
                    nmh_path: Some("/opt/hirz-nmh".into()),
                    force: true,
                },
            ),
        ),
    ];
    for (args, expected) in ok {
        assert_eq!(args::parse(&os(args)).unwrap(), expected, "{args:?}");
    }

    let usage: &[&[&str]] = &[
        &["frobnicate"],
        &["join"],
        &["init", "extra"],
        &["init", "--json"],
        &["list", "--site"],
        &["list", "--site="],
        &["list", "--unknown"],
        &["list", "-x"],
        &["status", "--json=yes"],
        &["delete"],
        &["delete", "a", "b", "c"],
        &["remove-device"],
        &["pin"],
        &["pin", "frob"],
        &["export"],
        &["import"],
        &["backup"],
        &["backup", "now"],
        &["setup", "chrome"],
        &["--vault", "/a", "--vault", "/b", "status"],
        &["list", "--site", "a", "--site", "b"],
    ];
    for args in usage {
        let e = args::parse(&os(args)).unwrap_err();
        assert_eq!(e.exit, Exit::Usage, "{args:?}");
        assert!(!e.message.is_empty());
    }
    let long = "x".repeat(5000);
    assert_eq!(
        args::parse(&os(&["list", "--site", &long]))
            .unwrap_err()
            .exit,
        Exit::Usage
    );
}

#[test]
fn help_texts_exist() {
    for t in [
        "init",
        "join",
        "status",
        "list",
        "delete",
        "devices",
        "remove-device",
        "pin",
        "export",
        "import",
        "backup",
        "setup",
    ] {
        assert!(app::help(Some(t)).unwrap().contains("Usage: hirz"), "{t}");
    }
    assert_eq!(app::help(Some("nope")).unwrap_err().exit, Exit::Usage);
    let m = Machine::new("help");
    assert!(run(&m, &["--help"], &[]).ok().contains("Getting started"));
}

// ---- init and join ----

#[test]
fn init_checks_the_phrase_and_refuses_to_overwrite() {
    let m = Machine::new("init");
    let r = run(&m, &["init"], &[]);
    let out = r.ok();
    assert!(out.contains("RECOVERY PHRASE"));
    assert!(out.contains("test-host"));
    assert_eq!(
        r.prompts.iter().filter(|p| p.starts_with("Word ")).count(),
        3
    );
    let vault = m.default_vault();
    assert!(vault.join(hirz_vault::HEADER_FILE).is_file());
    assert_eq!(
        fs::read(m.state().join("vault-path")).unwrap(),
        vault.as_os_str().as_encoded_bytes()
    );
    let mode = fs::metadata(m.state()).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);

    let again = run(&m, &["init", "--yes-i-saved-it"], &[]);
    assert_eq!(again.exit(), Exit::Failed);
    assert!(again.message().contains("already set up"));

    let other = Machine::new("init2");
    let r = run(
        &other,
        &[
            "--vault",
            vault.to_str().unwrap(),
            "init",
            "--yes-i-saved-it",
        ],
        &[],
    );
    assert_eq!(r.exit(), Exit::Failed);
    assert!(r.message().contains("hirz join --vault"));

    let busy = other.tmp.path("busy");
    fs::create_dir_all(&busy).unwrap();
    fs::write(busy.join("notes.txt"), b"x").unwrap();
    let r = run(
        &other,
        &[
            "--vault",
            busy.to_str().unwrap(),
            "init",
            "--yes-i-saved-it",
        ],
        &[],
    );
    assert_eq!(r.exit(), Exit::Failed);
    assert!(r.message().contains("not empty"));
    assert!(!other.state().join(hirz_vault::DEVICE_STATE_FILE).exists());
}

#[test]
fn init_quiz_failure_is_reported() {
    let m = Machine::new("quiz");
    let r = run_with(&m, &["init"], &[], true);
    assert_eq!(r.exit(), Exit::Cancelled);
    assert!(r.message().contains("not confirmed"));
    assert!(r.out.contains("Here is the phrase again"));
    assert!(m.default_vault().join(hirz_vault::HEADER_FILE).is_file());
}

#[test]
fn join_second_device_with_retries() {
    let a = Machine::new("join-a");
    let phrase = init(&a);
    let vault = a.default_vault();
    let vs = vault.to_str().unwrap().to_string();
    put(&a, &vault, vec![record("example.com", "alice", false, 1)]);

    let b = Machine::new("join-b");
    let missing = b.tmp.path("nothing-here");
    let r = run(&b, &["join", "--vault", missing.to_str().unwrap()], &[]);
    assert_eq!(r.exit(), Exit::NotSetUp);

    let other = RecoveryPhrase::from_entropy([7u8; 32])
        .to_words()
        .to_string();
    let r = run(&b, &["join", "--vault", &vs], &[&other]);
    assert_eq!(r.exit(), Exit::Denied);
    assert!(!b.state().join(hirz_vault::DEVICE_STATE_FILE).exists());

    let mut typo: Vec<&str> = phrase.split(' ').collect();
    typo[3] = "notaword";
    let typo = typo.join(" ");
    let r = run(
        &b,
        &["join", "--vault", &vs, "--name", "desk"],
        &["only three words", &typo, &phrase.to_uppercase()],
    );
    let out = r.ok();
    assert!(out.contains("exactly 24 words"));
    assert!(out.contains("Word 4 is not"));
    assert!(out.contains("1 passkey here"));
    assert_eq!(
        r.prompts
            .iter()
            .filter(|p| *p == "Recovery phrase: ")
            .count(),
        3
    );

    let devs = run(&b, &["devices", "--json"], &[]);
    let v: Value = serde_json::from_str(devs.ok()).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert!(
        arr.iter()
            .any(|d| d["name"] == "desk" && d["this_device"] == true)
    );
    assert!(
        arr.iter()
            .any(|d| d["name"] == "test-host" && d["this_device"] == false)
    );

    let st = run(&b, &["status", "--json"], &[]);
    let v: Value = serde_json::from_str(st.ok()).unwrap();
    assert_eq!(v["vault"]["devices_active"], 2);
    assert_eq!(v["vault"]["backed_up"], true);
    assert_eq!(v["vault"]["passkeys"], 1);

    let r = run(&b, &["join", "--vault", &vs], &[&phrase]);
    assert_eq!(r.exit(), Exit::Failed);
    assert!(r.message().contains("already set up"));
}

// ---- list and delete ----

#[test]
fn list_and_delete() {
    let m = Machine::new("list");
    init(&m);
    let vault = m.default_vault();
    let r = run(&m, &["list"], &[]);
    assert!(r.ok().contains("No passkeys yet"));
    let mut evil = record("example.org", "mallory\u{202e}\u{1b}[2J", true, 3);
    evil.user_display_name = None;
    put(
        &m,
        &vault,
        vec![
            record("example.com", "alice", false, 1),
            record("example.com", "bob", true, 2),
            evil,
        ],
    );
    let r = run(&m, &["list"], &[]);
    let out = r.ok();
    assert!(out.contains("SITE"));
    assert!(out.contains("alice"));
    assert!(out.contains("2023-11-14"));
    assert!(out.contains("010101010101"));
    assert!(out.contains("3 passkeys"));
    assert!(!out.contains('\u{1b}'));
    assert!(!out.contains('\u{202e}'));
    assert!(!out.to_lowercase().contains("private"));

    let r = run(&m, &["list", "--site", "EXAMPLE.com", "--json"], &[]);
    let v: Value = serde_json::from_str(r.ok()).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["user_name"], "alice");
    assert_eq!(arr[0]["algorithm"], "ES256");
    assert_eq!(arr[0]["prf"], true);
    assert!(r.out.find("\"key\"").is_none());

    let r = run(&m, &["delete", "0101"], &["n"]);
    assert_eq!(r.exit(), Exit::Cancelled);
    assert_eq!(records(&m, &vault).len(), 3);

    let r = run(&m, &["delete", "zz"], &[]);
    assert_eq!(r.exit(), Exit::Usage);
    let r = run(&m, &["delete", "ffff"], &[]);
    assert_eq!(r.exit(), Exit::Failed);

    let r = run(&m, &["delete", "0101"], &["y"]);
    assert!(r.ok().contains("Deleted"));
    let r = run(&m, &["delete", "--yes", "example.com", "bob"], &[]);
    r.ok();
    let left = records(&m, &vault);
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].rp_id, "example.org");
}

#[test]
fn delete_by_whole_id_when_it_prefixes_another() {
    let m = Machine::new("delete-short");
    init(&m);
    let vault = m.default_vault();
    let mut short = record("example.com", "alice", false, 10);
    short.credential_id = vec![10; 16];
    let long = record("example.com", "bob", false, 10);
    put(&m, &vault, vec![short, long]);

    let r = run(&m, &["delete", "0a0a"], &[]);
    assert_eq!(r.exit(), Exit::Usage);
    let whole = "0a".repeat(16);
    let r = run(&m, &["delete", &whole], &["y"]);
    assert!(r.ok().contains("Deleted"), "{}", r.out);
    let left = records(&m, &vault);
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].credential_id, vec![10u8; 32]);
}

// ---- export and import ----

#[test]
fn encrypted_export_imports_into_a_fresh_vault() {
    let a = Machine::new("exp-a");
    init(&a);
    let va = a.default_vault();
    put(
        &a,
        &va,
        vec![
            record("example.com", "alice", false, 1),
            record("login.example.org", "bob", true, 2),
            record("example.net", "carol", false, 3),
        ],
    );
    let file = a.tmp.path("passkeys.hirz");
    let fs_ = file.to_str().unwrap();
    let r = run(&a, &["export", "--cxf", fs_], &["short", PASS, PASS, "n"]);
    let out = r.ok();
    assert!(out.contains("at least 12 characters"));
    assert!(out.contains("Saved 3 passkeys"));
    let bytes = fs::read(&file).unwrap();
    assert!(bytes.starts_with(b"HIRZ-CXF"));
    assert!(!String::from_utf8_lossy(&bytes).contains("example.com"));
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!Vault::open(&va, &a.state()).unwrap().backup_state());

    let r = run(&a, &["export", "--cxf", fs_], &[]);
    assert_eq!(r.exit(), Exit::Failed);
    assert!(r.message().contains("already exists"));

    let b = Machine::new("exp-b");
    init(&b);
    let vb = b.default_vault();
    let r = run(
        &b,
        &["import", "--cxf", fs_],
        &[
            "wrong passphrase 1",
            "wrong passphrase 2",
            "wrong passphrase 3",
        ],
    );
    assert_eq!(r.exit(), Exit::Denied);
    assert!(records(&b, &vb).is_empty());

    let r = run(&b, &["import", "--cxf", fs_], &[PASS]);
    assert!(r.ok().contains("Imported 3 passkeys"));
    assert_eq!(records(&a, &va), records(&b, &vb));

    let r = run(&b, &["import", "--cxf", fs_], &[PASS]);
    assert!(r.ok().contains("3 passkeys were already in hirz"));
    assert_eq!(records(&b, &vb).len(), 3);
}

#[test]
fn plain_export_is_standard_cxf_and_counts_as_backup_when_confirmed() {
    let a = Machine::new("plain");
    init(&a);
    let va = a.default_vault();
    put(&a, &va, vec![record("example.com", "alice", false, 1)]);
    let file = a.tmp.path("export.json");
    let fs_ = file.to_str().unwrap();

    let r = run(&a, &["export", "--plain", "--cxf", fs_], &["no"]);
    assert_eq!(r.exit(), Exit::Cancelled);
    assert!(!file.exists());

    let r = run(&a, &["export", "--plain", "--cxf", fs_], &["yes", "y"]);
    assert!(r.ok().contains("not encrypted"));
    assert!(Vault::open(&va, &a.state()).unwrap().backup_state());

    let doc: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    assert_eq!(doc["version"]["major"], 1);
    assert_eq!(doc["version"]["minor"], 0);
    assert_eq!(doc["exporterRpId"], "hirz.dev");
    let account = &doc["accounts"][0];
    assert_eq!(account["collections"], Value::Array(vec![]));
    let item = &account["items"][0];
    assert_eq!(item["creationAt"], 1_700_000_001u64);
    let pk = &item["credentials"][0];
    assert_eq!(pk["type"], "passkey");
    assert_eq!(pk["rpId"], "example.com");
    assert_eq!(pk["username"], "alice");
    assert_eq!(pk["userDisplayName"], "alice display");
    assert_eq!(
        pk["credentialId"],
        hirz_proto::base64url::encode(&[1u8; 32])
    );
    assert_eq!(pk["userHandle"], hirz_proto::base64url::encode(&[1u8; 16]));
    let key = hirz_proto::base64url::decode(pk["key"].as_str().unwrap()).unwrap();
    assert!(hirz_crypto::es256::public_key(&key).is_ok());
    let h = &pk["fido2Extensions"]["hmacCredentials"];
    assert_eq!(h["algorithm"], "hmac-sha256");
    assert_eq!(h["credWithUV"], hirz_proto::base64url::encode(&[1u8; 32]));
    assert_eq!(item["extensions"][0]["name"], "hirz.dev/passkey");

    let c = Machine::new("plain-c");
    init(&c);
    let r = run(&c, &["import", "--cxf", fs_], &[]);
    assert!(r.ok().contains("Imported 1 passkey"));
    assert_eq!(records(&a, &va), records(&c, &c.default_vault()));
}

#[test]
fn import_from_another_provider() {
    let m = Machine::new("fixture");
    init(&m);
    let file = m.tmp.path("provider.json");
    fs::write(&file, FIXTURE).unwrap();
    let fs_ = file.to_str().unwrap();
    let r = run(&m, &["import", "--cxf", fs_], &[]);
    assert_eq!(r.exit(), Exit::Partial, "{}", r.out);
    let out = &r.out;
    assert!(out.contains("Export made by: Example Provider"));
    assert!(out.contains("Imported 4 passkeys"));
    assert!(out.contains("1 item of other kinds"));
    assert!(out.contains("credBlob data"));
    assert!(out.contains("Skipped 3 passkeys"));
    assert!(out.contains("example.net (carol): it uses an RSA key"));
    assert!(out.contains("not a valid domain name"));
    assert!(out.contains("example.org (gina): its credential id is empty"));
    assert!(!out.contains("bytes long"));

    let recs = records(&m, &m.default_vault());
    assert_eq!(recs.len(), 4);
    let alice = &recs[0];
    assert_eq!(alice.rp_id, "example.com");
    assert_eq!(alice.algorithm, -7);
    assert_eq!(alice.user_id, b"user-alice-0001");
    assert_eq!(alice.user_display_name.as_deref(), Some("Alice Example"));
    assert_eq!(alice.created_at, 1_700_000_000);
    assert!(alice.discoverable);
    assert_eq!(alice.rp_name, None);
    let h = alice.hmac_secret.as_ref().unwrap();
    assert_eq!(*h.cred_random_with_uv, [0x11; 32]);
    assert_eq!(*h.cred_random_without_uv, [0x22; 32]);
    let bob = &recs[1];
    assert_eq!(bob.rp_id, "login.example.org");
    assert_eq!(bob.algorithm, -8);
    assert_eq!(bob.user_id, b"user-bob-0000002");
    assert_eq!(bob.user_display_name, None);
    assert!(bob.hmac_secret.is_none());
    // Ids of other lengths than the 32 bytes hirz creates are kept as they are.
    let frank = &recs[2];
    assert_eq!(frank.credential_id, vec![4u8; 16]);
    assert_eq!(frank.rp_id, "example.org");
    assert_eq!(frank.algorithm, -7);
    let dave = &recs[3];
    assert_eq!(dave.credential_id, b"credentialIdExample");
    assert_eq!(dave.rp_id, "acme.example");
    {
        let v = Vault::open(&m.default_vault(), &m.state()).unwrap();
        assert!(v.get(&[4u8; 16]).is_some());
        assert!(v.get(&[4u8; 15]).is_none());
        assert!(v.get(&[4u8; 32]).is_none());
    }

    let r = run(&m, &["import", "--cxf", fs_], &[]);
    assert_eq!(r.exit(), Exit::Partial);
    assert!(r.out.contains("4 passkeys were already in hirz"));

    // Export and re-import keep the short ids.
    let out_file = m.tmp.path("short-ids.json");
    let o = out_file.to_str().unwrap();
    let r = run(&m, &["export", "--plain", "--cxf", o], &["yes", "y"]);
    r.ok();
    let c = Machine::new("fixture-c");
    init(&c);
    let r = run(&c, &["import", "--cxf", o], &[]);
    assert!(r.ok().contains("Imported 4 passkeys"), "{}", r.out);
    assert_eq!(
        records(&m, &m.default_vault()),
        records(&c, &c.default_vault())
    );

    // Ids over the WebAuthn limit of 1023 bytes are refused.
    let mut long: Value = serde_json::from_str(FIXTURE).unwrap();
    long["accounts"][0]["items"][1]["credentials"][0]["credentialId"] =
        Value::from(hirz_proto::base64url::encode(&[7u8; 1024]));
    let long_file = m.tmp.path("long.json");
    fs::write(&long_file, serde_json::to_vec(&long).unwrap()).unwrap();
    let r = run(&c, &["import", "--cxf", long_file.to_str().unwrap()], &[]);
    assert!(
        r.out.contains("(bob): the field credentialId is too long"),
        "{}",
        r.out
    );
    let mut max: Value = serde_json::from_str(FIXTURE).unwrap();
    max["accounts"][0]["items"][1]["credentials"][0]["credentialId"] =
        Value::from(hirz_proto::base64url::encode(&[7u8; 1023]));
    fs::write(&long_file, serde_json::to_vec(&max).unwrap()).unwrap();
    let r = run(&c, &["import", "--cxf", long_file.to_str().unwrap()], &[]);
    assert!(r.out.contains("Imported 1 passkey"), "{}", r.out);
    assert!(
        Vault::open(&c.default_vault(), &c.state())
            .unwrap()
            .get(&[7u8; 1023])
            .is_some()
    );

    let mut tampered: Value = serde_json::from_str(FIXTURE).unwrap();
    let other_key = hirz_proto::base64url::encode(&hirz_crypto::es256::generate().unwrap().0);
    tampered["accounts"][0]["items"][0]["credentials"][0]["key"] = Value::from(other_key);
    fs::write(&file, serde_json::to_vec(&tampered).unwrap()).unwrap();
    let r = run(&m, &["import", "--cxf", fs_], &[]);
    assert!(r.out.contains("a different passkey with the same id"));
    assert_eq!(
        records(&m, &m.default_vault())[0].private_key_pkcs8,
        recs[0].private_key_pkcs8
    );
}

#[test]
fn import_rejects_bad_documents() {
    let m = Machine::new("badcxf");
    init(&m);
    let file = m.tmp.path("bad.json");
    let fs_ = file.to_str().unwrap();
    for (content, needle) in [
        ("not json", "not valid JSON"),
        ("[]", "not a CXF export"),
        ("{\"accounts\": []}", "no version"),
        (
            "{\"version\": {\"major\": 2, \"minor\": 0}, \"accounts\": []}",
            "version 2",
        ),
        ("{\"version\": {\"major\": 1, \"minor\": 0}}", "no accounts"),
        (
            "{\"version\": {\"major\": 1, \"minor\": 0}, \"accounts\": [{\"items\": 5}]}",
            "not a list",
        ),
    ] {
        fs::write(&file, content).unwrap();
        let r = run(&m, &["import", "--cxf", fs_], &[]);
        assert_eq!(r.exit(), Exit::Failed, "{content}");
        assert!(r.message().contains(needle), "{content}: {}", r.message());
    }
    let deep = format!(
        "{{\"version\":{{\"major\":1,\"minor\":0}},\"accounts\":{}{}}}",
        "[".repeat(200),
        "]".repeat(200)
    );
    fs::write(&file, deep).unwrap();
    assert_eq!(run(&m, &["import", "--cxf", fs_], &[]).exit(), Exit::Failed);
    fs::write(&file, b"HIRZ-CXF\x09").unwrap();
    let r = run(&m, &["import", "--cxf", fs_], &[]);
    assert_eq!(r.exit(), Exit::Failed);
}

// ---- devices ----

#[test]
fn remove_device_reports_exposed_sites() {
    let a = Machine::new("rm-a");
    let phrase = init(&a);
    let vault = a.default_vault();
    let vs = vault.to_str().unwrap().to_string();
    put(
        &a,
        &vault,
        vec![
            record("example.com", "alice", false, 1),
            record("example.com", "alice2", false, 2),
            record("login.example.org", "bob", true, 3),
        ],
    );
    let b = Machine::new("rm-b");
    run(
        &b,
        &["join", "--vault", &vs, "--name", "old-laptop"],
        &[&phrase],
    )
    .ok();
    let b_id = crate::ui::hex(&Vault::open(&vault, &b.state()).unwrap().device_id());
    let a_id = crate::ui::hex(&Vault::open(&vault, &a.state()).unwrap().device_id());

    let r = run(&a, &["remove-device", &a_id[..8]], &[]);
    assert_eq!(r.exit(), Exit::Failed);
    assert!(r.message().contains("this computer"));

    let r = run(&a, &["remove-device", &b_id[..8]], &["n"]);
    assert_eq!(r.exit(), Exit::Cancelled);
    assert!(r.out.contains("keeps whatever it already read"));

    let r = run(&a, &["remove-device", &b_id[..8]], &["y"]);
    let out = r.ok();
    assert!(out.contains("Passkeys it could have copied (2 sites)"));
    assert!(out.contains("example.com  (2 passkeys)"));
    assert!(out.contains("login.example.org  (1 passkey)"));
    assert!(out.contains("replace the passkeys"));

    let devs = run(&a, &["devices"], &[]);
    let out = devs.ok();
    assert!(out.contains("removed"));
    assert!(out.contains("1 device in use"));

    let r = run(&a, &["remove-device", &b_id[..8]], &["y"]);
    assert_eq!(r.exit(), Exit::Failed);

    // The removed device can still open the folder but cannot read new generations.
    let st = run(&b, &["status"], &[]);
    assert_ne!(st.exit(), Exit::Ok);
}

#[test]
fn backup_confirm_sets_backup_state() {
    let m = Machine::new("backup");
    init(&m);
    let r = run(&m, &["status"], &[]);
    assert!(r.ok().contains("Backed up:      no"));
    let r = run(&m, &["backup", "confirm"], &["n"]);
    assert_eq!(r.exit(), Exit::Cancelled);
    run(&m, &["backup", "confirm"], &["yes"]).ok();
    assert!(
        Vault::open(&m.default_vault(), &m.state())
            .unwrap()
            .backup_state()
    );
    assert!(
        run(&m, &["backup", "confirm"], &[])
            .ok()
            .contains("already")
    );
}

// ---- pin ----

#[test]
fn pin_lifecycle() {
    let m = Machine::new("pin");
    let phrase = init(&m);
    assert!(
        run(&m, &["pin", "status"], &[])
            .ok()
            .contains("No hirz PIN")
    );
    let r = run(&m, &["pin", "set"], &["12", "1234", "1235", "1234", "1234"]);
    let out = r.ok();
    assert!(out.contains("at least 4 characters"));
    assert!(out.contains("different"));
    assert!(m.state().join("pin").is_file());
    assert_eq!(run(&m, &["pin", "set"], &[]).exit(), Exit::Failed);

    let r = run(&m, &["pin", "change"], &["9999"]);
    assert_eq!(r.exit(), Exit::Denied);
    assert!(r.message().contains("7 tries left"));
    assert!(run(&m, &["pin", "status"], &[]).ok().contains("1 of 8"));
    run(&m, &["pin", "change"], &["1234", "abcd", "abcd"]).ok();
    hirz_uv::PinStore::with_params(m.state(), FAST)
        .verify(b"abcd")
        .unwrap();

    let other = RecoveryPhrase::from_entropy([9u8; 32])
        .to_words()
        .to_string();
    let r = run(&m, &["pin", "reset"], &[&other]);
    assert_eq!(r.exit(), Exit::Denied);
    assert!(m.state().join("pin").is_file());
    run(&m, &["pin", "reset"], &[&phrase]).ok();
    assert!(!m.state().join("pin").exists());
}

// ---- status and setup ----

#[test]
fn status_before_and_after_setup() {
    let m = Machine::new("status");
    let r = run(&m, &["status"], &[]);
    assert_eq!(r.exit(), Exit::NotSetUp);
    assert!(r.out.contains("not set up"));
    assert!(r.out.contains("hirz setup firefox"));
    let r = run(&m, &["status", "--json"], &[]);
    let v: Value = serde_json::from_str(&r.out).unwrap();
    assert_eq!(v["set_up"], false);
    assert_eq!(v["approval"]["methods"][0], "pin");

    init(&m);
    let polkit = m.env.sys_path("/usr/share/polkit-1/actions");
    fs::create_dir_all(&polkit).unwrap();
    fs::write(
        polkit.join("dev.hirz.authenticate.policy"),
        b"<policyconfig/>",
    )
    .unwrap();
    let r = run(&m, &["status"], &[]);
    let out = r.ok();
    assert!(out.contains("Passkeys:       0"));
    assert!(out.contains("all vault files read correctly"));
    assert!(out.contains("Polkit action:  installed"));
    assert!(out.contains("broker socket"));

    let vault = m.default_vault();
    let dev_dir = fs::read_dir(vault.join("records"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let rec = fs::read_dir(&dev_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut bytes = fs::read(&rec).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&rec, bytes).unwrap();
    let r = run(&m, &["status", "--json"], &[]);
    let v: Value = serde_json::from_str(r.ok()).unwrap();
    assert_eq!(
        v["vault"]["sync"]["skipped_files"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let r = run(&m, &["status"], &[]);
    assert!(r.out.contains("1 file could not be read"));
}

#[test]
fn setup_firefox_writes_the_user_manifest() {
    let m = Machine::new("ff");
    let bin = m.env.exe_dir.clone().unwrap();
    fs::create_dir_all(&bin).unwrap();
    let r = run(&m, &["setup", "firefox"], &[]);
    assert_eq!(r.exit(), Exit::Failed);
    assert!(r.message().contains("--nmh-path"));

    let nmh = bin.join("hirz-nmh");
    fs::write(&nmh, b"#!/bin/sh\n").unwrap();
    fs::set_permissions(&nmh, fs::Permissions::from_mode(0o755)).unwrap();
    fs::create_dir_all(m.env.sys_path("/snap/bin")).unwrap();
    fs::write(m.env.sys_path("/snap/bin/firefox"), b"").unwrap();
    let r = run(&m, &["setup", "firefox"], &[]);
    let out = r.ok();
    assert!(out.contains("Installed"));
    assert!(out.contains("Snap"));
    let manifest = m.tmp.path(".mozilla/native-messaging-hosts/hirz.json");
    let v: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    let canon = fs::canonicalize(&nmh).unwrap();
    assert_eq!(v["path"], canon.to_str().unwrap());
    assert_eq!(v["name"], "hirz");
    assert_eq!(v["allowed_extensions"][0], "hirz@hirz.dev");
    assert!(
        run(&m, &["setup", "firefox"], &[])
            .ok()
            .contains("already set up")
    );

    let other = m.tmp.path("other-nmh");
    fs::write(&other, b"#!/bin/sh\n").unwrap();
    fs::set_permissions(&other, fs::Permissions::from_mode(0o755)).unwrap();
    let os_ = other.to_str().unwrap();
    let r = run(&m, &["setup", "firefox", "--nmh-path", os_], &["n"]);
    assert_eq!(r.exit(), Exit::Cancelled);
    run(&m, &["setup", "firefox", "--nmh-path", os_, "--force"], &[]).ok();
    let v: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    assert_eq!(
        v["path"],
        fs::canonicalize(&other).unwrap().to_str().unwrap()
    );

    let st = run(&m, &["status", "--json"], &[]);
    let v: Value = serde_json::from_str(&st.out).unwrap();
    assert_eq!(v["firefox"]["manifests"][0]["state"], "ok");
    assert_eq!(v["firefox"]["snap"], true);
}

#[test]
fn commands_need_setup() {
    let m = Machine::new("nosetup");
    for args in [
        &["list"][..],
        &["devices"],
        &["delete", "abcd"],
        &["backup", "confirm"],
        &["export", "--cxf", "x"],
        &["import", "--cxf", "x"],
    ] {
        assert_eq!(run(&m, args, &[]).exit(), Exit::NotSetUp, "{args:?}");
    }
}
