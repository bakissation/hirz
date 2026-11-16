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
use hirz_core::{
    Approval, ApprovalContext, ApprovalError, Approver, PairingApprovalContext,
    RemovalApprovalContext,
};
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
    fn pairing_approver<'s>(&'s self, _env: &Env) -> Box<dyn Approver + 's> {
        Box::new(FakeApprover {
            result: Ok(VERIFIED),
            seen: None,
            removals: None,
        })
    }
}

const VERIFIED: Approval = Approval {
    user_present: true,
    user_verified: true,
    selected: None,
};

/// What a pairing confirmation was shown: device name, words, request time.
type SeenPairing = (String, Vec<String>, u64);

/// Stands in for the hirz-uv window and the user's password, fingerprint or PIN.
struct FakeApprover<'a> {
    result: Result<Approval, ApprovalError>,
    seen: Option<&'a RefCell<Vec<SeenPairing>>>,
    /// Device name and id shown by removal confirmations.
    removals: Option<&'a RefCell<Vec<(String, String)>>>,
}

impl Approver for FakeApprover<'_> {
    fn approve(&self, _ctx: &ApprovalContext<'_>) -> Result<Approval, ApprovalError> {
        Err(ApprovalError::Internal("not used by the CLI".into()))
    }
    fn confirm_pairing(&self, ctx: &PairingApprovalContext<'_>) -> Result<Approval, ApprovalError> {
        if let Some(seen) = self.seen {
            seen.borrow_mut().push((
                ctx.device_name.to_string(),
                ctx.words.iter().map(|w| w.to_string()).collect(),
                ctx.requested_at,
            ));
        }
        self.result.clone()
    }
    fn confirm_removal(&self, ctx: &RemovalApprovalContext<'_>) -> Result<Approval, ApprovalError> {
        if let Some(seen) = self.removals {
            seen.borrow_mut()
                .push((ctx.device_name.to_string(), ctx.device_id_short.to_string()));
        }
        self.result.clone()
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

struct Opts<'a> {
    sys: &'a dyn System,
    program: &'a str,
    terminal: bool,
    wrong_words: bool,
}

fn run_with(m: &Machine, args: &[&str], answers: &[&str], wrong_words: bool) -> Run {
    run_opts(
        m,
        args,
        answers,
        Opts {
            sys: &FakeSys,
            program: "hirz",
            terminal: false,
            wrong_words,
        },
    )
}

fn run_opts(m: &Machine, args: &[&str], answers: &[&str], o: Opts<'_>) -> Run {
    let wrong_words = o.wrong_words;
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
        sys: o.sys,
        kdf: FAST,
        vault_flag: None,
        program: o.program.into(),
        out_is_terminal: o.terminal,
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
                    request: false,
                },
            ),
        ),
        (
            &["join", "--vault", "/v", "--request"],
            inv(
                Some("/v"),
                Command::Join {
                    name: None,
                    request: true,
                },
            ),
        ),
        (
            &["devices", "approve"],
            inv(None, Command::DevicesApprove { request: None }),
        ),
        (
            &["devices", "approve", "abcd"],
            inv(
                None,
                Command::DevicesApprove {
                    request: Some("abcd".into()),
                },
            ),
        ),
        (
            &["devices", "deny", "abcd"],
            inv(
                None,
                Command::DevicesDeny {
                    request: "abcd".into(),
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
        &["join", "--request"],
        &["devices", "approve", "a", "b"],
        &["devices", "approve", "--yes"],
        &["devices", "approve", "--json"],
        &["devices", "deny"],
        &["devices", "frob"],
        &["init", "--request"],
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
fn ssh_keys_are_named_in_the_terminal_and_raw_in_json() {
    let m = Machine::new("ssh");
    init(&m);
    let vault = m.default_vault();
    put(
        &m,
        &vault,
        vec![
            record("ssh:", "openssh", false, 4),
            record("ssh:work", "openssh", false, 5),
        ],
    );
    let out = run(&m, &["list"], &[]).ok().to_owned();
    assert!(out.contains("SSH key (work)"));
    assert!(out.lines().any(|l| l.starts_with("SSH key ")));
    assert!(!out.contains("ssh:"));

    let r = run(&m, &["list", "--site", "ssh:work", "--json"], &[]);
    let v: Value = serde_json::from_str(r.ok()).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 1);
    assert_eq!(v[0]["site"], "ssh:work");

    let r = run(&m, &["delete", "0505"], &["n"]);
    assert!(r.out.contains("Passkey: SSH key (work) (openssh)"));
    assert_eq!(r.exit(), Exit::Cancelled);
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
    assert_eq!(doc["exporterRpId"], "hirz.berkati.xyz");
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
    assert_eq!(item["extensions"][0]["name"], "hirz.berkati.xyz/passkey");

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

    // The removed device can still open the folder but cannot read new generations, and it
    // stops using the vault.
    let st = run(&b, &["status"], &[]);
    assert_ne!(st.exit(), Exit::Ok);
    assert!(st.out.contains(crate::app::REMOVED), "{}", st.out);
    let st = run(&b, &["status", "--json"], &[]);
    let v: Value = serde_json::from_str(&st.out).unwrap();
    assert_eq!(v["vault"]["this_device_removed"], true);
    for args in [
        &["list"][..],
        &["list", "--json"],
        &["devices"],
        &["devices", "approve"],
    ] {
        let r = run(&b, args, &[]);
        assert_eq!(r.exit(), Exit::Failed, "{args:?}");
        assert!(
            r.message().starts_with(crate::app::REMOVED),
            "{}",
            r.message()
        );
        assert!(r.message().contains("hirz forget-local"));
        assert!(r.out.is_empty());
    }

    // forget-local deletes only this computer's keys.
    let vault_files = tree(&vault);
    let r = run(&b, &["forget-local"], &["n"]);
    assert_eq!(r.exit(), Exit::Cancelled);
    assert!(b.state().join(hirz_vault::DEVICE_STATE_FILE).exists());
    let r = run(&b, &["forget-local"], &["y"]);
    assert!(r.ok().contains(crate::app::REMOVED));
    assert!(!b.state().join(hirz_vault::DEVICE_STATE_FILE).exists());
    assert!(!b.state().join(crate::env::VAULT_POINTER).exists());
    assert_eq!(tree(&vault), vault_files);
    assert_eq!(run(&b, &["list"], &[]).exit(), Exit::NotSetUp);
    assert!(
        run(&b, &["forget-local"], &[])
            .ok()
            .contains("nothing to forget")
    );
    assert_eq!(records(&a, &vault).len(), 3);
}

/// Every file under `dir` with its size, sorted.
fn tree(dir: &Path) -> Vec<(PathBuf, u64)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let len = fs::metadata(&p).unwrap().len();
                out.push((p, len));
            }
        }
    }
    out.sort();
    out
}

fn run_sys(m: &Machine, sys: &dyn System, args: &[&str], answers: &[&str]) -> Run {
    run_opts(
        m,
        args,
        answers,
        Opts {
            sys,
            program: "hirz",
            terminal: false,
            wrong_words: false,
        },
    )
}

#[test]
fn remove_device_requires_user_verification() {
    let a = Machine::new("rmuv-a");
    let phrase = init(&a);
    let vault = a.default_vault();
    let vs = vault.to_str().unwrap().to_string();
    let b = Machine::new("rmuv-b");
    run(
        &b,
        &["join", "--vault", &vs, "--name", "old-laptop"],
        &[&phrase],
    )
    .ok();
    let b_id = crate::ui::hex(&Vault::open(&vault, &b.state()).unwrap().device_id());
    let active = || {
        Vault::open(&vault, &a.state())
            .unwrap()
            .devices()
            .iter()
            .filter(|d| !d.removed)
            .count()
    };

    // No method at all: refused before any question.
    let none = UvSys::new(&[], Ok(VERIFIED));
    let r = run_sys(&a, &none, &["remove-device", &b_id[..8]], &["y"]);
    assert_eq!(r.exit(), Exit::Failed);
    assert!(r.message().contains("hirz pin set"), "{}", r.message());
    assert!(
        r.message()
            .contains(&format!("hirz remove-device {}", &b_id[..12]))
    );
    assert!(r.prompts.is_empty());
    assert!(none.removals.borrow().is_empty());

    // Answering no in the terminal never opens the window.
    let uv = UvSys::new(&[UvMethod::Polkit], Ok(VERIFIED));
    let r = run_sys(&a, &uv, &["remove-device", &b_id[..8]], &["n"]);
    assert_eq!(r.exit(), Exit::Cancelled);
    assert!(uv.removals.borrow().is_empty());

    for (result, exit, needle) in [
        (Err(ApprovalError::Denied), Exit::Cancelled, "cancelled"),
        (
            Err(ApprovalError::Timeout),
            Exit::Failed,
            "not answered in time",
        ),
        (Err(ApprovalError::Locked), Exit::Failed, "hirz pin reset"),
        (
            Err(ApprovalError::Unavailable),
            Exit::Failed,
            "hirz pin set",
        ),
        (
            Ok(Approval {
                user_present: true,
                user_verified: false,
                selected: None,
            }),
            Exit::Failed,
            "could not verify",
        ),
    ] {
        // --yes skips only the terminal question, never the verification.
        let uv = UvSys::new(&[UvMethod::Pin], result);
        let r = run_sys(&a, &uv, &["remove-device", &b_id[..8], "--yes"], &[]);
        assert_eq!(r.exit(), exit, "{}", r.message());
        assert!(r.message().contains(needle), "{}", r.message());
        assert!(r.message().contains("Nothing was removed."));
        assert!(r.out.contains("Confirm in the hirz window"));
        assert!(r.prompts.is_empty());
        assert_eq!(
            uv.removals.borrow().as_slice(),
            [("old-laptop".to_string(), b_id[..12].to_string())]
        );
        assert_eq!(active(), 2);
    }

    let ok = UvSys::new(&[UvMethod::Fingerprint], Ok(VERIFIED));
    let r = run_sys(&a, &ok, &["remove-device", &b_id[..8]], &["y"]);
    assert!(r.ok().contains("Removed \"old-laptop\""));
    assert_eq!(ok.removals.borrow().len(), 1);
    assert_eq!(active(), 1);
}

#[test]
fn forget_local_on_an_active_device_needs_the_word() {
    let m = Machine::new("forget-active");
    init(&m);
    let r = run(&m, &["forget-local"], &["y"]);
    assert_eq!(r.exit(), Exit::Cancelled);
    assert!(r.out.contains("still uses the vault"));
    assert!(m.state().join(hirz_vault::DEVICE_STATE_FILE).exists());
    run(&m, &["forget-local"], &["forget"]).ok();
    assert!(!m.state().join(hirz_vault::DEVICE_STATE_FILE).exists());
    assert!(Vault::exists(&m.default_vault()));
    assert_eq!(
        args::parse(&os(&["forget-local", "x"])).unwrap_err().exit,
        Exit::Usage
    );
}

#[test]
fn visibility_notes() {
    use crate::prompt::{NOTE_NOT_TERMINAL, NOTE_TERMINAL, visibility_note};
    assert_eq!(visibility_note(true, true), None);
    assert_eq!(visibility_note(true, false), None);
    assert_eq!(visibility_note(false, true), Some(NOTE_TERMINAL));
    assert_eq!(visibility_note(false, false), Some(NOTE_NOT_TERMINAL));
    let docs = include_str!("../../../docs/cli.md");
    assert!(docs.contains(NOTE_TERMINAL) && docs.contains(NOTE_NOT_TERMINAL));
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
    assert_eq!(v["allowed_extensions"][0], "hirz@berkati.xyz");
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

// ---- recovery phrase screen and program name ----

#[test]
fn command_name_uses_argv0_only_when_hirz_is_not_on_path() {
    use crate::env::command_name;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let none = |_: &Path| false;
    let in_bin = |p: &Path| p == Path::new("/usr/bin/hirz");
    let path = Some(OsStr::new("/usr/local/bin:/usr/bin"));
    let rel_path = Some(OsStr::new("bin:.:"));
    type Case<'a> = (
        Option<&'a OsStr>,
        Option<&'a OsStr>,
        &'a dyn Fn(&Path) -> bool,
        &'a str,
    );
    let cases: &[Case<'_>] = &[
        (None, path, &none, "hirz"),
        (Some(OsStr::new("hirz")), path, &none, "hirz"),
        (
            Some(OsStr::new("./target/debug/hirz")),
            path,
            &none,
            "./target/debug/hirz",
        ),
        (
            Some(OsStr::new("/opt/hirz/hirz")),
            None,
            &none,
            "/opt/hirz/hirz",
        ),
        (
            Some(OsStr::new("./target/debug/hirz")),
            path,
            &in_bin,
            "hirz",
        ),
        // Relative PATH entries are not used to decide.
        (
            Some(OsStr::new("./hirz")),
            rel_path,
            &|_: &Path| true,
            "./hirz",
        ),
        (
            Some(OsStr::new("/home/alice/my tools/hirz")),
            path,
            &none,
            "'/home/alice/my tools/hirz'",
        ),
        (
            Some(OsStr::new("/tmp/it's/hirz")),
            path,
            &none,
            "'/tmp/it'\\''s/hirz'",
        ),
        (Some(OsStr::new("/tmp/a\nb/hirz")), path, &none, "hirz"),
        (
            Some(OsStr::from_bytes(b"/tmp/\xff/hirz")),
            path,
            &none,
            "hirz",
        ),
    ];
    for (argv0, path_var, exec, expected) in cases {
        assert_eq!(
            command_name(*argv0, *path_var, *exec),
            *expected,
            "{argv0:?}"
        );
    }
}

#[test]
fn init_warns_and_clears_the_phrase_on_a_terminal() {
    let m = Machine::new("clear");
    let r = run_opts(
        &m,
        &["init"],
        &[],
        Opts {
            sys: &FakeSys,
            program: "./bin/hirz",
            terminal: true,
            wrong_words: false,
        },
    );
    let out = r.ok();
    assert!(out.contains("Do not copy, paste or screenshot this screen."));
    let clear = "\x1b[2J\x1b[3J\x1b[H";
    let after = &out[out.find(clear).expect("screen cleared") + clear.len()..];
    let words = phrase_words(out);
    // Phrase words are common English words that may occur in later text, so look for the
    // numbered layout of the phrase rather than for single words.
    assert!(
        words
            .iter()
            .enumerate()
            .all(|(i, w)| !after.contains(&format!("{:>2}. {w}", i + 1)))
    );
    assert!(after.contains("Correct. Keep the paper safe."));
    assert!(after.contains("./bin/hirz setup firefox"));
    assert!(after.contains("./bin/hirz devices approve"));
    assert!(after.contains("hirz join --vault DIR --request"));

    // Not a terminal, or no check: nothing is cleared.
    let m2 = Machine::new("noclear");
    let out = run(&m2, &["init"], &[]).ok().to_string();
    assert!(!out.contains(clear));
    assert!(out.contains("Do not copy, paste or screenshot"));
    assert!(out.contains("Connect Firefox: hirz setup firefox"));
    let m3 = Machine::new("noclear-saved");
    let r = run_opts(
        &m3,
        &["init", "--yes-i-saved-it"],
        &[],
        Opts {
            sys: &FakeSys,
            program: "hirz",
            terminal: true,
            wrong_words: false,
        },
    );
    assert!(!r.ok().contains(clear));
}

// ---- pairing ----

/// A system whose clock advances on every poll and that runs `on_sleep` while the joining
/// command waits, standing in for the user at the other device.
struct PairSys<'a> {
    clock: std::cell::Cell<u64>,
    step: u64,
    sleeps: std::cell::Cell<u32>,
    on_sleep: RefCell<Box<dyn FnMut(u32) + 'a>>,
}

impl<'a> PairSys<'a> {
    fn new(step: u64, f: impl FnMut(u32) + 'a) -> Self {
        PairSys {
            clock: std::cell::Cell::new(FakeSys.now()),
            step,
            sleeps: std::cell::Cell::new(0),
            on_sleep: RefCell::new(Box::new(f)),
        }
    }
}

impl System for PairSys<'_> {
    fn uv_methods(&self, env: &Env) -> Result<Vec<UvMethod>, String> {
        FakeSys.uv_methods(env)
    }
    fn zenity(&self) -> bool {
        true
    }
    fn hostname(&self) -> Option<String> {
        Some("new-host".into())
    }
    fn pairing_approver<'s>(&'s self, env: &Env) -> Box<dyn Approver + 's> {
        FakeSys.pairing_approver(env)
    }
    fn now(&self) -> u64 {
        self.clock.get()
    }
    fn sleep(&self, _d: std::time::Duration) {
        let n = self.sleeps.get() + 1;
        self.sleeps.set(n);
        self.clock.set(self.clock.get() + self.step);
        (self.on_sleep.borrow_mut())(n);
    }
}

fn join_request(m: &Machine, vault: &str, sys: &dyn System) -> Run {
    run_opts(
        m,
        &["join", "--vault", vault, "--request", "--name", "desk"],
        &[],
        Opts {
            sys,
            program: "hirz",
            terminal: false,
            wrong_words: false,
        },
    )
}

/// The line with the four upper-case verification words.
fn words_line(out: &str) -> String {
    out.lines()
        .find(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            l.starts_with("        ")
                && t.len() == 4
                && t.iter().all(|w| w.chars().all(|c| c.is_ascii_uppercase()))
        })
        .unwrap_or_else(|| panic!("no words in:\n{out}"))
        .to_string()
}

fn pairing_dir_files(vault: &Path) -> Vec<String> {
    fs::read_dir(vault.join("pairing"))
        .map(|rd| {
            rd.map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn pairing_adds_a_device_without_the_phrase() {
    let a = Machine::new("pair-a");
    init(&a);
    let vault = a.default_vault();
    let vs = vault.to_str().unwrap().to_string();
    put(&a, &vault, vec![record("example.com", "alice", false, 1)]);
    let r = run(&a, &["devices", "approve"], &[]);
    assert_eq!(r.exit(), Exit::Failed);
    assert!(r.message().contains("No device is waiting"));

    let b = Machine::new("pair-b");
    let approved = RefCell::new(String::new());
    let sys = PairSys::new(2, |n| match n {
        1 => {
            // A forged approval appears first: the new device warns and keeps waiting.
            let dir = vault.join("pairing");
            let req = pairing_dir_files(&vault)
                .into_iter()
                .find(|f| f.ends_with(".req"))
                .unwrap();
            fs::write(dir.join(req.replace(".req", ".ok")), b"HIRZ\x08\x01forged").unwrap();
            let listed = run(&a, &["devices"], &[]);
            assert!(listed.ok().contains("1 device waiting for approval"));
        }
        2 => {
            let r = run(&a, &["devices", "approve"], &["yes"]);
            *approved.borrow_mut() = r.ok().to_string();
        }
        _ => {}
    });
    let r = join_request(&b, &vs, &sys);
    let out = r.ok();
    let a_out = approved.borrow().clone();
    assert!(out.contains("hirz devices approve"));
    assert!(out.contains("Warning: an approval appeared"));
    assert_eq!(words_line(out), words_line(&a_out));
    assert!(a_out.contains("\"desk\""));
    assert!(a_out.contains("asked to join this vault less than a minute ago"));
    assert!(a_out.contains("Approved \"desk\""));
    assert!(out.contains("Approved. This computer (\"desk\")"));
    assert!(out.contains("1 passkey here"));
    assert!(out.contains("\"test-host\""));
    assert!(pairing_dir_files(&vault).is_empty());

    assert_eq!(records(&b, &vault).len(), 1);
    put(&b, &vault, vec![record("example.org", "bob", true, 2)]);
    assert_eq!(records(&a, &vault).len(), 2);
    let devs = run(&a, &["devices", "--json"], &[]);
    let v: Value = serde_json::from_str(devs.ok()).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 2);
    let st = run(&b, &["status", "--json"], &[]);
    let v: Value = serde_json::from_str(st.ok()).unwrap();
    assert_eq!(v["vault"]["backed_up"], true);
    assert_eq!(v["vault"]["passkeys"], 2);

    let again = join_request(&b, &vs, &FakeSys);
    assert_eq!(again.exit(), Exit::Failed);
    assert!(again.message().contains("already set up"));
}

#[test]
fn pairing_mismatch_deny_and_expiry_change_nothing() {
    let a = Machine::new("pair-no-a");
    init(&a);
    let vault = a.default_vault();
    let vs = vault.to_str().unwrap().to_string();

    // The user says the words differ: nothing is approved and the request is removed.
    let b = Machine::new("pair-no-b");
    let refused = RefCell::new(None);
    let sys = PairSys::new(60, |n| {
        if n == 1 {
            let r = run(&a, &["devices", "approve"], &["no"]);
            assert!(r.out.contains("Compare the words"));
            *refused.borrow_mut() = Some(r.exit());
            assert!(pairing_dir_files(&vault).is_empty());
        }
    });
    let r = join_request(&b, &vs, &sys);
    assert_eq!(*refused.borrow(), Some(Exit::Cancelled));
    assert_eq!(r.exit(), Exit::Failed);
    assert!(r.message().contains("No approval arrived in time"));
    assert!(!b.state().join(hirz_vault::DEVICE_STATE_FILE).exists());
    assert_eq!(
        run(&a, &["devices", "--json"], &[])
            .ok()
            .matches("\"id\"")
            .count(),
        1
    );

    // Denied by id; then the request runs out.
    let c = Machine::new("pair-no-c");
    let sys = PairSys::new(60, |n| {
        if n == 1 {
            let req = pairing_dir_files(&vault)
                .into_iter()
                .find(|f| f.ends_with(".req"))
                .unwrap();
            assert_eq!(run(&a, &["devices", "deny", "zz"], &[]).exit(), Exit::Usage);
            assert_eq!(
                run(&a, &["devices", "deny", "0000ffff"], &[]).exit(),
                Exit::Failed
            );
            let r = run(&a, &["devices", "deny", &req[..8]], &[]);
            assert!(r.ok().contains("Removed the request from \"desk\""));
        }
    });
    let r = join_request(&c, &vs, &sys);
    assert_eq!(r.exit(), Exit::Failed);
    assert!(!c.state().join(hirz_vault::DEVICE_STATE_FILE).exists());
    assert!(pairing_dir_files(&vault).is_empty());

    // A request nobody answers expires and is withdrawn.
    let d = Machine::new("pair-no-d");
    let sys = PairSys::new(60, |_| {});
    let r = join_request(&d, &vs, &sys);
    assert_eq!(r.exit(), Exit::Failed);
    assert!(r.out.contains("expires in 15 minutes"));
    assert!(pairing_dir_files(&vault).is_empty());
    assert!(sys.sleeps.get() >= 15);

    let missing = d.tmp.path("nothing-here");
    let r = join_request(&d, missing.to_str().unwrap(), &FakeSys);
    assert_eq!(r.exit(), Exit::NotSetUp);
}

/// `devices approve` with a chosen user verification outcome and set of methods.
struct UvSys {
    methods: Vec<UvMethod>,
    result: Result<Approval, ApprovalError>,
    seen: RefCell<Vec<SeenPairing>>,
    removals: RefCell<Vec<(String, String)>>,
}

impl UvSys {
    fn new(methods: &[UvMethod], result: Result<Approval, ApprovalError>) -> Self {
        UvSys {
            methods: methods.to_vec(),
            result,
            seen: RefCell::new(Vec::new()),
            removals: RefCell::new(Vec::new()),
        }
    }
}

impl System for UvSys {
    fn uv_methods(&self, _env: &Env) -> Result<Vec<UvMethod>, String> {
        Ok(self.methods.clone())
    }
    fn zenity(&self) -> bool {
        true
    }
    fn hostname(&self) -> Option<String> {
        Some("test-host".into())
    }
    fn pairing_approver<'s>(&'s self, _env: &Env) -> Box<dyn Approver + 's> {
        Box::new(FakeApprover {
            result: self.result.clone(),
            seen: Some(&self.seen),
            removals: Some(&self.removals),
        })
    }
}

fn approve_with(m: &Machine, sys: &UvSys, answers: &[&str]) -> Run {
    run_opts(
        m,
        &["devices", "approve"],
        answers,
        Opts {
            sys,
            program: "hirz",
            terminal: false,
            wrong_words: false,
        },
    )
}

#[test]
fn pairing_approval_requires_user_verification() {
    let a = Machine::new("pair-uv-a");
    init(&a);
    let vault = a.default_vault();
    let vs = vault.to_str().unwrap().to_string();
    let b = Machine::new("pair-uv-b");
    let approved = RefCell::new(String::new());
    let sys = PairSys::new(2, |n| {
        if n != 1 {
            return;
        }
        let waiting = || {
            pairing_dir_files(&vault)
                .iter()
                .filter(|f| f.ends_with(".req"))
                .count()
        };

        // No method at all: refused before the words are compared.
        let none = UvSys::new(&[], Ok(VERIFIED));
        let r = approve_with(&a, &none, &["yes"]);
        assert_eq!(r.exit(), Exit::Failed);
        assert!(r.message().contains("hirz pin set"), "{}", r.message());
        assert!(r.message().contains("polkit"));
        assert!(r.prompts.is_empty());
        assert!(none.seen.borrow().is_empty());
        assert_eq!(waiting(), 1);

        for (result, exit, needle) in [
            (
                Err(ApprovalError::Unavailable),
                Exit::Failed,
                "hirz pin set",
            ),
            (Err(ApprovalError::Denied), Exit::Cancelled, "still waiting"),
            (
                Err(ApprovalError::Timeout),
                Exit::Failed,
                "not answered in time",
            ),
            (Err(ApprovalError::Locked), Exit::Failed, "hirz pin reset"),
            (
                Err(ApprovalError::Internal("boom".into())),
                Exit::Failed,
                "boom",
            ),
            (
                Ok(Approval {
                    user_present: true,
                    user_verified: false,
                    selected: None,
                }),
                Exit::Failed,
                "could not verify",
            ),
        ] {
            let uv = UvSys::new(&[UvMethod::Polkit], result);
            let r = approve_with(&a, &uv, &["yes"]);
            assert_eq!(r.exit(), exit, "{}", r.message());
            assert!(r.message().contains(needle), "{}", r.message());
            assert!(r.out.contains("Confirm in the hirz window"));
            assert_eq!(uv.seen.borrow().len(), 1);
            assert_eq!(waiting(), 1, "a refused verification keeps the request");
        }

        let ok = UvSys::new(&[UvMethod::Pin], Ok(VERIFIED));
        let r = approve_with(&a, &ok, &["yes"]);
        let out = r.ok().to_string();
        let seen = ok.seen.borrow();
        let (name, words, requested_at) = &seen[0];
        assert_eq!(name, "desk");
        assert!(*requested_at > 0);
        let shown: Vec<String> = words_line(&out)
            .split_whitespace()
            .map(str::to_lowercase)
            .collect();
        assert_eq!(words, &shown);
        *approved.borrow_mut() = out;
    });
    let r = join_request(&b, &vs, &sys);
    r.ok();
    assert!(approved.borrow().contains("Approved \"desk\""));
    assert_eq!(records(&b, &vault).len(), 0);
}
