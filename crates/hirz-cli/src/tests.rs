#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use crate::app::{self, Ctx};
use crate::args::{self, Command, DeleteTarget, ImportFormat, Invocation, PinAction, RepairAction};
use crate::env::{Env, System};
use crate::error::{CliError, Exit};
use crate::prompt::Prompter;
use hirz_core::{
    Approval, ApprovalContext, ApprovalError, Approver, ExportApprovalContext,
    PairingApprovalContext, RemovalApprovalContext, RepairApprovalContext,
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
            exports: None,
            repairs: None,
        })
    }
}

const VERIFIED: Approval = Approval {
    user_present: true,
    user_verified: true,
    selected: None,
};

type SeenPairing = (String, Vec<String>, u64);

struct FakeApprover<'a> {
    result: Result<Approval, ApprovalError>,
    seen: Option<&'a RefCell<Vec<SeenPairing>>>,
    removals: Option<&'a RefCell<Vec<(String, String)>>>,
    exports: Option<&'a RefCell<Vec<(usize, bool)>>>,
    repairs: Option<&'a RefCell<Vec<String>>>,
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
    fn confirm_export(&self, ctx: &ExportApprovalContext) -> Result<Approval, ApprovalError> {
        if let Some(seen) = self.exports {
            seen.borrow_mut().push((ctx.passkeys, ctx.plain));
        }
        self.result.clone()
    }
    fn confirm_repair(&self, ctx: &RepairApprovalContext<'_>) -> Result<Approval, ApprovalError> {
        if let Some(seen) = self.repairs {
            seen.borrow_mut().push(match ctx {
                RepairApprovalContext::DiscardGeneration { generation } => {
                    format!("discard {generation}")
                }
                RepairApprovalContext::AcceptFork => "accept-fork".to_string(),
            });
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

/// Scripted answers: "Press Enter" prompts get an empty line, "Word N" prompts are answered from
/// the phrase printed so far (wrongly when `wrong_words`).
struct Script {
    answers: VecDeque<String>,
    out: SharedBuf,
    wrong_words: bool,
    prompts: Vec<String>,
    notices: Vec<String>,
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
    fn notice(&mut self, text: &str) {
        self.notices.push(text.to_string());
    }
}

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
    notices: Vec<String>,
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
        notices: Vec::new(),
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
        notices: script.notices,
    }
}

fn run(m: &Machine, args: &[&str], answers: &[&str]) -> Run {
    run_with(m, args, answers, false)
}

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
                    format: ImportFormat::Cxf,
                    file: "in.json".into(),
                    yes: false,
                },
            ),
        ),
        (
            &["import", "--yes", "--keepassxc", "dir"],
            inv(
                None,
                Command::Import {
                    format: ImportFormat::KeePassXc,
                    file: "dir".into(),
                    yes: true,
                },
            ),
        ),
        (
            &["import", "--bitwarden=bw.json"],
            inv(
                None,
                Command::Import {
                    format: ImportFormat::Bitwarden,
                    file: "bw.json".into(),
                    yes: false,
                },
            ),
        ),
        (
            &["import", "--keepassxc", "keys"],
            inv(
                None,
                Command::Import {
                    format: ImportFormat::KeePassXc,
                    file: "keys".into(),
                    yes: false,
                },
            ),
        ),
        (
            &["backup", "confirm"],
            inv(None, Command::BackupConfirm { yes: false }),
        ),
        (
            &["repair"],
            inv(
                None,
                Command::Repair {
                    action: RepairAction::Show,
                    yes: false,
                },
            ),
        ),
        (
            &["repair", "--discard", "0000000002-aa", "--yes"],
            inv(
                None,
                Command::Repair {
                    action: RepairAction::Discard("0000000002-aa".into()),
                    yes: true,
                },
            ),
        ),
        (
            &["repair", "--accept-fork"],
            inv(
                None,
                Command::Repair {
                    action: RepairAction::AcceptFork,
                    yes: false,
                },
            ),
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
        &["repair", "extra"],
        &["repair", "--discard"],
        &["repair", "--yes"],
        &["repair", "--discard", "x", "--accept-fork"],
        &["repair", "--discard", "x", "--discard", "y"],
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
        &["import", "--cxf", "a", "--bitwarden", "b"],
        &["import", "--keepassxc", "a", "--json"],
        &["import", "file.json"],
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
        &["import", "--cxf", fs_, "--yes"],
        &[
            "wrong passphrase 1",
            "wrong passphrase 2",
            "wrong passphrase 3",
        ],
    );
    assert_eq!(r.exit(), Exit::Denied);
    assert!(records(&b, &vb).is_empty());

    let r = run(&b, &["import", "--cxf", fs_, "--yes"], &[PASS]);
    assert!(r.ok().contains("Imported 3 passkeys"));
    assert_eq!(records(&a, &va), records(&b, &vb));

    let r = run(&b, &["import", "--cxf", fs_, "--yes"], &[PASS]);
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
    let r = run(&c, &["import", "--cxf", fs_, "--yes"], &[]);
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
    let r = run(&m, &["import", "--cxf", fs_, "--yes"], &[]);
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

    let r = run(&m, &["import", "--cxf", fs_, "--yes"], &[]);
    assert_eq!(r.exit(), Exit::Partial);
    assert!(r.out.contains("4 passkeys were already in hirz"));

    let out_file = m.tmp.path("short-ids.json");
    let o = out_file.to_str().unwrap();
    let r = run(&m, &["export", "--plain", "--cxf", o], &["yes", "y"]);
    r.ok();
    let c = Machine::new("fixture-c");
    init(&c);
    let r = run(&c, &["import", "--cxf", o, "--yes"], &[]);
    assert!(r.ok().contains("Imported 4 passkeys"), "{}", r.out);
    assert_eq!(
        records(&m, &m.default_vault()),
        records(&c, &c.default_vault())
    );

    let mut long: Value = serde_json::from_str(FIXTURE).unwrap();
    long["accounts"][0]["items"][1]["credentials"][0]["credentialId"] =
        Value::from(hirz_proto::base64url::encode(&[7u8; 1024]));
    let long_file = m.tmp.path("long.json");
    fs::write(&long_file, serde_json::to_vec(&long).unwrap()).unwrap();
    let r = run(
        &c,
        &["import", "--cxf", long_file.to_str().unwrap(), "--yes"],
        &[],
    );
    assert!(
        r.out.contains("(bob): the field credentialId is too long"),
        "{}",
        r.out
    );
    let mut max: Value = serde_json::from_str(FIXTURE).unwrap();
    max["accounts"][0]["items"][1]["credentials"][0]["credentialId"] =
        Value::from(hirz_proto::base64url::encode(&[7u8; 1023]));
    fs::write(&long_file, serde_json::to_vec(&max).unwrap()).unwrap();
    let r = run(
        &c,
        &["import", "--cxf", long_file.to_str().unwrap(), "--yes"],
        &[],
    );
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
    let r = run(&m, &["import", "--cxf", fs_, "--yes"], &[]);
    assert!(r.out.contains("a different passkey with the same id"));
    assert_eq!(
        records(&m, &m.default_vault())[0].private_key_pkcs8,
        recs[0].private_key_pkcs8
    );
}

fn bitwarden_sample() -> (String, Vec<Zeroizing<Vec<u8>>>) {
    use crate::foreign::bitwarden::{fido2_entry, plain_export};
    let keys: Vec<_> = (0..3)
        .map(|_| hirz_crypto::es256::generate().unwrap().0)
        .collect();
    let doc = plain_export(&[
        vec![
            fido2_entry(
                "6c7e3b2a-0d4f-4a8e-9b1c-2f3e4d5a6b7c",
                "example.com",
                "alice",
                "P-256",
                &keys[0],
            ),
            fido2_entry("b64.AQIDBA", "acme.example", "bob", "P-256", &keys[1]),
        ],
        vec![fido2_entry(
            "b64.BQYH",
            "example.org",
            "carol",
            "P-521",
            &keys[2],
        )],
    ]);
    (doc, keys)
}

#[test]
fn import_from_bitwarden() {
    use crate::foreign::bitwarden::{Kdf, protect};
    let m = Machine::new("bitwarden");
    init(&m);
    let (doc, keys) = bitwarden_sample();
    let file = m.tmp.path("bitwarden_export.json");
    fs::write(&file, &doc).unwrap();
    let fs_ = file.to_str().unwrap();
    let r = run(&m, &["import", "--bitwarden", fs_, "--yes"], &[]);
    assert_eq!(r.exit(), Exit::Partial, "{}", r.out);
    assert!(r.out.contains("Imported 2 passkeys"), "{}", r.out);
    assert!(r.out.contains("1 item of other kinds"), "{}", r.out);
    assert!(
        r.out
            .contains("example.org (carol): its key type is ECDSA P-521")
    );
    assert!(!r.out.contains("hunter2") && !r.out.contains("secret note"));
    let recs = records(&m, &m.default_vault());
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0].credential_id, [1, 2, 3, 4]);
    assert_eq!(recs[0].private_key_pkcs8, keys[1]);
    assert_eq!(recs[1].credential_id[..4], [0x6c, 0x7e, 0x3b, 0x2a]);
    assert_eq!(recs[1].private_key_pkcs8, keys[0]);
    assert!(recs.iter().all(|r| r.backup_eligible && r.algorithm == -7));

    let r = run(&m, &["import", "--bitwarden", fs_, "--yes"], &[]);
    assert_eq!(r.exit(), Exit::Partial);
    assert!(
        r.out.contains("2 passkeys were already in hirz"),
        "{}",
        r.out
    );
    assert_eq!(records(&m, &m.default_vault()), recs);

    let c = Machine::new("bitwarden-c");
    init(&c);
    let protected = protect(
        doc.as_bytes(),
        PASS,
        "c2FsdHNhbHRzYWx0c2FsdA==",
        Kdf::Pbkdf2 { iterations: 5_000 },
    );
    fs::write(&file, &protected).unwrap();
    let r = run(
        &c,
        &["import", "--bitwarden", fs_, "--yes"],
        &["wrong", "wrong too", "nope"],
    );
    assert_eq!(r.exit(), Exit::Denied, "{}", r.out);
    assert_eq!(r.prompts.len(), 3);
    assert!(records(&c, &c.default_vault()).is_empty());
    let r = run(
        &c,
        &["import", "--bitwarden", fs_, "--yes"],
        &["wrong", PASS],
    );
    assert_eq!(r.exit(), Exit::Partial, "{}", r.out);
    assert!(r.out.contains("password protected"));
    assert!(r.out.contains("Wrong password"));
    assert!(r.out.contains("Imported 2 passkeys"), "{}", r.out);
    assert_eq!(records(&c, &c.default_vault()), recs);

    let argon = protect(
        doc.as_bytes(),
        PASS,
        "salt",
        Kdf::Argon2id {
            iterations: 2,
            memory_mib: 16,
            parallelism: 1,
        },
    );
    fs::write(&file, argon.replace("\"data\": \"2.", "\"data\": \"2.A")).unwrap();
    let r = run(&c, &["import", "--bitwarden", fs_, "--yes"], &[PASS]);
    assert_eq!(r.exit(), Exit::Failed, "{}", r.out);
    fs::write(&file, &argon).unwrap();
    let r = run(&c, &["import", "--bitwarden", fs_, "--yes"], &[PASS]);
    assert!(
        r.out.contains("2 passkeys were already in hirz"),
        "{}",
        r.out
    );

    let account = r#"{"encrypted": true, "encKeyValidation_DO_NOT_EDIT": "2.a|b|c",
        "folders": [], "items": []}"#;
    fs::write(&file, account).unwrap();
    let r = run(&c, &["import", "--bitwarden", fs_, "--yes"], &[]);
    assert_eq!(r.exit(), Exit::Failed);
    assert!(r.message().contains("account key"), "{}", r.message());
}

#[test]
fn import_from_keepassxc() {
    use crate::foreign::keepassxc::passkey_file;
    let m = Machine::new("keepassxc");
    init(&m);
    let dir = m.tmp.path("passkeys");
    fs::create_dir_all(&dir).unwrap();
    let es = hirz_crypto::es256::generate().unwrap().0;
    let ed = hirz_crypto::ed25519::generate().unwrap().0;
    let one = dir.join("Example.passkey");
    fs::write(
        &one,
        passkey_file("example.com", "alice", &[9; 24], b"u-1", &es),
    )
    .unwrap();
    let r = run(
        &m,
        &["import", "--keepassxc", one.to_str().unwrap(), "--yes"],
        &[],
    );
    assert!(r.ok().contains("Imported 1 passkey"), "{}", r.out);

    fs::write(
        dir.join("Acme.passkey"),
        passkey_file("acme.example", "bob", &[8; 16], b"u-2", &ed),
    )
    .unwrap();
    fs::write(dir.join("broken.passkey"), "{").unwrap();
    fs::write(dir.join("notes.txt"), "ignored").unwrap();
    let r = run(
        &m,
        &["import", "--keepassxc", dir.to_str().unwrap(), "--yes"],
        &[],
    );
    assert_eq!(r.exit(), Exit::Partial, "{}", r.out);
    assert!(r.out.contains("Imported 1 passkey"), "{}", r.out);
    assert!(
        r.out.contains("1 passkey were already in hirz"),
        "{}",
        r.out
    );
    assert!(
        r.out.contains("broken.passkey: The file is not valid JSON"),
        "{}",
        r.out
    );
    let recs = records(&m, &m.default_vault());
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0].credential_id, vec![8; 16]);
    assert_eq!(recs[0].algorithm, -8);
    assert_eq!(recs[1].credential_id, vec![9; 24]);
    assert_eq!(recs[1].user_id, b"u-1");

    let empty = m.tmp.path("empty");
    fs::create_dir_all(&empty).unwrap();
    let r = run(
        &m,
        &["import", "--keepassxc", empty.to_str().unwrap(), "--yes"],
        &[],
    );
    assert_eq!(r.exit(), Exit::Failed);
    let r = run(
        &m,
        &[
            "import",
            "--keepassxc",
            dir.join("notes.txt").to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(r.exit(), Exit::Failed);
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
        let r = run(&m, &["import", "--cxf", fs_, "--yes"], &[]);
        assert_eq!(r.exit(), Exit::Failed, "{content}");
        assert!(r.message().contains(needle), "{content}: {}", r.message());
    }
    let deep = format!(
        "{{\"version\":{{\"major\":1,\"minor\":0}},\"accounts\":{}{}}}",
        "[".repeat(200),
        "]".repeat(200)
    );
    fs::write(&file, deep).unwrap();
    assert_eq!(
        run(&m, &["import", "--cxf", fs_, "--yes"], &[]).exit(),
        Exit::Failed
    );
    fs::write(&file, b"HIRZ-CXF\x09").unwrap();
    let r = run(&m, &["import", "--cxf", fs_, "--yes"], &[]);
    assert_eq!(r.exit(), Exit::Failed);
}

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

    let vault_files = tree(&vault);
    let r = run(&b, &["forget-local"], &["n"]);
    assert_eq!(r.exit(), Exit::Cancelled);
    assert!(b.state().join(hirz_vault::DEVICE_STATE_FILE).exists());
    let r = run(&b, &["forget-local"], &["y"]);
    assert!(r.ok().contains(crate::app::REMOVED));
    assert!(!b.state().join(hirz_vault::DEVICE_STATE_FILE).exists());
    assert!(!b.state().join(hirz_vault::VAULT_POINTER_FILE).exists());
    assert_eq!(tree(&vault), vault_files);
    assert_eq!(run(&b, &["list"], &[]).exit(), Exit::NotSetUp);
    assert!(
        run(&b, &["forget-local"], &[])
            .ok()
            .contains("nothing to forget")
    );
    assert_eq!(records(&a, &vault).len(), 3);
}

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
fn setup_firefox_refuses_when_a_package_installed_the_manifest() {
    let m = Machine::new("ff-pkg");
    let bin = m.env.exe_dir.clone().unwrap();
    fs::create_dir_all(&bin).unwrap();
    let nmh = bin.join("hirz-nmh");
    fs::write(&nmh, b"#!/bin/sh\n").unwrap();
    fs::set_permissions(&nmh, fs::Permissions::from_mode(0o755)).unwrap();
    let user = m.tmp.path(".mozilla/native-messaging-hosts/hirz.json");

    for (dir, body) in [
        (
            "/usr/lib/mozilla/native-messaging-hosts",
            crate::cmd_setup::render_manifest(&fs::canonicalize(&nmh).unwrap()).unwrap(),
        ),
        (
            "/usr/lib64/mozilla/native-messaging-hosts",
            "{}".to_string(),
        ),
    ] {
        let system = m.env.sys_path(dir);
        fs::create_dir_all(&system).unwrap();
        let file = system.join("hirz.json");
        fs::write(&file, body).unwrap();

        let r = run(&m, &["setup", "firefox"], &["y"]);
        assert_eq!(r.exit(), Exit::Failed, "{dir}");
        assert!(r.message().contains("A package already connected"), "{dir}");
        assert!(r.message().contains("setup firefox --force"), "{dir}");
        assert!(r.prompts.is_empty(), "{:?}", r.prompts);
        assert!(!user.exists(), "{dir}: nothing is written without --force");

        let r = run(&m, &["setup", "firefox", "--force"], &[]);
        let out = r.ok();
        assert!(out.contains("Installed"), "{dir}");
        assert!(out.contains("takes precedence over the packaged manifest"));
        assert!(user.exists(), "{dir}");
        fs::remove_file(&user).unwrap();
        fs::remove_file(&file).unwrap();
    }

    let r = run(&m, &["setup", "firefox"], &[]);
    assert!(r.ok().contains("Installed"));
    assert!(!r.out.contains("takes precedence"));
}

fn hide_generation(vault: &Path, number: u32) -> (PathBuf, PathBuf) {
    let prefix = format!("{number:010}-");
    let name = fs::read_dir(vault.join("keys"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .find(|n| n.starts_with(&prefix))
        .unwrap();
    let from = vault.join("keys").join(&name);
    let to = vault.join(format!(".hidden-{name}"));
    fs::rename(&from, &to).unwrap();
    (to, from)
}

fn device_hex(m: &Machine, vault: &Path) -> String {
    crate::ui::hex(&Vault::open(vault, &m.state()).unwrap().device_id())
}

fn uv_run(m: &Machine, sys: &UvSys, args: &[&str], answers: &[&str]) -> Run {
    run_sys(m, sys, args, answers)
}

/// `a` removes `x` and `x` removes `a` from the same parent; `b` follows neither.
fn mutual_removal() -> (Machine, Machine, Machine, PathBuf, String, String) {
    let a = Machine::new("repair-a");
    let phrase = init(&a);
    let vault = a.default_vault();
    let vs = vault.to_str().unwrap().to_string();
    put(&a, &vault, vec![record("example.com", "alice", false, 1)]);
    let x = Machine::new("repair-x");
    let b = Machine::new("repair-b");
    run(
        &x,
        &["join", "--vault", &vs, "--name", "mallory"],
        &[&phrase],
    )
    .ok();
    run(&b, &["join", "--vault", &vs, "--name", "bob"], &[&phrase]).ok();
    let a_id = device_hex(&a, &vault);
    let x_id = device_hex(&x, &vault);
    run(&a, &["remove-device", &x_id[..8]], &["y"]).ok();
    let (hidden, back) = hide_generation(&vault, 2);
    run(&x, &["remove-device", &a_id[..8]], &["y"]).ok();
    fs::rename(&hidden, &back).unwrap();
    (a, x, b, vault, a_id, x_id)
}

#[test]
fn repair_shows_a_conflict_and_discards_a_named_key_change_after_verification() {
    let (_a, _x, b, vault, a_id, x_id) = mutual_removal();
    let a_gen = format!("0000000002-{a_id}");
    let x_gen = format!("0000000002-{x_id}");

    let st = run(&b, &["status"], &[]);
    assert_eq!(st.exit(), Exit::Failed);
    assert!(st.out.contains("hirz repair"), "{}", st.out);

    let out = run(&b, &["repair"], &[]).ok().to_string();
    assert!(
        out.contains("Conflict: two devices removed each other"),
        "{out}"
    );
    assert!(
        out.contains("Key changes this computer does not follow (2)"),
        "{out}"
    );
    assert!(
        out.contains(&format!("{a_gen}  made by \"test-host\"")),
        "{out}"
    );
    assert!(
        out.contains(&format!("{x_gen}  made by \"mallory\"")),
        "{out}"
    );
    assert!(out.contains("repair --discard NAME"));
    assert!(!out.contains("--accept-fork"));

    let uv = UvSys::new(&[UvMethod::Pin], Ok(VERIFIED));
    let r = uv_run(&b, &uv, &["repair", "--discard", "banana"], &[]);
    assert_eq!(r.exit(), Exit::Usage, "{}", r.message());
    let r = uv_run(&b, &uv, &["repair", "--discard", "0000000001-00"], &[]);
    assert_eq!(r.exit(), Exit::Usage);
    let first = fs::read_dir(vault.join("keys"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .find(|n| n.starts_with("0000000001-"))
        .unwrap();
    let r = uv_run(&b, &uv, &["repair", "--discard", &first], &[]);
    assert_eq!(r.exit(), Exit::Failed);
    assert!(r.message().contains("not one of the key changes"));
    let unknown = format!("0000000002-{}", "ab".repeat(16));
    let r = uv_run(&b, &uv, &["repair", "--discard", &unknown], &[]);
    assert_eq!(r.exit(), Exit::Failed);
    assert!(uv.repairs.borrow().is_empty());

    let none = UvSys::new(&[], Ok(VERIFIED));
    let r = uv_run(&b, &none, &["repair", "--discard", &x_gen], &["y"]);
    assert_eq!(r.exit(), Exit::Failed);
    assert!(r.message().contains("hirz pin set"), "{}", r.message());
    assert!(r.prompts.is_empty());
    assert!(none.repairs.borrow().is_empty());

    let r = uv_run(&b, &uv, &["repair", "--discard", &x_gen], &["n"]);
    assert_eq!(r.exit(), Exit::Cancelled);
    assert!(
        r.prompts
            .iter()
            .any(|p| p.starts_with("Delete this key change now?"))
    );
    assert!(
        uv.repairs.borrow().is_empty(),
        "no window before the terminal question"
    );
    assert!(vault.join("keys").join(&x_gen).is_dir());

    for (result, exit, needle) in [
        (
            Err(ApprovalError::Denied),
            Exit::Cancelled,
            "Nothing was deleted.",
        ),
        (
            Err(ApprovalError::Unavailable),
            Exit::Failed,
            "hirz pin set",
        ),
        (
            Err(ApprovalError::Timeout),
            Exit::Failed,
            "not answered in time",
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
        let refusing = UvSys::new(&[UvMethod::Pin], result);
        let r = uv_run(&b, &refusing, &["repair", "--discard", &x_gen], &["y"]);
        assert_eq!(r.exit(), exit, "{}", r.message());
        assert!(r.message().contains(needle), "{}", r.message());
        assert!(r.out.contains("Confirm in the hirz window"));
        assert_eq!(
            refusing.repairs.borrow().as_slice(),
            [format!("discard {x_gen}")]
        );
        assert!(
            vault.join("keys").join(&x_gen).is_dir(),
            "a refused window deletes nothing"
        );
    }

    let r = uv_run(&b, &uv, &["repair", "--discard", &x_gen], &["y"]);
    let out = r.ok().to_string();
    assert_eq!(uv.repairs.borrow().as_slice(), [format!("discard {x_gen}")]);
    assert!(
        out.contains(&format!("Deleted the key change {x_gen}.")),
        "{out}"
    );
    assert!(out.contains("reports no fork and no conflict now"), "{out}");
    assert!(!vault.join("keys").join(&x_gen).exists());
    assert!(vault.join("keys").join(&a_gen).is_dir());
    assert_eq!(run(&b, &["status"], &[]).exit(), Exit::Ok);
    run(&b, &["list"], &[]).ok();
}

#[test]
fn repair_discard_with_yes_skips_only_the_terminal_question() {
    let (_a, _x, b, vault, _a_id, x_id) = mutual_removal();
    let x_gen = format!("0000000002-{x_id}");
    let uv = UvSys::new(&[UvMethod::Pin], Ok(VERIFIED));
    let r = uv_run(&b, &uv, &["repair", "--discard", &x_gen, "--yes"], &[]);
    r.ok();
    assert!(r.prompts.is_empty());
    assert_eq!(uv.repairs.borrow().len(), 1);
    assert!(!vault.join("keys").join(&x_gen).exists());
}

#[test]
fn repair_accepts_a_fork_only_after_a_typed_word_and_verification() {
    let a = Machine::new("fork-a");
    let phrase = init(&a);
    let vault = a.default_vault();
    let vs = vault.to_str().unwrap().to_string();
    put(&a, &vault, vec![record("example.com", "alice", false, 1)]);
    let c = Machine::new("fork-c");
    run(&c, &["join", "--vault", &vs, "--name", "old"], &[&phrase]).ok();
    let c_id = device_hex(&c, &vault);

    let uv = UvSys::new(&[UvMethod::Pin], Ok(VERIFIED));
    let healthy = uv_run(&a, &uv, &["repair"], &[]).ok().to_string();
    assert!(healthy.contains("Nothing to repair"), "{healthy}");
    let r = uv_run(&a, &uv, &["repair", "--accept-fork"], &["follow"]);
    assert_eq!(r.exit(), Exit::Failed);
    assert!(r.message().contains("does not report a fork"));
    assert!(uv.repairs.borrow().is_empty());

    run(&a, &["remove-device", &c_id[..8]], &["y"]).ok();
    hide_generation(&vault, 2);

    let st = run(&a, &["status"], &[]);
    assert_eq!(st.exit(), Exit::Failed);
    assert!(
        st.out.contains("no longer holds the key changes"),
        "{}",
        st.out
    );
    assert!(st.out.contains("hirz repair"), "{}", st.out);
    let r = run(&a, &["delete", "0101", "--yes"], &[]);
    assert_eq!(r.exit(), Exit::Failed);
    assert!(r.message().contains("hirz repair"), "{}", r.message());
    assert!(r.message().contains("no longer holds the key changes"));
    assert!(run(&a, &["list"], &[]).ok().contains("example.com"));

    let shown = uv_run(&a, &uv, &["repair"], &[]).ok().to_string();
    assert!(
        shown.contains("Fork: the vault folder no longer holds"),
        "{shown}"
    );
    assert!(shown.contains("repair --accept-fork"), "{shown}");

    let r = uv_run(&a, &uv, &["repair", "--accept-fork"], &["no"]);
    assert_eq!(r.exit(), Exit::Cancelled);
    assert!(
        r.prompts
            .iter()
            .any(|p| p.contains("Type follow to continue"))
    );
    assert!(uv.repairs.borrow().is_empty());

    for result in [
        Err(ApprovalError::Denied),
        Err(ApprovalError::Unavailable),
        Ok(Approval {
            user_present: true,
            user_verified: false,
            selected: None,
        }),
    ] {
        let refusing = UvSys::new(&[UvMethod::Pin], result);
        let r = uv_run(&a, &refusing, &["repair", "--accept-fork"], &["follow"]);
        assert_ne!(r.exit(), Exit::Ok);
        assert_eq!(refusing.repairs.borrow().as_slice(), ["accept-fork"]);
        assert_eq!(
            run(&a, &["status"], &[]).exit(),
            Exit::Failed,
            "a refused window leaves the fork reported"
        );
    }

    let r = uv_run(&a, &uv, &["repair", "--accept-fork"], &["follow"]);
    let out = r.ok().to_string();
    assert_eq!(uv.repairs.borrow().as_slice(), ["accept-fork"]);
    assert!(
        out.contains("follows the vault folder as it is now"),
        "{out}"
    );
    assert!(out.contains("1 passkey"), "{out}");
    assert!(out.contains("reports no fork and no conflict now"), "{out}");
    assert!(!run(&a, &["status"], &[]).out.contains("no longer holds"));
}

#[test]
fn repair_refuses_a_removed_device_and_needs_a_vault() {
    let m = Machine::new("repair-none");
    let r = run(&m, &["repair"], &[]);
    assert_eq!(r.exit(), Exit::NotSetUp);

    let a = Machine::new("repair-rm-a");
    let phrase = init(&a);
    let vault = a.default_vault();
    let vs = vault.to_str().unwrap().to_string();
    let b = Machine::new("repair-rm-b");
    run(&b, &["join", "--vault", &vs, "--name", "old"], &[&phrase]).ok();
    let b_id = device_hex(&b, &vault);
    run(&a, &["remove-device", &b_id[..8]], &["y"]).ok();
    for args in [
        &["repair"][..],
        &["repair", "--accept-fork"],
        &[
            "repair",
            "--discard",
            "0000000002-00000000000000000000000000000000",
        ],
    ] {
        let r = run(&b, args, &["follow", "y"]);
        assert_eq!(r.exit(), Exit::Failed, "{args:?}");
        assert!(
            r.message().starts_with(crate::app::REMOVED),
            "{}",
            r.message()
        );
    }
}

#[test]
fn vault_errors_for_a_fork_and_a_removed_device_are_plain() {
    use hirz_vault::VaultError;
    let fork = CliError::from(VaultError::Fork);
    assert_eq!(fork.exit, Exit::Failed);
    assert!(fork.message.contains("hirz repair"), "{}", fork.message);
    assert!(!fork.message.contains("Vault error"));
    let removed = CliError::from(VaultError::Removed);
    assert_eq!(removed.exit, Exit::Failed);
    assert!(removed.message.starts_with(crate::app::REMOVED));
}

#[test]
fn devices_show_who_approved_each_device() {
    let a = Machine::new("by-a");
    let phrase = init(&a);
    let vault = a.default_vault();
    let vs = vault.to_str().unwrap().to_string();
    let b = Machine::new("by-b");
    let c = Machine::new("by-c");
    run(
        &c,
        &["join", "--vault", &vs, "--name", "phrase-joined"],
        &[&phrase],
    )
    .ok();
    let approved = RefCell::new(false);
    let sys = PairSys::new(2, |n| {
        if n == 1 {
            run(&a, &["devices", "approve"], &["yes", "yes"]).ok();
            *approved.borrow_mut() = true;
        }
    });
    join_request(&b, &vs, &sys).ok();
    assert!(*approved.borrow());

    let out = run(&a, &["devices"], &[]).ok().to_string();
    let header = out.lines().next().unwrap();
    assert!(header.contains("ADDED BY"), "{out}");
    let row = |name: &str| {
        out.lines()
            .find(|l| l.starts_with(name))
            .unwrap()
            .to_string()
    };
    assert!(row("phrase-joined").contains("recovery phrase"), "{out}");
    assert!(row("test-host").contains("recovery phrase"), "{out}");
    assert!(row("desk").contains("test-host"), "{out}");

    let json: Value = serde_json::from_str(run(&a, &["devices", "--json"], &[]).ok()).unwrap();
    let a_id = device_hex(&a, &vault);
    let by = |name: &str| {
        json.as_array()
            .unwrap()
            .iter()
            .find(|d| d["name"] == name)
            .unwrap()["added_by"]
            .clone()
    };
    assert_eq!(by("desk"), Value::String(a_id));
    assert_eq!(by("phrase-joined"), Value::Null);
    assert_eq!(by("test-host"), Value::Null);
}

#[test]
fn a_cut_short_request_list_says_how_many_were_not_listed() {
    let a = Machine::new("hidden-a");
    init(&a);
    let vault = a.default_vault();
    let planted = hirz_vault::MAX_LISTED_REQUESTS + 3;
    let tmp = Tmp::new("hidden-states");
    for i in 0..planted {
        hirz_vault::PendingJoin::start(&vault, &tmp.path(&format!("s{i}")), &format!("dev {i}"))
            .unwrap();
    }
    let out = run(&a, &["devices"], &[]).ok().to_string();
    assert!(
        out.contains(&format!(
            "{} devices waiting for approval",
            hirz_vault::MAX_LISTED_REQUESTS
        )),
        "{out}"
    );
    assert!(out.contains("3 requests more not listed"), "{out}");
    assert!(out.contains("planting them"), "{out}");

    let uv = UvSys::new(&[UvMethod::Pin], Ok(VERIFIED));
    let r = approve_with(&a, &uv, &["1", "no"]);
    assert!(r.out.contains("3 requests more not listed"), "{}", r.out);
    assert!(uv.seen.borrow().is_empty());

    // Answering no removed the request that was picked, so one more became visible.
    let r = run(&a, &["devices", "deny", "ffff"], &[]);
    assert_eq!(r.exit(), Exit::Failed);
    assert!(
        r.message()
            .contains("2 waiting requests not listed may match"),
        "{}",
        r.message()
    );
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
        &["import", "--bitwarden", "x"],
        &["import", "--keepassxc", "x"],
    ] {
        assert_eq!(run(&m, args, &[]).exit(), Exit::NotSetUp, "{args:?}");
    }
}

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
    assert!(r.notices.is_empty());
    let enter = "\x1b[?1049h";
    let clear = "\x1b[2J\x1b[3J\x1b[H\x1b[?1049l";
    let shown_at = out.find("YOUR RECOVERY PHRASE").unwrap();
    let entered_at = out.find(enter).expect("alternate screen entered");
    let cleared_at = out.find(clear).expect("screen wiped and left");
    assert!(entered_at < shown_at && shown_at < cleared_at);
    assert_eq!(out.matches(enter).count(), 1);
    let after = &out[cleared_at + clear.len()..];
    let words = phrase_words(out);
    // Phrase words are common English words, so look for the numbered layout of the phrase.
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

    let m2 = Machine::new("noclear");
    let r2 = run(&m2, &["init"], &[]);
    let out = r2.ok().to_string();
    assert!(!out.contains(clear) && !out.contains(enter));
    assert_eq!(r2.notices.len(), 1);
    assert!(r2.notices[0].contains("not a terminal"), "{:?}", r2.notices);
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
    assert!(!r.ok().contains(clear) && !r.out.contains(enter));
    assert!(r.notices.is_empty());
}

/// The clock advances on every poll and `on_sleep` runs while the joining command waits (the user at the other device).
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
            let r = run(&a, &["devices", "approve"], &["yes", "yes"]);
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

struct UvSys {
    methods: Vec<UvMethod>,
    result: Result<Approval, ApprovalError>,
    seen: RefCell<Vec<SeenPairing>>,
    removals: RefCell<Vec<(String, String)>>,
    exports: RefCell<Vec<(usize, bool)>>,
    repairs: RefCell<Vec<String>>,
}

impl UvSys {
    fn new(methods: &[UvMethod], result: Result<Approval, ApprovalError>) -> Self {
        UvSys {
            methods: methods.to_vec(),
            result,
            seen: RefCell::new(Vec::new()),
            removals: RefCell::new(Vec::new()),
            exports: RefCell::new(Vec::new()),
            repairs: RefCell::new(Vec::new()),
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
            exports: Some(&self.exports),
            repairs: Some(&self.repairs),
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
            let r = approve_with(&a, &uv, &["yes", "yes"]);
            assert_eq!(r.exit(), exit, "{}", r.message());
            assert!(r.message().contains(needle), "{}", r.message());
            assert!(r.out.contains("Confirm in the hirz window"));
            assert_eq!(uv.seen.borrow().len(), 1);
            assert_eq!(waiting(), 1, "a refused verification keeps the request");
        }

        let ok = UvSys::new(&[UvMethod::Pin], Ok(VERIFIED));
        let r = approve_with(&a, &ok, &["yes", "yes"]);
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

const ENTER_SCREEN: &str = "\x1b[?1049h";
const LEAVE_SCREEN: &str = "\x1b[2J\x1b[3J\x1b[H\x1b[?1049l";

fn terminal_opts(wrong_words: bool) -> Opts<'static> {
    Opts {
        sys: &FakeSys,
        program: "hirz",
        terminal: true,
        wrong_words,
    }
}

#[test]
fn the_phrase_screen_is_left_when_the_check_fails() {
    let m = Machine::new("screen-fail");
    let r = run_opts(&m, &["init"], &[], terminal_opts(true));
    assert_eq!(r.exit(), Exit::Cancelled);
    assert!(r.message().contains("not confirmed"));
    let enter = r.out.find(ENTER_SCREEN).unwrap();
    let phrase = r.out.rfind("Here is the phrase again").unwrap();
    let leave = r.out.rfind(LEAVE_SCREEN).unwrap();
    assert!(enter < phrase && phrase < leave, "{}", r.out);
    assert!(!r.out[leave..].contains("RECOVERY PHRASE"));
    assert_eq!(r.out.matches(ENTER_SCREEN).count(), 1);
}

#[test]
fn the_phrase_is_shown_before_a_step_that_can_fail() {
    let m = Machine::new("phrase-first");
    fs::create_dir_all(
        m.state()
            .join(hirz_vault::VAULT_POINTER_FILE)
            .join("blocker"),
    )
    .unwrap();
    fs::set_permissions(m.state(), fs::Permissions::from_mode(0o700)).unwrap();
    let r = run(&m, &["init", "--yes-i-saved-it"], &[]);
    assert_eq!(r.exit(), Exit::Failed, "{}", r.out);
    assert!(r.message().contains("Could not record the vault location"));
    assert!(r.message().contains("recovery phrase shown is valid"));
    assert_eq!(phrase_words(&r.out).len(), 24);
    assert!(m.default_vault().join(hirz_vault::HEADER_FILE).is_file());
}

#[test]
fn hirz_vault_and_hirz_state_move_the_cli_like_the_daemons() {
    let home = Tmp::new("envvars");
    let vault = home.path("elsewhere/vault");
    let state = home.path("elsewhere/state");
    let h = home.0.clone();
    let vars = |extra: &'static [(&'static str, &'static str)]| {
        let h = h.clone();
        let vault = vault.clone();
        let state = state.clone();
        move |k: &str| -> Option<OsString> {
            let extra_value = extra.iter().find(|(n, _)| *n == k).map(|(_, v)| *v);
            match (k, extra_value) {
                ("HIRZ_VAULT", Some("set")) => Some(vault.clone().into_os_string()),
                ("HIRZ_STATE", Some("set")) => Some(state.clone().into_os_string()),
                ("HIRZ_VAULT" | "HIRZ_STATE", Some(other)) => Some(OsString::from(other)),
                ("HOME", _) => Some(h.clone().into_os_string()),
                _ => None,
            }
        }
    };
    let plain = Env::from_vars(vars(&[])).unwrap();
    assert_eq!(plain.state_dir(), h.join(".local/state/hirz"));
    assert_eq!(plain.vault_dir(None).unwrap(), plain.default_vault());

    let set = Env::from_vars(vars(&[("HIRZ_VAULT", "set"), ("HIRZ_STATE", "set")])).unwrap();
    assert_eq!(set.state_dir(), state);
    assert_eq!(set.uv.state_dir, state);
    assert_eq!(set.vault_dir(None).unwrap(), vault);
    assert_eq!(set.new_vault_dir(None).unwrap(), vault);
    let flag = h.join("flag");
    assert_eq!(set.vault_dir(Some(&flag)).unwrap(), flag);
    assert_eq!(set.new_vault_dir(Some(&flag)).unwrap(), flag);

    let relative =
        Env::from_vars(vars(&[("HIRZ_VAULT", "rel/vault"), ("HIRZ_STATE", "")])).unwrap();
    assert_eq!(relative.state_dir(), h.join(".local/state/hirz"));
    assert_eq!(relative.vault_dir(None).unwrap(), relative.default_vault());

    let mut env = set;
    env.root = h.join("root");
    env.cwd = Some(h.clone());
    let m = Machine { tmp: home, env };
    let r = run(&m, &["init", "--yes-i-saved-it"], &[]);
    r.ok();
    assert!(vault.join(hirz_vault::HEADER_FILE).is_file());
    assert!(state.join(hirz_vault::DEVICE_STATE_FILE).is_file());
    assert!(!m.default_vault().exists());
    put(&m, &vault, vec![record("example.com", "alice", false, 1)]);
    assert!(run(&m, &["list"], &[]).ok().contains("example.com"));
    let st = run(&m, &["status", "--json"], &[]);
    let v: Value = serde_json::from_str(&st.out).unwrap();
    assert_eq!(v["vault_dir"], vault.display().to_string());
    assert_eq!(v["state_dir"], state.display().to_string());
    assert_eq!(v["vault"]["passkeys"], 1);
}

#[test]
fn json_output_never_carries_raw_terminal_controls() {
    let m = Machine::new("json-controls");
    init(&m);
    let mut r = record("example.com", "ali\u{9b}31mce\u{7f}", false, 1);
    r.rp_name = Some("Evil\u{202e}Site\u{85}".into());
    put(&m, &m.default_vault(), vec![r]);
    let out = run(&m, &["list", "--json"], &[]);
    let text = out.ok();
    assert!(
        text.chars()
            .all(|c| !('\u{7f}'..='\u{9f}').contains(&c) && c != '\u{202e}'),
        "{text}"
    );
    assert!(text.contains("\\u009b") && text.contains("\\u007f") && text.contains("\\u202e"));
    let v: Value = serde_json::from_str(text).unwrap();
    assert_eq!(v[0]["user_name"], "ali\u{9b}31mce\u{7f}");
    assert_eq!(v[0]["site_name"], "Evil\u{202e}Site\u{85}");
}

fn two_look_alikes(m: &Machine) {
    let (mut a, mut b) = (
        record("example.com", "alice", false, 1),
        record("example.com", "alice", false, 2),
    );
    a.credential_id = [vec![0x11; 10], vec![0xaa; 22]].concat();
    b.credential_id = [vec![0x11; 10], vec![0xbb; 22]].concat();
    put(m, &m.default_vault(), vec![a, b]);
}

#[test]
fn ambiguous_delete_prints_enough_of_each_id_to_type() {
    let m = Machine::new("delete-digits");
    init(&m);
    two_look_alikes(&m);
    let r = run(&m, &["delete", "1111"], &[]);
    assert_eq!(r.exit(), Exit::Usage);
    assert!(r.message().contains("longer id prefix from the list above"));
    let ids: Vec<&str> = r
        .out
        .lines()
        .skip(1)
        .filter_map(|l| l.split_whitespace().last())
        .collect();
    assert_eq!(ids.len(), 2, "{}", r.out);
    assert_ne!(ids[0], ids[1]);
    assert!(ids[0].len() > 12 && ids[0].len() == ids[1].len(), "{ids:?}");
    let r = run(&m, &["delete", ids[0], "--yes"], &[]);
    r.ok();
    assert_eq!(records(&m, &m.default_vault()).len(), 1);
}

#[test]
fn approving_by_prefix_still_warns_that_several_devices_wait() {
    let a = Machine::new("several-a");
    init(&a);
    let vault = a.default_vault();
    let vs = vault.to_str().unwrap().to_string();
    let (b, c) = (Machine::new("several-b"), Machine::new("several-c"));
    let seen = RefCell::new(String::new());
    let outer = PairSys::new(60, |n| {
        if n != 1 {
            return;
        }
        let inner = PairSys::new(60, |m| {
            if m != 1 {
                return;
            }
            let reqs: Vec<String> = pairing_dir_files(&vault)
                .into_iter()
                .filter(|f| f.ends_with(".req"))
                .collect();
            assert_eq!(reqs.len(), 2);
            let r = run(&a, &["devices", "approve", &reqs[0][..8]], &["yes", "yes"]);
            *seen.borrow_mut() = r.out.clone();
            assert_eq!(r.exit(), Exit::Ok, "{}", r.out);
        });
        join_request(&c, &vs, &inner);
    });
    join_request(&b, &vs, &outer);
    let out = seen.borrow().clone();
    assert!(out.contains("Several devices are waiting"), "{out}");
    assert!(out.contains("hirz devices deny REQUEST"));
    let (table, rest) = out.split_once("A new device asked to join").unwrap();
    assert!(table.contains("WORDS"), "{table}");
    assert!(!table.contains("NAME"), "{table}");
    assert!(
        !table.contains("desk"),
        "no name before the words were confirmed: {table}"
    );
    let rows: Vec<&str> = table
        .lines()
        .filter(|l| l.starts_with(|c: char| c.is_ascii_digit()))
        .collect();
    assert_eq!(rows.len(), 2, "{table}");
    for row in rows {
        let words: Vec<&str> = row.split_whitespace().skip(1).take(4).collect();
        assert!(
            words
                .iter()
                .all(|w| w.chars().all(|c| c.is_ascii_uppercase())),
            "four words in capitals after the number: {row}"
        );
    }
    assert!(rest.contains("[desk]"));
    assert!(out.contains("Approved \"desk\""));
}

#[test]
fn the_name_of_a_device_is_shown_only_after_the_words_matched() {
    let a = Machine::new("name-late-a");
    init(&a);
    let vault = a.default_vault();
    let vs = vault.to_str().unwrap().to_string();
    let b = Machine::new("name-late-b");
    let seen = RefCell::new(Vec::new());
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

        // The words do not match: the name never reaches the screen.
        let r = run(&a, &["devices", "approve"], &["no"]);
        assert_eq!(r.exit(), Exit::Cancelled, "{}", r.out);
        assert!(!r.out.contains("desk"), "{}", r.out);
        assert!(!r.out.contains("calls itself"), "{}", r.out);
        assert_eq!(waiting(), 0, "a refused comparison removes the request");
        seen.borrow_mut().push(r.out);
    });
    let _ = join_request(&b, &vs, &sys);
    assert_eq!(seen.borrow().len(), 1);
}

#[test]
fn a_name_that_is_not_the_one_the_person_gave_is_refused_before_any_verification() {
    let a = Machine::new("name-no-a");
    init(&a);
    let vault = a.default_vault();
    let vs = vault.to_str().unwrap().to_string();
    let b = Machine::new("name-no-b");
    let seen = RefCell::new(Vec::new());
    let sys = PairSys::new(2, |n| {
        if n != 1 {
            return;
        }
        let uv = UvSys::new(&[UvMethod::Polkit], Ok(VERIFIED));
        let r = approve_with(&a, &uv, &["yes", "no"]);
        assert_eq!(r.exit(), Exit::Cancelled, "{}", r.out);
        assert!(
            uv.seen.borrow().is_empty(),
            "no verification window was opened"
        );
        assert!(r.out.contains("calls itself"), "{}", r.out);
        assert_eq!(
            pairing_dir_files(&vault)
                .iter()
                .filter(|f| f.ends_with(".req"))
                .count(),
            0
        );
        seen.borrow_mut().push(r.out);
    });
    let _ = join_request(&b, &vs, &sys);
    assert_eq!(seen.borrow().len(), 1);
}

#[test]
fn export_requires_user_verification_before_anything_is_built() {
    let m = Machine::new("export-uv");
    init(&m);
    put(
        &m,
        &m.default_vault(),
        vec![
            record("example.com", "alice", false, 1),
            record("example.org", "bob", true, 2),
        ],
    );
    let file = m.tmp.path("out.hirz");
    let fs_ = file.to_str().unwrap();
    assert!(args::parse(&os(&["export", "--cxf", fs_, "--yes"])).is_err());

    let none = UvSys::new(&[], Ok(VERIFIED));
    let r = run_sys(&m, &none, &["export", "--cxf", fs_], &[]);
    assert_eq!(r.exit(), Exit::Failed);
    assert!(r.message().contains("hirz pin set"), "{}", r.message());
    assert!(r.message().contains("Exporting your passkeys needs"));
    assert!(r.prompts.is_empty());
    assert!(none.exports.borrow().is_empty());
    assert!(!file.exists());

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
        for plain in [false, true] {
            let uv = UvSys::new(&[UvMethod::Pin], result.clone());
            let mut args = vec!["export", "--cxf", fs_];
            let answers: &[&str] = if plain {
                args.push("--plain");
                &["yes"]
            } else {
                &[PASS, PASS]
            };
            let r = run_sys(&m, &uv, &args, answers);
            assert_eq!(r.exit(), exit, "{}", r.message());
            assert!(r.message().contains(needle), "{}", r.message());
            assert!(r.message().contains("No file was written."));
            assert!(r.out.contains("Confirm in the hirz window"));
            assert_eq!(uv.exports.borrow().as_slice(), [(2, plain)]);
            assert!(!file.exists(), "a refused verification writes nothing");
        }
    }

    let ok = UvSys::new(&[UvMethod::Fingerprint], Ok(VERIFIED));
    let r = run_sys(&m, &ok, &["export", "--cxf", fs_], &[PASS, PASS, "n"]);
    assert!(r.ok().contains("Saved 2 passkeys"));
    assert_eq!(ok.exports.borrow().as_slice(), [(2, false)]);
    assert!(fs::read(&file).unwrap().starts_with(b"HIRZ-CXF"));
}

#[test]
fn export_import_and_pin_reset_refuse_a_removed_device() {
    let a = Machine::new("removed-a");
    let phrase = init(&a);
    let vault = a.default_vault();
    let vs = vault.to_str().unwrap().to_string();
    put(&a, &vault, vec![record("example.com", "alice", false, 1)]);
    let b = Machine::new("removed-b");
    run(&b, &["join", "--vault", &vs, "--name", "old"], &[&phrase]).ok();
    run(&b, &["pin", "set"], &["1234", "1234"]).ok();
    let b_id = crate::ui::hex(&Vault::open(&vault, &b.state()).unwrap().device_id());
    run(&a, &["remove-device", &b_id[..8]], &["y"]).ok();

    let export = b.tmp.path("export.hirz");
    let plain_export = b.tmp.path("plain.json");
    let shared = a.tmp.path("shared.json");
    let r = run(
        &a,
        &["export", "--plain", "--cxf", shared.to_str().unwrap()],
        &["yes", "y"],
    );
    r.ok();
    let files = tree(&vault);
    for args in [
        vec!["export", "--cxf", export.to_str().unwrap()],
        vec!["export", "--plain", "--cxf", plain_export.to_str().unwrap()],
        vec!["import", "--cxf", shared.to_str().unwrap(), "--yes"],
        vec!["import", "--bitwarden", shared.to_str().unwrap(), "--yes"],
        vec!["import", "--keepassxc", shared.to_str().unwrap(), "--yes"],
    ] {
        let r = run(&b, &args, &[PASS, PASS, "yes"]);
        assert_eq!(r.exit(), Exit::Failed, "{args:?}");
        assert!(
            r.message().starts_with(crate::app::REMOVED),
            "{}",
            r.message()
        );
        assert!(r.message().contains("hirz forget-local"));
        assert!(r.prompts.is_empty(), "{:?}", r.prompts);
        assert!(r.out.is_empty(), "{}", r.out);
    }
    assert!(!export.exists() && !plain_export.exists());
    assert_eq!(tree(&vault), files);

    let r = run(&b, &["pin", "reset"], &[&phrase]);
    assert_eq!(r.exit(), Exit::Failed);
    assert!(r.message().starts_with(crate::app::REMOVED));
    assert!(!r.prompts.iter().any(|p| p.contains("Recovery phrase")));
    assert!(run(&b, &["pin", "status"], &[]).ok().contains("is set"));

    run(&b, &["forget-local"], &["y"]).ok();
    let r = run(&b, &["pin", "reset"], &["y"]);
    assert!(r.ok().contains("The PIN was removed."));
}

#[test]
fn import_lists_what_it_adds_and_asks_first() {
    let m = Machine::new("preview");
    init(&m);
    let vault = m.default_vault();
    let mut mine = record("example.com", "alice", false, 9);
    mine.user_id = b"user-alice-0001".to_vec();
    put(&m, &vault, vec![mine]);
    let file = m.tmp.path("provider.json");
    fs::write(&file, FIXTURE).unwrap();
    let fs_ = file.to_str().unwrap();

    for answer in ["n", "", "maybe"] {
        let r = run(&m, &["import", "--cxf", fs_], &[answer]);
        assert_eq!(r.exit(), Exit::Cancelled, "{}", r.out);
        assert!(r.message().contains("Nothing was imported"));
        assert!(r.out.contains("Passkeys to add: 4"), "{}", r.out);
        assert!(r.out.contains("SITE"), "{}", r.out);
        assert!(r.out.contains("login.example.org"));
        assert!(r.out.contains("acme.example"));
        assert!(
            r.out
                .contains("Warning: example.com (alice): hirz already has a passkey")
        );
        assert!(!r.out.contains("Imported"));
        assert_eq!(records(&m, &vault).len(), 1);
    }
    assert_eq!(
        run(&m, &["import", "--cxf", fs_], &[]).exit(),
        Exit::Cancelled
    );
    assert_eq!(records(&m, &vault).len(), 1);

    let r = run(&m, &["import", "--cxf", fs_], &["y"]);
    assert_eq!(r.exit(), Exit::Partial, "{}", r.out);
    assert!(
        r.prompts
            .iter()
            .any(|p| p.starts_with("Add 4 passkeys to hirz?"))
    );
    assert!(r.out.contains("Imported 4 passkeys"));
    assert_eq!(records(&m, &vault).len(), 5);

    let other = Machine::new("preview-yes");
    init(&other);
    let r = run(&other, &["import", "--cxf", fs_, "--yes"], &[]);
    assert!(r.prompts.is_empty());
    assert!(r.out.contains("Passkeys to add: 4"));
    assert!(r.out.contains("Imported 4 passkeys"));
    assert!(!r.out.contains("Warning: example.com"));
}

#[test]
fn import_asks_nothing_when_nothing_would_be_added() {
    let m = Machine::new("preview-none");
    init(&m);
    let file = m.tmp.path("provider.json");
    fs::write(&file, FIXTURE).unwrap();
    let fs_ = file.to_str().unwrap();
    run(&m, &["import", "--cxf", fs_, "--yes"], &[]);
    let r = run(&m, &["import", "--cxf", fs_], &[]);
    assert_eq!(r.exit(), Exit::Partial);
    assert!(r.prompts.is_empty());
    assert!(!r.out.contains("Passkeys to add"));
    assert!(r.out.contains("4 passkeys were already in hirz"));
}

#[test]
fn imported_creation_times_never_come_from_the_future() {
    let m = Machine::new("future");
    init(&m);
    let file = m.tmp.path("future.json");
    fs::write(&file, FIXTURE.replace("1700000000", "4102444800")).unwrap();
    let before = crate::ui::now();
    run(
        &m,
        &["import", "--cxf", file.to_str().unwrap(), "--yes"],
        &[],
    );
    let after = crate::ui::now();
    let all = records(&m, &m.default_vault());
    assert!(!all.is_empty());
    assert!(all.iter().all(|r| r.created_at <= after));
    let alice = all
        .iter()
        .find(|r| r.user_name.as_deref() == Some("alice"))
        .unwrap();
    assert!(alice.created_at >= before);
}

#[test]
fn export_and_import_round_trip_ssh_keys_and_other_site_ids() {
    let a = Machine::new("ssh-a");
    init(&a);
    let va = a.default_vault();
    let sites = [
        "ssh:",
        "ssh:Work Key",
        "example.com",
        "Mixed.Case",
        "io.example.app",
    ];
    let mut recs: Vec<CredentialRecord> = sites
        .iter()
        .zip(1u8..)
        .map(|(rp, seed)| record(rp, "alice", seed % 2 == 0, seed))
        .collect();
    recs.push(record("caf\u{e9}.example", "zoe", false, 9));
    put(&a, &va, recs);

    let file = a.tmp.path("ssh.hirz");
    let fs_ = file.to_str().unwrap();
    let r = run(&a, &["export", "--cxf", fs_], &[PASS, PASS, "n"]);
    let out = r.ok();
    assert!(out.contains("Saved 6 passkeys"));
    assert!(
        out.contains("Warning: some passkeys have a site id"),
        "{out}"
    );
    assert!(out.contains("caf"), "{out}");

    let b = Machine::new("ssh-b");
    init(&b);
    let r = run(&b, &["import", "--cxf", fs_, "--yes"], &[PASS]);
    assert_eq!(r.exit(), Exit::Partial, "{}", r.out);
    assert!(r.out.contains("Imported 5 passkeys"), "{}", r.out);
    assert!(r.out.contains("Skipped 1 passkey"));
    assert!(
        r.out
            .contains("its site id is not text hirz can keep as it is")
    );
    let got = records(&b, &b.default_vault());
    let want: Vec<CredentialRecord> = records(&a, &va)
        .into_iter()
        .filter(|r| r.rp_id != "caf\u{e9}.example")
        .collect();
    assert_eq!(got, want);
    assert!(got.iter().any(|r| r.rp_id == "ssh:Work Key"));
    assert!(got.iter().any(|r| r.rp_id == "ssh:"));
    assert!(got.iter().any(|r| r.rp_id == "Mixed.Case"));
}

#[test]
fn unreadable_names_from_an_imported_folder_never_reach_the_terminal() {
    let m = Machine::new("kpxc-names");
    init(&m);
    let dir = m.tmp.path("keys");
    fs::create_dir_all(&dir).unwrap();
    let name = "x\u{1b}]0;owned\u{7}\u{1b}[2J\u{9b}31m.passkey";
    let bad = dir.join(name);
    fs::write(&bad, b"{}").unwrap();
    fs::set_permissions(&bad, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::File::open(&bad).is_ok() {
        return;
    }
    let r = run(
        &m,
        &["import", "--keepassxc", dir.to_str().unwrap(), "--yes"],
        &[],
    );
    assert_eq!(r.exit(), Exit::Partial, "{}", r.out);
    assert!(r.out.contains("Could not open"), "{}", r.out);
    assert!(
        r.out
            .chars()
            .all(|c| c == '\n' || !c.is_control() && !('\u{80}'..='\u{9f}').contains(&c)),
        "{:?}",
        r.out
    );
    let r = run(
        &m,
        &["import", "--keepassxc", bad.to_str().unwrap(), "--yes"],
        &[],
    );
    assert_eq!(r.exit(), Exit::Failed);
    assert!(r.message().contains("Could not open"));
    assert!(
        r.message()
            .chars()
            .all(|c| !c.is_control() && !('\u{80}'..='\u{9f}').contains(&c))
    );
}

#[test]
fn remove_device_lists_the_devices_it_approved_and_devices_flags_shared_names() {
    let a = Machine::new("rest-a");
    let r = run(&a, &["init", "--name", "laptop", "--yes-i-saved-it"], &[]);
    let out = r.ok();
    let phrase = phrase_words(out).join(" ");
    let vault = a.default_vault();
    let vs = vault.to_str().unwrap().to_string();
    let b = Machine::new("rest-b");
    run(
        &b,
        &["join", "--vault", &vs, "--name", "helper"],
        &[&phrase],
    )
    .ok();
    let y = Machine::new("rest-y");
    let pending = hirz_vault::PendingJoin::start(&vault, &y.state(), "laptop").unwrap();
    let mut bv = Vault::open(&vault, &b.state()).unwrap();
    let req = bv
        .pairing_requests()
        .unwrap()
        .into_iter()
        .find(|r| r.request_id == pending.request().request_id)
        .unwrap();
    bv.approve_pairing(&req).unwrap();
    let y_id = match pending.poll(&y.state()).unwrap() {
        hirz_vault::PairingPoll::Joined(v) => crate::ui::hex(&v.device_id()),
        other => panic!("{other:?}"),
    };
    let b_id = crate::ui::hex(&bv.device_id());

    let out = run(&a, &["devices"], &[]).ok().to_string();
    assert_eq!(out.matches("laptop (*)").count(), 2, "{out}");
    assert!(
        out.contains("Another device in use has the same name"),
        "{out}"
    );
    let r = run(&a, &["devices", "--json"], &[]);
    let v: Value = serde_json::from_str(&r.out).unwrap();
    let shared = v
        .as_array()
        .unwrap()
        .iter()
        .filter(|d| d["same_name_as_another"] == true)
        .count();
    assert_eq!(shared, 2);

    let r = run(&a, &["remove-device", &b_id[..8]], &["n"]);
    assert_eq!(r.exit(), Exit::Cancelled);
    assert!(
        r.out
            .contains("WARNING: 1 device in use was added through \"helper\""),
        "{}",
        r.out
    );
    assert!(r.out.contains(&y_id[..12]), "{}", r.out);
    let out = run(&a, &["remove-device", &b_id[..8]], &["y"])
        .ok()
        .to_string();
    assert!(
        out.contains("Still in use, added through \"helper\""),
        "{out}"
    );
    let out = run(&a, &["devices"], &[]).ok().to_string();
    assert!(out.contains("2 devices in use"), "{out}");
}
