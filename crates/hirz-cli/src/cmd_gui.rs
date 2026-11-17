//! `hirz init --gui`: the first-run setup in zenity windows. hirzd and hirz-nmh start it when an
//! app asks for a passkey and there is no vault (docs/approval.md, "Setting up hirz"). It creates
//! the vault exactly as `hirz init` does; the recovery phrase reaches its window only through
//! zenity's standard input.

use crate::app::Ctx;
use crate::cmd_vault::{
    PHRASE_WORDS, QUIZ_ROUNDS, QUIZ_WORDS, create_vault, init_target, random_positions,
    word_matches,
};
use crate::error::{CliError, CliResult, Exit};
use crate::ui::path_text;
use hirz_crypto::Zeroizing;
use hirz_uv::first_run;
use hirz_uv::runner::{
    CommandRunner, CommandSpec, EnvPolicy, MAX_INPUT, MIN_ZENITY_MAJOR, RunResult, SystemRunner,
    Tool,
};
use std::path::Path;
use std::time::Duration;

const TITLE: &str = "hirz: set up passkeys";
const WINDOW_SECONDS: u64 = 900;
const LOCK_TRIES: usize = 5;
/// Keeps the phrase window's text far below [`MAX_INPUT`] whatever the folder is called.
const MAX_SHOWN_PATH: usize = 300;
const WINDOW_GRACE: Duration = Duration::from_secs(5);
pub const JOIN_LABEL: &str = "I already use hirz on another computer";
pub const SET_UP_LABEL: &str = "Set up";
const CANCEL_LABEL: &str = "Cancel";
const WELCOME: &str = "hirz keeps your passkeys in an encrypted folder that you can sync between \
computers.\nIt is not set up on this computer yet. Set it up to create and use passkeys here.";
/// There is no window for joining yet, so this one keeps the single command that starts it.
const JOIN_TEXT: &str = "To use the vault you already have on another computer:\n\n\
1. Sync the vault folder to this computer and wait until it is copied.\n\n\
2. Open a terminal here and run this, with FOLDER the synced folder:\n\
hirz join --vault FOLDER --request\n\n\
It shows four words and tells you how to approve this computer on the other one.";
const CHECKBOX: &str = "I wrote down all 24 words";
const FIREFOX_TEXT: &str = "Firefox is installed without the hirz extension. With it, \
websites in Firefox use hirz directly.\n\nOpen its page on addons.mozilla.org? Click \
\"Add to Firefox\" there.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Welcome {
    SetUp,
    Join,
    Cancel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shown {
    Confirmed,
    Cancelled,
    /// The window could not be shown; says why.
    Failed(String),
}

/// The windows of the setup. Only [`Windows::phrase`] ever receives the recovery phrase.
pub trait Windows {
    /// Can windows be drawn at all; says why not.
    fn check(&mut self) -> Result<(), String>;
    fn welcome(&mut self) -> Welcome;
    fn info(&mut self, text: &str);
    fn error(&mut self, text: &str);
    fn question(&mut self, text: &str, ok: &str, cancel: &str) -> bool;
    /// Shows `text` (the phrase and its warnings) until the user confirms they wrote it down.
    fn phrase(&mut self, text: &[u8]) -> Shown;
    /// Asks for word `number` (1 to 24). `None` when cancelled.
    fn word(&mut self, number: usize) -> Option<Zeroizing<String>>;
}

fn timeout_arg() -> String {
    format!("--timeout={WINDOW_SECONDS}")
}

/// `--switch` replaces zenity's own Yes and No with the buttons given, in that order (zenity 4
/// `msg.c`). The long join label makes libadwaita stack them, and a stacked dialog shows the last
/// one on top (`adw-message-dialog.c`, compact allocation): Set up first, Cancel last. Side by
/// side they read Cancel, join, Set up, the order GNOME puts the main action in. With `--switch`
/// there is no default button, so Enter alone chooses nothing.
pub fn welcome_args() -> Vec<String> {
    vec![
        "--question".to_owned(),
        "--switch".to_owned(),
        "--no-markup".to_owned(),
        format!("--title={TITLE}"),
        format!("--text={WELCOME}"),
        format!("--extra-button={CANCEL_LABEL}"),
        format!("--extra-button={JOIN_LABEL}"),
        format!("--extra-button={SET_UP_LABEL}"),
        "--width=460".to_owned(),
        timeout_arg(),
    ]
}

/// `kind` is `--info` or `--error`.
pub fn message_args(kind: &str, text: &str) -> Vec<String> {
    vec![
        kind.to_owned(),
        "--no-markup".to_owned(),
        format!("--title={TITLE}"),
        format!("--text={text}"),
        "--width=520".to_owned(),
        timeout_arg(),
    ]
}

pub fn question_args(text: &str, ok: &str, cancel: &str) -> Vec<String> {
    vec![
        "--question".to_owned(),
        "--no-markup".to_owned(),
        format!("--title={TITLE}"),
        format!("--text={text}"),
        format!("--ok-label={ok}"),
        format!("--cancel-label={cancel}"),
        "--width=520".to_owned(),
        timeout_arg(),
    ]
}

/// Takes no text: the phrase goes to standard input. `--text-info` shows plain text, and OK only
/// works once the box is ticked.
pub fn phrase_args() -> Vec<String> {
    vec![
        "--text-info".to_owned(),
        format!("--title={TITLE}"),
        "--font=Monospace".to_owned(),
        format!("--checkbox={CHECKBOX}"),
        "--ok-label=Next".to_owned(),
        "--cancel-label=Cancel".to_owned(),
        "--width=680".to_owned(),
        "--height=600".to_owned(),
        timeout_arg(),
    ]
}

/// The entry text is read with mnemonics (docs/approval.md, "zenity 4 behaviour hirz relies on");
/// it holds no `_`.
pub fn word_args(number: usize) -> Vec<String> {
    vec![
        "--entry".to_owned(),
        "--hide-text".to_owned(),
        "--no-markup".to_owned(),
        format!("--title={TITLE}"),
        format!("--text=To check, type word {number} of your recovery phrase."),
        "--ok-label=Check".to_owned(),
        "--cancel-label=Cancel".to_owned(),
        "--width=460".to_owned(),
        timeout_arg(),
    ]
}

#[derive(Debug, Default)]
pub struct ZenityWindows<R = SystemRunner> {
    runner: R,
}

impl ZenityWindows<SystemRunner> {
    pub fn new() -> Self {
        ZenityWindows {
            runner: SystemRunner,
        }
    }
}

impl<R: CommandRunner> ZenityWindows<R> {
    #[cfg(test)]
    pub fn with_runner(runner: R) -> Self {
        ZenityWindows { runner }
    }

    fn spec(&self, mut args: Vec<String>) -> CommandSpec {
        if let Some(icon) = self
            .runner
            .window_icon()
            .and_then(|p| p.to_str().map(str::to_owned))
        {
            let at = usize::from(!args.is_empty());
            args.insert(at, format!("--window-icon={icon}"));
        }
        CommandSpec {
            tool: Tool::Zenity,
            args,
            env: EnvPolicy::Desktop,
            timeout: Duration::from_secs(WINDOW_SECONDS).saturating_add(WINDOW_GRACE),
        }
    }

    fn show(&self, kind: &str, args: Vec<String>) -> RunResult {
        let started = std::time::Instant::now();
        let r = self.runner.run(&self.spec(args));
        log_window(kind, &r, started.elapsed());
        r
    }
}

/// One line per window on standard error (the journal when the daemons started the setup): the
/// kind of window, how it ended and how long it was open. Never any text, words or input.
fn log_window(kind: &str, r: &RunResult, open: Duration) {
    let how = match r {
        RunResult::Exited {
            code: Some(c),
            stderr,
            ..
        } => format!("exit status {c}, {} bytes on standard error", stderr.len()),
        RunResult::Exited { code: None, .. } => "ended by a signal".to_owned(),
        RunResult::TimedOut => "timed out".to_owned(),
        RunResult::NotFound => "zenity not found".to_owned(),
        RunResult::Failed(why) => format!("failed: {why}"),
    };
    eprintln!(
        "hirz: setup window {kind}: {how}, open {} ms",
        open.as_millis()
    );
}

fn exit_code(r: &RunResult) -> Option<i32> {
    match r {
        RunResult::Exited { code, .. } => *code,
        _ => None,
    }
}

impl<R: CommandRunner> Windows for ZenityWindows<R> {
    fn check(&mut self) -> Result<(), String> {
        if !self.runner.tool_available(Tool::Zenity) {
            return Err(format!(
                "zenity was not found in a trusted system directory ({}); install zenity \
                 {MIN_ZENITY_MAJOR} or newer, or run `hirz init` in a terminal",
                hirz_uv::runner::TRUSTED_DIRS.join(", ")
            ));
        }
        match self.runner.zenity_major_version() {
            Some(v) if v < MIN_ZENITY_MAJOR => Err(format!(
                "zenity {v} is too old: the setup windows need zenity {MIN_ZENITY_MAJOR} or \
                 newer; run `hirz init` in a terminal instead"
            )),
            _ => Ok(()),
        }
    }

    fn welcome(&mut self) -> Welcome {
        match self.show("welcome", welcome_args()) {
            RunResult::Exited {
                code: Some(0 | 1),
                stdout,
                ..
            } => match hirz_uv::display::strip_entry_newline(&stdout) {
                b if b == SET_UP_LABEL.as_bytes() => Welcome::SetUp,
                b if b == JOIN_LABEL.as_bytes() => Welcome::Join,
                _ => Welcome::Cancel,
            },
            _ => Welcome::Cancel,
        }
    }

    fn info(&mut self, text: &str) {
        self.show("info", message_args("--info", text));
    }

    fn error(&mut self, text: &str) {
        self.show("error", message_args("--error", text));
    }

    fn question(&mut self, text: &str, ok: &str, cancel: &str) -> bool {
        exit_code(&self.show("question", question_args(text, ok, cancel))) == Some(0)
    }

    fn phrase(&mut self, text: &[u8]) -> Shown {
        let started = std::time::Instant::now();
        let r = self.runner.run_with_input(&self.spec(phrase_args()), text);
        log_window("phrase", &r, started.elapsed());
        match r {
            RunResult::Exited { code: Some(0), .. } => Shown::Confirmed,
            RunResult::Exited {
                code: Some(1 | 5), ..
            }
            | RunResult::TimedOut => Shown::Cancelled,
            RunResult::Exited { code, .. } => {
                Shown::Failed(format!("The window ended unexpectedly (status {code:?})."))
            }
            RunResult::NotFound => Shown::Failed("zenity was not found.".into()),
            RunResult::Failed(why) => Shown::Failed(format!("The window failed: {why}.")),
        }
    }

    fn word(&mut self, number: usize) -> Option<Zeroizing<String>> {
        match self.show("word", word_args(number)) {
            RunResult::Exited {
                code: Some(0),
                stdout,
                ..
            } => {
                let typed = hirz_uv::display::strip_entry_newline(&stdout);
                core::str::from_utf8(typed)
                    .ok()
                    .map(|t| Zeroizing::new(t.to_owned()))
            }
            _ => None,
        }
    }
}

/// The text of the phrase window: the same content and warnings as the terminal screen of
/// `hirz init`, the words numbered in a grid of four columns. Built in a buffer of fixed capacity
/// that is wiped on drop and never grows, so no copy of the phrase is left behind.
pub fn phrase_text(
    dir: &Path,
    name: &str,
    words: &[&str],
    again: Option<usize>,
) -> CliResult<Zeroizing<String>> {
    let mut t = Zeroizing::new(String::with_capacity(MAX_INPUT));
    let capacity = t.capacity();
    // One line per paragraph and bullet: the window wraps them to its width. Only the word grid
    // has fixed lines, and it fits the window in the monospace font.
    if let Some(n) = again {
        t.push_str(&format!(
            "That is not word {n}. Here is the phrase again. Check what you wrote down.\n\n"
        ));
    }
    t.push_str(&format!(
        "Your new vault is ready in {}.\nThis computer is called \"{name}\".\n\n\
         YOUR RECOVERY PHRASE (shown only this once):\n\n",
        crate::ui::clean(&path_text(dir), MAX_SHOWN_PATH)
    ));
    for (row, chunk) in words.chunks(4).enumerate() {
        t.push(' ');
        for (col, w) in chunk.iter().enumerate() {
            let n = row.saturating_mul(4).saturating_add(col).saturating_add(1);
            t.push(' ');
            if n < 10 {
                t.push(' ');
            }
            t.push_str(&n.to_string());
            t.push_str(". ");
            t.push_str(w);
            if col.saturating_add(1) < chunk.len() {
                for _ in w.chars().count()..10 {
                    t.push(' ');
                }
            }
        }
        t.push('\n');
    }
    t.push_str(
        "\nDo not copy, paste or screenshot this window.\n\n\
         Write these 24 words on paper, in this order, and keep the paper somewhere safe.\n\n\
         - If you lose every device that uses this vault, this phrase and a copy of the vault \
         folder are the only way to get your passkeys back.\n\
         - You also need it to add another computer.\n\
         - Anyone with the phrase and a copy of the folder can use your passkeys. Do not keep it \
         in a photo, an email or a chat.\n\
         - hirz does not keep a copy and cannot show it again.\n",
    );
    if t.len() > MAX_INPUT || t.capacity() != capacity {
        return Err(CliError::failed(
            "Internal error: the recovery phrase window text is too long.",
        ));
    }
    Ok(t)
}

/// Windows speak plainly: commands belong to the documentation and the terminal.
pub fn done_text(dir: &Path) -> String {
    format!(
        "hirz is set up.\n\nYour vault folder is:\n{}\n\n\
         Your passkeys are only on this computer for now. To keep them safe, sync this folder to \
         another computer and set hirz up there with \"{JOIN_LABEL}\".",
        path_text(dir)
    )
}

/// The plain version of a reason `init` refuses to start.
fn target_error(ctx: &Ctx<'_>, e: CliError) -> CliError {
    let Ok(dir) = ctx.env.new_vault_dir(ctx.vault_flag.as_deref()) else {
        return e;
    };
    let d = path_text(&dir);
    let plain = if ctx.env.device_state_exists() {
        "hirz is already set up on this computer.".to_owned()
    } else if hirz_vault::Vault::exists(&dir) {
        format!(
            "The folder {d} already holds a hirz vault. To use it here, choose \
             \"{JOIN_LABEL}\" and follow the steps."
        )
    } else if dir.exists() && !dir.is_dir() {
        format!("{d} is a file, so hirz cannot create its vault folder there.")
    } else if std::fs::read_dir(&dir).is_ok_and(|mut r| r.next().is_some()) {
        format!("The folder {d} is not empty, so hirz cannot create its vault there.")
    } else {
        return e;
    };
    CliError::new(e.exit, plain)
}

/// The vault exists but nobody has its phrase, and hirz could not take it back.
fn kept_text(ctx: &Ctx<'_>, dir: &Path, what: &str) -> String {
    format!(
        "{what}\n\nThe vault in {} was created and works, but nobody has its recovery phrase. \
         If you have no passkeys in it yet, delete that folder and the files in {}; hirz then \
         offers to set itself up again.",
        path_text(dir),
        path_text(ctx.env.state_dir())
    )
}

fn not_recorded_text(dir: &Path, why: &str) -> String {
    format!(
        "hirz could not note where your vault is ({why}).\n\nThe vault exists in {} and the \
         recovery phrase you wrote down is valid. The hirz documentation explains how to finish \
         the setup.",
        path_text(dir)
    )
}

fn cancelled_now(ctx: &Ctx<'_>, runtime: &Path) {
    let _ = first_run::mark_cancelled(runtime, ctx.sys.now());
}

/// Takes back the vault this run created; false (and a line on standard error) when hirz must not.
fn roll_back(made: &Result<crate::rollback::Created, String>) -> bool {
    let result = match made {
        Ok(created) => created.roll_back(),
        Err(why) => Err(why.clone()),
    };
    match result {
        Ok(()) => true,
        Err(why) => {
            eprintln!("hirz: the new vault was kept: {why}");
            false
        }
    }
}

fn rolled_back_text(what: &str) -> String {
    format!(
        "{what}\nhirz is not set up: the new vault was deleted, since nobody has its recovery \
         phrase. Set hirz up again when you have time to write the phrase down."
    )
}

fn shown_info(w: &mut dyn Windows, e: CliError) -> CliError {
    w.info(&e.message);
    e
}

/// Shows `e` in a window and returns it.
fn shown(w: &mut dyn Windows, e: CliError) -> CliError {
    w.error(&e.message);
    e
}

/// A cancel, the join answer and an unconfirmed phrase end with status 0: the windows already said
/// what happened, and the transient unit the setup runs in must not be marked as failed. Errors
/// keep their status.
pub fn init_gui(ctx: &mut Ctx<'_>, name: Option<String>, w: &mut dyn Windows) -> CliResult<Exit> {
    match setup(ctx, name, w) {
        Err(e) if e.exit == Exit::Cancelled => {
            let _ = ctx.say(&e.message);
            Ok(Exit::Ok)
        }
        other => other,
    }
}

fn setup(ctx: &mut Ctx<'_>, name: Option<String>, w: &mut dyn Windows) -> CliResult<Exit> {
    let runtime = ctx.env.runtime_dir.clone().ok_or_else(|| {
        CliError::failed(
            "XDG_RUNTIME_DIR is not set, so hirz cannot make sure only one setup window is open. \
             Run `hirz init` in a terminal instead.",
        )
    })?;
    let lock = setup_lock(&runtime)?;
    first_run::take_waiter_gone(&runtime);
    w.check().map_err(CliError::failed)?;

    let (dir, name) = init_target(ctx, name).map_err(|e| shown(w, target_error(ctx, e)))?;
    match w.welcome() {
        Welcome::SetUp => {}
        Welcome::Join => {
            cancelled_now(ctx, &runtime);
            w.info(JOIN_TEXT);
            return Ok(Exit::Ok);
        }
        Welcome::Cancel => {
            cancelled_now(ctx, &runtime);
            return Err(CliError::cancelled(
                "Setup cancelled. Nothing was created. Run `hirz init` when you want to set up \
                 hirz.",
            ));
        }
    }

    let before = crate::rollback::before(&dir, ctx.env.state_dir());
    let phrase = create_vault(ctx, &dir, &name).map_err(|e| shown(w, target_error(ctx, e)))?;
    let made = before
        .and_then(|b| crate::rollback::created(&dir, ctx.env.state_dir(), b))
        .map_err(|e| e.to_string());
    let phrase_words = phrase.to_words();
    drop(phrase);
    let words: Vec<&str> = phrase_words.split(' ').collect();
    if words.len() != PHRASE_WORDS {
        return Err(shown(
            w,
            CliError::failed("Internal error: recovery phrase length."),
        ));
    }

    let mut recorded = None;
    let mut confirmed = false;
    let mut wrong = None;
    'rounds: for _ in 0..QUIZ_ROUNDS {
        let text = phrase_text(&dir, &name, &words, wrong)?;
        let result = w.phrase(text.as_bytes());
        drop(text);
        if let Shown::Failed(why) = result {
            if roll_back(&made) {
                cancelled_now(ctx, &runtime);
                return Err(shown(w, CliError::cancelled(rolled_back_text(&why))));
            }
            return Err(shown(
                w,
                CliError::failed(kept_text(
                    ctx,
                    &dir,
                    &format!("The recovery phrase could not be shown. {why}"),
                )),
            ));
        }
        if recorded.is_none() {
            recorded = Some(ctx.env.record_vault_dir(&dir));
        }
        if result == Shown::Cancelled {
            break;
        }
        for pos in random_positions(QUIZ_WORDS)? {
            let Some(word) = words.get(pos) else {
                return Err(CliError::failed("Internal error: word position."));
            };
            let number = pos.saturating_add(1);
            let Some(typed) = w.word(number) else {
                break 'rounds;
            };
            if !word_matches(&typed, word) {
                wrong = Some(number);
                continue 'rounds;
            }
        }
        confirmed = true;
        break;
    }
    drop(words);
    drop(phrase_words);

    if !confirmed {
        if roll_back(&made) {
            cancelled_now(ctx, &runtime);
            return Err(shown_info(
                w,
                CliError::cancelled(rolled_back_text("The recovery phrase was not confirmed.")),
            ));
        }
        if let Some(Err(e)) = recorded {
            return Err(shown(
                w,
                CliError::failed(not_recorded_text(&dir, &e.message)),
            ));
        }
        return Err(shown(
            w,
            CliError::cancelled(kept_text(
                ctx,
                &dir,
                "The recovery phrase was not confirmed.",
            )),
        ));
    }
    if let Some(Err(e)) = recorded {
        return Err(shown(
            w,
            CliError::failed(not_recorded_text(&dir, &e.message)),
        ));
    }

    if crate::firefox::addon_state(ctx.env) == crate::firefox::AddonState::Missing
        && w.question(FIREFOX_TEXT, "Open the page", "Not now")
        && !ctx.sys.open_url(first_run::ADDON_PAGE)
    {
        w.info(&format!(
            "Could not open a browser. Open this page in Firefox and click \"Add to \
             Firefox\":\n{}",
            first_run::ADDON_PAGE
        ));
    }
    first_run::clear_cancelled(&runtime);
    w.info(&done_text(&dir));
    // The window is closed only now. With the lock released, a waiting request sees that setup
    // ended and goes on instead of giving up, so a note found after this is final and is never
    // missed, however late the request gave up.
    drop(lock);
    if first_run::take_waiter_gone(&runtime) {
        ctx.sys.notify(first_run::READY_NOTICE);
        eprintln!("hirz: setup done; a request stopped waiting, so the ready notice was sent");
    }
    Ok(Exit::Ok)
}

/// The daemons look at the lock while they wait for this window, taking it for an instant each
/// time, so a lock that is taken is tried a few more times before another window is assumed.
fn setup_lock(runtime: &Path) -> CliResult<first_run::SetupLock> {
    for _ in 0..LOCK_TRIES {
        if let Some(lock) = first_run::try_lock(runtime)
            .map_err(|e| CliError::io("Could not create the setup window's lock", &e))?
        {
            return Ok(lock);
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    Err(CliError::failed("A hirz setup window is already open."))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn every_window_is_plain_text_with_the_hirz_title() {
        let all = [
            welcome_args(),
            message_args("--info", "x"),
            message_args("--error", "x"),
            question_args("x", "Yes", "No"),
            phrase_args(),
            word_args(7),
        ];
        for args in &all {
            assert!(args.contains(&format!("--title={TITLE}")), "{args:?}");
            assert!(args.iter().any(|a| a.starts_with("--timeout=")));
            if args[0] != "--text-info" {
                assert!(args.contains(&"--no-markup".to_owned()), "{args:?}");
            }
            assert!(
                args.iter().all(|a| a.starts_with("--")),
                "every value is passed as --option=value: {args:?}"
            );
        }
        assert!(!word_args(7).iter().any(|a| a.contains('_')));
    }

    #[test]
    fn the_welcome_window_has_only_its_three_buttons_set_up_on_top() {
        let a = welcome_args();
        assert!(a.contains(&"--switch".to_owned()));
        let buttons: Vec<&str> = a
            .iter()
            .filter_map(|x| x.strip_prefix("--extra-button="))
            .collect();
        assert_eq!(buttons, [CANCEL_LABEL, JOIN_LABEL, SET_UP_LABEL]);
        assert!(!a.iter().any(|x| x.starts_with("--ok-label")));
    }

    #[test]
    fn the_phrase_grid_numbers_every_word() {
        let words: Vec<String> = (1..=24).map(|i| format!("word{i}")).collect();
        let refs: Vec<&str> = words.iter().map(String::as_str).collect();
        let t = phrase_text(Path::new("/v"), "laptop", &refs, None).unwrap();
        for (i, w) in refs.iter().enumerate() {
            assert!(t.contains(&format!("{}. {w}", i + 1)), "{}", t.as_str());
        }
        assert!(t.contains(" 1. word1       2. word2"));
        assert!(t.contains("Do not copy, paste or screenshot"));
        assert!(t.contains("hirz does not keep a copy"));
        assert!(!t.contains("That is not word"));
        let again = phrase_text(Path::new("/v"), "laptop", &refs, Some(5)).unwrap();
        assert!(again.starts_with("That is not word 5."));
    }
}
