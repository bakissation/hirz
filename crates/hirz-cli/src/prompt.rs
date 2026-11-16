//! Questions to the user. Everything interactive goes through [`Prompter`] so tests can
//! script the answers.

use crate::error::{CliError, CliResult};
use hirz_crypto::Zeroizing;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::process::{Command, Stdio};

/// Longest line accepted from the terminal.
const MAX_LINE: u64 = 4096;

pub trait Prompter {
    /// Shows `prompt` and reads one line without the line break. `None` at end of input.
    fn line(&mut self, prompt: &str) -> io::Result<Option<String>>;
    /// Like `line`, but hides the typed text when the terminal allows it.
    fn secret(&mut self, prompt: &str) -> io::Result<Option<Zeroizing<String>>>;
}

/// Asks a yes/no question. Only "y" or "yes" count as yes; end of input is no.
pub fn confirm(p: &mut dyn Prompter, question: &str) -> CliResult<bool> {
    let answer = p
        .line(&format!("{question} [y/N] "))
        .map_err(|e| CliError::io("Could not read your answer", &e))?;
    Ok(matches!(
        answer.as_deref().map(|a| a.trim().to_ascii_lowercase()),
        Some(a) if a == "y" || a == "yes"
    ))
}

/// Asks the user to type an exact word to go on (for steps that are hard to undo).
pub fn confirm_word(p: &mut dyn Prompter, question: &str, word: &str) -> CliResult<bool> {
    let answer = p
        .line(&format!("{question} Type {word} to continue: "))
        .map_err(|e| CliError::io("Could not read your answer", &e))?;
    Ok(answer.as_deref().map(str::trim) == Some(word))
}

pub fn read_secret(p: &mut dyn Prompter, prompt: &str) -> CliResult<Zeroizing<String>> {
    match p.secret(prompt) {
        Ok(Some(s)) => Ok(s),
        Ok(None) => Err(CliError::cancelled("No input. Nothing was changed.")),
        Err(e) => Err(CliError::io("Could not read your input", &e)),
    }
}

pub fn read_line(p: &mut dyn Prompter, prompt: &str) -> CliResult<String> {
    match p.line(prompt) {
        Ok(Some(s)) => Ok(s),
        Ok(None) => Err(CliError::cancelled("No input. Nothing was changed.")),
        Err(e) => Err(CliError::io("Could not read your input", &e)),
    }
}

/// Reads from the process's terminal. Prompts go to standard error so standard output stays
/// clean for scripts.
#[derive(Debug, Default)]
pub struct TerminalPrompter {
    warned_visible: bool,
}

impl TerminalPrompter {
    pub fn new() -> Self {
        Self::default()
    }

    fn read_raw(&mut self) -> io::Result<Option<Zeroizing<String>>> {
        let mut buf = Zeroizing::new(Vec::new());
        let stdin = io::stdin();
        let mut lock = stdin.lock().take(MAX_LINE.saturating_add(1));
        let n = lock.read_until(b'\n', &mut buf)?;
        if n == 0 {
            return Ok(None);
        }
        if buf.last() == Some(&b'\n') {
            buf.pop();
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
        } else if u64::try_from(buf.len()).unwrap_or(u64::MAX) > MAX_LINE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
        let text = String::from_utf8(core::mem::take(&mut *buf))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "input is not UTF-8"))?;
        Ok(Some(Zeroizing::new(text)))
    }
}

fn show(prompt: &str) {
    let mut e = io::stderr();
    let _ = e.write_all(prompt.as_bytes());
    let _ = e.flush();
}

/// Terminal echo control through `stty` from a root-owned system directory. The standard
/// library has no termios API and `unsafe` is not allowed outside hirz-sys.
struct EchoOff {
    stty: std::path::PathBuf,
    saved: String,
}

impl EchoOff {
    fn start() -> Option<EchoOff> {
        if !io::stdin().is_terminal() {
            return None;
        }
        let stty = hirz_uv::runner::resolve_tool("stty")?;
        let out = Command::new(&stty)
            .arg("-g")
            .stdin(Stdio::inherit())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let saved = String::from_utf8(out.stdout).ok()?.trim().to_string();
        if saved.is_empty()
            || saved.len() > 1024
            || !saved
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b':')
        {
            return None;
        }
        let ok = Command::new(&stty)
            .arg("-echo")
            .stdin(Stdio::inherit())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        ok.then_some(EchoOff { stty, saved })
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        let restored = Command::new(&self.stty)
            .arg(&self.saved)
            .stdin(Stdio::inherit())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        show("\n");
        if !restored {
            show("hirz: could not turn typing display back on. Type `reset` and press Enter.\n");
        }
    }
}

impl Prompter for TerminalPrompter {
    fn line(&mut self, prompt: &str) -> io::Result<Option<String>> {
        show(prompt);
        Ok(self.read_raw()?.map(|s| s.to_string()))
    }

    fn secret(&mut self, prompt: &str) -> io::Result<Option<Zeroizing<String>>> {
        let echo = EchoOff::start();
        if echo.is_none() && !self.warned_visible && io::stdin().is_terminal() {
            show("Note: this terminal cannot hide what you type, so it will be visible.\n");
            self.warned_visible = true;
        }
        show(prompt);
        let r = self.read_raw();
        drop(echo);
        r
    }
}
