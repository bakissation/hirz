//! Questions to the user. Everything interactive goes through [`Prompter`] so tests can
//! script the answers.

use crate::error::{CliError, CliResult};
use hirz_crypto::{Zeroize, Zeroizing};
use std::io::{self, IsTerminal, Write};
use std::os::fd::AsFd;

const MAX_LINE: usize = 4096;

pub trait Prompter {
    /// Shows `prompt` and reads one line without the line break. `None` at end of input.
    fn line(&mut self, prompt: &str) -> io::Result<Option<String>>;
    fn secret(&mut self, prompt: &str) -> io::Result<Option<Zeroizing<String>>>;
    /// A warning for the person at the terminal; standard error, so standard output stays clean.
    fn notice(&mut self, text: &str) {
        show(text);
    }
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
        read_line_from(&mut hirz_sys::read_stdin)
    }
}

/// One line, read a byte at a time from `read` into a buffer that never grows, so no copy of a
/// typed secret is left behind in memory that is freed without being wiped, and nothing after the
/// line is consumed. Standard input is not read through the standard library, whose buffer would
/// keep everything typed. `None` at end of input before any byte.
fn read_line_from(
    read: &mut dyn FnMut(&mut [u8]) -> io::Result<usize>,
) -> io::Result<Option<Zeroizing<String>>> {
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_LINE.saturating_add(1)));
    let mut byte = Zeroizing::new([0u8; 1]);
    let mut ended = false;
    loop {
        if read(&mut *byte)? == 0 {
            ended = true;
            break;
        }
        let [b] = *byte;
        match b {
            b'\n' => break,
            b => {
                if buf.len() >= MAX_LINE {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
                }
                buf.push(b);
            }
        }
    }
    if ended && buf.is_empty() {
        return Ok(None);
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    if core::str::from_utf8(&buf).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "input is not UTF-8",
        ));
    }
    match String::from_utf8(core::mem::take(&mut *buf)) {
        Ok(text) => Ok(Some(Zeroizing::new(text))),
        Err(e) => {
            let mut bytes = e.into_bytes();
            bytes.zeroize();
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "input is not UTF-8",
            ))
        }
    }
}

fn show(prompt: &str) {
    let mut e = io::stderr();
    let _ = e.write_all(prompt.as_bytes());
    let _ = e.flush();
}

/// Echo off on standard input while a secret is typed; it comes back on when this is dropped and
/// when Ctrl-C or another signal ends the process (hirz-sys, `EchoOff`).
fn hide_typing() -> Option<hirz_sys::EchoOff> {
    hirz_sys::EchoOff::start(io::stdin().as_fd()).ok()
}

pub const NOTE_TERMINAL: &str =
    "Note: this terminal cannot hide what you type, so it will be visible.";
pub const NOTE_NOT_TERMINAL: &str =
    "Note: standard input is not a terminal, so hirz cannot hide this input.";

pub fn visibility_note(echo_off: bool, stdin_is_terminal: bool) -> Option<&'static str> {
    match (echo_off, stdin_is_terminal) {
        (true, _) => None,
        (false, true) => Some(NOTE_TERMINAL),
        (false, false) => Some(NOTE_NOT_TERMINAL),
    }
}

impl Prompter for TerminalPrompter {
    fn line(&mut self, prompt: &str) -> io::Result<Option<String>> {
        show(prompt);
        Ok(self.read_raw()?.map(|mut text| core::mem::take(&mut *text)))
    }

    fn secret(&mut self, prompt: &str) -> io::Result<Option<Zeroizing<String>>> {
        let echo = hide_typing();
        if !self.warned_visible
            && let Some(note) = visibility_note(echo.is_some(), io::stdin().is_terminal())
        {
            show(note);
            show("\n");
            self.warned_visible = true;
        }
        show(prompt);
        let r = self.read_raw();
        let hid = echo.as_ref().is_some_and(hirz_sys::EchoOff::turned_off);
        drop(echo);
        if hid {
            show("\n");
        }
        r
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    /// A reader that hands out one byte per call and counts what it gave.
    struct Source<'a> {
        data: &'a [u8],
        taken: usize,
        calls: usize,
        sizes: Vec<usize>,
    }

    impl<'a> Source<'a> {
        fn new(data: &'a [u8]) -> Self {
            Source {
                data,
                taken: 0,
                calls: 0,
                sizes: Vec::new(),
            }
        }

        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.calls += 1;
            self.sizes.push(buf.len());
            match self.data.get(self.taken) {
                Some(b) => {
                    buf[0] = *b;
                    self.taken += 1;
                    Ok(1)
                }
                None => Ok(0),
            }
        }
    }

    fn line(data: &[u8]) -> (io::Result<Option<Zeroizing<String>>>, usize) {
        let mut source = Source::new(data);
        let r = read_line_from(&mut |buf| source.read(buf));
        (r, source.taken)
    }

    #[test]
    fn a_line_is_read_a_byte_at_a_time_and_nothing_after_it_is_taken() {
        let (r, taken) = line(b"first\nsecond\n");
        assert_eq!(r.unwrap().unwrap().as_str(), "first");
        assert_eq!(taken, 6, "the second line is still on standard input");
        let (r, _) = line(b"with crlf\r\nnext");
        assert_eq!(r.unwrap().unwrap().as_str(), "with crlf");
        let (r, taken) = line(b"no newline");
        assert_eq!(r.unwrap().unwrap().as_str(), "no newline");
        assert_eq!(taken, 10);
        assert!(line(b"").0.unwrap().is_none());
        assert_eq!(line(b"\n").0.unwrap().unwrap().as_str(), "");

        let mut source = Source::new(b"pin\n");
        let _ = read_line_from(&mut |buf| source.read(buf));
        assert!(source.sizes.iter().all(|n| *n == 1), "{:?}", source.sizes);
    }

    #[test]
    fn long_and_malformed_lines_are_refused() {
        let mut long = vec![b'a'; MAX_LINE];
        long.push(b'\n');
        assert_eq!(line(&long).0.unwrap().unwrap().len(), MAX_LINE);
        let mut too_long = vec![b'a'; MAX_LINE + 1];
        too_long.push(b'\n');
        assert_eq!(
            line(&too_long).0.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            line(b"caf\xe9\n").0.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            line("caf\u{e9}\n".as_bytes()).0.unwrap().unwrap().as_str(),
            "caf\u{e9}"
        );
    }

    #[test]
    fn a_read_error_is_passed_on() {
        let r = read_line_from(&mut |_| Err(io::Error::other("boom")));
        assert_eq!(r.unwrap_err().to_string(), "boom");
    }
}
