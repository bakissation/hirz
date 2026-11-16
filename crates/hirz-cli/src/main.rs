//! `hirz`: set up and manage the hirz passkey vault. See `docs/cli.md`.
#![forbid(unsafe_code)]

mod app;
mod args;
mod cmd_cxf;
mod cmd_pair;
mod cmd_pin;
mod cmd_repair;
mod cmd_setup;
mod cmd_status;
mod cmd_vault;
mod cxf;
mod env;
mod envelope;
mod error;
mod foreign;
mod prompt;
mod ui;

#[cfg(test)]
mod tests;

use std::io::{IsTerminal, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    if let Err(e) = hirz_sys::harden_process(false) {
        let _ = writeln!(
            std::io::stderr(),
            "hirz: cannot protect this process from memory dumps: {e}"
        );
        return ExitCode::FAILURE;
    }
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let code = run_process(&args);
    ExitCode::from(code)
}

fn run_process(args: &[std::ffi::OsString]) -> u8 {
    let mut stderr = std::io::stderr();
    let result = args::parse(args).and_then(|inv| {
        let env = env::Env::from_process()?;
        let sys = env::RealSystem;
        let mut prompter = prompt::TerminalPrompter::new();
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let mut ctx = app::Ctx {
            out: &mut out,
            prompt: &mut prompter,
            env: &env,
            sys: &sys,
            kdf: hirz_crypto::kdf::DEFAULT,
            vault_flag: None,
            program: env::command_name(
                std::env::args_os().next().as_deref(),
                std::env::var_os("PATH").as_deref(),
                &env::is_executable_file,
            ),
            out_is_terminal: std::io::stdout().is_terminal(),
        };
        let r = app::run(inv, &mut ctx);
        let _ = out.flush();
        r
    });
    match result {
        Ok(exit) => exit.code(),
        Err(e) => {
            let _ = writeln!(stderr, "hirz: {}", e.message);
            e.exit.code()
        }
    }
}
