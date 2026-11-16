//! hirzd: the user daemon behind the hirz virtual security key.
//!
//! Connects to hirz-uhid-broker, runs CTAPHID and CTAP2 (`hirz-ctap`) and answers with the
//! authenticator engine over the user's vault, asking `hirz-uv` for every approval. When the
//! broker goes away, hirzd reconnects with a growing delay.
#![forbid(unsafe_code)]

mod authenticator;
mod selftest;
mod session;

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hirz_ctap::Ctap2Handler;
use hirz_ctap::hid::{self, LoopEvent, StreamReportIo};
use hirz_uv::{HirzApprover, SystemRunner};

use authenticator::{Notice, VaultAuthenticator};
use session::{Session, Settings};

const DEFAULT_SOCKET: &str = "/run/hirz/uhid.sock";
const SOCKET_ENV: &str = "HIRZ_BROKER_SOCKET";
const MLOCK_ENV: &str = "HIRZ_MLOCK";
const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// A connection that lasted this long resets the reconnect delay.
const STABLE_CONNECTION: Duration = Duration::from_secs(30);

pub(crate) fn log(msg: std::fmt::Arguments<'_>) {
    eprintln!("hirzd: {msg}");
}

fn command_name(cmd: u8) -> &'static str {
    match cmd {
        0x01 => "authenticatorMakeCredential",
        0x02 => "authenticatorGetAssertion",
        0x04 => "authenticatorGetInfo",
        0x06 => "authenticatorClientPIN",
        0x07 => "authenticatorReset",
        0x08 => "authenticatorGetNextAssertion",
        0x09 => "authenticatorBioEnrollment",
        0x0a => "authenticatorCredentialManagement",
        0x0b => "authenticatorSelection",
        0x0c => "authenticatorLargeBlobs",
        0x0d => "authenticatorConfig",
        _ => "unknown",
    }
}

pub(crate) fn log_event(event: LoopEvent) {
    match event {
        LoopEvent::ChannelInit => log(format_args!("CTAPHID INIT: channel allocated")),
        LoopEvent::CborRequest { command, len } => log(format_args!(
            "CTAPHID CBOR request 0x{command:02x} ({}), {len} bytes",
            command_name(command)
        )),
        LoopEvent::CborResponse { status, len } => log(format_args!(
            "CTAPHID CBOR response status 0x{status:02x}, {len} bytes"
        )),
        LoopEvent::Cancelled => log(format_args!("request cancelled")),
    }
}

/// Serves the broker until the process is stopped, reconnecting whenever it goes away.
fn serve(path: &PathBuf, handler: Arc<Ctap2Handler<VaultAuthenticator<HirzApprover>>>) {
    let mut delay = MIN_BACKOFF;
    loop {
        match UnixStream::connect(path) {
            Ok(stream) => {
                log(format_args!(
                    "connected to the broker at {}",
                    path.display()
                ));
                let started = Instant::now();
                let mut io = StreamReportIo::new(stream);
                match hid::run(
                    &mut io,
                    Arc::clone(&handler) as Arc<dyn hid::CborHandler>,
                    hid::Config::default(),
                    log_event,
                ) {
                    // The broker closes the connection when it refuses the uid or stops.
                    Ok(()) => log(format_args!("the broker closed the connection")),
                    Err(e) => log(format_args!("transport error: {e}")),
                }
                if started.elapsed() >= STABLE_CONNECTION {
                    delay = MIN_BACKOFF;
                }
            }
            Err(e) => log(format_args!(
                "cannot connect to the broker at {}: {e}",
                path.display()
            )),
        }
        log(format_args!("reconnecting in {} s", delay.as_secs()));
        std::thread::sleep(delay);
        delay = delay.saturating_mul(2).min(MAX_BACKOFF);
    }
}

fn main() -> ExitCode {
    let mut self_test = false;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--self-test" => self_test = true,
            _ => {
                eprintln!(
                    "usage: hirzd [--self-test]\n\nEnvironment: {SOCKET_ENV} (default {DEFAULT_SOCKET}), {MLOCK_ENV}=1 to lock memory,\n{} and {} to override the vault and state folders",
                    session::VAULT_ENV,
                    session::STATE_ENV
                );
                return ExitCode::from(2);
            }
        }
    }

    let mlock = std::env::var(MLOCK_ENV).is_ok_and(|v| v == "1");
    if let Err(e) = hirz_sys::harden_process(mlock) {
        log(format_args!("cannot harden the process: {e}"));
        return ExitCode::FAILURE;
    }

    if self_test {
        return match selftest::run() {
            Ok(()) => {
                log(format_args!("loopback self-test passed"));
                ExitCode::SUCCESS
            }
            Err(e) => {
                log(format_args!("loopback self-test failed: {e}"));
                ExitCode::FAILURE
            }
        };
    }

    let settings = Settings::from_process();
    let approver = match settings.uv_paths() {
        Ok(paths) => HirzApprover::new(SystemRunner, &paths),
        Err(e) => {
            log(format_args!("cannot locate the hirz folders: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let authenticator =
        VaultAuthenticator::new(Session::new(settings, approver), Notice::new(true));
    let path = std::env::var_os(SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET));
    serve(&path, Arc::new(Ctap2Handler::new(authenticator)));
    ExitCode::FAILURE
}
