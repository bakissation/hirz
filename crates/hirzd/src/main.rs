//! hirzd: the user daemon behind the hirz virtual security key. CTAPHID and CTAP2 over the broker's
//! socket, answered by the engine over the user's vault, with `hirz-uv` approving each request
//! (docs/uhid.md).
#![forbid(unsafe_code)]

mod authenticator;
mod selftest;
mod trace;

use std::io::IsTerminal;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hirz_ctap::Ctap2Handler;
use hirz_ctap::hid::{self, LoopEvent, StreamReportIo};
use hirz_session as session;
use hirz_uv::{HirzApprover, SystemRunner};

use authenticator::{Notice, VaultAuthenticator};
use session::{Session, Settings};

const DEFAULT_SOCKET: &str = "/run/hirz/uhid.sock";
const SOCKET_ENV: &str = "HIRZ_BROKER_SOCKET";
const MLOCK_ENV: &str = "HIRZ_MLOCK";
/// The ceremony timeout is capped below the CTAPHID transaction limit, so a prompt ends before the
/// browser is told the request timed out (docs/approval.md).
pub(crate) const APPROVAL_MARGIN: Duration = Duration::from_secs(5);
const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
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
        LoopEvent::Busy => log(format_args!(
            "request refused: an earlier cancelled request is still waiting for its prompt"
        )),
    }
}

/// `HIRZ_DEBUG_CTAP=1` traces every CTAP2 request and response in hex (`trace.rs`). Requests and
/// responses name the sites the user has accounts at, so the trace is only ever printed to a
/// terminal: a service started with the variable set (journal, a log file) gets this notice and
/// no trace.
fn debug_ctap() -> bool {
    if !std::env::var_os("HIRZ_DEBUG_CTAP").is_some_and(|v| v == "1") {
        return false;
    }
    if std::io::stderr().is_terminal() {
        log(format_args!(
            "HIRZ_DEBUG_CTAP=1: tracing CTAP2 requests and responses to this terminal; account \
             names are left out, site ids and credential ids are not"
        ));
        true
    } else {
        log(format_args!(
            "HIRZ_DEBUG_CTAP=1 is ignored: the trace is printed to a terminal only, never to a \
             journal or a file"
        ));
        false
    }
}

struct DebugHandler(Arc<dyn hid::CborHandler>);

impl hid::CborHandler for DebugHandler {
    fn handle(&self, request: &[u8], ctx: &hid::RequestContext) -> Vec<u8> {
        log(format_args!("debug request {}", trace::request(request)));
        let response = self.0.handle(request, ctx);
        log(format_args!(
            "debug response {}",
            trace::response(request.first().copied(), &response)
        ));
        response
    }

    fn wink(&self) {
        self.0.wink();
    }

    fn may_block(&self, request: &[u8]) -> bool {
        self.0.may_block(request)
    }
}

/// `fresh_connection` runs after every connect to the broker, before the first report is read.
fn serve(
    path: &Path,
    handler: Arc<dyn hid::CborHandler>,
    debug: bool,
    fresh_connection: &dyn Fn(),
) {
    let mut delay = MIN_BACKOFF;
    loop {
        match UnixStream::connect(path).and_then(|mut stream| {
            use std::io::Write;
            stream.write_all(&hirz_sys::broker::HELLO_DEVICE)?;
            Ok(stream)
        }) {
            Ok(stream) => {
                log(format_args!(
                    "connected to the broker at {}",
                    path.display()
                ));
                let started = Instant::now();
                fresh_connection();
                let mut io = StreamReportIo::new(stream);
                let served: Arc<dyn hid::CborHandler> = if debug {
                    Arc::new(DebugHandler(Arc::clone(&handler)))
                } else {
                    Arc::clone(&handler)
                };
                match hid::run(&mut io, served, hid::Config::default(), log_event) {
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
    let transaction = hid::Config::default().processing_timeout;
    let approver = match settings.uv_paths() {
        Ok(paths) => HirzApprover::new(SystemRunner, &paths)
            .with_timeout_cap(transaction.saturating_sub(APPROVAL_MARGIN)),
        Err(e) => {
            log(format_args!("cannot locate the hirz folders: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let first_run = session::FirstRun::from_process(&settings);
    let authenticator =
        VaultAuthenticator::new(Session::new(settings, approver), Notice::new(true))
            .with_first_run(first_run);
    let path = std::env::var_os(SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET));
    let handler = Arc::new(Ctap2Handler::new(authenticator));
    let renewed = Arc::clone(&handler);
    serve(&path, handler, debug_ctap(), &|| {
        renewed.regenerate_key_agreement();
    });
    ExitCode::FAILURE
}
