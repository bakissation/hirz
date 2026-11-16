//! hirz-nmh: the native messaging host of the hirz Firefox extension.
//!
//! A reader thread takes frames from stdin so that `cancel` arrives while a ceremony waits
//! for the user; everything else is answered in order by the main thread through
//! `hirz_webauthn::handle`. See `docs/extension.md` for the protocol.
#![forbid(unsafe_code)]

mod framing;
#[path = "../../hirzd/src/session.rs"]
mod session;

use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::process::ExitCode;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard};

use framing::{FrameError, INBOUND_MAX, read_frame, write_frame};
use hirz_core::{
    Approver, AssertionResponse, CoreError, GetAssertionRequest, MakeCredentialRequest,
    MakeCredentialResponse,
};
use hirz_proto::json::{self, Json, Limits};
use hirz_uv::{CommandRunner, HirzApprover, SystemRunner};
use hirz_webauthn::envelope::{MAX_SAFE_INTEGER, error_reply};
use hirz_webauthn::{Error, PROTOCOL_VERSION};
use session::{Session, Settings, VaultStatus};

const LIMITS: Limits = Limits {
    max_len: INBOUND_MAX,
    max_depth: 32,
    max_items: 65_536,
};
/// Requests waiting behind a running ceremony.
const QUEUE: usize = 64;

fn diag(msg: std::fmt::Arguments<'_>) {
    let _ = writeln!(io::stderr(), "hirz-nmh: {msg}");
}

/// Whether a host-verified approval method can be used right now.
pub trait UvProbe {
    fn uv_available(&self) -> bool;
}

impl<R: CommandRunner> UvProbe for HirzApprover<R> {
    fn uv_available(&self) -> bool {
        self.available_uv_methods()
            .is_ok_and(|methods| !methods.is_empty())
    }
}

/// `hirz_webauthn::Engine` over the session's vault and approver.
struct HostEngine<'s, A> {
    session: &'s mut Session<A>,
    uv: bool,
    cancelled: &'s dyn Fn() -> bool,
}

impl<A: Approver> hirz_webauthn::Engine for HostEngine<'_, A> {
    fn make_credential(
        &mut self,
        request: &MakeCredentialRequest,
        origin_for_display: &str,
    ) -> Result<MakeCredentialResponse, CoreError> {
        self.session.with_engine(self.cancelled, |e| {
            e.make_credential(request, Some(origin_for_display))
        })
    }

    fn get_assertion(
        &mut self,
        request: &GetAssertionRequest,
        origin_for_display: &str,
    ) -> Result<AssertionResponse, CoreError> {
        self.session.with_engine(self.cancelled, |e| {
            e.get_assertion(request, Some(origin_for_display), None)
        })
    }

    fn user_verification_available(&self) -> bool {
        self.uv
    }
}

/// Ceremonies received but not yet answered, and those of them the extension cancelled.
#[derive(Debug, Default)]
struct Pending {
    waiting: BTreeSet<u64>,
    cancelled: BTreeSet<u64>,
}

fn lock(p: &Mutex<Pending>) -> MutexGuard<'_, Pending> {
    p.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Hello,
    Capabilities,
    Ceremony,
    Cancel,
    Other,
}

/// The `id` of a well-formed version 1 envelope, and its type.
fn classify(msg: &Json) -> (Option<u64>, Kind) {
    let id = msg
        .get("id")
        .and_then(Json::as_u64)
        .filter(|&n| n <= MAX_SAFE_INTEGER);
    let kind = match msg.get("type").and_then(Json::as_str) {
        _ if msg.get("v").and_then(Json::as_u64) != Some(PROTOCOL_VERSION) => Kind::Other,
        Some("hello") => Kind::Hello,
        Some("capabilities") => Kind::Capabilities,
        Some("create" | "get") => Kind::Ceremony,
        Some("cancel") => Kind::Cancel,
        _ => Kind::Other,
    };
    (id, kind)
}

fn type_name(msg: &Json) -> &str {
    match msg.get("type").and_then(Json::as_str) {
        Some(t @ ("hello" | "capabilities" | "create" | "get" | "cancel")) => t,
        _ => "other",
    }
}

enum Inbound {
    Message(Result<Json, ()>),
    Eof,
    Fatal(FrameError),
}

fn reader<R: Read>(
    mut input: R,
    tx: SyncSender<Inbound>,
    pending: Arc<Mutex<Pending>>,
    debug: bool,
) {
    loop {
        let bytes = match read_frame(&mut input, INBOUND_MAX) {
            Ok(Some(b)) => b,
            Ok(None) => {
                // Firefox closed the port: nobody can receive the pending results.
                let mut p = lock(&pending);
                let waiting = core::mem::take(&mut p.waiting);
                p.cancelled.extend(waiting);
                drop(p);
                let _ = tx.send(Inbound::Eof);
                return;
            }
            Err(e) => {
                let _ = tx.send(Inbound::Fatal(e));
                return;
            }
        };
        let parsed = json::parse(&bytes, &LIMITS).map_err(|_| ());
        if let Ok(msg) = &parsed {
            let (id, kind) = classify(msg);
            if debug {
                let id = id.map_or_else(|| "null".to_owned(), |n| n.to_string());
                diag(format_args!(
                    "recv type={} id={id} bytes={}",
                    type_name(msg),
                    bytes.len()
                ));
            }
            match (kind, id) {
                (Kind::Cancel, Some(id)) => {
                    let mut p = lock(&pending);
                    if p.waiting.contains(&id) {
                        p.cancelled.insert(id);
                    }
                    continue;
                }
                (Kind::Cancel, None) => continue,
                (Kind::Ceremony, Some(id)) => {
                    lock(&pending).waiting.insert(id);
                }
                _ => {}
            }
        } else if debug {
            diag(format_args!("recv rejected bytes={}", bytes.len()));
        }
        if tx.send(Inbound::Message(parsed)).is_err() {
            return;
        }
    }
}

fn abort_reply(id: u64) -> Json {
    Json::Object(vec![
        ("v".to_owned(), Json::from(PROTOCOL_VERSION)),
        ("id".to_owned(), Json::from(id)),
        ("ok".to_owned(), Json::Bool(false)),
        ("error".to_owned(), Json::from("AbortError")),
        ("message".to_owned(), Json::from("request cancelled")),
    ])
}

struct Host<A> {
    session: Session<A>,
    pending: Arc<Mutex<Pending>>,
}

impl<A: Approver + UvProbe> Host<A> {
    fn vault_ready(&mut self) -> bool {
        match self.session.ensure_vault() {
            VaultStatus::Ready => true,
            VaultStatus::Missing => false,
            VaultStatus::Broken(why) => {
                diag(format_args!("cannot open the vault: {why}"));
                false
            }
        }
    }

    fn answer(&mut self, msg: &Json) -> Json {
        let (id, kind) = classify(msg);
        match (kind, id) {
            (Kind::Ceremony, Some(id)) => {
                let reply = self.ceremony(msg, id);
                let mut p = lock(&self.pending);
                p.waiting.remove(&id);
                if p.cancelled.remove(&id) {
                    return abort_reply(id);
                }
                reply
            }
            (Kind::Capabilities, _) => {
                let uv = self.vault_ready() && self.session.approver().uv_available();
                self.handle(msg, uv, None)
            }
            _ => self.handle(msg, false, None),
        }
    }

    fn ceremony(&mut self, msg: &Json, id: u64) -> Json {
        if lock(&self.pending).cancelled.contains(&id) {
            return abort_reply(id);
        }
        if !self.vault_ready() {
            return error_reply(Some(id), &Error::NotHandled("no hirz vault on this device"));
        }
        self.handle(msg, false, Some(id))
    }

    /// `ceremony`: the id whose `cancel` refuses the approval.
    fn handle(&mut self, msg: &Json, uv: bool, ceremony: Option<u64>) -> Json {
        let pending = Arc::clone(&self.pending);
        let cancelled = move || ceremony.is_some_and(|id| lock(&pending).cancelled.contains(&id));
        let mut engine = HostEngine {
            session: &mut self.session,
            uv,
            cancelled: &cancelled,
        };
        hirz_webauthn::handle(msg, &mut engine)
    }
}

/// Serves one connection: `input` is read on its own thread, replies go to `output`.
fn run<R, W, A>(
    input: R,
    output: &mut W,
    session: Session<A>,
    debug: bool,
) -> Result<(), FrameError>
where
    R: Read + Send + 'static,
    W: Write,
    A: Approver + UvProbe,
{
    let pending = Arc::new(Mutex::new(Pending::default()));
    let (tx, rx): (SyncSender<Inbound>, Receiver<Inbound>) = sync_channel(QUEUE);
    let reader_pending = Arc::clone(&pending);
    std::thread::Builder::new()
        .name("stdin".into())
        .spawn(move || reader(input, tx, reader_pending, debug))?;
    let mut host = Host { session, pending };
    for inbound in rx {
        let reply = match inbound {
            Inbound::Message(Ok(msg)) => host.answer(&msg),
            Inbound::Message(Err(())) => error_reply(None, &Error::BadEnvelope("invalid JSON")),
            Inbound::Eof => return Ok(()),
            Inbound::Fatal(e) => return Err(e),
        };
        let bytes = reply.to_string().into_bytes();
        if debug {
            let id = reply.get("id").and_then(Json::as_u64);
            let ok = reply.get("ok").and_then(Json::as_bool).unwrap_or(false);
            let error = reply.get("error").and_then(Json::as_str).unwrap_or("-");
            diag(format_args!(
                "send id={} ok={ok} error={error} bytes={}",
                id.map_or_else(|| "null".to_owned(), |n| n.to_string()),
                bytes.len()
            ));
        }
        write_frame(output, &bytes)?;
    }
    Ok(())
}

fn main() -> ExitCode {
    if let Err(e) = hirz_sys::harden_process(false) {
        diag(format_args!("cannot harden the process: {e}"));
        return ExitCode::FAILURE;
    }
    let debug = std::env::var_os("HIRZ_LOG").is_some_and(|v| v == "debug");
    let settings = Settings::from_process();
    let approver = match settings.uv_paths() {
        Ok(paths) => HirzApprover::new(SystemRunner, &paths),
        Err(e) => {
            diag(format_args!("cannot locate the hirz folders: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let session = Session::new(settings, approver);
    let mut output = io::stdout().lock();
    match run(io::stdin(), &mut output, session, debug) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            diag(format_args!("{e}"));
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
