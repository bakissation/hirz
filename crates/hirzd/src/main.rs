//! hirzd: the user daemon behind the hirz virtual security key.
//!
//! Phase 0 spike: connects to hirz-uhid-broker, runs the CTAPHID transport and answers
//! authenticatorGetInfo. Every other CTAP2 command gets CTAP2_ERR_INVALID_COMMAND.
#![forbid(unsafe_code)]

mod getinfo;

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use hirz_ctap::hid::{self, CborHandler, LoopEvent, RequestContext, StreamReportIo};

const DEFAULT_SOCKET: &str = "/run/hirz/uhid.sock";
const SOCKET_ENV: &str = "HIRZ_BROKER_SOCKET";
const MLOCK_ENV: &str = "HIRZ_MLOCK";

const CTAP2_ERR_INVALID_COMMAND: u8 = 0x01;
const CTAP2_ERR_INVALID_LENGTH: u8 = 0x03;

fn log(msg: std::fmt::Arguments<'_>) {
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

/// The spike's CTAP2 handler.
#[derive(Debug, Default)]
struct SpikeHandler;

impl CborHandler for SpikeHandler {
    fn handle(&self, request: &[u8], _ctx: &RequestContext) -> Vec<u8> {
        match request.split_first() {
            Some((&getinfo::CMD_GET_INFO, [])) => getinfo::get_info_response(),
            Some((&getinfo::CMD_GET_INFO, _)) => vec![CTAP2_ERR_INVALID_LENGTH],
            _ => vec![CTAP2_ERR_INVALID_COMMAND],
        }
    }

    fn wink(&self) {
        log(format_args!("CTAPHID WINK"));
    }
}

fn log_event(event: LoopEvent) {
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

fn run_with_broker(path: PathBuf) -> ExitCode {
    let stream = match UnixStream::connect(&path) {
        Ok(s) => s,
        Err(e) => {
            log(format_args!(
                "cannot connect to the broker at {}: {e}",
                path.display()
            ));
            return ExitCode::FAILURE;
        }
    };
    log(format_args!(
        "connected to the broker at {}",
        path.display()
    ));
    let mut io = StreamReportIo::new(stream);
    match hid::run(
        &mut io,
        Arc::new(SpikeHandler),
        hid::Config::default(),
        log_event,
    ) {
        Ok(()) => {
            // The broker closes the connection when it refuses the uid or when it stops.
            log(format_args!("the broker closed the connection"));
            ExitCode::FAILURE
        }
        Err(e) => {
            log(format_args!("transport error: {e}"));
            ExitCode::FAILURE
        }
    }
}

/// Plays the browser against the daemon over an in-process socketpair (the fake broker):
/// CTAPHID_INIT, getInfo, and an unsupported command. Needs no root and no /dev/uhid.
fn loopback_self_test() -> io::Result<()> {
    let (daemon_end, mut host) = UnixStream::pair()?;
    let worker = std::thread::spawn(move || {
        let mut io = StreamReportIo::new(daemon_end);
        hid::run(
            &mut io,
            Arc::new(SpikeHandler),
            hid::Config::default(),
            log_event,
        )
    });
    host.set_read_timeout(Some(Duration::from_secs(5)))?;

    let nonce = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let mut init = [0u8; hid::REPORT_SIZE];
    let mut init_payload = Vec::from([0xff, 0xff, 0xff, 0xff, 0x86, 0x00, 0x08]);
    init_payload.extend_from_slice(&nonce);
    copy_prefix(&mut init, &init_payload);
    host.write_all(&init)?;
    let reply = transact_message(&mut host, hid::BROADCAST_CID)?;
    if reply.get(..8) != Some(&nonce[..]) || reply.len() != 17 {
        return Err(io::Error::other("bad CTAPHID_INIT response"));
    }
    let cid_bytes: [u8; 4] = reply
        .get(8..12)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| io::Error::other("short CTAPHID_INIT response"))?;
    let cid = u32::from_be_bytes(cid_bytes);

    for (request, expected) in [
        (vec![getinfo::CMD_GET_INFO], getinfo::get_info_response()),
        (vec![0x01, 0xa0], vec![CTAP2_ERR_INVALID_COMMAND]),
    ] {
        let packets = hid::build_message(cid, hid::cmd::CBOR, &request)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        for p in &packets {
            host.write_all(p)?;
        }
        let response = transact_message(&mut host, cid)?;
        if response != expected {
            return Err(io::Error::other("unexpected CBOR response"));
        }
    }

    drop(host);
    worker
        .join()
        .map_err(|_| io::Error::other("transport thread failed"))??;
    Ok(())
}

fn copy_prefix(dst: &mut [u8], src: &[u8]) {
    if let Some(d) = dst.get_mut(..src.len()) {
        d.copy_from_slice(src);
    }
}

/// Reads one complete CTAPHID message for `cid`, skipping keepalives.
fn transact_message(host: &mut UnixStream, cid: u32) -> io::Result<Vec<u8>> {
    let mut packet = [0u8; hid::REPORT_SIZE];
    loop {
        host.read_exact(&mut packet)?;
        match hid::parse_packet(&packet) {
            Ok(hid::Packet::Init {
                cid: c,
                cmd,
                bcnt,
                data,
            }) if c == cid => {
                if cmd == hid::cmd::KEEPALIVE {
                    continue;
                }
                if cmd == hid::cmd::ERROR {
                    return Err(io::Error::other("CTAPHID_ERROR from the transport"));
                }
                let total = usize::from(bcnt);
                let mut message = data.get(..total.min(data.len())).unwrap_or(&[]).to_vec();
                while message.len() < total {
                    host.read_exact(&mut packet)?;
                    let Ok(hid::Packet::Cont { data, .. }) = hid::parse_packet(&packet) else {
                        return Err(io::Error::other("expected a continuation packet"));
                    };
                    let want = total.saturating_sub(message.len()).min(data.len());
                    message.extend_from_slice(data.get(..want).unwrap_or(&[]));
                }
                return Ok(message);
            }
            _ => return Err(io::Error::other("unexpected packet")),
        }
    }
}

fn main() -> ExitCode {
    let mut self_test = false;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--self-test" => self_test = true,
            _ => {
                eprintln!(
                    "usage: hirzd [--self-test]\n\nEnvironment: {SOCKET_ENV} (default {DEFAULT_SOCKET}), {MLOCK_ENV}=1 to lock memory"
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
        return match loopback_self_test() {
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

    let path = std::env::var_os(SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET));
    run_with_broker(path)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn handler_answers_get_info_and_rejects_the_rest() {
        let h = SpikeHandler;
        let ctx = RequestContext::new();
        assert_eq!(h.handle(&[0x04], &ctx), getinfo::get_info_response());
        assert_eq!(
            h.handle(&[0x04, 0xa0], &ctx),
            vec![CTAP2_ERR_INVALID_LENGTH]
        );
        assert_eq!(
            h.handle(&[0x01, 0xa0], &ctx),
            vec![CTAP2_ERR_INVALID_COMMAND]
        );
        assert_eq!(h.handle(&[0x02], &ctx), vec![CTAP2_ERR_INVALID_COMMAND]);
    }

    #[test]
    fn loopback_with_fake_broker() {
        loopback_self_test().unwrap();
    }
}
