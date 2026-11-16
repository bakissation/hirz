#![forbid(unsafe_code)]

mod envelope;
mod framing;

use std::io::{self, Read, Write};
use std::process::ExitCode;

use envelope::{Envelope, ErrorKind, MsgType, PROTOCOL_VERSION};
use framing::{FrameError, INBOUND_MAX, read_frame, write_frame};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn error_reply(id: Option<u64>, code: &str) -> Vec<u8> {
    let id = id.map_or_else(|| "null".to_owned(), |n| n.to_string());
    format!(r#"{{"v":{PROTOCOL_VERSION},"id":{id},"ok":false,"error":"{code}"}}"#).into_bytes()
}

fn reply(env: Envelope) -> Option<Vec<u8>> {
    let id = env.id;
    let v = PROTOCOL_VERSION;
    let body = match env.kind {
        MsgType::Hello => format!(r#"{{"v":{v},"id":{id},"ok":true,"version":"{VERSION}"}}"#),
        MsgType::Capabilities => format!(
            r#"{{"v":{v},"id":{id},"ok":true,"capabilities":{{"userVerifyingPlatformAuthenticator":true,"passkeyPlatformAuthenticator":true}}}}"#
        ),
        MsgType::Create | MsgType::Get => return Some(error_reply(Some(id), "NotHandled")),
        MsgType::Cancel => return None,
    };
    Some(body.into_bytes())
}

fn handle(msg: &[u8], debug: bool) -> Option<Vec<u8>> {
    let parsed = envelope::parse(msg);
    if debug {
        let summary = match &parsed {
            Ok(env) => format!("type={} id={}", env.kind.as_str(), env.id),
            Err(e) => format!("rejected ({e})"),
        };
        let _ = writeln!(io::stderr(), "hirz-nmh: recv {summary} bytes={}", msg.len());
    }
    match parsed {
        Ok(env) => reply(env),
        Err(e) => {
            let code = match e.kind {
                ErrorKind::UnsupportedVersion => "UnsupportedVersion",
                ErrorKind::Malformed | ErrorKind::UnknownType => "BadRequest",
            };
            Some(error_reply(e.id, code))
        }
    }
}

fn run<R: Read, W: Write>(input: &mut R, output: &mut W, debug: bool) -> Result<(), FrameError> {
    while let Some(msg) = read_frame(input, INBOUND_MAX)? {
        if let Some(out) = handle(&msg, debug) {
            write_frame(output, &out)?;
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let debug = std::env::var_os("HIRZ_LOG").is_some_and(|v| v == "debug");
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    match run(&mut input, &mut output, debug) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(io::stderr(), "hirz-nmh: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn frames(msgs: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for m in msgs {
            out.extend_from_slice(&(m.len() as u32).to_ne_bytes());
            out.extend_from_slice(m);
        }
        out
    }

    fn replies(out: Vec<u8>) -> Vec<String> {
        let mut r = Cursor::new(out);
        let mut v = Vec::new();
        while let Some(m) = read_frame(&mut r, framing::OUTBOUND_MAX).unwrap() {
            v.push(String::from_utf8(m).unwrap());
        }
        v
    }

    fn exchange(msgs: &[&[u8]]) -> Vec<String> {
        let mut input = Cursor::new(frames(msgs));
        let mut out = Vec::new();
        run(&mut input, &mut out, false).unwrap();
        replies(out)
    }

    #[test]
    fn spike_session() {
        let got = exchange(&[
            br#"{"v":1,"id":1,"type":"hello"}"#,
            br#"{"v":1,"id":2,"type":"capabilities"}"#,
            br#"{"v":1,"id":3,"type":"create","origin":"https://example.com","topOrigin":"https://example.com","crossOrigin":false,"options":{"challenge":"AAAA"}}"#,
            br#"{"v":1,"id":3,"type":"cancel"}"#,
            br#"{"v":1,"id":4,"type":"get","origin":"https://example.com","topOrigin":"https://example.com","crossOrigin":false,"options":{}}"#,
        ]);
        assert_eq!(
            got,
            vec![
                r#"{"v":1,"id":1,"ok":true,"version":"0.1.0-dev"}"#.to_owned(),
                r#"{"v":1,"id":2,"ok":true,"capabilities":{"userVerifyingPlatformAuthenticator":true,"passkeyPlatformAuthenticator":true}}"#.to_owned(),
                r#"{"v":1,"id":3,"ok":false,"error":"NotHandled"}"#.to_owned(),
                r#"{"v":1,"id":4,"ok":false,"error":"NotHandled"}"#.to_owned(),
            ]
        );
    }

    #[test]
    fn bad_requests_are_answered_and_loop_continues() {
        let got = exchange(&[
            b"not json",
            br#"{"v":2,"id":8,"type":"hello"}"#,
            br#"{"v":1,"id":9,"type":"explode"}"#,
            br#"{"v":1,"id":10,"type":"hello"}"#,
        ]);
        assert_eq!(
            got,
            vec![
                r#"{"v":1,"id":null,"ok":false,"error":"BadRequest"}"#.to_owned(),
                r#"{"v":1,"id":8,"ok":false,"error":"UnsupportedVersion"}"#.to_owned(),
                r#"{"v":1,"id":9,"ok":false,"error":"BadRequest"}"#.to_owned(),
                r#"{"v":1,"id":10,"ok":true,"version":"0.1.0-dev"}"#.to_owned(),
            ]
        );
    }

    #[test]
    fn clean_exit_on_eof() {
        let mut out = Vec::new();
        run(&mut Cursor::new(Vec::new()), &mut out, false).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn oversize_frame_stops_the_loop() {
        let mut input = frames(&[br#"{"v":1,"id":1,"type":"hello"}"#]);
        input.extend_from_slice(&u32::MAX.to_ne_bytes());
        input.extend_from_slice(br#"{"v":1,"id":2,"type":"hello"}"#);
        let mut out = Vec::new();
        let res = run(&mut Cursor::new(input), &mut out, false);
        assert!(matches!(res, Err(FrameError::TooLarge { .. })));
        assert_eq!(replies(out).len(), 1);
    }

    #[test]
    fn truncated_stream_is_an_error() {
        let mut input = frames(&[br#"{"v":1,"id":1,"type":"hello"}"#]);
        input.extend_from_slice(&100u32.to_ne_bytes());
        input.extend_from_slice(b"{\"v\":");
        let mut out = Vec::new();
        let res = run(&mut Cursor::new(input), &mut out, true);
        assert!(matches!(res, Err(FrameError::TruncatedBody { .. })));
        assert_eq!(replies(out).len(), 1);
    }

    #[test]
    fn version_matches_package() {
        assert_eq!(VERSION, "0.1.0-dev");
    }
}
