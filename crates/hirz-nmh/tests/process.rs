#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

//! Runs the real `hirz-nmh` binary as Firefox does, with stdin and stdout pipes, against a
//! folder without a vault. No approval prompt can appear on this path.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn temp_dir() -> PathBuf {
    let mut r = [0u8; 8];
    hirz_crypto::random_fill(&mut r).unwrap();
    let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
    let p = std::env::temp_dir().join(format!("hirz-nmh-process-{hex}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn frame(msg: &str) -> Vec<u8> {
    let mut out = (msg.len() as u32).to_ne_bytes().to_vec();
    out.extend_from_slice(msg.as_bytes());
    out
}

#[test]
fn binary_without_vault_falls_back_to_firefox() {
    let dir = temp_dir();
    let mut child = Command::new(env!("CARGO_BIN_EXE_hirz-nmh"))
        .args(["/path/to/hirz.json", "hirz@berkati.xyz"])
        .env_clear()
        .env("HOME", &dir)
        .env("HIRZ_VAULT", dir.join("vault"))
        .env("HIRZ_STATE", dir.join("state"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = Vec::new();
    for msg in [
        r#"{"v":1,"id":1,"type":"hello"}"#,
        r#"{"v":1,"id":2,"type":"capabilities"}"#,
        r#"{"v":1,"id":3,"type":"create","origin":"https://example.com","topOrigin":"https://example.com","crossOrigin":false,"options":{"challenge":"AAAAAAAAAAAAAAAAAAAAAA","rp":{"name":"Example"},"user":{"id":"YWxpY2U","name":"alice","displayName":"Alice"},"pubKeyCredParams":[{"alg":-7,"type":"public-key"}]}}"#,
        r#"{"v":1,"id":7,"type":"cancel"}"#,
    ] {
        input.extend(frame(msg));
    }
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&input).unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut replies = Vec::new();
    for _ in 0..3 {
        let mut len = [0u8; 4];
        stdout.read_exact(&mut len).unwrap();
        let mut body = vec![0u8; u32::from_ne_bytes(len) as usize];
        stdout.read_exact(&mut body).unwrap();
        replies.push(String::from_utf8(body).unwrap());
    }
    drop(stdin);
    let mut rest = Vec::new();
    stdout.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty());
    assert!(child.wait().unwrap().success());
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(replies.len(), 3, "{replies:?}");
    assert_eq!(
        replies[0],
        format!(
            r#"{{"v":1,"id":1,"ok":true,"version":"{}"}}"#,
            env!("CARGO_PKG_VERSION")
        )
    );
    assert!(replies[1].contains(r#""userVerifyingPlatformAuthenticator":false"#));
    assert!(replies[2].starts_with(r#"{"v":1,"id":3,"ok":false,"error":"NotHandled""#));
}

#[test]
fn oversize_frame_exits_with_status_1() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_hirz-nmh"))
        .env_clear()
        .env("HOME", std::env::temp_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&u32::MAX.to_ne_bytes()).unwrap();
    drop(stdin);
    assert_eq!(child.wait().unwrap().code(), Some(1));
}
