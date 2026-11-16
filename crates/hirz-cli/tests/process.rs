#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Runs the real `hirz` binary. The CLI handles the recovery phrase, PINs, export passphrases
//! and plaintext private keys, so like the daemons it must not leave core dumps behind.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn temp_dir() -> PathBuf {
    let mut r = [0u8; 8];
    hirz_crypto::random_fill(&mut r).unwrap();
    let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
    let p = std::env::temp_dir().join(format!("hirz-cli-process-{hex}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn proc_file(pid: u32, name: &str) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/{name}")).unwrap()
}

#[test]
fn a_running_hirz_is_hardened_like_the_daemons() {
    let dir = temp_dir();
    let mut child = Command::new(env!("CARGO_BIN_EXE_hirz"))
        .args(["pin", "set"])
        .env_clear()
        .env("HOME", &dir)
        .env("HIRZ_STATE", dir.join("state"))
        .env("HIRZ_VAULT", dir.join("vault"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let mut stderr = child.stderr.take().unwrap();
    let mut seen = Vec::new();
    let mut chunk = [0u8; 256];
    while !String::from_utf8_lossy(&seen).contains("New PIN: ") {
        let n = stderr.read(&mut chunk).unwrap();
        assert!(
            n > 0,
            "hirz ended early: {}",
            String::from_utf8_lossy(&seen)
        );
        seen.extend_from_slice(&chunk[..n]);
    }

    let status = proc_file(pid, "status");
    let limits = proc_file(pid, "limits");
    let owner = std::os::unix::fs::MetadataExt::uid(
        &std::fs::metadata(format!("/proc/{pid}/status")).unwrap(),
    );
    child.kill().unwrap();
    child.wait().unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        status
            .lines()
            .any(|l| l.split_whitespace().eq(["NoNewPrivs:", "1"])),
        "{status}"
    );
    let core = limits
        .lines()
        .find(|l| l.starts_with("Max core file size"))
        .unwrap();
    assert!(
        core.split_whitespace()
            .rev()
            .skip(1)
            .take(2)
            .all(|v| v == "0"),
        "{core}"
    );
    assert_eq!(
        owner, 0,
        "the files of a non-dumpable process belong to root"
    );
}

#[test]
fn version_and_help_still_run() {
    for args in [["--version"], ["--help"]] {
        let out = Command::new(env!("CARGO_BIN_EXE_hirz"))
            .args(args)
            .env_clear()
            .env("HOME", std::env::temp_dir())
            .output()
            .unwrap();
        assert!(out.status.success(), "{args:?}");
        assert!(!out.stdout.is_empty());
    }
}
