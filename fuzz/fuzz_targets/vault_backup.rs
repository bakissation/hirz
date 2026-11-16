#![no_main]

//! Backup import with a fixed recovery phrase and no passphrase, so no Argon2 runs. Covers
//! the header reader and the AEAD rejection path; the record decoder behind the AEAD is
//! crate-private and not reachable with forged input.

use hirz_vault::{RecoveryPhrase, import_backup};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let phrase = RecoveryPhrase::from_entropy([7; 32]);
    let _ = import_backup(data, &phrase, None);
});
