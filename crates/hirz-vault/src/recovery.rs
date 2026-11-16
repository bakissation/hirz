//! Recovery key: 256 bits of entropy shown as 24 words of the BIP-39 English word list
//! (the last word carries an 8-bit SHA-256 checksum, as in BIP-39).

use crate::error::{PhraseError, VaultError};
use core::fmt;
use hirz_crypto::Zeroizing;

const WORDLIST: &str = include_str!("../data/bip39-english.txt");
pub(crate) const WORD_COUNT: usize = 24;

const INFO_X25519: &[u8] = b"hirz recovery x25519 v1";
const INFO_AUTH: &[u8] = b"hirz recovery auth v1";
const INFO_BACKUP: &[u8] = b"hirz recovery backup v1";

fn word_at(index: u16) -> Option<&'static str> {
    WORDLIST.lines().nth(usize::from(index))
}

/// Exact match, or a unique prefix of at least four letters (BIP-39 words are unique in
/// their first four letters).
fn index_of(word: &str) -> Option<u16> {
    let mut found = None;
    for (i, w) in WORDLIST.lines().enumerate() {
        if w == word {
            return u16::try_from(i).ok();
        }
        if word.len() >= 4 && w.starts_with(word) {
            if found.is_some() {
                return None;
            }
            found = u16::try_from(i).ok();
        }
    }
    found
}

fn checksum(entropy: &[u8; 32]) -> u8 {
    let [first, ..] = hirz_crypto::sha256(entropy);
    first
}

fn to_indices(entropy: &[u8; 32]) -> [u16; WORD_COUNT] {
    let mut out = [0u16; WORD_COUNT];
    let mut slots = out.iter_mut();
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    for b in entropy
        .iter()
        .copied()
        .chain(core::iter::once(checksum(entropy)))
    {
        acc = acc.wrapping_shl(8) | u32::from(b);
        nbits = nbits.saturating_add(8);
        while nbits >= 11 {
            nbits = nbits.saturating_sub(11);
            let idx = acc.wrapping_shr(nbits) & 0x7ff;
            if let Some(slot) = slots.next() {
                *slot = u16::try_from(idx).unwrap_or(0);
            }
            acc &= 1u32.wrapping_shl(nbits).wrapping_sub(1);
        }
    }
    out
}

fn from_indices(indices: &[u16; WORD_COUNT]) -> Result<Zeroizing<[u8; 32]>, PhraseError> {
    let mut bytes = Zeroizing::new([0u8; 33]);
    let mut out_iter = bytes.iter_mut();
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    for idx in indices {
        acc = acc.wrapping_shl(11) | u32::from(*idx & 0x7ff);
        nbits = nbits.saturating_add(11);
        while nbits >= 8 {
            nbits = nbits.saturating_sub(8);
            if let Some(o) = out_iter.next() {
                *o = u8::try_from(acc.wrapping_shr(nbits) & 0xff).unwrap_or(0);
            }
            acc &= 1u32.wrapping_shl(nbits).wrapping_sub(1);
        }
    }
    let mut entropy = Zeroizing::new([0u8; 32]);
    for (e, b) in entropy.iter_mut().zip(bytes.iter()) {
        *e = *b;
    }
    let expected = bytes.get(32).copied().unwrap_or(0);
    if !hirz_crypto::ct_eq(&[checksum(&entropy)], &[expected]) {
        return Err(PhraseError::Checksum);
    }
    Ok(entropy)
}

/// The vault recovery key. Shown once at vault creation; never stored by hirz.
pub struct RecoveryPhrase {
    entropy: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for RecoveryPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryPhrase(..)")
    }
}

impl RecoveryPhrase {
    pub(crate) fn generate() -> Result<Self, VaultError> {
        let mut entropy = Zeroizing::new([0u8; 32]);
        hirz_crypto::random_fill(entropy.as_mut_slice())?;
        Ok(RecoveryPhrase { entropy })
    }

    pub fn from_entropy(entropy: [u8; 32]) -> Self {
        RecoveryPhrase {
            entropy: Zeroizing::new(entropy),
        }
    }

    /// Parses 24 words separated by whitespace. Case-insensitive; a unique prefix of four or
    /// more letters is accepted for each word.
    pub fn parse(phrase: &str) -> Result<Self, VaultError> {
        let lowered = Zeroizing::new(phrase.to_lowercase());
        let words: Vec<&str> = lowered.split_whitespace().collect();
        if words.len() != WORD_COUNT {
            return Err(VaultError::Phrase(PhraseError::WordCount(words.len())));
        }
        let mut indices = Zeroizing::new([0u16; WORD_COUNT]);
        for (pos, (slot, word)) in indices.iter_mut().zip(words.iter()).enumerate() {
            *slot = index_of(word).ok_or(VaultError::Phrase(PhraseError::UnknownWord(pos)))?;
        }
        let entropy = from_indices(&indices).map_err(VaultError::Phrase)?;
        Ok(RecoveryPhrase { entropy })
    }

    /// The 24 words separated by single spaces.
    pub fn to_words(&self) -> Zeroizing<String> {
        let indices = Zeroizing::new(to_indices(&self.entropy));
        let mut s = Zeroizing::new(String::with_capacity(WORD_COUNT.saturating_mul(9)));
        for (i, idx) in indices.iter().enumerate() {
            if i > 0 {
                s.push(' ');
            }
            s.push_str(word_at(*idx).unwrap_or("?"));
        }
        s
    }

    pub fn entropy(&self) -> &[u8; 32] {
        &self.entropy
    }

    fn derive(&self, info: &[u8]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        let mut out = Zeroizing::new([0u8; 32]);
        hirz_crypto::hkdf_sha256(
            b"hirz recovery",
            self.entropy.as_slice(),
            info,
            out.as_mut_slice(),
        )?;
        Ok(out)
    }

    /// X25519 private key that recovery slots are sealed to.
    pub(crate) fn x25519_private(&self) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        self.derive(INFO_X25519)
    }

    pub(crate) fn x25519_public(&self) -> Result<[u8; 32], VaultError> {
        Ok(hirz_crypto::x25519::public_key(&*self.x25519_private()?)?)
    }

    /// MAC key that authenticates the genesis generation.
    pub(crate) fn auth_key(&self) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        self.derive(INFO_AUTH)
    }

    /// Input key material for backup exports.
    pub(crate) fn backup_ikm(&self) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        self.derive(INFO_BACKUP)
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn wordlist_for_tests() -> &'static str {
    WORDLIST
}
