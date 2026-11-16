//! The only hirz crate that calls cryptographic libraries (aws-lc-rs, argon2).
//! Every other crate goes through this API so the crypto surface stays small and auditable.
//!
//! API contract: the function signatures below are relied on by other crates. Implementations
//! may change; signatures change only together with their callers.
#![forbid(unsafe_code)]

use zeroize::Zeroizing;

/// Secret bytes that are wiped on drop.
pub type Secret = Zeroizing<Vec<u8>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Malformed key, ciphertext, signature or parameter.
    Invalid,
    /// Authentication failed (AEAD tag, MAC, signature verification).
    Auth,
    /// The system random generator failed.
    Rng,
}

pub type Result<T> = core::result::Result<T, CryptoError>;

/// Fill `out` from the system CSPRNG.
pub fn random_fill(out: &mut [u8]) -> Result<()> {
    let _ = out;
    Err(CryptoError::Rng)
}

/// Constant-time equality.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let _ = (a, b);
    false
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let _ = data;
    [0u8; 32]
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let _ = (key, data);
    [0u8; 32]
}

/// HKDF-SHA-256 (RFC 5869). `out.len()` at most 255 * 32.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    let _ = (salt, ikm, info, out);
    Err(CryptoError::Invalid)
}

/// ES256 (ECDSA P-256 with SHA-256).
pub mod es256 {
    use super::{Result, Secret};

    /// Returns (PKCS#8 private key, uncompressed public point x, y).
    pub fn generate() -> Result<(Secret, [u8; 32], [u8; 32])> {
        Err(super::CryptoError::Rng)
    }
    /// ASN.1 DER signature over `msg` (WebAuthn wants DER for ES256).
    pub fn sign(pkcs8: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        let _ = (pkcs8, msg);
        Err(super::CryptoError::Invalid)
    }
    pub fn public_key(pkcs8: &[u8]) -> Result<([u8; 32], [u8; 32])> {
        let _ = pkcs8;
        Err(super::CryptoError::Invalid)
    }
    /// Verify a DER signature against an uncompressed point (tests and self-checks).
    pub fn verify(x: &[u8; 32], y: &[u8; 32], msg: &[u8], der_sig: &[u8]) -> Result<()> {
        let _ = (x, y, msg, der_sig);
        Err(super::CryptoError::Auth)
    }
    /// SubjectPublicKeyInfo DER for WebAuthn `getPublicKey()`.
    pub fn spki_der(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
        let _ = (x, y);
        Vec::new()
    }
}

/// Ed25519 (COSE EdDSA, alg -8).
pub mod ed25519 {
    use super::{Result, Secret};

    /// Returns (PKCS#8 private key, 32-byte public key).
    pub fn generate() -> Result<(Secret, [u8; 32])> {
        Err(super::CryptoError::Rng)
    }
    pub fn sign(pkcs8: &[u8], msg: &[u8]) -> Result<[u8; 64]> {
        let _ = (pkcs8, msg);
        Err(super::CryptoError::Invalid)
    }
    pub fn public_key(pkcs8: &[u8]) -> Result<[u8; 32]> {
        let _ = pkcs8;
        Err(super::CryptoError::Invalid)
    }
    pub fn verify(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<()> {
        let _ = (public, msg, sig);
        Err(super::CryptoError::Auth)
    }
    pub fn spki_der(public: &[u8; 32]) -> Vec<u8> {
        let _ = public;
        Vec::new()
    }
}

/// AES-256-GCM. Output layout of `seal`: 12-byte random nonce || ciphertext || 16-byte tag.
pub mod aead {
    use super::{Result, Secret};

    pub const KEY_LEN: usize = 32;
    pub const NONCE_LEN: usize = 12;
    pub const TAG_LEN: usize = 16;

    pub fn seal(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let _ = (key, aad, plaintext);
        Err(super::CryptoError::Invalid)
    }
    pub fn open(key: &[u8; KEY_LEN], aad: &[u8], sealed: &[u8]) -> Result<Secret> {
        let _ = (key, aad, sealed);
        Err(super::CryptoError::Auth)
    }
}

/// X25519 key agreement plus a small sealed-box construction for wrapping keys to a device:
/// ephemeral X25519, HKDF-SHA-256 over (shared || eph_pub || recipient_pub), AES-256-GCM.
pub mod x25519 {
    use super::{Result, Secret};

    /// Returns (32-byte private key, 32-byte public key).
    pub fn generate() -> Result<(Secret, [u8; 32])> {
        Err(super::CryptoError::Rng)
    }
    pub fn public_key(private: &[u8; 32]) -> Result<[u8; 32]> {
        let _ = private;
        Err(super::CryptoError::Invalid)
    }
    /// Output: 32-byte ephemeral public key || aead::seal output.
    pub fn seal_to(recipient: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let _ = (recipient, aad, plaintext);
        Err(super::CryptoError::Invalid)
    }
    pub fn open_from(private: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Secret> {
        let _ = (private, aad, sealed);
        Err(super::CryptoError::Auth)
    }
}

/// Primitives for the CTAP2 PIN/UV auth protocols (used for hmac-secret key agreement).
pub mod ctap_pin_uv {
    use super::{Result, Secret};

    /// Ephemeral P-256 key agreement key: (private handle bytes, public x, y).
    /// The private part is a PKCS#8 or raw scalar as the implementation needs; callers
    /// only pass it back to `ecdh`.
    pub fn generate() -> Result<(Secret, [u8; 32], [u8; 32])> {
        Err(super::CryptoError::Rng)
    }
    /// Raw ECDH x-coordinate (32 bytes) with the peer's uncompressed point.
    pub fn ecdh(private: &[u8], peer_x: &[u8; 32], peer_y: &[u8; 32]) -> Result<Secret> {
        let _ = (private, peer_x, peer_y);
        Err(super::CryptoError::Invalid)
    }
    /// AES-256-CBC without padding; `data.len()` must be a multiple of 16.
    pub fn aes256_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
        let _ = (key, iv, data);
        Err(super::CryptoError::Invalid)
    }
    pub fn aes256_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Result<Secret> {
        let _ = (key, iv, data);
        Err(super::CryptoError::Invalid)
    }
}

/// Argon2id password hashing (RFC 9106).
pub mod kdf {
    use super::{Result, Secret};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Argon2Params {
        pub m_cost_kib: u32,
        pub t_cost: u32,
        pub p_cost: u32,
    }

    /// RFC 9106 second recommended option: 64 MiB, t=3, p=4.
    pub const DEFAULT: Argon2Params = Argon2Params { m_cost_kib: 65536, t_cost: 3, p_cost: 4 };

    pub fn argon2id(password: &[u8], salt: &[u8], params: Argon2Params) -> Result<Secret> {
        let _ = (password, salt, params);
        Err(super::CryptoError::Invalid)
    }
}
