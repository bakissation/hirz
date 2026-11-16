//! The only hirz crate that calls cryptographic libraries (aws-lc-rs, argon2).
//! Every other crate goes through this API so the crypto surface stays small and auditable.
//!
//! API contract: the function signatures below are relied on by other crates. Implementations
//! may change; signatures change only together with their callers.
#![forbid(unsafe_code)]

use aws_lc_rs::{constant_time, digest, hkdf, hmac, rand as lc_rand};

/// Re-exported so crates without a direct zeroize dependency can hold secrets.
pub use zeroize::{Zeroize, Zeroizing};

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
    lc_rand::fill(out).map_err(|_| CryptoError::Rng)
}

/// Constant-time equality. Lengths are not secret: different lengths return false at once.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && constant_time::verify_slices_are_equal(a, b).is_ok()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, data);
    to_array(d.as_ref())
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&k, data);
    to_array(tag.as_ref())
}

/// Maximum HKDF-SHA-256 output length (RFC 5869: 255 * HashLen).
pub const HKDF_SHA256_MAX_OUT: usize = 255 * 32;

struct OutLen(usize);

impl hkdf::KeyType for OutLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-SHA-256 (RFC 5869). `out.len()` at most 255 * 32.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    if out.is_empty() || out.len() > HKDF_SHA256_MAX_OUT {
        return Err(CryptoError::Invalid);
    }
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(ikm);
    let info_parts = [info];
    let okm = prk
        .expand(&info_parts, OutLen(out.len()))
        .map_err(|_| CryptoError::Invalid)?;
    okm.fill(out).map_err(|_| CryptoError::Invalid)
}

fn to_array(src: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (o, s) in out.iter_mut().zip(src.iter()) {
        *o = *s;
    }
    out
}

fn split_point(point: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    match point {
        [0x04, rest @ ..] if rest.len() == 64 => {
            let (x, y) = rest.split_at(32);
            Ok((to_array(x), to_array(y)))
        }
        _ => Err(CryptoError::Invalid),
    }
}

fn uncompressed_point(x: &[u8; 32], y: &[u8; 32]) -> [u8; 65] {
    let mut p = [0u8; 65];
    let (head, rest) = p.split_at_mut(1);
    let (px, py) = rest.split_at_mut(32);
    head.copy_from_slice(&[0x04]);
    px.copy_from_slice(x);
    py.copy_from_slice(y);
    p
}

/// ES256 (ECDSA P-256 with SHA-256).
pub mod es256 {
    use super::{CryptoError, Result, Secret};
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{self, EcdsaKeyPair, KeyPair};
    use zeroize::Zeroizing;

    /// DER prefix of a P-256 SubjectPublicKeyInfo: SEQUENCE { SEQUENCE { id-ecPublicKey,
    /// prime256v1 }, BIT STRING (0 unused bits) 0x04 }; x and y follow.
    const P256_SPKI_PREFIX: [u8; 27] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    ];

    fn load(pkcs8: &[u8]) -> Result<EcdsaKeyPair> {
        EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8)
            .map_err(|_| CryptoError::Invalid)
    }

    /// Returns (PKCS#8 private key, uncompressed public point x, y).
    pub fn generate() -> Result<(Secret, [u8; 32], [u8; 32])> {
        let kp = EcdsaKeyPair::generate(&signature::ECDSA_P256_SHA256_ASN1_SIGNING)
            .map_err(|_| CryptoError::Rng)?;
        let doc = kp.to_pkcs8v1().map_err(|_| CryptoError::Invalid)?;
        let (x, y) = super::split_point(kp.public_key().as_ref())?;
        Ok((Zeroizing::new(doc.as_ref().to_vec()), x, y))
    }
    /// ASN.1 DER signature over `msg` (WebAuthn wants DER for ES256).
    pub fn sign(pkcs8: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        let kp = load(pkcs8)?;
        let sig = kp
            .sign(&SystemRandom::new(), msg)
            .map_err(|_| CryptoError::Invalid)?;
        Ok(sig.as_ref().to_vec())
    }
    pub fn public_key(pkcs8: &[u8]) -> Result<([u8; 32], [u8; 32])> {
        let kp = load(pkcs8)?;
        super::split_point(kp.public_key().as_ref())
    }
    /// Verify a DER signature against an uncompressed point (tests and self-checks).
    pub fn verify(x: &[u8; 32], y: &[u8; 32], msg: &[u8], der_sig: &[u8]) -> Result<()> {
        let point = super::uncompressed_point(x, y);
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &point)
            .verify(msg, der_sig)
            .map_err(|_| CryptoError::Auth)
    }
    /// SubjectPublicKeyInfo DER for WebAuthn `getPublicKey()`.
    pub fn spki_der(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(91);
        out.extend_from_slice(&P256_SPKI_PREFIX);
        out.extend_from_slice(x);
        out.extend_from_slice(y);
        out
    }
}

/// Ed25519 (COSE EdDSA, alg -8).
pub mod ed25519 {
    use super::{CryptoError, Result, Secret};
    use aws_lc_rs::signature::{self, Ed25519KeyPair, KeyPair};
    use zeroize::Zeroizing;

    /// DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410): SEQUENCE { SEQUENCE {
    /// id-Ed25519 }, BIT STRING (0 unused bits) }; the 32-byte key follows.
    const ED25519_SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];

    fn load(pkcs8: &[u8]) -> Result<Ed25519KeyPair> {
        Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| CryptoError::Invalid)
    }

    fn public_of(kp: &Ed25519KeyPair) -> Result<[u8; 32]> {
        let pk = kp.public_key().as_ref();
        if pk.len() != 32 {
            return Err(CryptoError::Invalid);
        }
        Ok(super::to_array(pk))
    }

    /// Returns (PKCS#8 private key, 32-byte public key).
    pub fn generate() -> Result<(Secret, [u8; 32])> {
        let kp = Ed25519KeyPair::generate().map_err(|_| CryptoError::Rng)?;
        let doc = kp.to_pkcs8v1().map_err(|_| CryptoError::Invalid)?;
        Ok((Zeroizing::new(doc.as_ref().to_vec()), public_of(&kp)?))
    }
    /// PKCS#8 v1 document for a 32-byte RFC 8032 seed (import and test vectors).
    pub fn pkcs8_from_seed(seed: &[u8; 32]) -> Result<Secret> {
        let kp = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| CryptoError::Invalid)?;
        let doc = kp.to_pkcs8v1().map_err(|_| CryptoError::Invalid)?;
        Ok(Zeroizing::new(doc.as_ref().to_vec()))
    }
    pub fn sign(pkcs8: &[u8], msg: &[u8]) -> Result<[u8; 64]> {
        let kp = load(pkcs8)?;
        let sig = kp.try_sign(msg).map_err(|_| CryptoError::Invalid)?;
        let bytes = sig.as_ref();
        if bytes.len() != 64 {
            return Err(CryptoError::Invalid);
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(bytes);
        Ok(out)
    }
    pub fn public_key(pkcs8: &[u8]) -> Result<[u8; 32]> {
        public_of(&load(pkcs8)?)
    }
    pub fn verify(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<()> {
        signature::UnparsedPublicKey::new(&signature::ED25519, public)
            .verify(msg, sig)
            .map_err(|_| CryptoError::Auth)
    }
    pub fn spki_der(public: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(44);
        out.extend_from_slice(&ED25519_SPKI_PREFIX);
        out.extend_from_slice(public);
        out
    }
}

/// AES-256-GCM. Output layout of `seal`: 12-byte random nonce || ciphertext || 16-byte tag.
pub mod aead {
    use super::{CryptoError, Result, Secret};
    use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    use zeroize::Zeroizing;

    pub const KEY_LEN: usize = 32;
    pub const NONCE_LEN: usize = 12;
    pub const TAG_LEN: usize = 16;

    fn key(k: &[u8; KEY_LEN]) -> Result<LessSafeKey> {
        let unbound = UnboundKey::new(&AES_256_GCM, k).map_err(|_| CryptoError::Invalid)?;
        Ok(LessSafeKey::new(unbound))
    }

    pub fn seal(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        super::random_fill(&mut nonce)?;
        seal_with_nonce(key, &nonce, aad, plaintext)
    }

    /// Deterministic variant for known-answer tests. A nonce must never repeat under one key.
    pub fn seal_with_nonce(
        k: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let lk = key(k)?;
        let cap = plaintext
            .len()
            .checked_add(NONCE_LEN + TAG_LEN)
            .ok_or(CryptoError::Invalid)?;
        // Capacity is reserved up front so no reallocation leaves plaintext behind.
        let mut out = Vec::with_capacity(cap);
        out.extend_from_slice(nonce);
        out.extend_from_slice(plaintext);
        let body = out.get_mut(NONCE_LEN..).ok_or(CryptoError::Invalid)?;
        let tag = lk
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(*nonce), Aad::from(aad), body)
            .map_err(|_| CryptoError::Invalid)?;
        out.extend_from_slice(tag.as_ref());
        Ok(out)
    }

    pub fn open(key: &[u8; KEY_LEN], aad: &[u8], sealed: &[u8]) -> Result<Secret> {
        if sealed.len() < NONCE_LEN + TAG_LEN {
            return Err(CryptoError::Auth);
        }
        let (nonce_bytes, body) = sealed.split_at(NONCE_LEN);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(nonce_bytes);
        let lk = self::key(key)?;
        let mut buf = Zeroizing::new(body.to_vec());
        let pt_len = lk
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                buf.as_mut_slice(),
            )
            .map_err(|_| CryptoError::Auth)?
            .len();
        buf.truncate(pt_len);
        Ok(buf)
    }
}

/// X25519 key agreement plus a small sealed-box construction for wrapping keys to a device:
/// ephemeral X25519, HKDF-SHA-256 over (shared || eph_pub || recipient_pub), AES-256-GCM.
///
/// Exact construction: key = HKDF-SHA-256(salt = empty, ikm = X25519(eph, recipient),
/// info = "hirz x25519 seal v1" || eph_pub || recipient_pub, L = 32); output =
/// eph_pub || nonce || ciphertext || tag.
pub mod x25519 {
    use super::{CryptoError, Result, Secret};
    use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
    use zeroize::Zeroizing;

    const SEAL_INFO: &[u8] = b"hirz x25519 seal v1";

    fn load(private: &[u8; 32]) -> Result<PrivateKey> {
        PrivateKey::from_private_key(&X25519, private).map_err(|_| CryptoError::Invalid)
    }

    fn public_of(k: &PrivateKey) -> Result<[u8; 32]> {
        let pk = k.compute_public_key().map_err(|_| CryptoError::Invalid)?;
        if pk.as_ref().len() != 32 {
            return Err(CryptoError::Invalid);
        }
        Ok(super::to_array(pk.as_ref()))
    }

    /// Raw X25519 (RFC 7748). Fails on an all-zero shared secret (small-order peer key).
    pub fn agree(private: &[u8; 32], peer: &[u8; 32]) -> Result<Secret> {
        agree_with(&load(private)?, peer)
    }

    fn agree_with(k: &PrivateKey, peer: &[u8; 32]) -> Result<Secret> {
        let shared = agreement::agree(
            k,
            UnparsedPublicKey::new(&X25519, peer),
            CryptoError::Invalid,
            |s| Ok(Zeroizing::new(s.to_vec())),
        )?;
        if shared.len() != 32 || shared.iter().all(|b| *b == 0) {
            return Err(CryptoError::Invalid);
        }
        Ok(shared)
    }

    fn seal_key(
        shared: &[u8],
        eph_pub: &[u8; 32],
        recipient: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>> {
        let mut info = Vec::with_capacity(SEAL_INFO.len().saturating_add(64));
        info.extend_from_slice(SEAL_INFO);
        info.extend_from_slice(eph_pub);
        info.extend_from_slice(recipient);
        let mut key = Zeroizing::new([0u8; 32]);
        super::hkdf_sha256(&[], shared, &info, key.as_mut_slice())?;
        Ok(key)
    }

    /// Returns (32-byte private key, 32-byte public key).
    pub fn generate() -> Result<(Secret, [u8; 32])> {
        let mut private = Zeroizing::new([0u8; 32]);
        super::random_fill(private.as_mut_slice())?;
        let public = public_of(&load(&private)?)?;
        Ok((Zeroizing::new(private.to_vec()), public))
    }
    pub fn public_key(private: &[u8; 32]) -> Result<[u8; 32]> {
        public_of(&load(private)?)
    }
    /// Output: 32-byte ephemeral public key || aead::seal output.
    pub fn seal_to(recipient: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let (eph_private, eph_pub) = generate()?;
        let eph_arr: Zeroizing<[u8; 32]> = Zeroizing::new(super::to_array(&eph_private));
        let shared = agree(&eph_arr, recipient)?;
        let key = seal_key(&shared, &eph_pub, recipient)?;
        let sealed = super::aead::seal(&key, aad, plaintext)?;
        let mut out = Vec::with_capacity(sealed.len().saturating_add(32));
        out.extend_from_slice(&eph_pub);
        out.extend_from_slice(&sealed);
        Ok(out)
    }
    pub fn open_from(private: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Secret> {
        if sealed.len() < 32 + super::aead::NONCE_LEN + super::aead::TAG_LEN {
            return Err(CryptoError::Auth);
        }
        let (eph, body) = sealed.split_at(32);
        let eph_pub = super::to_array(eph);
        let k = load(private)?;
        let own_pub = public_of(&k)?;
        let shared = agree_with(&k, &eph_pub).map_err(|_| CryptoError::Auth)?;
        let key = seal_key(&shared, &eph_pub, &own_pub)?;
        super::aead::open(&key, aad, body)
    }
}

/// Primitives for the CTAP2 PIN/UV auth protocols (used for hmac-secret key agreement).
pub mod ctap_pin_uv {
    use super::{CryptoError, Result, Secret};
    use aws_lc_rs::agreement::{self, ECDH_P256, PrivateKey, UnparsedPublicKey};
    use aws_lc_rs::cipher::{
        AES_256, DecryptingKey, DecryptionContext, EncryptingKey, EncryptionContext,
        UnboundCipherKey,
    };
    use aws_lc_rs::encoding::{AsBigEndian, EcPrivateKeyBin};
    use aws_lc_rs::iv::FixedLength;
    use zeroize::Zeroizing;

    /// Ephemeral P-256 key agreement key: (private handle bytes, public x, y).
    /// The private part is a PKCS#8 or raw scalar as the implementation needs; callers
    /// only pass it back to `ecdh`.
    ///
    /// This implementation returns the raw 32-byte big-endian scalar.
    pub fn generate() -> Result<(Secret, [u8; 32], [u8; 32])> {
        let k = PrivateKey::generate(&ECDH_P256).map_err(|_| CryptoError::Rng)?;
        let scalar: EcPrivateKeyBin<'static> = k.as_be_bytes().map_err(|_| CryptoError::Invalid)?;
        let public = k.compute_public_key().map_err(|_| CryptoError::Invalid)?;
        let (x, y) = super::split_point(public.as_ref())?;
        Ok((Zeroizing::new(scalar.as_ref().to_vec()), x, y))
    }
    /// Raw ECDH x-coordinate (32 bytes) with the peer's uncompressed point.
    pub fn ecdh(private: &[u8], peer_x: &[u8; 32], peer_y: &[u8; 32]) -> Result<Secret> {
        let k =
            PrivateKey::from_private_key(&ECDH_P256, private).map_err(|_| CryptoError::Invalid)?;
        let point = super::uncompressed_point(peer_x, peer_y);
        agreement::agree(
            &k,
            UnparsedPublicKey::new(&ECDH_P256, &point),
            CryptoError::Invalid,
            |s| Ok(Zeroizing::new(s.to_vec())),
        )
    }
    /// AES-256-CBC without padding; `data.len()` must be a multiple of 16.
    pub fn aes256_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
        if !data.len().is_multiple_of(16) {
            return Err(CryptoError::Invalid);
        }
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let k = UnboundCipherKey::new(&AES_256, key).map_err(|_| CryptoError::Invalid)?;
        let ek = EncryptingKey::cbc(k).map_err(|_| CryptoError::Invalid)?;
        let mut buf = data.to_vec();
        ek.less_safe_encrypt(&mut buf, EncryptionContext::Iv128(FixedLength::from(*iv)))
            .map_err(|_| CryptoError::Invalid)?;
        Ok(buf)
    }
    pub fn aes256_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Result<Secret> {
        if !data.len().is_multiple_of(16) {
            return Err(CryptoError::Invalid);
        }
        if data.is_empty() {
            return Ok(Zeroizing::new(Vec::new()));
        }
        let k = UnboundCipherKey::new(&AES_256, key).map_err(|_| CryptoError::Invalid)?;
        let dk = DecryptingKey::cbc(k).map_err(|_| CryptoError::Invalid)?;
        let mut buf = Zeroizing::new(data.to_vec());
        dk.decrypt(
            buf.as_mut_slice(),
            DecryptionContext::Iv128(FixedLength::from(*iv)),
        )
        .map_err(|_| CryptoError::Invalid)?;
        Ok(buf)
    }
}

/// Argon2id password hashing (RFC 9106).
pub mod kdf {
    use super::{CryptoError, Result, Secret};
    use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
    use zeroize::Zeroizing;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Argon2Params {
        pub m_cost_kib: u32,
        pub t_cost: u32,
        pub p_cost: u32,
    }

    /// RFC 9106 second recommended option: 64 MiB, t=3, p=4.
    pub const DEFAULT: Argon2Params = Argon2Params {
        m_cost_kib: 65536,
        t_cost: 3,
        p_cost: 4,
    };

    /// Upper bounds accepted by this crate, so parameters read from a hostile file cannot
    /// force a denial of service: 4 GiB, 64 passes, 64 lanes.
    pub const LIMIT: Argon2Params = Argon2Params {
        m_cost_kib: 4 * 1024 * 1024,
        t_cost: 64,
        p_cost: 64,
    };

    /// Output length of `argon2id`.
    pub const OUTPUT_LEN: usize = 32;

    pub fn within_limits(params: Argon2Params) -> bool {
        params.m_cost_kib <= LIMIT.m_cost_kib
            && params.t_cost <= LIMIT.t_cost
            && params.p_cost <= LIMIT.p_cost
    }

    /// Argon2id v1.3 with a 32-byte output.
    pub fn argon2id(password: &[u8], salt: &[u8], params: Argon2Params) -> Result<Secret> {
        argon2id_full(password, salt, &[], &[], params, OUTPUT_LEN)
    }

    /// Argon2id v1.3 with the optional secret value K and associated data X of RFC 9106.
    pub fn argon2id_full(
        password: &[u8],
        salt: &[u8],
        secret: &[u8],
        associated_data: &[u8],
        params: Argon2Params,
        out_len: usize,
    ) -> Result<Secret> {
        if !within_limits(params) || out_len == 0 || out_len > 1024 {
            return Err(CryptoError::Invalid);
        }
        let ad = AssociatedData::new(associated_data).map_err(|_| CryptoError::Invalid)?;
        let p = ParamsBuilder::new()
            .m_cost(params.m_cost_kib)
            .t_cost(params.t_cost)
            .p_cost(params.p_cost)
            .data(ad)
            .output_len(out_len)
            .build()
            .map_err(|_| CryptoError::Invalid)?;
        let ctx = if secret.is_empty() {
            Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
        } else {
            Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, p)
                .map_err(|_| CryptoError::Invalid)?
        };
        let mut out = Zeroizing::new(vec![0u8; out_len]);
        ctx.hash_password_into(password, salt, out.as_mut_slice())
            .map_err(|_| CryptoError::Invalid)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
