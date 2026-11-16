//! The only hirz crate that calls cryptographic libraries (aws-lc-rs, argon2).
//! Every other crate goes through this API so the crypto surface stays small and auditable.
#![forbid(unsafe_code)]

use aws_lc_rs::{constant_time, digest, hkdf, hmac, pbkdf2, rand as lc_rand};

pub use zeroize::{Zeroize, Zeroizing};

pub type Secret = Zeroizing<Vec<u8>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    Invalid,
    Auth,
    Rng,
}

pub type Result<T> = core::result::Result<T, CryptoError>;

pub fn random_fill(out: &mut [u8]) -> Result<()> {
    lc_rand::fill(out).map_err(|_| CryptoError::Rng)
}

/// Lengths are not secret: different lengths return false at once.
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

pub const HKDF_SHA256_MAX_OUT: usize = 255 * 32;

struct OutLen(usize);

impl hkdf::KeyType for OutLen {
    fn len(&self) -> usize {
        self.0
    }
}

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

/// Expand only: `prk` is used as the pseudorandom key, without an extract step.
pub fn hkdf_sha256_expand(prk: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    if prk.is_empty() || out.is_empty() || out.len() > HKDF_SHA256_MAX_OUT {
        return Err(CryptoError::Invalid);
    }
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, prk);
    let info_parts = [info];
    let okm = prk
        .expand(&info_parts, OutLen(out.len()))
        .map_err(|_| CryptoError::Invalid)?;
    okm.fill(out).map_err(|_| CryptoError::Invalid)
}

pub fn hmac_sha256_verify(key: &[u8], data: &[u8], tag: &[u8]) -> Result<()> {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::verify(&k, data, tag).map_err(|_| CryptoError::Auth)
}

/// Caps a count read from a hostile file so it cannot stall the caller.
pub const PBKDF2_MAX_ITERATIONS: u32 = 10_000_000;

/// Output 1 to 1024 bytes.
pub fn pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out_len: usize,
) -> Result<Secret> {
    let iterations = core::num::NonZeroU32::new(iterations)
        .filter(|i| i.get() <= PBKDF2_MAX_ITERATIONS)
        .ok_or(CryptoError::Invalid)?;
    if out_len == 0 || out_len > 1024 {
        return Err(CryptoError::Invalid);
    }
    let mut out = Zeroizing::new(vec![0u8; out_len]);
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        password,
        out.as_mut_slice(),
    );
    Ok(out)
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

pub mod es256 {
    use super::{CryptoError, Result, Secret};
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{self, EcdsaKeyPair, KeyPair};
    use zeroize::Zeroizing;

    /// DER prefix of a P-256 SubjectPublicKeyInfo; the uncompressed point 0x04 || x || y follows.
    const P256_SPKI_PREFIX: [u8; 27] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    ];

    fn load(pkcs8: &[u8]) -> Result<EcdsaKeyPair> {
        EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8)
            .map_err(|_| CryptoError::Invalid)
    }

    /// (PKCS#8 private key, x, y).
    pub fn generate() -> Result<(Secret, [u8; 32], [u8; 32])> {
        let kp = EcdsaKeyPair::generate(&signature::ECDSA_P256_SHA256_ASN1_SIGNING)
            .map_err(|_| CryptoError::Rng)?;
        let doc = kp.to_pkcs8v1().map_err(|_| CryptoError::Invalid)?;
        let (x, y) = super::split_point(kp.public_key().as_ref())?;
        Ok((Zeroizing::new(doc.as_ref().to_vec()), x, y))
    }
    /// ASN.1 DER signature, as WebAuthn requires for ES256.
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
    pub fn verify(x: &[u8; 32], y: &[u8; 32], msg: &[u8], der_sig: &[u8]) -> Result<()> {
        let point = super::uncompressed_point(x, y);
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &point)
            .verify(msg, der_sig)
            .map_err(|_| CryptoError::Auth)
    }
    pub fn spki_der(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(91);
        out.extend_from_slice(&P256_SPKI_PREFIX);
        out.extend_from_slice(x);
        out.extend_from_slice(y);
        out
    }
}

pub mod ed25519 {
    use super::{CryptoError, Result, Secret};
    use aws_lc_rs::signature::{self, Ed25519KeyPair, KeyPair};
    use zeroize::Zeroizing;

    /// DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410); the 32-byte key follows.
    const ED25519_SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];

    fn load(pkcs8: &[u8]) -> Result<Ed25519KeyPair> {
        Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| CryptoError::Invalid)
    }

    fn public_of(kp: &Ed25519KeyPair) -> Result<[u8; 32]> {
        <[u8; 32]>::try_from(kp.public_key().as_ref()).map_err(|_| CryptoError::Invalid)
    }

    pub fn generate() -> Result<(Secret, [u8; 32])> {
        let kp = Ed25519KeyPair::generate().map_err(|_| CryptoError::Rng)?;
        let doc = kp.to_pkcs8v1().map_err(|_| CryptoError::Invalid)?;
        Ok((Zeroizing::new(doc.as_ref().to_vec()), public_of(&kp)?))
    }
    pub fn pkcs8_from_seed(seed: &[u8; 32]) -> Result<Secret> {
        let kp = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| CryptoError::Invalid)?;
        let doc = kp.to_pkcs8v1().map_err(|_| CryptoError::Invalid)?;
        Ok(Zeroizing::new(doc.as_ref().to_vec()))
    }
    pub fn sign(pkcs8: &[u8], msg: &[u8]) -> Result<[u8; 64]> {
        let kp = load(pkcs8)?;
        let sig = kp.try_sign(msg).map_err(|_| CryptoError::Invalid)?;
        <[u8; 64]>::try_from(sig.as_ref()).map_err(|_| CryptoError::Invalid)
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

/// AES-256-GCM. `seal` output: 12-byte random nonce || ciphertext || 16-byte tag.
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

    /// A nonce must never repeat under one key; for known-answer tests only.
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
        // Reserved up front so no reallocation leaves plaintext behind.
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
        let (nonce, body) = sealed
            .split_first_chunk::<NONCE_LEN>()
            .ok_or(CryptoError::Auth)?;
        let lk = self::key(key)?;
        let mut buf = Zeroizing::new(body.to_vec());
        let pt_len = lk
            .open_in_place(
                Nonce::assume_unique_for_key(*nonce),
                Aad::from(aad),
                buf.as_mut_slice(),
            )
            .map_err(|_| CryptoError::Auth)?
            .len();
        buf.truncate(pt_len);
        Ok(buf)
    }
}

/// Sealed box for wrapping keys to a device; construction in docs/vault-format.md.
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
        <[u8; 32]>::try_from(pk.as_ref()).map_err(|_| CryptoError::Invalid)
    }

    /// Fails on an all-zero shared secret (small-order peer key).
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

    pub fn generate() -> Result<(Secret, [u8; 32])> {
        let mut private = Zeroizing::new([0u8; 32]);
        super::random_fill(private.as_mut_slice())?;
        let public = public_of(&load(&private)?)?;
        Ok((Zeroizing::new(private.to_vec()), public))
    }
    pub fn public_key(private: &[u8; 32]) -> Result<[u8; 32]> {
        public_of(&load(private)?)
    }
    pub fn seal_to(recipient: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let eph = PrivateKey::generate(&X25519).map_err(|_| CryptoError::Rng)?;
        let eph_pub = public_of(&eph)?;
        let shared = agree_with(&eph, recipient)?;
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
        let (eph_pub, body) = sealed.split_first_chunk::<32>().ok_or(CryptoError::Auth)?;
        let k = load(private)?;
        let own_pub = public_of(&k)?;
        let shared = agree_with(&k, eph_pub).map_err(|_| CryptoError::Auth)?;
        let key = seal_key(&shared, eph_pub, &own_pub)?;
        super::aead::open(&key, aad, body)
    }
}

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

    /// The private part is the raw 32-byte big-endian scalar; callers only pass it back to `ecdh`.
    pub fn generate() -> Result<(Secret, [u8; 32], [u8; 32])> {
        let k = PrivateKey::generate(&ECDH_P256).map_err(|_| CryptoError::Rng)?;
        let scalar: EcPrivateKeyBin<'static> = k.as_be_bytes().map_err(|_| CryptoError::Invalid)?;
        let public = k.compute_public_key().map_err(|_| CryptoError::Invalid)?;
        let (x, y) = super::split_point(public.as_ref())?;
        Ok((Zeroizing::new(scalar.as_ref().to_vec()), x, y))
    }
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
    /// No padding: `data.len()` must be a multiple of 16.
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

/// AES-256-CBC with PKCS#7 padding, then HMAC-SHA-256 over `iv || ciphertext`, as some
/// password manager exports use it.
pub mod aes_cbc_hmac {
    use super::{CryptoError, Result, Secret};
    use aws_lc_rs::cipher::{
        AES_256, DecryptionContext, EncryptionContext, PaddedBlockDecryptingKey,
        PaddedBlockEncryptingKey, UnboundCipherKey,
    };
    use aws_lc_rs::hmac;
    use aws_lc_rs::iv::FixedLength;
    use zeroize::Zeroizing;

    pub const KEY_LEN: usize = 32;
    pub const IV_LEN: usize = 16;
    pub const TAG_LEN: usize = 32;

    fn tag(mac_key: &[u8; KEY_LEN], iv: &[u8], ciphertext: &[u8]) -> hmac::Tag {
        let mut ctx = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA256, mac_key));
        ctx.update(iv);
        ctx.update(ciphertext);
        ctx.sign()
    }

    /// Returns (iv, ciphertext, tag).
    pub fn seal(
        enc_key: &[u8; KEY_LEN],
        mac_key: &[u8; KEY_LEN],
        plaintext: &[u8],
    ) -> Result<([u8; IV_LEN], Vec<u8>, [u8; TAG_LEN])> {
        let mut iv = [0u8; IV_LEN];
        super::random_fill(&mut iv)?;
        let k = UnboundCipherKey::new(&AES_256, enc_key).map_err(|_| CryptoError::Invalid)?;
        let ek = PaddedBlockEncryptingKey::cbc_pkcs7(k).map_err(|_| CryptoError::Invalid)?;
        let mut buf = plaintext.to_vec();
        ek.less_safe_encrypt(&mut buf, EncryptionContext::Iv128(FixedLength::from(iv)))
            .map_err(|_| CryptoError::Invalid)?;
        let t = tag(mac_key, &iv, &buf);
        Ok((iv, buf, super::to_array(t.as_ref())))
    }

    /// Verifies the tag in constant time before decrypting.
    pub fn open(
        enc_key: &[u8; KEY_LEN],
        mac_key: &[u8; KEY_LEN],
        iv: &[u8; IV_LEN],
        ciphertext: &[u8],
        mac: &[u8],
    ) -> Result<Secret> {
        let expected = tag(mac_key, iv, ciphertext);
        if !super::ct_eq(expected.as_ref(), mac) {
            return Err(CryptoError::Auth);
        }
        if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
            return Err(CryptoError::Invalid);
        }
        let k = UnboundCipherKey::new(&AES_256, enc_key).map_err(|_| CryptoError::Invalid)?;
        let dk = PaddedBlockDecryptingKey::cbc_pkcs7(k).map_err(|_| CryptoError::Invalid)?;
        let mut buf = Zeroizing::new(ciphertext.to_vec());
        let len = dk
            .decrypt(
                buf.as_mut_slice(),
                DecryptionContext::Iv128(FixedLength::from(*iv)),
            )
            .map_err(|_| CryptoError::Invalid)?
            .len();
        buf.truncate(len);
        Ok(buf)
    }
}

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

    pub const OUTPUT_LEN: usize = 32;

    pub fn within_limits(params: Argon2Params) -> bool {
        params.m_cost_kib <= LIMIT.m_cost_kib
            && params.t_cost <= LIMIT.t_cost
            && params.p_cost <= LIMIT.p_cost
    }

    pub fn argon2id(password: &[u8], salt: &[u8], params: Argon2Params) -> Result<Secret> {
        argon2id_full(password, salt, &[], &[], params, OUTPUT_LEN)
    }

    /// Argon2id with the optional secret value K and associated data X of RFC 9106.
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
