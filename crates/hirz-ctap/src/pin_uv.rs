//! PIN/UV auth protocols one and two (CTAP 2.2 sections 6.5.6 and 6.5.7), limited to what
//! hmac-secret needs: the authenticator key-agreement key, shared-secret derivation,
//! encrypt, decrypt, authenticate and verify. hirz has no clientPin and issues no
//! pinUvAuthToken.

use core::fmt;

use hirz_core::{CoreError, HmacSecretSalts, HmacSecretWrap};
use hirz_crypto::{CryptoError, Secret, Zeroizing, ctap_pin_uv};
use hirz_proto::cose::KeyAgreementKey;

use crate::status::Status;

const AES_BLOCK: usize = 16;
const PROTOCOL_ONE_MAC_LEN: usize = 16;
const PROTOCOL_TWO_SALT: [u8; 32] = [0u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinUvAuthProtocol {
    One = 1,
    Two = 2,
}

impl PinUvAuthProtocol {
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            1 => Some(Self::One),
            2 => Some(Self::Two),
            _ => None,
        }
    }

    pub fn number(self) -> u64 {
        self as u64
    }

    fn index(self) -> usize {
        match self {
            Self::One => 0,
            Self::Two => 1,
        }
    }
}

/// The result of `kdf(Z)`: 32 bytes for protocol one, HMAC key followed by AES key (64
/// bytes) for protocol two.
pub struct SharedSecret {
    protocol: PinUvAuthProtocol,
    key: Secret,
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedSecret")
            .field("protocol", &self.protocol)
            .finish_non_exhaustive()
    }
}

fn key32(bytes: &[u8]) -> Result<&[u8; 32], CryptoError> {
    <&[u8; 32]>::try_from(bytes).map_err(|_| CryptoError::Invalid)
}

impl SharedSecret {
    /// `kdf(Z)` for the given protocol, where `z` is the ECDH x coordinate.
    pub fn from_z(protocol: PinUvAuthProtocol, z: &[u8]) -> Result<Self, CryptoError> {
        let key = match protocol {
            PinUvAuthProtocol::One => Zeroizing::new(hirz_crypto::sha256(z).to_vec()),
            PinUvAuthProtocol::Two => {
                let mut out = Zeroizing::new(vec![0u8; 64]);
                let (hmac_key, aes_key) = out.split_at_mut(32);
                hirz_crypto::hkdf_sha256(&PROTOCOL_TWO_SALT, z, b"CTAP2 HMAC key", hmac_key)?;
                hirz_crypto::hkdf_sha256(&PROTOCOL_TWO_SALT, z, b"CTAP2 AES key", aes_key)?;
                out
            }
        };
        Ok(Self { protocol, key })
    }

    pub fn protocol(&self) -> PinUvAuthProtocol {
        self.protocol
    }

    fn hmac_key(&self) -> &[u8] {
        match self.protocol {
            PinUvAuthProtocol::One => &self.key,
            PinUvAuthProtocol::Two => self.key.get(..32).unwrap_or(&[]),
        }
    }

    fn aes_key(&self) -> Result<&[u8; 32], CryptoError> {
        match self.protocol {
            PinUvAuthProtocol::One => key32(&self.key),
            PinUvAuthProtocol::Two => key32(self.key.get(32..).unwrap_or(&[])),
        }
    }

    /// Protocol one: AES-256-CBC with a zero IV. Protocol two: a random IV, prepended.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let key = self.aes_key()?;
        match self.protocol {
            PinUvAuthProtocol::One => {
                ctap_pin_uv::aes256_cbc_encrypt(key, &[0u8; AES_BLOCK], plaintext)
            }
            PinUvAuthProtocol::Two => {
                let mut iv = [0u8; AES_BLOCK];
                hirz_crypto::random_fill(&mut iv)?;
                let ct = ctap_pin_uv::aes256_cbc_encrypt(key, &iv, plaintext)?;
                let mut out = Vec::with_capacity(AES_BLOCK.saturating_add(ct.len()));
                out.extend_from_slice(&iv);
                out.extend_from_slice(&ct);
                Ok(out)
            }
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Secret, CryptoError> {
        let key = self.aes_key()?;
        match self.protocol {
            PinUvAuthProtocol::One => {
                ctap_pin_uv::aes256_cbc_decrypt(key, &[0u8; AES_BLOCK], ciphertext)
            }
            PinUvAuthProtocol::Two => {
                let (iv, ct) = ciphertext
                    .split_first_chunk::<AES_BLOCK>()
                    .ok_or(CryptoError::Invalid)?;
                ctap_pin_uv::aes256_cbc_decrypt(key, iv, ct)
            }
        }
    }

    /// Protocol one: the first 16 bytes of HMAC-SHA-256. Protocol two: all 32 bytes.
    pub fn authenticate(&self, message: &[u8]) -> Vec<u8> {
        let mac = hirz_crypto::hmac_sha256(self.hmac_key(), message);
        match self.protocol {
            PinUvAuthProtocol::One => mac.get(..PROTOCOL_ONE_MAC_LEN).unwrap_or(&[]).to_vec(),
            PinUvAuthProtocol::Two => mac.to_vec(),
        }
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        hirz_crypto::ct_eq(&self.authenticate(message), signature)
    }
}

struct KeyPair {
    private: Secret,
    x: [u8; 32],
    y: [u8; 32],
}

impl KeyPair {
    fn generate() -> Result<Self, CryptoError> {
        let (private, x, y) = ctap_pin_uv::generate()?;
        Ok(Self { private, x, y })
    }
}

/// The authenticator key-agreement keys, one per protocol. They live for the process
/// lifetime (one "power cycle" of the virtual device) and are created on first use.
#[derive(Default)]
pub struct KeyAgreementKeys {
    keys: [Option<KeyPair>; 2],
}

impl fmt::Debug for KeyAgreementKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyAgreementKeys").finish_non_exhaustive()
    }
}

impl KeyAgreementKeys {
    pub fn new() -> Self {
        Self::default()
    }

    fn pair(&mut self, protocol: PinUvAuthProtocol) -> Result<&KeyPair, CryptoError> {
        let slot = self
            .keys
            .get_mut(protocol.index())
            .ok_or(CryptoError::Invalid)?;
        if slot.is_none() {
            *slot = Some(KeyPair::generate()?);
        }
        slot.as_ref().ok_or(CryptoError::Invalid)
    }

    /// `getPublicKey()`: the x and y coordinates of the protocol's P-256 key.
    pub fn public_key(
        &mut self,
        protocol: PinUvAuthProtocol,
    ) -> Result<([u8; 32], [u8; 32]), CryptoError> {
        let pair = self.pair(protocol)?;
        Ok((pair.x, pair.y))
    }

    /// `decapsulate(peerCoseKey)`: ECDH with the platform key, then `kdf(Z)`.
    pub fn shared_secret(
        &mut self,
        protocol: PinUvAuthProtocol,
        peer: &KeyAgreementKey,
    ) -> Result<SharedSecret, CryptoError> {
        let pair = self.pair(protocol)?;
        let z = ctap_pin_uv::ecdh(&pair.private, &peer.x, &peer.y)?;
        SharedSecret::from_z(protocol, &z)
    }

    /// Forgets every key; the next use creates fresh ones.
    pub fn regenerate(&mut self) {
        self.keys = Default::default();
    }
}

/// Encrypts the engine's hmac-secret output for the platform before it is embedded in
/// authenticatorData.
#[derive(Debug)]
pub struct HmacSecretWrapper {
    secret: SharedSecret,
}

impl HmacSecretWrapper {
    pub fn new(secret: SharedSecret) -> Self {
        Self { secret }
    }
}

impl HmacSecretWrap for HmacSecretWrapper {
    fn wrap(&self, output: &[u8]) -> Result<Vec<u8>, CoreError> {
        if output.len() != 32 && output.len() != 64 {
            return Err(CoreError::InvalidRequest("hmac-secret output length"));
        }
        self.secret
            .encrypt(output)
            .map_err(|e| CoreError::Crypto(format!("hmac-secret encrypt: {e:?}")))
    }
}

/// Checks `saltAuth` over `saltEnc`, then decrypts one or two 32-byte salts.
pub fn decrypt_salts(
    secret: &SharedSecret,
    salt_enc: &[u8],
    salt_auth: &[u8],
) -> Result<HmacSecretSalts, Status> {
    if !secret.verify(salt_enc, salt_auth) {
        return Err(Status::PinAuthInvalid);
    }
    let plain = secret
        .decrypt(salt_enc)
        .map_err(|_| Status::InvalidLength)?;
    let first = |s: &[u8]| <[u8; 32]>::try_from(s).map_err(|_| Status::InvalidLength);
    match plain.len() {
        32 => Ok(HmacSecretSalts {
            salt1: first(&plain)?,
            salt2: None,
        }),
        64 => {
            let (a, b) = plain.split_at(32);
            Ok(HmacSecretSalts {
                salt1: first(a)?,
                salt2: Some(first(b)?),
            })
        }
        _ => Err(Status::InvalidLength),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn platform_secret(
        keys: &mut KeyAgreementKeys,
        protocol: PinUvAuthProtocol,
    ) -> (KeyAgreementKey, SharedSecret) {
        let (ax, ay) = keys.public_key(protocol).unwrap();
        let (private, x, y) = ctap_pin_uv::generate().unwrap();
        let z = ctap_pin_uv::ecdh(&private, &ax, &ay).unwrap();
        (
            KeyAgreementKey { x, y },
            SharedSecret::from_z(protocol, &z).unwrap(),
        )
    }

    #[test]
    fn both_sides_derive_the_same_secret() {
        for protocol in [PinUvAuthProtocol::One, PinUvAuthProtocol::Two] {
            let mut keys = KeyAgreementKeys::new();
            let (peer, platform) = platform_secret(&mut keys, protocol);
            let auth = keys.shared_secret(protocol, &peer).unwrap();
            assert_eq!(*auth.key, *platform.key);
            let expected_len = match protocol {
                PinUvAuthProtocol::One => 32,
                PinUvAuthProtocol::Two => 64,
            };
            assert_eq!(auth.key.len(), expected_len);
            let ct = platform.encrypt(&[7u8; 64]).unwrap();
            assert_eq!(*auth.decrypt(&ct).unwrap(), vec![7u8; 64]);
            let mac = platform.authenticate(&ct);
            assert!(auth.verify(&ct, &mac));
            assert!(!auth.verify(&ct, &mac[..mac.len() - 1]));
        }
    }

    #[test]
    fn protocol_one_uses_a_zero_iv_and_short_mac() {
        let s = SharedSecret::from_z(PinUvAuthProtocol::One, &[1u8; 32]).unwrap();
        assert_eq!(*s.key, hirz_crypto::sha256(&[1u8; 32]).to_vec());
        let ct = s.encrypt(&[0u8; 32]).unwrap();
        assert_eq!(ct.len(), 32);
        assert_eq!(ct, s.encrypt(&[0u8; 32]).unwrap());
        assert_eq!(s.authenticate(b"m").len(), 16);
        assert_eq!(
            s.authenticate(b"m"),
            hirz_crypto::hmac_sha256(&s.key, b"m")[..16].to_vec()
        );
    }

    #[test]
    fn protocol_two_splits_keys_and_prepends_iv() {
        let z = [9u8; 32];
        let s = SharedSecret::from_z(PinUvAuthProtocol::Two, &z).unwrap();
        let mut hmac_key = [0u8; 32];
        let mut aes_key = [0u8; 32];
        hirz_crypto::hkdf_sha256(&[0u8; 32], &z, b"CTAP2 HMAC key", &mut hmac_key).unwrap();
        hirz_crypto::hkdf_sha256(&[0u8; 32], &z, b"CTAP2 AES key", &mut aes_key).unwrap();
        assert_eq!(&s.key[..32], &hmac_key);
        assert_eq!(&s.key[32..], &aes_key);
        assert_eq!(
            s.authenticate(b"m"),
            hirz_crypto::hmac_sha256(&hmac_key, b"m").to_vec()
        );
        let ct = s.encrypt(&[0u8; 32]).unwrap();
        assert_eq!(ct.len(), 48);
        let iv: [u8; 16] = ct[..16].try_into().unwrap();
        let plain = ctap_pin_uv::aes256_cbc_decrypt(&aes_key, &iv, &ct[16..]).unwrap();
        assert_eq!(*plain, vec![0u8; 32]);
        assert!(s.decrypt(&ct[..15]).is_err());
    }

    #[test]
    fn salts_need_a_valid_mac_and_length() {
        let s = SharedSecret::from_z(PinUvAuthProtocol::Two, &[3u8; 32]).unwrap();
        let enc = s.encrypt(&[5u8; 64]).unwrap();
        let auth = s.authenticate(&enc);
        let salts = decrypt_salts(&s, &enc, &auth).unwrap();
        assert_eq!(salts.salt1, [5u8; 32]);
        assert_eq!(salts.salt2, Some([5u8; 32]));
        assert_eq!(
            decrypt_salts(&s, &enc, &[0u8; 32]),
            Err(Status::PinAuthInvalid)
        );
        let short = s.encrypt(&[5u8; 16]).unwrap();
        let auth = s.authenticate(&short);
        assert_eq!(decrypt_salts(&s, &short, &auth), Err(Status::InvalidLength));
        let odd = [1u8; 40];
        let auth = s.authenticate(&odd);
        assert_eq!(decrypt_salts(&s, &odd, &auth), Err(Status::InvalidLength));
    }

    #[test]
    fn wrapper_rejects_odd_output_lengths() {
        let s = SharedSecret::from_z(PinUvAuthProtocol::One, &[3u8; 32]).unwrap();
        let w = HmacSecretWrapper::new(s);
        assert!(w.wrap(&[0u8; 32]).is_ok());
        assert!(w.wrap(&[0u8; 48]).is_err());
    }

    #[test]
    fn regenerate_changes_the_public_key() {
        let mut keys = KeyAgreementKeys::new();
        let a = keys.public_key(PinUvAuthProtocol::Two).unwrap();
        assert_eq!(a, keys.public_key(PinUvAuthProtocol::Two).unwrap());
        assert_ne!(a, keys.public_key(PinUvAuthProtocol::One).unwrap());
        keys.regenerate();
        assert_ne!(a, keys.public_key(PinUvAuthProtocol::Two).unwrap());
    }
}
