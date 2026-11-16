//! Credential records and vault events, and their binary encoding.

use crate::DeviceId;
use crate::codec::{self, Fields, Writer};
use crate::error::VaultError;
use core::fmt;
use hirz_crypto::Zeroizing;

/// hirz creates 32-byte ids; imported passkeys keep the id their original authenticator chose.
pub const MAX_CREDENTIAL_ID_LEN: usize = hirz_proto::auth_data::MAX_CREDENTIAL_ID_LEN;
pub const MAX_USER_ID_LEN: usize = hirz_proto::MAX_USER_ID_LEN;
pub const MAX_STRING_LEN: usize = 1024;
pub const MAX_PKCS8_LEN: usize = 1024;
pub const MAX_DEVICE_NAME_LEN: usize = 256;

/// Version 2 allows credential ids of 1 to 1023 bytes. Version 1 (fixed 32-byte ids) is
/// still read.
const RECORD_VERSION: u8 = 2;
const TOMBSTONE_VERSION: u8 = 2;
const V1: u8 = 1;
const V1_CREDENTIAL_ID_LEN: usize = 32;
const EVENT_VERSION: u8 = 2;

/// The two CTAP hmac-secret values (CredRandomWithUV and CredRandomWithoutUV).
#[derive(Clone, PartialEq, Eq)]
pub struct HmacSecretPair {
    pub cred_random_with_uv: Zeroizing<[u8; 32]>,
    pub cred_random_without_uv: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for HmacSecretPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HmacSecretPair(..)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CredentialRecord {
    /// Lookups compare the full id.
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_id: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub algorithm: i64,
    pub private_key_pkcs8: Zeroizing<Vec<u8>>,
    /// Unix seconds.
    pub created_at: u64,
    /// CTAP credProtect level (1 to 3).
    pub cred_protect: Option<u8>,
    pub hmac_secret: Option<HmacSecretPair>,
    pub discoverable: bool,
    /// Always true for vault credentials (WebAuthn BE flag).
    pub backup_eligible: bool,
}

impl fmt::Debug for CredentialRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialRecord")
            .field("credential_id", &codec::hex(&self.credential_id))
            .field("rp_id", &self.rp_id)
            .field("rp_name", &self.rp_name)
            .field("user_name", &self.user_name)
            .field("user_display_name", &self.user_display_name)
            .field("algorithm", &self.algorithm)
            .field("created_at", &self.created_at)
            .field("cred_protect", &self.cred_protect)
            .field("hmac_secret", &self.hmac_secret.is_some())
            .field("discoverable", &self.discoverable)
            .finish_non_exhaustive()
    }
}

fn check_opt_string(s: &Option<String>) -> Result<(), VaultError> {
    match s {
        Some(v) if v.len() > MAX_STRING_LEN => Err(VaultError::InvalidRecord("string too long")),
        _ => Ok(()),
    }
}

fn valid_credential_id(id: &[u8]) -> bool {
    !id.is_empty() && id.len() <= MAX_CREDENTIAL_ID_LEN
}

fn credential_id_value(v: &[u8], version: u8) -> Result<Vec<u8>, VaultError> {
    let ok = if version == V1 {
        v.len() == V1_CREDENTIAL_ID_LEN
    } else {
        valid_credential_id(v)
    };
    if !ok {
        return Err(VaultError::Corrupt("credential_id"));
    }
    Ok(v.to_vec())
}

impl CredentialRecord {
    pub fn validate(&self) -> Result<(), VaultError> {
        if !valid_credential_id(&self.credential_id) {
            return Err(VaultError::InvalidRecord(
                "credential_id must be 1 to 1023 bytes",
            ));
        }
        if self.rp_id.is_empty() || self.rp_id.len() > MAX_STRING_LEN {
            return Err(VaultError::InvalidRecord("rp_id"));
        }
        check_opt_string(&self.rp_name)?;
        check_opt_string(&self.user_name)?;
        check_opt_string(&self.user_display_name)?;
        if self.user_id.len() > MAX_USER_ID_LEN {
            return Err(VaultError::InvalidRecord("user_id longer than 64 bytes"));
        }
        if self.private_key_pkcs8.is_empty() || self.private_key_pkcs8.len() > MAX_PKCS8_LEN {
            return Err(VaultError::InvalidRecord("private key"));
        }
        if let Some(level) = self.cred_protect
            && !(1..=3).contains(&level)
        {
            return Err(VaultError::InvalidRecord("cred_protect"));
        }
        if !self.backup_eligible {
            return Err(VaultError::InvalidRecord("backup_eligible must be true"));
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        self.validate()?;
        let mut w = Writer::new(RECORD_VERSION);
        w.field(0x01, &self.credential_id)?;
        w.field(0x02, self.rp_id.as_bytes())?;
        if let Some(v) = &self.rp_name {
            w.field(0x03, v.as_bytes())?;
        }
        w.field(0x04, &self.user_id)?;
        if let Some(v) = &self.user_name {
            w.field(0x05, v.as_bytes())?;
        }
        if let Some(v) = &self.user_display_name {
            w.field(0x06, v.as_bytes())?;
        }
        w.i64_field(0x07, self.algorithm)?;
        w.field(0x08, &self.private_key_pkcs8)?;
        w.u64_field(0x09, self.created_at)?;
        if let Some(level) = self.cred_protect {
            w.u8_field(0x0a, level)?;
        }
        if let Some(pair) = &self.hmac_secret {
            let mut both = Zeroizing::new([0u8; 64]);
            let (a, b) = both.split_at_mut(32);
            a.copy_from_slice(pair.cred_random_with_uv.as_slice());
            b.copy_from_slice(pair.cred_random_without_uv.as_slice());
            w.field(0x0b, both.as_slice())?;
        }
        w.u8_field(0x0c, u8::from(self.discoverable))?;
        w.u8_field(0x0d, u8::from(self.backup_eligible))?;
        Ok(w.finish())
    }

    pub(crate) fn decode(data: &[u8]) -> Result<Self, VaultError> {
        let (mut f, version) = Fields::new_versions(data, &[V1, RECORD_VERSION])?;
        let mut credential_id = None;
        let mut rp_id = None;
        let mut rp_name = None;
        let mut user_id = None;
        let mut user_name = None;
        let mut user_display_name = None;
        let mut algorithm = None;
        let mut private_key = None;
        let mut created_at = None;
        let mut cred_protect = None;
        let mut hmac_secret = None;
        let mut discoverable = None;
        let mut backup_eligible = None;
        while let Some((tag, v)) = f.next_field()? {
            match tag {
                0x01 => credential_id = Some(credential_id_value(v, version)?),
                0x02 => rp_id = Some(codec::string_value(v, MAX_STRING_LEN)?),
                0x03 => rp_name = Some(codec::string_value(v, MAX_STRING_LEN)?),
                0x04 => {
                    if v.len() > MAX_USER_ID_LEN {
                        return Err(VaultError::Corrupt("user_id"));
                    }
                    user_id = Some(v.to_vec());
                }
                0x05 => user_name = Some(codec::string_value(v, MAX_STRING_LEN)?),
                0x06 => user_display_name = Some(codec::string_value(v, MAX_STRING_LEN)?),
                0x07 => algorithm = Some(codec::i64_value(v)?),
                0x08 => {
                    if v.is_empty() || v.len() > MAX_PKCS8_LEN {
                        return Err(VaultError::Corrupt("private key"));
                    }
                    private_key = Some(Zeroizing::new(v.to_vec()));
                }
                0x09 => created_at = Some(codec::u64_value(v)?),
                0x0a => cred_protect = Some(codec::u8_value(v)?),
                0x0b => {
                    let both = codec::fixed::<64>(v)?;
                    let both = Zeroizing::new(both);
                    let (a, b) = both.split_at(32);
                    hmac_secret = Some(HmacSecretPair {
                        cred_random_with_uv: Zeroizing::new(codec::fixed::<32>(a)?),
                        cred_random_without_uv: Zeroizing::new(codec::fixed::<32>(b)?),
                    });
                }
                0x0c => discoverable = Some(codec::bool_value(v)?),
                0x0d => backup_eligible = Some(codec::bool_value(v)?),
                t if t >= 0x40 => {}
                _ => return Err(VaultError::Corrupt("unknown critical field")),
            }
        }
        let missing = VaultError::Corrupt("missing field");
        let rec = CredentialRecord {
            credential_id: credential_id.ok_or(missing.clone())?,
            rp_id: rp_id.ok_or(missing.clone())?,
            rp_name,
            user_id: user_id.ok_or(missing.clone())?,
            user_name,
            user_display_name,
            algorithm: algorithm.ok_or(missing.clone())?,
            private_key_pkcs8: private_key.ok_or(missing.clone())?,
            created_at: created_at.ok_or(missing.clone())?,
            cred_protect,
            hmac_secret,
            discoverable: discoverable.ok_or(missing.clone())?,
            backup_eligible: backup_eligible.ok_or(missing)?,
        };
        rec.validate()
            .map_err(|_| VaultError::Corrupt("record validation"))?;
        Ok(rec)
    }
}

/// `endorser` all zero means the recovery key endorsed the device (vault creation or a recovery
/// phrase join); otherwise it is the id of the device that approved the pairing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeviceAnnouncement {
    pub(crate) device_id: DeviceId,
    pub(crate) name: String,
    pub(crate) x25519_public: [u8; 32],
    pub(crate) added_at: u64,
    pub(crate) signing_public: [u8; 32],
    pub(crate) endorser: DeviceId,
    pub(crate) signature: [u8; 64],
}

pub(crate) const RECOVERY_ENDORSER: DeviceId = [0u8; 16];

/// Device ids are bound to the device's signing key, so a device cannot be re-announced with
/// another key.
pub(crate) fn device_id_for(signing_public: &[u8; 32]) -> DeviceId {
    let h = hirz_crypto::sha256(&codec::aad("hirz device id v1", &[signing_public]));
    let mut out = [0u8; 16];
    for (o, b) in out.iter_mut().zip(h.iter()) {
        *o = *b;
    }
    out
}

impl DeviceAnnouncement {
    pub(crate) fn endorsement_message(&self, vault_id: &[u8; 16]) -> Vec<u8> {
        codec::aad(
            "hirz device endorsement v1",
            &[
                vault_id,
                &self.device_id,
                self.name.as_bytes(),
                &self.x25519_public,
                &self.added_at.to_be_bytes(),
                &self.signing_public,
                &self.endorser,
            ],
        )
    }

    pub(crate) fn endorse(
        &mut self,
        vault_id: &[u8; 16],
        seed: &[u8; 32],
    ) -> Result<(), VaultError> {
        self.signature =
            hirz_crypto::ed25519::sign_with_seed(seed, &self.endorsement_message(vault_id))?;
        Ok(())
    }

    pub(crate) fn endorsement_valid(
        &self,
        vault_id: &[u8; 16],
        endorser_public: &[u8; 32],
    ) -> bool {
        hirz_crypto::ed25519::verify(
            endorser_public,
            &self.endorsement_message(vault_id),
            &self.signature,
        )
        .is_ok()
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if self.name.len() > MAX_DEVICE_NAME_LEN {
            return Err(VaultError::InvalidRecord("device name"));
        }
        let mut w = Writer::new(1);
        w.field(0x01, &self.device_id)?;
        w.field(0x02, self.name.as_bytes())?;
        w.field(0x03, &self.x25519_public)?;
        w.u64_field(0x04, self.added_at)?;
        w.field(0x05, &self.signing_public)?;
        w.field(0x06, &self.endorser)?;
        w.field(0x07, &self.signature)?;
        Ok(w.finish())
    }

    pub(crate) fn decode(payload: &[u8]) -> Result<DeviceAnnouncement, VaultError> {
        let mut f = Fields::new(payload, 1)?;
        let device_id = expect_field(&mut f, 0x01).and_then(codec::fixed::<16>)?;
        let name =
            expect_field(&mut f, 0x02).and_then(|v| codec::string_value(v, MAX_DEVICE_NAME_LEN))?;
        let x25519_public = expect_field(&mut f, 0x03).and_then(codec::fixed::<32>)?;
        let added_at = expect_field(&mut f, 0x04).and_then(codec::u64_value)?;
        let signing_public = expect_field(&mut f, 0x05).and_then(codec::fixed::<32>)?;
        let endorser = expect_field(&mut f, 0x06).and_then(codec::fixed::<16>)?;
        let signature = expect_field(&mut f, 0x07).and_then(codec::fixed::<64>)?;
        expect_end(&mut f)?;
        if device_id_for(&signing_public) != device_id || endorser == device_id {
            return Err(VaultError::Corrupt("device announcement"));
        }
        Ok(DeviceAnnouncement {
            device_id,
            name,
            x25519_public,
            added_at,
            signing_public,
            endorser,
            signature,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EventKind {
    Put(Box<CredentialRecord>),
    Tombstone(Vec<u8>),
    DeviceAdded(DeviceAnnouncement),
    DeviceRemoved { device_id: DeviceId, at: u64 },
    BackupConfirmed { at: u64 },
}

impl EventKind {
    fn code(&self) -> u8 {
        match self {
            EventKind::Put(_) => 1,
            EventKind::Tombstone(_) => 2,
            EventKind::DeviceAdded(_) => 3,
            EventKind::DeviceRemoved { .. } => 4,
            EventKind::BackupConfirmed { .. } => 5,
        }
    }
}

/// The first 16 bytes of an event's hash (docs/vault-format.md, 5.2); it covers the origin, the
/// content and the origin's signing key, so it stays the same through every re-write.
pub(crate) type EventId = [u8; 16];

/// An event with its merge identity. `origin` stays the same when an event is re-written
/// under a new key generation, so the merge order never changes through a rotation. The origin
/// device signs it, so no other device can write an event in its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Event {
    pub(crate) kind: EventKind,
    pub(crate) origin_author: DeviceId,
    pub(crate) origin_lamport: u64,
    /// Ed25519 key of the origin device; the origin id is derived from it.
    pub(crate) signer: [u8; 32],
    pub(crate) signature: [u8; 64],
}

impl Event {
    pub(crate) fn signed(
        kind: EventKind,
        origin_author: DeviceId,
        origin_lamport: u64,
        seed: &[u8; 32],
        vault_id: &[u8; 16],
    ) -> Result<Event, VaultError> {
        let mut e = Event {
            kind,
            origin_author,
            origin_lamport,
            signer: hirz_crypto::ed25519::public_from_seed(seed)?,
            signature: [0u8; 64],
        };
        e.signature =
            hirz_crypto::ed25519::sign_with_seed(seed, &signature_message(vault_id, &e.digest()?))?;
        Ok(e)
    }

    /// SHA-256 of the signed fields (everything but the signature and the author tag).
    pub(crate) fn digest(&self) -> Result<[u8; 32], VaultError> {
        Ok(hirz_crypto::sha256(&self.signed_part()?))
    }

    pub(crate) fn id(&self, vault_id: &[u8; 16]) -> Result<EventId, VaultError> {
        Ok(event_id(vault_id, &self.digest()?))
    }

    /// The origin id matches the signing key and the signature over `digest` verifies.
    pub(crate) fn signature_valid(&self, vault_id: &[u8; 16], digest: &[u8; 32]) -> bool {
        device_id_for(&self.signer) == self.origin_author
            && hirz_crypto::ed25519::verify(
                &self.signer,
                &signature_message(vault_id, digest),
                &self.signature,
            )
            .is_ok()
    }

    fn signed_part(&self) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let payload = self.encode_payload()?;
        let mut w = Writer::new(EVENT_VERSION);
        w.u8_field(0x01, self.kind.code())?;
        w.field(0x02, &self.origin_author)?;
        w.u64_field(0x03, self.origin_lamport)?;
        w.field(0x04, &payload)?;
        w.field(0x05, &self.signer)?;
        Ok(w.finish())
    }

    pub(crate) fn encode_body(&self) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let mut body = self.signed_part()?;
        body.push(0x06);
        body.extend_from_slice(&64u16.to_be_bytes());
        body.extend_from_slice(&self.signature);
        Ok(body)
    }

    fn encode_payload(&self) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        match &self.kind {
            EventKind::Put(rec) => rec.encode(),
            EventKind::Tombstone(id) => {
                if !valid_credential_id(id) {
                    return Err(VaultError::InvalidRecord("credential_id"));
                }
                let mut w = Writer::new(TOMBSTONE_VERSION);
                w.field(0x01, id)?;
                Ok(w.finish())
            }
            EventKind::DeviceAdded(d) => d.encode(),
            EventKind::DeviceRemoved { device_id, at } => {
                let mut w = Writer::new(1);
                w.field(0x01, device_id)?;
                w.u64_field(0x02, *at)?;
                Ok(w.finish())
            }
            EventKind::BackupConfirmed { at } => {
                let mut w = Writer::new(1);
                w.u64_field(0x01, *at)?;
                Ok(w.finish())
            }
        }
    }

    /// Decodes `body || tag field`; returns the event, the body bytes the tag covers and
    /// the author tag.
    pub(crate) fn decode(data: &[u8]) -> Result<(Event, usize, [u8; 32]), VaultError> {
        let mut f = Fields::new(data, EVENT_VERSION)?;
        let mut kind = None;
        let mut author = None;
        let mut lamport = None;
        let mut payload = None;
        let mut signer = None;
        let mut signature = None;
        let mut tag_value = None;
        let mut body_len = data.len();
        loop {
            let before = f.remaining();
            let Some((tag, v)) = f.next_field()? else {
                break;
            };
            match tag {
                0x01 => kind = Some(codec::u8_value(v)?),
                0x02 => author = Some(codec::fixed::<16>(v)?),
                0x03 => lamport = Some(codec::u64_value(v)?),
                0x04 => payload = Some(v),
                0x05 => signer = Some(codec::fixed::<32>(v)?),
                0x06 => signature = Some(codec::fixed::<64>(v)?),
                0x7f => {
                    tag_value = Some(codec::fixed::<32>(v)?);
                    body_len = data.len().saturating_sub(before);
                    if f.remaining() != 0 {
                        return Err(VaultError::Corrupt("data after author tag"));
                    }
                }
                _ => return Err(VaultError::Corrupt("unknown event field")),
            }
        }
        let missing = VaultError::Corrupt("missing event field");
        let payload = payload.ok_or(missing.clone())?;
        let kind = match kind.ok_or(missing.clone())? {
            1 => EventKind::Put(Box::new(CredentialRecord::decode(payload)?)),
            2 => {
                let (mut f, version) = Fields::new_versions(payload, &[V1, TOMBSTONE_VERSION])?;
                let id = match f.next_field()? {
                    Some((0x01, v)) => credential_id_value(v, version)?,
                    _ => return Err(VaultError::Corrupt("tombstone")),
                };
                expect_end(&mut f)?;
                EventKind::Tombstone(id)
            }
            3 => EventKind::DeviceAdded(DeviceAnnouncement::decode(payload)?),
            4 => {
                let mut f = Fields::new(payload, 1)?;
                let device_id = expect_field(&mut f, 0x01).and_then(codec::fixed::<16>)?;
                let at = expect_field(&mut f, 0x02).and_then(codec::u64_value)?;
                expect_end(&mut f)?;
                EventKind::DeviceRemoved { device_id, at }
            }
            5 => {
                let mut f = Fields::new(payload, 1)?;
                let at = expect_field(&mut f, 0x01).and_then(codec::u64_value)?;
                expect_end(&mut f)?;
                EventKind::BackupConfirmed { at }
            }
            _ => return Err(VaultError::Corrupt("unknown event kind")),
        };
        let event = Event {
            kind,
            origin_author: author.ok_or(missing.clone())?,
            origin_lamport: lamport.ok_or(missing.clone())?,
            signer: signer.ok_or(missing.clone())?,
            signature: signature.ok_or(missing.clone())?,
        };
        Ok((event, body_len, tag_value.ok_or(missing)?))
    }
}

pub(crate) fn event_id(vault_id: &[u8; 16], digest: &[u8; 32]) -> EventId {
    let h = hirz_crypto::sha256(&codec::aad("hirz event id v1", &[vault_id, digest]));
    let mut out = [0u8; 16];
    for (o, b) in out.iter_mut().zip(h.iter()) {
        *o = *b;
    }
    out
}

fn signature_message(vault_id: &[u8; 16], digest: &[u8; 32]) -> Vec<u8> {
    codec::aad("hirz event signature v1", &[vault_id, digest])
}

pub(crate) fn append_tag(body: &mut Zeroizing<Vec<u8>>, tag: &[u8; 32]) {
    body.push(0x7f);
    body.extend_from_slice(&32u16.to_be_bytes());
    body.extend_from_slice(tag);
}

pub(crate) fn expect_field<'a>(f: &mut Fields<'a>, tag: u8) -> Result<&'a [u8], VaultError> {
    match f.next_field()? {
        Some((t, v)) if t == tag => Ok(v),
        _ => Err(VaultError::Corrupt("unexpected field")),
    }
}

pub(crate) fn expect_end(f: &mut Fields<'_>) -> Result<(), VaultError> {
    match f.next_field()? {
        None => Ok(()),
        Some(_) => Err(VaultError::Corrupt("unexpected field")),
    }
}
