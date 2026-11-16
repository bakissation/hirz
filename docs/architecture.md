# hirz architecture

hirz is a passkey (WebAuthn / FIDO2) authenticator for Linux. One Rust core holds the
authenticator logic and an encrypted, syncable vault. Two frontends reach it in v0.1:

- **Virtual security key** (`hirzd` + `hirz-uhid-broker`): a CTAP2 device on `/dev/uhid`.
  The browser performs the WebAuthn client role (origin binding, iframes, permissions
  policy). Works in Firefox, Chromium and libfido2 tools.
- **Firefox extension** (`extension/` + `hirz-nmh`): takes over `navigator.credentials`
  in pages and talks to a native messaging host. hirz performs the client role itself.

Both frontends open the same vault directly. There is no shared daemon socket between
them: the vault is a folder of immutable files, so concurrent writers are safe by design.

```
 browser (Firefox / Chromium)                     Firefox page
        | CTAP2 over HID                                | navigator.credentials
   /dev/hidraw  <-  uhid  <- hirz-uhid-broker (root)    | MAIN-world shim -> relay -> background
                               | 64-byte reports only   | native messaging (stdio)
                               v                        v
                            hirzd (user)             hirz-nmh (user, per connection)
                    hirz-ctap: CTAPHID + CTAP2     hirz-webauthn: origin, RP ID, PSL,
                               \                   clientDataJSON, JSON envelopes
                                \                     /
                                 v                   v
                          hirz-core: authenticator engine
                          (makeCredential / getAssertion, flags, selection)
                           |                 |                 |
                      hirz-vault         hirz-uv           hirz-crypto
                   (records, sync)   (approval prompts)  (aws-lc-rs, argon2)
```

## Crates

| Crate | Kind | Purpose | Allowed dependencies |
|---|---|---|---|
| `hirz-proto` | lib | CBOR (encode + strict decode), COSE_Key, authenticatorData, attestation object (`none`), clientDataJSON serializer, base64url, minimal strict JSON reader/writer | none |
| `hirz-crypto` | lib | The only crate that touches crypto crates: ES256 and Ed25519 keygen/sign/verify, PKCS#8, SHA-256, HMAC, HKDF, AEAD (AES-256-GCM), X25519, RNG, Argon2id, secret types that zeroize | aws-lc-rs, argon2, zeroize |
| `hirz-sys` | lib | The only crate with `unsafe`: prctl, rlimit, mlock, peer credentials, uhid event structs, fd passing | libc |
| `hirz-vault` | lib | Vault folder format, record encryption, merge, device registry, recovery key | hirz-proto, hirz-crypto |
| `hirz-ctap` | lib | CTAPHID framing, CTAP2 command decode/encode, U2F later | hirz-proto |
| `hirz-webauthn` | lib | Client role for the extension path: origin parsing, RP ID validation with the public suffix list, options and response JSON | hirz-proto, hirz-crypto, hirz-core |
| `hirz-core` | lib | Authenticator engine, independent of transport | hirz-proto, hirz-crypto, hirz-vault |
| `hirz-uv` | lib | Approval methods (polkit, fprintd, hirz PIN, click-to-allow) and trusted prompts | hirz-core, hirz-crypto, hirz-sys |
| `hirzd` | bin | User daemon: uhid frontend | all libs |
| `hirz-uhid-broker` | bin | Root helper: owns `/dev/uhid`, creates only a FIDO device, relays reports | hirz-sys |
| `hirz-nmh` | bin | Native messaging host for the extension | all libs |
| `hirz-cli` (`hirz`) | bin | `init`, `list`, `delete`, `devices`, `export`, `import`, `status` | all libs (serde_json allowed here only, for CXF) |

Rules: `unsafe_code` is forbidden in every crate except `hirz-sys`. No async runtime, no
TLS, no D-Bus library, no URL library, no proc macros in the authenticator binaries.
Panics abort. Every external dependency is listed in `docs/dependencies.md` with a reason.

## Core contracts (hirz-core)

The engine works on CTAP-level requests. The extension path converts WebAuthn JSON into
these structures after computing `clientDataJSON` and its hash; the uhid path decodes them
from CTAP2 CBOR.

```rust
pub enum UvRequirement { Required, Preferred, Discouraged }

pub struct RpEntity { pub id: String, pub name: Option<String> }
pub struct UserEntity { pub id: Vec<u8>, pub name: Option<String>, pub display_name: Option<String> }

pub struct MakeCredentialRequest {
    pub client_data_hash: [u8; 32],
    pub rp: RpEntity,
    pub user: UserEntity,
    pub algorithms: Vec<i64>,          // COSE alg ids in RP preference order
    pub exclude_list: Vec<Vec<u8>>,    // credential ids
    pub resident_key: bool,            // hirz always stores credentials in the vault
    pub uv: UvRequirement,
    pub extensions: MakeExtensions,    // cred_props, hmac_secret (prf), cred_protect
}

pub struct GetAssertionRequest {
    pub client_data_hash: [u8; 32],
    pub rp_id: String,
    pub allow_list: Vec<Vec<u8>>,
    pub uv: UvRequirement,
    pub up: bool,
    pub extensions: GetExtensions,     // hmac_secret salts (prf)
}

/// Implemented by hirz-uv. The engine never signs unless this returns Ok.
pub trait Approver {
    fn approve(&self, ctx: &ApprovalContext) -> Result<Approval, ApprovalError>;
}
pub struct ApprovalContext<'a> {
    pub ceremony: Ceremony,                       // Create | Get
    pub rp_id: &'a str,
    pub rp_name: Option<&'a str>,
    pub candidates: &'a [CandidateAccount],       // for Get: accounts to choose from
    pub new_account: Option<&'a UserEntity>,      // for Create
    pub uv_required: bool,
    pub origin: Option<&'a str>,                  // extension path only, for display
}
pub struct Approval { pub user_present: bool, pub user_verified: bool, pub selected: Option<usize> }
```

The engine returns `authenticatorData`, the credential id, the public key (COSE), the
signature and the user handle; frontends wrap them in CTAP2 CBOR or WebAuthn JSON.

### Flags and identity

- AAGUID: `c049d046-0de0-4b9c-824f-5b5eeeff218f` (fixed for the product).
- Attestation format: `none`.
- `UP` only after a gesture; `UV` only after a host-verified method (polkit, fprintd, PIN).
  Click-to-allow sets `UV=0` and is refused when the RP requires UV.
- `BE=1` for every credential at creation, never changed. `BS=1` once the vault has a
  second device or a confirmed backup, otherwise `0`.
- `signCount` is always 0.
- Algorithms: ES256 (-7) and EdDSA (-8). Other algorithms are not offered.
- Credential ids: 32 random bytes. All credentials are stored in the vault, including
  non-discoverable ones, so they sync.

## Trust boundaries

1. Web page: hostile. Never a source of origin, RP ID truth or approval.
2. Extension background: trusted for `sender.origin` (set by Firefox) and nothing else
   the page could influence. The host re-validates origin and RP ID.
3. Native host / daemon: owns all policy, approval and signing. A request without a
   fresh approval from `hirz-uv` is never signed.
4. Other processes of the same user: can read the vault while unlocked and can talk to
   the hidraw node. hirz states this in `docs/threat-model.md`; every signature still
   needs an approval prompt.
5. Root broker: smallest possible surface; only relays fixed-size HID reports for a device
   it created with the FIDO report descriptor. It never passes the `/dev/uhid` fd out.

## Local state

- Vault (synced): `$XDG_DATA_HOME/hirz/vault/` by default, or a user-chosen folder.
- Device state (never synced): `$XDG_STATE_HOME/hirz/` holds the device secret, the
  wrapped vault key, PIN verifier, retry counters and rate-limit state (files 0600, dir 0700).
