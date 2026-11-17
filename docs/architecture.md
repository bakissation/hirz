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
| `hirz-proto` | lib | CBOR (encode + strict decode), COSE_Key, authenticatorData, attestation object (`none`), clientDataJSON serializer, base64url, minimal strict JSON reader/writer | zeroize (wipes parser scratch and parsed values) |
| `hirz-crypto` | lib | The only crate that touches crypto crates: ES256 and Ed25519 keygen/sign/verify, PKCS#8, SHA-256, HMAC, HKDF, AEAD (AES-256-GCM), X25519, RNG, Argon2id, secret types that zeroize | aws-lc-rs, argon2, zeroize |
| `hirz-sys` | lib | The only crate with `unsafe`: prctl, rlimit, mlock, peer credentials, flock, uhid event structs, fd passing, terminal echo (restored on Ctrl-C) and an unbuffered read of standard input | libc |
| `hirz-vault` | lib | Vault folder format, record encryption, merge, device registry, recovery key | hirz-proto, hirz-crypto |
| `hirz-ctap` | lib | CTAPHID framing, CTAP2 command decode/encode, PIN/UV protocols for hmac-secret, U2F later | hirz-proto, hirz-core, hirz-crypto |
| `hirz-webauthn` | lib | Client role for the extension path: origin parsing, RP ID validation with the public suffix list, options and response JSON | hirz-proto, hirz-crypto, hirz-core |
| `hirz-core` | lib | Authenticator engine, independent of transport | hirz-proto, hirz-crypto, hirz-vault |
| `hirz-uv` | lib | Approval methods (polkit, fprintd, hirz PIN, click-to-allow) and trusted prompts | hirz-core, hirz-crypto, hirz-sys |
| `hirz-session` | lib | Where the vault lives (`HIRZ_VAULT`, `HIRZ_STATE`, XDG folders) and one opened vault with its approver; shared by `hirzd` and `hirz-nmh` | hirz-core, hirz-vault, hirz-uv |
| `hirzd` | bin | User daemon: uhid frontend | all libs |
| `hirz-uhid-broker` | bin | Root helper: owns `/dev/uhid`, creates only a FIDO device, relays reports | hirz-sys |
| `hirz-nmh` | bin | Native messaging host for the extension | all libs |
| `hirz-cli` (`hirz`) | bin | `init`, `list`, `delete`, `devices`, `repair`, `export`, `import`, `status` | all libs (serde_json allowed here only, for CXF) |

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

/// Implemented by hirz-uv. The engine never signs with UP=1 unless this returns Ok.
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

### Engine policy

Policy of `hirz-core` relative to CTAP 2.2 section 6. Every ceremony first reloads the
vault, so credentials another frontend or the folder sync tool wrote meanwhile are visible.

- **Silent probes** (`up: false`): platforms send getAssertion with `up: false` to find out
  which entries of an allow list or exclude list exist here before the real request (CTAP 2.2
  section 6.2.2, "pre-flight"). With a non-empty allow list the engine signs for the first
  applicable credential without calling the approver: flags UP=0 and UV=0, BE and BS as
  usual, no hmac-secret output and no user entity. Relying parties reject assertions without
  UP for sign-in, so a probe result cannot log anyone in. Credentials with credProtect level 3
  are not applicable without UV and are skipped. An empty allow list, or a probe that asks for
  UV, never reaches a credential (`NoCredentials` and `UvRequiredUnavailable`). A probe
  reveals to local processes whether a credential exists for a site, which processes of the
  same user can learn from the vault anyway.
- **excludeList**: a listed credential of this RP still asks the user (a Create prompt)
  before `CredentialExcluded` is returned, so a page cannot probe for credentials without a
  gesture. If the user declines or the prompt times out, the approval error is returned
  instead, exactly as for a declined creation (WebAuthn section 6.3.2 step 3). Excluded
  credentials with credProtect level 3 only count when the approval included UV, as in CTAP.
- **credProtect**: level 3 needs UV; level 2 needs UV when there is no allow list. CTAP
  decides UV before looking up credentials, hirz decides it during the approval. So when a
  shown candidate needs UV the approver is asked with `uv_required`. If UV turns out to be
  unavailable and the RP did not require it, the protected candidates are dropped and the
  approver is asked again with the rest, or `NoCredentials` is returned: protected credentials
  stay invisible without UV, as in CTAP.
- **No applicable credential**: `NoCredentials` at once, without a prompt (CTAP 2.2
  getAssertion step 7). The extension path must not tell pages (WebAuthn privacy
  considerations): `hirz-nmh` answers it with `NotHandled`, so Firefox runs its own
  ceremony and user interface, and a "no credential" that follows a prompt becomes a
  refusal instead. A refusal that comes before any window was shown (the prompt budget is used
  up, no verification method works, zenity or a helper is missing, the config is broken; the
  approver says `ApprovalError::NothingShown`) gets the same answer, `NotHandled`: with a
  matching credential and without one, a page sees the same thing, and only a window the user
  saw can end in a refusal. The uhid path returns `CTAP2_ERR_NO_CREDENTIALS`, which the
  browser, as the client, hides from the page, and `CTAP2_ERR_NOT_ALLOWED` for a refusal.
- **Allow list**: the first applicable credential in allow-list order is used, without a
  choice (CTAP: "select any credential"). Without an allow list the user picks among the
  discoverable credentials, newest first.
- **Same account again**: creating a discoverable credential replaces older discoverable
  credentials of the same RP id and user id (CTAP makeCredential, `rk`), after the new one
  is stored. The delete is best effort: a leftover older credential only shows up as an
  extra account.
- **User entity**: returned for flows without an allow list; name and display name only when
  the approval included UV (CTAP getAssertion, user identifiable information).
- **Machine login**: RP ids starting with `pam://` (pam-u2f for login, sudo and screen
  unlock), `io.systemd.home` (systemd-homed) and `io.systemd.cryptsetup` (systemd-cryptenroll;
  the list is `hirz_core::machine_login`) are refused with `ApprovalError::Unavailable` (CTAP2_ERR_NOT_ALLOWED) before any
  prompt or vault access, silent probes included. hirz passkeys are synced software keys and
  must not become a login factor for the computer they run on, and an unlock that waits for a
  hirz approval could deadlock.
- **hmac-secret**: with a wrap (CTAP path) the output is encrypted into the authData
  extensions; without one (extension path) it is returned raw in `hmac_secret_output`. As CTAP
  specifies, a credential has two secrets, one used when the approval verified the user and one
  when it did not. With `userVerification: "preferred"` a click approval and a password or PIN
  approval therefore give different PRF or hmac-secret results for the same credential. A site
  that derives keys from the output must request `required`; hirz does not force verification
  when only `preferred` was asked.
- **Before the prompt**: a device that was removed is refused (`ApprovalError::Unavailable`)
  and so is a registration while the vault is read-only (a fork, a rotation conflict, or a key
  change this device holds no key for: saving would fail), so nobody approves something that
  cannot be stored. Signing in with existing passkeys still works in a fork. The daemons look at
  the vault folder once per request (`hirz-session`, which tells the engine so with
  `Engine::with_loaded_vault`); the engine reloads on its own only when it was not told. A vault
  that reports `VaultError::Fork` or `VaultError::Removed` while a request is served is answered
  like any other refusal (CTAP2_ERR_NOT_ALLOWED in hirzd, `NotAllowedError` in hirz-nmh) and the
  vault stays open; hirz-nmh answers a registration with `NotHandled` when it knows beforehand
  that it cannot be saved. A fork is logged once when it starts and once when it ends, by both
  daemons. Requests that only read and never ask the user (`list` and capability checks in
  hirz-nmh, silent probes in hirzd) do not scan the folder each time: they reuse the last look
  when it is less than 3 seconds old (`Session::ensure_vault_recent`), so a page or a client
  cannot make every request read the whole folder and run its maintenance. Anything that
  signs, registers or prompts always looks first.
- **After the prompt**: a prompt stays open for up to two minutes, so the engine looks again
  once the user has approved. It checks that the request is still wanted (a cancel that arrived
  meanwhile stops it), reloads the vault, and refuses when this device was removed meanwhile or
  the chosen credential was deleted; the excludeList is checked against the reloaded vault. A new
  credential is deleted again when a cancel arrives right after it was stored, and the older
  credential of the same account is replaced only after that last check (`Engine::with_commit`).
  hirz-nmh makes that check and the reader's handling of `cancel` exclusive under one lock: a
  registration that is reported as cancelled was never stored, and one that is stored can no
  longer be cancelled (a cancel that comes later finds nothing waiting, and the extension drops
  the late answer). On the uhid path the transport drops the answer of a cancelled request, but
  a cancel that arrives after the answer was sent cannot be undone.

## Trust boundaries

1. Web page: hostile. Never a source of origin, RP ID truth or approval.
2. Extension background: trusted for `sender.origin` (set by Firefox) and nothing else
   the page could influence. The host re-validates origin and RP ID.
3. Native host / daemon: owns all policy, approval and signing. A request without a
   fresh approval from `hirz-uv` is never signed with the user-present flag.
4. Other processes of the same user: can read the vault while unlocked and can talk to
   the hidraw node. hirz states this in `docs/threat-model.md`; every signature with the
   user-present flag still needs an approval prompt. Silent existence checks (CTAP
   getAssertion with `up: false`) sign with UP=0, which relying parties reject for sign-in,
   matching hardware security keys; they reveal to local processes whether a credential
   exists for a site, which same-user processes can learn from the vault anyway.
5. Root broker: smallest possible surface; only relays fixed-size HID reports for a device
   it created with the FIDO report descriptor. It never passes the `/dev/uhid` fd out.

## Local state

- Vault (synced): `$XDG_DATA_HOME/hirz/vault/` by default, or a user-chosen folder that
  `hirz init` / `hirz join` record in `$XDG_STATE_HOME/hirz/vault-path`. hirzd and
  hirz-nmh resolve it the same way (`crates/hirz-session`, shared by both), with
  `HIRZ_VAULT` and `HIRZ_STATE` as overrides for tests. Without a vault, hirzd refuses
  every ceremony and hirz-nmh hands every ceremony back to Firefox; both start the setup
  window, `hirz init --gui` (docs/approval.md, "Setting up hirz").
- Device state (never synced): `$XDG_STATE_HOME/hirz/` holds the device secret, the
  wrapped vault key, PIN verifier, retry counters and rate-limit state (files 0600, dir 0700).

## Implementation notes

- **CBOR (`hirz-proto`).** The decoder accepts unsigned and negative integers, byte and text
  strings, arrays, maps, booleans and null, all with definite lengths. Floats, tags,
  `undefined`, other simple values and indefinite lengths are rejected, and map keys must be
  integers or text. Canonical form follows CTAP2 section 8: shortest-form arguments and map
  keys sorted by major type, then encoded length, then bytewise. Within one major type this
  matches the length-first ordering of RFC 8949 section 4.2.3; across major types all integer
  keys come before text keys.
- **Origins (`hirz-webauthn`).** Only tuple origins that can be a WebAuthn caller are
  accepted: `https` with a domain host, or `http` with `localhost` or a subdomain of it
  (potentially trustworthy per the secure contexts rules). The input must already be in the
  browser's serialization (lowercase ASCII, punycode for IDN labels, no default port) and
  anything else is rejected rather than normalized, because the string is copied verbatim
  into `clientDataJSON`. IP literals are rejected: WebAuthn requires the effective domain to
  be a valid domain, and an IP address is not one. The Public Suffix List is compiled in
  (version and license: `crates/hirz-webauthn/README.md`); rules from both the ICANN and
  PRIVATE sections are used, as browsers do.
