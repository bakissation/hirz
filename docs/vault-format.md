# hirz vault format, version 1

The vault is a directory that the user syncs between devices with a tool of their choice
(Syncthing, Nextcloud, Dropbox, rclone, git). This document specifies every file in it, the
local per-device state, the merge rule and the security properties of the format.
Implementation: `crates/hirz-vault`. Cryptographic primitives: `crates/hirz-crypto`.

Design rules:

- **Files are immutable.** A file is written once (temp file, fsync, rename, fsync of the
  directory) and never modified. Every file name contains the writer's device id or random
  bytes, so two devices never write the same name and sync tools never create conflict copies.
- **Merging is deterministic.** Changes are events; every device computes the same state from
  the same set of files, in any order.
- **The folder is not a guessing target.** Records are encrypted under a random 256-bit vault
  key. No key that protects synced data is derived from a password.
- **One bad file never breaks the vault.** Unknown names, temp files, conflict copies and
  files that fail authentication are skipped and reported.

## 1. Conventions

- Integers are unsigned big endian unless stated. `i64` is two's complement big endian.
- `||` is concatenation. `[n]` is a byte string of length n.
- `hex(x)` is lowercase hexadecimal.
- **Device id**: 16 random bytes. **Vault id**: 16 random bytes.
- **Generation id** (`GenId`, 20 bytes): `number u32 || rotator device id [16]`. Generations
  are ordered by `(number, rotator)`.
- **File prefix** (6 bytes): `"HIRZ" || type u8 || 0x01` (format version 1).

| Type | File |
|---|---|
| 0x01 | vault header |
| 0x02 | record event |
| 0x03 | generation info |
| 0x04 | device key slot |
| 0x05 | recovery key slot |
| 0x06 | backup export |
| 0x10 | local device state |
| 0x11 | local keyring |
| 0x12 | local counter |

- **AAD encoding**: `aad(label, parts) = UTF-8(label) || 0x00 || for each part: (u32 length || part)`.
- **TLV body**: `version u8 || field*`, field = `tag u8 || length u16 || value`. Tags appear in
  strictly increasing order, at most once. In credential records and generation info, unknown
  tags `>= 0x40` are skipped and unknown tags `< 0x40` make the body invalid. In events and
  local state every unknown tag is invalid.
- **AEAD**: AES-256-GCM with a random 12-byte nonce; output `nonce [12] || ciphertext || tag [16]`.
- **HKDF**: HKDF-SHA-256 (RFC 5869). **HMAC**: HMAC-SHA-256.
- **Sealed box** to an X25519 public key `R`: fresh ephemeral key `e`;
  `k = HKDF(salt = empty, ikm = X25519(e, R), info = "hirz x25519 seal v1" || e_pub || R, L = 32)`;
  output `e_pub [32] || AEAD(k, aad, plaintext)`. An all-zero shared secret is refused.
- Size caps on read: any vault file 1 MiB, backup 64 MiB, strings 1024 bytes, user id 64
  bytes, PKCS#8 key 1024 bytes, device name 256 bytes.

## 2. Directory layout

```
<vault>/
  hirz-vault                                     header
  keys/<gen-dir>/gen.info                        generation info
  keys/<gen-dir>/<hex(device id)>.slot           vault key sealed to a device
  keys/<gen-dir>/recovery.slot                   vault key sealed to the recovery key
  records/<hex(writer device id)>/<lamport>-<hex(random [8])>.rec   events
```

- `<gen-dir>` = `number` as 10 decimal digits, `-`, `hex(rotator)`. Example:
  `0000000002-6f1c...` (32 hex digits). `number >= 1`.
- `<lamport>` = 20 decimal digits (a u64). The random part makes names unique.
- Anything else is ignored: names that do not parse exactly (including sync-tool conflict
  copies such as `*.sync-conflict-*` or `* (conflicted copy)*`), names starting with `.`
  (temp files are `.<name>.tmp-<hex>`), and files where a directory is expected.

All files and directories are created with modes 0600 and 0700.

## 3. Header: `hirz-vault`

```
prefix(0x01) || vault_id [16] || created_at u64 (unix seconds)
```

30 bytes, plaintext, written once at creation. The vault id is bound into every AAD below, so
a replaced header makes every other file fail to authenticate. Key generations are not
recorded here (that would make the header mutable); they live in `keys/` (section 4).

## 4. Key generations

The vault key `K` of a generation is 32 random bytes. It is never derived from a password.
A generation is created at vault creation (the genesis, number 1) and by every rotation
(number = parent number + 1, rotator = the device that rotates).

### 4.1 `gen.info`

```
prefix(0x03) || has_parent u8 || parent GenId [20] || AEAD(key, aad, body)
```

- `has_parent` is 0 for the genesis (parent field all zero), 1 otherwise.
- `key` is the **parent generation's key**; for the genesis it is the genesis key itself.
- `aad = aad("hirz gen info v1", [0x01, vault_id, gen_id, parent_or_zero])`.
- `body` (TLV version 1):

| Tag | Value |
|---|---|
| 0x01 | commitment [32] = HMAC(K, aad("hirz key commitment v1", [vault_id, gen_id])) |
| 0x02 | recovery public key [32] (X25519) |
| 0x03 | device ids removed by this generation, n x [16] (n <= 1024) |
| 0x04 | created_at u64 |
| 0x05 | reemit_first u64: first counter of the events the rotator re-wrote |
| 0x06 | reemit_count u64: number of those events |
| 0x07 | genesis only: recovery tag [32] = HMAC(R_auth, aad("hirz genesis v1", [vault_id, gen_id, commitment, recovery_pub])) |

Because `gen.info` is sealed under the parent key, only a holder of the parent key can create
a child generation. Sealing a key to a device's public key is possible for anyone with folder
access, which is why a slot alone never makes a generation valid.

### 4.2 Slots

```
<device>.slot:  prefix(0x04) || sealed box to the device X25519 key,
                aad = aad("hirz device slot v1", [0x01, vault_id, gen_id, device_id]), plaintext K
recovery.slot:  prefix(0x05) || sealed box to the recovery X25519 key,
                aad = aad("hirz recovery slot v1", [0x01, vault_id, gen_id]), plaintext K
```

A rotator writes the slots of all active devices and the recovery slot. A device that joins
writes its own slot into the current generation.

### 4.3 Resolving the current generation

A device trusts the generations in its local keyring (section 7); the genesis entry is the
root of trust. A device joining with the recovery key trusts the genesis whose recovery slot
opens, whose commitment matches and whose recovery tag verifies with `R_auth`.

Generations are processed in ascending order. A generation `G` with parent `P` is
**authentic** when `P` is authentic and its key is known, `G.number = P.number + 1`,
`gen.info` opens under `K_P`, the recovery public key equals the parent's, and `G.rotator`
is not in `removed(P)`. `removed(G) = removed(P) ∪ G.removed`. The device then opens its own
slot (or the keyring entry, or the recovery slot when joining) and checks the commitment; a
key that does not match is discarded. Authentic generations without a key for this device
still count in the next step, so every device that holds the parent key reaches the same
decision.

**Conflict rule.** `G` is rejected when some authentic generation `D` that is not a
descendant of `G` has `G.rotator ∈ removed(D)`; descendants of rejected generations are
rejected too. All accusations count at once.

**Completeness.** The genesis is complete. Another generation is complete when the records
directory of its rotator holds valid events under it for every counter in
`[reemit_first, reemit_first + reemit_count)`. The rotator writes `gen.info` last, but sync
tools deliver files in any order, so readers check this explicitly.

**Current generation** = the highest `(number, rotator)` among authentic, non-rejected,
complete generations for which the device has the key. If an authentic, non-rejected
generation with a higher number exists for which the device has no key, the device is
**locked out** (it was removed, or joined after the rotation was prepared) and refuses
writes. If a rejected generation exists above the current one, the vault is in a
**rotation conflict** (section 9.3).

## 5. Records

### 5.1 File

```
records/<hex(writer)>/<lamport>-<hex(random)>.rec:
prefix(0x02) || gen_id [20] || AEAD(record_key, aad, event)

P          = "records/" || hex(writer) || "/" || file name      (the relative path)
record_key = HKDF(salt = vault_id, ikm = K_gen, info = aad("hirz record key v1", [gen_id, P]), L = 32)
aad        = aad("hirz record v1", [0x01, vault_id, gen_id, P])
```

The path is authenticated: renaming, moving or copying a file to another name makes it fail.
The per-file key keeps the number of random nonces per AES-GCM key at one.

### 5.2 Event (TLV version 1)

| Tag | Value |
|---|---|
| 0x01 | kind u8 |
| 0x02 | origin device id [16] |
| 0x03 | origin counter u64 |
| 0x04 | payload (TLV, below) |
| 0x7f | author tag [32] = HMAC(writer's device secret, aad("hirz author v1", [vault_id, P, bytes before this field])) |

The origin `(counter, device)` is the event's merge identity. A fresh event has origin =
(file counter, writer). An event re-written under a new generation keeps its origin. Only the
writer can verify the author tag; it is used to recognise the writer's own events (6.4).

Payloads, all TLV version 1:

| Kind | Payload |
|---|---|
| 1 put credential | the credential record (5.3) |
| 2 tombstone | 0x01 credential id [32] |
| 3 device added | 0x01 device id [16], 0x02 name (UTF-8), 0x03 X25519 public key [32], 0x04 added_at u64 |
| 4 device removed | 0x01 device id [16], 0x02 removed_at u64 |
| 5 backup confirmed | 0x01 confirmed_at u64 |

### 5.3 Credential record (TLV version 1)

| Tag | Field | Value |
|---|---|---|
| 0x01 | credential_id | [32] |
| 0x02 | rp_id | UTF-8, 1 to 1024 bytes |
| 0x03 | rp_name | UTF-8, optional |
| 0x04 | user_id | 0 to 64 bytes |
| 0x05 | user_name | UTF-8, optional |
| 0x06 | user_display_name | UTF-8, optional |
| 0x07 | algorithm | i64 (COSE: -7 ES256, -8 EdDSA) |
| 0x08 | private key | PKCS#8 DER, 1 to 1024 bytes |
| 0x09 | created_at | u64 unix seconds |
| 0x0a | cred_protect | u8 in 1..=3, optional |
| 0x0b | hmac-secret | [64]: cred_random_with_uv [32] then cred_random_without_uv [32], optional |
| 0x0c | discoverable | u8 0 or 1 |
| 0x0d | backup_eligible | u8, must be 1 |

## 6. Merge and writes

### 6.1 Counter (Lamport clock)

Each device keeps a counter in its local state. A new event uses
`max(next, highest counter seen in the folder + 1, highest counter previously seen + 1)`.
Several processes of the same device share the counter under the state lock (section 7).

### 6.2 Merge rule

Only events under the current generation are merged, and events whose writer is in
`removed(current)` are ignored. For each entity the winner is the event with the highest
key `(origin counter, origin device, rank, path)` where rank is 1 for a tombstone and 0
otherwise:

- credential id: put or tombstone. A tombstone wins a tie on `(counter, device)`; a live
  credential is one whose winner is a put.
- device id: device added (latest wins); device removed (a device stays removed).
- backup confirmed: present or not.

The path only breaks ties between exact duplicates, so the result is a total order.

### 6.3 Writes

Temp file `.<name>.tmp-<hex>` in the target directory (mode 0600, `O_EXCL`), write, fsync,
rename to the final name, fsync the directory. Readers never see partial files under a final
name; a file that is still incomplete on the receiving side (sync in progress) fails
authentication and is retried on the next reload.

### 6.4 Carrying own events forward

On reload a device looks for its own events (author tag verifies) under generations other than
the current one with a number not above it, including rejected ones. Each event that the
current view does not already hold with an equal or higher merge key is re-written under the
current generation with its origin unchanged. This saves writes made while the device had not
yet received a rotation. Events of other writers under old generations are never adopted.

### 6.5 Garbage collection

Once the current generation is older than 24 hours (its `created_at`), a device deletes record
files of older or sibling generations (number not above the current one) whose content the
current view holds with an equal or higher key, and the device slots of older generations.
`gen.info` and `recovery.slot` of every generation stay: they form the chain a recovery walks.
The delay avoids a device seeing an empty vault because deletions arrived before new files.

## 7. Local state (never synced)

Directory mode 0700, files 0600, one directory per device and vault.

```
device:   prefix(0x10) || TLV v1 { 0x01 vault_id, 0x02 device_id, 0x03 device secret [32],
                                   0x04 X25519 private key [32], 0x05 device name }
keyring:  prefix(0x11) || AEAD(device secret, aad("hirz keyring v1", [0x01, vault_id, device_id]),
                               TLV v1 { 0x01 recovery public key, 0x02 n x (GenId [20] || K [32] || root u8) })
counter:  prefix(0x12) || next u64 || max_seen u64
lock:     created with O_EXCL, holds the owner pid
```

The vault key is stored locally only wrapped by the device secret. The `device` file itself
is protected by file permissions (and full disk encryption); wrapping the device secret with a
TPM or a PIN is a later addition that does not change the synced format.

The lock guards counter and keyring updates only. A lock whose owner pid no longer exists, or
older than 60 seconds, is broken by renaming it aside and re-checking.

## 8. Recovery key

`E` = 32 random bytes, shown once as 24 words of the BIP-39 English list: the 264 bits
`E || SHA-256(E)[0]` split into 24 indices of 11 bits. Parsing is case-insensitive and accepts
a unique prefix of at least four letters; a wrong checksum is reported as such.

```
R_x25519 = HKDF(salt = "hirz recovery", ikm = E, info = "hirz recovery x25519 v1", 32)   private key of recovery slots
R_auth   = HKDF(salt = "hirz recovery", ikm = E, info = "hirz recovery auth v1", 32)     genesis tag
R_backup = HKDF(salt = "hirz recovery", ikm = E, info = "hirz recovery backup v1", 32)   backup exports
```

No Argon2 is applied: 256 bits of entropy are not guessable. Rotators seal new generations to
the recovery public key, so devices never need `E`.

### 8.1 Backup export (outside the vault)

```
prefix(0x06) || vault_id [16] || flags u8 (1 = passphrase) || salt [16]
             || m_cost u32 || t_cost u32 || p_cost u32 || AEAD(key, aad = all preceding bytes, body)
key  = HKDF(salt, ikm = R_backup || Argon2id(passphrase, salt, m, t, p, 32) if flagged,
            info = aad("hirz backup v1", [vault_id]), 32)
body = count u32 || count x (length u32 || credential record)
```

Export uses Argon2id with m = 64 MiB, t = 3, p = 4 (RFC 9106 second recommendation). Import
refuses m above 1 GiB, t or p above 16, more than 100000 records or records over 64 KiB.

## 9. Rotation and device removal

### 9.1 Procedure

To remove device `X`, a device `D`:

1. Reloads, and deletes key generation directories created by `X` that are not in its own
   current line (the user has declared `X` untrusted; this also ends a rotation conflict).
2. Creates `K'` and generation `G' = (current.number + 1, D)`.
3. Reserves `n` consecutive counters, writes the slots of every active device except `X` and
   every removed device, writes `recovery.slot`.
4. Re-writes every winning event (credentials, tombstones, devices, removals, backup) under
   `G'` with its origin kept, plus a fresh `device removed X` event: `n` events.
5. Adds `G'` to its keyring, then writes `gen.info` under the old key with
   `removed = {X}` (and any removal not yet applied by a generation), `reemit_first`,
   `reemit_count = n`.

Readers switch to `G'` once it is complete. Old files are collected later (6.5).

If the current generation still holds a slot for a device that a `device removed` event names
(two devices removed different devices at the same time), the next reload of any active
device rotates again, so concurrent rotations converge on a generation without either.

### 9.2 What rotation does and does not protect

Rotation protects **future** data: `X` holds no slot in `G'`, and nothing under `G'` can be
decrypted with the keys it had. Records written afterwards, including new passkeys, are out
of its reach.

Rotation cannot take back what `X` already had. A removed device that held the vault key has
had the opportunity to decrypt every passkey that existed up to its removal, and may keep
copies. The only remedy for those credentials is to register new passkeys at the sites
concerned and delete the old ones there. This is inherent to any synced passkey store.

Events that `X` writes after its removal under keys it still holds are ignored: they are not
under the current generation, and the carry-forward step only adopts events whose author tag
the adopting device can verify.

### 9.3 Rotation conflict

A removed device that still has write access to the folder can race the rotation that removes
it, creating its own child of the same parent that removes the honest rotator. By the conflict
rule both generations are then rejected on every device, and the vault falls back to the
parent generation, whose key the removed device also holds. hirz cannot tell which device is
legitimate, so it:

- reports `rotation_conflict`,
- refuses content writes (new or changed credentials, deletions) and all automatic
  maintenance,
- lets the user run "remove device" again on the trusted side, which discards the untrusted
  device's generations and rotates.

The user must first revoke the removed device's access to the synced folder (remove it from
the Syncthing share, revoke its app password, and so on); otherwise it can repeat the race.

## 10. Threat model of the format

**A copy of the synced folder** (cloud provider, stolen backup, a peer's disk) reveals:

- the vault id and creation time, the number of key generations and when they were created
  (directory names and file times), which device ids exist and which generation they hold
  slots in, the number of events each device wrote, event counters, file sizes and times.
- It does not reveal relying party ids, user names, device names, credential ids or keys:
  those are only inside AES-256-GCM ciphertext. File names contain no data derived from them.
- It is not a brute-force target: every key protecting it is random (256 bits). Only an
  optional backup export, kept outside the folder, involves a passphrase, and that export
  also requires the recovery key.

**Someone who can write to the folder** but holds no vault key can delete or withhold files,
replay older files, or corrupt files. Corrupt or moved files fail authentication and are
skipped. Forged generations fail: a slot sealed to a device's public key is not enough, since
`gen.info` must authenticate under the previous key, and the genesis is anchored in each
device's keyring or in the recovery key. Deletion and rollback cannot be prevented; a device
reports `rollback_suspected` when the highest counter in the folder drops below one it saw
before.

**A device that holds the current key** is fully trusted by the format: it can read and write
everything. Removing it is section 9.

**Local state** (`device` file) is protected by file permissions; any process running as the
same user can read it (see `docs/threat-model.md`).

Accepted limits: metadata in section 10 is visible; record sizes are not padded; a sync tool
that delivers a rotation's files to one device long before another leaves the second on the
old generation until it receives them (its writes are carried forward afterwards); a device
that joins while a rotation is in flight may need to join again.
