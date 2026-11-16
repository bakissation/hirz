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
| 0x06 | reserved (an earlier backup export format, removed) |
| 0x07 | pairing request |
| 0x08 | pairing approval |
| 0x10 | local device state |
| 0x11 | local keyring |
| 0x12 | local counter |
| 0x13 | local line |

- **AAD encoding**: `aad(label, parts) = UTF-8(label) || 0x00 || for each part: (u32 length || part)`.
- **TLV body**: `version u8 || field*`, field = `tag u8 || length u16 || value`. The version
  byte versions each body on its own; the file prefix stays at format version 1. Tags appear in
  strictly increasing order, at most once. In credential records and generation info, unknown
  tags `>= 0x40` are skipped and unknown tags `< 0x40` make the body invalid. In events and
  local state every unknown tag is invalid.
- **AEAD**: AES-256-GCM with a random 12-byte nonce; output `nonce [12] || ciphertext || tag [16]`.
- **HKDF**: HKDF-SHA-256 (RFC 5869). **HMAC**: HMAC-SHA-256.
- **Sealed box** to an X25519 public key `R`: fresh ephemeral key `e`;
  `k = HKDF(salt = empty, ikm = X25519(e, R), info = "hirz x25519 seal v1" || e_pub || R, L = 32)`;
  output `e_pub [32] || AEAD(k, aad, plaintext)`. An all-zero shared secret is refused.
- **Signature**: Ed25519 (RFC 8032) over the stated message.
- Size caps on read: any vault file 1 MiB, strings 1024 bytes, user id 64 bytes, PKCS#8 key
  1024 bytes, device name 256 bytes, 512 members and 1024 removed ids per generation, 32
  announcements in an endorsement chain, 10000 key generations.

## 2. Directory layout

```
<vault>/
  hirz-vault                                     header
  keys/<gen-dir>/gen.info                        generation info
  keys/<gen-dir>/<hex(device id)>.slot           vault key sealed to a device
  keys/<gen-dir>/recovery.slot                   vault key sealed to the recovery key
  records/<hex(writer device id)>/<lamport>-<hex(random [8])>.rec   events
  pairing/<hex(request id)>.req                  pairing request (section 11)
  pairing/<hex(request id)>.ok                   pairing approval (section 11)
```

- `<gen-dir>` = `number` as 10 decimal digits, `-`, `hex(rotator)`. Example:
  `0000000002-6f1c...` (32 hex digits). `number >= 1`.
- `<lamport>` = 20 decimal digits (a u64). The random part makes names unique.
- Anything else is ignored: names that do not parse exactly (including sync-tool conflict
  copies such as `*.sync-conflict-*` or `* (conflicted copy)*`), names starting with `.`
  (temp files are `.<name>.tmp-<hex>`), and files where a directory is expected.
- Symbolic links are never followed inside the vault (the vault folder itself may be one). A
  file is read only when `lstat` says it is a regular file and the opened descriptor is that
  same file (device and inode), opened with `O_NONBLOCK`; anything else is skipped and
  reported. A directory inside the vault that is a symlink is skipped when reading and makes
  writes into it fail; writes create missing directories one component at a time and refuse a
  component that is not a real directory.
- Writes and deletions go through directories held open: each component is checked with
  `lstat`, opened, and must be the same directory (device and inode); the next component and
  the file are then reached through that descriptor (`/proc/self/fd/N/<name>`, as `openat` and
  `unlinkat` would), so swapping a checked directory for a symlink afterwards does not redirect
  them. Without `/proc` hirz falls back to the checked path, which leaves that short race open.

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
(number = parent number + 1, rotator = the device that rotates). Every generation is signed
by its rotator, and a child is only valid when its rotator was a member of the parent (4.4).

### 4.1 `gen.info`

```
prefix(0x03) || has_parent u8 || parent GenId [20] || AEAD(key, aad, body)
```

- `has_parent` is 0 for the genesis (parent field all zero), 1 otherwise.
- `key` is the **parent generation's key**; for the genesis it is the genesis key itself.
- `aad = aad("hirz gen info v1", [0x01, vault_id, gen_id, parent_or_zero])`.
- `body` (TLV version 3):

| Tag | Value |
|---|---|
| 0x01 | commitment [32] = HMAC(K, aad("hirz key commitment v1", [vault_id, gen_id])) |
| 0x02 | recovery public key [32] (X25519) |
| 0x04 | created_at u64, informational only: no decision uses it |
| 0x05 | reemit_first u64: first counter of the events the rotator re-wrote |
| 0x06 | reemit_count u64: number of those events |
| 0x07 | genesis only: recovery tag [32] = HMAC(R_auth, aad("hirz genesis v2", [vault_id, gen_id, commitment, recovery_pub, recovery_signing_pub])) |
| 0x08 | recovery signing public key [32] (Ed25519, section 8) |
| 0x09 | members: n x (device id [16], signing public key [32], X25519 public key [32]) concatenated, sorted by device id, n <= 512: every device the rotator sealed a slot to, the rotator included |
| 0x0a | optional endorsement chain: n x (length u16, device added payload of 5.2) concatenated, n <= 32 (4.4) |
| 0x20 to 0x3f | optional: the removals this generation makes (9.5), encoded as below and cut into consecutive fields of at most 65535 bytes starting at 0x20 |
| 0x7f | signature [64] by the rotator over aad("hirz gen info signature v1", [vault_id, gen_id, parent_or_zero, body bytes before this field]); must be the last field |

Removals: `n u32 || n x (removed device id [16] || cause device id [16] || cause event id [16]
|| m u32 || m x event id [16])`, `n <= 1024`, at most 50000 event ids in all, each list of
event ids sorted and without duplicates (9.5).

Each member's device id must be derived from its signing key (5.2), and the rotator must be a
member; the signature is checked with the rotator's member key. Because `gen.info` is sealed
under the parent key, only a holder of the parent key can create a child generation, and
because it is signed, only a member of the parent can be its rotator (4.4). Sealing a key to a
device's public key is possible for anyone with folder access, which is why a slot alone never
makes a generation valid.

### 4.2 Slots

```
<device>.slot:  prefix(0x04) || sealed box to the device X25519 key,
                aad = aad("hirz device slot v1", [0x01, vault_id, gen_id, device_id]), plaintext K
recovery.slot:  prefix(0x05) || sealed box to the recovery X25519 key,
                aad = aad("hirz recovery slot v1", [0x01, vault_id, gen_id]), plaintext K
```

A rotator writes the slots of all active devices and the recovery slot. A device that joins
writes its own slot into the current generation; for a device added by pairing, the
approving device writes it (section 11).

### 4.3 Resolving the current generation

A device trusts the generations in its local keyring (section 7); the genesis entry is the
root of trust. A device joining with the recovery key trusts the genesis whose recovery slot
opens, whose commitment matches and whose recovery tag verifies with `R_auth`.

Generations are processed in ascending order. A generation `G` with parent `P` is
**authentic** when `P` is authentic and its key is known, `G.number = P.number + 1`,
`gen.info` opens under `K_P` and its signature verifies (4.1), both recovery public keys equal
the parent's, and the rotator has an authority path in `P` (4.4). `path(G)` is that path, the
rotator included. If `path(G)` meets `removed(P)`, `G` is rejected. `removed(G) = removed(P) ∪`
the devices of `G`'s removals that are in force (9.5). The device then opens its own slot (or the keyring entry, or the recovery slot when
joining) and checks the commitment; a key that does not match is discarded. Authentic
generations without a key for this device still count in the next step, so every device that
holds the parent key and follows the same line reaches the same decision.

**Void generations.** A device that follows a line (7, 9.4) keeps `removed(line)`: every
removal that a generation of its line ever made (9.5), stored in its local line file, so the set
survives a generation of the line going missing from the folder, a move to another branch and
an accepted fork. It ignores every authentic generation other than the genesis outside its
line whose path meets a device of `removed(line)`, and every descendant of one. Its own line already
decided that the device the path rests on is untrusted. Void generations are reported with the
rejected ones and their accusations do not count on that device.

**Removals in force.** After the generations are resolved, the device decides which removals
are in force (9.5): those of every generation that is neither void nor rejected, and those of
`removed(line)`, except the voided ones. `removed(G)` and the conflict rule below use only
removals in force, and so does everything that follows.

**Exposed generations.** A generation outside the line, not void, whose member list names a
device that a removal in force removed (other than this device) is **exposed**: a device that
had not seen the removal made it, and the removed device holds its key. The device never
follows an exposed generation and does not read its content, but its accusations count
(conflict rule), and its removals in force apply everywhere: the device's next rotation leaves
those devices out too (9.1). Two devices that removed different devices at the same time
therefore each rotate once more and meet on a generation without either. Exposed generations
are not listed with the rejected ones: they settle by themselves once their rotator catches up.

**Tainted generations.** A generation that lists a voided removal, and everything built on it,
is **tainted**: the device whose removal was voided holds no key to its parent and cannot
follow it. A device never moves to a tainted generation, and a device whose pin is tainted
moves to the highest generation that is neither rejected, void nor tainted and is not an
ancestor of the pin, when one exists (it rotates there first if a removed device holds a slot).

**Conflict rule.** `G` is rejected when some authentic, non-void generation `D` that is not a
descendant of `G` has `path(G) ∩ removed(D)` non-empty; descendants of rejected generations
are rejected too. All accusations count at once. A rejection is **settled** when at least one
generation that accused it is not rejected itself.

**Completeness.** The genesis is complete. Another generation is complete when the records
directory of its rotator holds valid events under it for every counter in
`[reemit_first, reemit_first + reemit_count)`. The rotator writes `gen.info` last, but sync
tools deliver files in any order, so readers check this explicitly.

**Current generation.** The winner is the highest `(number, rotator)` among authentic,
non-rejected, non-void, non-exposed, non-tainted, complete generations for which the device has the key. A
device without a line (while joining) takes the winner. A device with a line takes the winner
too, unless the winner is a strict ancestor of its pin: then it stays on the pin (its pin lost
a conflict, or files of its pin are missing) and never falls back. The winner may be a
generation outside the line when the pin was rejected by a settled accusation or two honest
rotations happened at the same time; that is how concurrent rotations converge (9.1). When the
pin was rejected by a settled accusation and only exposed generations are left to move to, the
device follows the highest of them that is not an ancestor of the pin; a removed device then
holds the current key, so the device rotates before it writes anything (9.1, 9.4).

If an authentic, accepted descendant of the current generation exists for which the device has
no key, the device is **locked out** (it was removed, or joined after the rotation was
prepared) and refuses writes. If an unsettled rejected generation exists above the current
one, or the device stays on a pin that was rejected, the vault is in a **rotation conflict**
(section 9.3).

### 4.4 Authority of a rotator

A child `G` of `P` is only valid when its rotator was a member of `P`. The **authority path**
of the rotator `r` in `P` is:

- `{r}`, when `P`'s member list (4.1, tag 0x09) contains `r`;
- otherwise it is built from `G`'s endorsement chain (tag 0x0a): starting at `r`, take the
  announcement of the current device from the chain, check its endorsement (5.2) and add its
  endorser, until the endorser is in `P`'s member list (added to the path, end) or is the
  recovery key (verified with `P`'s recovery signing key, end). An announcement missing from
  the chain, a bad signature, a repeated device or more than 32 steps make `G` invalid.

Devices that joined `P` after it was created (pairing, recovery phrase) are not in its member
list, so their rotations carry the chain. A device endorsed by the recovery key needs no other
device; a device added by pairing rests on the device that approved it, and so on. Every
member list is signed by a rotator whose own authority was checked when its generation was
accepted, so the path ends either at someone holding the recovery phrase or at a device that
an accepted generation vouched for.

A device that was removed keeps the keys of the generations it was a member of and can still
write files into the folder. It can sign as itself and can endorse devices it makes up, but
every path it can build contains its own id. The generation that removed it therefore rejects
anything it builds (conflict rule, or void on a device that follows the removal).

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

### 5.2 Event (TLV version 2)

| Tag | Value |
|---|---|
| 0x01 | kind u8 |
| 0x02 | origin device id [16] |
| 0x03 | origin counter u64 |
| 0x04 | payload (TLV, below) |
| 0x05 | origin signing public key [32] (Ed25519) |
| 0x06 | origin signature [64] = Ed25519 by the origin over aad("hirz event signature v1", [vault_id, SHA-256(bytes before this field)]) |
| 0x7f | author tag [32] = HMAC(writer's device secret, aad("hirz author v1", [vault_id, P, bytes before this field])) |

The origin `(counter, device)` is the event's merge identity. A fresh event has origin =
(file counter, writer). An event re-written under a new generation keeps its origin and its
origin signature unchanged. The origin device id must be derived from the key in 0x05 (see
"Device identity" below) and the signature must verify; otherwise the record is skipped and
reported ("event signature does not verify"). So any device can carry an event forward, but
none can write one in another device's name. The **event id** is the first 16 bytes of
SHA-256(aad("hirz event id v1", [vault_id, SHA-256(bytes before 0x06)])): it names the content
and the origin, and stays the same through every re-write (9.5). Only the writer can verify the
author tag; it is used to recognise the writer's own events (6.4).

Payloads, all TLV version 1:

| Kind | Payload |
|---|---|
| 1 put credential | the credential record (5.3) |
| 2 tombstone | 0x01 credential id, 1 to 1023 bytes (TLV version 2; see below) |
| 3 device added | 0x01 device id [16], 0x02 name (UTF-8), 0x03 X25519 public key [32], 0x04 added_at u64, 0x05 signing public key [32] (Ed25519), 0x06 endorser [16], 0x07 endorsement [64] |
| 4 device removed | 0x01 device id [16], 0x02 removed_at u64 |
| 5 backup confirmed | 0x01 confirmed_at u64 |

Tombstone payloads are written as TLV version 2. Version 1 tombstones, whose credential id
is exactly 32 bytes, are still read.

**Device identity.** A device id is derived from the device's Ed25519 signing key:
`device_id = SHA-256(aad("hirz device id v1", [signing public key]))[0..16]`. A device added
payload whose id does not match its key is invalid, so a device cannot be announced again with
another key. The **endorser** is the device that approved a pairing, or 16 zero bytes for the
recovery key (vault creation and joining with the recovery phrase); a device never endorses
itself. The **endorsement** is a signature by the endorser over
`aad("hirz device endorsement v1", [vault_id, device id, name, X25519 key, added_at u64,
signing key, endorser])`. The same payload is used in endorsement chains (4.4).

### 5.3 Credential record (TLV version 2)

| Tag | Field | Value |
|---|---|---|
| 0x01 | credential_id | 1 to 1023 bytes (WebAuthn limit) |
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

hirz creates 32-byte credential ids. Passkeys imported from other providers keep the id their
original authenticator chose, so the site still recognises them; it can be any length from 1
to 1023 bytes.

**Version 1** records are byte-identical to version 2 except for the version byte, and the
credential_id field must be exactly 32 bytes long. Writers produce version 2 only; readers
accept version 1 and version 2 and refuse a version 1 record whose id is not 32 bytes. A
version 2 record with a 32-byte id differs from the version 1 encoding of the same record in
the first byte only (`0x01` becomes `0x02`). Builds that read only version 1 skip version 2
record files as malformed (`skipped` in the scan report) and must be upgraded; event and
file layouts around the record are unchanged, so nothing else is affected.
## 6. Merge and writes

### 6.1 Counter (Lamport clock)

Each device keeps a counter in its local state. A new event uses
`max(next, highest counter seen in the folder + 1, highest counter previously seen + 1)`.
Several processes of the same device share the counter under the state lock (section 7).

Counters from the folder are untrusted. Each scan sets a bound: it starts at
`max(next, max_seen) + 2^32` (0 + 2^32 for a device that is joining and has no counter file),
and every counter named in a record file name that is not above the bound raises the bound to
that counter + 2^32, in ascending order. A record whose file counter or origin counter is above
the bound is skipped and reported ("counter out of range"), so it never raises the counter,
`max_seen` or the merge view. One event numbered near `u64::MAX` therefore cannot exhaust the
counter space and freeze every writer: reaching it takes about 2^32 files, each within 2^32 of
the last. A member that writes one event at the top of the window does not hide the honest
events after it from a device that joins later, because their counters are within 2^32 of it.
Only this device's own `next` can overflow, which needs 2^64 local writes.

### 6.2 Merge rule

Only events under the current generation are merged, and events whose writer is in
`removed(current)` or was removed by a removal in force (4.3) are ignored. An event whose origin
a removal in force removed counts only when its event id is in the cutoff of every removal in
force of that device (9.5); others are skipped and reported ("event of a removed device after
its removal"). An event counts only when its origin is a member of the generation or a device
whose announcement counts there; others are skipped ("event of a device the generation does
not know"). A `device added` event counts only when its
announcement is one the generation vouches for: for a device in the member list, its keys must
equal the listed ones; for any other device the endorsement must verify with the recovery
signing key, or with the key of an endorser that is a member or a device whose announcement
counts and that is not removed (`removed(current)` and the removals in force). Announcements of
removed devices count for display only. Others are skipped and reported ("device added without
a valid endorsement"). A device approved by a device that was removed later therefore keeps
counting only because the removing rotator listed it as a member (9.2). For each entity the
winner is the event with the highest key `(origin counter, origin device, rank, path)` where
rank is 1 for a tombstone and 0 otherwise:

- credential id: put or tombstone. A tombstone wins a tie on `(counter, device)`; a live
  credential is one whose winner is a put. Ids are compared as whole byte strings, length
  included, so an id that is the prefix of another is a different entity, and lookups by id
  are exact matches.
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
current generation with its origin and signature unchanged, but only when it would count under
the current generation (6.2): an event of a removed device only within the cutoffs, an event
of a device the generation knows, and a `device added` only with a valid endorsement. This saves writes made while the device had not yet
received a rotation. Events of other writers under old generations are never adopted. When the
device is about to rotate (9.1), it rotates first and the rotation re-writes these events, so
they never pass through a generation that a removed device can open.

### 6.5 Garbage collection

Once the current generation has been current on this device for 24 hours (the `first_seen`
time of its line entry, section 7, taken from the local clock; never `created_at`, which the
rotator chooses), a device deletes record files of older or sibling generations (number not
above the current one) whose content the current view holds with an equal or higher key, and
the device slots of older generations. Nothing is collected during a rotation conflict or a
fork.
`gen.info` and `recovery.slot` of every generation stay: they form the chain a recovery walks.
The delay avoids a device seeing an empty vault because deletions arrived before new files.

## 7. Local state (never synced)

Directory mode 0700, files 0600, one directory per device and vault.

```
device:   prefix(0x10) || TLV v1 { 0x01 vault_id, 0x02 device_id, 0x03 device secret [32],
                                   0x04 X25519 private key [32], 0x05 device name,
                                   0x06 Ed25519 signing seed [32] }
keyring:  prefix(0x11) || AEAD(device secret, aad("hirz keyring v1", [0x01, vault_id, device_id]),
                               0x02 || recovery public key [32] || n u32 || n x (GenId [20] || K [32] || root u8))
counter:  prefix(0x12) || next u64 || max_seen u64
line:     prefix(0x13) || 0x03 || n u32 || n x (GenId [20] || info hash [32] || first_seen u64)
                       || removals (as in 4.1)
lock:     created with O_EXCL, holds the owner pid
```

The device id must match the signing seed (5.2). The keyring holds at most 10000 generations;
its count is 32 bits wide, so the cap, not the encoding, is the limit, and a rotation that
would pass it is refused.

The **line** is the chain of generations this device follows, genesis first and the current
one (the **pin**) last, with the **info hash** of each generation as first read and the local
time the device first made it current, followed by `removed(line)`: every removal (with cause
and cutoff, 9.5) that a generation of the line ever made, minus those later found void. The
info hash is SHA-256 of the authenticated
plaintext of `gen.info` (the signed body and the signature), not of the file: a holder of the
parent key can encrypt the same body again under a new nonce, which changes the file but not
the hash. The line is written whenever the current generation or `removed(line)` changes,
except during a fork. Section 9.4 says how it is used.

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
R_sign   = HKDF(salt = "hirz recovery", ikm = E, info = "hirz recovery ed25519 v1", 32)  Ed25519 seed that endorses devices
```

No Argon2 is applied: 256 bits of entropy are not guessable. Rotators seal new generations to
the recovery public key, so devices never need `E`. The device that creates the vault and
every device that joins with the phrase are endorsed with `R_sign` (5.2).

**The recovery key cannot be changed.** Every generation must carry the parent's recovery
public keys (4.3), so every future generation key is sealed to the same `R_x25519`, whatever
devices are removed. Whoever learns the 24 words and can read the folder can open every
generation, past and future. Removing a device does not help against that; the only remedy
today is a new vault (`hirz init` in a new folder, then export and import the passkeys). A
rotation that installs a new recovery key, signed by the rotator as in 4.4, is planned.

### 8.1 Backup export (reserved)

File type 0x06 and a derivation `R_backup` belonged to an earlier vault backup export that no
command used; it was removed. Passkeys are exported in the CXF format instead
(`docs/sync.md`, section 7), which does not use the recovery phrase.

## 9. Rotation and device removal

### 9.1 Procedure

To remove device `X`, a device `D`:

1. Reloads, and deletes key generation directories that are not in its own current line and
   were created by `X` or have an authority path through `X` (4.4), with everything built on
   them (the user has declared `X` untrusted; this also ends a rotation conflict that `X`
   caused; a fork needs 9.4).
2. Creates `K'` and generation `G' = (current.number + 1, D)`.
3. Reserves `n` consecutive counters, writes the slots of every active device except `X`,
   every removed device and every device of a removal in force (4.3), writes `recovery.slot`.
4. Re-writes every winning event (credentials, tombstones, devices, removals, backup) under
   `G'` with its origin and signature kept, together with its own events from other
   generations that the view does not hold yet (6.4), plus a fresh `device removed` event for
   `X`: `n` events.
5. Adds `G'` to its keyring, then writes `gen.info` under the old key with its removals
   (9.5): for `X`, cause = the fresh `device removed` event and cutoff = the ids of `X`'s
   events among the `n` it re-wrote; for a device removed by a `device removed` event in the
   view, cause = that event; a removal in force that the current generation has not applied
   yet is copied unchanged. Then `reemit_first`,
   `reemit_count = n`, the members it sealed slots to and, when the current generation does
   not list `D`, its endorsement chain (4.4), signed with `D`'s key.

Readers switch to `G'` once it is complete. Old files are collected later (6.5). If `D` itself
made a generation with the id of `G'` earlier that is not in its line any more (its `gen.info`
was deleted and `D` accepted the fork), `G'` replaces it: `D` re-writes its own events from it
in step 4, deletes its own record files under it after step 5 and replaces the keyring entry.
Other devices that hold the old key keep reading records under it with that key until they
carry their own events forward.

If the current generation still holds a slot for a device that a `device removed` event names
or that a removal in force removed (two devices removed different devices at the same time),
the next reload of any active device rotates again before it
carries anything forward, so concurrent rotations converge on a generation without either. A
slot only counts when the generation's signed member list names the device, or when a `device
added` event under the generation's own key, outside the rotator's re-emitted range, added it
later. A slot file's name alone never counts, so someone without the key cannot make devices
rotate by planting files. While a device removed by a removal in force holds a slot in the
current generation, content writes and carrying events forward are refused until such a
rotation succeeds.

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
the adopting device can verify. Generations that `X` writes after its removal, under its own id
or under ids it makes up and endorses, have authority paths through `X` (4.4): a device that
follows the removal ignores them (void, 4.3), and every other device rejects them because the
removing generation accuses them. A device that has not seen the removal yet and finds only
`X`'s generations, because `X` deleted or withheld the removing one, cannot tell; see
section 10.

A device `B` that has not seen the removal still trusts `X` until it does: `X` can make `B`
show passkeys it changed, remove devices or approve devices `X` made up, and when `B` rotates,
its new generation lists `X` as a member. None of it outlasts `B` catching up (9.5). A device
that saw the removal never follows such a generation (exposed, 4.3), never writes under a key
`X` holds (9.1) and does not read its content. Every event `X` made after its removal is
outside the removal's cutoff, so it counts nowhere once the removal is known, whoever carries
it; a removal whose cause is such an event is void, so the device `X` had removed keeps its
place; and devices `X` approved after its removal never count. When `B` learns of the removal it
drops all of that from its view, leaves its own generations that rest on a voided removal, and
carries forward only its own events that count (6.4).

What `B` wrote itself while it was misled stays: a passkey the user registered on `B` in that
time, or a device the user approved on `B`. Those are the user's own actions on a device that
was not removed.

**Devices that `X` approved stay.** A device `Y` that `X` approved by pairing, or endorsed
through a device it approved, keeps its slot when `X` is removed: the removing rotator lists it
as a member like every active device. Each was approved while `X` was trusted, and hirz cannot
tell a device the user approved on `X` from one that someone holding `X` approved without the
user (with `X`'s keys no user verification is needed). `Vault::devices_resting_on` lists them;
`hirz remove-device` shows them with name, id and date added and a warning before it asks, and
`hirz devices` marks devices in use that share a name. Removing each of them is the user's
decision.

### 9.3 Rotation conflict

A removed device that still has write access to the folder can race the rotation that removes
it, creating its own child of the same parent that removes the honest rotator (or, later, a
generation resting on it that removes honest devices). Each of the two rotators keeps the line
it chose: the other generation is void there. A device that followed neither cannot tell
which one is legitimate: by the conflict rule both are rejected there, the device stays on the
parent generation (whose key the removed device also holds), and hirz:

- reports `rotation_conflict` and lists the rejected generations in the scan report,
- keeps serving the passkeys it has (reading never stops),
- refuses content writes (new or changed credentials, deletions) and all automatic
  maintenance,
- never reports the device as removed because of a generation outside its line,
- lets the user run "remove device" again on a device they trust, which discards the
  generations resting on the untrusted device and rotates, or discard a named generation
  directory after user verification (`Vault::discard_generation`, behind `hirz repair
  --discard`).

Joining with the recovery phrase still works during a conflict, so a user who lost every
device can join and settle it from the new device: the new device stores the keys of the
generations of the unsettled conflict that its recovery slot opens, so after "remove device"
discards one side it can follow the other. The user must first revoke the removed device's
access to the synced folder (remove it from the Syncthing share, revoke its app password, and
so on); otherwise it can repeat the race.

### 9.4 The line a device follows, and forks

Each device records the line of generations it follows (section 7). On every reload:

- every generation of the stored line must still be in the folder, authentic, with the same
  info hash (7) as when it was first followed. Otherwise the device reports `fork_detected`:
  someone with folder access deleted a generation it already trusted, or its rotator rewrote
  it. It then keeps serving from the newest generation of its line that is still present,
  refuses every write including rotations, and runs no automatic maintenance;
- it never moves to an ancestor of its pin (4.3), so a removal it has followed stays in
  force even if the removing generation is accused later;
- generations resting on a device of `removed(line)` are void and generations listing a
  device removed by a removal in force as a member are exposed (4.3), whether or not the
  generation that removed it is still in the folder;
- `this_device_removed` is set only when the current generation, or an accepted descendant
  of it that this device has no key for, removes this device. Void and exposed generations
  never set it, so a removed device that deletes the removing generation and forges a removal
  of the honest devices only causes a fork on the devices that saw its removal.

A fork ends when the files come back (sync history), or when the user, after checking the
folder, tells hirz to follow the folder as it is now (`Vault::accept_fork`; `hirz repair
--accept-fork`, after user verification). Accepting cuts the line back to the newest
generation of it that is still present, taking the folder's current version of it and its
ancestors, and keeps `removed(line)`: every removal the line made stays in force, generations
resting on a removed device stay void, and when a removed device holds a slot in the
generation the device now follows, the device rotates (9.1) before it writes anything.
`remove-device` does not end a fork: it discards generations outside the line that rest on the
device, but cannot bring back a missing generation, and rotating is refused during a fork.

### 9.5 Removal causes and cutoffs

Every removal a generation makes names its **cause**, the `device removed` event that led to it
(its origin device and event id, 5.2), and its **cutoff**, the ids of every event of the removed
device that the remover re-wrote when it removed it: everything of that device the remover held
and trusted. Events are signed by their origin, so the removed device cannot make an event
appear in another device's name, and the cutoff lists ids, not counters, so a backdated counter
does not bring an event under it. A removal is copied unchanged (same cause, same cutoff) when
another device applies it, so copies are one decision.

Once a removal of a device `X` is in force:

- an event whose origin is `X` counts only when every removal in force of `X` lists it in its
  cutoff (if two devices removed `X` without seeing each other's removal, only events both held
  count);
- a removal whose cause is an event of `X` is **void** when no removal in force of `X` lists
  that event in every cutoff, unless that removal removes the device that caused the removal of
  `X` (two devices removing each other is a race for the conflict rule, 9.3, not a voiding).
  Voiding is decided in two rounds: removals voided in the first round do not void others in
  the second.

A void removal does not count in `removed(G)`, its device keeps its place, and the generations
listing it are tainted (4.3). Removals are only checked against removals in force: generations
that rest on `X` (void) or lost a conflict cannot void anything.

## 10. Threat model of the format

**A copy of the synced folder** (cloud provider, stolen backup, a peer's disk) reveals:

- the vault id and creation time, the number of key generations and when they were created
  (directory names and file times), which device ids exist and which generation they hold
  slots in, the number of events each device wrote, event counters, file sizes and times.
- It does not reveal relying party ids, user names, device names, credential ids or keys:
  those are only inside AES-256-GCM ciphertext. File names contain no data derived from them:
  record names are a counter and random bytes, whatever the length of the credential id.
- It is not a brute-force target: every key protecting it is random (256 bits). Nothing in
  it is derived from a passphrase; the optional passphrase of an encrypted CXF export
  (`docs/sync.md`, section 7) only protects that file, which is kept outside the folder.

**Someone who can write to the folder** but holds no vault key can delete or withhold files,
replay older files, corrupt files, or plant symlinks. Corrupt or moved files fail
authentication and are skipped; symlinks are never followed (section 2). Forged generations
fail: a slot sealed to a device's public key is not enough, since `gen.info` must authenticate
under the previous key and carry a member's signature, and the genesis is anchored in each
device's keyring or in the recovery key. Planted slot files never trigger a rotation (9.1).
Deletion and rollback cannot be prevented, only partly detected:

- a device reports `rollback_suspected` when the highest counter in the folder drops below
  the highest it saw before, or when files of the generation it follows go missing;
- withholding or deleting a single older file (a tombstone, a `device removed` event, one
  credential) is **not** detected: a deleted passkey whose tombstone is withheld is live
  again on every device, with no report. There is no per-writer hash chain or signed event
  count yet;
- deleting or rewriting a generation a device already follows is reported as a fork (9.4).

**A removed device that can still write to the folder** holds the keys of every generation it
was a member of. Against a device that saw the removal it can do little beyond the above: its
generations are void there and generations that still give it a slot are exposed (9.4), so the
device never follows them or writes under a key the removed device holds, even after the
removing generation is deleted. Through a device that has not seen the removal yet it can
mislead only that device, and only until it catches up: every event the removed device made
after its removal, and every removal caused by one, is void as soon as the removal is known
(9.5). A device that has not seen the removal yet, and a new device joining, decide by the
conflict rule: they reject the removed device's generations while the removing generation is
in the folder, and report a conflict if the removed device also forged removals of honest
devices. If the removed device deletes or withholds the removing generation before another
device sees it, that device cannot know about the removal and follows the removed device's
generations; the devices that did follow the removal report a fork as soon as the folder
changes under them. Devices the removed device approved while it was trusted keep their access
(9.2). Revoking the removed device's access to the folder is therefore part of removing it.

**Event counters** from the folder are bounded (6.1): a key holder cannot exhaust the counter
space of other devices, nor hide later events from a device that joins.

**Pairing** (section 11) adds plaintext files that reveal the names and public keys of
devices asking to join, and lets anyone who can write to the folder ask to join. Such a
request is only approved when the user confirms on a trusted device that its four words
match those on the new device; section 11.6 explains why that is enough.

**A device that holds the current key** is fully trusted by the format: it can read and write
everything. Removing it is section 9.

**Local state** (`device` file) is protected by file permissions; any process running as the
same user can read it (see `docs/threat-model.md`).

Accepted limits: metadata in section 10 is visible; record sizes are not padded; a sync tool
that delivers a rotation's files to one device long before another leaves the second on the
old generation until it receives them (its writes are carried forward afterwards); a device
that joins while a rotation is in flight may need to join again.

## 11. Device pairing

A new device can join without the recovery key: it asks through the folder, and a device
that already holds the vault key approves it after the user has compared four words shown on
both screens. The folder is the only channel; there is no relay, no server and no password
exchange (PAKE). The recovery key (section 8) stays the fallback.

### 11.1 Request: `pairing/<hex(request id)>.req`

Written by the new device. Plaintext, because it holds only public data:

```
prefix(0x07) || TLV v1 { 0x01 request_id [16], 0x02 device_id [16], 0x03 name (ASCII, 1 to 32 bytes, see below),
                         0x04 X25519 public key [32], 0x05 created_at u64, 0x06 expires_at u64,
                         0x07 Ed25519 signing public key [32] }
```

The X25519 and signing key pairs are created for this request and kept in memory only; the
device id must be derived from the signing key (5.2), otherwise the request is malformed.
`expires_at - created_at` is between 1 second and 15 minutes (writers use 15 minutes); other
values make the request malformed. The request id must equal the file name. A request is
**usable** while `now <= expires_at` and `created_at <= now + 5 minutes` (device clocks
differ). A new device refuses to start pairing when the folder holds no genesis generation
(not synced yet) or more than one generation directory with number 1 that is shaped exactly
like a genesis: a `gen.info` with the genesis prefix (`has_parent = 0`) and the exact length of
a genesis `gen.info` (one member, a recovery tag, no removals, no chain), and a `recovery.slot`
of the exact slot length. Candidates that are not real directories or have another shape are
junk and ignored. Two candidates of that shape cannot be told apart without a key, so the new
device asks the user to join with the recovery phrase; someone who can write to the folder can
cause that, as they can stop pairing by deleting files.

The name is chosen by the new device and is not authenticated, and anyone who can write to
the folder can make one up. A request is well formed only when its name has 1 to 32 characters
of ASCII letters, digits, space, `-`, `_` and `.`, no leading, trailing or doubled space, no
token of three or more capital letters, and at most two tokens that read as words of the BIP-39
list (as the recovery phrase parser reads a word: an exact match, or four or more letters that
start exactly one word), so that a name cannot spell the verification words of section 11.2.
Tokens are separated by space, `-`, `_` and `.`. A request with another name is malformed:
approvers do not list it and delete it after 20 minutes. A new device that is given or finds
another name (the host name, `--name`) reduces it before it writes the request: other characters
become `-`, white space is collapsed, capitals words are lowercased, the name is cut to 32 bytes,
and a name that still breaks a rule becomes `new-device`. The name in the request is the name
the device registers under.

### 11.2 Verification words

```
F     = SHA-256(bytes of keys/<genesis>/gen.info)
input = aad("hirz pairing words v1", [0x01, vault_id, F, request_id, device_id, name,
                                      public key, created_at u64, expires_at u64, signing key])
h     = Argon2id(password = input, salt = request_id, m = 64 MiB, t = 3, p = 4, 32 bytes)
words = the first 44 bits of h as four 11-bit indices into the BIP-39 English list
```

The new device computes the words from the vault id and genesis it found in the folder. The
approving device computes them from the request it read and **its own** vault id and
genesis (the root entry of its keyring), never from claims in the request. Every field of the
request and the identity of the vault are therefore bound into the words: changing the public
key, the name, the device id or the times, or showing the new device a different vault,
changes them. The genesis `gen.info` is written once and never collected (6.5), so `F`
identifies the vault even if a header with the same vault id is copied.

### 11.3 Approval

The user runs the approve command on a device that holds the current key and confirms that
the words match. That device then:

1. checks that the request file still holds exactly the request the user saw and is still
   usable (otherwise nothing is written: the file changed or expired in the meantime), that
   its device id is not a device the vault already knows (active or removed), and that the
   vault allows content writes (no rotation conflict, not locked out);
2. writes `keys/<current>/<hex(device id)>.slot`, the current key sealed to the request key
   (section 4.2);
3. writes `pairing/<hex(request id)>.ok`:

   ```
   prefix(0x08) || expires_at u64 || sealed box to the request's X25519 key,
     aad = aad("hirz pairing approval v1", [0x01, vault_id, request_id, device_id,
                                            public key, expires_at u64]),
     plaintext = n x (GenId [20] || K [32])
   ```

   with every generation from the genesis to the current one, in order (numbers 1, 2, ...,
   current; at most 10000 entries, the keyring cap). `expires_at` must equal the request's;
4. writes a `device added` event (kind 3) for the new device with its name, public key and
   signing key, endorsed by the approving device (5.2). It is an ordinary event under the
   current generation, covered by the author tag, the generation rules and the merge rule
   (6.2);
5. deletes the request file.

A request whose device id the vault already knows is never offered again and is deleted,
so a request can be approved once.

### 11.4 Finishing on the new device

The new device polls the folder for `pairing/<hex(request id)>.ok`. When it appears, the
device:

1. opens it with its private key (the AAD binds the vault, the request id, the device id,
   the public key and the expiry, so an approval of another request does not open);
2. checks that the chain starts at the genesis it saw when it made the request, opens that
   genesis `gen.info` with the first key and checks the key commitment, and takes the
   recovery public key from it;
3. resolves the generations (4.3) with the received keys as its keyring, genesis as root;
   every received key must belong to an authentic generation and match its commitment;
4. waits (keeps polling) while it would be locked out, while there is a rotation conflict, or
   while the current generation does not yet hold a `device added` event for its own device
   id, public key and signing key from a non-removed writer: the sync tool may deliver those
   files later;
5. then writes its local state (section 7) with every key it can now open, exactly as a
   recovery join does, and deletes the request and approval files.

It writes nothing into the folder: its slot and `device added` event come from the approver.
An approval that fails step 1, 2 or 3 is reported and ignored; polling continues, because a
file still being copied fails the same way. The new device stops polling two minutes after
`expires_at` and then deletes its request.

### 11.5 Cleanup

A listing returns at most 16 usable requests, oldest first, and says how many more there are,
so a folder full of planted requests cannot flood the approval screen. When a device lists
requests it deletes requests that expired or name a known device,
approvals more than one hour past their `expires_at`, and request or approval files that have
been unreadable for more than 20 minutes (by modification time; a shorter-lived unreadable
file may still be syncing). Other names in `pairing/` are ignored.

### 11.6 Security

**Someone who can only read the folder** learns the names and public keys of devices asking
to join and when they asked. The approval is sealed to the new device's key.

**Someone who can write to the folder** can plant requests with their own key, delete or
replace requests, and write fake approvals.

- A planted request is only approved if the user confirms on a trusted device that its words
  match the words on the screen of the new device. That comparison is the security of
  pairing: the approve command shows the words prominently, explains that a mismatch means
  tampering, asks the user to type `yes`, has no option to skip the question, and deletes the
  request on any other answer. It then shows the words again in a hirz window and requires
  user verification (system password, fingerprint or hirz PIN; a click never counts) before
  writing anything. Several waiting requests are flagged as suspicious.
- The device name is untrusted text that anyone who can write to the folder can set, so the
  approver treats it as data and keeps it out of the comparison: the terminal and the hirz
  window show the four words and nothing else the other device chose (a list of several
  requests shows the words of each, not names), and only after the user said that the words
  match do they show the name, labelled as chosen by the device and put in brackets, and ask
  for a second confirmation. The name is also limited as described in 11.1, so a planted
  request called after the genuine words cannot spell them.
- To pass the comparison, a planted request must produce the same four words as the genuine
  one. The words carry 44 bits. The attacker sees the genuine request only once it is in the
  folder and must find a matching request before the user approves, within the 15-minute
  lifetime: a second preimage on 44 bits, about 2^43 tries on average, each costing one
  Argon2id evaluation with 64 MiB. At a generous 10^4 evaluations per second that takes
  about 28 years, so the success probability within 15 minutes is about 2^-21. A plain hash
  would not be enough: 2^43 SHA-256 evaluations take minutes on one graphics card. Requests
  made in advance do not help either, since every word evaluation costs the same and the
  creation time must be within the usable window. 44 bits are enough because the
  comparison is interactive and short-lived; they would not be for a long-term fingerprint.
- Swapping the request file after the user compared the words does not redirect the key: the
  approver seals to the request as shown and refuses if the file changed.
- A fake approval written without the vault key fails at 11.4: the keys do not open the
  genesis `gen.info` the new device saw, or do not match the commitments of the generations.
  A removed device that still holds old keys can open old generations but not the current
  one, so the new device stays waiting and gives up at expiry; generations it forges with
  the old keys rest on it and are rejected (4.4), so a chain through them is refused.
- A request that reuses the id of an existing device is refused, so pairing cannot replace a
  device's public key.

**Limits.** The new device has no prior anchor: it trusts the single genesis it finds in the
folder when it makes the request. A sync service that shows the new device a completely
different, attacker-made vault can approve its own vault immediately; the new device then
holds none of the user's passkeys and new passkeys made on it go to that vault. The words do
not match on the user's trusted device in that case (the genesis is bound into them), and the
new device lists the other devices of the vault it joined, so the user can notice. The
recovery key join (section 8) has an anchor and is not affected.

Approving requires typing `yes` in a terminal session of the user and then passing user
verification (system password, fingerprint or hirz PIN, see `docs/approval.md`), so someone
at an unlocked session who does not know the password, a finger or the PIN cannot add a device
without it. This does not stop a process already running as the user: it can read the device
state file (section 7), which gives it the vault key, without pairing at all. The hirz PIN is
weaker than the other two in one respect: it is a verifier file in the user's state directory
that `hirz pin set` creates without any proof when none exists, so someone with a shell in the
unlocked session can set a PIN of their own, list `pin` first in the `methods` line of the
approval config and then pass this check. The password and the fingerprint cannot be provisioned
that way. A user who wants approval of devices to resist a person at the shell should keep
`methods` to the password and the fingerprint.
