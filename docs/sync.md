# Syncing your passkeys between computers

hirz keeps your passkeys in a **vault folder**. Every file in it is encrypted and written
once, never changed afterwards. To have the same passkeys on several computers, you let a
file sync program copy that folder between them. hirz has no server and no account: you
choose where your encrypted files go.

What syncs and what does not:

| Folder | What it holds | Sync it? |
|---|---|---|
| The vault folder (default `~/.local/share/hirz/vault`) | Encrypted passkeys, the list of devices, encrypted vault keys | **Yes** |
| `~/.local/state/hirz` | This computer's own key and settings | **Never.** Each computer has its own |

A copy of the vault folder does not reveal your sites, account names or keys, and it cannot
be unlocked by guessing a password: the keys are random. It does show how many files there
are and when they were written. See [vault-format.md](vault-format.md), section 10.

The format and every command are described in [cli.md](cli.md).

## 1. Choose a sync program

Any program that copies a folder between computers works. Pick one you already use.

| Program | Good to know |
|---|---|
| Syncthing | Computer to computer, no cloud. Both computers must be on at the same time now and then, or one computer must always be on |
| Nextcloud | Your own or a hosted server, desktop client for Linux |
| Dropbox | Official Linux client |
| git | For people who already use git; you run the sync commands yourself |
| Others (rclone, Seafile, ...) | Fine, as long as they copy files and folders as they are |

hirz never writes the same file name twice, so sync programs do not create "conflicted
copy" files. If one appears anyway, hirz ignores it.

## 2. First computer: create the vault inside the synced folder

Create the vault as a **new, empty** folder inside the folder your sync program watches.
Replace the example paths with yours.

```
hirz init --vault ~/Sync/hirz
```

hirz shows your 24-word **recovery phrase** once. Write it on paper; do not copy, paste or
screenshot it. It is the only way back if you lose every computer, and it adds a computer
when no other one is at hand. hirz then asks you to type three of the words to check, and
clears the phrase from the terminal.

Already created the vault in the default place? Move it before adding passkeys: run
`hirz status` to see the folders, then start over (delete the vault folder and
`~/.local/state/hirz`) and run `hirz init --vault ~/Sync/hirz`.

### Syncthing, step by step

1. Install Syncthing on both computers and open its web page (usually
   http://127.0.0.1:8384).
2. On the first computer, choose **Add Folder**. Folder path: `~/Sync/hirz` (the vault
   folder). Give it a label such as `hirz`.
3. Connect the two computers: on each, **Add Remote Device** with the other computer's
   device ID (Actions, Show ID).
4. In the folder's **Sharing** tab, tick the second computer. Accept the folder on the
   second computer and choose an empty path there, for example `~/Sync/hirz`.
5. Wait until both show "Up to Date".

Syncthing only copies while both computers are on. If they rarely are, keep a third
device that is always on (a home server or a small board) in the share.

### Nextcloud, step by step

1. Install the Nextcloud desktop client on both computers and sign in.
2. Let it sync a local folder, for example `~/Nextcloud`.
3. On the first computer: `hirz init --vault ~/Nextcloud/hirz`.
4. On the second computer, wait until `~/Nextcloud/hirz` has been downloaded completely
   (the client shows the folder as synced).

### Dropbox, step by step

1. Install the Dropbox client on both computers and sign in. It syncs `~/Dropbox`.
2. On the first computer: `hirz init --vault ~/Dropbox/hirz`.
3. On the second computer, wait until `~/Dropbox/hirz` is fully synced.

Use only one sync program for the vault folder.

### git, step by step

Use a **private** repository. Every change is a new file, so merges never conflict.

First computer:

```
hirz init --vault ~/hirz-vault
cd ~/hirz-vault
git init
git add -A
git commit -m "hirz vault"
git remote add origin <your private repository>
git push -u origin HEAD
```

Second computer:

```
git clone <your private repository> ~/hirz-vault
```

To sync, on any computer, run in the vault folder (for example from a timer or before and
after you use your passkeys):

```
git pull --rebase
git add -A
git commit -m sync
git push
```

`git add -A` matters: hirz deletes old files after a while, and those deletions must be
synced too. Do not keep anything else in this folder.

## 3. Add a second computer

1. Install hirz on the second computer.
2. Set up your sync program there and wait until the vault folder has been copied
   completely.
3. On the **new** computer, run:

   ```
   hirz join --vault ~/Sync/hirz --request
   ```

   It shows four words, for example `MAPLE   ORBIT   QUARTZ   EMBER`, and waits.
4. On a computer that **already uses** the vault, once your sync program has copied the
   request there, run:

   ```
   hirz devices approve
   ```

   It shows four words, and nothing the new computer chose. Compare them with the words on
   the new computer. Type `yes` only if all four are exactly the same and you started the
   join yourself. If anything differs, answer no: someone who can change files in your synced
   folder may be trying to get your passkeys. hirz then deletes the request. Only after your
   `yes` does hirz show the name the new computer gave itself and ask whether that is the
   computer you are setting up (a name can be made up by anyone who can write to the folder,
   so it is never next to the words you compare).

   After the second `yes`, a hirz window shows the four words once more, alone, and then the
   name the device chose, and then asks
   for your system password, your fingerprint or your hirz PIN, as when you use a passkey.
   The device is approved only when that check succeeds; clicking Allow is never enough
   here, even for sites where you enabled click-to-allow. If this computer has none of
   those methods, `approve` refuses and tells you how to set a hirz PIN (`hirz pin set`)
   or install the polkit action ([approval.md](approval.md)). If you cancel the window or
   the check fails, nothing is approved and the request keeps waiting.
5. The new computer finishes as soon as the sync program has copied the approval back to
   it, and lists the other devices of the vault so you can check that it is yours.

The request is valid for 15 minutes. To refuse a request without looking at its words, run
`hirz devices deny ID` with the start of the id that `hirz devices approve` shows. Several
waiting requests when you started only one are a warning sign: deny the ones you do not
know.

Why four words are enough: an attacker would have to find another request with the same
words within those 15 minutes, and each attempt is deliberately slow to compute; see
[vault-format.md](vault-format.md), section 11.6. The approval itself is encrypted for the
new computer's own key, so a copy of the folder does not reveal it; it only shows the
names of computers that asked to join. The words protect you only if you compare them:
hirz never approves on its own.

**No other computer at hand?** Use the recovery phrase instead:

```
hirz join --vault ~/Sync/hirz
```

and type the 24 words (the first four letters of each word are enough). If `join` says the
phrase does not open the vault even though the words are right, the folder is probably not
completely copied yet: wait and try again.

Either way, the new computer gets its own key; the recovery phrase is not stored. Your
passkeys now count as backed up, so sites can see that you will not lose them with one
computer. Check both computers with `hirz devices` and `hirz status`.

New passkeys created on one computer appear on the others as soon as the sync program has
copied the new files. `hirz status` lists files that could not be read. A few files listed
for a short time usually means a copy is still in progress. Files listed for a long time are
damaged; your sync program's version history may have an intact copy.

## 4. Get your passkeys back after losing every computer

You need two things: the **recovery phrase** and a **copy of the vault folder** (from your
cloud account, another device in the Syncthing share, the git repository, or a backup).

1. Install hirz on the new computer.
2. Put the vault folder on it (sign in to the sync program, or clone the repository).
3. Run `hirz join --vault <the folder>` and type the recovery phrase.

If you have no copy of the vault folder but you kept an encrypted export file
(section 7), create a new vault with `hirz init` and run `hirz import --cxf <file>`.

Without the recovery phrase and without an export, the passkeys cannot be recovered. Sign
in to each site another way and create new passkeys.

## 5. Remove a lost, sold or old computer

On a computer you still use:

```
hirz devices
hirz remove-device <the first characters of its id>
```

After you answer yes, a hirz window shows the computer's name and id and asks for your
system password, your fingerprint or your hirz PIN, as when you approve a new device.

What this does:

- hirz creates a new vault key and gives it only to the remaining computers. The removed
  computer cannot read passkeys that are added or changed from now on.
- When the removed computer still runs hirz and its sync tool brings the change, it stops
  using the vault: browsers no longer get passkeys from it, and `hirz list`, `hirz devices`
  and `hirz status` say "This computer was removed from your hirz vault; its passkeys are
  no longer used here." On that computer, `hirz forget-local` deletes its hirz keys (the
  shared folder is left alone).

What it cannot do:

- The removed computer keeps everything it already read. Until its removal it could read
  every passkey in the vault. hirz lists those sites. To be safe, replace each of those
  passkeys: sign in to the site, create a new passkey, then delete the old one at the site
  and with `hirz delete`.
- Stopping on its own only works for a computer that runs an honest hirz. Someone who has
  the computer, or copied its files, is not stopped by it.
- hirz cannot take the folder away from it. Also stop sharing the vault folder with that
  computer: remove it from the Syncthing share, sign it out of Nextcloud or Dropbox (and
  revoke its app password), or revoke its access to the repository. Key changes it makes
  with its old keys are ignored by your other computers, but while it can change the folder
  it can delete the removal before a computer that has not seen it yet syncs. Until such a
  computer syncs the removal it still trusts the removed one, which can show it changed
  passkeys or make it remove another computer; once the removal arrives, all of that is
  undone on every computer. The removed computer never gets a key to passkeys added after its
  removal on a computer that saw the removal.
- Computers it approved stay. When you remove a computer, any computer it approved with
  `hirz devices approve` (or that one approved in turn) keeps its access. `hirz
  remove-device` lists them before it asks, with name, id and date. Someone who had the
  removed computer may have approved one of their own and named it like one of yours, so
  check each one and remove those you did not approve yourself. `hirz devices` marks
  computers in use that share a name with "(*)".
- The recovery phrase stays the same. If you think someone else learned it, create a new
  vault and move your passkeys there with `hirz export` and `hirz import`.

If both computers removed each other at about the same time, or the removed computer keeps
writing key changes into the folder, `hirz status` on a computer that saw neither removal
reports a conflict. Passkeys keep working there, but nothing new is saved and the computer is
not treated as removed. Stop sharing the folder with the computer you do not trust first, then
run `hirz remove-device` for it again on a computer you trust (any of them): this deletes the
key changes that rest on the untrusted computer. `hirz repair` lists the key changes this
computer does not follow, and `hirz repair --discard NAME` deletes one named key change after
you confirm and verify in a hirz window. Do not run `hirz forget-local` on a computer that
reports a conflict.

### Fork recovery

`hirz status` reports a **fork** when the vault folder no longer holds the key changes this
computer followed before: someone with access to the folder deleted or rewrote one, or your sync
tool restored an older copy of the folder. hirzd and hirz-nmh log it once, and hirzd also shows
a desktop notification. Passkeys keep working, but nothing new is saved and no automatic
maintenance runs: registrations are refused (hirz-nmh hands them to Firefox), changes such as
`hirz delete` fail with a message that points to `hirz repair`.

1. Run `hirz repair` to see the state. It lists the key changes this computer does not
   follow and says which device of the vault each one carries the name of.
2. Stop sharing the vault folder with every device you do not trust (remove it from the
   Syncthing share, sign it out of the cloud account, revoke its app password or repository
   access). Without this, whatever made the change can make it again.
3. Restore the folder from your sync tool's history (Syncthing file versions, the trash and
   version history of Nextcloud or Dropbox, `git` history). When the missing key change comes
   back, the fork ends by itself on the next request.
4. If a key change you do not trust is still there, delete it with
   `hirz repair --discard NAME`, using the name `hirz repair` printed. This deletes the key
   change and every one built on it. Run `hirz remove-device` for the untrusted device as
   well, so the vault key changes again.
5. Only when the folder cannot be restored and you trust it as it is now, run
   `hirz repair --accept-fork`. This computer then goes on from the newest key change it
   followed that is still in the folder, as the folder holds it now. Every computer it saw
   removed stays removed: key changes made through one are ignored, and if one could still
   read the vault key it goes on from, hirz changes the vault key again before it saves
   anything. Do this on one computer at a time, and check each one first.

`--discard` and `--accept-fork` both need your system password, fingerprint or hirz PIN in a
hirz window, and hirz asks a question first (`--accept-fork` asks you to type `follow`). There
is no way to skip the window. A join with the recovery phrase still works on a computer that
reports a fork, and while the folder is in a conflict: the new computer says so, and running
`hirz remove-device` there for the computer you do not trust settles the conflict.

## 6. "Backed up" and what sites see

When you sign in, hirz tells the site whether the passkey is backed up (the WebAuthn BS
flag). hirz says yes once:

- the vault has a second computer (`hirz join`), or
- you confirmed a backup with `hirz backup confirm`: answer yes only if your passkeys exist
  somewhere other than this computer (the vault folder is synced to a cloud or another
  device, or an export file is stored elsewhere).

Until then hirz says no, which is the truth: losing this one computer would lose the
passkeys.

## 7. Exporting and importing passkeys

`hirz export` writes all passkeys in the FIDO **Credential Exchange Format** (CXF) 1.0, the
format passkey managers use to move passkeys between each other. `hirz import` reads it.

```
hirz export --cxf ~/passkeys.hirz            # encrypted with a passphrase you choose
hirz export --cxf ~/passkeys.json --plain    # plain CXF for another passkey manager
hirz import --cxf ~/passkeys.hirz
```

- An encrypted export is a backup that does not need the vault folder or the recovery
  phrase, only its passphrase. Choose a long passphrase (several random words); anyone
  who gets the file can try to guess it.
- A plain export contains your private keys unencrypted. Import it into the other program
  right away, then delete it.
- An export gives out every private key, so it asks for user verification (system password,
  fingerprint or hirz PIN) in a hirz window before the file is built, as approving a device
  does. Neither export nor import works on a computer that another device removed from the
  vault.
- Import first lists the sites and accounts it would add, warns when one has the same site
  and user handle as a passkey hirz already has, and asks before it adds anything (`--yes`
  skips the question for scripts). An imported passkey signs in to the account it names, and
  a file you did not make yourself can name someone else's account under your user name.
- Import never replaces a passkey that hirz already has, and lists every passkey it skips
  with the reason. Passwords, notes and other non-passkey items in a CXF file are ignored.

### What is exported

One CXF `Account` with one `Item` per passkey; each item holds one `passkey` credential.

| CXF field | hirz value |
|---|---|
| Header `version` | `{ "major": 1, "minor": 0 }` |
| Header `exporterRpId`, `exporterDisplayName` | `hirz.berkati.xyz`, `hirz` |
| Header `timestamp` | export time, unix seconds |
| `Account.id` | 16 random bytes; `username` and `email` are empty strings |
| `Item.id` | the credential id |
| `Item.creationAt` | the passkey's creation time |
| `Item.title`, `Item.subtitle` | the site (RP id) and the user name |
| `Passkey.credentialId` | credential id, base64url |
| `Passkey.rpId` | RP id |
| `Passkey.username`, `userDisplayName` | user name and display name (empty string when unknown) |
| `Passkey.userHandle` | user handle, base64url |
| `Passkey.key` | private key, PKCS#8 DER, base64url |
| `fido2Extensions.hmacCredentials` | when the passkey has PRF / hmac-secret values: `algorithm: "hmac-sha256"`, `credWithUV`, `credWithoutUV` (32 bytes each, used as-is) |

CXF requires that passkeys with a non-zero signature counter are left out of exports. hirz
never uses a counter (it is always 0), so every passkey is exported, and imported passkeys
keep a counter of 0.

hirz adds an item extension named `hirz.berkati.xyz/passkey` (the CXF form for exporter
extensions) with fields CXF has no place for: `discoverable` (bool), `rpName` (the name the
site gave itself, when known) and `credProtect` (1 to 3, when set). Other programs ignore
it; hirz uses it when importing so a hirz to hirz round trip keeps every field. That
includes passkeys of OpenSSH security keys (`ssh:` and `ssh:NAME`) and any other site id
printable ASCII can write, which are kept exactly as hirz stored them. A passkey whose site
id has control characters or non-ASCII text is written to the file, but `hirz import`
cannot read it back, so `hirz export` lists those passkeys before it exports.

### Import rules

Every passkey is checked on its own; one bad passkey never stops the others.

| Field | Rule |
|---|---|
| `credentialId` | base64url (trailing `=` padding tolerated). Any length from 1 to 1023 bytes (the WebAuthn limit) is kept unchanged, so the site still recognises the passkey; hirz itself creates 32-byte ids. An empty or longer id skips the passkey |
| `rpId` | lowercased, must be a valid host name (`xn--` form for international names), or an OpenSSH security key id (`ssh:` or `ssh:NAME`, printable ASCII, kept as it is). In an item that carries hirz's own extension (a hirz export) any printable ASCII id is kept exactly, except machine login ids (`pam://`, `io.systemd.home`, `io.systemd.cryptsetup`), which hirz never serves. Those ids are skipped in every format, with a reason, instead of being stored where they could never be used |
| `username`, `userDisplayName` | text up to 1024 bytes; empty means unknown |
| `userHandle` | base64url, at most 64 bytes |
| `key` | PKCS#8 that parses as a P-256 (ES256) or Ed25519 key. RSA, P-384, P-521, Ed448 and unreadable keys are skipped, naming the key type |
| `hmacCredentials` | kept when the algorithm is `hmac-sha256` and both values are 32 bytes; other sizes skip the passkey (hirz could not reproduce the PRF results); unknown algorithms are ignored with a note |
| `credBlob`, `largeBlob` | not supported: the passkey is imported and the data is reported as not kept |
| `Item.creationAt` | creation time; missing, zero or later than the time of the import means the time of the import |
| unknown fields | ignored, as CXF requires |

Imported passkeys keep their original credential ids (1 to 1023 bytes) and work through both
the Firefox extension and the virtual security key, which reports a maximum credential id
length of 1023 bytes.

A passkey whose credential id is already in hirz is reported as already present when the key
is the same, and skipped when it differs. The file may be at most 64 MiB and hold at most
100000 passkeys. It is read with the same strict JSON reader as the Bitwarden and KeePassXC
files: nesting is limited to 32 levels, the document to 3000000 values, and duplicate
object keys and raw control characters in strings are refused, before any passkey is looked
at.

### Importing from Bitwarden and KeePassXC

```
hirz import --bitwarden ~/bitwarden_export.json
hirz import --keepassxc ~/passkeys/            # a .passkey file, or a folder of them
```

Duplicates, skipped passkeys and the report work as for CXF imports. Imported passkeys are
backup eligible (BE) like every hirz passkey, keep their original credential ids and start
with a signature counter of 0. Only passkey fields are read: passwords, notes, TOTP
secrets, card and identity data are never stored or shown. The file is read into a buffer
sized from its length, the parsers wipe what they built when a file fails to parse part way,
and hirz wipes the buffers it controls once it is done with them
(`docs/threat-model.md`, "Secrets in memory").

**Bitwarden** JSON exports (File > Export vault, format `.json`):

- Unencrypted exports are read directly.
- Password protected exports (`"passwordProtected": true`) ask for the file password, three
  tries. The key is derived from the password and the file's `salt` with PBKDF2-SHA256
  (5000 to 2000000 iterations) or Argon2id (2 to 10 iterations, 16 to 1024 MiB, 1 to 16
  lanes), the ranges Bitwarden accepts, then expanded with HKDF into an AES-256-CBC key and
  an HMAC-SHA256 key. The MAC is checked in constant time before anything is decrypted.
- Account restricted exports (encrypted with the Bitwarden account key) cannot be read
  outside Bitwarden; hirz says so. Export again as password protected or unencrypted.

From each item hirz reads `login.fido2Credentials` only:

| Field | Rule |
|---|---|
| `credentialId` | `b64.` followed by base64 (up to 1023 bytes once decoded) is used as is; otherwise a GUID that stands for its 16 bytes, as Bitwarden does |
| `keyType`, `keyAlgorithm`, `keyCurve` | must be `public-key`, `ECDSA`, `P-256`; other key types are skipped and named |
| `keyValue` | base64url PKCS#8 that must parse as a P-256 key |
| `rpId` | as for CXF files of other programs |
| `userHandle` | base64url, at most 64 bytes; empty or missing is allowed |
| `userName`, `userDisplayName`, `rpName` | text up to 1024 bytes |
| `discoverable` | `"true"` or `true` makes a discoverable passkey; anything else does not |
| `creationDate` | RFC 3339 UTC time; missing, malformed or in the future means now |
| `counter` | ignored |

The file may be at most 64 MiB with at most 200000 items and 100000 passkeys.

**KeePassXC** `.passkey` files (Entry > Passkey > Export) hold `relyingParty`, `username`,
`credentialId` and `userHandle` (base64url) and `privateKey` (a PKCS#8 PEM block). P-256
and Ed25519 keys are imported; RSA keys are skipped. Each file may be at most 64 KiB. A
folder is read non-recursively, every `*.passkey` file in name order; a file that cannot be
read is listed as skipped. File names are chosen by whoever made the folder, so every name
that reaches the terminal, in the skip list and in error messages, has control characters
replaced first. KeePass XML exports, which keep passkeys in `KPEX_PASSKEY_*`
entry attributes, are not supported: export the passkeys as `.passkey` files instead.

### Encrypted export file

The encrypted export is the CXF JSON document inside a small binary envelope:

```
magic        "HIRZ-CXF"                  8 bytes, ASCII
version      0x01                        1 byte
kdf          0x01 = Argon2id v1.3        1 byte
m_cost       u32 big endian, KiB         4 bytes
t_cost       u32 big endian              4 bytes
p_cost       u32 big endian              4 bytes
salt         random                      16 bytes
sealed       AES-256-GCM: nonce [12] || ciphertext || tag [16]

stretched = Argon2id(passphrase, salt, m_cost, t_cost, p_cost, 32 bytes)
key       = HKDF-SHA-256(salt = salt, ikm = stretched, info = "hirz cxf envelope v1", 32 bytes)
aad       = the 38 header bytes (magic through salt)
plaintext = the CXF JSON document (UTF-8)
```

- New exports use m = 64 MiB, t = 3, p = 4 (RFC 9106, second recommended option).
- Import refuses m above 1 GiB, t or p above 16, or t or p of 0, before doing any work, so
  a hostile file cannot demand absurd memory or time.
- The header is authenticated: changing any byte, including the cost parameters, makes
  the passphrase check fail.
- A wrong passphrase and a modified file give the same error.
- The passphrase is at least 12 characters and at most 1024 bytes.

This envelope is independent of the vault: it needs neither the recovery phrase nor the
vault key, so the file can be imported into any new vault. The vault itself has no other
export format (`docs/vault-format.md`, section 8.1 is reserved).
