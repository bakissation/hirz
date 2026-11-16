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

hirz shows your 24-word **recovery phrase** once. Write it on paper. You need it to add a
computer, and it is the only way back if you lose every computer. hirz then asks you to
type three of the words to check.

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
3. Run:

   ```
   hirz join --vault ~/Sync/hirz
   ```

4. Type the 24-word recovery phrase. The first four letters of each word are enough.

The new computer gets its own key; the recovery phrase is not stored. Your passkeys now
count as backed up, so sites can see that you will not lose them with one computer. Check
both computers with `hirz devices` and `hirz status`.

If `join` says the phrase does not open the vault even though the words are right, the
folder is probably not completely copied yet: wait and try again.

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

What this does:

- hirz creates a new vault key and gives it only to the remaining computers. The removed
  computer cannot read passkeys that are added or changed from now on.

What it cannot do:

- The removed computer keeps everything it already read. Until its removal it could read
  every passkey in the vault. hirz lists those sites. To be safe, replace each of those
  passkeys: sign in to the site, create a new passkey, then delete the old one at the site
  and with `hirz delete`.
- hirz cannot take the folder away from it. Also stop sharing the vault folder with that
  computer: remove it from the Syncthing share, sign it out of Nextcloud or Dropbox (and
  revoke its app password), or revoke its access to the repository.

If both computers removed each other at about the same time, `hirz status` reports a
conflict. Stop sharing the folder with the computer you do not trust first, then run
`hirz remove-device` for it again on the computer you trust.

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
- Import never replaces a passkey that hirz already has, and lists every passkey it skips
  with the reason. Passwords, notes and other non-passkey items in a CXF file are ignored.

### What is exported

One CXF `Account` with one `Item` per passkey; each item holds one `passkey` credential.

| CXF field | hirz value |
|---|---|
| Header `version` | `{ "major": 1, "minor": 0 }` |
| Header `exporterRpId`, `exporterDisplayName` | `hirz.dev`, `hirz` |
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

hirz adds an item extension named `hirz.dev/passkey` (the CXF form for exporter
extensions) with fields CXF has no place for: `discoverable` (bool), `rpName` (the name the
site gave itself, when known) and `credProtect` (1 to 3, when set). Other programs ignore
it; hirz uses it when importing so a hirz to hirz round trip keeps every field.

### Import rules

Every passkey is checked on its own; one bad passkey never stops the others.

| Field | Rule |
|---|---|
| `credentialId` | base64url (trailing `=` padding tolerated). Any length from 1 to 1023 bytes (the WebAuthn limit) is kept unchanged, so the site still recognises the passkey; hirz itself creates 32-byte ids. An empty or longer id skips the passkey |
| `rpId` | lowercased, must be a valid host name (`xn--` form for international names) |
| `username`, `userDisplayName` | text up to 1024 bytes; empty means unknown |
| `userHandle` | base64url, at most 64 bytes |
| `key` | PKCS#8 that parses as a P-256 (ES256) or Ed25519 key. RSA, P-384, P-521, Ed448 and unreadable keys are skipped, naming the key type |
| `hmacCredentials` | kept when the algorithm is `hmac-sha256` and both values are 32 bytes; other sizes skip the passkey (hirz could not reproduce the PRF results); unknown algorithms are ignored with a note |
| `credBlob`, `largeBlob` | not supported: the passkey is imported and the data is reported as not kept |
| `Item.creationAt` | creation time; missing or in the future means now |
| unknown fields | ignored, as CXF requires |

Imported passkeys keep their original credential ids (1 to 1023 bytes) and work through both
the Firefox extension and the virtual security key, which reports a maximum credential id
length of 1023 bytes.

A passkey whose credential id is already in hirz is reported as already present when the key
is the same, and skipped when it differs. The file may be at most 64 MiB and hold at most
100000 passkeys; JSON nesting is limited to 128 levels.

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
vault key, so the file can be imported into any new vault. It is not the vault's own backup
format (`docs/vault-format.md`, section 8.1), which is bound to one vault's recovery key.
