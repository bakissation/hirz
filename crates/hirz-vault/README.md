# hirz-vault

Encrypted, folder-synced credential vault for hirz. The vault is a directory of immutable
files that any file-sync tool can carry between devices. The format is specified in
[`docs/vault-format.md`](../../docs/vault-format.md).

## Third-party data

`data/bip39-english.txt` is the English word list of BIP-39 ("Mnemonic code for generating
deterministic keys", by Marek Palatinus, Pavol Rusnak, Aaron Voisine and Sean Bowe),
published under the MIT License as part of the Bitcoin Improvement Proposals repository.
It is used unchanged (SHA-256
`2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`) to display recovery keys.
The MIT notice is in `data/LICENSE-BIP39`.
