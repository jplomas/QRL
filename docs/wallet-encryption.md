# Node wallet encryption

Node `wallet.json` and `walletd.json` keep their version 1 address layout. Newly
encrypted files add `encryption_version: 2`; each secret field contains a
`qrl-node-v2:salt:nonce:tag:ciphertext` envelope with hex-encoded components.
The cipher uses scrypt with `N=131072`, `r=8`, `p=1`, a 32-byte random salt,
and AES-256-GCM with a 12-byte nonce and 16-byte tag. The authenticated data
binds each field to its address and field name. Walletd slave seeds use the
same format. Public address and OTS-index metadata remain outside the encrypted
fields.

The KDF and AEAD settings follow `qrl-wallet`'s v3 implementation, but the
file formats are different. The updated web wallet opens node v1/v2 files,
decrypts their fields, and preserves slave groups and OTS indexes in an
upgraded v3 envelope. The node opens web-wallet v3 envelopes, including ones
containing node slave groups. An encrypted v3 envelope hides its address list
until unlock; walletd converts it to node v2 after a successful unlock.
Older web-wallet builds do not understand node v2 fields and may discard
slave groups, so use the updated web wallet for round-tripping `walletd.json`.

Legacy AES-CTR files remain readable. Run `qrl wallet_upgrade_encryption` to
upgrade an encrypted CLI wallet without writing a plaintext intermediate file.
Walletd upgrades a legacy encrypted wallet on successful unlock. Both paths
write the replacement atomically; a failed write leaves the old file intact.
Back up the wallet before migration, and keep that backup private. Older node
versions cannot decrypt the new fields.
