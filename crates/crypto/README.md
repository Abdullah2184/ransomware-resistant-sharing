# Crypto (`crates/crypto`)

Pure client-side cryptographic primitives, canonical schema parsers/serializers,
and EIP-712 typed-data hashing for RRDS (`TECHNICAL_SPECIFICATION.md` §§6–7).
Contains no network, database, storage, or key-custody adapter dependencies.

## Contents

- **Authenticated chunk encryption (`encryption.rs`):** Stateful AES-256-GCM
  1 MiB chunk encryptor/decryptor (`DEFAULT_CHUNK_SIZE = 1_048_576`, matching
  [`docs/adr/content-package-unixfs-profile.md`](../../docs/adr/content-package-unixfs-profile.md)),
  reserved chunk-0 `encrypt_private_metadata` / `decrypt_private_metadata`,
  context-bound AAD, and `Zeroizing` key/plaintext buffers.
- **HPKE key wrapping (`key_wrapping.rs`):** RFC 9180 base-mode HPKE
  (`X25519 / HKDF-SHA256 / AES-256-GCM`) binding `(fileId, versionNumber,
  epochId, memberId, encryptionKeyVersion)` into HPKE `info` / AAD.
- **Canonical formats (`manifest.rs`, `envelope_set.rs`):**
  - `EncryptedFileManifest` (`rrds.encrypted-file-manifest.v1`, SHA-256
    `manifest_hash()`, and canonical `raw_sha256_cid()`).
  - `KeyEnvelopeSet` (`rrds.key-envelope-set.v1`, sorted unique recipients,
    max 1,024 entries).
- **EIP-712 typed-data signing digests (`signing.rs`):** Single source of truth
  for `Eip712Domain` (`FileRegistry`, `AccessGovernance`, `Gateway`),
  `VersionAppend`, `AccessLookup`, `EnvelopeSetUpdate`, `MemberKeyProof`, and
  `LoginChallengeDigestInput`, cross-verified against
  `tests/fixtures/eip712-v1.json`.

## Verification

```shell
cargo test -p crypto --locked --offline
```
