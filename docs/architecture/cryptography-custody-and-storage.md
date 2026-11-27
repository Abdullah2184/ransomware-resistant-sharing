# Cryptography, Key Custody, and Encrypted Storage Pipeline

This document describes the implemented client-side encryption, HPKE key
wrapping, key custody boundary, and private IPFS/Cluster storage dataflow
defined by [`TECHNICAL_SPECIFICATION.md`](../specifications/TECHNICAL_SPECIFICATION.md)
(§§5–6, 9, 12–14) and the accepted storage/envelope ADRs.

## 1. Content Encryption & Chunking (`crates/crypto`)

- **Cipher & key lifecycle (`encryption.rs`):**
  - **AES-256-GCM** (`aes-gcm = 0.11.1` with `zeroize` enabled so expanded round
    keys are zeroized on drop).
  - Every file version (including append-only restores) generates a fresh random
    non-zero 32-byte `DataEncryptionKey` directly into `Zeroizing<[u8; 32]>`, a
    fresh non-zero 32-byte `EpochId`, and a fresh random 64-bit `NoncePrefix`.
  - `DataEncryptionKey` and `NoncePrefix` redact their bytes in `Debug` output.
- **Deterministic Nonce & Chunk Layout (`nonce.rs`, `manifest.rs`):**
  - 96-bit GCM nonce = `noncePrefix[8] || chunkIndex[4-byte big-endian]`.
  - Index `0` is reserved for optional encrypted private metadata
    (`encrypt_private_metadata` / `decrypt_private_metadata`, bounded by
    `MAX_PRIVATE_METADATA_BYTES = 64 KiB` ciphertext + tag).
  - Content chunks use 1-based sequential indexes `1..=N` (0-byte files have
    `chunkCount = 0` and omit `chunks/`). Chunk counts overflowing `u32` and
    post-final encryptor/decryptor calls are rejected.
  - Default and maximum chunk size is **1 MiB** (`1,048,576` bytes plaintext,
    `1,048,592` bytes ciphertext + 16-byte GCM tag), matching
    [`docs/adr/content-package-unixfs-profile.md`](../adr/content-package-unixfs-profile.md)
    (amended from §5.1's 4 MiB draft because Kubo `0.43.1` enforces a
    `2,096,896`-byte chunker ceiling).
- **Authenticated Associated Data (AAD):**
  - Every chunk and private-metadata block binds:
    `b"rrds/encrypted-content/v1" || fileId || versionNumber || epochId || chunkIndex || totalChunks`.
  - `ChunkEncryptor`, `ChunkDecryptor`, and private-metadata helpers reject zero
    `fileId` or `epochId` values and verify exact full-chunk lengths for all
    non-final chunks.
- **Canonical Manifest (`rrds.encrypted-content.v1`):**
  - Compact canonical JSON validated against
    [`schemas/encrypted-file-manifest-v1.json`](../../schemas/encrypted-file-manifest-v1.json)
    with lowercase `0x` hex identifiers, canonical unpadded base64url fields,
    `version == 1 <=> parentManifestHash == ZERO`, sequential chunk indexes,
    and canonical raw SHA-256 CIDv1 references (`raw_sha256_cid`).
  - `EncryptedFileManifest::manifest_hash()` computes the SHA-256 digest of the
    canonical manifest bytes committed on-chain in `FileRegistry`.

## 2. HPKE Recipient Key Wrapping & Envelope Sets (`crates/crypto`)

- **Suite (`key_wrapping.rs`):**
  - **RFC 9180 Base mode** with `DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`,
    and `AES-256-GCM` (`hpke = 0.15.1` / `x25519-dalek = 3.0.0`, zeroizing
    private keys on drop).
  - Wraps the exact 32-byte DEK into a 32-byte `encapsulatedKey` and 48-byte
    `wrappedDek` (32-byte DEK + 16-byte GCM tag).
  - Uses domain-separated `info = b"rrds/key-wrap/v1"` and HPKE AAD
    `b"rrds/key-wrap-context/v1" || fileId || versionNumber || epochId || recipientMemberId || recipientKeyVersion`.
  - Verified against both the official RFC 9180 Base-mode vector and an
    independent OpenSSL->Rust vector in
    [`tests/fixtures/hpke-rfc9180-v1.json`](../../tests/fixtures/hpke-rfc9180-v1.json).
- **Key & Context Validation:**
  - `HpkeRecipientPublicKey::from_bytes` and `open_dek` explicitly reject all
    RFC 7748 §6.1 low-order Curve25519 points (both canonical and bit-255-set,
    including `[0; 32]`).
  - `KeyEnvelope::wrap` and `open_dek` reject zero `fileId`, `epochId`, or
    `recipientMemberId`, and `open_dek` copies unwrapped DEK bytes directly into
    `Zeroizing<[u8; 32]>`.
- **Canonical Envelope Set (`envelope_set.rs`, `rrds.key-envelope-set.v1`):**
  - Validated against
    [`schemas/key-envelope-set-v1.json`](../../schemas/key-envelope-set-v1.json):
    non-empty (`1..=1,024` entries per
    [`docs/adr/envelope-set-limits.md`](../adr/envelope-set-limits.md)),
    strictly sorted unique non-zero `memberId`s, non-zero `fileId`/`epochId`,
    `revision >= 1`, lowercase `0x` hex, and canonical unpadded base64url.
  - Immutable in IPFS; sharing or key rotation creates a new envelope set at
    `revision + 1` without re-encrypting file ciphertext.

## 3. Key Custody Holder Boundary (`crates/ports`, `crates/key_custody`)

- **`KeyCustodyProvider` trait (`crates/ports/src/lib.rs`):**
  - Exposes `public_identity`, `sign_typed_digest`, `unwrap_dek`, and
    `health_check` (also implemented for `Arc<T>`).
  - `sign_typed_digest` accepts **only** `crypto::TypedDigest` (constructed
    exclusively from approved EIP-712 operation structs), preventing arbitrary-byte
    signing bypasses.
- **Startup Policy Enforcement (`verify_provider_policy`):**
  - `CustodyStartupPolicy::Production` (the CLI default) fails closed unless
    `health_check()` reports `healthy == true`, `secp256k1_signing == true`,
    `hpke_x25519_unwrap == true`, `private_keys_non_exportable == true`, and
    `test_only == false`.
  - `DevelopmentKeyCustody` reports `test_only: true` and
    `private_keys_non_exportable: false`, so it is usable **only** when
    `RRDS_ALLOW_UNSAFE_DEV_CUSTODY=true` (`CustodyStartupPolicy::UnsafeDevelopment`).
- **Invariants enforced inside `DevelopmentKeyCustody`:**
  - Rejects zero `memberId`, zero `encryption_seed`, and reused
    `signing_secret == encryption_seed` (§7.7.1 key separation).
  - Enforces cross-role `KeyId` isolation (encryption key IDs cannot sign;
    signing key IDs cannot unwrap DEKs) and binds `key_version` into derived dev
    `KeyId`s so rotated versions never collide.
  - Verifies EIP-2 low-`s` canonicalization (`signature.normalize_s().is_none()`)
    on every emitted EVM signature.
  - Verifies `WrapContext`'s `(recipient_member_id, recipient_key_version)`
    against its own registered identity inside `unwrap_dek` before decapsulation.
  - `apps/cli` wraps dev secret env vars and parsed secret byte arrays in
    `Zeroizing` and enforces HTTPS by default for non-loopback gateway URLs.
- **Separate Relayer Key Custody (`crates/chain_adapter/src/relayer.rs`):**
  - Relayer keys live behind `RelayerSigner` on the gateway server, guarded by
    `RelayerStartupPolicy::Production` (rejecting `DevelopmentRelayerSigner`
    unless explicitly opted into unsafe dev mode), isolated from member keys and
    QBFT validator keys.

## 4. End-to-End Upload, IPFS Replication, and Verified Download Pipeline

### Upload / Modify / Restore (`UploadService` -> Gateway -> IPFS Cluster -> Besu)
1. **Local pre-checks (`apps/cli` + `crates/application/src/upload.rs`):**
   - `apps/cli` reads regular files only (rejecting symlinks/directories) into a
     bounded `Zeroizing<Vec<u8>>` buffer and fails closed on non-`disabled`
     `RRDS_SCANNER_MODE` values until an external scanner adapter is attached.
   - `UploadService` runs the configured `PreUploadScanner` (`DisabledScanner` by
     default), validates active file head / `expected_parent_head`, resolves all
     active recipient public identities (`MemberSuspended` / `Unauthorized` fail
     fast), and verifies local custody's `signing_address` matches the author's
     active on-chain `signing_address` **before** encrypting or pinning.
2. **Client-side encryption & staging (`RRDSPKG1`):**
   - Encrypts private metadata (chunk 0) and content chunks `1..=N` under a fresh
     DEK, builds canonical `EncryptedFileManifest` and `KeyEnvelopeSet`, and
     frames the content package using the shared `RRDSPKG1` framing codec
     (`crates/ports`).
   - Sends ciphertext packages to `POST /v1/blobs/content` and canonical
     envelope sets to `POST /v1/blobs/envelopes` over authenticated HTTP.
3. **Gateway ACL pre-check & Cluster pin quorum (`services/gateway` + `crates/ipfs_adapter`):**
   - Before touching IPFS, gateway routes (`routes/blobs.rs`) authenticate the
     active member at one QBFT-committed block and verify file head state +
     Write/Read ACLs so unauthorized callers cannot pin orphaned blobs.
   - `IpfsClusterStore` selects a healthy Kubo peer (with multi-Kubo failover),
     imports the 2-level UnixFS directory (`manifest.json` + `chunks/00000001..N`)
     with `cid-version=1`, `hash=sha2-256`, `chunker=size-1048592`,
     `raw-leaves=true`, `wrap-with-directory=true`, `pin=false`, validates every
     returned chunk/manifest CID, pins via authenticated IPFS Cluster Basic Auth
     (with multi-Cluster failover and redirects disabled), waits for
     `MIN_PIN_REPLICAS` distinct `pinned` peers, and verifies the root block CID.
   - Kubo containers disable the public HTTP gateway (`Addresses.Gateway ""`)
     and use static peer bootstrap multiaddrs inside the private swarm.
4. **On-chain commit (`POST /v1/files`, `POST /v1/files/{id}/versions`, `POST /v1/files/{id}/versions/{v}/envelopes`):**
   - Gateway validates EIP-712 signatures, ACLs, stale heads, existing Cluster
     pin quorum via `ensure_replication` (verifying `GET /pins/{cid}` + root
     block without blind repinning; returning `503 replication_insufficient` if
     unsatisfied), and canonical staged envelope sets before relaying Type-2
     transactions via `TransactionRelayer`.
   - If ledger commit fails after pinning, `UploadService` / `ShareService`
     returns `OrphanedUpload` / `OrphanedEnvelopeUpload` carrying the pinned
     CIDs instead of claiming success.

### Authorized Download & Verification (`DownloadService` + `crates/crypto/src/car.rs`)
1. **Signed access lookup (`POST /v1/files/{id}/versions/{v}/access`):**
   - Returns authoritative `manifestHash`, `contentCid`, `envelopeSetCid`,
     `epochId`, `envelopeRevision`, and `finalizedBlock` after durable audit
     commit.
2. **Bounded retrieval & CARv1 verification:**
   - Gateway streams `GET .../content` (`application/vnd.ipld.car`, `Cache-Control: no-store`)
     and `GET .../envelope` (verifying raw SHA-256 CID, canonical
     `KeyEnvelopeSet`, and caller's `(memberId, encryptionKeyVersion)` entry)
     only after repeating finalized ACL checks and committing audit rows.
   - Client parses the CARv1 stream using shared `crates/crypto/src/car.rs`,
     verifying every block's CIDv1 SHA-256 digest and traversing the 2-level
     UnixFS `dag-pb` directory (`manifest.json` + `chunks/00000001..N`, or
     `manifest.json`-only for 0-byte files).
3. **Fail-closed pre-unwrap verification & decryption (`DownloadService`):**
   - Verifies envelope-set raw SHA-256 CID, canonical `KeyEnvelopeSet`, header
     fields, and presence of the caller's `(memberId, encryptionKeyVersion)` entry.
   - **Before** calling `custody.unwrap_dek`, verifies canonical
     `EncryptedFileManifest`, `manifest_hash == access.manifest_hash` (and
     optional `expected_manifest_hash`), chunk count, chunk indexes, declared
     byte lengths, and every chunk's `raw_sha256_cid` so tampered packages never
     unwrap a DEK into memory.
   - Calls `custody.unwrap_dek` with `WrapContext`, decrypts optional private
     metadata (nonce index 0) and chunks `1..=N` into `Zeroizing<Vec<u8>>`
     (automatically zeroized if any chunk fails AEAD authentication), and only
     then writes output atomically in `apps/cli` (`0600` temp + `fsync` + `rename`).
