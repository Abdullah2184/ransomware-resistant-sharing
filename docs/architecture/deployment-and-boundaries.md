# Deployment Placement, Crate Boundaries, and Data Isolation

This document defines the strict module dependency rules and runtime data-access
boundaries enforced across the RRDS workspace (see
`TECHNICAL_SPECIFICATION.md` §§1.1, 4, 5, and 10).

## Enforced Crate & Service Dependency Matrix

| Module | Allowed Internal Dependencies | Prohibited Dependencies (Must Never Appear) |
| --- | --- | --- |
| `crates/domain` | None (includes shared zero-dependency `hex` codecs) | `crypto`, `ports`, `application`, `chain_adapter`, `ipfs_adapter`, `metadata_store`, `key_custody`, network/SQL crates |
| `crates/crypto` | `domain` | `ports`, `application`, `chain_adapter`, `ipfs_adapter`, `metadata_store`, `key_custody`, network/SQL crates |
| `crates/ports` | `domain`, `crypto` | Any concrete adapter (`chain_adapter`, `ipfs_adapter`, `metadata_store`, `key_custody`) or service |
| `crates/application` | `domain`, `crypto`, `ports` (`key_custody` in `[dev-dependencies]` only) | `chain_adapter`, `ipfs_adapter`, `metadata_store`, `reqwest`, `sqlx`, `axum` |
| `crates/key_custody` | `domain`, `crypto`, `ports` | `chain_adapter`, `ipfs_adapter`, `metadata_store`, network/SQL crates |
| `crates/chain_adapter` | `domain` | `ipfs_adapter`, `metadata_store`, `key_custody`, `application`, plaintext encryption |
| `crates/ipfs_adapter` | `domain`, `crypto` (canonical manifest/CID validation only), `ports` | `chain_adapter`, `metadata_store`, `key_custody`, `application` |
| `crates/metadata_store` | None (owns `PostgresPoolConfig`, `MigrationMode` defaulting to `verify`, and SQLx migrations `0001`–`0006`) | `chain_adapter`, `ipfs_adapter`, `crypto`, `key_custody`, `application` |
| `crates/scanner` | `domain`, `ports` (`DisabledScanner` default MVP adapter) | Network, storage, chain, DB, or key-custody crates |
| `services/indexer` | `domain`, `chain_adapter`, `metadata_store` (runs under least-privilege `rrfs_indexer` DB role) | `ipfs_adapter`, `key_custody`, `crypto` decryption, `application` |
| `services/gateway` | `domain`, `crypto` (EIP-712 digests, `keccak256`, raw CID & canonical envelope-set parsing only), `ports`, `chain_adapter`, `ipfs_adapter`, `metadata_store` (`key_custody` in `[dev-dependencies]` only; runs under least-privilege `rrfs_gateway` DB role) | `key_custody` (runtime), `application`, plaintext file encryption/decryption or HPKE unwrap |
| `apps/cli` | `domain`, `crypto`, `ports`, `application`, `key_custody`, `scanner` (communicates exclusively via `GatewayHttpClient` over HTTPS with redirects disabled and bounded responses; `RRDS_ALLOW_INSECURE_HTTP=true` required for non-loopback HTTP) | `chain_adapter` (direct Besu RPC), `ipfs_adapter` (direct Kubo/Cluster), `metadata_store` / `sqlx` (direct PostgreSQL), IPFS Cluster admin credentials |

## Data Access & Trust-Boundary Invariants

1. **Plaintext & DEK Isolation:**
   - Plaintext files, plaintext private metadata, and unwrapped AES-256-GCM DEKs
     exist transiently **only** inside client-side `crates/application`,
     `crates/crypto`, and `crates/key_custody` (using `Zeroizing` secret/plaintext
     buffers; `DownloadService` verifies manifest and all chunk CIDs *before*
     calling `custody.unwrap_dek`).
   - `services/gateway`, `services/indexer`, `crates/ipfs_adapter`,
     `crates/chain_adapter`, and PostgreSQL **never** receive plaintext content,
     unwrapped DEKs, or member private keys.
2. **Authoritative Authorization vs. Informational Projections:**
   - Every protected read, blob-staging, and write route (`GET /v1/identities/{memberId}`,
     `POST .../access`, `GET .../content`, `GET .../envelope`,
     `GET /v1/files/{id}/versions`, `POST /v1/blobs/content`,
     `POST /v1/blobs/envelopes`, `POST /v1/files`, `POST .../versions`,
     `POST .../envelopes`) queries **authoritative Besu QBFT-committed contract
     state** at a single block number via `BesuClient` (checking `member.active()`
     and file Write/Read/historical ACLs before staging blobs, relaying
     transactions, or releasing protected data).
   - PostgreSQL projections (`files_projection`, `folders_projection`,
     `versions_projection`, `access_projection`, `historical_read_access_projection`,
     `envelope_sets_projection`) are strictly **informational**
     (`"authoritative": false` on `GET /v1/files`) and can be wiped and rebuilt
     deterministically from finalized events.
3. **Database Role Separation (`infra/postgres/init-roles.sql`):**
   - `rrfs_migrator` owns schema DDL and runs migrations (`DATABASE_MIGRATION_MODE=run`).
   - `rrfs_indexer` writes only indexer/projection tables and has zero privileges
     on `gateway_*` tables (`DATABASE_MIGRATION_MODE=verify`).
   - `rrfs_gateway` reads projections (`SELECT` only), manages operational
     gateway state, and has append-only (`SELECT, INSERT`) access to
     `gateway_audit_events` (`UPDATE`/`DELETE`/`TRUNCATE` blocked by both role
     grants and database triggers).
   - Optional `rrfs_audit_reader` has read-only `SELECT` on `gateway_audit_events`.
4. **Key Role Separation:**
   - Member signing keys (secp256k1) and encryption keys (X25519) live behind
     `KeyCustodyProvider` on the endpoint (`CustodyStartupPolicy::Production`
     rejects `DevelopmentKeyCustody`; `DevelopmentKeyCustody` enforces distinct
     signing/encryption keys, EIP-2 low-`s`, key-version-bound `KeyId`s, and
     custody-side `WrapContext` identity binding).
   - Gateway transaction-relayer keys live behind `RelayerSigner` on the gateway
     server (`RelayerStartupPolicy::Production` rejects
     `DevelopmentRelayerSigner`) and must never be reused as member keys or QBFT
     validator keys.
   - QBFT validator keys remain isolated on validator hosts (`infra/besu-qbft`).
5. **No Single-Point Feature Duplication:**
   - Canonical hex encoding/decoding lives once in `crates/domain/src/hex.rs`
     (reused by `apps/cli`, `crates/crypto`, `crates/chain_adapter`,
     `services/gateway`, and `services/indexer`).
   - All EIP-712 typed-data domain separators, struct hashes (`VersionAppend`,
     `AccessLookup`, `EnvelopeSetUpdate`, `MemberKeyProof`, `LoginChallenge`),
     and `keccak256` live once in `crates/crypto/src/signing.rs` and are
     cross-checked against `tests/fixtures/eip712-v1.json` and
     `contracts/contracts/libraries/RrdsEip712.sol`.
   - Raw SHA-256 CIDv1 computation and verification (`raw_sha256_cid`,
     `verify_sha256_cid`) and CARv1 + 2-level UnixFS `dag-pb` package
     encoding/extraction (`crates/crypto/src/car.rs`) live once in `crates/crypto`
     (reused by `crates/ipfs_adapter`, `crates/ports`, `crates/application`,
     `services/gateway`, and `apps/cli`).
   - Encrypted `ContentPackage` HTTP staging framing (`RRDSPKG1`) lives once in
     `crates/ports::{encode_content_package_frame, decode_content_package_frame}`
     (reused by `apps/cli` and `services/gateway`).
   - Gateway route handlers are cleanly separated into
     `services/gateway/src/routes/{mod,middleware,auth,reads,writes,blobs}.rs`,
     sharing `authenticate_bearer`, `authenticate_active_member`,
     `authorize_version_read`, `read_bounded_envelope_set`, `WriteAuditContext`,
     and `authorize_blob_staging`.
6. **Automated CI Enforcement:**
   - [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) verifies
     `cargo fmt`, strict Clippy (`-D warnings`), offline workspace unit/HTTP
     tests (with zero silent DB skips), live PostgreSQL integration &
     least-privilege RBAC tests (`-- --ignored` against `rrfs_migrator`,
     `rrfs_gateway`, `rrfs_indexer`, and `rrfs_audit_reader`), Solidity/Hardhat
     tests (including §7.9 gas bounds), Compose syntax, and automated checks
     enforcing the crate dependency matrix above on every push and pull request.
