# Deployment Placement, Crate Boundaries, and Data Isolation

This document defines the strict module dependency rules and runtime data-access
boundaries enforced across the RRDS workspace (see
`TECHNICAL_SPECIFICATION.md` §§1.1, 4, 5, and 10).

## Enforced Crate & Service Dependency Matrix

| Module | Allowed Internal Dependencies | Prohibited Dependencies (Must Never Appear) |
| --- | --- | --- |
| `crates/domain` | None | `crypto`, `ports`, `application`, `chain_adapter`, `ipfs_adapter`, `metadata_store`, `key_custody`, network/SQL crates |
| `crates/crypto` | `domain` | `ports`, `application`, `chain_adapter`, `ipfs_adapter`, `metadata_store`, `key_custody`, network/SQL crates |
| `crates/ports` | `domain`, `crypto` | Any concrete adapter (`chain_adapter`, `ipfs_adapter`, `metadata_store`, `key_custody`) or service |
| `crates/application` | `domain`, `crypto`, `ports` (`key_custody` in `[dev-dependencies]` only) | `chain_adapter`, `ipfs_adapter`, `metadata_store`, `reqwest`, `sqlx`, `axum` |
| `crates/key_custody` | `domain`, `crypto`, `ports` | `chain_adapter`, `ipfs_adapter`, `metadata_store`, network/SQL crates |
| `crates/chain_adapter` | `domain` | `ipfs_adapter`, `metadata_store`, `key_custody`, `application`, plaintext encryption |
| `crates/ipfs_adapter` | `domain`, `crypto` (canonical manifest/CID validation only), `ports` | `chain_adapter`, `metadata_store`, `key_custody`, `application` |
| `crates/metadata_store` | None | `chain_adapter`, `ipfs_adapter`, `crypto`, `key_custody`, `application` |
| `crates/scanner` | `domain`, `ports` (`DisabledScanner` default MVP adapter) | Network, storage, chain, DB, or key-custody crates |
| `services/indexer` | `domain`, `chain_adapter`, `metadata_store` | `ipfs_adapter`, `key_custody`, `crypto` decryption, `application` |
| `services/gateway` | `domain`, `crypto` (EIP-712 digests & canonical envelope-set parsing only), `ports`, `chain_adapter`, `ipfs_adapter`, `metadata_store` (`key_custody` in `[dev-dependencies]` only) | `key_custody` (runtime), `application`, plaintext file encryption/decryption or HPKE unwrap |
| `apps/cli` | `domain`, `crypto`, `ports`, `application`, `key_custody` (communicates exclusively via `GatewayHttpClient` over HTTP) | `chain_adapter` (direct Besu RPC), `ipfs_adapter` (direct Kubo/Cluster), `metadata_store` / `sqlx` (direct PostgreSQL), IPFS Cluster admin credentials |

## Data Access & Trust-Boundary Invariants

1. **Plaintext & DEK Isolation:**
   - Plaintext files, plaintext private metadata, and unwrapped AES-256-GCM DEKs
     exist transiently **only** inside client-side `crates/application`,
     `crates/crypto`, and `crates/key_custody`.
   - `services/gateway`, `services/indexer`, `crates/ipfs_adapter`,
     `crates/chain_adapter`, and PostgreSQL **never** receive plaintext content,
     unwrapped DEKs, or member private keys.
2. **Authoritative Authorization vs. Informational Projections:**
   - Every access check (`GET /v1/identities/{memberId}`, `POST .../access`,
     `GET .../content`, `GET .../envelope`, `GET /v1/files/{id}/versions`,
     `POST /v1/files`, `POST .../versions`, `POST .../envelopes`) queries
     **authoritative Besu QBFT-committed contract state** at a single block
     number via `BesuClient`.
   - PostgreSQL projections (`files_projection`, `folders_projection`,
     `versions_projection`, `access_projection`, `historical_read_access_projection`)
     are strictly **informational** (`"authoritative": false` on `GET /v1/files`)
     and can be wiped and rebuilt deterministically from finalized events.
3. **Key Role Separation:**
   - Member signing keys (secp256k1) and encryption keys (X25519) live behind
     `KeyCustodyProvider` on the endpoint (`CustodyStartupPolicy::Production`
     rejects `DevelopmentKeyCustody`).
   - Gateway transaction-relayer keys live behind `RelayerSigner` on the gateway
     server (`RelayerStartupPolicy::Production` rejects
     `DevelopmentRelayerSigner`) and must never be reused as member keys or QBFT
     validator keys.
   - QBFT validator keys remain isolated on validator hosts (`infra/besu-qbft`).
4. **No Single-Point Feature Duplication:**
   - All EIP-712 typed-data domain separators and struct hashes (`VersionAppend`,
     `AccessLookup`, `EnvelopeSetUpdate`, `MemberKeyProof`, `LoginChallenge`)
     live once in `crates/crypto/src/signing.rs` and are cross-checked against
     `tests/fixtures/eip712-v1.json` and `contracts/contracts/libraries/RrdsEip712.sol`.
   - Raw SHA-256 CIDv1 computation lives once in `crates/crypto::raw_sha256_cid`
     (reused by `crates/ipfs_adapter`, `crates/ports`, `crates/application`, and `apps/cli`).
   - Encrypted `ContentPackage` HTTP staging framing (`RRDSPKG1`) lives once in
     `crates/ports::{encode_content_package_frame, decode_content_package_frame}`
     (reused by `apps/cli` and `services/gateway`).
   - Gateway bearer session extraction and verification live once in
     `services/gateway/src/routes.rs::authenticate_bearer`.
5. **Automated CI Enforcement:**
   - [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) verifies
     `cargo fmt`, strict Clippy (`-D warnings`), workspace unit/HTTP tests,
     live PostgreSQL integration tests (`metadata-store`, `indexer`, `gateway`),
     Solidity/Hardhat tests, Compose syntax, and automated checks enforcing the
     crate dependency matrix above on every push and pull request.
