# Development & Cross-Component Interdependency Notes

This document flags every cross-crate and cross-language coupling point in RRDS
so future changes maintain binary, cryptographic, ABI, and schema compatibility
(`manual_review.md` #8).

## 1. EIP-712 Typed-Data Schemas (Rust <-> Solidity <-> TypeScript)

All five EIP-712 domains and struct hashes MUST remain byte-identical across:

- **Rust (single source of truth):** `crates/crypto/src/signing.rs`
  - Reused by `crates/application`, `services/gateway/src/auth.rs`, and
    `services/gateway/src/routes.rs`.
- **Solidity:** `contracts/contracts/libraries/RrdsEip712.sol`
- **Cross-language test vectors:** `tests/fixtures/eip712-v1.json` (verified by
  both `crates/crypto` unit tests and `contracts/test/Eip712.ts` +
  `contracts/contracts/RrdsEip712.t.sol`).

> Never duplicate EIP-712 struct hashing in a service or app; always import from
> `crates/crypto`.

## 2. Smart Contract ABIs & Event Signatures (Solidity <-> Rust)

Whenever a function signature, struct field order, or event signature changes in
`contracts/contracts/FileRegistry.sol` or `AccessGovernance.sol`, you MUST update:

1. **Contract reads & ABI write encoders:** `crates/chain_adapter/src/lib.rs`
   and `crates/chain_adapter/src/relayer.rs` (`createFile`, `appendVersion`,
   `updateEnvelopeSet`, `getFile`, `getVersion`, `memberIdentity`,
   `hasReadAccess`, `hasWriteAccess`, `hasHistoricalReadAccess`,
   `currentEnvelopeSet`).
2. **Event topic hashes & ABI log decoders:** `services/indexer/src/decoder.rs`
   and projection logic in `services/indexer/src/main.rs` (including
   `EnvelopeSetInitialized` -> `revision = 1` and `ReadAccessRevoked` clearing
   `historical_read_access_projection`).

## 3. Content Package & Manifest Profile (Crypto <-> IPFS Adapter <-> Schemas <-> CLI)

The 1 MiB chunk profile (`DEFAULT_CHUNK_SIZE_BYTES = 1_048_576`, ciphertext+tag
`1_048_592`, Kubo `chunker=size-1048592`, `cid-version=1`, `hash=sha2-256`,
`raw-leaves=true`, `wrap-with-directory=true`) is coupled across:

- `docs/adr/content-package-unixfs-profile.md`
- `crates/crypto/src/{encryption.rs,manifest.rs}` (`DEFAULT_CHUNK_SIZE_BYTES`,
  `raw_sha256_cid`)
- `schemas/encrypted-file-manifest-v1.json` and `schemas/key-envelope-set-v1.json`
- `crates/ipfs_adapter/src/lib.rs` (delegates raw SHA-256 CID hashing to
  `crypto::raw_sha256_cid`)
- `crates/ports/src/blob_store.rs` (shared `RRDSPKG1` binary frame used by both
  `apps/cli` and `services/gateway`)
- `apps/cli/src/car.rs` (CARv1 raw-block extractor using `crypto::raw_sha256_cid`)

## 4. PostgreSQL Schema & Migrations (Metadata Store <-> Indexer <-> Gateway)

- All SQL migrations live in `crates/metadata_store/migrations/` (`0001`–`0005`).
- `crates/metadata_store/build.rs` emits `cargo:rerun-if-changed=migrations` so
  `sqlx::migrate!("./migrations")` always recompiles when a migration is added.
- **Immutability rule:** Never edit an existing numbered migration file once
  applied — SQLx validates checksums and fails with `VersionMismatch`. Always
  create the next numbered migration (`0006_...sql`).
- When adding new tables, also update least-privilege grants in
  `infra/postgres/init-roles.sql`.

## 5. Why `services/` and `crates/` Are Separate (`manual_review.md` #5)

- `crates/` holds **reusable, host-independent libraries** with narrow
  responsibilities (`domain`, `crypto`, `ports`, `application`, `key_custody`,
  `scanner`, `chain_adapter`, `ipfs_adapter`, `metadata_store`).
- `services/` (`gateway`, `indexer`) and `apps/` (`cli`) are **deployable
  runtime binaries** that compose only the subset of crates permitted for their
  host trust boundary (enforced by CI in `.github/workflows/ci.yml` and
  documented in `docs/architecture/deployment-and-boundaries.md`).
- Example: `crates/application` runs on client endpoints (`apps/cli`), while
  `crates/chain_adapter`, `crates/ipfs_adapter`, and `crates/metadata_store`
  run strictly on organization servers (`services/gateway`, `services/indexer`).

## 6. Standardized Test Placement (`manual_review.md` #11)

- **Unit & narrow adapter tests:** Co-located in `#[cfg(test)] mod tests` inside
  each crate/service (`crates/*`, `services/*`, `apps/cli`) and Foundry/Hardhat
  contract tests inside `contracts/`.
- **Cross-component suites:** Live in workspace package `tests/` (`rrds-tests`):
  - `tests/end_to_end/acceptance.rs` — full lifecycle, ransomware recovery,
    concurrency, revocation, and key-rotation acceptance tests.
  - `tests/security/invariants.rs` — cryptographic tamper, domain separation,
    startup policy, and plaintext-rejection negative tests.
  - `tests/integration/cross_component.rs` — cross-crate signing -> ABI encoding
    -> Type-2 relayer integration tests.
  - `tests/fixtures/eip712-v1.json` — shared Rust/Solidity/TypeScript vectors.
