# Blockchain-Based Ransomware-Resistant Data Sharing (RRDS)

A consortium-based encrypted file-sharing and ransomware-recovery system built on
a permissioned Hyperledger Besu QBFT blockchain, private IPFS / IPFS Cluster
storage, client-side authenticated encryption, and hardware-backed key custody.

## Project Overview

The system provides:

- **Client-side encryption:** Files are split into 1 MiB chunks and encrypted
  locally with AES-256-GCM using a fresh 256-bit Data Encryption Key (DEK) per
  file version; DEKs are wrapped per recipient using RFC 9180 HPKE
  (`X25519 / HKDF-SHA256 / AES-256-GCM`). Plaintext and unwrapped DEKs never
  leave the client endpoint.
- **Distributed encrypted storage:** Immutable encrypted content packages and
  key-envelope sets are stored in a private Kubo / IPFS Cluster swarm with
  enforced multi-peer pin quorum (`MIN_PIN_REPLICAS`) before any ledger commit.
- **Append-only versioning and recovery:** `FileRegistry` preserves an immutable
  linear version chain (`V1 -> V2 -> ...`). Ransomware recovery restores a clean
  prior version as a brand-new head version encrypted under a fresh DEK while
  preserving forensic history.
- **Separate Read/Write ACLs & historical access:** `AccessGovernance` enforces
  independent per-file Read and Write permissions. File-level Read covers the
  current head and future versions; accessing older versions requires an explicit
  version-scoped historical grant (invalidated automatically upon Read revocation).
- **Multisignature governance:** Organization Safes, an Emergency Safe (suspend
  only), and a 24-hour Consortium Safe `TimelockController` govern membership,
  key rotation, and policy changes.

## Documentation Map

- **Canonical Specification:** [`docs/specifications/TECHNICAL_SPECIFICATION.md`](docs/specifications/TECHNICAL_SPECIFICATION.md)
- **System Architecture & Trust Boundaries:** [`docs/architecture/README.md`](docs/architecture/README.md)
  - [Deployment Placement, Crate Boundaries & Data Isolation](docs/architecture/deployment-and-boundaries.md)
  - [Authentication and Challenge-Response Workflow](docs/architecture/authentication-and-challenge.md)
  - [Historical Access Model](docs/architecture/historical-access.md)
  - [Data Recovery and Key Revocation](docs/architecture/recovery-and-revocation.md)
- **Threat Model & Security Boundaries:** [`docs/threat-model.md`](docs/threat-model.md)
- **Smart Contract API & Gas Reference:** [`docs/contract-api.md`](docs/contract-api.md)
- **Gateway HTTP API:** [`docs/api.md`](docs/api.md)
- **Architecture Decision Records (ADRs):** [`docs/adr/`](docs/adr/)
- **Design Decisions & MVP Limitations:** [`docs/decisions/README.md`](docs/decisions/README.md)
- **Cross-Component Coupling & Development Notes:** [`docs/development-notes.md`](docs/development-notes.md)
- **Incident Recovery & Operations Runbook:** [`docs/runbooks/ransomware-recovery.md`](docs/runbooks/ransomware-recovery.md)
- **Production-Separated Per-Role Compose Templates:** [`infra/compose/README.md`](infra/compose/README.md)
- **Scripted Local Demo:** [`scripts/demo-local.sh`](scripts/demo-local.sh)
- **Detailed Progress & Historical Log:** [`progress_report.md`](progress_report.md)
- **Living Engineering Review:** [`agentic_review.md`](agentic_review.md)

## System Architecture & Deployment Placement

In production, components are deployed on separate hosts/trust domains (local
Docker Compose co-locates services for development convenience only):

| Deployment Host / Domain | Repository Modules | Responsibilities & Data Boundary |
| --- | --- | --- |
| **User / Client Endpoint** | [`apps/cli`](apps/cli/README.md), [`crates/application`](crates/application/README.md), [`crates/crypto`](crates/crypto/README.md), [`crates/key_custody`](crates/key_custody/README.md), [`crates/scanner`](crates/scanner/README.md) | Local AES-256-GCM encryption/decryption, HPKE wrapping, EIP-712 signing via hardware key custody. Only component permitted to hold plaintext or unwrapped DEKs. |
| **Organization Gateway Server** | [`services/gateway`](services/gateway/README.md), [`crates/ipfs_adapter`](crates/ipfs_adapter/README.md), [`crates/chain_adapter`](crates/chain_adapter/README.md), [`crates/metadata_store`](crates/metadata_store/README.md) | Authenticated HTTP API, PostgreSQL rate limiting & append-only hash-chained audit trail, authoritative Besu `eth_call` authorization, ciphertext/envelope retrieval, pin-before-commit enforcement, and Type-2 transaction relay. Never sees plaintext or DEKs. |
| **Organization Indexer & Database** | [`services/indexer`](services/indexer/README.md), [`crates/metadata_store`](crates/metadata_store/README.md) | Projects QBFT-committed Besu events into rebuildable PostgreSQL tables for browsing/history. Informational only; never authorizes access. |
| **Consortium IPFS / Cluster Peers** | [`infra/ipfs-cluster`](infra/ipfs-cluster/README.md) | Private-swarm Kubo + IPFS Cluster peers storing encrypted content packages and immutable envelope sets. Admin APIs are never exposed to endpoints. |
| **Consortium Besu QBFT Validators & RPC** | [`contracts/`](contracts/), [`infra/besu-qbft`](infra/besu-qbft/README.md) | 4-validator QBFT network + RPC node hosting `AccessGovernance`, `FileRegistry`, and `RrdsTimelockController`. Authoritative source of truth. |

## Technology Stack & Pinned Toolchain

- **Rust `1.99.1`** (`edition = 2024`, offline `--locked` builds via `Cargo.lock`):
  `domain`, `crypto`, `ports`, `application`, `key_custody`, `ipfs_adapter`,
  `chain_adapter`, `metadata_store`, `scanner`, `gateway` (`axum 0.8.9`,
  `sqlx 0.9.0`, `tokio 1.54.1`), `indexer`, `cli`.
- **Solidity `0.8.34` / Hardhat `3.21.2` / Node.js `26.13.0` / pnpm `12.18.0`**:
  smart contracts and deployment modules (`contracts/pnpm-lock.yaml`).
- **Infrastructure:** Hyperledger Besu `26.11.0` (QBFT), Kubo `0.43.1`, IPFS
  Cluster `1.1.6`, PostgreSQL `18.6`.

## Local Development Setup

> **Secret handling:** `.env`, `infra/ipfs-cluster/secrets/*`, and
> `infra/besu-qbft/networkFiles/keys/*` are local-only and git-ignored. Never
> print, copy, commit, or replace `.env`. Use `.env.example` as reference and
> keep deployer keys in the Hardhat keystore.

1. Initialize local IPFS Cluster secrets once and start PostgreSQL + two local
   Kubo/Cluster peers:

   ```shell
   sh infra/ipfs-cluster/init-secrets.sh
   docker compose --env-file .env -f infra/compose.yaml up -d
   sh infra/ipfs-cluster/verify.sh
   ```

2. Start the separate local 4-validator Besu QBFT network (see
   [`infra/besu-qbft/README.md`](infra/besu-qbft/README.md)).

3. Run offline verification:

   ```shell
   cargo fmt --all -- --check
   cargo test --workspace --all-targets --locked --offline
   cargo clippy --workspace --all-targets --locked --offline -- -D warnings
   ```

4. Run live local integration tests against running Compose services (never
   run `docker compose down -v` and do not target `rrfs_dev` for test runs):

   ```shell
   set -a && . ./.env && set +a
   cargo test -p ipfs-adapter --locked --test cluster_integration -- --ignored
   DATABASE_URL="${DATABASE_URL%/*}/rrfs_indexer_test" cargo test -p metadata-store -p indexer -p gateway --locked
   ```

## Current Implementation & Verification Status (26 November 2026)

- **Implemented and unit/integration tested (P0–P5, CI & P7):**
  - **CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)):** Automated
    Rust fmt/Clippy/tests, crate-boundary verification, live PostgreSQL 18.6
    integration tests (`metadata-store`, `indexer`, `gateway`), Hardhat
    contract tests, and Compose (dev + per-role) / diff hygiene checks.
  - `crates/domain`, `crates/crypto`, `crates/ports` (including shared `RRDSPKG1`
    encrypted-package framing and `PreUploadScanner` port), `crates/key_custody`
    (with `CustodyStartupPolicy` production guard), `crates/scanner`
    (`DisabledScanner`, disabled by default), and `crates/application`
    (`AuthService`, `UploadService`, `DownloadService`, `ShareService`).
  - Solidity `AccessGovernance`, `FileRegistry`, `RrdsTimelockController`, and
    EIP-712/CID libraries (`35` Hardhat tests passing: 29 Solidity, 6 Node.js
    including §7.9 gas-bound verification in `GasBounds.ts`).
  - `crates/ipfs_adapter` (1 MiB chunk profile with multi-peer upload &
    retrieval failover per
    [`docs/adr/content-package-unixfs-profile.md`](docs/adr/content-package-unixfs-profile.md)):
    verified live against two local Kubo `0.43.1` + Cluster `1.1.6` peers
    (`sh infra/ipfs-cluster/verify.sh` and `cluster_integration` passed).
  - `crates/metadata_store` (migrations `0001`–`0006`, configurable
    `DATABASE_MIGRATION_MODE` defaulting to read-only `verify`, `build.rs`
    migration-change tracking, and schema-aware least-privilege role separation
    in [`infra/postgres/init-roles.sql`](infra/postgres/init-roles.sql))
    and `services/indexer`: verified live on host against PostgreSQL
    `rrfs_indexer_test` including real `rrfs_gateway` & `rrfs_indexer` RBAC
    enforcement (`28` passed).
  - `crates/chain_adapter`: QBFT finalized-head queries, ABI calldata encoders
    for `createFile` / `appendVersion` / `updateEnvelopeSet`, canonical RLP &
    EIP-2718 Type-2 zero-gas-price transaction relayer with sequential nonces
    and timeout reconciliation ([`docs/adr/chain-adapter-rpc-and-relayer.md`](docs/adr/chain-adapter-rpc-and-relayer.md)).
  - `services/gateway`: challenge-response auth + `DELETE /v1/auth/session`
    revocation, `X-Request-Id` correlation & structured JSON logs, multi-budget
    rate limiting (`src:*`, `member:*`, separate `invalid_sig_src:*`), public
    identity lookup, signed access lookup, ciphertext streaming, canonical
    envelope retrieval, indexer-backed file listing & version history,
    self-audited audit queries, authenticated ciphertext-only blob staging
    (`POST /v1/blobs/{content,envelopes}`), and relayed write routes
    (`POST /v1/files`, `POST /v1/files/{fileId}/versions`,
    `POST /v1/files/{fileId}/versions/{version}/envelopes`) with pin-before-commit
    quorum enforcement, verified by real-HTTP Axum integration tests and live
    PostgreSQL tests on `rrfs_indexer_test`.
  - `apps/cli`: thin CLI commands (`health`, `login`, `logout`, `whoami`,
    `identity`, `ls`, `history`, `upload`, `modify`, `download`, `share`,
    `restore`, `audit`) wired to `crates/application`, default-disabled
    `PreUploadScanner`, and `GatewayHttpClient` (with regular-file/size input
    validation, CARv1 raw-block CID verification, atomic `0600` + `fsync` +
    `rename` output writes, and `CustodyStartupPolicy` enforcement), verified
    end-to-end over HTTP.
  - **P7 & Spec Hardening (`tests/`, `schemas/`, runbook, demo, Compose templates & docs):**
    cross-component `rrds-tests` workspace suite (`tests/end_to_end/acceptance.rs`,
    `tests/security/invariants.rs`, `tests/integration/cross_component.rs`),
    cross-implementation RFC 9180 HPKE test vectors ([`tests/fixtures/hpke-rfc9180-v1.json`](tests/fixtures/hpke-rfc9180-v1.json)),
    complete JSON schemas under [`schemas/`](schemas/),
    incident recovery runbook ([`docs/runbooks/ransomware-recovery.md`](docs/runbooks/ransomware-recovery.md)),
    threat model ([`docs/threat-model.md`](docs/threat-model.md)),
    contract API & gas reference ([`docs/contract-api.md`](docs/contract-api.md)),
    scripted local demo ([`scripts/demo-local.sh`](scripts/demo-local.sh)),
    production-separated per-role Compose templates ([`infra/compose/`](infra/compose/README.md)),
    design justifications ([`docs/decisions/README.md`](docs/decisions/README.md)),
    and cross-component development notes ([`docs/development-notes.md`](docs/development-notes.md)).
  - Full offline Rust workspace suite: **124 passed, 0 failed** (115 executed
    offline; 9 PostgreSQL tests return early when `DATABASE_URL` is unset and
    were separately verified live on host against `rrfs_indexer_test` with
    `28` passed across `metadata-store`/`indexer`/`gateway`; 1 live two-peer
    Cluster test is ignored by default and separately verified on host), strict
    Clippy (`-D warnings`), `cargo fmt --check`, and `git diff --check` passing.

- **Remaining before MVP acceptance (§15.4):**
  - **P6 (In progress — local Besu smoke-test deployed 27 Nov 2026):**
    `RrdsTimelockController`, `AccessGovernance`, and `FileRegistry` are deployed
    on local Besu (`chainId=1337`) using **dev-only EOA placeholders** (to be
    replaced with real Safe multisigs later; see
    [`contracts/README.md`](contracts/README.md)), and the 24-hour timelocked
    activation batch (`FILE_REGISTRY_ROLE` + demo org) is scheduled (ready at
    `2026-11-27T20:26:20.000Z`). Remaining: execute the ready timelock batch,
    enroll demo member(s), configure contract addresses in local `.env`, run
    live end-to-end verification (`indexer` + `gateway` + `scripts/demo-local.sh`),
    inspect `rrfs_dev` migration 3 (`VersionMismatch(3)`), and later validate
    real Safe smart-account proxies on Besu before any production claim.

See [`progress_report.md`](progress_report.md) for the complete chronological
record and maintainer decisions.
