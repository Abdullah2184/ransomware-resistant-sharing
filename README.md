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
- **Multisignature governance:** Audited Safe v1.4.1 (`2-of-3`) threshold proxy
  contracts (`@safe-global/safe-contracts` `1.4.1`) for Organization Safes, an
  Emergency Safe (suspend only), and a 24-hour Consortium Safe
  `RrdsTimelockController` govern membership, key rotation, and policy changes.
- **Key custody (MVP baseline):** The MVP operates with `DevelopmentKeyCustody`
  (CLI) and `DevelopmentRelayerSigner` (gateway), explicitly gated by
  `RRDS_ALLOW_UNSAFE_DEV_CUSTODY=true` / `GATEWAY_ALLOW_UNSAFE_DEV_RELAYER=true`
  and refused whenever `RRDS_ENV=production` or `Production` startup policies are
  enforced. Hardware HSM / PKCS#11 adapters remain post-MVP behind the existing
  `KeyCustodyProvider` and `RelayerSigner` ports.

## Documentation Map

- **Canonical Specification:** [`docs/specifications/TECHNICAL_SPECIFICATION.md`](docs/specifications/TECHNICAL_SPECIFICATION.md)
- **System Architecture & Trust Boundaries:** [`docs/architecture/README.md`](docs/architecture/README.md)
  - [Deployment Placement, Crate Boundaries & Data Isolation](docs/architecture/deployment-and-boundaries.md)
  - [Cryptography, Key Custody & Encrypted IPFS Storage](docs/architecture/cryptography-custody-and-storage.md)
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
- **Consortium Operational & Governance Policies (§17):** [`docs/operations/consortium-policies.md`](docs/operations/consortium-policies.md)
- **Production-Separated Per-Role Compose Templates:** [`infra/compose/README.md`](infra/compose/README.md)
- **Step-by-Step MVP Demonstration Guide:** [`demo.md`](demo.md)
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

## Current Implementation & Verification Status (28 November 2026)

- **Implemented and verified across the full stack:**
  - **CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)):** Automated
    Rust fmt/Clippy/tests, crate-boundary verification, live PostgreSQL 18.6
    integration tests (`metadata-store`, `indexer`, `gateway`), Hardhat
    contract tests, and Compose / diff hygiene checks.
  - **Smart contracts & Audited Safe v1.4.1 (`contracts/`):** `AccessGovernance`
    (Option B member-signed relayed `updateEnvelopeSet` with strictly
    Safe-governed ACL mutations, `17,475` runtime bytes), `FileRegistry`,
    `RrdsTimelockController` (`86,400`s delay), EIP-712/CID libraries, and
    real audited `@safe-global/safe-contracts@1.4.1` `2-of-3` threshold Safe
    proxies (`37` Hardhat tests passing: 30 Solidity, 7 Node.js including
    `GasBounds.ts` and `SafeGovernance.ts`).
  - **Core Rust crates (`domain`, `crypto`, `ports`, `key_custody`, `scanner`, `application`):**
    1 MiB AES-256-GCM chunks, official RFC 9180 + OpenSSL HPKE vectors
    ([`tests/fixtures/hpke-rfc9180-v1.json`](tests/fixtures/hpke-rfc9180-v1.json)),
    EIP-712 cross-language parity, `RRDSPKG1` framing, `PreUploadScanner`
    (`DisabledScanner` default), `CustodyStartupPolicy` production guard, and
    `AuthService` / `UploadService` (with `restore_version_from`) /
    `DownloadService` / `ShareService`.
  - **Storage (`crates/ipfs_adapter`):** Kubo `0.43.1` + Cluster `1.1.6`
    multi-peer upload/retrieval failover, pin quorum verification, Cluster
    `unpin`, and `health_status` probing — verified live against two local
    Kubo/Cluster peers.
  - **Database & Indexer (`crates/metadata_store`, `services/indexer`):**
    Migrations `0001`–`0007` (including `gateway_relayed_transactions` &
    `gateway_orphan_blobs`), standalone `rrds-migrate` binary (`run`/`verify`),
    least-privilege roles ([`infra/postgres/init-roles.sql`](infra/postgres/init-roles.sql)),
    `RRDS_ENV=production` startup guards, and full governance/timelock event
    decoding (`RoleGranted`, `CallScheduled`, `CallExecuted`, etc.).
  - **Gateway & Relayer (`crates/chain_adapter`, `services/gateway`):**
    Challenge-response auth + `DELETE /v1/auth/session`, multi-budget
    PostgreSQL token-bucket rate limits (`src:*`, `member:*`, `org:*`,
    `invalid_sig_src:*`), bounded concurrent-stream semaphore
    (`GATEWAY_MAX_CONCURRENT_STREAMS`), `file.version_restore` source-version
    audit tracking, Type-2 zero-gas-price relayer with gas estimation & nonce
    resync, persistent transaction reconciliation (`GET /v1/transactions/{txHash}`
    with cross-member `404` isolation), safe background `OrphanBlobCleaner`
    (verifying both Postgres projections and Besu on-chain state before
    unpinning), background `StorageHealthMonitor`, and `RRDS_ENV=production`
    refusal guards.
  - **Thin CLI (`apps/cli`):** 13 commands (`health`, `login`, `logout`,
    `whoami`, `identity`, `ls`, `history`, `upload`, `modify`, `download`,
    `share`, `restore`, `audit`) with regular-file/size bounds, CARv1 CID
    verification, and atomic `0600` output writes.
  - **Operations & Policies:** Complete per-role Compose templates
    ([`infra/compose/`](infra/compose/README.md): `database`, `gateway` + Caddy
    TLS, `indexer`, `ipfs-peer`, `besu-validator`, `besu-rpc`), consortium
    operational policies ([`docs/operations/consortium-policies.md`](docs/operations/consortium-policies.md)),
    incident recovery runbook, and scripted demo ([`scripts/demo-local.sh`](scripts/demo-local.sh)).

- **Live Besu QBFT Verification & Current Activation Window:**
  - Full live end-to-end demo (`scripts/demo-local.sh`: login -> V1 upload with
    2-peer Cluster pin -> live indexer sync -> byte-for-byte verified download
    -> V2 append -> contiguous hash-chained audit trail) verified on the initial
    Besu deployment (`blocks 59814..60745`).
  - **Current active deployment (Safe v1.4.1 `2-of-3` + Option B):** Deployed
    at blocks `62877`–`62894` (`consortiumSafe`, `emergencySafe`,
    `organizationSafe` all verified `threshold=2`); 24-hour timelock activation
    batch scheduled via **`2-of-3` `consortiumSafe.execTransaction`** at block
    `62898`, executable at **`2026-11-29T03:19:33.000Z`** (see
    [`contracts/README.md`](contracts/README.md)). Once executed, run
    `register-member`, update `.env`, and exercise live Safe-governed ACL grant
    + Option B relayed `cli share`.
  - **Post-MVP deferred:** Hardware HSM / PKCS#11 implementations of
    `KeyCustodyProvider` and `RelayerSigner` (MVP uses explicitly gated
    dev software custody).

See [`progress_report.md`](progress_report.md) for the complete chronological
record and verification matrix.
