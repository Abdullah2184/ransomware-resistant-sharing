# Project progress and remaining work

**Reviewed:** 26 November 2026
**Canonical guide:** [`TECHNICAL_SPECIFICATION.md`](TECHNICAL_SPECIFICATION.md)
**Branch:** `agent/development`
**Repository state:** P0–P5, CI, and P7 implementation, unit/integration/security/acceptance
tests, live local IPFS Cluster & PostgreSQL (`rrfs_indexer_test`) verification,
runbook, demo script, per-role Compose templates, and synchronized documentation
are in the working tree on `agent/development`.

## Current assessment

All offline-implementable backlog phases (P0–P5, CI, and P7) are implemented
and verified: pure domain and crypto crates, `ports` (with `RRDSPKG1` framing
and `PreUploadScanner`), `scanner` (`DisabledScanner`), `key_custody` (with
`CustodyStartupPolicy`), the `application` use-case services (`AuthService`,
`UploadService`, `DownloadService`, `ShareService`), Solidity contracts and 39
Hardhat tests, the Kubo/Cluster adapter (verified live against two local peers
with 1 MiB chunks), the PostgreSQL `metadata_store` (migrations `0001`–`0005` +
role separation SQL) and `indexer` (verified live on host against
`rrfs_indexer_test`), the `chain_adapter` Type-2 transaction relayer and ABI
encoders, the hardened `gateway` read/blob/write/session-revocation routes, the
thin 12-command `apps/cli` (`GatewayHttpClient` + CARv1 verifier), the
cross-component `tests/` suites (`rrds-tests`), recovery runbook, scripted demo,
per-role Compose templates, design justifications, and development notes. The
specification's MVP acceptance criteria in §15.4 remain **open** pending **P6
(maintainer-gated)**: deploying contracts to local Besu with approved Safe
addresses, executing timelocked `FILE_REGISTRY_ROLE` activation, running live
end-to-end verification against deployed Besu contracts, and reviewing the
pre-existing `rrfs_dev` migration 3 checksum discrepancy.

## Phase status

| Specification phase | Status | Remaining work |
|       ---           |   ---  |     ---        |
| 0 — repository and decisions | Established + CI workflow added | Complete open operational/production decisions before production deployment. |
| 1 — domain, crypto & application | Implemented & unit-tested (+ `scanner` default-disabled interface) | Add published/cross-implementation HPKE vectors. |
| 2 — contracts | Local contract implementation & 39 tests passing | Deploy to Besu with approved Safe addresses, activate `FILE_REGISTRY_ROLE` through the 24h timelock, and verify deployed contracts (P6). |
| 3 — storage and indexer | Live two-peer Cluster & PostgreSQL (`rrfs_indexer_test`) verified (+ role separation SQL) | Inspect pre-existing `rrfs_dev` migration 3 checksum discrepancy before any additive reconciliation (maintainer-gated). |
| 4 — gateway & relayer | Auth, session revocation, `X-Request-Id`, multi-budget rate limits, read/blob/write routes implemented & HTTP/PostgreSQL-tested | Production TLS termination and live-Besu end-to-end verification once contracts are deployed (P6). |
| 5 — CLI | Thin CLI (`health`, `login`, `whoami`, `identity`, `ls`, `history`, `upload`, `modify`, `download`, `share`, `restore`, `audit`) wired to `crates/application` & `GatewayHttpClient` and HTTP-tested | Production HSM custody adapter and live-Besu end-to-end verification once contracts are deployed (P6). |
| 6 — integration and demo | Acceptance/security/integration suites (`tests/`), recovery runbook, scripted demo, per-role Compose templates, and design/dev docs implemented & verified offline (P7) | Live end-to-end verification against deployed Besu contracts & Safe timelock activation (P6) plus optional leftover template cleanup. |

## Current verified foundations

- Rust domain and crypto types include AES-256-GCM chunk encryption,
  RFC 9180 HPKE wrapping, canonical manifest/envelope-set validation, and
  EIP-712 cross-language digest tests.
- Solidity `AccessGovernance`, `FileRegistry`, CID/EIP-712 libraries, and a
  timelock deployment module have local tests. The suite last passed 39 tests
  (32 Solidity and 7 TypeScript); this does not verify deployment to Besu or an
  actual Safe.
- Besu QBFT has a local four-validator topology and a separate RPC node. Its
  last recorded live verifier passed chain ID 1337, four peers, four
  validators, and QBFT committed block 969. The generic PoS `finalized` tag
  returned `Unknown block`; the specification and chain adapter use the latest
  QBFT committed head, with an explicit block number for related state reads.
- Local Cluster replication now passes. After configuring the pinned Kubo
  0.43.1 services with a private LAN DHT and its legacy provider for custom DHT
  routing, Kubo 2 discovered Kubo 1 as provider and retrieved the payload. The
  full verifier reports `PINNED` on both Cluster peers with zero attempts. The
  local two-node setup still shares a single host and failure domain.
- PostgreSQL contains `rrfs_dev` and `rrfs_indexer_test`. Neither database was
  modified. Host-side Kubo and PostgreSQL access and live DB integration remain
  unverified: Compose declares loopback ports 5432/15001/15002, but Kubo's
  `127.0.0.1:15001` endpoint refused connections from this coding shell and the
  running PostgreSQL container had no active network port allocation. Applying
  `docker compose up -d` did not remove or recreate named volumes.
- The gateway currently exposes `/healthz`, public contract-backed identity,
  challenge/session, signed access lookup, and encrypted content streaming.
  Authorization and audit happen before releasing protected references or
  ciphertext, but a stream audit does not prove complete client receipt.
- The last `cargo test --workspace --all-targets --locked --offline` run
  passed. PostgreSQL tests skip when `DATABASE_URL` is unset, and the live
  two-peer IPFS integration test is ignored by default. Strict Clippy,
  formatting, `git diff --check`, Hardhat tests, Compose validation, and the
  Besu verifier were also recorded as passing in the prior implementation
  increment.
- This takeover turn reran that full offline workspace suite successfully after
  rerunning with local-listener permission. Cargo reported 74 passing tests;
  the PostgreSQL integration harness returned early because `DATABASE_URL` was
  unset, and the live Kubo integration test remains ignored by default.
  `git diff --check` passed.

## Immediate implementation sequence

1. Safely establish the local integration baseline: Cluster two-peer
   replication is now verified; run indexer integration tests from a
   Docker-networked Rust runner against `rrfs_indexer_test`, retain `rrfs_dev`
   and its migration history, and check host Kubo/PostgreSQL connectivity.
2. Deploy contracts to the already configured Besu network after the approved
   Safe inputs are available. Verify deployment, timelocked registry-role
   activation, and chain-adapter reads.
3. Implement application service boundaries and the transaction-relay port,
   then add gateway routes in small slices with unit/integration tests.
4. Connect the CLI to application services and add end-to-end workflows.
5. Run acceptance/failure tests, update operational documentation, and close
   unresolved decisions before claiming MVP completion.

## Manual setup / maintainer decisions

These items require maintainer-owned credentials, addresses, policy choices, or
environment access. Do not invent them or place secrets in tracked files:

- Provide approved `consortiumSafeAddress` and `emergencySafeAddress` values
  in the private Hardhat Ignition parameters and the deployer key in the
  Hardhat keystore. After deployment, the consortium Safe must schedule and
  execute `FILE_REGISTRY_ROLE` through the configured 24-hour timelock.
- From the Docker Desktop host, verify loopback forwarding for PostgreSQL
  `127.0.0.1:5432` and Kubo `127.0.0.1:15001/15002`. Then set `DATABASE_URL`
  to the existing `rrfs_indexer_test` database and run
  `cargo test -p indexer -p metadata_store --locked`; no new database is needed.
- Configure the deployed `CONTRACT_FILE_REGISTRY_ADDRESS` and
  `CONTRACT_ACCESS_GOVERNANCE_ADDRESS` in the ignored local environment after
  deployment.
- Do not use `rrfs_dev` for new migration verification until its recorded
  migration 3 checksum/schema discrepancy has been reviewed.
- Decide the production HSM topology/provider, member onboarding authority,
  organization Safe thresholds, independent replica policy, retention/orphan
  cleanup policy, and emergency recovery policy before production work.
- No manual Kubo/Cluster configuration is currently needed; the local
  two-peer replication verifier passes after the tracked routing fix.
- The local Besu network has been configured and verified; no manual Besu
  genesis or validator-key setup is currently needed.

## Known documentation inconsistencies to reconcile

- [`services/indexer/README.md`](services/indexer/README.md) previously said it
  queried Besu's generic `finalized` tag. This was corrected to match the QBFT
  chain adapter's use of `latest` as the committed/finalized head, in
  accordance with specification §7.10.
- Kubo's local routing/provider behavior and its Kubo 0.43.1 version-bound
  sweep-provider workaround are documented in the IPFS Cluster README and
  [`docs/adr/local-integration-verification.md`](docs/adr/local-integration-verification.md).
- [`infra/besu-qbft/README.md`](infra/besu-qbft/README.md) now labels block 743
  as an earlier snapshot and block 969 as the later same-day observation.
- The root README contains older takeover notes alongside later runtime
  updates. Preserve the historical record but make the current status and
  dates explicit so old blockers are not mistaken for current state.

## Effort estimate

The remaining work is significant. A rough estimate for one engineer to reach
a reproducible local MVP is **6–10 weeks**, assuming timely Safe/address and
database setup and no new protocol changes. Production HSM integration,
independently operated consortium infrastructure, and production security
review are outside that estimate.

## Takeover review and P0/P1 increment (26 November 2026)

- Recorded a full engineering review in [`agentic_review.md`](agentic_review.md)
  covering component boundaries, deployment placement, spec gaps, bugs, test
  quality, backlog priorities, and [`manual_review.md`](manual_review.md) items.
- **P0 fixes & hardening:**
  - Closed the rate-limit bypass on `POST /v1/files/{fileId}/versions/{version}/access`
    (`services/gateway/src/routes.rs`) and tightened the `access_lookup`
    encryption-key-version check.
  - Fixed `CONTRACT_FILE_REGISTRY_ADDRESS` error reporting in
    `services/gateway/src/config.rs`.
  - Consolidated EIP-712 `LoginChallenge` digest hashing into
    `crates/crypto/src/signing.rs` (tested against `tests/fixtures/eip712-v1.json`)
    and removed duplicate EIP-712 helpers from `services/gateway/src/auth.rs`.
  - Fixed `services/indexer/src/main.rs` so `EnvelopeSetInitialized` projects
    `revision = 1` (matching `AccessGovernance.sol`), `ReadAccessRevoked`
    invalidates `historical_read_access_projection`, and the dormant PostgreSQL
    test log data includes the required `0x` prefix.
  - Added `CustodyStartupPolicy` and `verify_provider_policy` in
    `crates/key_custody` so non-development startup rejects test-only or
    exportable-key providers.
- **P1 domain, ports, crypto & application core:**
  - Added `FolderId`, `MemberStatus`, `FileStatus`, `PublicMemberIdentity`,
    `FileMetadata`, `AccessReference`, `LoginChallenge`, and `TransactionReceipt`
    to `crates/domain`.
  - Added chunk-0 `encrypt_private_metadata` / `decrypt_private_metadata`,
    `EncryptedFileManifest::manifest_hash`, `raw_sha256_cid`, and
    `EncryptedChunk::from_parts` to `crates/crypto`.
  - Added `Clock` / `SystemClock`, `AuthenticatedSession`, `HeadState`,
    `GatewayAuthPort`, and `LedgerPort` to `crates/ports`.
  - Implemented `crates/application` (`AuthService`, `UploadService` for
    create/modify/append-only restore + `OrphanedUpload`, `DownloadService`, and
    `ShareService`) with 4 end-to-end in-memory workflow tests covering login,
    upload, download, tamper detection, sharing without re-encryption,
    historical read grants, revocation + known old-key limits, append-only
    restore, insufficient pin quorum, and orphaned uploads.
- **Architecture documentation (`manual_review.md` #1):**
  - Added [`docs/architecture/README.md`](docs/architecture/README.md),
    [`docs/architecture/authentication-and-challenge.md`](docs/architecture/authentication-and-challenge.md),
    [`docs/architecture/historical-access.md`](docs/architecture/historical-access.md),
    and [`docs/architecture/recovery-and-revocation.md`](docs/architecture/recovery-and-revocation.md),
    plus updated `crates/application/README.md`, `crates/ports/README.md`, and
    `crates/key_custody/README.md`.
- **P2 gateway read routes, HTTP test harness & IPFS Cluster test fix (26 November 2026):**
  - Diagnosed the live Cluster test failure from host output: Windows Docker
    Desktop (`dockerDesktopLinuxEngine`) was stopped, AND
    `crates/ipfs_adapter/tests/cluster_integration.rs` failed before network I/O
    because Cargo runs integration tests with CWD `crates/ipfs_adapter/`, where
    relative `.env` `IPFS_CLUSTER_PASSWORD_FILE` paths do not exist. Fixed
    workspace-root path resolution and non-secret diagnostics in
    `cluster_integration.rs` and reconciled `infra/ipfs-cluster/README.md`.
  - Added `GatewayChainPort` and `GatewayStorePort` traits in
    `services/gateway/src/ports.rs` and implemented the missing read-side routes
    in `services/gateway/src/{store.rs,routes.rs}`:
    `GET /v1/files/{fileId}/versions/{version}/envelope` (validating canonical
    `KeyEnvelopeSet` + recipient key version + fail-closed audit),
    `GET /v1/files` (`authoritative: false` with finalized/indexed cursors),
    `GET /v1/files/{fileId}/versions` (authoritative Read ACL + version
    history), and `GET /v1/audit` (self-audited member audit query), all
    rate-limited.
  - Added a real-HTTP Axum end-to-end test in `services/gateway/src/routes.rs`
    covering auth, replay rejection, public identity, signed access lookup,
    historical access, content & envelope retrieval, listing, history, audit
    queries, fail-closed audit persistence errors (`503`), and `/access` rate
    limiting (`429`). Updated `docs/api.md` and `services/gateway/README.md`.
- **Live two-peer IPFS Cluster & Rust `ipfs-adapter` verification (26 November 2026):**
  - Fixed `kubo2` restart loop (`Error: open /data/ipfs/datastore/LOG: permission denied`)
    by normalizing `/data/ipfs` ownership in `infra/ipfs-cluster/start-kubo.sh`
    and switching `infra/compose.yaml` Kubo healthchecks to `gosu ipfs ipfs --api /ip4/127.0.0.1/tcp/5001 id`.
  - Fixed three live Kubo `0.43.1` / Cluster `1.1.6` protocol bugs discovered
    during live integration testing: amended chunk profile to 1 MiB plaintext
    (`1,048,576` bytes; `chunker=size-1048592` under Kubo's `2,096,896`-byte
    ceiling; updated `docs/adr/content-package-unixfs-profile.md`,
    `crates/crypto`, `schemas/encrypted-file-manifest-v1.json`, and
    `crates/ipfs_adapter`), handled Kubo's intermediate `"chunks"` directory
    entry on `wrap-with-directory=true` adds, and fixed Cluster pin-status
    polling from `/pins/{cid}/status` to `/pins/{cid}`.
  - Live host verification passed: all 5 Compose services healthy,
    `sh infra/ipfs-cluster/verify.sh` passed (`PINNED` on both peers, 0
    attempts), and `cargo test -p ipfs-adapter --locked --test cluster_integration -- --ignored`
    passed (`1 passed; 0 failed` in 1.66s).
- **Live PostgreSQL verification & P3 relayer + gateway write routes (26 November 2026):**
  - Verified all 5 PostgreSQL integration tests (`metadata-store`, `indexer`, `gateway`) live on host against `rrfs_indexer_test` (`20 passed; 0 failed`, leaving `rrfs_dev` untouched).
  - Recorded [`docs/adr/chain-adapter-rpc-and-relayer.md`](docs/adr/chain-adapter-rpc-and-relayer.md) and added [`crates/chain_adapter/README.md`](crates/chain_adapter/README.md).
  - Implemented `crates/chain_adapter/src/relayer.rs` (Solidity ABI calldata encoders for `FileRegistry.createFile`, `FileRegistry.appendVersion`, and `AccessGovernance.updateEnvelopeSet`; canonical RLP & zero-gas-price EIP-2718 Type-2 transactions; `RelayerSigner` / `DevelopmentRelayerSigner` with `RelayerStartupPolicy`; `TransactionRelayer` with sequential nonce tracking and `reconcile_transaction`) plus `BesuClient::{has_write_access, pending_nonce, estimate_gas, send_raw_transaction, transaction_receipt}` with proper JSON-RPC `null` receipt handling.
  - Wired `GatewayRelayerPort`, `BesuContractRelayer`, `GatewayStore::record_write_attempt`, and the 3 rate-limited gateway write routes (`POST /v1/files`, `POST /v1/files/{fileId}/versions`, `POST /v1/files/{fileId}/versions/{version}/envelopes`) with EIP-712 verification, stale-head checks, pin-before-commit Cluster quorum enforcement, canonical `KeyEnvelopeSet` validation, explicit commit/revert/timeout responses, and real-HTTP Axum integration tests; updated `docs/api.md` and `services/gateway/README.md`.
- **P4 thin CLI, HTTP gateway client & ciphertext blob staging (26 November 2026):**
  - Added shared `RRDSPKG1` encrypted-package framing (`encode_content_package_frame` / `decode_content_package_frame` with unit tests) in `crates/ports/src/blob_store.rs` and authenticated ciphertext-only staging routes `POST /v1/blobs/content` and `POST /v1/blobs/envelopes` in `services/gateway` (keeping Kubo/Cluster credentials off endpoints).
  - Added `HpkeRecipientKeyPair::derive_from_seed` and `DevelopmentKeyCustody::from_dev_secrets` (rejected by `CustodyStartupPolicy::Production`).
  - Implemented `apps/cli/src/{gateway_client.rs,car.rs,main.rs}`: `GatewayHttpClient` implementing `GatewayAuthPort`, `LedgerPort`, and `BlobStore` strictly over HTTP, bounded CARv1 reader with raw-block SHA-256 CID verification, and thin CLI commands (`health`, `login`, `whoami`, `identity`, `ls`, `history`, `upload`, `modify`, `download`, `share`, `restore`, `audit`) with an end-to-end HTTP test covering login, upload, download, share without re-encryption, recipient decrypt, modify, and append-only restore.
  - Updated `apps/cli/README.md`, `docs/adr/phase-5-cli-incremental-scope.md`, `docs/api.md`, `services/gateway/README.md`, `docs/architecture/deployment-and-boundaries.md`, `README.md`, and `agentic_review.md`.
- **CI workflow & P5 gateway hardening + scanner interface (26 November 2026):**
  - Added [`.github/workflows/ci.yml`](.github/workflows/ci.yml) covering Rust
    fmt/Clippy/tests, crate-boundary verification, live PostgreSQL 18.6
    integration tests (`metadata-store`, `indexer`, `gateway`), Hardhat
    contract tests, and Compose/diff hygiene.
  - Implemented `ports::PreUploadScanner` (`ScannerMode::{Disabled, Warn, Enforce}`,
    default `Disabled`) and `crates/scanner::DisabledScanner` with unit tests.
  - Added migration `0005_gateway_session_revocation.sql`, PostgreSQL
    least-privilege role-separation template [`infra/postgres/init-roles.sql`](infra/postgres/init-roles.sql)
    + [`infra/postgres/README.md`](infra/postgres/README.md), `DELETE /v1/auth/session`
    revocation (atomic DB + audit), `X-Request-Id` correlation & structured JSON
    operational logs, and multi-budget rate limiting (`src:*`, `member:*`, and
    separate `invalid_sig_src:*` buckets) with HTTP & PostgreSQL tests.
  - Added `crates/metadata_store/build.rs` (`cargo:rerun-if-changed=migrations`)
    so `sqlx::migrate!` always recompiles when new SQL migrations are added, and
    verified all 5 PostgreSQL integration tests (including `0005` session
    revocation) live on host against `rrfs_indexer_test`.
- **P7 cross-component test suites, recovery runbook, demo, per-role Compose templates & design/dev docs (26 November 2026):**
  - Added workspace test package `rrds-tests` ([`tests/Cargo.toml`](tests/Cargo.toml))
    covering 9 cross-component tests:
    - [`tests/end_to_end/acceptance.rs`](tests/end_to_end/acceptance.rs) (3 tests):
      ransomware containment & append-only recovery over 1 MiB multi-chunk
      payloads (`DEFAULT_CHUNK_SIZE_BYTES`), concurrent stale-head conflict
      rejection & orphan CID reporting, and read revocation invalidating
      historical grants + key rotation without ciphertext re-encryption.
    - [`tests/security/invariants.rs`](tests/security/invariants.rs) (5 tests):
      AEAD tamper / chunk-swap / context-transplant rejection, HPKE recipient &
      context binding, EIP-712 cross-contract & cross-chain domain separation,
      production `CustodyStartupPolicy` / `RelayerStartupPolicy` enforcement,
      and plaintext `RRDSPKG1` frame rejection + default-disabled scanner check.
    - [`tests/integration/cross_component.rs`](tests/integration/cross_component.rs) (1 test):
      real `KeyCustodyProvider` EIP-712 signing -> `chain_adapter` ABI encoding
      (`createFile` & `updateEnvelopeSet`) -> `TransactionRelayer` EIP-2718
      Type-2 zero-gas-price submission against a mock Besu JSON-RPC endpoint.
  - Added [`docs/runbooks/ransomware-recovery.md`](docs/runbooks/ransomware-recovery.md)
    (containment, forensic inspection, historical read grant, `rrds restore`,
    indexer rebuild/reindex, relayer reconciliation, orphan CID handling, and
    post-incident rotation/reinstatement).
  - Added [`scripts/demo-local.sh`](scripts/demo-local.sh) (`sh -n` verified,
    zero hardcoded secrets) driving `rrds` end-to-end against a running gateway.
  - Added production-separated per-role Compose templates under
    [`infra/compose/`](infra/compose/README.md) (`database.yaml`, `ipfs-peer.yaml`,
    `besu-validator.yaml`, `besu-rpc.yaml`) and wired them into CI hygiene checks.
  - Added [`docs/decisions/README.md`](docs/decisions/README.md) (design
    justifications & explicit MVP limitations) and
    [`docs/development-notes.md`](docs/development-notes.md) (cross-component
    coupling, `services/` vs `crates/` rationale, and test placement conventions).
- **Verification (26 November 2026):**
  - `cargo test --workspace --all-targets --locked --offline`: **106 passed**
    (101 executed offline, 5 PostgreSQL tests returned early because `DATABASE_URL`
    is unset and were separately verified live on host against
    `rrfs_indexer_test`), 0 failed; live `ipfs-adapter` two-peer
    `cluster_integration` passed separately on host (`1 passed` in 1.66s).
  - `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`:
    passed (0 warnings).
  - `cargo fmt --all -- --check`, `sh -n scripts/demo-local.sh`, and
    `git diff --check`: passed.
  - Hardhat (`pnpm exec hardhat test --no-compile` against checked-in artifacts):
    **39 passing** (32 Solidity, 7 Node.js; 34 RRDS + 5 leftover `Counter`
    template tests).
  - MVP acceptance criteria in §15.4 remain **unmet** pending maintainer-gated
    Besu contract/Safe deployment and live-Besu end-to-end verification (P6).