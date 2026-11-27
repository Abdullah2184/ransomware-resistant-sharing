# Project Progress and Remaining Work

**Last verified:** 27 November 2026
**Canonical specification:** [`docs/specifications/TECHNICAL_SPECIFICATION.md`](docs/specifications/TECHNICAL_SPECIFICATION.md) (RRDS-TS-001 v1.0)
**Branch:** `agent/development` (uncommitted working tree containing P0–P5, CI, and P7)

---

## 1. Executive Summary — Where We Are Right Now

All offline-implementable engineering phases (**P0–P5, CI, and P7**) are **implemented and verified**:

- **End-to-end Rust stack:** `domain`, `crypto` (1 MiB AES-256-GCM chunks + RFC 9180 HPKE + EIP-712 + canonical codecs), `ports` (including shared `RRDSPKG1` framing and `PreUploadScanner`), `scanner` (`DisabledScanner`, disabled by default), `key_custody` (with `CustodyStartupPolicy` production guard), `application` (`AuthService`, `UploadService`, `DownloadService`, `ShareService`), `ipfs_adapter` (Kubo `0.43.1` + Cluster `1.1.6`), `chain_adapter` (QBFT reads + ABI encoders + Type-2 zero-gas-price transaction relayer), `metadata_store` (migrations `0001`–`0005` + `build.rs` rebuild tracking + least-privilege role SQL), `indexer`, hardened `gateway` (all read, blob-staging, write-relay, session-revocation, audit, and multi-budget rate-limit routes), thin 12-command `apps/cli` (`GatewayHttpClient` + CARv1 verifier), and cross-component `rrds-tests` (`tests/`).
- **Smart contracts:** `AccessGovernance`, `FileRegistry`, `RrdsTimelockController`, `RrdsCid`, and `RrdsEip712` are implemented and locally tested with Hardhat.
- **Live local infrastructure verified:** Two-peer Kubo `0.43.1` + IPFS Cluster `1.1.6` replication and PostgreSQL `18.6` (`rrfs_indexer_test`, migrations `0001`–`0005`) have both been verified live on the host. Local 4-validator Besu QBFT + RPC node was previously verified live (chain ID `1337`, 4 validators, committed block `969`).
- **Operations, CI & documentation:** GitHub Actions CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)), incident recovery runbook ([`docs/runbooks/ransomware-recovery.md`](docs/runbooks/ransomware-recovery.md)), scripted local demo ([`scripts/demo-local.sh`](scripts/demo-local.sh)), production-separated per-role Compose templates ([`infra/compose/`](infra/compose/README.md)), design justifications ([`docs/decisions/README.md`](docs/decisions/README.md)), development coupling notes ([`docs/development-notes.md`](docs/development-notes.md)), architecture guides, and component READMEs are complete.

**MVP status (§15.4):** **In final P6 activation window.** On 27 November 2026,
`RrdsTimelockController`, `AccessGovernance`, and `FileRegistry` were deployed
onto the live local 4-validator Besu QBFT network (`chainId = 1337`) using
**dev-only EOA placeholders** for `consortiumSafe`, `emergencySafe`, and
`organizationSafe` (clearly marked smoke-test only — real Safe multisig proxies
must replace them later per [`docs/adr/governance-authority-and-timelock.md`](docs/adr/governance-authority-and-timelock.md)),
and the 24-hour timelocked activation batch (`FILE_REGISTRY_ROLE` + demo org
registration) was scheduled on-chain (ready at `2026-11-27T20:26:20.000Z`).
Once executed, remaining local MVP sign-off is enrolling test member(s),
configuring contract addresses in `.env`, running live end-to-end verification
(`gateway` + `indexer` + `scripts/demo-local.sh`), and inspecting `rrfs_dev`
migration 3.

---

## 2. Verifiable Implementation & Test Matrix

Every number below reflects the most recent verified runs on this branch:

| Suite / Component | Scope Verified | Exact Verified Result | Command |
| --- | --- | --- | --- |
| **Rust workspace (offline)** | `domain` (9), `crypto` (33), `ports` (3), `scanner` (2), `key-custody` (8), `application` (8), `ipfs-adapter` (14), `chain-adapter` (19), `metadata-store` (2), `indexer` (5), `gateway` (13), `cli` (9), `rrds-tests` (`end_to_end` 3, `security` 6, `integration` 3) | **137 passed, 0 failed, 12 ignored** (**zero** silent DB skips: 10 live PostgreSQL tests and 2 live dual-node IPFS tests are explicitly `#[ignore]`) | `cargo test --workspace --all-targets --locked --offline` |
| **Live PostgreSQL (`rrfs_indexer_test`)** | `metadata-store` (2: migrations `0001`–`0006` + real `rrfs_gateway`/`rrfs_indexer` RBAC), `indexer` (4: replay incl. `EnvelopeSetInitialized` `revision=1`, rebuild, rollback, revocation invalidation, `reconcile_head` `0x` upsert & reindex reset), `gateway` (4: transactional auth/audit/`TRUNCATE`/burst-recovery/pruning, 8-way concurrency races, live projection queries, and live Postgres Axum HTTP router E2E) | **10 passed, 0 failed** (all 10 `#[ignore]` DB tests verified live on host against `rrfs_indexer_test`; `rrfs_dev` untouched) | `DATABASE_URL=.../rrfs_indexer_test DATABASE_GATEWAY_URL=... DATABASE_INDEXER_URL=... cargo test -p metadata-store -p indexer -p gateway --locked --offline -- --ignored` |
| **Live two-peer IPFS / Cluster** | Kubo `0.43.1` ×2 (`15001`/`15002`) + IPFS Cluster `1.1.6` ×2 (`9094`) private swarm, 1 MiB multi-chunk & 0-byte UnixFS 2-level CARv1 (`manifest.json` + `chunks/00000001..N`), bidirectional upload/retrieve across **both** Kubo nodes, `UploadService`/`DownloadService`/`ShareService`, Cluster auth `401` & tamper negative checks | **`verify.sh` passed** & **live dual-node tests: 2 passed, 0 failed** (`cluster_integration` 10.37s + `cross_component_integration` 2.72s on host) | `sh infra/ipfs-cluster/verify.sh` & `cargo test -p ipfs-adapter --test cluster_integration -p rrds-tests --test cross_component_integration --locked -- --ignored` |
| **Solidity & Hardhat contracts** | `AccessGovernance`, `FileRegistry` (duplicate check removed & freshly recompiled with `solc 0.8.34`), `RrdsTimelockController`, `RrdsCid`, `RrdsEip712`, EIP-712 cross-language fixtures, §7.9 gas bounds (`GasBounds.ts`) | **35 passing** (29 Solidity, 6 Node.js; freshly compiled with `solc 0.8.34`) | `pnpm --dir contracts exec hardhat test` |
| **Static analysis & hygiene** | Workspace linting, formatting, demo shell syntax, whitespace/EOF | **All passed** (0 Clippy warnings) | `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`, `cargo fmt --all -- --check`, `sh -n scripts/demo-local.sh`, `git diff --check` |
| **Local Besu QBFT network & contracts** | 4 validators + 1 non-validator RPC node (`127.0.0.1:8545`), `RrdsTimelockController` (`0x18cd...a80f`), `AccessGovernance` (`0xe130...6663`), `FileRegistry` (`0xf27d...e5cb`), 24h timelock activation batch scheduled | **Verified live** (27 Nov 2026: `chainId=1337`, 4 peers, 4 validators, deployed blocks `48149`/`48151`/`48153`, activation batch scheduled at block `48177`, ready `2026-11-27T20:26:20.000Z`; **dev-only EOA placeholders**, not real Safes yet) | `sh infra/besu-qbft/verify.sh` & `node contracts/scripts/besu-bootstrap.mjs status` |

---

## 3. Specification Phase Status (§16)

| Specification Phase | Status | Remaining Work |
| --- | --- | --- |
| **Phase 0 — Repository & decisions** | **Complete** (workspace, pinned toolchains, ADRs, CI workflow, design & coupling docs) | Resolve §17 production policy decisions before production rollout; optional leftover template cleanup. |
| **Phase 1 — Domain, crypto & application** | **Complete & tested** (`domain`, `crypto` + RFC 9180/OpenSSL HPKE vectors, `ports`, `key_custody`, `scanner` wired into `UploadService`, `application`) | None for local MVP. |
| **Phase 2 — Smart contracts** | **Implemented & locally tested** (34 RRDS Hardhat tests passing) | **P6 (maintainer-gated):** Deploy to local Besu with approved Safe addresses and execute timelocked `FILE_REGISTRY_ROLE` activation. |
| **Phase 3 — Storage & indexer** | **Complete & live-verified** (2-peer Kubo/Cluster + PostgreSQL `rrfs_indexer_test` + role-separation SQL) | Inspect pre-existing `rrfs_dev` migration 3 checksum mismatch (`VersionMismatch(3)`) before running migrations against `rrfs_dev`. |
| **Phase 4 — Gateway & relayer** | **Complete & HTTP/DB-tested** (auth, session revocation, `X-Request-Id`, JSON logs, multi-budget rate limits, read/blob/write routes, Type-2 relayer) | Live-Besu verification once contracts are deployed (**P6**); production TLS termination & non-dev relayer HSM (post-MVP). |
| **Phase 5 — CLI** | **Complete & HTTP-tested** (`health`, `login`, `whoami`, `identity`, `ls`, `history`, `upload`, `modify`, `download`, `share`, `restore`, `audit`) | Live-Besu end-to-end verification once contracts are deployed (**P6**); production HSM `KeyCustodyProvider` (post-MVP). |
| **Phase 6 — Integration, hardening & demo** | **Offline deliverables complete & tested (P7)** (`tests/`, recovery runbook, `scripts/demo-local.sh`, per-role `infra/compose/*.yaml`) | Run live end-to-end demo & integration verification against live Besu + deployed contracts + Cluster + PostgreSQL (**P6**). |

---

## 4. MVP Acceptance Criteria Tracker (`TECHNICAL_SPECIFICATION.md` §15.4)

| # | §15.4 Acceptance Criterion | Offline / Component Verification | Live Full-Stack Verification |
| --- | --- | --- | --- |
| 1 | Local encryption with fresh DEK -> content/envelope CIDs -> pin quorum -> on-chain registration | **Verified** (`application`, `ipfs_adapter`, `gateway`, `cli`, `rrds-tests`) | Cluster quorum **verified live**; Besu on-chain commit **pending P6** |
| 2 | Chain stores metadata/pointers only (no file bytes, private metadata, raw DEKs, or wrapped keys) | **Verified** (`contracts/`, `chain_adapter`, `gateway`, `rrds-tests`) | **Pending P6** live Besu deployment |
| 3 | Authorized user downloads, verifies, and decrypts; unauthorized user without envelope cannot decrypt ciphertext | **Verified** (`crypto`, `application`, `gateway`, `cli`, `rrds-tests`) | **Pending P6** live Besu deployment |
| 4 | Upload/modify rejects unauthorized writers, replayed/expired signatures, and stale parents | **Verified** (`contracts/`, `gateway`, `rrds-tests`) | **Pending P6** live Besu deployment |
| 5 | Successful & failed access attempts durably logged in PostgreSQL; audit failure fails closed; no routine read txs | **Verified** (`gateway` HTTP + **live PostgreSQL `rrfs_indexer_test`**) | PostgreSQL **verified live**; live Besu check **pending P6** |
| 6 | Share adds new envelope via governed update without re-encrypting ciphertext; historical sharing is explicit | **Verified** (`contracts/`, `application`, `gateway`, `cli`, `rrds-tests`) | **Pending P6** live Besu deployment |
| 7 | Revoke blocks future versions & invalidates historical grants; old-key limitation documented & tested | **Verified** (`contracts/`, `indexer`, `application`, `rrds-tests`, `docs/architecture/recovery-and-revocation.md`) | **Pending P6** live Besu deployment |
| 8 | Restore appends a new version referencing current head as parent with a fresh DEK; no history deleted | **Verified** (`contracts/`, `application`, `cli`, `rrds-tests`) | **Pending P6** live Besu deployment |
| 9 | Logical folder/file browsing; rebuildable indexer views never grant access | **Verified** (`indexer` live on `rrfs_indexer_test`, `gateway`, `cli`) | PostgreSQL **verified live**; live Besu indexing **pending P6** |
| 10 | Automated tests for client, gateway, contract, and storage runnable via documented local commands | **Verified** (`106` Rust + `22` live DB + `1` live Cluster + `39` Hardhat + CI) | Local Cluster & PostgreSQL **verified live** |
| 11 | No plaintext/DEK/private-key leaks; production mode refuses test-only key providers | **Verified** (`CustodyStartupPolicy`, `RelayerStartupPolicy`, `rrds-tests`, hygiene checks) | **Verified** |
| 12 | Every module has a short README documenting purpose, interface, and test command | **Verified** (all crates, services, apps, and infra directories have updated READMEs) | **Verified** |
| 13 | Reproducible multi-node setup to run all nodes simultaneously and test workflows | **Verified** (`infra/compose.yaml`, `infra/besu-qbft/`, `infra/compose/*.yaml`, `scripts/demo-local.sh`) | Cluster + PostgreSQL + Besu verified individually; combined live run **pending P6** |

---

## 5. What Remains Right Now

### A. Remaining for Local MVP Sign-Off (**P6 — In Progress**)

1. **Execute the scheduled 24-hour timelock batch (ready `2026-11-27T20:26:20.000Z`):**
   - Already completed (27 Nov 2026) with **dev-only EOA smoke-test placeholders** (git-ignored in `contracts/secrets/besu-dev-accounts.json`):
     - `RrdsTimelockController` deployed at `0x18cd48bbff72acf29bd50f8e98397b1a07eba80f` (block `48149`)
     - `AccessGovernance` deployed at `0xe1304f22747114aafdd0c0c3f8e64b83c5326663` (block `48151`)
     - `FileRegistry` deployed at `0xf27d55447405f702299ed948325cfd9025fbe5cb` (block `48153`)
     - Activation batch (`grantRole(FILE_REGISTRY_ROLE, FileRegistry)` + `registerOrganization(rrds-dev-org-1, orgSafe)`) scheduled at block `48177` (`opId = 0xb05fc2b0d9d0e021d65045c2c1537a5909692e54dcfda06bf0b07c828cf100fc`, `delay = 86400s`)
   - Once ready at `2026-11-27T20:26:20.000Z`, run:
     `node contracts/scripts/besu-bootstrap.mjs execute`
2. **Configure local `.env`, enroll demo member(s) & run live end-to-end verification:**
   - Set `CONTRACT_ACCESS_GOVERNANCE_ADDRESS=0xe1304f22747114aafdd0c0c3f8e64b83c5326663` and `CONTRACT_FILE_REGISTRY_ADDRESS=0xf27d55447405f702299ed948325cfd9025fbe5cb` in local ignored `.env`.
   - Enroll test member(s) from `organizationSafe` with EIP-712 `MemberKeyProof`, start `services/indexer` + `services/gateway` against live Besu + Kubo/Cluster + PostgreSQL, and run [`scripts/demo-local.sh`](scripts/demo-local.sh) plus `indexer --rebuild-projections`.
3. **Replace dev-only EOA placeholders with real Safe smart-account proxies** before any staging/production claim (per [`docs/adr/governance-authority-and-timelock.md`](docs/adr/governance-authority-and-timelock.md) #8).
4. **Reconcile empty `rrfs_dev` schema (diagnosed 27 Nov 2026 — awaiting approval):**
   - Forensic read-only inspection confirmed `rrfs_dev` stores tables in schema `rrfs` (`search_path=rrfs`) with `0` rows across `indexed_contract_events`, `gateway_audit_events`, and `gateway_sessions`, and an earlier pre-commit draft of `0003` (missing `gateway_used_access_nonces`, `0004`, `0005`, `0006`, and role grants). Resetting the empty `rrfs` schema and applying `0001`–`0006` + `init-roles.sql` carries zero data loss once approved; `rrfs_indexer_test` is clean and verified through `0006`. Do not run `docker compose down -v`.

### B. Optional Pre-Merge Repository Cleanup

- Leftover template cleanup (**completed 27 November 2026**): removed `contracts/contracts/Counter.sol`, `contracts/contracts/Counter.t.sol`, `contracts/test/Counter.ts`, `contracts/ignition/modules/Counter.ts`, `contracts/scripts/send-op-tx.ts`, empty `crates/metadata_store/src/migrations/`, and unused root `package.json`; added [`contracts/ignition/parameters.example.json`](contracts/ignition/parameters.example.json) and gitignored `contracts/ignition/*.local.json` and `contracts/ignition/deployments/`.
- Optionally validate per-role templates on host with `for f in infra/compose/*.yaml; do docker compose -f "$f" config --quiet; done`.
- Review and commit the working tree changes on `agent/development` in logical commits before opening a PR / merging.

### C. Post-MVP / Production Readiness (Outside Local MVP Scope, Spec §17)

- Implement hardware-backed `KeyCustodyProvider` and `RelayerSigner` (PKCS#11 / HSM) per chosen consortium HSM topology (§17 #1).
- Add published RFC 9180 HPKE cross-implementation test vectors (`X25519 / HKDF-SHA256 / AES-256-GCM`).
- Deploy behind TLS termination with least-privilege PostgreSQL roles ([`infra/postgres/init-roles.sql`](infra/postgres/init-roles.sql)) and separate physical hosts per [`infra/compose/`](infra/compose/README.md).
- Finalize open operational/governance policies in §17 (member onboarding proof, Safe thresholds, independent replica policy, retention/orphan cleanup age, emergency recovery policy).

---

## 6. Updated Remaining Effort Estimate

- **To reach verified local MVP (§15.4):** **~1–2 days** once maintainer Safe addresses and deployer keystore inputs are ready (contract deployment, timelock activation, live end-to-end demo run, and `rrfs_dev` inspection).
- **To reach production readiness:** Separate milestone covering HSM/PKCS#11 integration, multi-organization independent infrastructure deployment, TLS/secrets management, and external security review.

---

## 7. Chronological Implementation Log (26–27 November 2026)

- **Takeover review & P0 fixes:**
  - Recorded initial engineering review in [`agentic_review.md`](agentic_review.md).
  - Closed the rate-limit bypass on `POST /v1/files/{fileId}/versions/{version}/access`, tightened `access_lookup` encryption-key-version validation, and fixed `CONTRACT_FILE_REGISTRY_ADDRESS` error reporting in `services/gateway`.
  - Consolidated EIP-712 `LoginChallenge` digest hashing into `crates/crypto/src/signing.rs` (tested against `tests/fixtures/eip712-v1.json`).
  - Fixed `services/indexer/src/main.rs` (`EnvelopeSetInitialized` `revision = 1`, `ReadAccessRevoked` invalidating `historical_read_access_projection`, `"0x"` hex prefix in DB test).
  - Added `CustodyStartupPolicy` and `verify_provider_policy` in `crates/key_custody`.
- **P1 domain, ports, crypto & application core:**
  - Extended `crates/domain`, `crates/crypto` (chunk-0 private metadata AEAD, `manifest_hash`, `raw_sha256_cid`), and `crates/ports` (`Clock`, `GatewayAuthPort`, `LedgerPort`).
  - Implemented `crates/application` (`AuthService`, `UploadService` with create/modify/append-only restore + `OrphanedUpload`, `DownloadService`, `ShareService`) with 4 end-to-end workflow tests.
  - Added architecture deep dives under [`docs/architecture/`](docs/architecture/README.md).
- **P2 gateway read routes, HTTP test harness & live two-peer IPFS Cluster verification:**
  - Added `GatewayChainPort` / `GatewayStorePort` and implemented `GET /v1/files/{fileId}/versions/{version}/envelope`, `GET /v1/files`, `GET /v1/files/{fileId}/versions`, and `GET /v1/audit` with real-HTTP Axum tests.
  - Fixed `kubo2` ownership/healthcheck, 1 MiB chunk profile (`chunker=size-1048592`), intermediate `"chunks"` directory handling, Cluster `/pins/{cid}` status polling, and workspace-root secret path resolution in `cluster_integration.rs`.
  - Verified live on host: all 5 Compose services healthy, `sh infra/ipfs-cluster/verify.sh` passed, and `cluster_integration` passed (`1 passed; 0 failed` in 1.66s).
- **P3 transaction relayer, gateway write routes & boundary audit:**
  - Recorded [`docs/adr/chain-adapter-rpc-and-relayer.md`](docs/adr/chain-adapter-rpc-and-relayer.md) and [`crates/chain_adapter/README.md`](crates/chain_adapter/README.md).
  - Implemented ABI encoders (`createFile`, `appendVersion`, `updateEnvelopeSet`), canonical RLP & zero-gas-price EIP-2718 Type-2 transactions, `RelayerSigner` / `RelayerStartupPolicy`, `TransactionRelayer` + `reconcile_transaction`, and JSON-RPC `rpc_nullable` handling.
  - Implemented `POST /v1/files`, `POST /v1/files/{fileId}/versions`, and `POST /v1/files/{fileId}/versions/{version}/envelopes` with EIP-712 checks, stale-head rejection, canonical envelope validation, and pin-before-commit quorum enforcement.
  - Completed crate-boundary and duplication audit ([`docs/architecture/deployment-and-boundaries.md`](docs/architecture/deployment-and-boundaries.md)) and added all missing component READMEs.
- **P4 thin CLI, HTTP gateway client & ciphertext blob staging:**
  - Added canonical `RRDSPKG1` framing in `crates/ports/src/blob_store.rs` and authenticated ciphertext-only staging routes `POST /v1/blobs/{content,envelopes}` in `services/gateway`.
  - Implemented `GatewayHttpClient`, bounded CARv1 CID verifier, and 12 CLI commands (`health`, `login`, `whoami`, `identity`, `ls`, `history`, `upload`, `modify`, `download`, `share`, `restore`, `audit`) in `apps/cli`, verified end-to-end over HTTP.
- **CI workflow & P5 gateway hardening + scanner interface:**
  - Added [`.github/workflows/ci.yml`](.github/workflows/ci.yml) (Rust fmt/Clippy/tests, crate-boundary checks, live PostgreSQL 18.6 integration job, Hardhat contracts, Compose/diff hygiene).
  - Implemented `ports::PreUploadScanner` (`ScannerMode`, default `Disabled`) and `crates/scanner::DisabledScanner`.
  - Added migration `0005_gateway_session_revocation.sql`, `crates/metadata_store/build.rs` (`cargo:rerun-if-changed=migrations`), [`infra/postgres/init-roles.sql`](infra/postgres/init-roles.sql), `DELETE /v1/auth/session`, `X-Request-Id` correlation & JSON operational logging, and multi-budget rate limiting (`src:*`, `member:*`, `invalid_sig_src:*`).
  - Verified all 5 PostgreSQL integration tests (`22 passed; 0 failed` across `metadata-store`, `indexer`, `gateway`) live on host against `rrfs_indexer_test`.
- **P7 cross-component test suites, recovery runbook, demo, per-role Compose templates & design/dev docs:**
  - Added `rrds-tests` ([`tests/Cargo.toml`](tests/Cargo.toml)): 3 end-to-end acceptance tests ([`tests/end_to_end/acceptance.rs`](tests/end_to_end/acceptance.rs)), 5 security invariant tests ([`tests/security/invariants.rs`](tests/security/invariants.rs)), and 1 cross-component signing-to-relayer integration test ([`tests/integration/cross_component.rs`](tests/integration/cross_component.rs)).
  - Added [`docs/runbooks/ransomware-recovery.md`](docs/runbooks/ransomware-recovery.md), [`scripts/demo-local.sh`](scripts/demo-local.sh), production-separated Compose templates under [`infra/compose/`](infra/compose/README.md), [`docs/decisions/README.md`](docs/decisions/README.md), and [`docs/development-notes.md`](docs/development-notes.md).
- **Spec-gap hardening, cross-system integration, gas bounds & repo organization (27 November 2026):**
  - Wired optional `PreUploadScanner` hook into `UploadService` (disabled by default; `Disabled`, `Warn`, and `Enforce` modes verified before any storage/ledger I/O).
  - Hardened `apps/cli`: added `rrds logout` (`DELETE /v1/auth/session`), pre-read regular-file/symlink + size validation (`read_regular_file_bounded`), atomic `0600` + `fsync` + `rename` output writes (`write_file_atomic_restricted`), and deduplicated `build_upload_service` with `DisabledScanner`.
  - Added multi-peer Kubo upload failover in `crates/ipfs_adapter` (`select_healthy_kubo_url` for streaming `put_content` + per-peer retry for `put_envelope_set`) with 2 mock-HTTP failover tests.
  - Added official RFC 9180 Base mode + independent OpenSSL (`node:crypto`) -> Rust cross-implementation HPKE test vectors ([`tests/fixtures/hpke-rfc9180-v1.json`](tests/fixtures/hpke-rfc9180-v1.json)).
  - Deduplicated `eth_call_bool` in `crates/chain_adapter` and added mock-RPC tests for `file_head_at`, `has_read_access`, `file_version`, and `current_envelope_set`.
  - Added `register-member` (EIP-712 `MemberKeyProof` + RFC 9180 X25519 derivation) to [`contracts/scripts/besu-bootstrap.mjs`](contracts/scripts/besu-bootstrap.mjs) and §7.9 contract gas-bound verification ([`contracts/test/GasBounds.ts`](contracts/test/GasBounds.ts); `35` Hardhat tests passing).
  - Added missing §11 schemas ([`schemas/access-request-v1.json`](schemas/access-request-v1.json), [`schemas/version-manifest-v1.json`](schemas/version-manifest-v1.json)), consolidated [`docs/threat-model.md`](docs/threat-model.md) and [`docs/contract-api.md`](docs/contract-api.md), relocated `TECHNICAL_SPECIFICATION.md` into [`docs/specifications/TECHNICAL_SPECIFICATION.md`](docs/specifications/TECHNICAL_SPECIFICATION.md) (removing empty `docs/source/`), and added a 6-crate cross-system integration test (`application` + `scanner` + `key_custody` + `ipfs_adapter` failover + `chain_adapter` Type-2 relayer) plus schema/fixture contract checks in [`tests/integration/cross_component.rs`](tests/integration/cross_component.rs).
  - Verified full offline workspace suite (**118 passed, 0 failed**), strict Clippy (`-D warnings`), `cargo fmt --check`, Hardhat (**35 passing**), `sh -n scripts/demo-local.sh`, `node --check contracts/scripts/besu-bootstrap.mjs`, and `git diff --check`.
- **Independent PostgreSQL audit, hardening & production-grade DB tests (27 November 2026):**
  - Fixed [`infra/postgres/init-roles.sql`](infra/postgres/init-roles.sql) (`indexed_contract_events` instead of non-existent `chain_events`, added `organizations_projection`, `indexer_projection_chain`, read-only `_sqlx_migrations`, optional `rrfs_audit_reader`, and schema-aware `current_schema()`).
  - Added additive migration `0006_postgres_hardening_indexes_and_audit_guard.sql` (`BEFORE TRUNCATE` audit guard + indexes for member audit queries, folder listings, event replay cursor pagination, and session expiry pruning).
  - Added `MigrationMode` (`verify` default, `run`, `off`) and `PostgresPoolConfig` (`DATABASE_MAX_CONNECTIONS`, `DATABASE_ACQUIRE_TIMEOUT_SECONDS`) to `crates/metadata_store` and wired both into `services/gateway` and `services/indexer` so least-privilege runtime roles validate schema integrity without DDL permissions.
  - Fixed negative-token rate-limit debt in `services/gateway/src/store.rs` (`FOR UPDATE` row-locked token bucket clamping at `0.0`) and added bounded expired challenge & session pruning.
  - Added production PostgreSQL tests & CI RBAC enforcement ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)): live `init-roles.sql` execution + real `rrfs_gateway`/`rrfs_indexer` privilege tests, `UPDATE`/`DELETE`/`TRUNCATE` audit rejection, burst rate-limit recovery, 8-way concurrent challenge/nonce/rate-limit/audit-chain race tests, live projection query tests (`list_files_and_folders`, `list_file_versions`, `query_member_audit_events`), and indexer `ReadAccessRevoked`/reindex-reset tests (**28 passed, 0 failed** live on `rrfs_indexer_test`; **124 passed, 0 failed** offline workspace).
