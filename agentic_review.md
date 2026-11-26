# Agentic Engineering Review

## 1. Review Snapshot

- **Review date:** 26 November 2026
- **Repository:** `ransomware-resistant-sharing`
- **Branch:** `agent/development` (tracking `origin/agent/development`, ahead by 1 commit at review start)
- **Reviewed HEAD commit:** `2c21e10625beead86f63035c2976a412f2f9f3f4` (`more notes`)
- **Last implementation commit:** `01e361fd0de2d5ca56d48e03834e0bdc608351ae` (`Remove internal flag from rrfs-private so loopback ports publish`, 12 Nov 2026) and `8d40896` (`Continue implementation and verify local infrastructure`, 12 Nov 2026)
- **Canonical baseline:** [`TECHNICAL_SPECIFICATION.md`](TECHNICAL_SPECIFICATION.md) (RRDS-TS-001 v1.0) and ADRs under [`docs/adr/`](docs/adr/)
- **Maintainer review baseline:** [`manual_review.md`](manual_review.md) (24 Nov 2026)

---

## 2. Component Map & Intended Deployment Placement

A key concern raised in `manual_review.md` (#5, #7, #10) is why logic is split between `crates/` and `services/` and where each folder runs in production.

**Why `crates/` vs `services/` exists:**
- `crates/` holds **reusable Rust libraries** (domain types, cryptographic primitives, port traits, and protocol adapters) that are compiled into one or more binaries without creating dependency cycles (`TECHNICAL_SPECIFICATION.md` §§11–12).
- `apps/` holds **endpoint-facing user binaries** (currently `apps/cli`; future `apps/desktop`).
- `services/` holds **independently deployed server binaries** (`services/gateway`, `services/indexer`).
- `contracts/` holds **on-chain EVM smart contracts** and Hardhat tests/deployment modules.
- `infra/` holds **infrastructure orchestration** (Besu QBFT, Kubo/IPFS Cluster, PostgreSQL).

| Path | Component | Responsibility | Intended Production Placement | Current Implementation State |
| --- | --- | --- | --- | --- |
| `apps/cli` | CLI binary (`rrds`) | Thin user interface calling `crates/application` / Gateway HTTPS API | **User / Client Endpoint** | Minimal (`health` command only) |
| `crates/domain` | Domain library | Pure typed IDs, errors, version graph invariants (no I/O) | Shared library (Client Endpoint + Gateway + Indexer) | Partial (IDs, `DomainError`, `VersionGraph`; missing `FolderId`, `FileMetadata`, `MemberIdentity`, `AccessPolicy`, `AuditEvent`) |
| `crates/application` | Application use-case core | Workflow orchestration (auth, upload, download, modify, share, revoke, history, recover) | **User / Client Endpoint** (and reusable service boundaries) | **Empty stub** (1-line file) |
| `crates/crypto` | Cryptography & formats | AES-256-GCM chunking, RFC 9180 HPKE DEK wrapping, canonical manifest & envelope-set codecs, EIP-712 digests | **User / Client Endpoint** (encrypt/decrypt/wrap/sign) & **Gateway** (signature/digest verification only — never plaintext/DEKs) | Strong foundation; missing `LoginChallenge` digest (duplicated in gateway), chunk-0 private-metadata encrypt/decrypt helpers, and published RFC 9180 HPKE vectors |
| `crates/key_custody` | Key custody adapters | `KeyCustodyProvider` implementations (signing & DEK unwrap) | **User / Client Endpoint** (member HSM/token) and **Org Gateway/Relayer host** (separate relayer custody) | Software-only `DevelopmentKeyCustody`; no production startup guard or PKCS#11/HSM adapter |
| `crates/ports` | Hexagonal port traits | Async traits (`KeyCustodyProvider`, `BlobStore`, planned `LedgerPort`, `Clock`, `Scanner`, gateway/query ports) | Shared interface library | Partial (`KeyCustodyProvider` and `BlobStore` only) |
| `crates/scanner` | Local plaintext anomaly/malware scanner | Optional best-effort defense-in-depth local scanning prior to encryption | **User / Client Endpoint** (before encryption; disabled by default) | **Empty stub** (1-line file) |
| `crates/ipfs_adapter` | Kubo & IPFS Cluster adapter | Implements `BlobStore`: deterministic UnixFS upload, Cluster pin quorum wait, root block CID verification, failover retrieval | **Organization Gateway / Storage Adapter Server** (must not expose Kubo admin APIs to endpoints) | Implemented; offline tests pass; live 2-peer integration test is `#[ignore]` |
| `crates/chain_adapter` | Besu JSON-RPC client | Read-only `eth_call`, `eth_getLogs`, QBFT committed head queries | **Organization Gateway Server** & **Indexer Server** | Read-only queries implemented via hand-rolled `reqwest` JSON-RPC + manual ABI; **no transaction signing/relay/receipt tracking**; deviates from spec §3 Alloy requirement without an ADR |
| `crates/metadata_store` | PostgreSQL pool & migrations | SQLx `PgPool` wrapper and versioned SQL migrations (`0001`–`0004`) | **Organization Gateway Server** & **Indexer Server** | Thin 48-line wrapper; all SQL queries currently live inside `services/gateway/src/store.rs` and `services/indexer/src/main.rs` |
| `services/gateway` | Authenticated HTTP API & relayer | Challenge/session auth, rate limiting, authoritative `eth_call` checks, hash-chained audit logging, ciphertext streaming, tx relay | **Organization Gateway Server** (independent of endpoints and validators) | Partial (health, public identity, login challenge/session, signed access lookup, ciphertext CAR stream); missing listings, history, upload/create/append, envelope update, ACL/governance, audit query, and relayer |
| `services/indexer` | Finalized-event projector | Polls QBFT-committed logs, stores raw events + checkpoints atomically, builds searchable PostgreSQL projections, reconciles file heads | **Organization Server** (co-located with PostgreSQL + trusted Besu RPC; see Indexing Placement note below) | Implemented with `--rebuild-projections` and `--reindex-from-chain`; contains projection bugs (see §4) and DB tests are currently unverified |
| `contracts/` | Solidity contracts & Hardhat suite | `AccessGovernance.sol`, `FileRegistry.sol`, `RrdsTimelockController.sol`, `RrdsCid.sol`, `RrdsEip712.sol`, Ignition deployment | **Consortium Besu QBFT Blockchain** (deployed once per network) | Core contracts implemented and locally tested; not yet deployed to Besu or integrated with real Safe accounts |
| `infra/besu-qbft/` | Besu QBFT Compose stack | 4 validators + 1 separate non-validator RPC node (`127.0.0.1:8545`) | **Consortium Validator & RPC Infrastructure** (each validator on an independent org host in production) | Local dev stack configured; previously verified on 12 Nov 2026; not re-verified in this sandbox |
| `infra/compose.yaml` + `infra/ipfs-cluster/` | Dev PostgreSQL + 2-peer Kubo/Cluster | Private-swarm Kubo 0.43.1 (×2), CRDT Cluster 1.1.6 (×2), PostgreSQL 18.6 | **Storage Peer Nodes** (IPFS/Cluster per org) & **Organization DB Server** (PostgreSQL) — combined only for dev | Local 2-peer replication fixed & verified 12 Nov 2026; PostgreSQL host connectivity and `rrfs_dev` migration 3 mismatch remain open |

### Deployment Note on Indexing Placement (`manual_review.md` #11)

`manual_review.md` asks whether indexing can run on the user endpoint to reduce gateway latency. Based on `TECHNICAL_SPECIFICATION.md` §§2, 4, 7.6, 7.12, and 10.4.7:
- **Recommendation: keep canonical event indexing on the organization server (`services/indexer` + PostgreSQL), and optionally add a non-authoritative client-side cache with `finalizedBlock` cursors if UI browsing latency becomes noticeable.**
- **Reasons:**
  1. **Trust & network boundary:** Endpoint-side indexing requires exposing Besu JSON-RPC (`eth_getLogs`) directly to untrusted endpoints, breaking §4/§7.6 where endpoints talk only to the authenticated gateway over HTTPS.
  2. **Consortium metadata exposure:** Full chain-log syncing would pull all organizations' on-chain file/folder/ACL events onto every endpoint.
  3. **Operational overhead:** Each endpoint would have to maintain a persistent database, handle chain checkpoints, and pay cold-start sync latency.
  4. **Latency profile:** Gateway-served SQL queries against a co-located organization PostgreSQL projection are sub-millisecond and already avoid QBFT/RPC round trips for browsing/history.

---

## 3. Strengths & Gaps Against `TECHNICAL_SPECIFICATION.md`

### Strengths
- **Cryptography core (`crates/crypto`):** Clean, zeroizing AES-256-GCM chunk encryptor/decryptor with non-reusable `prefix64-index32` nonces and full context-bound AAD (`fileId`, `versionNumber`, `epochId`, `chunkIndex`, `totalChunks`). RFC 9180 HPKE (`X25519` + `HKDF-SHA256` + `AES-256-GCM`) with context binding. Strict canonical JSON codecs + JSON Schemas for manifests (`schemas/encrypted-file-manifest-v1.json`) and envelope sets (`schemas/key-envelope-set-v1.json`, max 1,024 sorted unique members).
- **Cross-language EIP-712 parity:** Rust (`crates/crypto`, `services/gateway`), Solidity (`RrdsEip712.sol`), and TypeScript (`viem` in `contracts/test/Eip712.ts`) all match shared deterministic digest fixtures in `tests/fixtures/eip712-v1.json`.
- **Smart contract separation & governance design:** Clean split between `AccessGovernance.sol` and `FileRegistry.sol`, atomic file creation + initial creator Read/Write ACL + initial envelope pointer, version-scoped historical Read ACL with revocation epoch invalidation, signing-key EIP-712 proof-of-possession, immutable folder parents, and `RrdsTimelockController` (24-hour delay, open executor, no deployer admin bypass). `AccessGovernance` bytecode (17,229 bytes) stays well under EIP-170 (24,576 bytes).
- **Fail-closed read audit & QBFT finality alignment:** Gateway access lookup and content retrieval query a single recorded QBFT-committed block number (`latest` head, not PoS `finalized`) and commit an append-only Keccak-256 hash-chained PostgreSQL audit row before returning CIDs or streaming ciphertext.

### Major Gaps Against Specification
1. **Application core (`crates/application`) is empty:** None of the §9 workflows (auth, upload, download, modify, share, revoke, history, restore/revert) exist yet.
2. **Transaction relayer (`chain_adapter` + `services/gateway`) is unimplemented:** No Ethereum transaction signing, relayer nonce management, gas estimation/limits, `eth_sendRawTransaction`, receipt/finality polling, or timeout reconciliation (§§7.7–7.13).
3. **Missing Gateway API endpoints (§8.1):**
   - `GET /v1/files?folderId=...` (file/folder listings with finalized block cursor)
   - `POST /v1/files` (create file + initial version)
   - `POST /v1/files/{fileId}/versions` (append/modify/restore version with ciphertext upload + pin quorum + relayed tx)
   - `GET /v1/files/{fileId}/versions` (version history)
   - `GET /v1/files/{fileId}/versions/{version}/envelope` (or envelope retrieval route for authorized downloads — currently only `/content` CAR streaming exists, no authorized envelope-set download route!)
   - `POST /v1/files/{fileId}/versions/{version}/envelopes` (envelope-set upload/update)
   - `POST /v1/files/{fileId}/acl/proposals` / governed share & revoke integration
   - `GET /v1/audit` (access-controlled, self-audited audit query endpoint)
4. **Gateway hardening gaps (§8, §10.4.6, §14):** No per-member/per-org/resource-consumption rate-limit budgets (only per-source-IP), no session revocation, no request/correlation IDs, no PostgreSQL role separation (`rrfs_gateway` vs `rrfs_indexer` vs audit reader), no TLS termination config, and no structured `tracing` JSON logging (uses `eprintln!`).
5. **CLI (`apps/cli`) only implements `health`:** Missing all Phase 5 commands and `clap` CLI structure.
6. **Key custody production guard & hardware adapter (`crates/key_custody`):** Missing the mandatory non-development startup check rejecting `test_only` / exportable providers (§3, §13, §15.4 #11) and any PKCS#11/HSM adapter.
7. **Scanner (`crates/scanner`) is empty:** Disabled-by-default stub trait and policy hook not yet wired.
8. **Missing schemas & fixtures (§11, §15.1):** `schemas/access-request-v1.json` and `schemas/version-manifest-v1.json` do not exist; published/cross-implementation RFC 9180 HPKE test vectors are missing.
9. **Deployment & End-to-End Acceptance (§15.3–§15.4):** Contracts are not deployed to local Besu, real Safe/timelock activation is unverified, PostgreSQL integration tests are unverified in the current environment, and `tests/{integration,end_to_end,security}/` are empty.

---

## 4. Concrete Issues, Bugs, Risks & Duplication Findings

### Bugs & Security Issues Found in Existing Code
1. **[HIGH — Security] Un-rate-limited `POST /v1/files/{file_id}/versions/{version}/access` route:**
   In `services/gateway/src/routes.rs` (`enforce_rate_limit`, lines 1475–1483), the path matcher covers `/v1/identities/`, `/v1/auth/challenge`, `/v1/auth/session`, and `/v1/files/.../content`, but omits `/v1/files/.../access`. Requests to `access_lookup` hit the wildcard `_ => return next.run(request).await` and completely bypass PostgreSQL rate limiting.
2. **[MEDIUM — Correctness] Indexer projects initial envelope-set revision as `0` instead of `1`:**
   In `contracts/contracts/AccessGovernance.sol` (`initializeEnvelopeSet`, line 545), `pointer.revision` is initialized to `1`. Both `crates/crypto/src/envelope_set.rs` (line 115) and `crates/chain_adapter/src/lib.rs` (line 573) reject revision `0`. However, `services/indexer/src/main.rs` (`project_event_inner`, lines 1026–1041) inserts `revision = 0` on `EnvelopeSetInitialized`, causing projected revision drift from contract state.
3. **[MEDIUM — Correctness / Security Consistency] Indexer does not clear historical read grants on `ReadAccessRevoked`:**
   In `contracts/contracts/AccessGovernance.sol` (`setFilePermission`, lines 461–463), revoking file-level Read increments `readPermissionEpochs[fileId][memberId]`, invalidating all prior historical grants without emitting per-version revoke events. In `services/indexer/src/main.rs` (`project_event_inner`, lines 984–1004), `ReadAccessRevoked` updates `access_projection` only and leaves `historical_read_access_projection.granted = TRUE`. If Read is later re-granted, the projection falsely shows stale historical grants as active (contradicting `docs/adr/version-scoped-historical-read-access.md`).
4. **[MEDIUM — Broken Dormant Test] Indexer DB test omits `"0x"` prefix on hex data:**
   In `services/indexer/src/main.rs` (`tests::event_replay_is_idempotent_and_projection_rebuild_is_atomic`, lines 1275–1286), `historical_read_granted` passes ABI data without a `"0x"` prefix. Because `chain_adapter::decode_hex` requires `"0x"`, this test will fail immediately whenever `DATABASE_URL` is configured. It went undetected because PostgreSQL tests silently return early when `DATABASE_URL` is unset.
5. **[LOW — Defense-in-Depth] Fail-open fallback in `access_lookup` key version check:**
   In `services/gateway/src/routes.rs` (line 819):
   `key_version != KeyVersion::new(member.encryption_key_version).unwrap_or(key_version)`
   If `member.encryption_key_version` were ever `0`, `.unwrap_or(key_version)` would evaluate equal (fail open) rather than rejecting. Should compare `key_version.get() != member.encryption_key_version`.
6. **[LOW — Diagnostics] Copy-pasted error messages in gateway config:**
   In `services/gateway/src/config.rs` (`parse_address`, lines 96–114), validation errors for `CONTRACT_FILE_REGISTRY_ADDRESS` print `"CONTRACT_ACCESS_GOVERNANCE_ADDRESS ..."`.
7. **[LOW — Redundant check] Duplicate condition in `FileRegistry.sol`:**
   In `contracts/contracts/FileRegistry.sol` (`createFolder`, lines 242 and 245), `files[folderId].status != FileStatus.Unregistered` is checked twice consecutively.
8. **[MEDIUM — Missing ADR / Spec Deviation] Hand-rolled JSON-RPC & ABI instead of Alloy:**
   `TECHNICAL_SPECIFICATION.md` §3 specifies the **Alloy Rust ecosystem** for EVM RPC, contract bindings, and EIP-712. `crates/chain_adapter/src/lib.rs` instead uses `reqwest` + manual Keccak selectors and manual byte-offset ABI decoding without an ADR documenting the deviation. Before adding raw transaction signing and ABI encoding for relayer calls, either adopt Alloy (preferred per §3) or record an ADR justifying the lightweight client.
9. **[LOW — Partial Spec Feature] Private metadata (chunk 0) encrypt/decrypt missing:**
   `crates/crypto/src/manifest.rs` defines `PrivateMetadataCiphertext` at `nonceIndex = 0`, and `NoncePrefix::for_chunk_index(0)` is reserved, but `crates/crypto/src/encryption.rs` only encrypts/decrypts chunks `1..=N` and exposes no chunk-0 private metadata AEAD helper.
10. **[LOW — Operational] `IpfsClusterStore::put_content` does not fail over across configured Kubo nodes on upload:**
    `crates/ipfs_adapter/src/lib.rs` (`add`, line 164) only uses `self.kubo_api_urls.first()`, whereas retrieval (`open_reader`) iterates through all configured Kubo endpoints.

### Duplication & Interdependency Observations (`manual_review.md` #8)
- **EIP-712 & hex encoding duplicated across 6 files:**
  `struct_hash`, `uint_word_u64`, `uint_word_u32`, `address_word`, `keccak`, and hex codecs are copy-pasted across `crates/crypto/src/signing.rs`, `services/gateway/src/auth.rs`, `services/gateway/src/store.rs`, `crates/chain_adapter/src/lib.rs`, `services/indexer/src/main.rs`, and `services/indexer/src/decoder.rs`. Crucially, `LoginChallenge` EIP-712 hashing lives only inside `services/gateway/src/auth.rs`, preventing client code (`crates/application` / `apps/cli`) from sharing it without duplication.
- **No `LedgerPort` abstraction between `services/gateway` and `crates/chain_adapter`:**
  `services/gateway/src/routes.rs` directly imports and calls concrete `BesuClient` methods and `GatewayStore` SQL helpers, preventing unit testing of gateway route handlers with mock ledger/store implementations.
- **Service SQL coupled inside service binaries rather than `crates/metadata_store`:**
  `crates/metadata_store` owns the SQL migrations (`migrations/0001`–`0004`), while `services/gateway/src/store.rs` and `services/indexer/src/main.rs` embed raw SQL against those tables directly. Schema changes require coordinated edits across all three crates.
- **Documentation & infrastructure drift:**
  - `infra/ipfs-cluster/README.md` still states the Compose Docker network is `internal` and contains contradictory older status paragraphs claiming `PIN_ERROR` before the bottom update confirming replication passed.
  - `README.md` mixes outdated status notes (e.g., line 138 claiming local replication remains unverified) with later takeover notes (lines 317–322 confirming replication passed).
  - `docs/api.md` line 71 refers to Besu's `finalized` state rather than QBFT committed head.
  - `crates/metadata_store/src/migrations/` is an empty leftover directory alongside the real `crates/metadata_store/migrations/`.
  - `contracts/` still includes Hardhat template files (`Counter.sol`, `Counter.t.sol`, `test/Counter.ts`, `ignition/modules/Counter.ts`, `scripts/send-op-tx.ts`).
  - Root `package.json` is an unused npm boilerplate file; real JS dependencies live in `contracts/package.json`.

---

## 5. Test Coverage Quality & Verification Status

### Verified in This Review Session (26 November 2026)

| Suite / Command | Result | Details & Caveats |
| --- | --- | --- |
| `cargo fmt --all -- --check` | **PASSED** | Clean formatting across workspace |
| `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` | **PASSED** | Zero warnings |
| `git diff --check` | **PASSED** | Clean whitespace/EOF checks |
| `cargo test --workspace --all-targets --locked --offline` | **PASSED (69 executed, 5 DB skipped, 1 ignored)** | Cargo reports `74 passed; 0 failed; 1 ignored`, but **5 PostgreSQL tests returned early without executing assertions** because `DATABASE_URL` was unset (`gateway::store::tests`, 3 `indexer::tests`, 1 `metadata_store::postgres_connection`). `ipfs_adapter::cluster_integration` is `#[ignore]`. |
| `cd contracts && XDG_CONFIG_HOME=/tmp/hh-config XDG_CACHE_HOME=/tmp/hh-cache XDG_DATA_HOME=/tmp/hh-data pnpm exec hardhat test --no-compile` | **PASSED (39 passing: 32 Solidity, 7 Node.js)** | Executed against checked-in compiled artifacts (`solc 0.8.34`). Includes 5 leftover `Counter` template tests (3 Solidity, 2 Node.js), so **34 RRDS tests** (29 Solidity, 5 Node.js EIP-712 vector checks). Fresh recompilation in this sandbox failed (`HHE905`) due to no network/external `~/.cache` access. |

### Unverified / Environment-Dependent Items
- **PostgreSQL integration tests (`metadata_store`, `indexer`, `gateway::store`):** Not run in this session (`DATABASE_URL` unset / no sandbox network access). Additionally, `rrfs_dev` has an unresolved SQLx migration 3 checksum mismatch (`VersionMismatch(3)`) documented in `docs/adr/local-integration-verification.md`; `rrfs_indexer_test` exists for clean verification once reachable.
- **Live two-peer IPFS Cluster integration test (`crates/ipfs_adapter/tests/cluster_integration.rs`):** Not run (`#[ignore]`). Previous session on 12 Nov 2026 recorded `sh infra/ipfs-cluster/verify.sh` passing after the Kubo 0.43.1 LAN DHT + `Provide.DHT.SweepEnabled=false` fix, but Rust `cluster_integration` itself remains unverified against host loopback ports.
- **Live Besu QBFT deployment, Safe multisig, and timelock activation:** Not run. Local Besu chain health (chain ID 1337, 4 validators, committed block 969) was recorded on 12 Nov 2026, but `RrdsDeployment.ts` has never been deployed to Besu because approved `consortiumSafeAddress`, `emergencySafeAddress`, and Hardhat keystore deployer key are maintainer-owned inputs.

### Test Quality Critique (`manual_review.md` #2)
- **Strong areas:** `crates/crypto` (26 tests covering chunk boundaries, bit flips, context transplant, reordering, missing chunks, HPKE negative cases, canonical JSON/base64url strictness, 1,024-entry boundary, EIP-712 vectors) and `contracts/` (29 Solidity tests covering ACL isolation, historical epochs, key proof-of-possession, timelock delay, stale heads, CID validation, folder org isolation).
- **Weak areas:**
  - `services/gateway/src/routes.rs` has **zero HTTP handler tests** — only 3 struct serde tests. None of the auth, rate-limit, access-lookup, or content-stream HTTP flows are tested via Axum `tower::ServiceExt::oneshot`, which is why the missing rate limit on `/access` was never caught.
  - `crates/application` and `crates/scanner` have **0 tests** (empty stubs).
  - `crates/chain_adapter` tests cover `finalized_block`, `file_head`, `active_member_signer`, `member_identity`, `has_historical_read_access`, and `logs`, but do **not** test `file_head_at`, `has_read_access`, `file_version`, or `current_envelope_set`!
  - `crates/ipfs_adapter` unit tests do not cover `put_content` end-to-end streaming or `verify_retrievable` error paths.
  - Silent early-return DB tests (`if DATABASE_URL is unset { return; }`) inflate reported pass counts and masked the `"0x"` bug in `indexer::tests`.

---

## 6. Prioritized Development Backlog

| Priority | Work Item | Dependencies | Status (26 Nov 2026) | Can Run Offline / Without Manual Blockers? |
| --- | --- | --- | --- | --- |
| **P0 (Immediate)** | Fix audited security & correctness bugs: gateway `/access` rate-limit gap, `access_lookup` key-version check, `config.rs` error text; indexer `EnvelopeSetInitialized` revision (`1`), `ReadAccessRevoked` historical invalidation, broken `"0x"` DB test; deduplicate `LoginChallenge` EIP-712 into `crates/crypto` and add `KeyCustodyProvider` production startup guard | None | **Completed** (verified offline; indexer DB test remains pending PostgreSQL connectivity) | **Yes** |
| **P1 (Next — Core MVP)** | Build `crates/domain` (missing core models), `crates/ports` (`Clock`, `GatewayAuthPort`, `LedgerPort`), `crates/crypto` (chunk-0 private metadata + manifest hash & raw CID helpers), and `crates/application` core workflows (`auth`, `upload`/`modify`/`restore`, `download`, `share`) with full in-memory workflow & negative security tests | P0 | **Completed** (`application` 4 workflow suites passing offline) | **Yes** |
| **P2** | Add gateway HTTP route tests (via trait-abstracted `GatewayChainPort` + `GatewayStorePort`), add envelope-set retrieval route (`GET /v1/files/{fileId}/versions/{version}/envelope`), file/folder listing (`GET /v1/files`), version history (`GET /v1/files/{fileId}/versions`), and access-controlled audit query (`GET /v1/audit`) | P1 | **Completed** (verified offline via real Axum HTTP test suite; live DB SQL paths remain pending PostgreSQL connectivity) | **Yes** |
| **P3** | Decide Alloy vs manual RPC/ABI via ADR and implement transaction relayer (`chain_adapter` + `services/gateway`): relayer key custody, nonce management, gas limits, `eth_sendRawTransaction`, receipt/finality tracking, timeout reconciliation; wire `POST /v1/files`, `POST /v1/files/{fileId}/versions`, and `POST /v1/files/{fileId}/versions/{version}/envelopes` | P1, P2 | **Completed** (ADR + relayer + gateway write routes verified via unit & real-HTTP Axum tests) | **Yes** |
| **P4** | Expand `apps/cli` (`clap` subcommands calling `crates/application`): `login`, `identity`, `ls`, `upload`, `download`, `modify`, `history`, `share`, `restore`, `audit` + ciphertext blob staging | P1, P2, P3 | **Completed** (12 CLI commands + `GatewayHttpClient` + `RRDSPKG1` staging + CARv1 verifier HTTP-tested) | **Yes** |
| **P5** | Add gateway hardening: multi-budget rate limiting (source/member/invalid-sig), session revocation, correlation IDs, structured JSON logs, PostgreSQL role separation (`rrfs_gateway`, `rrfs_indexer`, audit reader), `crates/scanner` interface + disabled default + CI workflow | P2, P3 | **Completed** (verified offline & live on host against PostgreSQL `rrfs_indexer_test`) | **Yes** |
| **P6 (Maintainer-gated)** | Run PostgreSQL integration tests against `rrfs_indexer_test` and resolve `rrfs_dev` migration 3 mismatch; run live Rust `cluster_integration` test; deploy contracts to local Besu with approved Safe addresses + keystore key and execute 24h timelock activation | Maintainer Safe inputs + Besu deployment | **Partially completed** (`rrfs_indexer_test` & live 2-peer `cluster_integration` verified on host; Besu contract/Safe deployment & `rrfs_dev` review remain maintainer-gated) | **Blocked on maintainer inputs** |
| **P7** | End-to-end acceptance/security/integration suites (`tests/`), recovery runbook (`docs/runbooks/ransomware-recovery.md`), scripted demo (`scripts/demo-local.sh`), production-separated Compose templates (`infra/compose/`), design decisions & development notes | P3–P5 | **Completed** (offline suites & deliverables verified; live-Besu run awaits P6) | **Yes** (live-Besu run awaits P6) |

### Incremental Changes Completed After Initial Review (26 November 2026)

- **P0 fixes verified:**
  - `services/gateway/src/routes.rs`: added `/v1/files/{fileId}/versions/{version}/access` (`file.access`) to `rate_limit_action` / `enforce_rate_limit` with unit test coverage for all routes; tightened `access_lookup` key-version check to `key_version.get() != member.encryption_key_version`.
  - `services/gateway/src/config.rs`: parameterized `parse_address` with the env var name + unit test.
  - `services/gateway/src/auth.rs` & `crates/crypto/src/signing.rs`: moved `Eip712Domain::gateway` and `LoginChallengeDigestInput` into `crates/crypto`, eliminating duplicated EIP-712 encoding in gateway and verifying against `tests/fixtures/eip712-v1.json`.
  - `services/indexer/src/main.rs`: corrected `EnvelopeSetInitialized` initial revision from `0` to `1`; added `historical_read_access_projection` invalidation on `ReadAccessRevoked`; fixed missing `"0x"` prefix in `event_replay_is_idempotent_and_projection_rebuild_is_atomic`.
  - `crates/key_custody/src/lib.rs`: added `CustodyStartupPolicy` and `verify_provider_policy` rejecting test-only/exportable providers outside explicit unsafe development mode, with unit tests.
- **P1 core application & ports verified:**
  - `crates/domain`: added `FolderId`, `MemberStatus`, `FileStatus`, `PublicMemberIdentity`, `FileMetadata`, `AccessReference`, `LoginChallenge`, `TransactionReceipt`.
  - `crates/crypto`: added chunk-0 `encrypt_private_metadata` / `decrypt_private_metadata`, `EncryptedFileManifest::manifest_hash`, `raw_sha256_cid`, and `EncryptedChunk::from_parts`.
  - `crates/ports`: added `Clock` / `SystemClock`, `AuthenticatedSession`, `HeadState`, `GatewayAuthPort`, and `LedgerPort`.
  - `crates/application`: implemented `AuthService`, `UploadService` (create, modify, append-only restore, `OrphanedUpload`), `DownloadService` (signed lookup, envelope/manifest/chunk CID + AES-GCM verification), and `ShareService` (envelope-set update without re-encrypting ciphertext), verified by 4 end-to-end in-memory workflow tests.
- **Documentation (`manual_review.md` #1):** created `docs/architecture/{README,authentication-and-challenge,historical-access,recovery-and-revocation}.md` and updated `crates/{application,key_custody,ports}/README.md`.
- **P2 gateway ports, read routes, HTTP tests & Cluster test fix verified:**
  - `crates/ipfs_adapter/tests/cluster_integration.rs`: fixed relative `IPFS_CLUSTER_PASSWORD_FILE` resolution against the workspace root (Cargo runs integration tests with CWD `crates/ipfs_adapter/`) and added clear non-secret env var diagnostics; updated `infra/ipfs-cluster/README.md`. Live execution remains blocked on starting Windows Docker Desktop (`dockerDesktopLinuxEngine` pipe absent).
  - `services/gateway/src/ports.rs`: added `GatewayChainPort` and `GatewayStorePort` traits (implemented for `BesuClient` and `GatewayStore`).
  - `services/gateway/src/{store.rs,routes.rs}`: added `GET /v1/files/{fileId}/versions/{version}/envelope` (with canonical `KeyEnvelopeSet` + recipient key-version validation and fail-closed audit), `GET /v1/files` (indexer-backed listing with `finalizedBlock` / `indexedBlock` cursors and `authoritative: false`), `GET /v1/files/{fileId}/versions` (authoritative Read ACL check + projected version history), and `GET /v1/audit` (self-audited member audit query), all wired into `rate_limit_action`.
  - `services/gateway/src/routes.rs`: added real-HTTP Axum end-to-end test (`http_tests::gateway_end_to_end_auth_access_content_envelope_listing_history_and_audit`) covering login, replay rejection, public identity, signed access lookup, historical grants, content & envelope retrieval, listings, version history, self-audited audit queries, fail-closed audit errors (503), and `/access` rate limiting (429).
  - Updated `docs/api.md` and `services/gateway/README.md`.
- **Live two-peer IPFS Cluster & Rust `ipfs-adapter` integration verified (26 Nov 2026):**
  - Fixed `infra/ipfs-cluster/start-kubo.sh` (`chown -R ipfs /data/ipfs`, `gosu ipfs` bootstrap query) and `infra/compose.yaml` (HTTP API healthcheck as `ipfs` instead of root datastore `ipfs id`).
  - Fixed 3 live Kubo `0.43.1` / Cluster `1.1.6` protocol bugs in `crates/ipfs_adapter/src/lib.rs`, `crates/crypto`, `schemas/encrypted-file-manifest-v1.json`, and `docs/adr/content-package-unixfs-profile.md`: 1 MiB chunk profile (`size-1048592` under Kubo's `2,096,896`-byte max), intermediate `"chunks"` directory handling on `wrap-with-directory=true`, and Cluster `GET /pins/{cid}` status polling.
  - Verified live on host: `sh infra/ipfs-cluster/verify.sh` passed (`PINNED` on both peers, 0 attempts) and `cargo test -p ipfs-adapter --locked --test cluster_integration -- --ignored` passed (`1 passed; 0 failed` in 1.66s).
- **Live PostgreSQL (`rrfs_indexer_test`) verified (26 Nov 2026):** Granted `rrfs_migrator` privileges on `rrfs_indexer_test` (leaving `rrfs_dev` untouched) and verified all 5 PostgreSQL integration tests across `metadata-store`, `indexer`, and `gateway` (`20 passed; 0 failed` on host).
- **P3 transaction relayer & gateway write routes verified (26 Nov 2026):**
  - Added [`docs/adr/chain-adapter-rpc-and-relayer.md`](docs/adr/chain-adapter-rpc-and-relayer.md) and [`crates/chain_adapter/README.md`](crates/chain_adapter/README.md).
  - `crates/chain_adapter`: added `BesuClient::has_write_access`, `pending_nonce`, `estimate_gas`, `send_raw_transaction`, `transaction_receipt` (with JSON-RPC 2.0 `rpc_nullable` handling for pending `null` receipts), Solidity ABI calldata encoders (`encode_create_file_calldata`, `encode_append_version_calldata`, `encode_update_envelope_set_calldata`), canonical RLP & EIP-2718 Type-2 zero-gas-price transaction builder, `RelayerSigner` / `DevelopmentRelayerSigner` + `RelayerStartupPolicy`, and `TransactionRelayer` with sequential nonce tracking, `Committed`/`Reverted`/`ConfirmationTimedOut` reporting, and `reconcile_transaction` (6 new unit + mock-TCP RPC tests).
  - `services/gateway`: added `GatewayRelayerPort`, `BesuContractRelayer`, `GatewayChainPort::has_write_access`, `GatewayStorePort::record_write_attempt` (with PostgreSQL hash-chain test coverage), `MIN_PIN_REPLICAS` / `DEFAULT_TX_GAS_LIMIT` config, optional opt-in dev relayer wiring in `main.rs`, and the 3 rate-limited write routes: `POST /v1/files`, `POST /v1/files/{fileId}/versions`, and `POST /v1/files/{fileId}/versions/{version}/envelopes` — enforcing active member identity, Write/Read ACLs, EIP-712 signatures, stale-head checks, canonical `KeyEnvelopeSet` validation at `revision + 1`, and pin-before-commit Cluster quorum BEFORE relaying.
  - Added real-HTTP Axum write-route integration test (`gateway_write_routes_enforce_signatures_pin_quorum_stale_head_and_relay_outcomes`) and updated `docs/api.md` and `services/gateway/README.md`.
- **Boundary, duplication & documentation audit (26 Nov 2026):**
  - Audited all workspace `Cargo.toml` dependencies and runtime data paths: zero illegal cross-system dependencies (no plaintext/DEK handling in gateway/indexer/storage, no direct Besu/PostgreSQL access in `application` or `apps/cli`, no runtime `key_custody` in `gateway`), documented in [`docs/architecture/deployment-and-boundaries.md`](docs/architecture/deployment-and-boundaries.md).
  - Eliminated two remaining duplications: delegated `crates/ipfs_adapter`'s `raw_chunk_cid` to `crypto::raw_sha256_cid`, and refactored `access_lookup` and `retrieve_version_content` in `services/gateway/src/routes.rs` to reuse `authenticate_bearer`.
  - Synchronized root `README.md`, `progress_report.md` (top assessment & phase table), `docs/architecture/{README,deployment-and-boundaries,authentication-and-challenge}.md`, and added the remaining missing component READMEs (`crates/{domain,crypto,metadata_store,scanner}/README.md`) so every crate, service, app, and infra directory has a current README.
- **P4 thin CLI, HTTP gateway client & ciphertext blob staging verified (26 Nov 2026):**
  - `crates/ports`: added canonical `RRDSPKG1` encrypted-package framing (`encode_content_package_frame`, `decode_content_package_frame` + round-trip/tamper unit test) shared between `apps/cli` and `services/gateway` with zero duplication.
  - `services/gateway`: added rate-limited, authenticated ciphertext-only staging routes `POST /v1/blobs/content` (bounded by `GATEWAY_MAX_BLOB_UPLOAD_BYTES`, default 64 MiB) and `POST /v1/blobs/envelopes` (max 512 KiB) so endpoints never receive Kubo/Cluster credentials; covered by real-HTTP Axum tests.
  - `apps/cli`: implemented `GatewayHttpClient` (`GatewayAuthPort` + `LedgerPort` + `BlobStore` strictly over HTTP), bounded CARv1 reader (`car.rs`) verifying raw-block SHA-256 CIDs, and 12 thin CLI commands (`health`, `login`, `whoami`, `identity`, `ls`, `history`, `upload`, `modify`, `download`, `share`, `restore`, `audit`) enforcing `CustodyStartupPolicy::Production` by default and verified by an end-to-end HTTP test (`login -> upload -> download -> share -> recipient decrypt -> modify -> append-only restore`). Zero direct Besu/PostgreSQL/IPFS dependencies in `apps/cli`.
  - Updated `apps/cli/README.md`, `docs/adr/phase-5-cli-incremental-scope.md`, `docs/api.md`, `services/gateway/README.md`, `docs/architecture/deployment-and-boundaries.md`, `README.md`, and `progress_report.md`.
- **CI workflow & P5 gateway hardening + scanner interface verified (26 Nov 2026):**
  - Added [`.github/workflows/ci.yml`](.github/workflows/ci.yml) (Rust fmt/Clippy/tests, crate-boundary enforcement, live PostgreSQL 18.6 integration job, Hardhat contract job, Compose/diff hygiene).
  - `crates/ports` & `crates/scanner`: implemented `PreUploadScanner`, `ScannerMode` (default `Disabled`), `ScanOutcome`, `ScanVerdict`, `evaluate_scan_outcome`, and `DisabledScanner` (2 unit tests).
  - `crates/metadata_store` & `infra/postgres`: added `0005_gateway_session_revocation.sql` (`revoked_at` + active-session partial index) and least-privilege role-separation SQL template (`infra/postgres/init-roles.sql` + `README.md`).
  - `services/gateway`: added `DELETE /v1/auth/session` (transactional revocation + `auth.session.revoke` audit), `X-Request-Id` correlation & structured JSON operational logging, and multi-budget rate limiting (`src:*`, `member:*`, and separate `invalid_sig_src:*` so spoofed claims cannot lock out a victim), verified with real-HTTP Axum tests (`gateway_enforces_request_ids_session_revocation_and_multi_budget_rate_limits`) and extended PostgreSQL hash-chain assertions.
  - Added `crates/metadata_store/build.rs` (`cargo:rerun-if-changed=migrations`) so `sqlx::migrate!` always recompiles when migrations change; verified live on host against PostgreSQL `rrfs_indexer_test` (all 5 DB tests passing, including migration `0005`).
- **P7 cross-component test suites, runbook, demo, Compose templates & design/dev docs verified (26 Nov 2026):**
  - Added workspace test package `rrds-tests` (`tests/Cargo.toml`) with 9 tests across `tests/end_to_end/acceptance.rs` (3), `tests/security/invariants.rs` (5), and `tests/integration/cross_component.rs` (1) covering 1 MiB multi-chunk ransomware containment & append-only recovery, stale-head rejection & orphan CID reporting, read revocation + historical grant invalidation + key rotation without re-encryption, AEAD/HPKE/EIP-712/policy/scanner security invariants, and signed Type-2 relayer submission.
  - Added [`docs/runbooks/ransomware-recovery.md`](docs/runbooks/ransomware-recovery.md), [`scripts/demo-local.sh`](scripts/demo-local.sh), production-separated per-role Compose templates under [`infra/compose/`](infra/compose/README.md) (validated in `.github/workflows/ci.yml`), [`docs/decisions/README.md`](docs/decisions/README.md), and [`docs/development-notes.md`](docs/development-notes.md).
  - Synchronized `README.md`, `progress_report.md`, and `agentic_review.md`.
- **Latest post-change verification (26 Nov 2026):** `cargo test --workspace --all-targets --locked --offline` passed (**106 reported `ok`**: 101 executed offline, 5 PostgreSQL tests returned early because `DATABASE_URL` is unset and were separately verified live on host against `rrfs_indexer_test`; 1 live two-peer Cluster test separately verified passing on host), `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`, `cargo fmt --all -- --check`, `sh -n scripts/demo-local.sh`, and `git diff --check` all passed.

---

## 7. Documentation & Organization Work Needed (`manual_review.md` Alignment)

Tracking items from [`manual_review.md`](manual_review.md):
1. **Architecture deep dives (`docs/architecture/`):** **Completed** (`README.md`, `historical-access.md`, `recovery-and-revocation.md`, `authentication-and-challenge.md`, `deployment-and-boundaries.md`).
2. **Design justifications & limitations (`docs/decisions/`):** **Completed** in [`docs/decisions/README.md`](docs/decisions/README.md) (`manual_review.md` #9).
3. **Rewrite root `README.md` (`manual_review.md` #6, #7):** **Completed** — concise overview, deployment-placement table, current status, and links to `progress_report.md`.
4. **Development & interdependency notes (`docs/development-notes.md`, `manual_review.md` #8):** **Completed** — documents EIP-712, Solidity ABI/event, 1 MiB CIDv1/CARv1/`RRDSPKG1`, SQLx migration coupling, `services/` vs `crates/` rationale, and test placement.
5. **Reconcile stale component READMEs (`manual_review.md` #2):** **Completed** — all crates, services, apps, and infra directories have current READMEs.
6. **Repository & Compose organization (`manual_review.md` #3, #4, #10, #11):**
   - **Completed:** Production-separated per-role Compose templates (`infra/compose/{database,ipfs-peer,besu-validator,besu-rpc}.yaml`) alongside unified dev `infra/compose.yaml`, and standardized cross-component test placement in `tests/{integration,end_to_end,security}/`.
   - **Optional maintainer-confirmed cleanup:** Remove leftover Hardhat template files (`contracts/contracts/Counter*`, `contracts/test/Counter.ts`, `contracts/ignition/modules/Counter.ts`, `contracts/scripts/send-op-tx.ts`), empty `crates/metadata_store/src/migrations/`, and unused root `package.json`; optionally relocate `TECHNICAL_SPECIFICATION.md` into `docs/specifications/` and update cross-links.
