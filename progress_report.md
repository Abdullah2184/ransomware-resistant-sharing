# Project Progress and Remaining Work

**Last verified:** 28 November 2026
**Canonical specification:** [`docs/specifications/TECHNICAL_SPECIFICATION.md`](docs/specifications/TECHNICAL_SPECIFICATION.md) (RRDS-TS-001 v1.0)
**Branch:** `agent/development`

---

## 1. Executive Summary — Current State

All MVP engineering phases (**P0–P7**), **Option B** member-signed relayed
envelope updates, **audited Safe v1.4.1 `2-of-3` threshold governance**,
**PostgreSQL migration `0007` + `rrds-migrate`**, **persistent transaction
reconciliation & safe orphan blob cleanup**, **per-org & concurrent-stream
quotas**, **background storage health monitoring**, **production startup
guards**, **per-role multi-org Compose templates**, and **§17 consortium
operational policies** are implemented and verified:

- **End-to-end Rust stack:** `domain`, `crypto` (1 MiB AES-256-GCM chunks +
  verified RFC 9180 / OpenSSL HPKE vectors + EIP-712 + CARv1 codecs), `ports`
  (`RRDSPKG1` framing, `BlobStore::unpin`/`health_status`, `PreUploadScanner`),
  `scanner` (`DisabledScanner`, disabled by default), `key_custody` (MVP dev
  software custody with `CustodyStartupPolicy::Production` refusal guard),
  `application` (`AuthService`, `UploadService` with `restore_version_from`,
  `DownloadService`, `ShareService`), `ipfs_adapter` (Kubo `0.43.1` + Cluster
  `1.1.6` failover, `unpin`, `health_status`), `chain_adapter` (QBFT pinned
  reads, EIP-1474 revert vs RPC error classification, Type-2 zero-gas-price
  relayer with bounded gas estimation & timeout reconciliation), `metadata_store`
  (migrations `0001`–`0007` + standalone `rrds-migrate` binary +
  [`infra/postgres/init-roles.sql`](infra/postgres/init-roles.sql)), `indexer`
  (full contract, role, and timelock event decoding + `RRDS_ENV=production`
  guards), `gateway` (all auth, read, blob-staging, write-relay,
  `GET /v1/transactions/{txHash}` reconciliation, `file.version_restore` audit,
  multi-budget rate limits `src:*`/`member:*`/`org:*`/`invalid_sig_src:*`,
  bounded concurrent streams, `OrphanBlobCleaner`, `StorageHealthMonitor`, and
  `RRDS_ENV=production` guards), thin 13-command `apps/cli`, and `rrds-tests`.
- **Smart contracts & Audited Safe v1.4.1 (`contracts/`):** `AccessGovernance`
  (Option B, `17,475` runtime bytes), `FileRegistry`, `RrdsTimelockController`,
  `RrdsCid`, `RrdsEip712`, and `@safe-global/safe-contracts@1.4.1` (`Safe`
  singleton, `SafeProxyFactory`, `CompatibilityFallbackHandler`, `2-of-3`
  `consortiumSafe`, `emergencySafe`, `organizationSafe`) verified by **37
  Hardhat tests** (`30` Solidity, `7` Node.js including `GasBounds.ts` and
  `SafeGovernance.ts`).
- **Live Besu QBFT + IPFS Cluster + PostgreSQL verification:**
  - Pre-Option-B deployment completed its 24h timelock and passed the full
    live 8-stage `scripts/demo-local.sh` flow (`login` -> `upload` V1 with
    2-peer Cluster pin -> live `indexer` sync -> byte-for-byte `download` ->
    `modify` V2 -> contiguous hash-chained `audit` trail).
  - **Active Safe v1.4.1 (`2-of-3`) + Option B deployment:** Deployed onto
    local Besu QBFT (`chainId=1337`, blocks `62877`–`62894`); 24-hour timelock
    activation batch scheduled via real **`2-of-3`
    `consortiumSafe.execTransaction`** at block `62898`, executable at
    **`2026-11-29T03:19:33.000Z`** (`08:19:33 PKT`).
- **MVP Key Custody Scope (§17 #1):** The MVP explicitly operates with
  `DevelopmentKeyCustody` (CLI) and `DevelopmentRelayerSigner` (gateway),
  gated behind explicit unsafe-dev flags and refused in `RRDS_ENV=production`.
  Hardware HSM / PKCS#11 adapters remain deferred post-MVP behind the existing
  `KeyCustodyProvider` and `RelayerSigner` traits.

---

## 2. Verifiable Implementation & Test Matrix (28 November 2026)

| Suite / Component | Scope Verified | Exact Verified Result | Command |
| --- | --- | --- | --- |
| **Rust workspace (offline)** | All 12 workspace crates + `rrds-tests` (`domain`, `crypto`, `ports`, `scanner`, `key-custody`, `application`, `ipfs-adapter` incl. `unpin`/`health_status`, `chain-adapter`, `metadata-store` `0001`–`0007` + `rrds-migrate`, `indexer`, `gateway` incl. tx reconciliation / orphan cleaner / restore audit / org & stream limits / prod guards, `cli`, `rrds-tests`) | **146 passed, 0 failed** (16 live-infra tests explicitly `#[ignore]`) | `cargo test --workspace --all-targets --locked --offline` |
| **Live PostgreSQL `18.6` (`0001`–`0007` + RBAC) & Live Besu QBFT (Safe v1.4.1 + Option B)** | `rrds-migrate run` (`rrfs_migrator`), `init-roles.sql`, `rrds-migrate verify` (`rrfs_gateway` & `rrfs_indexer`), `metadata-store` (2: schema + 4-role RBAC), `chain-adapter` (1: live Besu reads/reverts/logs on Safe+Option B deployment), `indexer` (5: incl. live Besu governance/timelock indexing), `gateway` (6: incl. tx/orphan lifecycle, restore audit, 8-way concurrency, live Postgres & live Besu HTTP routers) | **14 passed, 0 failed** | `rrds-migrate run` + `init-roles.sql` + `cargo test -p metadata-store -p chain-adapter -p indexer -p gateway --locked --offline -- --ignored --test-threads=1` |
| **Live two-peer IPFS / Cluster + Real CLI -> Gateway E2E** | Kubo `0.43.1` ×2 (`15001`/`15002`) + IPFS Cluster `1.1.6` ×2 (`9094`) private swarm: live `target/debug/cli` -> real Axum `services/gateway` -> real `IpfsClusterStore` (`1.15 MiB` multi-chunk upload, 2-peer Cluster pin quorum, byte-for-byte download, modify V2, historical-access denial + Safe grant + Option B `share` + Bob download, append-only `restore` V1->V3 + `file.version_restore` audit, plaintext rejection, read-only modify rejection, `MIN_PIN_REPLICAS=5` fail-closed, live `OrphanBlobCleaner` `DELETE /pins/{cid}`, and `logout`) + `cluster_integration` + `cross_component_integration` | **`verify.sh` passed & 3/3 live IPFS tests passed** (`cli_binary_through_real_gateway_to_live_dual_node_ipfs_cluster_end_to_end` passed in `7.22s`) | `sh infra/ipfs-cluster/verify.sh` & `cargo test -p gateway cli_binary_through_real_gateway_to_live_dual_node_ipfs_cluster_end_to_end --locked --offline -- --ignored` |
| **Solidity, Hardhat & Audited Safe v1.4.1** | `AccessGovernance` (Option B), `FileRegistry`, `RrdsTimelockController`, `RrdsCid`, `RrdsEip712`, EIP-712 cross-language vectors, `GasBounds.ts`, and `SafeGovernance.ts` (real `2-of-3` Safe `execTransaction`, `GS020`/`GS026` negative tests, Option B relay, emergency suspend + timelocked reinstate) | **37 passing** (`30` Solidity, `7` Node.js) | `pnpm --dir contracts exec hardhat test` |
| **Static analysis & hygiene** | Clippy `-D warnings`, `cargo fmt --check`, `node --check`, `sh -n scripts/demo-local.sh`, `git diff --check` | **All passed** (0 warnings) | `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` |

---

## 3. Remaining Operational Steps

1. **Migrate `rrfs_dev` & `rrfs_indexer_test` to `0007` via real `rrds-migrate`:**
   After resetting the verified-empty `rrfs` schema in `rrfs_dev`, run
   `./target/debug/rrds-migrate run` with `rrfs_migrator` `DATABASE_URL` and
   apply `infra/postgres/init-roles.sql` so both local databases are on `0001`–`0007`.
2. **Execute Safe v1.4.1 + Option B 24h Timelock (ready `2026-11-29T03:19:33.000Z` / `08:19:33 PKT`):**
   ```shell
   node contracts/scripts/besu-bootstrap.mjs execute
   node contracts/scripts/besu-bootstrap.mjs register-member
   node contracts/scripts/besu-bootstrap.mjs status
   ```
   Update `.env` with the new Safe-backed contract addresses
   (`CONTRACT_TIMELOCK_ADDRESS=0x5a51c4bd51709838764c185b490221855e37e64d`,
   `CONTRACT_ACCESS_GOVERNANCE_ADDRESS=0x04ec7bde5732ca6c5e04709641c53a564e1c5472`,
   `CONTRACT_FILE_REGISTRY_ADDRESS=0xeae1730d50eb47b7573c682afa2ee4995ba1968d`),
   restart `indexer` (`INDEXER_START_BLOCK=62875`) and `gateway`, and run a
   live Safe-governed `grant-read` -> Option B `cli share` -> `cli restore` pass.
3. **Post-MVP (Explicitly Deferred per §17 #1):**
   Implement production hardware-backed PKCS#11 / HSM `KeyCustodyProvider` and
   `RelayerSigner` adapters when target consortium hardware is selected.
