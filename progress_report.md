# Project progress and remaining work

**Reviewed:** 12 November 2026  
**Canonical guide:** [`TECHNICAL_SPECIFICATION.md`](TECHNICAL_SPECIFICATION.md)  
**Branch:** `agent/development`  
**Repository state:** the worktree contains uncommitted changes from prior
implementation increments. This report describes that working tree; preserve
those changes and do not reset or clean it as a troubleshooting step.

## Current assessment

The project has substantial foundations but is not an end-to-end MVP. Crypto
primitives and formats, core contracts and local contract tests, a Kubo/Cluster
adapter, an event indexer, and the gateway authentication/access-read paths
exist. The application use-case crate is empty, the scanner is a stub, the CLI
only checks gateway health, and state-changing application operations are not
relayed. Storage replication and PostgreSQL-backed integration remain
unverified. The specification's acceptance criteria in §15.4 have not been
met.

## Phase status

| Specification phase | Status | Remaining work |
|---|---|---|
| 0 — repository and decisions | Mostly established | Add/confirm CI and reconcile implementation documentation. Complete open operational decisions before production deployment. |
| 1 — domain and cryptography | Substantial foundation | Add published/cross-implementation HPKE vectors and connect primitives to client/application workflows. |
| 2 — contracts | Local contract implementation and tests exist | Deploy to Besu, provide approved Safe configuration, activate `FILE_REGISTRY_ROLE` through the timelock, and verify the deployed contracts. |
| 3 — storage and indexer | Local two-peer replication now verified; DB acceptance remains open | Run migrations and indexer tests against the isolated database from a Docker-networked runner; verify host Kubo/PostgreSQL access; inspect the existing `rrfs_dev` schema before considering additive reconciliation for its migration checksum mismatch. |
| 4 — gateway | Partial | Add listing/history/audit and upload/version/envelope/share/revoke operations; implement the relayer and transaction lifecycle; validate recipient envelopes and preserve audit requirements. |
| 5 — CLI | Health command only | Add use-case services first, then thin commands for identity, files/folders, upload/download, modify/history, sharing/revocation, and recovery. |
| 6 — integration and demo | Not started | Complete end-to-end and failure-path tests, restart/replay and concurrency checks, recovery runbook, and scripted demo. |

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
- PostgreSQL contains `rrfs_dev` and `rrfs_indexer_test`. Host-side port access
  and live DB integration remain unverified; neither database was modified.
  Compose declares loopback ports 5432/15001/15002 and `up -d` left all named
  volumes in place, but the coding shell still cannot connect to Kubo on
  15001; PostgreSQL's running container has no active network port allocation.
- Current read-only Docker diagnostics confirm both Kubo and Cluster peer
  connectivity, but the test CID is pinned only on Kubo 1. Kubo 2 reports no
  local pin, its direct `ipfs cat` did not complete, and its log records the
  failed pin as `context canceled`. The root cause is not yet established.
  PostgreSQL has `rrfs_dev` and the isolated `rrfs_indexer_test` databases; no
  database or persistent content was modified during this check.
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
- Provide a `DATABASE_URL` for a fresh, isolated integration database. Do not
  use `rrfs_dev` for new migration verification until its recorded migration
  3 checksum/schema discrepancy has been reviewed.
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
