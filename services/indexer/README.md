# Finalized-chain indexer

The indexer treats Besu's latest QBFT-committed block as finalized and projects
`FileRegistry` and `AccessGovernance` events through that explicit block into
PostgreSQL. The chain adapter uses `eth_getBlockByNumber("latest", false)` to
identify the committed head; it does not request Besu's generic `finalized` tag,
which is not available on this QBFT network. Event insertion,
projection updates, and checkpoint advancement are committed in one
transaction. The persisted block hash is checked against Besu before polling
continues. PostgreSQL projections are for search/history and never authorize
access.

Historical Read grant/revoke events are projected into
`historical_read_access_projection` by migration `0004`. The projection is
rebuildable from persisted finalized events and remains informational; gateways
query the contract for authoritative grants at the same finalized block as the
file Read ACL and head.

Required configuration:

- `BESU_RPC_URL`, `BESU_CHAIN_ID`, and `DATABASE_URL`
- `CONTRACT_FILE_REGISTRY_ADDRESS` and `CONTRACT_ACCESS_GOVERNANCE_ADDRESS`
- Optional `INDEXER_START_BLOCK`, `INDEXER_BATCH_SIZE`,
  `INDEXER_CONFIRMATION_POLICY=finalized`, and
  `INDEXER_RECONCILIATION_INTERVAL_SECONDS`

Recovery commands:

- `indexer --rebuild-projections` atomically reconstructs projections from
  persisted indexed finalized events, retaining those events and checkpoints.
- `indexer --reindex-from-chain` clears the configured chain's indexed events,
  checkpoint, and projections, then replays from `INDEXER_START_BLOCK`. Use it
  only when Besu retains the complete event history from that block. It does
  not alter chain state or unrelated database tables.

Run unit and PostgreSQL integration tests with:

```shell
cargo test -p indexer --locked
```

The PostgreSQL tests require `DATABASE_URL`. They serialize their work,
exercise actual transactions/migrations, and roll back all test records.

## Local database verification status (12 November 2026)

The existing `rrfs_dev` database records SQLx migrations 1–3, but migration 3's
stored checksum differs from the checked-in `0003_gateway_auth_audit.sql`.
After rebuilding the metadata-store crate, the indexer integration tests fail
with `VersionMismatch(3)` before exercising their database cases. The database
and migration history were left unchanged. A separate empty `rrfs_indexer_test`
database was created, but the current host shell cannot connect through the
Compose-published PostgreSQL port. Resume against a fresh database from a
Docker-networked runner, and review the existing schema before deciding on any
additive reconciliation for `rrfs_dev`. See
[`docs/adr/local-integration-verification.md`](../../docs/adr/local-integration-verification.md).
