# Finalized-chain indexer

The indexer reads only Besu's `finalized` block tag and projects finalized
`FileRegistry` and `AccessGovernance` events into PostgreSQL. Event insertion,
projection updates, and checkpoint advancement are committed in one
transaction. The persisted block hash is checked against Besu before polling
continues. PostgreSQL projections are for search/history and never authorize
access.

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
