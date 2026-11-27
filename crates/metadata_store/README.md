# Metadata Store (`crates/metadata_store`)

Shared PostgreSQL connection pool, configurable startup `MigrationMode`, and
versioned SQLx migration runner for `services/indexer` and `services/gateway`.
Contains no blockchain, IPFS, or application-layer logic.

## Migrations (`migrations/`)

- `0001_indexer_projections.sql` — Indexer checkpoints, raw finalized contract
  events (`indexed_contract_events`), and rebuildable read projections (files,
  folders, versions, ACLs, envelope sets).
- `0002_indexer_identity_projections.sql` — Organization, member, key-version,
  and single-chain lock (`indexer_projection_chain`) read projections.
- `0003_gateway_auth_audit.sql` — Gateway login challenges, hashed session
  tokens, shared token-bucket rate limits, one-time `AccessLookup` nonces, and
  the append-only hash-chained `gateway_audit_events` table with
  `BEFORE UPDATE OR DELETE` immutability trigger.
- `0004_historical_read_projection.sql` — Version-scoped
  `historical_read_access_projection`.
- `0005_gateway_session_revocation.sql` — Additive `revoked_at` column and
  partial active-session index on `gateway_sessions` for `DELETE /v1/auth/session`.
- `0006_postgres_hardening_indexes_and_audit_guard.sql` — Defense-in-depth
  `BEFORE TRUNCATE` trigger on `gateway_audit_events` and indexes for member
  audit queries, folder listings, replay cursor pagination, and session expiry
  pruning.

## Startup Migration Mode & Pool Tuning

- `DATABASE_MIGRATION_MODE`:
  - `verify` *(default)* — read-only checksum & version verification against
    `_sqlx_migrations` (safe for least-privilege `rrfs_gateway` and
    `rrfs_indexer` runtime roles).
  - `run` — executes pending migrations (for `rrfs_migrator` or local dev).
  - `off` — skips migration checks.
- `DATABASE_MAX_CONNECTIONS` (default `10`, range `1..=100`) and
  `DATABASE_ACQUIRE_TIMEOUT_SECONDS` (default `5`, range `1..=60`).

> Existing migrations are immutable once applied (`build.rs` emits
> `cargo:rerun-if-changed=migrations`). For least-privilege role separation
> (`rrfs_migrator`, `rrfs_indexer`, `rrfs_gateway`, optional
> `rrfs_audit_reader`), see [`infra/postgres/README.md`](../../infra/postgres/README.md).

## Verification

```shell
set -a && . ./.env && set +a
DATABASE_URL="${DATABASE_URL%/*}/rrfs_indexer_test" \
DATABASE_GATEWAY_URL="postgres://rrfs_gateway:${RRFS_GATEWAY_PASSWORD}@127.0.0.1:5432/rrfs_indexer_test" \
DATABASE_INDEXER_URL="postgres://rrfs_indexer:${RRFS_INDEXER_PASSWORD}@127.0.0.1:5432/rrfs_indexer_test" \
cargo test -p metadata-store -p indexer -p gateway --locked
```
