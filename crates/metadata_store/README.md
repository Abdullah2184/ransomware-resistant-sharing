# Metadata Store (`crates/metadata_store`)

Shared PostgreSQL connection pool and versioned SQLx migration runner for
`services/indexer` and `services/gateway`. Contains no blockchain, IPFS, or
application-layer logic.

## Migrations (`migrations/`)

- `0001_indexer_projections.sql` — Indexer checkpoints, raw finalized contract
  events, and rebuildable read projections (files, folders, versions, ACLs,
  envelope sets).
- `0002_indexer_identity_projections.sql` — Member and key-version read
  projections.
- `0003_gateway_auth_audit.sql` — Gateway login challenges, hashed session
  tokens, shared token-bucket rate limits, one-time `AccessLookup` nonces, and
  the append-only hash-chained `gateway_audit_events` table with immutability
  trigger.
- `0004_historical_read_projection.sql` — Version-scoped
  `historical_read_access_projection`.
- `0005_gateway_session_revocation.sql` — Additive `revoked_at` column and
  partial active-session index on `gateway_sessions` for `DELETE /v1/auth/session`.

> Existing migrations are immutable once applied. Only add new numbered
> migrations for future schema changes. For least-privilege PostgreSQL role
> separation (`rrfs_migrator`, `rrfs_indexer`, `rrfs_gateway`), see
> [`infra/postgres/README.md`](../../infra/postgres/README.md).

## Verification

```shell
set -a && . ./.env && set +a
DATABASE_URL="${DATABASE_URL%/*}/rrfs_indexer_test" cargo test -p metadata-store --locked
```
