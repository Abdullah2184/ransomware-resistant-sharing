# PostgreSQL Role Separation (`infra/postgres`)

`TECHNICAL_SPECIFICATION.md` §14 requires separating database roles so the
gateway API role can never mutate contract-derived indexer projections or
rewrite audit history:

| Role | Purpose | Grants |
| --- | --- | --- |
| `rrfs_migrator` | Runs versioned SQLx migrations (`crates/metadata_store/migrations/`) | Schema `USAGE, CREATE`, DDL owner |
| `rrfs_indexer` | Runs `services/indexer` event ingestion and projection rebuilds | Read/write on `indexer_checkpoints`, `chain_events`, and `*_projection` tables only; no access to gateway sessions or audit tables |
| `rrfs_gateway` | Runs `services/gateway` API | Read-only (`SELECT`) on indexer projections; read/write on `gateway_login_challenges`, `gateway_sessions`, `gateway_used_access_nonces`, `gateway_rate_buckets`; append-only (`SELECT, INSERT`) on `gateway_audit_events` |

Apply [`init-roles.sql`](init-roles.sql) with a PostgreSQL superuser after
creating the three roles with distinct passwords and running migrations as
`rrfs_migrator`. Never store role passwords in tracked files.
