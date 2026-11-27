# PostgreSQL Role Separation (`infra/postgres`)

[`TECHNICAL_SPECIFICATION.md`](../../docs/specifications/TECHNICAL_SPECIFICATION.md)
§§7.4, 10.4, 13, and 14 require separating database roles so neither the gateway
nor the indexer can violate trust boundaries:

| Role | Purpose | Privileges |
| --- | --- | --- |
| `rrfs_migrator` | Runs versioned SQLx migrations (`crates/metadata_store/migrations/`) | Schema `USAGE, CREATE`, DDL owner |
| `rrfs_indexer` | Runs `services/indexer` event ingestion and projection rebuilds (`DATABASE_MIGRATION_MODE=verify`) | `SELECT, INSERT, UPDATE, DELETE` on all 12 indexer/projection tables (`indexer_checkpoints`, `indexed_contract_events`, `indexer_projection_chain`, `organizations_projection`, `members_projection`, `member_keys_projection`, `folders_projection`, `files_projection`, `versions_projection`, `access_projection`, `historical_read_access_projection`, `envelope_sets_projection`) + `SELECT` on `_sqlx_migrations`; **zero** access to `gateway_*` tables |
| `rrfs_gateway` | Runs `services/gateway` API (`DATABASE_MIGRATION_MODE=verify`) | `SELECT` only on indexer projections + `_sqlx_migrations`; `SELECT, INSERT, UPDATE, DELETE` on `gateway_login_challenges`, `gateway_sessions`, `gateway_used_access_nonces`, `gateway_rate_buckets`; append-only (`SELECT, INSERT`) on `gateway_audit_events` + sequence `USAGE, SELECT` |
| `rrfs_audit_reader` *(optional)* | Dedicated read-only audit/SIEM inspection role (§7.4) | `SELECT` only on `gateway_audit_events` |

## Applying Role Grants

1. Create `rrfs_migrator`, `rrfs_indexer`, and `rrfs_gateway` (and optionally
   `rrfs_audit_reader`) with distinct randomly generated passwords.
2. Run SQLx migrations as `rrfs_migrator` (e.g., `DATABASE_MIGRATION_MODE=run`).
3. Apply [`init-roles.sql`](init-roles.sql) with a PostgreSQL superuser or schema
   owner in the target schema (`current_schema()`, works with `public` or a
   dedicated schema such as `rrfs`):

   ```shell
   psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f infra/postgres/init-roles.sql
   ```

4. Run `services/gateway` as `rrfs_gateway` and `services/indexer` as
   `rrfs_indexer` with `DATABASE_MIGRATION_MODE=verify` (the default). Never
   store role passwords in tracked files.
