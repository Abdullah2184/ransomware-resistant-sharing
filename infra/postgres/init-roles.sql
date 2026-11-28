-- Least-privilege PostgreSQL role separation script for RRDS
-- (docs/specifications/TECHNICAL_SPECIFICATION.md §§7.4, 10.4, 14).
--
-- Prerequisites:
--   1. Create login roles with distinct, randomly generated passwords:
--        rrfs_migrator, rrfs_indexer, rrfs_gateway
--      (and optionally `rrfs_audit_reader` for dedicated read-only audit/SIEM queries).
--   2. Run SQLx migrations (`0001`..`0006`) as `rrfs_migrator` in the target
--      schema (`public` or a dedicated schema such as `rrfs` via `search_path`).
--   3. Execute this script as a PostgreSQL superuser (or schema owner) with
--      `search_path` set to the schema containing the migrated tables:
--        psql -v ON_ERROR_STOP=1 -f infra/postgres/init-roles.sql
--
-- Enforced security invariants:
--   - `rrfs_gateway` CANNOT INSERT, UPDATE, DELETE, or TRUNCATE any indexer
--     projection or raw chain-event table.
--   - `rrfs_gateway` CANNOT UPDATE, DELETE, or TRUNCATE `gateway_audit_events`
--     (enforced by both privilege omission and database triggers).
--   - `rrfs_indexer` CANNOT read or write any `gateway_*` auth, session,
--     nonce, rate-limit, or audit table.
--   - Both `rrfs_gateway` and `rrfs_indexer` receive `SELECT` ONLY on
--     `_sqlx_migrations` so `DATABASE_MIGRATION_MODE=verify` can validate
--     schema/checksum integrity at startup without DDL privileges.

DO $$
DECLARE
    target_schema text := current_schema();
    indexer_tables text[] := ARRAY[
        'indexer_checkpoints',
        'indexed_contract_events',
        'indexer_projection_chain',
        'organizations_projection',
        'members_projection',
        'member_keys_projection',
        'folders_projection',
        'files_projection',
        'versions_projection',
        'access_projection',
        'historical_read_access_projection',
        'envelope_sets_projection'
    ];
    gateway_read_projections text[] := ARRAY[
        'indexer_checkpoints',
        'organizations_projection',
        'members_projection',
        'member_keys_projection',
        'folders_projection',
        'files_projection',
        'versions_projection',
        'access_projection',
        'historical_read_access_projection',
        'envelope_sets_projection'
    ];
    gateway_rw_tables text[] := ARRAY[
        'gateway_login_challenges',
        'gateway_sessions',
        'gateway_used_access_nonces',
        'gateway_rate_buckets',
        'gateway_relayed_transactions',
        'gateway_orphan_blobs'
    ];
    tbl text;
BEGIN
    IF target_schema IS NULL OR target_schema = '' THEN
        RAISE EXCEPTION 'current_schema() is empty; set search_path before applying init-roles.sql';
    END IF;

    EXECUTE format('REVOKE ALL ON SCHEMA %I FROM PUBLIC', target_schema);
    EXECUTE format('GRANT USAGE, CREATE ON SCHEMA %I TO rrfs_migrator', target_schema);
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO rrfs_indexer', target_schema);
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO rrfs_gateway', target_schema);

    -- Reset table-level privileges before applying least-privilege grants.
    FOREACH tbl IN ARRAY indexer_tables LOOP
        EXECUTE format('REVOKE ALL ON TABLE %I.%I FROM PUBLIC, rrfs_indexer, rrfs_gateway', target_schema, tbl);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE %I.%I TO rrfs_indexer', target_schema, tbl);
    END LOOP;

    FOREACH tbl IN ARRAY gateway_read_projections LOOP
        EXECUTE format('GRANT SELECT ON TABLE %I.%I TO rrfs_gateway', target_schema, tbl);
    END LOOP;

    FOREACH tbl IN ARRAY gateway_rw_tables LOOP
        EXECUTE format('REVOKE ALL ON TABLE %I.%I FROM PUBLIC, rrfs_indexer, rrfs_gateway', target_schema, tbl);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE %I.%I TO rrfs_gateway', target_schema, tbl);
    END LOOP;

    -- Append-only hash-chained audit table: gateway may only read & append.
    EXECUTE format('REVOKE ALL ON TABLE %I.gateway_audit_events FROM PUBLIC, rrfs_indexer, rrfs_gateway', target_schema);
    EXECUTE format('GRANT SELECT, INSERT ON TABLE %I.gateway_audit_events TO rrfs_gateway', target_schema);
    EXECUTE format('REVOKE ALL ON SEQUENCE %I.gateway_audit_events_sequence_seq FROM PUBLIC, rrfs_indexer, rrfs_gateway', target_schema);
    EXECUTE format('GRANT USAGE, SELECT ON SEQUENCE %I.gateway_audit_events_sequence_seq TO rrfs_gateway', target_schema);

    -- Read-only access to SQLx migration ledger for startup schema verification (`DATABASE_MIGRATION_MODE=verify`).
    EXECUTE format('REVOKE ALL ON TABLE %I._sqlx_migrations FROM PUBLIC, rrfs_indexer, rrfs_gateway', target_schema);
    EXECUTE format('GRANT SELECT ON TABLE %I._sqlx_migrations TO rrfs_indexer, rrfs_gateway', target_schema);

    -- Optional dedicated compliance/SIEM audit reader role (§7.4).
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rrfs_audit_reader') THEN
        EXECUTE format('GRANT USAGE ON SCHEMA %I TO rrfs_audit_reader', target_schema);
        EXECUTE format('REVOKE ALL ON TABLE %I.gateway_audit_events FROM rrfs_audit_reader', target_schema);
        EXECUTE format('GRANT SELECT ON TABLE %I.gateway_audit_events TO rrfs_audit_reader', target_schema);
    END IF;
END
$$;
