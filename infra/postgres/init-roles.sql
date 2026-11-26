-- Least-privilege PostgreSQL role separation template for RRDS
-- (TECHNICAL_SPECIFICATION.md §§10.4, 14).
--
-- Apply with a database superuser after creating roles with distinct,
-- randomly generated passwords (see .env.example: RRFS_MIGRATOR_PASSWORD,
-- RRFS_INDEXER_PASSWORD, RRFS_GATEWAY_PASSWORD) and running SQLx migrations
-- as `rrfs_migrator`.
--
-- Security invariant:
--   `rrfs_gateway` MUST NOT be granted INSERT, UPDATE, or DELETE on indexer
--   projection tables (`chain_events`, `indexer_checkpoints`,
--   `members_projection`, `member_keys_projection`, `folders_projection`,
--   `files_projection`, `versions_projection`, `access_projection`,
--   `historical_read_access_projection`, `envelope_sets_projection`).
--   `rrfs_gateway` MUST ONLY append/read `gateway_audit_events` (enforced by
--   both grants and the `gateway_audit_no_update_or_delete` trigger).

REVOKE ALL ON SCHEMA public FROM PUBLIC;

GRANT USAGE, CREATE ON SCHEMA public TO rrfs_migrator;
GRANT USAGE ON SCHEMA public TO rrfs_indexer;
GRANT USAGE ON SCHEMA public TO rrfs_gateway;

-- Indexer role: owns event ingestion and rebuildable read projections only.
GRANT SELECT, INSERT, UPDATE, DELETE ON
    indexer_checkpoints,
    chain_events,
    members_projection,
    member_keys_projection,
    folders_projection,
    files_projection,
    versions_projection,
    access_projection,
    historical_read_access_projection,
    envelope_sets_projection
TO rrfs_indexer;

-- Gateway role: read-only access to indexer projections.
GRANT SELECT ON
    indexer_checkpoints,
    members_projection,
    member_keys_projection,
    folders_projection,
    files_projection,
    versions_projection,
    access_projection,
    historical_read_access_projection,
    envelope_sets_projection
TO rrfs_gateway;

-- Gateway role: operational auth, rate-limit, and one-time nonce tables.
GRANT SELECT, INSERT, UPDATE, DELETE ON
    gateway_login_challenges,
    gateway_sessions,
    gateway_used_access_nonces,
    gateway_rate_buckets
TO rrfs_gateway;

-- Gateway role: append-only access to hash-chained audit events.
GRANT SELECT, INSERT ON gateway_audit_events TO rrfs_gateway;
GRANT USAGE, SELECT ON SEQUENCE gateway_audit_events_sequence_seq TO rrfs_gateway;
