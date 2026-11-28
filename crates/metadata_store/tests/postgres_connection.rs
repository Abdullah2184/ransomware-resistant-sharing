use metadata_store::{MetadataStoreError, MigrationMode, PostgresPoolConfig, PostgresStore};

#[tokio::test]
#[ignore = "requires DATABASE_URL (PostgreSQL)"]
async fn migrates_metadata_schema_and_verifies_all_tables_indexes_and_triggers() {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set when running ignored PostgreSQL tests");

    let store = PostgresStore::connect_with_config(&database_url, PostgresPoolConfig::default())
        .await
        .expect("Failed to connect to PostgreSQL");

    store.ping().await.expect("PostgreSQL ping query failed");
    store
        .apply_migration_mode(MigrationMode::Run)
        .await
        .expect("Schema migration failed");
    store
        .apply_migration_mode(MigrationMode::Run)
        .await
        .expect("Repeated migration should be a no-op");
    store
        .apply_migration_mode(MigrationMode::Verify)
        .await
        .expect("Read-only migration verification should pass after migrate");
    store
        .apply_migration_mode(MigrationMode::Off)
        .await
        .expect("MigrationMode::Off should be a no-op");

    // Verify all 17 application tables + SQLx ledger exist.
    for table in [
        "_sqlx_migrations",
        "indexer_checkpoints",
        "indexed_contract_events",
        "indexer_projection_chain",
        "organizations_projection",
        "members_projection",
        "member_keys_projection",
        "folders_projection",
        "files_projection",
        "versions_projection",
        "access_projection",
        "historical_read_access_projection",
        "envelope_sets_projection",
        "gateway_login_challenges",
        "gateway_sessions",
        "gateway_used_access_nonces",
        "gateway_rate_buckets",
        "gateway_audit_events",
        "gateway_relayed_transactions",
        "gateway_orphan_blobs",
    ] {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(table)
            .fetch_one(store.pool())
            .await
            .expect("query table existence");
        assert!(exists, "expected table `{table}` to exist after migrations");
    }

    // Verify migration 0005 column + migration 0006 hardening indexes exist.
    let revoked_at_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
            SELECT 1 FROM information_schema.columns \
            WHERE table_schema = current_schema() \
              AND table_name = 'gateway_sessions' \
              AND column_name = 'revoked_at' \
        )",
    )
    .fetch_one(store.pool())
    .await
    .expect("query gateway_sessions.revoked_at");
    assert!(revoked_at_exists);

    for index in [
        "gateway_sessions_active_lookup",
        "gateway_audit_events_actor_sequence",
        "folders_projection_parent",
        "indexed_contract_events_replay_order",
        "gateway_sessions_expiry",
        "gateway_relayed_transactions_status_created",
        "gateway_relayed_transactions_actor_created",
        "gateway_orphan_blobs_status_created",
    ] {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(index)
            .fetch_one(store.pool())
            .await
            .expect("query index existence");
        assert!(exists, "expected index `{index}` to exist");
    }

    // Verify both audit immutability triggers (UPDATE/DELETE and TRUNCATE) are installed.
    for trigger in [
        "gateway_audit_no_update_or_delete",
        "gateway_audit_no_truncate",
    ] {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS ( \
                SELECT 1 FROM pg_trigger t \
                JOIN pg_class c ON c.oid = t.tgrelid \
                JOIN pg_namespace n ON n.oid = c.relnamespace \
                WHERE n.nspname = current_schema() \
                  AND c.relname = 'gateway_audit_events' \
                  AND t.tgname = $1 \
                  AND NOT t.tgisinternal \
            )",
        )
        .bind(trigger)
        .fetch_one(store.pool())
        .await
        .expect("query trigger existence");
        assert!(
            exists,
            "expected trigger `{trigger}` on gateway_audit_events"
        );
    }
}

#[tokio::test]
#[ignore = "requires DATABASE_GATEWAY_URL and DATABASE_INDEXER_URL (PostgreSQL)"]
async fn least_privilege_roles_enforce_gateway_and_indexer_trust_boundaries() {
    let gateway_url = std::env::var("DATABASE_GATEWAY_URL")
        .expect("DATABASE_GATEWAY_URL must be set when running ignored RBAC PostgreSQL tests");
    let indexer_url = std::env::var("DATABASE_INDEXER_URL")
        .expect("DATABASE_INDEXER_URL must be set when running ignored RBAC PostgreSQL tests");

    let gateway = PostgresStore::connect(&gateway_url)
        .await
        .expect("connect as rrfs_gateway");
    let indexer = PostgresStore::connect(&indexer_url)
        .await
        .expect("connect as rrfs_indexer");

    // Both runtime roles must succeed with read-only MigrationMode::Verify
    // and MUST be denied DDL execution.
    gateway
        .apply_migration_mode(MigrationMode::Verify)
        .await
        .expect("rrfs_gateway must pass MigrationMode::Verify");
    indexer
        .apply_migration_mode(MigrationMode::Verify)
        .await
        .expect("rrfs_indexer must pass MigrationMode::Verify");

    assert!(
        sqlx::query("CREATE TABLE rrfs_illegal_gateway_ddl (id INT)")
            .execute(gateway.pool())
            .await
            .is_err(),
        "rrfs_gateway must not hold CREATE DDL privileges"
    );
    assert!(
        sqlx::query("CREATE TABLE rrfs_illegal_indexer_ddl (id INT)")
            .execute(indexer.pool())
            .await
            .is_err(),
        "rrfs_indexer must not hold CREATE DDL privileges"
    );

    // rrfs_gateway: allowed to read projections, DENIED from writing projections or raw events.
    for table in [
        "indexer_checkpoints",
        "organizations_projection",
        "members_projection",
        "member_keys_projection",
        "folders_projection",
        "files_projection",
        "versions_projection",
        "access_projection",
        "historical_read_access_projection",
        "envelope_sets_projection",
    ] {
        let query = format!("SELECT 1 FROM {table} LIMIT 1");
        sqlx::query(sqlx::AssertSqlSafe(query))
            .fetch_optional(gateway.pool())
            .await
            .unwrap_or_else(|e| panic!("rrfs_gateway should SELECT from {table}: {e}"));
    }

    assert!(
        sqlx::query("SELECT 1 FROM indexed_contract_events LIMIT 1")
            .fetch_optional(gateway.pool())
            .await
            .is_err(),
        "rrfs_gateway must not read raw indexed_contract_events"
    );
    assert!(
        sqlx::query("DELETE FROM files_projection WHERE file_id = '0x00'")
            .execute(gateway.pool())
            .await
            .is_err(),
        "rrfs_gateway must not mutate files_projection"
    );
    assert!(
        sqlx::query("DELETE FROM access_projection WHERE file_id = '0x00'")
            .execute(gateway.pool())
            .await
            .is_err(),
        "rrfs_gateway must not mutate access_projection"
    );
    assert!(
        sqlx::query("DELETE FROM indexer_checkpoints WHERE chain_id = -1")
            .execute(gateway.pool())
            .await
            .is_err(),
        "rrfs_gateway must not mutate indexer_checkpoints"
    );

    // rrfs_gateway: allowed append-only INSERT/SELECT on gateway_audit_events,
    // DENIED UPDATE/DELETE/TRUNCATE.
    {
        let mut tx = gateway.pool().begin().await.expect("begin gateway tx");
        sqlx::query(
            "INSERT INTO gateway_audit_events \
             (record, record_canonical, previous_hash, record_hash) \
             VALUES ('{}'::jsonb, '{}', $1, $2)",
        )
        .bind([0u8; 32].as_slice())
        .bind([0x99u8; 32].as_slice())
        .execute(&mut *tx)
        .await
        .expect("rrfs_gateway must be able to append gateway_audit_events");
        tx.rollback().await.expect("rollback probe audit insert");
    }
    assert!(
        sqlx::query("UPDATE gateway_audit_events SET record = record WHERE sequence = -1")
            .execute(gateway.pool())
            .await
            .is_err(),
        "rrfs_gateway must not UPDATE gateway_audit_events"
    );
    assert!(
        sqlx::query("DELETE FROM gateway_audit_events WHERE sequence = -1")
            .execute(gateway.pool())
            .await
            .is_err(),
        "rrfs_gateway must not DELETE gateway_audit_events"
    );
    assert!(
        sqlx::query("TRUNCATE TABLE gateway_audit_events")
            .execute(gateway.pool())
            .await
            .is_err(),
        "rrfs_gateway must not TRUNCATE gateway_audit_events"
    );

    // rrfs_indexer: allowed read/write on indexer tables, DENIED access to all gateway_* tables.
    {
        let mut tx = indexer.pool().begin().await.expect("begin indexer tx");
        sqlx::query(
            "INSERT INTO organizations_projection (organization_id, authority, updated_block_number) \
             VALUES ($1, $2, 1)",
        )
        .bind(format!("0x{}", "fa".repeat(32)))
        .bind(format!("0x{}", "fb".repeat(20)))
        .execute(&mut *tx)
        .await
        .expect("rrfs_indexer must write organizations_projection");
        tx.rollback().await.expect("rollback indexer probe");
    }
    for gateway_table in [
        "gateway_login_challenges",
        "gateway_sessions",
        "gateway_used_access_nonces",
        "gateway_rate_buckets",
        "gateway_audit_events",
        "gateway_relayed_transactions",
        "gateway_orphan_blobs",
    ] {
        let query = format!("SELECT 1 FROM {gateway_table} LIMIT 1");
        assert!(
            sqlx::query(sqlx::AssertSqlSafe(query))
                .fetch_optional(indexer.pool())
                .await
                .is_err(),
            "rrfs_indexer must NOT read `{gateway_table}`"
        );
    }

    // Optional compliance role check: if DATABASE_AUDIT_READER_URL is provided, verify read-only.
    if let Ok(audit_url) = std::env::var("DATABASE_AUDIT_READER_URL") {
        let audit_reader = PostgresStore::connect(&audit_url)
            .await
            .expect("connect as rrfs_audit_reader");
        sqlx::query("SELECT count(*) FROM gateway_audit_events")
            .fetch_one(audit_reader.pool())
            .await
            .expect("rrfs_audit_reader must read gateway_audit_events");
        assert!(
            sqlx::query(
                "INSERT INTO gateway_audit_events \
                 (record, record_canonical, previous_hash, record_hash) \
                 VALUES ('{}'::jsonb, '{}', $1, $2)",
            )
            .bind([0u8; 32].as_slice())
            .bind([0x98u8; 32].as_slice())
            .execute(audit_reader.pool())
            .await
            .is_err(),
            "rrfs_audit_reader must NOT insert into gateway_audit_events"
        );
        assert!(
            sqlx::query("SELECT 1 FROM gateway_sessions LIMIT 1")
                .fetch_optional(audit_reader.pool())
                .await
                .is_err(),
            "rrfs_audit_reader must NOT read gateway_sessions"
        );
    }

    // Sanity-check typed error variant display stays clear and non-leaking.
    assert!(
        MetadataStoreError::MissingMigration(6)
            .to_string()
            .contains("migration 6")
    );
}
