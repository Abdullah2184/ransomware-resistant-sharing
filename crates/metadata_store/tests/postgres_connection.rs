use metadata_store::PostgresStore;

#[tokio::test]
async fn migrates_indexer_schema_and_reuses_versioned_migrations() {
    let database_url = match std::env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!("Skipping PostgreSQL integration test: DATABASE_URL is not set.");
            return;
        }
    };

    let store = PostgresStore::connect(&database_url)
        .await
        .expect("Failed to connect to PostgreSQL");

    store.ping().await.expect("PostgreSQL ping query failed");
    store
        .migrate()
        .await
        .expect("Indexer schema migration failed");
    store
        .migrate()
        .await
        .expect("Repeated migration should be a no-op");

    let projections_exist: bool = sqlx::query_scalar(
        "SELECT to_regclass('indexer_checkpoints') IS NOT NULL \
         AND to_regclass('indexed_contract_events') IS NOT NULL \
         AND to_regclass('files_projection') IS NOT NULL \
         AND to_regclass('organizations_projection') IS NOT NULL \
         AND to_regclass('indexer_projection_chain') IS NOT NULL",
    )
    .fetch_one(store.pool())
    .await
    .expect("Could not verify indexer projection tables");
    assert!(projections_exist);
}
