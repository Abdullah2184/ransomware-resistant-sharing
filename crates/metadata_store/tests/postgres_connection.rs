use metadata_store::PostgresStore;

#[tokio::test]
async fn connects_to_postgres_and_executes_query() {
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
}
