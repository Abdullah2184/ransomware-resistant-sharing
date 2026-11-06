use std::time::Duration;

use sqlx::{PgPool, postgres::PgPoolOptions};

const MAX_CONNECTIONS: u32 = 5;
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

/// PostgreSQL-backed metadata store.
///
/// Owns a SQLx connection pool shared by database operations.
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    /// Establishes a connection pool to PostgreSQL.
    ///
    /// The first connection is established before this method returns,
    /// so connection errors are reported during initialization.
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(MAX_CONNECTIONS)
            .acquire_timeout(ACQUIRE_TIMEOUT)
            .connect(database_url)
            .await?;

        Ok(Self { pool })
    }

    /// Checks whether the database can execute a simple query.
    pub async fn ping(&self) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;

        Ok(())
    }
}
