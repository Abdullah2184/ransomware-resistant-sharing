use std::{collections::HashMap, env, error::Error, fmt, time::Duration};

use sqlx::{
    PgPool, Row,
    migrate::{MigrationType, Migrator},
    postgres::PgPoolOptions,
};

const DEFAULT_MAX_CONNECTIONS: u32 = 10;
const MAX_ALLOWED_CONNECTIONS: u32 = 100;
const DEFAULT_ACQUIRE_TIMEOUT_SECONDS: u64 = 5;
const MAX_ACQUIRE_TIMEOUT_SECONDS: u64 = 60;
static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Controls how services handle schema migrations on startup
/// (`docs/specifications/TECHNICAL_SPECIFICATION.md` §13).
///
/// Defaults to [`MigrationMode::Verify`] so least-privilege runtime roles
/// (`rrfs_gateway`, `rrfs_indexer`) validate schema/checksum state read-only
/// without requiring DDL privileges.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MigrationMode {
    Run,
    #[default]
    Verify,
    Off,
}

impl MigrationMode {
    pub fn parse(raw: &str) -> Result<Self, MetadataStoreError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "run" => Ok(Self::Run),
            "verify" => Ok(Self::Verify),
            "off" => Ok(Self::Off),
            _ => Err(MetadataStoreError::InvalidConfig(
                "DATABASE_MIGRATION_MODE must be one of: run, verify, off".to_owned(),
            )),
        }
    }

    pub fn from_env() -> Result<Self, MetadataStoreError> {
        match env::var("DATABASE_MIGRATION_MODE") {
            Ok(raw) if !raw.trim().is_empty() => Self::parse(&raw),
            Ok(_) | Err(env::VarError::NotPresent) => Ok(Self::Verify),
            Err(env::VarError::NotUnicode(_)) => Err(MetadataStoreError::InvalidConfig(
                "DATABASE_MIGRATION_MODE contains invalid Unicode".to_owned(),
            )),
        }
    }
}

/// Connection pool tuning parameters for [`PostgresStore`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgresPoolConfig {
    pub max_connections: u32,
    pub acquire_timeout: Duration,
}

impl Default for PostgresPoolConfig {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            acquire_timeout: Duration::from_secs(DEFAULT_ACQUIRE_TIMEOUT_SECONDS),
        }
    }
}

impl PostgresPoolConfig {
    pub fn from_env() -> Result<Self, MetadataStoreError> {
        let max_connections = match env::var("DATABASE_MAX_CONNECTIONS") {
            Ok(raw) if !raw.trim().is_empty() => {
                let parsed = raw.trim().parse::<u32>().map_err(|_| {
                    MetadataStoreError::InvalidConfig(
                        "DATABASE_MAX_CONNECTIONS must be a positive integer".to_owned(),
                    )
                })?;
                if parsed == 0 || parsed > MAX_ALLOWED_CONNECTIONS {
                    return Err(MetadataStoreError::InvalidConfig(format!(
                        "DATABASE_MAX_CONNECTIONS must be between 1 and {MAX_ALLOWED_CONNECTIONS}"
                    )));
                }
                parsed
            }
            Ok(_) | Err(env::VarError::NotPresent) => DEFAULT_MAX_CONNECTIONS,
            Err(env::VarError::NotUnicode(_)) => {
                return Err(MetadataStoreError::InvalidConfig(
                    "DATABASE_MAX_CONNECTIONS contains invalid Unicode".to_owned(),
                ));
            }
        };

        let acquire_timeout_secs = match env::var("DATABASE_ACQUIRE_TIMEOUT_SECONDS") {
            Ok(raw) if !raw.trim().is_empty() => {
                let parsed = raw.trim().parse::<u64>().map_err(|_| {
                    MetadataStoreError::InvalidConfig(
                        "DATABASE_ACQUIRE_TIMEOUT_SECONDS must be a positive integer".to_owned(),
                    )
                })?;
                if parsed == 0 || parsed > MAX_ACQUIRE_TIMEOUT_SECONDS {
                    return Err(MetadataStoreError::InvalidConfig(format!(
                        "DATABASE_ACQUIRE_TIMEOUT_SECONDS must be between 1 and {MAX_ACQUIRE_TIMEOUT_SECONDS}"
                    )));
                }
                parsed
            }
            Ok(_) | Err(env::VarError::NotPresent) => DEFAULT_ACQUIRE_TIMEOUT_SECONDS,
            Err(env::VarError::NotUnicode(_)) => {
                return Err(MetadataStoreError::InvalidConfig(
                    "DATABASE_ACQUIRE_TIMEOUT_SECONDS contains invalid Unicode".to_owned(),
                ));
            }
        };

        Ok(Self {
            max_connections,
            acquire_timeout: Duration::from_secs(acquire_timeout_secs),
        })
    }
}

/// Errors returned during PostgreSQL pool setup or migration verification.
#[derive(Debug)]
pub enum MetadataStoreError {
    InvalidConfig(String),
    Database(sqlx::Error),
    Migrate(sqlx::migrate::MigrateError),
    MissingMigration(i64),
    FailedMigration(i64),
    ChecksumMismatch(i64),
}

impl fmt::Display for MetadataStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(formatter, "invalid database config: {message}"),
            Self::Database(error) => write!(formatter, "database error: {error}"),
            Self::Migrate(error) => write!(formatter, "migration error: {error}"),
            Self::MissingMigration(version) => write!(
                formatter,
                "required database migration {version} is not applied; run migrations as rrfs_migrator or set DATABASE_MIGRATION_MODE=run"
            ),
            Self::FailedMigration(version) => {
                write!(formatter, "database migration {version} did not succeed")
            }
            Self::ChecksumMismatch(version) => write!(
                formatter,
                "database migration {version} checksum does not match compiled migration"
            ),
        }
    }
}

impl Error for MetadataStoreError {}

impl From<sqlx::Error> for MetadataStoreError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

impl From<sqlx::migrate::MigrateError> for MetadataStoreError {
    fn from(error: sqlx::migrate::MigrateError) -> Self {
        Self::Migrate(error)
    }
}

/// PostgreSQL-backed metadata store.
///
/// Owns a SQLx connection pool shared by database operations.
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    /// Establishes a connection pool to PostgreSQL using default pool settings.
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        Self::connect_with_config(database_url, PostgresPoolConfig::default()).await
    }

    /// Establishes a connection pool to PostgreSQL with explicit pool tuning.
    pub async fn connect_with_config(
        database_url: &str,
        config: PostgresPoolConfig,
    ) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(config.acquire_timeout)
            .connect(database_url)
            .await?;

        Ok(Self { pool })
    }

    /// Checks whether the database can execute a simple query.
    pub async fn ping(&self) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;

        Ok(())
    }

    /// Applies the additive, versioned metadata and indexer schema migrations.
    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        MIGRATOR.run(&self.pool).await
    }

    /// Verifies read-only that all embedded migrations are applied in
    /// `_sqlx_migrations` with `success = TRUE` and exact checksum equality.
    ///
    /// Requires only `SELECT` on `_sqlx_migrations`, allowing least-privilege
    /// runtime roles (`rrfs_gateway`, `rrfs_indexer`) to fail closed on schema
    /// drift without needing DDL privileges.
    pub async fn verify_migrations(&self) -> Result<(), MetadataStoreError> {
        let rows =
            sqlx::query("SELECT version, checksum, success FROM _sqlx_migrations ORDER BY version")
                .fetch_all(&self.pool)
                .await?;

        let mut applied: HashMap<i64, (Vec<u8>, bool)> = HashMap::with_capacity(rows.len());
        for row in rows {
            let version: i64 = row.try_get("version")?;
            let checksum: Vec<u8> = row.try_get("checksum")?;
            let success: bool = row.try_get("success")?;
            applied.insert(version, (checksum, success));
        }

        for migration in MIGRATOR
            .iter()
            .filter(|migration| migration.migration_type != MigrationType::ReversibleDown)
        {
            let Some((recorded_checksum, success)) = applied.get(&migration.version) else {
                return Err(MetadataStoreError::MissingMigration(migration.version));
            };
            if !*success {
                return Err(MetadataStoreError::FailedMigration(migration.version));
            }
            if recorded_checksum.as_slice() != migration.checksum.as_ref() {
                return Err(MetadataStoreError::ChecksumMismatch(migration.version));
            }
        }
        Ok(())
    }

    /// Executes the configured startup [`MigrationMode`].
    pub async fn apply_migration_mode(
        &self,
        mode: MigrationMode,
    ) -> Result<(), MetadataStoreError> {
        match mode {
            MigrationMode::Run => {
                self.migrate().await?;
                Ok(())
            }
            MigrationMode::Verify => self.verify_migrations().await,
            MigrationMode::Off => Ok(()),
        }
    }

    /// Gives infrastructure services access to the shared pool for repository
    /// operations without transferring ownership of the pool.
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_mode_parses_known_values_and_rejects_unknown() {
        assert_eq!(MigrationMode::parse("run").unwrap(), MigrationMode::Run);
        assert_eq!(
            MigrationMode::parse("VERIFY").unwrap(),
            MigrationMode::Verify
        );
        assert_eq!(MigrationMode::parse(" off ").unwrap(), MigrationMode::Off);
        assert!(MigrationMode::parse("auto").is_err());
        assert_eq!(MigrationMode::default(), MigrationMode::Verify);
    }

    #[test]
    fn embedded_migrator_contains_expected_sequential_versions() {
        let versions: Vec<i64> = MIGRATOR.iter().map(|m| m.version).collect();
        assert_eq!(versions, vec![1, 2, 3, 4, 5, 6, 7]);
    }
}
