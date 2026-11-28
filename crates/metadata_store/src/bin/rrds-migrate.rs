//! Standalone SQLx migration runner for least-privilege RRDS deployments.
//!
//! Run as the `rrfs_migrator` role before starting `rrfs_gateway` and
//! `rrfs_indexer` in `DATABASE_MIGRATION_MODE=verify` mode:
//!   `DATABASE_URL=postgres://rrfs_migrator:...@host:5432/rrfs_dev rrds-migrate run`
//!   `DATABASE_URL=postgres://rrfs_gateway:...@host:5432/rrfs_dev rrds-migrate verify`

use std::{env, process::ExitCode};

use metadata_store::{MigrationMode, PostgresPoolConfig, PostgresStore};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("rrds-migrate: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<String, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let mode = match args.first().map(String::as_str) {
        Some("run") => MigrationMode::Run,
        Some("verify") | None => MigrationMode::Verify,
        Some("--help" | "-h" | "help") => {
            return Ok(
                "usage: rrds-migrate [run|verify]\n  run    apply embedded SQLx migrations using DATABASE_URL\n  verify validate all compiled migrations and checksums read-only (default)"
                    .to_owned(),
            );
        }
        Some(other) => {
            return Err(format!(
                "unknown subcommand `{other}` (expected `run` or `verify`)"
            ));
        }
    };

    let database_url =
        env::var("DATABASE_URL").map_err(|_| "DATABASE_URL must be configured".to_owned())?;
    let pool_config = PostgresPoolConfig::from_env().map_err(|err| err.to_string())?;
    let store = PostgresStore::connect_with_config(&database_url, pool_config)
        .await
        .map_err(|err| err.to_string())?;
    store
        .apply_migration_mode(mode)
        .await
        .map_err(|err| err.to_string())?;

    match mode {
        MigrationMode::Run => Ok("migrations applied and verified".to_owned()),
        MigrationMode::Verify => Ok("schema migrations verified".to_owned()),
        MigrationMode::Off => Ok("migration check skipped".to_owned()),
    }
}
