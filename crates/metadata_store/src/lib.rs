//! PostgreSQL-backed metadata storage adapter.

pub mod postgres;

pub use postgres::{MetadataStoreError, MigrationMode, PostgresPoolConfig, PostgresStore};
