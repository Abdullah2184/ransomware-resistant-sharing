mod auth;
mod config;
mod maintenance;
mod ports;
mod routes;
mod store;

use std::{env, error::Error, net::TcpListener, sync::Arc, time::Duration};

use chain_adapter::{
    BesuClient, DevelopmentRelayerSigner, RelayerConfig, RelayerStartupPolicy, TransactionRelayer,
};
use config::{GatewayConfig, RuntimeEnvironment};
use ipfs_adapter::{IpfsClusterStore, IpfsConfig};
use metadata_store::{MigrationMode, PostgresPoolConfig, PostgresStore};
use ports::BesuContractRelayer;
use routes::{AppState, router};
use store::GatewayStore;
use tokio::sync::watch;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = GatewayConfig::from_env().map_err(std::io::Error::other)?;
    let chain = BesuClient::new(&config.besu_rpc_url)?;
    let blob_store = IpfsClusterStore::new(IpfsConfig::from_env()?)?;
    let connected_chain_id = chain.chain_id().await?;
    if connected_chain_id != config.chain_id {
        return Err(std::io::Error::other("configured chain ID does not match Besu").into());
    }
    let pool_config = PostgresPoolConfig::from_env()?;
    let migration_mode = MigrationMode::from_env()?;
    let metadata = PostgresStore::connect_with_config(&config.database_url, pool_config).await?;
    metadata.apply_migration_mode(migration_mode).await?;
    let listener = TcpListener::bind(config.bind)?;
    listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(listener)?;
    let address = listener.local_addr()?;

    let relayer = build_optional_relayer(&config)?;
    let storage_health_interval = Duration::from_secs(config.storage_health_interval_seconds);
    let orphan_retention_seconds = config.orphan_retention_seconds;
    let mut state = AppState::new(
        GatewayStore::new(metadata.pool().clone()),
        chain,
        blob_store,
        config,
    );
    if let Some(relayer) = relayer {
        state = state.with_relayer(relayer);
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let health_monitor = maintenance::spawn_storage_health_monitor(
        Arc::clone(&state.blob_store),
        storage_health_interval,
        shutdown_rx.clone(),
    );
    let pending_tx_reconciler = maintenance::spawn_pending_transaction_reconciler(
        state.clone(),
        Duration::from_secs(15),
        shutdown_rx.clone(),
    );
    let orphan_cleaner = maintenance::spawn_orphan_blob_cleaner(
        state.clone(),
        orphan_retention_seconds,
        Duration::from_secs(orphan_retention_seconds.min(300)),
        shutdown_rx,
    );
    eprintln!("gateway listening on {address}");

    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    })
    .await?;
    let _ = health_monitor.await;
    let _ = pending_tx_reconciler.await;
    let _ = orphan_cleaner.await;
    Ok(())
}

fn build_optional_relayer(
    config: &GatewayConfig,
) -> Result<Option<BesuContractRelayer>, Box<dyn Error>> {
    let allow_unsafe_dev = env::var("GATEWAY_ALLOW_UNSAFE_DEV_RELAYER")
        .map(|value| value == "true")
        .unwrap_or(false);
    let Some(signer) = DevelopmentRelayerSigner::from_env_var("GATEWAY_RELAYER_UNSAFE_DEV_KEY")?
    else {
        return Ok(None);
    };
    if config.environment == RuntimeEnvironment::Production && allow_unsafe_dev {
        return Err(std::io::Error::other(
            "GATEWAY_ALLOW_UNSAFE_DEV_RELAYER cannot be enabled when RRDS_ENV=production",
        )
        .into());
    }
    let policy = if allow_unsafe_dev {
        RelayerStartupPolicy::UnsafeDevelopment
    } else {
        RelayerStartupPolicy::Production
    };
    let signer = Arc::new(signer);
    let mut relayer_config = RelayerConfig::local_default(config.chain_id);
    relayer_config.default_gas_limit = config.default_tx_gas_limit;
    relayer_config.max_gas_limit = relayer_config
        .max_gas_limit
        .max(config.default_tx_gas_limit);
    relayer_config.confirmation_timeout =
        Duration::from_secs(config.transaction_confirmation_timeout_seconds);
    let relayer_client = BesuClient::new(&config.besu_rpc_url)?;
    let tx_relayer = TransactionRelayer::new(relayer_client, signer, policy, relayer_config)?;
    Ok(Some(BesuContractRelayer::new(
        tx_relayer,
        config.file_registry,
        config.access_governance,
        config.default_tx_gas_limit,
    )))
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        eprintln!("gateway could not register shutdown signal: {error}");
    }
}
