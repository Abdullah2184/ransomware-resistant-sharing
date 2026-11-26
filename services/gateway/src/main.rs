mod auth;
mod config;
mod ports;
mod routes;
mod store;

use std::{env, error::Error, net::TcpListener, sync::Arc};

use chain_adapter::{
    BesuClient, DevelopmentRelayerSigner, RelayerConfig, RelayerStartupPolicy, TransactionRelayer,
};
use config::GatewayConfig;
use ipfs_adapter::{IpfsClusterStore, IpfsConfig};
use metadata_store::PostgresStore;
use ports::BesuContractRelayer;
use routes::{AppState, router};
use store::GatewayStore;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = GatewayConfig::from_env().map_err(std::io::Error::other)?;
    let chain = BesuClient::new(&config.besu_rpc_url)?;
    let blob_store = IpfsClusterStore::new(IpfsConfig::from_env()?)?;
    let connected_chain_id = chain.chain_id().await?;
    if connected_chain_id != config.chain_id {
        return Err(std::io::Error::other("configured chain ID does not match Besu").into());
    }
    let metadata = PostgresStore::connect(&config.database_url).await?;
    metadata.migrate().await?;
    let listener = TcpListener::bind(config.bind)?;
    listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(listener)?;
    let address = listener.local_addr()?;

    let relayer = build_optional_relayer(&config)?;
    let mut state = AppState::new(
        GatewayStore::new(metadata.pool().clone()),
        chain,
        blob_store,
        config,
    );
    if let Some(relayer) = relayer {
        state = state.with_relayer(relayer);
    }
    eprintln!("gateway listening on {address}");

    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

fn build_optional_relayer(
    config: &GatewayConfig,
) -> Result<Option<BesuContractRelayer>, Box<dyn Error>> {
    let allow_unsafe_dev = env::var("GATEWAY_ALLOW_UNSAFE_DEV_RELAYER")
        .map(|value| value == "true")
        .unwrap_or(false);
    let dev_key = match env::var("GATEWAY_RELAYER_UNSAFE_DEV_KEY") {
        Ok(value) if !value.is_empty() => Some(value),
        Ok(_) | Err(env::VarError::NotPresent) => None,
        Err(env::VarError::NotUnicode(_)) => {
            return Err(std::io::Error::other("GATEWAY_RELAYER_UNSAFE_DEV_KEY is invalid").into());
        }
    };
    let Some(dev_key) = dev_key else {
        return Ok(None);
    };
    let policy = if allow_unsafe_dev {
        RelayerStartupPolicy::UnsafeDevelopment
    } else {
        RelayerStartupPolicy::Production
    };
    let signer = Arc::new(DevelopmentRelayerSigner::from_hex_secret(&dev_key)?);
    let mut relayer_config = RelayerConfig::local_default(config.chain_id);
    relayer_config.default_gas_limit = config.default_tx_gas_limit;
    relayer_config.max_gas_limit = relayer_config
        .max_gas_limit
        .max(config.default_tx_gas_limit);
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
