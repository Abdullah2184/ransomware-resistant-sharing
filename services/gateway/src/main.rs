mod auth;
mod config;
mod routes;
mod store;

use std::{error::Error, net::TcpListener};

use chain_adapter::BesuClient;
use config::GatewayConfig;
use metadata_store::PostgresStore;
use routes::{AppState, router};
use store::GatewayStore;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = GatewayConfig::from_env().map_err(std::io::Error::other)?;
    let chain = BesuClient::new(&config.besu_rpc_url)?;
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
    eprintln!("gateway listening on {address}");

    axum::serve(
        listener,
        router(AppState::new(
            GatewayStore::new(metadata.pool().clone()),
            chain,
            config,
        ))
        .into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        eprintln!("gateway could not register shutdown signal: {error}");
    }
}
