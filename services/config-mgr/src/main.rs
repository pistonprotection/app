//! PistonProtection Configuration Manager Service
//!
//! Manages configuration distribution to worker nodes and handles
//! configuration versioning and updates.

use pistonprotection_common::{config::Config, telemetry};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info};

mod config_store;
mod distributor;
mod handlers;

const SERVICE_NAME: &str = "config-mgr";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration
    let config = Config::load(SERVICE_NAME)?;

    // Initialize telemetry
    telemetry::init(SERVICE_NAME, &config.telemetry)?;

    info!(
        "Starting {} service v{}",
        SERVICE_NAME,
        env!("CARGO_PKG_VERSION")
    );

    // Initialize database connection
    let db_pool = if let Some(ref db_config) = config.database {
        Some(pistonprotection_common::db::create_pool(db_config).await?)
    } else {
        panic!("Database configuration is required for config-mgr");
    };

    // Initialize Redis connection
    let redis_pool = if let Some(ref redis_config) = config.redis {
        Some(pistonprotection_common::redis::create_pool(redis_config).await?)
    } else {
        info!("No Redis configuration provided, running without pub/sub");
        None
    };

    // Create config store
    let store = Arc::new(config_store::ConfigStore::new(
        db_pool.clone().unwrap(),
        redis_pool.clone(),
    ));

    // Create distributor
    let distributor = Arc::new(distributor::ConfigDistributor::new(
        store.clone(),
        redis_pool.clone(),
    ));

    // Create shared state
    let state = handlers::AppState {
        store,
        distributor,
        config: Arc::new(config.clone()),
    };

    // Start HTTP server
    let http_addr: SocketAddr = config.http_addr().parse()?;
    let http_server = handlers::create_router(state.clone());
    let http_handle = tokio::spawn(async move {
        info!("HTTP server listening on {}", http_addr);
        let listener = tokio::net::TcpListener::bind(http_addr).await.unwrap();
        axum::serve(listener, http_server).await.unwrap();
    });

    // Start gRPC server
    let grpc_addr: SocketAddr = config.grpc_addr().parse()?;
    let grpc_server = handlers::create_grpc_server(state.clone()).await?;
    let grpc_handle = tokio::spawn(async move {
        info!("gRPC server listening on {}", grpc_addr);
        if let Err(e) = grpc_server.serve(grpc_addr).await {
            error!("gRPC server error: {}", e);
        }
    });

    // Start config distribution background task
    let dist_state = state.clone();
    let dist_handle = tokio::spawn(async move {
        if let Err(e) = dist_state.distributor.run_distribution_loop().await {
            error!("Distribution loop error: {}", e);
        }
    });

    // Wait for shutdown signal
    shutdown_signal().await;
    info!("Shutting down...");

    // Cleanup
    telemetry::shutdown();

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
