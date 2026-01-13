//! PistonProtection Configuration Manager Service
//!
//! Manages configuration distribution to worker nodes and handles
//! configuration versioning and updates.

use pistonprotection_common::{config::Config, error::Error, telemetry};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::watch;
use tracing::{error, info, warn};

mod config_store;
mod distributor;
mod handlers;

#[cfg(test)]
mod tests;

const SERVICE_NAME: &str = "config-mgr";

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    // Load configuration
    let config = Config::load(SERVICE_NAME).map_err(|e| Box::new(e) as BoxError)?;

    // Initialize telemetry
    telemetry::init(SERVICE_NAME, &config.telemetry).map_err(|e| Box::new(e) as BoxError)?;

    info!(
        service = SERVICE_NAME,
        version = env!("CARGO_PKG_VERSION"),
        "Starting service"
    );

    // Initialize database connection (required for config-mgr)
    let db_pool = match &config.database {
        Some(db_config) => {
            info!("Initializing database connection pool");
            pistonprotection_common::db::create_pool(db_config)
                .await
                .map_err(|e| Box::new(e) as BoxError)?
        }
        None => {
            error!("Database configuration is required for config-mgr");
            return Err(Box::new(Error::Internal(
                "Database configuration is required for config-mgr".to_string(),
            )) as BoxError);
        }
    };

    // Initialize Redis connection (optional but recommended)
    let redis_pool = match &config.redis {
        Some(redis_config) => {
            info!("Initializing Redis connection pool");
            match pistonprotection_common::redis::create_pool(redis_config).await {
                Ok(pool) => {
                    info!("Redis connection pool initialized successfully");
                    Some(pool)
                }
                Err(e) => {
                    warn!(error = %e, "Failed to initialize Redis, running without pub/sub");
                    None
                }
            }
        }
        None => {
            info!("No Redis configuration provided, running without pub/sub");
            None
        }
    };

    // Create config store
    let store = Arc::new(config_store::ConfigStore::new(
        db_pool.clone(),
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

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Start HTTP server
    let http_addr: SocketAddr = config
        .http_addr()
        .parse()
        .map_err(|e: std::net::AddrParseError| Box::new(e) as BoxError)?;
    let http_server = handlers::create_router(state.clone());
    let http_shutdown_rx = shutdown_rx.clone();
    let http_handle = tokio::spawn(async move {
        info!(addr = %http_addr, "Starting HTTP server");
        match tokio::net::TcpListener::bind(http_addr).await {
            Ok(listener) => {
                info!(addr = %http_addr, "HTTP server listening");
                let shutdown = async move {
                    let mut rx = http_shutdown_rx;
                    while !*rx.borrow() {
                        if rx.changed().await.is_err() {
                            break;
                        }
                    }
                };
                if let Err(e) = axum::serve(listener, http_server)
                    .with_graceful_shutdown(shutdown)
                    .await
                {
                    error!(error = %e, "HTTP server error");
                }
            }
            Err(e) => {
                error!(error = %e, addr = %http_addr, "Failed to bind HTTP server");
            }
        }
    });

    // Start gRPC server
    let grpc_addr: SocketAddr = config
        .grpc_addr()
        .parse()
        .map_err(|e: std::net::AddrParseError| Box::new(e) as BoxError)?;
    let grpc_server = handlers::create_grpc_server(state.clone()).await?;
    let grpc_shutdown_rx = shutdown_rx.clone();
    let grpc_handle = tokio::spawn(async move {
        info!(addr = %grpc_addr, "Starting gRPC server");
        let shutdown = async move {
            let mut rx = grpc_shutdown_rx;
            while !*rx.borrow() {
                if rx.changed().await.is_err() {
                    break;
                }
            }
        };
        if let Err(e) = grpc_server.serve_with_shutdown(grpc_addr, shutdown).await {
            error!(error = %e, "gRPC server error");
        }
    });

    // Start config distribution background task
    let dist_state = state.clone();
    let mut dist_shutdown_rx = shutdown_rx.clone();
    let dist_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                result = dist_state.distributor.run_distribution_loop() => {
                    if let Err(e) = result {
                        error!(error = %e, "Distribution loop error");
                    }
                    break;
                }
                _ = dist_shutdown_rx.changed() => {
                    if *dist_shutdown_rx.borrow() {
                        info!("Distribution loop shutting down");
                        break;
                    }
                }
            }
        }
    });

    // Wait for shutdown signal
    shutdown_signal().await;
    info!("Shutdown signal received, initiating graceful shutdown...");

    // Signal shutdown to all tasks
    if let Err(e) = shutdown_tx.send(true) {
        warn!(error = %e, "Failed to send shutdown signal");
    }

    // Wait for tasks with timeout
    let shutdown_timeout = tokio::time::Duration::from_secs(30);

    tokio::select! {
        _ = http_handle => info!("HTTP server shutdown complete"),
        _ = tokio::time::sleep(shutdown_timeout) => warn!("HTTP server shutdown timed out"),
    }

    tokio::select! {
        _ = grpc_handle => info!("gRPC server shutdown complete"),
        _ = tokio::time::sleep(shutdown_timeout) => warn!("gRPC server shutdown timed out"),
    }

    dist_handle.abort();

    // Cleanup telemetry
    telemetry::shutdown();
    info!("Shutdown complete");

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        match signal::ctrl_c().await {
            Ok(()) => info!("Received Ctrl+C signal"),
            Err(e) => error!(error = %e, "Failed to listen for Ctrl+C signal"),
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
                info!("Received SIGTERM signal");
            }
            Err(e) => error!(error = %e, "Failed to listen for SIGTERM signal"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
