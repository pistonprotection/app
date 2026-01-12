//! PistonProtection Gateway Service
//!
//! The main API gateway that handles all external requests and routes them
//! to the appropriate internal services.

use pistonprotection_common::{config::Config, telemetry};
use std::net::SocketAddr;
use tokio::signal;
use tokio::sync::watch;
use tracing::{error, info, warn};

mod handlers;
mod middleware;
mod services;

const SERVICE_NAME: &str = "gateway";

/// Application error type for main
#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    #[error("Initialization error: {0}")]
    Init(#[from] pistonprotection_common::error::Error),

    #[error("Database initialization error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Redis initialization error: {0}")]
    Redis(String),

    #[error("Address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    #[error("gRPC server error: {0}")]
    Grpc(#[from] Box<dyn std::error::Error + Send + Sync>),

    #[error("HTTP server error: {0}")]
    Http(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    // Load configuration
    let config = Config::load(SERVICE_NAME)?;

    // Initialize telemetry
    telemetry::init(SERVICE_NAME, &config.telemetry)?;

    info!(
        service = SERVICE_NAME,
        version = env!("CARGO_PKG_VERSION"),
        "Starting service"
    );

    // Initialize database connection
    let db_pool = match &config.database {
        Some(db_config) => {
            info!("Initializing database connection pool");
            match pistonprotection_common::db::create_pool(db_config).await {
                Ok(pool) => {
                    info!("Database connection pool initialized successfully");
                    Some(pool)
                }
                Err(e) => {
                    error!(error = %e, "Failed to initialize database connection pool");
                    return Err(AppError::Database(e));
                }
            }
        }
        None => {
            info!("No database configuration provided, running without database");
            None
        }
    };

    // Initialize Redis connection
    let redis_pool = match &config.redis {
        Some(redis_config) => {
            info!("Initializing Redis connection pool");
            match pistonprotection_common::redis::create_pool(redis_config).await {
                Ok(pool) => {
                    info!("Redis connection pool initialized successfully");
                    Some(pool)
                }
                Err(e) => {
                    error!(error = %e, "Failed to initialize Redis connection pool");
                    return Err(AppError::Redis(e.to_string()));
                }
            }
        }
        None => {
            info!("No Redis configuration provided, running without cache");
            None
        }
    };

    // Create shared state
    let app_state = services::AppState::new(db_pool, redis_pool, config.clone());

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Start HTTP server (health checks, metrics)
    let http_addr: SocketAddr = config.http_addr().parse()?;
    let http_server = handlers::http::create_router(app_state.clone());
    let http_shutdown_rx = shutdown_rx.clone();

    let http_handle = tokio::spawn(async move {
        info!(addr = %http_addr, "Starting HTTP server");

        let listener = match tokio::net::TcpListener::bind(http_addr).await {
            Ok(l) => l,
            Err(e) => {
                error!(error = %e, addr = %http_addr, "Failed to bind HTTP server");
                return Err(e);
            }
        };

        info!(addr = %http_addr, "HTTP server listening");

        // Create a graceful shutdown future
        let shutdown = async move {
            let mut rx = http_shutdown_rx;
            while !*rx.borrow() {
                if rx.changed().await.is_err() {
                    break;
                }
            }
        };

        axum::serve(listener, http_server)
            .with_graceful_shutdown(shutdown)
            .await
            .map_err(|e| {
                error!(error = %e, "HTTP server error");
                e
            })?;

        info!("HTTP server shut down gracefully");
        Ok(())
    });

    // Start gRPC server
    let grpc_addr: SocketAddr = config.grpc_addr().parse()?;
    let grpc_server = handlers::grpc::create_server(app_state.clone()).await?;
    let grpc_shutdown_rx = shutdown_rx.clone();

    let grpc_handle = tokio::spawn(async move {
        info!(addr = %grpc_addr, "Starting gRPC server");

        // Create a shutdown signal for gRPC
        let shutdown = async move {
            let mut rx = grpc_shutdown_rx;
            while !*rx.borrow() {
                if rx.changed().await.is_err() {
                    break;
                }
            }
        };

        grpc_server
            .serve_with_shutdown(grpc_addr, shutdown)
            .await
            .map_err(|e| {
                error!(error = %e, "gRPC server error");
                e
            })?;

        info!("gRPC server shut down gracefully");
        Ok::<_, tonic::transport::Error>(())
    });

    // Wait for shutdown signal
    shutdown_signal().await;
    info!("Shutdown signal received, initiating graceful shutdown...");

    // Signal all servers to shut down
    if let Err(e) = shutdown_tx.send(true) {
        warn!(error = %e, "Failed to send shutdown signal");
    }

    // Wait for servers to shut down with timeout
    let shutdown_timeout = tokio::time::Duration::from_secs(30);

    tokio::select! {
        result = http_handle => {
            match result {
                Ok(Ok(())) => info!("HTTP server shutdown complete"),
                Ok(Err(e)) => error!(error = %e, "HTTP server encountered error during shutdown"),
                Err(e) => error!(error = %e, "HTTP server task panicked"),
            }
        }
        _ = tokio::time::sleep(shutdown_timeout) => {
            warn!("HTTP server shutdown timed out");
        }
    }

    tokio::select! {
        result = grpc_handle => {
            match result {
                Ok(Ok(())) => info!("gRPC server shutdown complete"),
                Ok(Err(e)) => error!(error = %e, "gRPC server encountered error during shutdown"),
                Err(e) => error!(error = %e, "gRPC server task panicked"),
            }
        }
        _ = tokio::time::sleep(shutdown_timeout) => {
            warn!("gRPC server shutdown timed out");
        }
    }

    // Cleanup telemetry
    telemetry::shutdown();
    info!("Shutdown complete");

    Ok(())
}

/// Wait for shutdown signals (Ctrl+C or SIGTERM)
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
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}
