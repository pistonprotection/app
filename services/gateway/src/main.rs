//! PistonProtection Gateway Service
//!
//! The main API gateway that handles all external requests and routes them
//! to the appropriate internal services.

use pistonprotection_common::{config::Config, telemetry};
use std::net::SocketAddr;
use tokio::signal;
use tracing::{error, info};

mod handlers;
mod middleware;
mod services;

const SERVICE_NAME: &str = "gateway";

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
        info!("No database configuration provided, running without database");
        None
    };

    // Initialize Redis connection
    let redis_pool = if let Some(ref redis_config) = config.redis {
        Some(pistonprotection_common::redis::create_pool(redis_config).await?)
    } else {
        info!("No Redis configuration provided, running without cache");
        None
    };

    // Create shared state
    let app_state = services::AppState::new(db_pool, redis_pool, config.clone());

    // Start HTTP server (health checks, metrics)
    let http_addr: SocketAddr = config.http_addr().parse()?;
    let http_server = handlers::http::create_router(app_state.clone());
    let http_handle = tokio::spawn(async move {
        info!("HTTP server listening on {}", http_addr);
        let listener = tokio::net::TcpListener::bind(http_addr).await.unwrap();
        axum::serve(listener, http_server).await.unwrap();
    });

    // Start gRPC server
    let grpc_addr: SocketAddr = config.grpc_addr().parse()?;
    let grpc_server = handlers::grpc::create_server(app_state.clone()).await?;
    let grpc_handle = tokio::spawn(async move {
        info!("gRPC server listening on {}", grpc_addr);
        if let Err(e) = grpc_server.serve(grpc_addr).await {
            error!("gRPC server error: {}", e);
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
