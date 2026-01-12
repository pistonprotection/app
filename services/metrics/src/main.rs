//! PistonProtection Metrics Collector Service
//!
//! Collects and aggregates metrics from worker nodes and provides
//! APIs for querying metrics data.

use pistonprotection_common::{config::Config, telemetry};
use std::net::SocketAddr;
use tokio::signal;
use tracing::{error, info};

const SERVICE_NAME: &str = "metrics";

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
        info!("No database configuration, running without persistence");
        None
    };

    // Initialize Redis connection
    let redis_pool = if let Some(ref redis_config) = config.redis {
        Some(pistonprotection_common::redis::create_pool(redis_config).await?)
    } else {
        None
    };

    info!("Metrics collector ready");

    // Wait for shutdown signal
    shutdown_signal().await;
    info!("Shutting down...");

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
