//! PistonProtection Authentication Service
//!
//! Provides authentication, authorization, user management, organization management,
//! API key handling, and role-based access control (RBAC) for the PistonProtection platform.

use pistonprotection_common::{config::Config, telemetry};
use std::net::SocketAddr;
use tokio::signal;
use tracing::{error, info};

mod config;
mod db;
mod handlers;
mod models;
mod services;

use config::AuthConfig;
use services::AppState;

const SERVICE_NAME: &str = "auth";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load base configuration
    let base_config = Config::load(SERVICE_NAME)?;

    // Load auth-specific configuration
    let auth_config = AuthConfig::load()?;

    // Initialize telemetry
    telemetry::init(SERVICE_NAME, &base_config.telemetry)?;

    info!(
        "Starting {} service v{}",
        SERVICE_NAME,
        env!("CARGO_PKG_VERSION")
    );

    // Initialize database connection (required for auth service)
    let db_pool = match &base_config.database {
        Some(db_config) => {
            let pool = pistonprotection_common::db::create_pool(db_config).await?;
            // Run migrations
            db::run_migrations(&pool).await?;
            pool
        }
        None => {
            error!("Database configuration is required for auth service");
            return Err("Database configuration required".into());
        }
    };

    // Initialize Redis connection (required for session caching)
    let redis_pool = match &base_config.redis {
        Some(redis_config) => pistonprotection_common::redis::create_pool(redis_config).await?,
        None => {
            error!("Redis configuration is required for auth service");
            return Err("Redis configuration required".into());
        }
    };

    // Create shared state
    let app_state = AppState::new(db_pool, redis_pool, base_config.clone(), auth_config);

    // Start HTTP server (health checks, metrics)
    let http_addr: SocketAddr = base_config.http_addr().parse()?;
    let http_server = handlers::http::create_router(app_state.clone());
    let _http_handle = tokio::spawn(async move {
        info!("HTTP server listening on {}", http_addr);
        let listener = match tokio::net::TcpListener::bind(http_addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to bind HTTP server: {}", e);
                return;
            }
        };
        if let Err(e) = axum::serve(listener, http_server).await {
            error!("HTTP server error: {}", e);
        }
    });

    // Start gRPC server
    let grpc_addr: SocketAddr = base_config.grpc_addr().parse()?;
    let grpc_server = handlers::grpc::create_server(app_state.clone()).await?;
    let _grpc_handle = tokio::spawn(async move {
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
