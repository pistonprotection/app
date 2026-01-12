//! PistonProtection Worker Service
//!
//! Runs on edge nodes and manages eBPF/XDP programs for packet filtering.

use pistonprotection_common::{config::Config, telemetry};
use std::net::SocketAddr;
use tokio::signal;
use tracing::{error, info, warn};

mod ebpf;
mod handlers;
mod protocol;

const SERVICE_NAME: &str = "worker";

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

    // Check for root privileges (required for eBPF)
    if !nix::unistd::geteuid().is_root() {
        warn!("Worker is not running as root - eBPF programs may fail to load");
    }

    // Discover network interfaces
    let interfaces = ebpf::interface::discover_interfaces()?;
    info!("Discovered {} network interfaces", interfaces.len());
    for iface in &interfaces {
        info!("  - {} ({})", iface.name, iface.ip_address.map(|ip| ip.to_string()).unwrap_or_default());
    }

    // Initialize eBPF loader
    let ebpf_loader = ebpf::loader::EbpfLoader::new()?;

    // Initialize Redis connection for config updates
    let redis_pool = if let Some(ref redis_config) = config.redis {
        Some(pistonprotection_common::redis::create_pool(redis_config).await?)
    } else {
        warn!("No Redis configuration - running in standalone mode");
        None
    };

    // Create worker state
    let state = handlers::WorkerState::new(
        ebpf_loader,
        redis_pool,
        config.clone(),
        interfaces,
    );

    // Start HTTP server (health checks, metrics)
    let http_addr: SocketAddr = config.http_addr().parse()?;
    let http_server = handlers::http::create_router(state.clone());
    let http_handle = tokio::spawn(async move {
        info!("HTTP server listening on {}", http_addr);
        let listener = tokio::net::TcpListener::bind(http_addr).await.unwrap();
        axum::serve(listener, http_server).await.unwrap();
    });

    // Connect to control plane and register
    let control_plane_addr = std::env::var("PISTON_CONTROL_PLANE_ADDR")
        .unwrap_or_else(|_| "http://gateway:50051".to_string());

    info!("Connecting to control plane at {}", control_plane_addr);

    // Start the worker loop
    let worker_handle = tokio::spawn(async move {
        if let Err(e) = handlers::worker_loop(state, &control_plane_addr).await {
            error!("Worker loop error: {}", e);
        }
    });

    // Wait for shutdown signal
    shutdown_signal().await;
    info!("Shutting down...");

    // Cleanup eBPF programs
    // Note: Programs are automatically detached when the loader is dropped

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
