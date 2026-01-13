//! PistonProtection Worker Service
//!
//! Runs on edge nodes and manages eBPF/XDP programs for packet filtering.
//! Connects to the control plane gateway for configuration and coordination.

use parking_lot::RwLock;
use pistonprotection_common::{config::Config, telemetry};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::watch;
use tracing::{error, info, warn};

mod config_sync;
mod control_plane;
pub mod ebpf;
mod handlers;
pub mod protocol;
pub mod routing;

// Tests temporarily disabled - requires refactoring to library crate
// #[cfg(test)]
// mod tests;

use config_sync::ConfigSyncManager;
use control_plane::{ConnectionState, ControlPlaneClient, ControlPlaneConfig};

const SERVICE_NAME: &str = "worker";

/// Worker runtime state
pub struct WorkerRuntime {
    /// eBPF loader
    pub loader: Arc<RwLock<ebpf::loader::EbpfLoader>>,
    /// Configuration sync manager
    pub config_sync: Arc<ConfigSyncManager>,
    /// Control plane client
    pub control_plane: Arc<ControlPlaneClient>,
    /// Network interfaces
    pub interfaces: Arc<Vec<ebpf::interface::NetworkInterface>>,
    /// Application configuration
    pub config: Arc<Config>,
    /// Shutdown signal sender
    shutdown_tx: watch::Sender<bool>,
    /// Shutdown signal receiver
    shutdown_rx: watch::Receiver<bool>,
}

impl WorkerRuntime {
    /// Create a new worker runtime
    pub fn new(
        loader: ebpf::loader::EbpfLoader,
        interfaces: Vec<ebpf::interface::NetworkInterface>,
        config: Config,
        control_plane_config: ControlPlaneConfig,
    ) -> Self {
        let loader = Arc::new(RwLock::new(loader));
        let interfaces = Arc::new(interfaces);

        // Create configuration sync manager
        let config_sync = Arc::new(ConfigSyncManager::new(Arc::clone(&loader)));

        // Create control plane client
        let control_plane = Arc::new(ControlPlaneClient::new(
            control_plane_config,
            interfaces.as_ref().clone(),
            Arc::clone(&loader),
            Arc::clone(&config_sync),
        ));

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        Self {
            loader,
            config_sync,
            control_plane,
            interfaces,
            config: Arc::new(config),
            shutdown_tx,
            shutdown_rx,
        }
    }

    /// Get a clone of the shutdown receiver
    pub fn shutdown_receiver(&self) -> watch::Receiver<bool> {
        self.shutdown_rx.clone()
    }

    /// Signal shutdown
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Check if worker is healthy
    pub fn is_healthy(&self) -> bool {
        // Check control plane connection (allow standalone mode)
        let is_standalone = std::env::var("PISTON_STANDALONE").is_ok();
        let cp_healthy = is_standalone || self.control_plane.is_connected();

        // Check eBPF loader (basic check - loader exists and lock can be acquired)
        let loader_healthy = {
            let _loader = self.loader.read();
            // Loader is healthy if it exists and lock can be acquired
            true
        };

        cp_healthy && loader_healthy
    }

    /// Check if worker is ready to serve traffic
    pub fn is_ready(&self) -> bool {
        let is_standalone = std::env::var("PISTON_STANDALONE").is_ok();

        if is_standalone {
            // In standalone mode, always ready
            return true;
        }

        // In connected mode, must be connected and have configuration
        self.control_plane.is_connected() && self.config_sync.current_version().is_some()
    }
}

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
        info!(
            "  - {} (index: {}, ip: {}, xdp_capable: {})",
            iface.name,
            iface.index,
            iface
                .ip_address
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "none".to_string()),
            iface.supports_xdp()
        );
    }

    // Initialize eBPF loader
    let ebpf_loader = ebpf::loader::EbpfLoader::new()?;

    // Load control plane configuration from environment
    let control_plane_config = ControlPlaneConfig::from_env();

    info!("Control plane address: {}", control_plane_config.address);
    info!(
        "Heartbeat interval: {:?}",
        control_plane_config.heartbeat_interval
    );
    info!(
        "Metrics interval: {:?}",
        control_plane_config.metrics_interval
    );

    // Create worker runtime
    let runtime = Arc::new(WorkerRuntime::new(
        ebpf_loader,
        interfaces.clone(),
        config.clone(),
        control_plane_config.clone(),
    ));

    // Initialize Redis connection for config updates (optional)
    let redis_pool = if let Some(ref redis_config) = config.redis {
        match pistonprotection_common::redis::create_pool(redis_config).await {
            Ok(pool) => {
                info!("Redis connection established");
                Some(pool)
            }
            Err(e) => {
                warn!(
                    "Failed to connect to Redis: {}. Continuing without Redis.",
                    e
                );
                None
            }
        }
    } else {
        info!("No Redis configuration - running without Redis");
        None
    };

    // Create worker state for HTTP handlers
    let worker_state = handlers::WorkerState::new(
        Arc::clone(&runtime.loader),
        Arc::clone(&runtime.config_sync),
        Arc::clone(&runtime.control_plane),
        redis_pool,
        Arc::clone(&runtime.config),
        Arc::clone(&runtime.interfaces),
    );

    // Start HTTP server (health checks, metrics)
    let http_addr: SocketAddr = config.http_addr().parse()?;
    let http_server = handlers::http::create_router(worker_state.clone());
    let http_handle = tokio::spawn(async move {
        info!(addr = %http_addr, "Starting HTTP server");
        match tokio::net::TcpListener::bind(http_addr).await {
            Ok(listener) => {
                info!(addr = %http_addr, "HTTP server listening");
                if let Err(e) = axum::serve(listener, http_server).await {
                    error!(error = %e, "HTTP server error");
                }
            }
            Err(e) => {
                error!(error = %e, addr = %http_addr, "Failed to bind HTTP server");
            }
        }
    });

    // Start control plane connection (unless in standalone mode)
    let is_standalone = std::env::var("PISTON_STANDALONE").is_ok();
    let control_plane_handle = if !is_standalone {
        let cp_client = Arc::clone(&runtime.control_plane);
        Some(tokio::spawn(async move {
            match cp_client.start().await {
                Ok(_) => {
                    info!("Control plane client started");
                }
                Err(e) => {
                    error!("Failed to start control plane client: {}", e);
                    warn!("Worker will continue in degraded mode without control plane");
                }
            }
        }))
    } else {
        info!("Running in standalone mode - control plane connection disabled");
        None
    };

    // Start periodic tasks
    let periodic_handle = spawn_periodic_tasks(Arc::clone(&runtime));

    // Start eBPF map cleanup task
    let cleanup_handle = spawn_cleanup_task(Arc::clone(&runtime));

    // Monitor control plane state changes
    let state_monitor_handle = spawn_state_monitor(Arc::clone(&runtime));

    // Wait for shutdown signal
    shutdown_signal().await;
    info!("Shutdown signal received");

    // Graceful shutdown
    info!("Initiating graceful shutdown...");

    // Signal shutdown to all tasks
    runtime.shutdown();

    // Shutdown control plane client
    if !is_standalone {
        if let Err(e) = runtime.control_plane.shutdown().await {
            warn!("Error during control plane shutdown: {}", e);
        }
    }

    // Wait for tasks to complete (with timeout)
    let shutdown_timeout = tokio::time::Duration::from_secs(10);

    tokio::select! {
        _ = tokio::time::sleep(shutdown_timeout) => {
            warn!("Shutdown timeout reached, forcing exit");
        }
        _ = async {
            periodic_handle.abort();
            cleanup_handle.abort();
            state_monitor_handle.abort();
            if let Some(h) = control_plane_handle {
                h.abort();
            }
            http_handle.abort();
        } => {
            info!("All tasks terminated");
        }
    }

    // Cleanup eBPF programs
    info!("Cleaning up eBPF programs...");
    // Note: Programs are automatically detached when the loader is dropped

    // Cleanup telemetry
    telemetry::shutdown();

    info!("Worker shutdown complete");
    Ok(())
}

/// Spawn periodic tasks (metrics collection, health checks)
fn spawn_periodic_tasks(runtime: Arc<WorkerRuntime>) -> tokio::task::JoinHandle<()> {
    let mut shutdown_rx = runtime.shutdown_receiver();

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Periodic tasks shutting down");
                        break;
                    }
                }
                _ = interval.tick() => {
                    // Log runtime status periodically
                    let version = runtime.config_sync.current_version();
                    let state = runtime.control_plane.connection_state();
                    let stats = runtime.config_sync.stats();

                    info!(
                        "Worker status: connection={}, config_version={}, backends={}, syncs={}",
                        state,
                        version.map(|v| v.version).unwrap_or(0),
                        stats.backends_configured,
                        stats.configs_applied
                    );

                    // Update Prometheus metrics
                    update_prometheus_metrics(&runtime);
                }
            }
        }
    })
}

/// Spawn cleanup task for expired entries
fn spawn_cleanup_task(runtime: Arc<WorkerRuntime>) -> tokio::task::JoinHandle<()> {
    let mut shutdown_rx = runtime.shutdown_receiver();

    tokio::spawn(async move {
        // Run cleanup every 30 seconds
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Cleanup task shutting down");
                        break;
                    }
                }
                _ = interval.tick() => {
                    // Cleanup expired entries in eBPF maps
                    let loader = runtime.loader.read();
                    let maps = loader.maps();
                    let mut map_manager = maps.write();
                    map_manager.cleanup_expired();
                }
            }
        }
    })
}

/// Spawn control plane state monitor
fn spawn_state_monitor(runtime: Arc<WorkerRuntime>) -> tokio::task::JoinHandle<()> {
    let mut state_rx = runtime.control_plane.subscribe_state_changes();
    let mut shutdown_rx = runtime.shutdown_receiver();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("State monitor shutting down");
                        break;
                    }
                }
                result = state_rx.changed() => {
                    if result.is_err() {
                        break;
                    }

                    let state = *state_rx.borrow();
                    match state {
                        ConnectionState::Connected => {
                            info!("Control plane connection established");
                            // Trigger config sync on reconnection
                            runtime.config_sync.trigger_sync();
                        }
                        ConnectionState::Disconnected => {
                            warn!("Control plane connection lost");
                        }
                        ConnectionState::Reconnecting => {
                            info!("Attempting to reconnect to control plane...");
                        }
                        ConnectionState::ShuttingDown => {
                            info!("Control plane connection shutting down");
                        }
                        ConnectionState::Connecting => {
                            info!("Connecting to control plane...");
                        }
                    }

                    // Update connection state metric
                    pistonprotection_common::metrics::ACTIVE_CONNECTIONS
                        .with_label_values(&["worker", "control_plane"])
                        .set(if state == ConnectionState::Connected { 1.0 } else { 0.0 });
                }
            }
        }
    })
}

/// Update Prometheus metrics
fn update_prometheus_metrics(runtime: &WorkerRuntime) {
    let loader = runtime.loader.read();
    let maps = loader.maps();
    let map_stats = maps.read().stats();

    // Update eBPF map metrics
    pistonprotection_common::metrics::ACTIVE_CONNECTIONS
        .with_label_values(&["worker", "conntrack"])
        .set(map_stats.conntrack_entries as f64);

    pistonprotection_common::metrics::ACTIVE_CONNECTIONS
        .with_label_values(&["worker", "blocked_ips"])
        .set(map_stats.blocked_ips as f64);

    pistonprotection_common::metrics::ACTIVE_CONNECTIONS
        .with_label_values(&["worker", "rate_limits"])
        .set(map_stats.rate_limits as f64);

    pistonprotection_common::metrics::ACTIVE_CONNECTIONS
        .with_label_values(&["worker", "backends"])
        .set(map_stats.backends as f64);

    // Update sync stats
    let _sync_stats = runtime.config_sync.stats();

    // These would be custom metrics in a full implementation
    // pistonprotection_common::metrics::CONFIGS_APPLIED
    //     .with_label_values(&["worker"])
    //     .set(sync_stats.configs_applied as f64);
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
