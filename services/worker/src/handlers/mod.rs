//! Worker service handlers

pub mod http;

use crate::ebpf::{interface::NetworkInterface, loader::EbpfLoader};
use deadpool_redis::Pool as RedisPool;
use parking_lot::RwLock;
use pistonprotection_common::{config::Config, error::Result, redis::CacheService};
use pistonprotection_proto::worker::{
    worker_service_client::WorkerServiceClient, HeartbeatRequest, RegisterRequest, Worker,
    WorkerCapabilities, WorkerStatus,
};
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tonic::transport::Channel;
use tracing::{debug, error, info, warn};

/// Worker state
#[derive(Clone)]
pub struct WorkerState {
    pub loader: Arc<RwLock<EbpfLoader>>,
    pub cache: Option<CacheService>,
    pub config: Arc<Config>,
    pub interfaces: Arc<Vec<NetworkInterface>>,
    pub worker_id: Arc<RwLock<Option<String>>>,
}

impl WorkerState {
    pub fn new(
        loader: EbpfLoader,
        redis: Option<RedisPool>,
        config: Config,
        interfaces: Vec<NetworkInterface>,
    ) -> Self {
        let cache = redis.map(|pool| CacheService::new(pool, "piston:worker"));

        Self {
            loader: Arc::new(RwLock::new(loader)),
            cache,
            config: Arc::new(config),
            interfaces: Arc::new(interfaces),
            worker_id: Arc::new(RwLock::new(None)),
        }
    }
}

/// Main worker loop
pub async fn worker_loop(state: WorkerState, control_plane_addr: &str) -> Result<()> {
    // Connect to control plane
    let channel = Channel::from_shared(control_plane_addr.to_string())
        .map_err(|e| pistonprotection_common::error::Error::Internal(e.to_string()))?
        .connect()
        .await
        .map_err(|e| pistonprotection_common::error::Error::Internal(format!("Failed to connect: {}", e)))?;

    let mut client = WorkerServiceClient::new(channel);

    // Register with control plane
    let worker_info = build_worker_info(&state);
    let register_response = client
        .register(RegisterRequest {
            worker: Some(worker_info),
        })
        .await;

    match register_response {
        Ok(response) => {
            let resp = response.into_inner();
            info!("Registered with control plane, worker_id: {}", resp.worker_id);
            *state.worker_id.write() = Some(resp.worker_id.clone());

            // Apply initial configuration if provided
            if let Some(config) = resp.initial_config {
                apply_config(&state, &config).await?;
            }
        }
        Err(e) => {
            warn!("Failed to register with control plane: {}. Running in standalone mode.", e);
        }
    }

    // Heartbeat loop
    let mut heartbeat_interval = interval(Duration::from_secs(10));

    loop {
        heartbeat_interval.tick().await;

        if let Some(worker_id) = state.worker_id.read().clone() {
            // Send heartbeat
            let metrics = collect_worker_metrics(&state);
            let heartbeat = HeartbeatRequest {
                worker_id: worker_id.clone(),
                status: WorkerStatus::Ready.into(),
                metrics: Some(metrics),
            };

            match client.heartbeat(heartbeat).await {
                Ok(response) => {
                    let resp = response.into_inner();
                    if resp.config_update_available {
                        debug!("Configuration update available, fetching...");
                        // Fetch and apply new configuration
                        // TODO: Implement config streaming
                    }
                }
                Err(e) => {
                    warn!("Heartbeat failed: {}", e);
                }
            }
        }

        // Periodic tasks
        cleanup_expired_entries(&state);
    }
}

/// Build worker information for registration
fn build_worker_info(state: &WorkerState) -> Worker {
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();

    Worker {
        id: String::new(), // Assigned by control plane
        node_name: std::env::var("NODE_NAME").unwrap_or_else(|_| hostname.clone()),
        hostname,
        interfaces: state
            .interfaces
            .iter()
            .map(|iface| pistonprotection_proto::worker::NetworkInterface {
                name: iface.name.clone(),
                ip_address: iface.ip_address.map(|ip| ip.into()),
                mac_address: iface
                    .mac_address
                    .map(|mac| mac.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")),
                xdp_status: None,
                rx_bytes: 0,
                tx_bytes: 0,
                rx_packets: 0,
                tx_packets: 0,
                rx_dropped: 0,
                tx_dropped: 0,
            })
            .collect(),
        capabilities: Some(WorkerCapabilities {
            xdp_native: true,
            xdp_driver: true,
            xdp_offload: false,
            bpf_helpers: vec![],
            max_bpf_stack_size: 512,
            max_map_entries: 1_000_000,
            cpu_cores: sys.cpus().len() as u32,
            memory_bytes: sys.total_memory(),
            network_drivers: vec![],
            kernel_version: sysinfo::System::kernel_version().unwrap_or_default(),
            kernel_major: 0,
            kernel_minor: 0,
        }),
        status: WorkerStatus::Registering.into(),
        labels: std::collections::HashMap::new(),
        registered_at: None,
        last_heartbeat: None,
    }
}

/// Collect worker metrics
fn collect_worker_metrics(state: &WorkerState) -> pistonprotection_proto::worker::WorkerMetrics {
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();

    let cpu_percent = sys.global_cpu_usage();
    let memory_percent = (sys.used_memory() as f32 / sys.total_memory() as f32) * 100.0;

    pistonprotection_proto::worker::WorkerMetrics {
        cpu_percent,
        memory_percent,
        interfaces: vec![], // TODO: Collect interface metrics
    }
}

/// Apply configuration from control plane
async fn apply_config(
    state: &WorkerState,
    config: &pistonprotection_proto::worker::FilterConfig,
) -> Result<()> {
    info!("Applying configuration version {}", config.version);

    // Update map manager with new configuration
    let mut loader = state.loader.write();
    let maps = loader.maps();
    let mut map_manager = maps.write();

    for backend in &config.backends {
        map_manager.update_backend(crate::ebpf::maps::BackendConfig {
            id: backend.backend_id.clone(),
            protection_level: backend.protection.as_ref().map(|p| p.level as u8).unwrap_or(0),
            rate_limit_pps: backend
                .protection
                .as_ref()
                .and_then(|p| p.per_ip_rate.as_ref())
                .map(|r| r.tokens_per_second)
                .unwrap_or(10000),
            rate_limit_bps: 0,
            blocked_countries: backend
                .protection
                .as_ref()
                .map(|p| p.blocked_country_ids.iter().map(|&id| id as u16).collect())
                .unwrap_or_default(),
        });
    }

    Ok(())
}

/// Cleanup expired entries
fn cleanup_expired_entries(state: &WorkerState) {
    let loader = state.loader.read();
    let maps = loader.maps();
    let mut map_manager = maps.write();
    map_manager.cleanup_expired();
}
