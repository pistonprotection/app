//! HTTP handlers for health checks, metrics, and status endpoints
//!
//! Provides REST API endpoints for:
//! - Health checks (liveness and readiness probes)
//! - Prometheus metrics
//! - Worker status and configuration information
//! - Administrative operations (IP blocking, config refresh)

use super::WorkerState;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

/// Create the HTTP router with all endpoints
pub fn create_router(state: WorkerState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        // Health check endpoints
        .route("/health", get(health_check))
        .route("/health/live", get(liveness_check))
        .route("/health/ready", get(readiness_check))
        // Metrics endpoint
        .route("/metrics", get(metrics))
        // Status endpoints
        .route("/status", get(detailed_status))
        .route("/status/connection", get(connection_status))
        .route("/status/config", get(config_status))
        .route("/status/interfaces", get(interfaces_status))
        // Admin endpoints
        .route("/admin/blocked-ips", get(list_blocked_ips))
        .route("/admin/blocked-ips", post(block_ip))
        .route("/admin/blocked-ips/:ip", delete(unblock_ip))
        .route("/admin/refresh-config", post(refresh_config))
        // Add middleware layers
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

// ============================================================================
// Health Check Handlers
// ============================================================================

/// Health status response
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    version: &'static str,
    worker_id: Option<String>,
    connection_state: String,
    interfaces: usize,
    xdp_programs: usize,
    config_version: u32,
}

/// Main health check endpoint
async fn health_check(State(state): State<WorkerState>) -> impl IntoResponse {
    let health_result = state.health_check();

    let response = HealthResponse {
        status: if health_result.healthy {
            "healthy"
        } else {
            "unhealthy"
        },
        service: "worker",
        version: env!("CARGO_PKG_VERSION"),
        worker_id: state.worker_id(),
        connection_state: format!("{}", state.connection_state()),
        interfaces: state.interfaces.len(),
        xdp_programs: health_result.xdp_programs_count,
        config_version: health_result.config_version,
    };

    let status = if health_result.healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status, Json(response))
}

/// Kubernetes liveness probe
///
/// Returns 200 OK if the worker process is running and can respond to requests.
/// This check should be lightweight and always succeed if the process is alive.
async fn liveness_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

/// Kubernetes readiness probe
///
/// Returns 200 OK if the worker is ready to handle traffic.
/// In standalone mode, always ready.
/// In connected mode, requires control plane connection and configuration.
async fn readiness_check(State(state): State<WorkerState>) -> impl IntoResponse {
    let is_ready = state.is_ready();

    if is_ready {
        (StatusCode::OK, "READY")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "NOT_READY")
    }
}

// ============================================================================
// Metrics Handler
// ============================================================================

/// Prometheus metrics endpoint
async fn metrics(State(state): State<WorkerState>) -> impl IntoResponse {
    // Collect additional worker-specific metrics
    let map_stats = state.map_stats();
    let _sync_stats = state.sync_stats();

    // Update custom metrics
    pistonprotection_common::metrics::ACTIVE_CONNECTIONS
        .with_label_values(&["worker", "ebpf"])
        .set(map_stats.conntrack_entries as f64);

    pistonprotection_common::metrics::ACTIVE_CONNECTIONS
        .with_label_values(&["worker", "blocked_ips"])
        .set(map_stats.blocked_ips as f64);

    pistonprotection_common::metrics::ACTIVE_CONNECTIONS
        .with_label_values(&["worker", "backends"])
        .set(map_stats.backends as f64);

    // Connection state (1 = connected, 0 = disconnected)
    pistonprotection_common::metrics::ACTIVE_CONNECTIONS
        .with_label_values(&["worker", "control_plane"])
        .set(if state.is_connected() { 1.0 } else { 0.0 });

    let metrics = pistonprotection_common::metrics::encode_metrics();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        metrics,
    )
}

// ============================================================================
// Status Handlers
// ============================================================================

/// Detailed status response
#[derive(Serialize)]
struct StatusResponse {
    worker_id: Option<String>,
    version: String,
    connection: ConnectionStatusResponse,
    configuration: ConfigStatusResponse,
    interfaces: Vec<InterfaceStatus>,
    xdp_programs: Vec<XdpProgramStatus>,
    map_stats: MapStatsResponse,
    sync_stats: SyncStatsResponse,
    system: SystemStats,
}

#[derive(Serialize)]
struct ConnectionStatusResponse {
    state: String,
    connected: bool,
    seconds_since_heartbeat: u64,
    control_plane_address: String,
}

#[derive(Serialize)]
struct ConfigStatusResponse {
    version: u32,
    config_id: Option<String>,
    backends_count: usize,
    backends: Vec<String>,
    last_sync: Option<String>,
}

#[derive(Serialize)]
struct InterfaceStatus {
    name: String,
    index: u32,
    ip: Option<String>,
    is_up: bool,
    supports_xdp: bool,
    xdp_attached: bool,
}

#[derive(Serialize)]
struct XdpProgramStatus {
    interface: String,
    program_name: String,
    mode: String,
}

#[derive(Serialize)]
struct MapStatsResponse {
    blocked_ips: usize,
    rate_limits: usize,
    conntrack_entries: usize,
    backends: usize,
}

#[derive(Serialize)]
struct SyncStatsResponse {
    configs_applied: u64,
    map_updates_applied: u64,
    backends_configured: u64,
    rules_configured: u64,
    sync_failures: u64,
    last_error: Option<String>,
}

#[derive(Serialize)]
struct SystemStats {
    cpu_percent: f32,
    memory_percent: f32,
    memory_used_mb: u64,
    memory_total_mb: u64,
}

/// Detailed status endpoint
async fn detailed_status(State(state): State<WorkerState>) -> impl IntoResponse {
    let worker_id = state.worker_id();
    let loader = state.loader.read();

    // Interface status
    let interfaces: Vec<InterfaceStatus> = state
        .interfaces
        .iter()
        .map(|iface| InterfaceStatus {
            name: iface.name.clone(),
            index: iface.index,
            ip: iface.ip_address.map(|ip| ip.to_string()),
            is_up: iface.is_up,
            supports_xdp: iface.supports_xdp(),
            xdp_attached: loader.is_attached(&iface.name),
        })
        .collect();

    // XDP programs
    let xdp_programs: Vec<XdpProgramStatus> = loader
        .list_attached()
        .iter()
        .map(|prog| XdpProgramStatus {
            interface: prog.interface.clone(),
            program_name: prog.program_name.clone(),
            mode: format!("{:?}", prog.mode),
        })
        .collect();

    // Map stats
    let map_stats = state.map_stats();

    // Sync stats
    let sync_stats = state.sync_stats();

    // Config version
    let config_version = state.config_sync.current_version();

    // System stats
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();

    let system = SystemStats {
        cpu_percent: sys.global_cpu_usage(),
        memory_percent: (sys.used_memory() as f32 / sys.total_memory() as f32) * 100.0,
        memory_used_mb: sys.used_memory() / 1024 / 1024,
        memory_total_mb: sys.total_memory() / 1024 / 1024,
    };

    // Control plane address from environment
    let control_plane_address = std::env::var("PISTON_CONTROL_PLANE_ADDR")
        .unwrap_or_else(|_| "http://gateway:50051".to_string());

    let response = StatusResponse {
        worker_id,
        version: env!("CARGO_PKG_VERSION").to_string(),
        connection: ConnectionStatusResponse {
            state: format!("{}", state.connection_state()),
            connected: state.is_connected(),
            seconds_since_heartbeat: state.control_plane.seconds_since_last_heartbeat(),
            control_plane_address,
        },
        configuration: ConfigStatusResponse {
            version: config_version.as_ref().map(|v| v.version).unwrap_or(0),
            config_id: config_version.map(|v| v.config_id),
            backends_count: state.configured_backends().len(),
            backends: state.configured_backends(),
            last_sync: sync_stats.last_sync.map(|t| t.to_rfc3339()),
        },
        interfaces,
        xdp_programs,
        map_stats: MapStatsResponse {
            blocked_ips: map_stats.blocked_ips,
            rate_limits: map_stats.rate_limits,
            conntrack_entries: map_stats.conntrack_entries,
            backends: map_stats.backends,
        },
        sync_stats: SyncStatsResponse {
            configs_applied: sync_stats.configs_applied,
            map_updates_applied: sync_stats.map_updates_applied,
            backends_configured: sync_stats.backends_configured,
            rules_configured: sync_stats.rules_configured,
            sync_failures: sync_stats.sync_failures,
            last_error: sync_stats.last_error,
        },
        system,
    };

    (StatusCode::OK, Json(response))
}

/// Connection status endpoint
async fn connection_status(State(state): State<WorkerState>) -> impl IntoResponse {
    let control_plane_address = std::env::var("PISTON_CONTROL_PLANE_ADDR")
        .unwrap_or_else(|_| "http://gateway:50051".to_string());

    let response = ConnectionStatusResponse {
        state: format!("{}", state.connection_state()),
        connected: state.is_connected(),
        seconds_since_heartbeat: state.control_plane.seconds_since_last_heartbeat(),
        control_plane_address,
    };

    (StatusCode::OK, Json(response))
}

/// Configuration status endpoint
async fn config_status(State(state): State<WorkerState>) -> impl IntoResponse {
    let config_version = state.config_sync.current_version();
    let sync_stats = state.sync_stats();

    let response = ConfigStatusResponse {
        version: config_version.as_ref().map(|v| v.version).unwrap_or(0),
        config_id: config_version.map(|v| v.config_id),
        backends_count: state.configured_backends().len(),
        backends: state.configured_backends(),
        last_sync: sync_stats.last_sync.map(|t| t.to_rfc3339()),
    };

    (StatusCode::OK, Json(response))
}

/// Interfaces status endpoint
async fn interfaces_status(State(state): State<WorkerState>) -> impl IntoResponse {
    let loader = state.loader.read();

    let interfaces: Vec<InterfaceStatus> = state
        .interfaces
        .iter()
        .map(|iface| InterfaceStatus {
            name: iface.name.clone(),
            index: iface.index,
            ip: iface.ip_address.map(|ip| ip.to_string()),
            is_up: iface.is_up,
            supports_xdp: iface.supports_xdp(),
            xdp_attached: loader.is_attached(&iface.name),
        })
        .collect();

    (StatusCode::OK, Json(interfaces))
}

// ============================================================================
// Admin Handlers
// ============================================================================

/// Blocked IP entry response
#[derive(Serialize)]
struct BlockedIpResponse {
    ip: String,
    reason: String,
    blocked_at: String,
    expires_at: Option<String>,
    packets_blocked: u64,
}

/// List all blocked IPs
async fn list_blocked_ips(State(state): State<WorkerState>) -> impl IntoResponse {
    let blocked = state.list_blocked_ips();

    let response: Vec<BlockedIpResponse> = blocked
        .into_iter()
        .map(|entry| BlockedIpResponse {
            ip: entry.ip.to_string(),
            reason: entry.reason,
            blocked_at: entry.blocked_at.to_rfc3339(),
            expires_at: entry.expires_at.map(|t| t.to_rfc3339()),
            packets_blocked: entry.packets_blocked,
        })
        .collect();

    (StatusCode::OK, Json(response))
}

/// Block IP request
#[derive(Deserialize)]
struct BlockIpRequest {
    ip: String,
    reason: String,
    #[serde(default)]
    duration_secs: Option<u32>,
}

/// Block IP response
#[derive(Serialize)]
struct BlockIpSuccessResponse {
    success: bool,
    message: String,
}

/// Block an IP address
async fn block_ip(
    State(state): State<WorkerState>,
    Json(request): Json<BlockIpRequest>,
) -> impl IntoResponse {
    let ip: IpAddr = match request.ip.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(BlockIpSuccessResponse {
                    success: false,
                    message: format!("Invalid IP address: {}", request.ip),
                }),
            );
        }
    };

    match state.block_ip(ip, &request.reason, request.duration_secs) {
        Ok(_) => (
            StatusCode::OK,
            Json(BlockIpSuccessResponse {
                success: true,
                message: format!("IP {} blocked successfully", ip),
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(BlockIpSuccessResponse {
                success: false,
                message: format!("Failed to block IP: {}", e),
            }),
        ),
    }
}

/// Unblock an IP address
async fn unblock_ip(
    State(state): State<WorkerState>,
    Path(ip_str): Path<String>,
) -> impl IntoResponse {
    let ip: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(BlockIpSuccessResponse {
                    success: false,
                    message: format!("Invalid IP address: {}", ip_str),
                }),
            );
        }
    };

    match state.unblock_ip(&ip) {
        Ok(_) => (
            StatusCode::OK,
            Json(BlockIpSuccessResponse {
                success: true,
                message: format!("IP {} unblocked successfully", ip),
            }),
        ),
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(BlockIpSuccessResponse {
                success: false,
                message: format!("Failed to unblock IP: {}", e),
            }),
        ),
    }
}

/// Refresh configuration response
#[derive(Serialize)]
struct RefreshConfigResponse {
    success: bool,
    message: String,
}

/// Trigger configuration refresh
async fn refresh_config(State(state): State<WorkerState>) -> impl IntoResponse {
    state.trigger_config_refresh();

    (
        StatusCode::OK,
        Json(RefreshConfigResponse {
            success: true,
            message: "Configuration refresh triggered".to_string(),
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_ip_request_deserialization() {
        let json = r#"{"ip": "192.168.1.1", "reason": "test", "duration_secs": 60}"#;
        let request: BlockIpRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.ip, "192.168.1.1");
        assert_eq!(request.reason, "test");
        assert_eq!(request.duration_secs, Some(60));
    }

    #[test]
    fn test_block_ip_request_without_duration() {
        let json = r#"{"ip": "192.168.1.1", "reason": "test"}"#;
        let request: BlockIpRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.duration_secs, None);
    }
}
