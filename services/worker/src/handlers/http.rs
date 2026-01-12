//! HTTP handlers for health checks and metrics

use super::WorkerState;
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::Serialize;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

/// Create the HTTP router
pub fn create_router(state: WorkerState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/health", get(health_check))
        .route("/health/live", get(liveness_check))
        .route("/health/ready", get(readiness_check))
        .route("/metrics", get(metrics))
        .route("/status", get(status))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

/// Health status response
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    version: &'static str,
    worker_id: Option<String>,
    interfaces: usize,
    xdp_programs: usize,
}

/// Main health check endpoint
async fn health_check(State(state): State<WorkerState>) -> impl IntoResponse {
    let worker_id = state.worker_id.read().clone();
    let loader = state.loader.read();
    let xdp_count = loader.list_attached().len();

    let response = HealthResponse {
        status: "healthy",
        service: "worker",
        version: env!("CARGO_PKG_VERSION"),
        worker_id,
        interfaces: state.interfaces.len(),
        xdp_programs: xdp_count,
    };

    (StatusCode::OK, Json(response))
}

/// Kubernetes liveness probe
async fn liveness_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

/// Kubernetes readiness probe
async fn readiness_check(State(state): State<WorkerState>) -> impl IntoResponse {
    // Check if we're registered with control plane
    let is_registered = state.worker_id.read().is_some();

    // In standalone mode, we're always ready
    // In connected mode, we need to be registered
    let is_standalone = std::env::var("PISTON_STANDALONE").is_ok();

    if is_registered || is_standalone {
        (StatusCode::OK, "READY")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "NOT_READY")
    }
}

/// Prometheus metrics endpoint
async fn metrics(State(state): State<WorkerState>) -> impl IntoResponse {
    // Collect additional worker-specific metrics
    let loader = state.loader.read();
    let maps = loader.maps();
    let map_stats = maps.read().stats();

    // Add custom metrics
    pistonprotection_common::metrics::ACTIVE_CONNECTIONS
        .with_label_values(&["worker", "ebpf"])
        .set(map_stats.conntrack_entries as f64);

    let metrics = pistonprotection_common::metrics::encode_metrics();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        metrics,
    )
}

/// Detailed status endpoint
#[derive(Serialize)]
struct StatusResponse {
    worker_id: Option<String>,
    version: String,
    interfaces: Vec<InterfaceStatus>,
    xdp_programs: Vec<XdpProgramStatus>,
    map_stats: MapStatsResponse,
    system: SystemStats,
}

#[derive(Serialize)]
struct InterfaceStatus {
    name: String,
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
struct SystemStats {
    cpu_percent: f32,
    memory_percent: f32,
    memory_used_mb: u64,
    memory_total_mb: u64,
}

async fn status(State(state): State<WorkerState>) -> impl IntoResponse {
    let worker_id = state.worker_id.read().clone();
    let loader = state.loader.read();

    // Interface status
    let interfaces: Vec<InterfaceStatus> = state
        .interfaces
        .iter()
        .map(|iface| InterfaceStatus {
            name: iface.name.clone(),
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
    let maps = loader.maps();
    let map_stats = maps.read().stats();

    // System stats
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();

    let system = SystemStats {
        cpu_percent: sys.global_cpu_usage(),
        memory_percent: (sys.used_memory() as f32 / sys.total_memory() as f32) * 100.0,
        memory_used_mb: sys.used_memory() / 1024 / 1024,
        memory_total_mb: sys.total_memory() / 1024 / 1024,
    };

    let response = StatusResponse {
        worker_id,
        version: env!("CARGO_PKG_VERSION").to_string(),
        interfaces,
        xdp_programs,
        map_stats: MapStatsResponse {
            blocked_ips: map_stats.blocked_ips,
            rate_limits: map_stats.rate_limits,
            conntrack_entries: map_stats.conntrack_entries,
            backends: map_stats.backends,
        },
        system,
    };

    (StatusCode::OK, Json(response))
}
