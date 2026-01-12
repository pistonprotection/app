//! HTTP and gRPC handlers for config-mgr

use crate::{config_store::ConfigStore, distributor::ConfigDistributor};
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use pistonprotection_common::config::Config;
use pistonprotection_proto::worker::{
    worker_service_server::{WorkerService, WorkerServiceServer},
    *,
};
use serde::Serialize;
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tonic::{transport::Server, Request, Response, Status};
use tonic_health::server::health_reporter;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::info;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<ConfigStore>,
    pub distributor: Arc<ConfigDistributor>,
    pub config: Arc<Config>,
}

// HTTP Handlers

pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/health", get(health_check))
        .route("/health/live", get(liveness_check))
        .route("/health/ready", get(readiness_check))
        .route("/metrics", get(metrics))
        .route("/workers", get(list_workers))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    version: &'static str,
    config_version: u32,
    workers: usize,
}

async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    let workers = state.distributor.list_workers();

    Json(HealthResponse {
        status: "healthy",
        service: "config-mgr",
        version: env!("CARGO_PKG_VERSION"),
        config_version: state.store.current_version(),
        workers: workers.len(),
    })
}

async fn liveness_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

async fn readiness_check(State(_state): State<AppState>) -> impl IntoResponse {
    (StatusCode::OK, "READY")
}

async fn metrics() -> impl IntoResponse {
    let metrics = pistonprotection_common::metrics::encode_metrics();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        metrics,
    )
}

#[derive(Serialize)]
struct WorkersResponse {
    workers: Vec<WorkerInfo>,
}

#[derive(Serialize)]
struct WorkerInfo {
    worker_id: String,
    node_name: String,
    interfaces: Vec<String>,
    config_version: u32,
    last_heartbeat: String,
}

async fn list_workers(State(state): State<AppState>) -> impl IntoResponse {
    let workers = state
        .distributor
        .list_workers()
        .into_iter()
        .map(|w| WorkerInfo {
            worker_id: w.worker_id,
            node_name: w.node_name,
            interfaces: w.interfaces,
            config_version: w.config_version,
            last_heartbeat: w.last_heartbeat.to_rfc3339(),
        })
        .collect();

    Json(WorkersResponse { workers })
}

// gRPC Handlers

pub struct WorkerGrpcService {
    store: Arc<ConfigStore>,
    distributor: Arc<ConfigDistributor>,
}

impl WorkerGrpcService {
    pub fn new(store: Arc<ConfigStore>, distributor: Arc<ConfigDistributor>) -> Self {
        Self { store, distributor }
    }
}

#[tonic::async_trait]
impl WorkerService for WorkerGrpcService {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner();
        let worker = req.worker.ok_or_else(|| Status::invalid_argument("Worker info required"))?;

        let worker_id = uuid::Uuid::new_v4().to_string();

        let interfaces: Vec<String> = worker.interfaces.iter().map(|i| i.name.clone()).collect();

        self.distributor
            .register_worker(worker_id.clone(), worker.node_name, interfaces);

        // Get initial configuration
        let config = self
            .store
            .generate_config()
            .await
            .map_err(|e| Status::internal(format!("Failed to generate config: {}", e)))?;

        info!(worker_id = %worker_id, "Worker registered via gRPC");

        Ok(Response::new(RegisterResponse {
            worker_id,
            initial_config: Some(config),
        }))
    }

    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let req = request.into_inner();

        // Update heartbeat
        self.distributor.update_heartbeat(&req.worker_id, 0); // TODO: track version

        // Check if config update is needed
        let latest_version = self.store.current_version();

        Ok(Response::new(HeartbeatResponse {
            config_update_available: false, // TODO: compare versions
            latest_config_version: latest_version,
        }))
    }

    async fn deregister(
        &self,
        request: Request<DeregisterRequest>,
    ) -> Result<Response<DeregisterResponse>, Status> {
        let req = request.into_inner();

        self.distributor.deregister_worker(&req.worker_id);

        Ok(Response::new(DeregisterResponse { success: true }))
    }

    async fn get_config(
        &self,
        request: Request<GetConfigRequest>,
    ) -> Result<Response<GetConfigResponse>, Status> {
        let req = request.into_inner();

        let config = self
            .distributor
            .get_config_for_worker(&req.worker_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get config: {}", e)))?;

        let up_to_date = !self.distributor.needs_update(&req.worker_id, req.current_version);

        Ok(Response::new(GetConfigResponse {
            config: Some(config),
            up_to_date,
        }))
    }

    type StreamConfigStream = Pin<Box<dyn Stream<Item = Result<FilterConfig, Status>> + Send>>;

    async fn stream_config(
        &self,
        _request: Request<StreamConfigRequest>,
    ) -> Result<Response<Self::StreamConfigStream>, Status> {
        // TODO: Implement streaming config updates
        Err(Status::unimplemented("Config streaming not implemented yet"))
    }

    async fn apply_map_updates(
        &self,
        _request: Request<ApplyMapUpdatesRequest>,
    ) -> Result<Response<ApplyMapUpdatesResponse>, Status> {
        Err(Status::unimplemented("Not implemented"))
    }

    async fn report_metrics(
        &self,
        _request: Request<ReportMetricsRequest>,
    ) -> Result<Response<ReportMetricsResponse>, Status> {
        // Accept metrics from workers
        // TODO: Forward to metrics service
        Ok(Response::new(ReportMetricsResponse { success: true }))
    }

    async fn report_attack(
        &self,
        _request: Request<ReportAttackRequest>,
    ) -> Result<Response<ReportAttackResponse>, Status> {
        // TODO: Handle attack reports
        Ok(Response::new(ReportAttackResponse {
            block_updates: vec![],
            escalate_protection: false,
            new_protection_level: 0,
        }))
    }

    type SyncConnTrackStream = Pin<Box<dyn Stream<Item = Result<ConnTrackSync, Status>> + Send>>;

    async fn sync_conn_track(
        &self,
        _request: Request<tonic::Streaming<ConnTrackSync>>,
    ) -> Result<Response<Self::SyncConnTrackStream>, Status> {
        Err(Status::unimplemented("Not implemented"))
    }

    async fn get_blocked_ips(
        &self,
        _request: Request<GetBlockedIpsRequest>,
    ) -> Result<Response<GetBlockedIpsResponse>, Status> {
        Ok(Response::new(GetBlockedIpsResponse {
            ips: vec![],
            pagination: None,
        }))
    }

    async fn block_ip(
        &self,
        _request: Request<BlockIpRequest>,
    ) -> Result<Response<BlockIpResponse>, Status> {
        Ok(Response::new(BlockIpResponse { success: true }))
    }

    async fn unblock_ip(
        &self,
        _request: Request<UnblockIpRequest>,
    ) -> Result<Response<UnblockIpResponse>, Status> {
        Ok(Response::new(UnblockIpResponse { success: true }))
    }

    async fn get_xdp_stats(
        &self,
        _request: Request<GetXdpStatsRequest>,
    ) -> Result<Response<GetXdpStatsResponse>, Status> {
        Err(Status::unimplemented("Not implemented"))
    }

    async fn dump_maps(
        &self,
        _request: Request<DumpMapsRequest>,
    ) -> Result<Response<DumpMapsResponse>, Status> {
        Err(Status::unimplemented("Not implemented"))
    }
}

pub async fn create_grpc_server(
    state: AppState,
) -> Result<tonic::transport::server::Router, Box<dyn std::error::Error>> {
    let (mut health_reporter, health_service) = health_reporter();
    health_reporter
        .set_serving::<WorkerServiceServer<WorkerGrpcService>>()
        .await;

    let worker_service = WorkerGrpcService::new(state.store, state.distributor);

    Ok(Server::builder()
        .add_service(health_service)
        .add_service(WorkerServiceServer::new(worker_service)))
}
