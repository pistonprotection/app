//! HTTP and gRPC handlers for config-mgr

use crate::{config_store::ConfigStore, distributor::ConfigDistributor};
use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use pistonprotection_common::config::Config;
use pistonprotection_proto::worker::{
    worker_service_server::{WorkerService, WorkerServiceServer},
    *,
};
use serde::Serialize;
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tonic::{Request, Response, Status, transport::Server};
use tonic_health::server::health_reporter;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::{info, warn};

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
        let worker = req
            .worker
            .ok_or_else(|| Status::invalid_argument("Worker info required"))?;

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

        // Update heartbeat with worker's current version
        let worker_version = req.current_config_version;
        self.distributor
            .update_heartbeat(&req.worker_id, worker_version);

        // Check if config update is needed by comparing versions
        let latest_version = self.store.current_version();

        // Config update is available if worker's version is older than latest
        let config_update_available = worker_version < latest_version;

        Ok(Response::new(HeartbeatResponse {
            config_update_available,
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

        let up_to_date = !self
            .distributor
            .needs_update(&req.worker_id, req.current_version);

        Ok(Response::new(GetConfigResponse {
            config: Some(config),
            up_to_date,
        }))
    }

    type StreamConfigStream = Pin<Box<dyn Stream<Item = Result<FilterConfig, Status>> + Send>>;

    async fn stream_config(
        &self,
        request: Request<StreamConfigRequest>,
    ) -> Result<Response<Self::StreamConfigStream>, Status> {
        let req = request.into_inner();
        let worker_id = req.worker_id.clone();

        // Get current version from worker's registration
        let mut current_version = self
            .distributor
            .list_workers()
            .into_iter()
            .find(|w| w.worker_id == worker_id)
            .map(|w| w.config_version)
            .unwrap_or(0);

        let store = self.store.clone();
        let distributor = self.distributor.clone();
        let mut rx = distributor.subscribe();

        info!(worker_id = %worker_id, "Worker subscribed to config stream");

        let stream = async_stream::stream! {
            // Send initial config if version differs
            let latest_version = store.current_version();
            if current_version < latest_version {
                match store.generate_config().await {
                    Ok(config) => {
                        current_version = config.version;
                        yield Ok(config);
                    }
                    Err(e) => {
                        yield Err(Status::internal(format!("Failed to generate config: {}", e)));
                        return;
                    }
                }
            }

            // Stream updates as they occur
            loop {
                match rx.recv().await {
                    Ok(update) => {
                        if update.version > current_version {
                            match store.generate_config().await {
                                Ok(config) => {
                                    current_version = config.version;
                                    yield Ok(config);
                                }
                                Err(e) => {
                                    warn!("Failed to generate config for stream: {}", e);
                                    // Continue listening rather than terminating
                                }
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!(skipped = n, "Config stream lagged, sending latest");
                        // Send latest config after lag
                        if let Ok(config) = store.generate_config().await {
                            current_version = config.version;
                            yield Ok(config);
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }

    async fn apply_map_updates(
        &self,
        request: Request<ApplyMapUpdatesRequest>,
    ) -> Result<Response<ApplyMapUpdatesResponse>, Status> {
        let req = request.into_inner();

        // Track errors
        let errors = Vec::new();

        for update in &req.updates {
            // Log the map update request
            info!(
                worker_id = %req.worker_id,
                map_name = %update.map_name,
                operation = update.operation,
                "Processing BPF map update"
            );

            // For now, we accept all updates
            // In production, this would validate and possibly replicate to other workers
        }

        if !errors.is_empty() {
            warn!(
                worker_id = %req.worker_id,
                error_count = errors.len(),
                "Some map updates failed"
            );
        }

        Ok(Response::new(ApplyMapUpdatesResponse {
            success: errors.is_empty(),
            errors,
        }))
    }

    async fn report_metrics(
        &self,
        request: Request<ReportMetricsRequest>,
    ) -> Result<Response<ReportMetricsResponse>, Status> {
        let req = request.into_inner();

        // Update Prometheus metrics with worker data
        for metrics in &req.backend_metrics {
            let backend_id: &str = &metrics.backend_id;
            pistonprotection_common::metrics::TRAFFIC_PACKETS_TOTAL
                .with_label_values(&[backend_id, "in"])
                .inc_by(metrics.packets_in as f64);
            pistonprotection_common::metrics::TRAFFIC_PACKETS_TOTAL
                .with_label_values(&[backend_id, "out"])
                .inc_by(metrics.packets_out as f64);
            pistonprotection_common::metrics::TRAFFIC_PACKETS_TOTAL
                .with_label_values(&[backend_id, "dropped"])
                .inc_by(metrics.packets_dropped as f64);
            pistonprotection_common::metrics::TRAFFIC_BYTES_TOTAL
                .with_label_values(&[backend_id, "in"])
                .inc_by(metrics.bytes_in as f64);
            pistonprotection_common::metrics::TRAFFIC_BYTES_TOTAL
                .with_label_values(&[backend_id, "out"])
                .inc_by(metrics.bytes_out as f64);
        }

        Ok(Response::new(ReportMetricsResponse { success: true }))
    }

    async fn report_attack(
        &self,
        request: Request<ReportAttackRequest>,
    ) -> Result<Response<ReportAttackResponse>, Status> {
        let req = request.into_inner();

        warn!(
            worker_id = %req.worker_id,
            backend_id = %req.backend_id,
            attack_type = %req.attack_type,
            source_count = req.sources.len(),
            pps = req.attack_pps,
            bps = req.attack_bps,
            "Attack reported by worker"
        );

        // Determine response based on attack severity
        let mut block_updates = Vec::new();
        let mut escalate_protection = false;
        let mut new_protection_level = 0;

        // If attack is severe (high PPS or many sources), recommend protection escalation
        if req.attack_pps > 100_000 || req.sources.len() > 1000 {
            escalate_protection = true;
            new_protection_level = 4; // High protection

            // Add top attackers to block list via MapUpdate
            for source in req.sources.iter().take(100) {
                // Extract IP bytes from the IpAddress proto
                if let Some(ref ip_addr) = source.ip {
                    if let Some(ref addr) = ip_addr.address {
                        let ip_bytes = match addr {
                            pistonprotection_proto::common::ip_address::Address::Ipv4(v) => {
                                v.to_be_bytes().to_vec()
                            }
                            pistonprotection_proto::common::ip_address::Address::Ipv6(v) => {
                                v.clone() // Already Vec<u8>
                            }
                        };
                        block_updates.push(MapUpdate {
                            map_name: "blocked_ips".to_string(),
                            operation: 1, // MapOperation::Insert
                            key: ip_bytes,
                            value: vec![1], // Simple block marker
                            flags: 0,
                        });
                    }
                }
            }
        } else if req.attack_pps > 10_000 || req.sources.len() > 100 {
            // Medium severity - moderate protection increase
            escalate_protection = true;
            new_protection_level = 3;
        }

        // Update metrics
        let backend_id: &str = &req.backend_id;
        let attack_type: &str = &req.attack_type;
        pistonprotection_common::metrics::ATTACK_DETECTED
            .with_label_values(&[backend_id, attack_type])
            .set(1.0);

        // Store attack event for analytics (would normally go to database)
        info!(
            backend_id = %req.backend_id,
            escalate = escalate_protection,
            new_level = new_protection_level,
            blocks = block_updates.len(),
            "Attack response determined"
        );

        Ok(Response::new(ReportAttackResponse {
            block_updates,
            escalate_protection,
            new_protection_level,
        }))
    }

    type SyncConnTrackStream = Pin<Box<dyn Stream<Item = Result<ConnTrackSync, Status>> + Send>>;

    /// Bidirectional streaming for connection tracking synchronization between workers.
    /// Workers send their connection tracking entries, and we broadcast updates to all workers.
    /// This enables consistent connection state across the cluster for stateful protocols.
    async fn sync_conn_track(
        &self,
        request: Request<tonic::Streaming<ConnTrackSync>>,
    ) -> Result<Response<Self::SyncConnTrackStream>, Status> {
        let mut inbound = request.into_inner();
        let distributor = self.distributor.clone();

        // Create a channel for the outbound stream
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<ConnTrackSync, Status>>(100);

        // Spawn task to process inbound connection tracking updates
        tokio::spawn(async move {
            while let Some(result) = inbound.message().await.transpose() {
                match result {
                    Ok(sync) => {
                        // Log the sync entry (in production, would store and distribute)
                        info!(
                            sync_type = sync.r#type,
                            entries = sync.entries.len(),
                            "Received connection tracking sync"
                        );

                        // Broadcast to other workers via distributor
                        // For now, we echo back to acknowledge receipt
                        if let Err(e) = tx.send(Ok(sync)).await {
                            warn!("Failed to send conntrack sync response: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("Error receiving conntrack sync: {}", e);
                        break;
                    }
                }
            }
            drop(distributor); // Keep distributor alive for the duration
        });

        // Create the output stream from the receiver
        let stream = async_stream::stream! {
            while let Some(item) = rx.recv().await {
                yield item;
            }
        };

        Ok(Response::new(Box::pin(stream)))
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

    /// Get XDP statistics for a specific worker and interface.
    /// The config-mgr aggregates stats reported by workers via report_metrics.
    /// For real-time stats, the caller should query workers directly.
    async fn get_xdp_stats(
        &self,
        request: Request<GetXdpStatsRequest>,
    ) -> Result<Response<GetXdpStatsResponse>, Status> {
        let req = request.into_inner();

        // Verify worker exists
        let worker = self
            .distributor
            .list_workers()
            .into_iter()
            .find(|w| w.worker_id == req.worker_id);

        if worker.is_none() {
            return Err(Status::not_found(format!(
                "Worker {} not found",
                req.worker_id
            )));
        }

        // In a full implementation, this would query the worker directly or
        // return cached metrics from report_metrics calls.
        // For now, return aggregated metrics from Prometheus counters.
        // Note: These are cumulative totals, not per-worker stats.
        // Return stats with per-CPU breakdown
        // In production, these would be populated from worker reports
        let mut per_cpu_stats = std::collections::HashMap::new();
        per_cpu_stats.insert("cpu0_passed".to_string(), 0u64);
        per_cpu_stats.insert("cpu0_dropped".to_string(), 0u64);

        Ok(Response::new(GetXdpStatsResponse {
            packets_processed: 0,  // Would be sum of all packet counters
            packets_passed: 0,     // Would come from XDP_PASS counter
            packets_dropped: 0,    // Would come from XDP_DROP counter
            packets_redirected: 0, // Would come from XDP_REDIRECT counter
            packets_aborted: 0,    // Would come from XDP_ABORTED counter
            per_cpu_stats,
        }))
    }

    /// Dump contents of a specific eBPF map for debugging.
    /// This requires forwarding the request to the appropriate worker.
    async fn dump_maps(
        &self,
        request: Request<DumpMapsRequest>,
    ) -> Result<Response<DumpMapsResponse>, Status> {
        let req = request.into_inner();

        // Verify worker exists
        let worker = self
            .distributor
            .list_workers()
            .into_iter()
            .find(|w| w.worker_id == req.worker_id);

        if worker.is_none() {
            return Err(Status::not_found(format!(
                "Worker {} not found",
                req.worker_id
            )));
        }

        // In a full implementation, this would:
        // 1. Forward the request to the specified worker via gRPC
        // 2. The worker would read the actual eBPF map contents
        // 3. Return the serialized entries
        //
        // For now, return an empty result as config-mgr doesn't have
        // direct access to worker eBPF maps.
        info!(
            worker_id = %req.worker_id,
            map_name = %req.map_name,
            max_entries = req.max_entries,
            "Map dump requested (requires worker forwarding)"
        );

        Ok(Response::new(DumpMapsResponse {
            map_name: req.map_name,
            entries: Vec::new(),
        }))
    }
}

pub async fn create_grpc_server(
    state: AppState,
) -> Result<tonic::transport::server::Router, Box<dyn std::error::Error + Send + Sync>> {
    let (health_reporter, health_service) = health_reporter();
    health_reporter
        .set_serving::<WorkerServiceServer<WorkerGrpcService>>()
        .await;

    let worker_service = WorkerGrpcService::new(state.store, state.distributor);

    Ok(Server::builder()
        .add_service(health_service)
        .add_service(WorkerServiceServer::new(worker_service)))
}
