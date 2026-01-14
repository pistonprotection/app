//! PistonProtection Kubernetes Operator
//!
//! This operator manages DDoS protection resources in Kubernetes clusters.
//! It provides:
//! - DDoSProtection CRD for defining protected backends
//! - FilterRule CRD for custom filtering rules
//! - Backend CRD for backend service definitions
//! - IPBlocklist CRD for IP blocklist management
//!
//! The operator synchronizes configuration with the PistonProtection gateway
//! service via gRPC and manages worker deployments for traffic filtering.

use anyhow::{Context as AnyhowContext, Result};
use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use futures::StreamExt;
use kube::{
    Client, CustomResourceExt, Resource,
    api::Api,
    runtime::{
        controller::Controller,
        events::{Recorder, Reporter},
        watcher::Config as WatcherConfig,
    },
};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use pistonprotection_operator::client::{GatewayClient, GatewayClientConfig};
use pistonprotection_operator::controllers;
use pistonprotection_operator::crd::{Backend, DDoSProtection, FilterRule, IPBlocklist};
use pistonprotection_operator::metrics::Metrics;
use pistonprotection_operator::worker::WorkerManager;

/// Application state shared across components
struct AppState {
    /// Whether the operator is ready to serve traffic
    ready: AtomicBool,
    /// Whether the operator is healthy
    healthy: AtomicBool,
    /// Whether this instance is the leader
    is_leader: AtomicBool,
    /// Metrics collector
    metrics: Arc<Metrics>,
    /// Gateway client
    gateway_client: Arc<GatewayClient>,
    /// Worker manager
    worker_manager: Arc<RwLock<Option<WorkerManager>>>,
}

impl AppState {
    fn new(metrics: Arc<Metrics>, gateway_client: Arc<GatewayClient>) -> Self {
        Self {
            ready: AtomicBool::new(false),
            healthy: AtomicBool::new(true),
            is_leader: AtomicBool::new(false),
            metrics,
            gateway_client,
            worker_manager: Arc::new(RwLock::new(None)),
        }
    }
}

/// Configuration for the operator
#[derive(Clone, Debug)]
struct OperatorConfig {
    /// Namespace to watch (empty for all namespaces)
    namespace: Option<String>,
    /// Leader election enabled
    leader_election: bool,
    /// Leader election lease name
    lease_name: String,
    /// Leader election lease namespace
    lease_namespace: String,
    /// Metrics server address
    metrics_addr: String,
    /// Health server address
    health_addr: String,
    /// Enable Backend controller
    enable_backend_controller: bool,
    /// Enable IPBlocklist controller
    enable_ipblocklist_controller: bool,
    /// Worker namespace for pod discovery
    worker_namespace: String,
    /// Worker pod selector
    worker_selector: String,
    /// Worker gRPC port
    worker_grpc_port: u16,
    /// Reconciliation concurrency
    concurrency: usize,
}

impl Default for OperatorConfig {
    fn default() -> Self {
        Self {
            namespace: std::env::var("WATCH_NAMESPACE").ok(),
            leader_election: std::env::var("LEADER_ELECTION")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true),
            lease_name: std::env::var("LEASE_NAME")
                .unwrap_or_else(|_| "pistonprotection-operator".to_string()),
            lease_namespace: std::env::var("LEASE_NAMESPACE")
                .unwrap_or_else(|_| "pistonprotection-system".to_string()),
            metrics_addr: std::env::var("METRICS_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            health_addr: std::env::var("HEALTH_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:8081".to_string()),
            enable_backend_controller: std::env::var("ENABLE_BACKEND_CONTROLLER")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true),
            enable_ipblocklist_controller: std::env::var("ENABLE_IPBLOCKLIST_CONTROLLER")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true),
            worker_namespace: std::env::var("WORKER_NAMESPACE")
                .unwrap_or_else(|_| "pistonprotection-system".to_string()),
            worker_selector: std::env::var("WORKER_SELECTOR")
                .unwrap_or_else(|_| "app.kubernetes.io/component=worker".to_string()),
            worker_grpc_port: std::env::var("WORKER_GRPC_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(50052),
            concurrency: std::env::var("RECONCILIATION_CONCURRENCY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(4),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("pistonprotection_operator=info".parse()?)
                .add_directive("kube=info".parse()?)
                .add_directive("tower=warn".parse()?),
        )
        .json()
        .with_current_span(true)
        .init();

    info!("Starting PistonProtection Operator");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config = OperatorConfig::default();
    info!("Configuration loaded: {:?}", config);

    // Create Kubernetes client
    let client = Client::try_default()
        .await
        .context("Failed to create Kubernetes client")?;
    info!("Connected to Kubernetes cluster");

    // Initialize metrics
    let metrics = Arc::new(Metrics::new());
    metrics.record_startup();

    // Initialize gateway client
    let gateway_config = GatewayClientConfig::from_env();
    let gateway_client = Arc::new(GatewayClient::new(gateway_config));

    // Try to connect to gateway (non-blocking, will retry during reconciliation)
    if let Err(e) = gateway_client.connect().await {
        warn!("Initial gateway connection failed (will retry): {}", e);
        metrics.set_gateway_connected(false);
    } else {
        info!("Connected to gateway service");
        metrics.set_gateway_connected(true);
    }

    // Create application state
    let state = Arc::new(AppState::new(metrics.clone(), gateway_client.clone()));

    // Initialize worker manager
    let worker_manager = WorkerManager::new(
        client.clone(),
        config.worker_namespace.clone(),
        config.worker_selector.clone(),
        config.worker_grpc_port,
    );
    {
        let mut wm = state.worker_manager.write().await;
        *wm = Some(worker_manager);
    }

    // Initial worker discovery
    if let Some(ref wm) = *state.worker_manager.read().await {
        match wm.discover_workers().await {
            Ok(workers) => {
                info!("Discovered {} worker pods", workers.len());
                metrics.record_worker_count(workers.len());
            }
            Err(e) => {
                warn!("Initial worker discovery failed: {}", e);
            }
        }
    }

    // Start health/metrics server
    let health_server = start_health_server(state.clone(), &config);

    // Print CRD information
    print_crd_info();

    // Leader election handling
    let is_leader = if config.leader_election {
        // In production, implement proper leader election using k8s leases
        // For now, assume we're always the leader in single-replica deployments
        info!("Leader election enabled, assuming leadership");
        Arc::new(AtomicBool::new(true))
    } else {
        info!("Leader election disabled");
        Arc::new(AtomicBool::new(true))
    };

    state.is_leader.store(true, Ordering::SeqCst);
    metrics.set_leader(true);

    // Create event recorder
    let reporter = Reporter {
        controller: "pistonprotection-operator".to_string(),
        instance: std::env::var("POD_NAME").ok(),
    };

    // Start controllers
    let ddos_controller = start_ddos_controller(
        client.clone(),
        gateway_client.clone(),
        metrics.clone(),
        &config,
        reporter.clone(),
    );

    let filter_controller = start_filter_controller(
        client.clone(),
        gateway_client.clone(),
        metrics.clone(),
        &config,
        reporter.clone(),
    );

    let backend_controller = if config.enable_backend_controller {
        Some(start_backend_controller(
            client.clone(),
            gateway_client.clone(),
            metrics.clone(),
            &config,
            reporter.clone(),
        ))
    } else {
        None
    };

    let ipblocklist_controller = if config.enable_ipblocklist_controller {
        Some(start_ipblocklist_controller(
            client.clone(),
            gateway_client.clone(),
            metrics.clone(),
            &config,
            reporter.clone(),
        ))
    } else {
        None
    };

    // Mark as ready
    state.ready.store(true, Ordering::SeqCst);
    info!("Operator is ready");

    // Run all controllers concurrently
    tokio::select! {
        result = health_server => {
            if let Err(e) = result {
                error!("Health server error: {}", e);
            }
        }
        _ = ddos_controller => {
            error!("DDoSProtection controller exited unexpectedly");
        }
        _ = filter_controller => {
            error!("FilterRule controller exited unexpectedly");
        }
        _ = async {
            if let Some(ctrl) = backend_controller {
                ctrl.await
            } else {
                // Never completes if backend controller is disabled
                std::future::pending::<()>().await
            }
        } => {
            error!("Backend controller exited unexpectedly");
        }
        _ = async {
            if let Some(ctrl) = ipblocklist_controller {
                ctrl.await
            } else {
                // Never completes if IPBlocklist controller is disabled
                std::future::pending::<()>().await
            }
        } => {
            error!("IPBlocklist controller exited unexpectedly");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
    }

    info!("Shutting down operator");
    state.ready.store(false, Ordering::SeqCst);

    Ok(())
}

/// Start the DDoSProtection controller
async fn start_ddos_controller(
    client: Client,
    gateway_client: Arc<GatewayClient>,
    metrics: Arc<Metrics>,
    config: &OperatorConfig,
    reporter: Reporter,
) {
    let api: Api<DDoSProtection> = match &config.namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };

    let ctx = Arc::new(controllers::ddos_protection::Context::new(
        client.clone(),
        (*gateway_client).clone(),
        metrics.clone(),
        reporter,
    ));

    info!("Starting DDoSProtection controller");

    Controller::new(api, WatcherConfig::default().any_semantic())
        .shutdown_on_signal()
        .run(
            controllers::ddos_protection::reconcile,
            controllers::ddos_protection::error_policy,
            ctx,
        )
        .for_each(|result| async {
            match result {
                Ok((obj, _action)) => {
                    info!("Reconciled DDoSProtection: {}", obj.name);
                }
                Err(e) => {
                    error!("Reconciliation error: {:?}", e);
                }
            }
        })
        .await;
}

/// Start the FilterRule controller
async fn start_filter_controller(
    client: Client,
    gateway_client: Arc<GatewayClient>,
    metrics: Arc<Metrics>,
    config: &OperatorConfig,
    reporter: Reporter,
) {
    let api: Api<FilterRule> = match &config.namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };

    let ctx = Arc::new(controllers::filter_rule::Context::new(
        client.clone(),
        (*gateway_client).clone(),
        metrics.clone(),
        reporter,
    ));

    info!("Starting FilterRule controller");

    Controller::new(api, WatcherConfig::default().any_semantic())
        .shutdown_on_signal()
        .run(
            controllers::filter_rule::reconcile,
            controllers::filter_rule::error_policy,
            ctx,
        )
        .for_each(|result| async {
            match result {
                Ok((obj, _action)) => {
                    info!("Reconciled FilterRule: {}", obj.name);
                }
                Err(e) => {
                    error!("Reconciliation error: {:?}", e);
                }
            }
        })
        .await;
}

/// Start the Backend controller
async fn start_backend_controller(
    client: Client,
    gateway_client: Arc<GatewayClient>,
    metrics: Arc<Metrics>,
    config: &OperatorConfig,
    reporter: Reporter,
) {
    let api: Api<Backend> = match &config.namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };

    let ctx = Arc::new(controllers::backend::Context::new(
        client.clone(),
        (*gateway_client).clone(),
        metrics.clone(),
        reporter,
    ));

    info!("Starting Backend controller");

    Controller::new(api, WatcherConfig::default().any_semantic())
        .shutdown_on_signal()
        .run(
            controllers::backend::reconcile,
            controllers::backend::error_policy,
            ctx,
        )
        .for_each(|result| async {
            match result {
                Ok((obj, _action)) => {
                    info!("Reconciled Backend: {}", obj.name);
                }
                Err(e) => {
                    error!("Reconciliation error: {:?}", e);
                }
            }
        })
        .await;
}

/// Start the IPBlocklist controller
async fn start_ipblocklist_controller(
    client: Client,
    gateway_client: Arc<GatewayClient>,
    metrics: Arc<Metrics>,
    config: &OperatorConfig,
    reporter: Reporter,
) {
    let api: Api<IPBlocklist> = match &config.namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };

    let ctx = Arc::new(controllers::ip_blocklist::Context::new(
        client.clone(),
        (*gateway_client).clone(),
        metrics.clone(),
        reporter,
    ));

    info!("Starting IPBlocklist controller");

    Controller::new(api, WatcherConfig::default().any_semantic())
        .shutdown_on_signal()
        .run(
            controllers::ip_blocklist::reconcile,
            controllers::ip_blocklist::error_policy,
            ctx,
        )
        .for_each(|result| async {
            match result {
                Ok((obj, _action)) => {
                    info!("Reconciled IPBlocklist: {}", obj.name);
                }
                Err(e) => {
                    error!("Reconciliation error: {:?}", e);
                }
            }
        })
        .await;
}

/// Start the health and metrics HTTP server
async fn start_health_server(state: Arc<AppState>, config: &OperatorConfig) -> Result<()> {
    let app = Router::new()
        .route("/healthz", get(health_handler))
        .route("/readyz", get(readiness_handler))
        .route("/metrics", get(metrics_handler))
        .route("/", get(root_handler))
        .with_state(state);

    let addr: std::net::SocketAddr = config.health_addr.parse()?;
    info!("Starting health/metrics server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .await
        .context("Health server failed")?;

    Ok(())
}

/// Health check handler
async fn health_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if state.healthy.load(Ordering::SeqCst) {
        (StatusCode::OK, "OK")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "Unhealthy")
    }
}

/// Readiness check handler
async fn readiness_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if state.ready.load(Ordering::SeqCst) && state.is_leader.load(Ordering::SeqCst) {
        (StatusCode::OK, "Ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "Not Ready")
    }
}

/// Metrics handler
async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let output = state.metrics.encode();
    (
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8")],
        output,
    )
}

/// Root handler
async fn root_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        format!(
            "PistonProtection Operator v{}\n\nEndpoints:\n  /healthz - Health check\n  /readyz - Readiness check\n  /metrics - Prometheus metrics\n",
            env!("CARGO_PKG_VERSION")
        ),
    )
}

/// Print CRD information for debugging
fn print_crd_info() {
    info!("Registered CRDs:");
    info!(
        "  - {}/{}",
        DDoSProtection::group(&()),
        DDoSProtection::kind(&())
    );
    info!("  - {}/{}", FilterRule::group(&()), FilterRule::kind(&()));
    info!("  - {}/{}", Backend::group(&()), Backend::kind(&()));
    info!("  - {}/{}", IPBlocklist::group(&()), IPBlocklist::kind(&()));
}

/// Generate CRD YAML manifests (for installation)
#[allow(dead_code)]
fn generate_crds() -> String {
    let ddos_crd = serde_yaml::to_string(&DDoSProtection::crd()).unwrap();
    let filter_crd = serde_yaml::to_string(&FilterRule::crd()).unwrap();
    let backend_crd = serde_yaml::to_string(&Backend::crd()).unwrap();
    let ipblocklist_crd = serde_yaml::to_string(&IPBlocklist::crd()).unwrap();

    format!(
        "---\n{}\n---\n{}\n---\n{}\n---\n{}",
        ddos_crd, filter_crd, backend_crd, ipblocklist_crd
    )
}

#[cfg(test)]
mod main_tests {
    use super::*;

    #[test]
    fn test_operator_config_default() {
        let config = OperatorConfig::default();
        assert!(config.leader_election);
        assert_eq!(config.concurrency, 4);
        assert!(config.enable_backend_controller);
        assert!(config.enable_ipblocklist_controller);
    }

    #[test]
    fn test_generate_crds() {
        let crds = generate_crds();
        assert!(crds.contains("DDoSProtection"));
        assert!(crds.contains("FilterRule"));
        assert!(crds.contains("Backend"));
        assert!(crds.contains("IPBlocklist"));
        assert!(crds.contains("pistonprotection.io"));
    }

    #[test]
    fn test_app_state() {
        let metrics = Arc::new(Metrics::new());
        let gateway = Arc::new(GatewayClient::new(GatewayClientConfig::default()));
        let state = AppState::new(metrics, gateway);

        assert!(!state.ready.load(Ordering::SeqCst));
        assert!(state.healthy.load(Ordering::SeqCst));

        state.ready.store(true, Ordering::SeqCst);
        assert!(state.ready.load(Ordering::SeqCst));
    }
}
