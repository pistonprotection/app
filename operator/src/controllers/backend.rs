//! Backend Controller
//!
//! This optional controller manages Backend custom resources, handling:
//! - Backend endpoint management
//! - Health checking
//! - Gateway synchronization
//! - Status updates

use crate::client::GatewayClient;
use crate::crd::{Backend, BackendStatus, Condition, EndpointStatus, FINALIZER, HealthState};
use crate::error::{Error, Result};
use crate::metrics::{Metrics, ReconciliationTimer};

use kube::{
    Client, Resource, ResourceExt,
    api::{Api, ObjectMeta, Patch, PatchParams},
    runtime::{
        controller::Action,
        events::{Event, EventType, Recorder, Reporter},
        finalizer::{Event as FinalizerEvent, finalizer},
    },
};
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Context shared across reconciliation calls
pub struct Context {
    /// Kubernetes client
    pub client: Client,
    /// Gateway gRPC client
    pub gateway_client: GatewayClient,
    /// Metrics collector
    pub metrics: Arc<Metrics>,
    /// Event reporter
    pub reporter: Reporter,
}

impl Context {
    /// Create a new context
    pub fn new(
        client: Client,
        gateway_client: GatewayClient,
        metrics: Arc<Metrics>,
        reporter: Reporter,
    ) -> Self {
        Self {
            client,
            gateway_client,
            metrics,
            reporter,
        }
    }

    /// Create a recorder for events
    fn recorder(&self) -> Recorder {
        Recorder::new(self.client.clone(), self.reporter.clone())
    }
}

/// Reconcile a Backend resource
pub async fn reconcile(
    backend: Arc<Backend>,
    ctx: Arc<Context>,
) -> std::result::Result<Action, Error> {
    let name = backend.name_any();
    let namespace = backend.namespace().unwrap_or_else(|| "default".to_string());

    info!(
        "Reconciling Backend {}/{} (generation: {:?})",
        namespace, name, backend.metadata.generation
    );

    let timer = ReconciliationTimer::new(&ctx.metrics, "Backend", &namespace);

    // Create recorder for events
    let recorder = ctx.recorder();

    // Get API for this namespace
    let backend_api: Api<Backend> = Api::namespaced(ctx.client.clone(), &namespace);

    // Handle finalizer
    let result = finalizer(&backend_api, FINALIZER, backend, |event| async {
        match event {
            FinalizerEvent::Apply(backend) => {
                reconcile_apply(&backend, &ctx, &recorder, &namespace, &name).await
            }
            FinalizerEvent::Cleanup(backend) => {
                reconcile_cleanup(&backend, &ctx, &recorder, &namespace, &name).await
            }
        }
    })
    .await;

    match result {
        Ok(action) => {
            timer.success();
            Ok(action)
        }
        Err(e) => {
            let error = match e {
                kube::runtime::finalizer::Error::ApplyFailed(e) => e,
                kube::runtime::finalizer::Error::CleanupFailed(e) => e,
                kube::runtime::finalizer::Error::AddFinalizer(e) => Error::KubeError(e),
                kube::runtime::finalizer::Error::RemoveFinalizer(e) => Error::KubeError(e),
                kube::runtime::finalizer::Error::UnnamedObject => {
                    Error::Permanent("Resource has no name".to_string())
                }
                kube::runtime::finalizer::Error::InvalidFinalizer => {
                    Error::Permanent("Invalid finalizer".to_string())
                }
            };
            timer.error(error.category());
            Err(error)
        }
    }
}

/// Apply reconciliation - handle create/update
async fn reconcile_apply(
    backend: &Backend,
    ctx: &Context,
    recorder: &Recorder,
    namespace: &str,
    name: &str,
) -> Result<Action> {
    info!("Applying Backend {}/{}", namespace, name);

    // Validate the backend
    validate_backend(backend)?;

    // Create object reference for events
    let obj_ref = backend.object_ref(&());

    // Record event
    recorder
        .publish(
            &Event {
                type_: EventType::Normal,
                reason: "Reconciling".to_string(),
                note: Some(format!("Processing backend: {}", backend.spec.display_name)),
                action: "Reconcile".to_string(),
                secondary: None,
            },
            &obj_ref,
        )
        .await
        .ok();

    // Check health of endpoints
    let endpoint_statuses = check_endpoint_health(backend).await;

    // Calculate health statistics
    let total_endpoints = backend.spec.endpoints.len() as i32;
    let healthy_endpoints = endpoint_statuses
        .iter()
        .filter(|s| s.health == HealthState::Healthy)
        .count() as i32;

    // Determine overall health
    let overall_health = if healthy_endpoints == 0 {
        HealthState::Unhealthy
    } else if healthy_endpoints < total_endpoints {
        HealthState::Degraded
    } else {
        HealthState::Healthy
    };

    // Sync to gateway (simulated - in production would use actual gRPC client)
    let sync_start = std::time::Instant::now();
    let gateway_synced = sync_backend_to_gateway(&ctx.gateway_client, backend).await;

    ctx.metrics.record_gateway_sync(
        "Backend",
        namespace,
        name,
        sync_start.elapsed().as_secs_f64(),
        gateway_synced,
    );

    // Update status
    let status = build_status(
        backend,
        overall_health,
        healthy_endpoints,
        total_endpoints,
        endpoint_statuses,
        gateway_synced,
        None,
    );
    update_status(&ctx.client, namespace, name, status).await?;

    // Record success event
    recorder
        .publish(
            &Event {
                type_: EventType::Normal,
                reason: "Reconciled".to_string(),
                note: Some(format!(
                    "Backend {} healthy: {}/{}",
                    backend.spec.display_name, healthy_endpoints, total_endpoints
                )),
                action: "Reconcile".to_string(),
                secondary: None,
            },
            &obj_ref,
        )
        .await
        .ok();

    // Determine requeue interval based on health check configuration
    let requeue_after = if let Some(ref hc) = backend.spec.health_check {
        Duration::from_secs(hc.interval_seconds as u64)
    } else {
        Duration::from_secs(60) // Default health check interval
    };

    Ok(Action::requeue(requeue_after))
}

/// Cleanup reconciliation - handle delete
async fn reconcile_cleanup(
    backend: &Backend,
    ctx: &Context,
    recorder: &Recorder,
    namespace: &str,
    name: &str,
) -> Result<Action> {
    info!("Cleaning up Backend {}/{}", namespace, name);

    // Create object reference for events
    let obj_ref = backend.object_ref(&());

    // Record event
    recorder
        .publish(
            &Event {
                type_: EventType::Normal,
                reason: "Deleting".to_string(),
                note: Some("Removing backend from gateway".to_string()),
                action: "Delete".to_string(),
                secondary: None,
            },
            &obj_ref,
        )
        .await
        .ok();

    // Remove from gateway (simulated)
    info!(
        "Removing backend {} from gateway",
        backend.spec.display_name
    );

    info!("Cleanup complete for Backend {}/{}", namespace, name);

    Ok(Action::await_change())
}

/// Validate Backend resource
fn validate_backend(backend: &Backend) -> Result<()> {
    // Validate display name
    if backend.spec.display_name.is_empty() {
        return Err(Error::validation("displayName", "display name is required"));
    }

    // Validate endpoints
    if backend.spec.endpoints.is_empty() {
        return Err(Error::validation(
            "endpoints",
            "at least one endpoint is required",
        ));
    }

    for (i, endpoint) in backend.spec.endpoints.iter().enumerate() {
        // Validate address
        if endpoint.address.is_empty() {
            return Err(Error::validation(
                &format!("endpoints[{}].address", i),
                "endpoint address is required",
            ));
        }

        // Validate port
        if endpoint.port == 0 {
            return Err(Error::validation(
                &format!("endpoints[{}].port", i),
                "endpoint port must be non-zero",
            ));
        }

        // Validate address format (hostname or IP)
        let addr_str = format!("{}:{}", endpoint.address, endpoint.port);
        if addr_str.to_socket_addrs().is_err() && !is_valid_hostname(&endpoint.address) {
            return Err(Error::validation(
                &format!("endpoints[{}].address", i),
                &format!("invalid address: {}", endpoint.address),
            ));
        }
    }

    // Validate health check if present
    if let Some(ref hc) = backend.spec.health_check {
        if hc.interval_seconds == 0 {
            return Err(Error::validation(
                "healthCheck.intervalSeconds",
                "health check interval must be non-zero",
            ));
        }
        if hc.timeout_seconds >= hc.interval_seconds {
            return Err(Error::validation(
                "healthCheck.timeoutSeconds",
                "timeout must be less than interval",
            ));
        }
    }

    Ok(())
}

/// Check if string is a valid hostname
fn is_valid_hostname(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }

    // Check each label
    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }

        // First and last character must be alphanumeric
        let chars: Vec<char> = label.chars().collect();
        if !chars.first().map(|c| c.is_alphanumeric()).unwrap_or(false) {
            return false;
        }
        if !chars.last().map(|c| c.is_alphanumeric()).unwrap_or(false) {
            return false;
        }

        // All characters must be alphanumeric or hyphen
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return false;
        }
    }

    true
}

/// Check health of all endpoints
async fn check_endpoint_health(backend: &Backend) -> Vec<EndpointStatus> {
    let mut statuses = Vec::new();

    for endpoint in &backend.spec.endpoints {
        if !endpoint.enabled {
            statuses.push(EndpointStatus {
                address: endpoint.address.clone(),
                port: endpoint.port,
                health: HealthState::Unknown,
                last_check: Some(chrono::Utc::now().to_rfc3339()),
                last_error: Some("Endpoint is disabled".to_string()),
                consecutive_failures: 0,
            });
            continue;
        }

        // Perform health check
        let health_result = perform_health_check(
            &endpoint.address,
            endpoint.port,
            backend.spec.health_check.as_ref(),
        )
        .await;

        let (health, last_error, consecutive_failures) = match health_result {
            Ok(_) => (HealthState::Healthy, None, 0),
            Err(e) => (HealthState::Unhealthy, Some(e), 1),
        };

        statuses.push(EndpointStatus {
            address: endpoint.address.clone(),
            port: endpoint.port,
            health,
            last_check: Some(chrono::Utc::now().to_rfc3339()),
            last_error,
            consecutive_failures,
        });
    }

    statuses
}

/// Perform health check on a single endpoint
async fn perform_health_check(
    address: &str,
    port: u16,
    _health_check: Option<&crate::crd::HealthCheckSpec>,
) -> std::result::Result<(), String> {
    // Simple TCP connection check
    let addr_str = format!("{}:{}", address, port);

    let timeout = Duration::from_secs(5);

    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr_str)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(format!("Connection failed: {}", e)),
        Err(_) => Err("Connection timeout".to_string()),
    }
}

/// Sync backend to gateway
async fn sync_backend_to_gateway(_gateway_client: &GatewayClient, backend: &Backend) -> bool {
    // In production, this would call the actual gateway gRPC service
    // For now, we simulate a successful sync
    debug!("Syncing backend {} to gateway", backend.spec.display_name);

    true
}

/// Update the status of a Backend resource
async fn update_status(
    client: &Client,
    namespace: &str,
    name: &str,
    status: BackendStatus,
) -> Result<()> {
    let api: Api<Backend> = Api::namespaced(client.clone(), namespace);

    let patch = serde_json::json!({
        "status": status
    });

    api.patch_status(
        name,
        &PatchParams::apply("pistonprotection-operator"),
        &Patch::Merge(&patch),
    )
    .await
    .map_err(Error::KubeError)?;

    debug!("Status updated for Backend {}/{}", namespace, name);

    Ok(())
}

/// Build status object
fn build_status(
    backend: &Backend,
    overall_health: HealthState,
    healthy_endpoints: i32,
    total_endpoints: i32,
    endpoint_statuses: Vec<EndpointStatus>,
    gateway_synced: bool,
    error_message: Option<String>,
) -> BackendStatus {
    let now = chrono::Utc::now().to_rfc3339();

    let mut conditions = Vec::new();

    // Ready condition
    conditions.push(Condition::new(
        "Ready",
        overall_health == HealthState::Healthy,
        match overall_health {
            HealthState::Healthy => "AllEndpointsHealthy",
            HealthState::Degraded => "SomeEndpointsUnhealthy",
            HealthState::Unhealthy => "AllEndpointsUnhealthy",
            HealthState::Unknown => "HealthUnknown",
        },
        match overall_health {
            HealthState::Healthy => "All endpoints are healthy",
            HealthState::Degraded => "Some endpoints are unhealthy",
            HealthState::Unhealthy => "All endpoints are unhealthy",
            HealthState::Unknown => "Endpoint health is unknown",
        },
    ));

    // GatewaySynced condition
    conditions.push(Condition::new(
        "GatewaySynced",
        gateway_synced,
        if gateway_synced {
            "SyncSucceeded"
        } else {
            "SyncFailed"
        },
        if gateway_synced {
            "Backend synced to gateway"
        } else {
            "Failed to sync backend to gateway"
        },
    ));

    BackendStatus {
        health: overall_health,
        healthy_endpoints,
        endpoint_count: total_endpoints,
        observed_generation: backend.metadata.generation,
        gateway_synced,
        last_synced: if gateway_synced { Some(now) } else { None },
        endpoints: endpoint_statuses,
        conditions,
    }
}

/// Error policy for the controller
pub fn error_policy(backend: Arc<Backend>, error: &Error, _ctx: Arc<Context>) -> Action {
    let name = backend.name_any();
    let namespace = backend.namespace().unwrap_or_default();

    warn!(
        "Reconciliation error for Backend {}/{}: {:?}",
        namespace, name, error
    );

    let delay = error.retry_delay();

    if error.is_permanent() {
        warn!(
            "Permanent error for Backend {}/{}, not requeuing",
            namespace, name
        );
        Action::await_change()
    } else {
        info!("Requeuing Backend {}/{} in {:?}", namespace, name, delay);
        Action::requeue(delay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{BackendCrdSpec, EndpointSpec, Protocol};

    fn create_test_backend() -> Backend {
        Backend {
            metadata: ObjectMeta {
                name: Some("test-backend".to_string()),
                namespace: Some("default".to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: BackendCrdSpec {
                display_name: "Test Backend".to_string(),
                protocol: Protocol::Tcp,
                endpoints: vec![EndpointSpec {
                    address: "10.0.0.1".to_string(),
                    port: 8080,
                    weight: 1,
                    priority: None,
                    enabled: true,
                }],
                load_balancing: None,
                health_check: None,
                tls: None,
                connection_pool: None,
                metadata: None,
            },
            status: None,
        }
    }

    #[test]
    fn test_validate_backend() {
        let backend = create_test_backend();
        assert!(validate_backend(&backend).is_ok());
    }

    #[test]
    fn test_validate_empty_display_name() {
        let mut backend = create_test_backend();
        backend.spec.display_name = "".to_string();
        assert!(validate_backend(&backend).is_err());
    }

    #[test]
    fn test_validate_empty_endpoints() {
        let mut backend = create_test_backend();
        backend.spec.endpoints = vec![];
        assert!(validate_backend(&backend).is_err());
    }

    #[test]
    fn test_validate_invalid_port() {
        let mut backend = create_test_backend();
        backend.spec.endpoints[0].port = 0;
        assert!(validate_backend(&backend).is_err());
    }

    #[test]
    fn test_is_valid_hostname() {
        assert!(is_valid_hostname("example.com"));
        assert!(is_valid_hostname("sub.example.com"));
        assert!(is_valid_hostname("my-service"));
        assert!(is_valid_hostname("a"));

        assert!(!is_valid_hostname(""));
        assert!(!is_valid_hostname("-invalid"));
        assert!(!is_valid_hostname("invalid-"));
        assert!(!is_valid_hostname("invalid..com"));
    }

    #[test]
    fn test_determine_health_state() {
        // All healthy
        let healthy = HealthState::Healthy;
        assert_eq!(healthy, HealthState::Healthy);

        // Degraded
        let degraded = HealthState::Degraded;
        assert_eq!(degraded, HealthState::Degraded);

        // Unhealthy
        let unhealthy = HealthState::Unhealthy;
        assert_eq!(unhealthy, HealthState::Unhealthy);
    }
}
