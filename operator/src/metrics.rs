//! Prometheus Metrics for the PistonProtection Operator
//!
//! This module provides comprehensive metrics for monitoring operator health,
//! reconciliation performance, and resource management.

use prometheus::{
    Gauge, GaugeVec, HistogramOpts, HistogramVec, IntCounter,
    IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
};
use tracing::error;

/// Label names for metrics
const RESOURCE_TYPE_LABEL: &str = "resource_type";
const NAMESPACE_LABEL: &str = "namespace";
const NAME_LABEL: &str = "name";
const PHASE_LABEL: &str = "phase";
const ERROR_CATEGORY_LABEL: &str = "error_category";
const OPERATION_LABEL: &str = "operation";
const STATUS_LABEL: &str = "status";

/// Metrics collector for the operator
#[derive(Clone)]
pub struct Metrics {
    /// Registry for all metrics
    pub registry: Registry,

    // ========================================================================
    // Reconciliation Metrics
    // ========================================================================
    /// Total number of reconciliations performed
    pub reconciliations_total: IntCounterVec,

    /// Total number of reconciliation errors
    pub reconciliation_errors_total: IntCounterVec,

    /// Duration of reconciliation operations
    pub reconciliation_duration_seconds: HistogramVec,

    /// Current reconciliation queue depth
    pub reconciliation_queue_depth: IntGaugeVec,

    /// Number of active reconciliations
    pub active_reconciliations: IntGaugeVec,

    // ========================================================================
    // Resource Metrics
    // ========================================================================
    /// Number of managed resources by type and phase
    pub resources_managed: IntGaugeVec,

    /// Total resources created
    pub resources_created_total: IntCounterVec,

    /// Total resources updated
    pub resources_updated_total: IntCounterVec,

    /// Total resources deleted
    pub resources_deleted_total: IntCounterVec,

    // ========================================================================
    // Gateway Sync Metrics
    // ========================================================================
    /// Gateway sync operations total
    pub gateway_sync_total: IntCounterVec,

    /// Gateway sync errors total
    pub gateway_sync_errors_total: IntCounterVec,

    /// Gateway sync duration
    pub gateway_sync_duration_seconds: HistogramVec,

    /// Gateway connection status (1 = connected, 0 = disconnected)
    pub gateway_connected: IntGauge,

    /// Last successful gateway sync timestamp
    pub gateway_last_sync_timestamp: GaugeVec,

    // ========================================================================
    // Backend Metrics
    // ========================================================================
    /// Number of backends by protection resource
    pub backends_total: IntGaugeVec,

    /// Healthy backends
    pub backends_healthy: IntGaugeVec,

    // ========================================================================
    // Worker Metrics
    // ========================================================================
    /// Desired worker replicas
    pub workers_desired: IntGaugeVec,

    /// Ready worker replicas
    pub workers_ready: IntGaugeVec,

    /// Available worker replicas
    pub workers_available: IntGaugeVec,

    // ========================================================================
    // Kubernetes API Metrics
    // ========================================================================
    /// Kubernetes API calls total
    pub kube_api_calls_total: IntCounterVec,

    /// Kubernetes API call duration
    pub kube_api_duration_seconds: HistogramVec,

    /// Kubernetes API errors
    pub kube_api_errors_total: IntCounterVec,

    // ========================================================================
    // Leader Election Metrics
    // ========================================================================
    /// Whether this instance is the leader
    pub leader_election_leader: IntGauge,

    /// Leader election transitions
    pub leader_election_transitions_total: IntCounter,

    // ========================================================================
    // Health Metrics
    // ========================================================================
    /// Operator health status (1 = healthy)
    pub health_status: IntGauge,

    /// Operator startup timestamp
    pub startup_timestamp: Gauge,
}

impl Metrics {
    /// Create a new Metrics instance with all metrics registered
    pub fn new() -> Self {
        let registry = Registry::new();
        let metrics = Self::new_with_registry(registry);
        metrics
    }

    /// Create metrics with a custom registry
    pub fn new_with_registry(registry: Registry) -> Self {
        // Reconciliation metrics
        let reconciliations_total = IntCounterVec::new(
            Opts::new(
                "pistonprotection_reconciliations_total",
                "Total number of reconciliations performed",
            ),
            &[RESOURCE_TYPE_LABEL, NAMESPACE_LABEL],
        )
        .expect("metric creation should succeed");

        let reconciliation_errors_total = IntCounterVec::new(
            Opts::new(
                "pistonprotection_reconciliation_errors_total",
                "Total number of reconciliation errors",
            ),
            &[RESOURCE_TYPE_LABEL, NAMESPACE_LABEL, ERROR_CATEGORY_LABEL],
        )
        .expect("metric creation should succeed");

        let reconciliation_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "pistonprotection_reconciliation_duration_seconds",
                "Duration of reconciliation operations",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &[RESOURCE_TYPE_LABEL],
        )
        .expect("metric creation should succeed");

        let reconciliation_queue_depth = IntGaugeVec::new(
            Opts::new(
                "pistonprotection_reconciliation_queue_depth",
                "Current reconciliation queue depth",
            ),
            &[RESOURCE_TYPE_LABEL],
        )
        .expect("metric creation should succeed");

        let active_reconciliations = IntGaugeVec::new(
            Opts::new(
                "pistonprotection_active_reconciliations",
                "Number of currently active reconciliations",
            ),
            &[RESOURCE_TYPE_LABEL],
        )
        .expect("metric creation should succeed");

        // Resource metrics
        let resources_managed = IntGaugeVec::new(
            Opts::new(
                "pistonprotection_resources_managed",
                "Number of managed resources by type and phase",
            ),
            &[RESOURCE_TYPE_LABEL, PHASE_LABEL],
        )
        .expect("metric creation should succeed");

        let resources_created_total = IntCounterVec::new(
            Opts::new(
                "pistonprotection_resources_created_total",
                "Total resources created",
            ),
            &[RESOURCE_TYPE_LABEL, NAMESPACE_LABEL],
        )
        .expect("metric creation should succeed");

        let resources_updated_total = IntCounterVec::new(
            Opts::new(
                "pistonprotection_resources_updated_total",
                "Total resources updated",
            ),
            &[RESOURCE_TYPE_LABEL, NAMESPACE_LABEL],
        )
        .expect("metric creation should succeed");

        let resources_deleted_total = IntCounterVec::new(
            Opts::new(
                "pistonprotection_resources_deleted_total",
                "Total resources deleted",
            ),
            &[RESOURCE_TYPE_LABEL, NAMESPACE_LABEL],
        )
        .expect("metric creation should succeed");

        // Gateway sync metrics
        let gateway_sync_total = IntCounterVec::new(
            Opts::new(
                "pistonprotection_gateway_sync_total",
                "Total gateway sync operations",
            ),
            &[RESOURCE_TYPE_LABEL, STATUS_LABEL],
        )
        .expect("metric creation should succeed");

        let gateway_sync_errors_total = IntCounterVec::new(
            Opts::new(
                "pistonprotection_gateway_sync_errors_total",
                "Total gateway sync errors",
            ),
            &[RESOURCE_TYPE_LABEL, ERROR_CATEGORY_LABEL],
        )
        .expect("metric creation should succeed");

        let gateway_sync_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "pistonprotection_gateway_sync_duration_seconds",
                "Duration of gateway sync operations",
            )
            .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]),
            &[RESOURCE_TYPE_LABEL],
        )
        .expect("metric creation should succeed");

        let gateway_connected = IntGauge::new(
            "pistonprotection_gateway_connected",
            "Gateway connection status (1 = connected)",
        )
        .expect("metric creation should succeed");

        let gateway_last_sync_timestamp = GaugeVec::new(
            Opts::new(
                "pistonprotection_gateway_last_sync_timestamp",
                "Timestamp of last successful gateway sync",
            ),
            &[RESOURCE_TYPE_LABEL, NAMESPACE_LABEL, NAME_LABEL],
        )
        .expect("metric creation should succeed");

        // Backend metrics
        let backends_total = IntGaugeVec::new(
            Opts::new(
                "pistonprotection_backends_total",
                "Total number of backends",
            ),
            &[NAMESPACE_LABEL, NAME_LABEL],
        )
        .expect("metric creation should succeed");

        let backends_healthy = IntGaugeVec::new(
            Opts::new(
                "pistonprotection_backends_healthy",
                "Number of healthy backends",
            ),
            &[NAMESPACE_LABEL, NAME_LABEL],
        )
        .expect("metric creation should succeed");

        // Worker metrics
        let workers_desired = IntGaugeVec::new(
            Opts::new(
                "pistonprotection_workers_desired",
                "Desired number of worker replicas",
            ),
            &[NAMESPACE_LABEL, NAME_LABEL],
        )
        .expect("metric creation should succeed");

        let workers_ready = IntGaugeVec::new(
            Opts::new(
                "pistonprotection_workers_ready",
                "Number of ready worker replicas",
            ),
            &[NAMESPACE_LABEL, NAME_LABEL],
        )
        .expect("metric creation should succeed");

        let workers_available = IntGaugeVec::new(
            Opts::new(
                "pistonprotection_workers_available",
                "Number of available worker replicas",
            ),
            &[NAMESPACE_LABEL, NAME_LABEL],
        )
        .expect("metric creation should succeed");

        // Kubernetes API metrics
        let kube_api_calls_total = IntCounterVec::new(
            Opts::new(
                "pistonprotection_kube_api_calls_total",
                "Total Kubernetes API calls",
            ),
            &[OPERATION_LABEL, RESOURCE_TYPE_LABEL],
        )
        .expect("metric creation should succeed");

        let kube_api_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "pistonprotection_kube_api_duration_seconds",
                "Duration of Kubernetes API calls",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
            ]),
            &[OPERATION_LABEL, RESOURCE_TYPE_LABEL],
        )
        .expect("metric creation should succeed");

        let kube_api_errors_total = IntCounterVec::new(
            Opts::new(
                "pistonprotection_kube_api_errors_total",
                "Total Kubernetes API errors",
            ),
            &[OPERATION_LABEL, RESOURCE_TYPE_LABEL],
        )
        .expect("metric creation should succeed");

        // Leader election metrics
        let leader_election_leader = IntGauge::new(
            "pistonprotection_leader_election_leader",
            "Whether this instance is the leader (1 = leader)",
        )
        .expect("metric creation should succeed");

        let leader_election_transitions_total = IntCounter::new(
            "pistonprotection_leader_election_transitions_total",
            "Total leader election transitions",
        )
        .expect("metric creation should succeed");

        // Health metrics
        let health_status = IntGauge::new(
            "pistonprotection_health_status",
            "Operator health status (1 = healthy)",
        )
        .expect("metric creation should succeed");

        let startup_timestamp = Gauge::new(
            "pistonprotection_startup_timestamp_seconds",
            "Operator startup timestamp in seconds since epoch",
        )
        .expect("metric creation should succeed");

        let metrics = Self {
            registry,
            reconciliations_total,
            reconciliation_errors_total,
            reconciliation_duration_seconds,
            reconciliation_queue_depth,
            active_reconciliations,
            resources_managed,
            resources_created_total,
            resources_updated_total,
            resources_deleted_total,
            gateway_sync_total,
            gateway_sync_errors_total,
            gateway_sync_duration_seconds,
            gateway_connected,
            gateway_last_sync_timestamp,
            backends_total,
            backends_healthy,
            workers_desired,
            workers_ready,
            workers_available,
            kube_api_calls_total,
            kube_api_duration_seconds,
            kube_api_errors_total,
            leader_election_leader,
            leader_election_transitions_total,
            health_status,
            startup_timestamp,
        };

        // Register all metrics
        if let Err(e) = metrics.register_all() {
            error!("Failed to register metrics: {}", e);
        }

        metrics
    }

    /// Register all metrics with the registry
    fn register_all(&self) -> Result<(), prometheus::Error> {
        self.registry
            .register(Box::new(self.reconciliations_total.clone()))?;
        self.registry
            .register(Box::new(self.reconciliation_errors_total.clone()))?;
        self.registry
            .register(Box::new(self.reconciliation_duration_seconds.clone()))?;
        self.registry
            .register(Box::new(self.reconciliation_queue_depth.clone()))?;
        self.registry
            .register(Box::new(self.active_reconciliations.clone()))?;
        self.registry
            .register(Box::new(self.resources_managed.clone()))?;
        self.registry
            .register(Box::new(self.resources_created_total.clone()))?;
        self.registry
            .register(Box::new(self.resources_updated_total.clone()))?;
        self.registry
            .register(Box::new(self.resources_deleted_total.clone()))?;
        self.registry
            .register(Box::new(self.gateway_sync_total.clone()))?;
        self.registry
            .register(Box::new(self.gateway_sync_errors_total.clone()))?;
        self.registry
            .register(Box::new(self.gateway_sync_duration_seconds.clone()))?;
        self.registry
            .register(Box::new(self.gateway_connected.clone()))?;
        self.registry
            .register(Box::new(self.gateway_last_sync_timestamp.clone()))?;
        self.registry
            .register(Box::new(self.backends_total.clone()))?;
        self.registry
            .register(Box::new(self.backends_healthy.clone()))?;
        self.registry
            .register(Box::new(self.workers_desired.clone()))?;
        self.registry
            .register(Box::new(self.workers_ready.clone()))?;
        self.registry
            .register(Box::new(self.workers_available.clone()))?;
        self.registry
            .register(Box::new(self.kube_api_calls_total.clone()))?;
        self.registry
            .register(Box::new(self.kube_api_duration_seconds.clone()))?;
        self.registry
            .register(Box::new(self.kube_api_errors_total.clone()))?;
        self.registry
            .register(Box::new(self.leader_election_leader.clone()))?;
        self.registry
            .register(Box::new(self.leader_election_transitions_total.clone()))?;
        self.registry
            .register(Box::new(self.health_status.clone()))?;
        self.registry
            .register(Box::new(self.startup_timestamp.clone()))?;
        Ok(())
    }

    /// Record a reconciliation start
    pub fn record_reconciliation_start(&self, resource_type: &str) {
        self.active_reconciliations
            .with_label_values(&[resource_type])
            .inc();
    }

    /// Record a reconciliation completion
    pub fn record_reconciliation_complete(
        &self,
        resource_type: &str,
        namespace: &str,
        duration_secs: f64,
        success: bool,
    ) {
        self.active_reconciliations
            .with_label_values(&[resource_type])
            .dec();

        self.reconciliations_total
            .with_label_values(&[resource_type, namespace])
            .inc();

        self.reconciliation_duration_seconds
            .with_label_values(&[resource_type])
            .observe(duration_secs);

        if !success {
            // Error will be recorded separately with category
        }
    }

    /// Record a reconciliation error
    pub fn record_reconciliation_error(
        &self,
        resource_type: &str,
        namespace: &str,
        error_category: &str,
    ) {
        self.reconciliation_errors_total
            .with_label_values(&[resource_type, namespace, error_category])
            .inc();
    }

    /// Record a gateway sync operation
    pub fn record_gateway_sync(
        &self,
        resource_type: &str,
        namespace: &str,
        name: &str,
        duration_secs: f64,
        success: bool,
    ) {
        let status = if success { "success" } else { "failure" };
        self.gateway_sync_total
            .with_label_values(&[resource_type, status])
            .inc();

        self.gateway_sync_duration_seconds
            .with_label_values(&[resource_type])
            .observe(duration_secs);

        if success {
            self.gateway_last_sync_timestamp
                .with_label_values(&[resource_type, namespace, name])
                .set(chrono::Utc::now().timestamp() as f64);
        }
    }

    /// Record gateway sync error
    pub fn record_gateway_sync_error(&self, resource_type: &str, error_category: &str) {
        self.gateway_sync_errors_total
            .with_label_values(&[resource_type, error_category])
            .inc();
    }

    /// Update resource counts
    pub fn set_resource_count(&self, resource_type: &str, phase: &str, count: i64) {
        self.resources_managed
            .with_label_values(&[resource_type, phase])
            .set(count);
    }

    /// Update backend counts
    pub fn set_backend_counts(&self, namespace: &str, name: &str, total: i64, healthy: i64) {
        self.backends_total
            .with_label_values(&[namespace, name])
            .set(total);
        self.backends_healthy
            .with_label_values(&[namespace, name])
            .set(healthy);
    }

    /// Update worker counts
    pub fn set_worker_counts(
        &self,
        namespace: &str,
        name: &str,
        desired: i64,
        ready: i64,
        available: i64,
    ) {
        self.workers_desired
            .with_label_values(&[namespace, name])
            .set(desired);
        self.workers_ready
            .with_label_values(&[namespace, name])
            .set(ready);
        self.workers_available
            .with_label_values(&[namespace, name])
            .set(available);
    }

    /// Record Kubernetes API call
    pub fn record_kube_api_call(
        &self,
        operation: &str,
        resource_type: &str,
        duration_secs: f64,
        success: bool,
    ) {
        self.kube_api_calls_total
            .with_label_values(&[operation, resource_type])
            .inc();

        self.kube_api_duration_seconds
            .with_label_values(&[operation, resource_type])
            .observe(duration_secs);

        if !success {
            self.kube_api_errors_total
                .with_label_values(&[operation, resource_type])
                .inc();
        }
    }

    /// Set leader election status
    pub fn set_leader(&self, is_leader: bool) {
        self.leader_election_leader
            .set(if is_leader { 1 } else { 0 });
        if is_leader {
            self.leader_election_transitions_total.inc();
        }
    }

    /// Set health status
    pub fn set_healthy(&self, healthy: bool) {
        self.health_status.set(if healthy { 1 } else { 0 });
    }

    /// Set gateway connection status
    pub fn set_gateway_connected(&self, connected: bool) {
        self.gateway_connected.set(if connected { 1 } else { 0 });
    }

    /// Record startup time
    pub fn record_startup(&self) {
        self.startup_timestamp
            .set(chrono::Utc::now().timestamp() as f64);
        self.health_status.set(1);
    }

    /// Record total discovered worker pod count
    pub fn record_worker_count(&self, count: usize) {
        // Use a global namespace for overall worker count
        self.workers_available
            .with_label_values(&["_global_", "_all_"])
            .set(count as i64);
    }

    /// Encode metrics for Prometheus scraping
    pub fn encode(&self) -> String {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard for tracking reconciliation duration
pub struct ReconciliationTimer<'a> {
    metrics: &'a Metrics,
    resource_type: String,
    namespace: String,
    start: std::time::Instant,
}

impl<'a> ReconciliationTimer<'a> {
    /// Start a new reconciliation timer
    pub fn new(metrics: &'a Metrics, resource_type: &str, namespace: &str) -> Self {
        metrics.record_reconciliation_start(resource_type);
        Self {
            metrics,
            resource_type: resource_type.to_string(),
            namespace: namespace.to_string(),
            start: std::time::Instant::now(),
        }
    }

    /// Complete the reconciliation successfully
    pub fn success(self) {
        let duration = self.start.elapsed().as_secs_f64();
        self.metrics.record_reconciliation_complete(
            &self.resource_type,
            &self.namespace,
            duration,
            true,
        );
        // Prevent drop from running
        std::mem::forget(self);
    }

    /// Complete the reconciliation with an error
    pub fn error(self, error_category: &str) {
        let duration = self.start.elapsed().as_secs_f64();
        self.metrics.record_reconciliation_complete(
            &self.resource_type,
            &self.namespace,
            duration,
            false,
        );
        self.metrics.record_reconciliation_error(
            &self.resource_type,
            &self.namespace,
            error_category,
        );
        // Prevent drop from running
        std::mem::forget(self);
    }
}

impl Drop for ReconciliationTimer<'_> {
    fn drop(&mut self) {
        // If dropped without calling success/error, record as error
        let duration = self.start.elapsed().as_secs_f64();
        self.metrics.record_reconciliation_complete(
            &self.resource_type,
            &self.namespace,
            duration,
            false,
        );
        self.metrics
            .record_reconciliation_error(&self.resource_type, &self.namespace, "unknown");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = Metrics::new();
        assert!(metrics.encode().contains("pistonprotection"));
    }

    #[test]
    fn test_reconciliation_metrics() {
        let metrics = Metrics::new();

        metrics.record_reconciliation_start("DDoSProtection");
        metrics.record_reconciliation_complete("DDoSProtection", "default", 0.5, true);

        let output = metrics.encode();
        assert!(output.contains("pistonprotection_reconciliations_total"));
    }

    #[test]
    fn test_gateway_metrics() {
        let metrics = Metrics::new();

        metrics.record_gateway_sync("DDoSProtection", "default", "test", 0.1, true);
        metrics.set_gateway_connected(true);

        let output = metrics.encode();
        assert!(output.contains("pistonprotection_gateway_sync_total"));
        assert!(output.contains("pistonprotection_gateway_connected"));
    }
}
