//! Prometheus metrics utilities

use prometheus::{
    register_counter_vec, register_gauge_vec, register_histogram_vec, CounterVec, Encoder,
    GaugeVec, HistogramVec, TextEncoder,
};

lazy_static::lazy_static! {
    /// gRPC request counter
    pub static ref GRPC_REQUESTS_TOTAL: CounterVec = register_counter_vec!(
        "grpc_requests_total",
        "Total number of gRPC requests",
        &["service", "method", "status"]
    ).unwrap();

    /// gRPC request duration histogram
    pub static ref GRPC_REQUEST_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "grpc_request_duration_seconds",
        "gRPC request duration in seconds",
        &["service", "method"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    ).unwrap();

    /// Active connections gauge
    pub static ref ACTIVE_CONNECTIONS: GaugeVec = register_gauge_vec!(
        "active_connections",
        "Number of active connections",
        &["service", "type"]
    ).unwrap();

    /// Database query counter
    pub static ref DB_QUERIES_TOTAL: CounterVec = register_counter_vec!(
        "db_queries_total",
        "Total number of database queries",
        &["service", "operation", "status"]
    ).unwrap();

    /// Database query duration histogram
    pub static ref DB_QUERY_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "db_query_duration_seconds",
        "Database query duration in seconds",
        &["service", "operation"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5]
    ).unwrap();

    /// Cache operations counter
    pub static ref CACHE_OPERATIONS_TOTAL: CounterVec = register_counter_vec!(
        "cache_operations_total",
        "Total number of cache operations",
        &["service", "operation", "result"]
    ).unwrap();

    /// Traffic bytes counter
    pub static ref TRAFFIC_BYTES_TOTAL: CounterVec = register_counter_vec!(
        "traffic_bytes_total",
        "Total bytes processed",
        &["backend_id", "direction"]
    ).unwrap();

    /// Traffic packets counter
    pub static ref TRAFFIC_PACKETS_TOTAL: CounterVec = register_counter_vec!(
        "traffic_packets_total",
        "Total packets processed",
        &["backend_id", "action"]
    ).unwrap();

    /// Attack detection gauge
    pub static ref ATTACK_DETECTED: GaugeVec = register_gauge_vec!(
        "attack_detected",
        "Whether an attack is currently detected (1 = yes, 0 = no)",
        &["backend_id", "attack_type"]
    ).unwrap();

    /// Protection level gauge
    pub static ref PROTECTION_LEVEL: GaugeVec = register_gauge_vec!(
        "protection_level",
        "Current protection level (0-5)",
        &["backend_id"]
    ).unwrap();
}

/// Encode all metrics as Prometheus text format
pub fn encode_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();

    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        tracing::error!("Failed to encode metrics: {}", e);
        return String::from("# Error encoding metrics\n");
    }

    String::from_utf8(buffer).unwrap_or_else(|e| {
        tracing::error!("Metrics output is not valid UTF-8: {}", e);
        String::from("# Error: invalid UTF-8 in metrics\n")
    })
}

/// Helper struct for timing operations
pub struct Timer {
    start: std::time::Instant,
    histogram: HistogramVec,
    labels: Vec<String>,
}

impl Timer {
    /// Start a new timer
    pub fn start(histogram: &HistogramVec, labels: &[&str]) -> Self {
        Self {
            start: std::time::Instant::now(),
            histogram: histogram.clone(),
            labels: labels.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Record the elapsed time
    pub fn record(self) {
        let duration = self.start.elapsed().as_secs_f64();
        let labels: Vec<&str> = self.labels.iter().map(|s| s.as_str()).collect();
        self.histogram.with_label_values(&labels).observe(duration);
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        // Auto-record on drop if not already recorded
        let duration = self.start.elapsed().as_secs_f64();
        let labels: Vec<&str> = self.labels.iter().map(|s| s.as_str()).collect();
        self.histogram.with_label_values(&labels).observe(duration);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_encode() {
        // Increment a counter
        GRPC_REQUESTS_TOTAL
            .with_label_values(&["test", "test_method", "ok"])
            .inc();

        // Encode metrics
        let output = encode_metrics();
        assert!(output.contains("grpc_requests_total"));
    }
}
