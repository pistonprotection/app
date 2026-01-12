//! Prometheus metrics for the operator

use prometheus::{Counter, Gauge, Histogram, IntCounter, IntGauge, Registry};

pub struct Metrics {
    pub reconciliations_total: IntCounter,
    pub reconciliation_errors_total: IntCounter,
    pub resources_managed: IntGauge,
    pub reconciliation_duration_seconds: Histogram,
}

impl Metrics {
    pub fn new() -> Self {
        let reconciliations_total = IntCounter::new(
            "pistonprotection_reconciliations_total",
            "Total number of reconciliations",
        )
        .unwrap();

        let reconciliation_errors_total = IntCounter::new(
            "pistonprotection_reconciliation_errors_total",
            "Total number of reconciliation errors",
        )
        .unwrap();

        let resources_managed = IntGauge::new(
            "pistonprotection_resources_managed",
            "Number of DDoSProtection resources currently managed",
        )
        .unwrap();

        let reconciliation_duration_seconds = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "pistonprotection_reconciliation_duration_seconds",
                "Duration of reconciliation in seconds",
            )
            .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
        )
        .unwrap();

        Self {
            reconciliations_total,
            reconciliation_errors_total,
            resources_managed,
            reconciliation_duration_seconds,
        }
    }

    pub fn register(&self, registry: &Registry) -> Result<(), prometheus::Error> {
        registry.register(Box::new(self.reconciliations_total.clone()))?;
        registry.register(Box::new(self.reconciliation_errors_total.clone()))?;
        registry.register(Box::new(self.resources_managed.clone()))?;
        registry.register(Box::new(self.reconciliation_duration_seconds.clone()))?;
        Ok(())
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}
