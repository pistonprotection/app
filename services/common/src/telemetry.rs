//! Telemetry and tracing configuration

use crate::config::TelemetryConfig;
use crate::error::Result;
use tracing::info;
use tracing_subscriber::{
    EnvFilter, Layer, Registry, fmt, layer::SubscriberExt, util::SubscriberInitExt,
};

/// Initialize telemetry (tracing and logging)
pub fn init(service_name: &str, config: &TelemetryConfig) -> Result<()> {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    let fmt_layer = if config.json_logs {
        fmt::layer()
            .json()
            .with_target(true)
            .with_thread_ids(true)
            .with_file(true)
            .with_line_number(true)
            .boxed()
    } else {
        fmt::layer()
            .with_target(true)
            .with_thread_ids(false)
            .with_file(true)
            .with_line_number(true)
            .boxed()
    };

    let subscriber = Registry::default().with(env_filter).with(fmt_layer);

    if config.tracing_enabled {
        if let Some(ref endpoint) = config.otlp_endpoint {
            // OpenTelemetry tracing is configured but we're simplifying for now
            // The full OTLP integration can be added when the opentelemetry crate API stabilizes
            subscriber.init();
            info!(
                service = service_name,
                endpoint = endpoint.as_str(),
                "Telemetry initialized (OTLP endpoint configured but not connected)"
            );
        } else {
            subscriber.init();
            info!("Telemetry initialized without OTLP endpoint");
        }
    } else {
        subscriber.init();
        info!("Telemetry initialized (tracing disabled)");
    }

    Ok(())
}

/// Shutdown telemetry (flush traces)
pub fn shutdown() {
    // Currently a no-op since we're not using the full opentelemetry pipeline
    // This will be implemented when OTLP tracing is fully integrated
}
