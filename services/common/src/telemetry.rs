//! Telemetry and tracing configuration

use crate::config::TelemetryConfig;
use crate::error::Result;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::WithExportConfig;
use tracing::info;
use tracing_subscriber::{
    fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry,
};

/// Initialize telemetry (tracing and logging)
pub fn init(service_name: &str, config: &TelemetryConfig) -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.log_level));

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
            let tracer = opentelemetry_otlp::new_pipeline()
                .tracing()
                .with_exporter(
                    opentelemetry_otlp::new_exporter()
                        .tonic()
                        .with_endpoint(endpoint),
                )
                .with_trace_config(
                    opentelemetry::sdk::trace::Config::default().with_resource(
                        opentelemetry::sdk::Resource::new(vec![
                            opentelemetry::KeyValue::new(
                                opentelemetry::semantic_conventions::resource::SERVICE_NAME,
                                service_name.to_string(),
                            ),
                        ]),
                    ),
                )
                .install_batch(opentelemetry::runtime::Tokio)
                .expect("Failed to initialize tracer");

            let telemetry_layer =
                tracing_opentelemetry::layer().with_tracer(tracer.tracer(service_name));

            subscriber.with(telemetry_layer).init();
            info!("OpenTelemetry tracing initialized with endpoint: {}", endpoint);
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
    opentelemetry::global::shutdown_tracer_provider();
}
