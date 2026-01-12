//! Configuration management for PistonProtection services

use serde::Deserialize;
use std::env;

/// Base configuration shared by all services
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Service name
    pub service_name: String,

    /// Environment (development, staging, production)
    #[serde(default = "default_environment")]
    pub environment: String,

    /// Server configuration
    #[serde(default)]
    pub server: ServerConfig,

    /// Database configuration
    pub database: Option<DatabaseConfig>,

    /// Redis configuration
    pub redis: Option<RedisConfig>,

    /// Telemetry configuration
    #[serde(default)]
    pub telemetry: TelemetryConfig,

    /// Metrics configuration
    #[serde(default)]
    pub metrics: MetricsConfig,
}

fn default_environment() -> String {
    "development".to_string()
}

/// Server configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// gRPC server host
    #[serde(default = "default_host")]
    pub host: String,

    /// gRPC server port
    #[serde(default = "default_grpc_port")]
    pub grpc_port: u16,

    /// HTTP server port (for health checks, metrics)
    #[serde(default = "default_http_port")]
    pub http_port: u16,

    /// Maximum concurrent connections
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    /// Request timeout in seconds
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,

    /// Enable TLS
    #[serde(default)]
    pub tls_enabled: bool,

    /// TLS certificate path
    pub tls_cert_path: Option<String>,

    /// TLS key path
    pub tls_key_path: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            grpc_port: default_grpc_port(),
            http_port: default_http_port(),
            max_connections: default_max_connections(),
            request_timeout_secs: default_request_timeout(),
            tls_enabled: false,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_grpc_port() -> u16 {
    50051
}

fn default_http_port() -> u16 {
    8080
}

fn default_max_connections() -> u32 {
    10000
}

fn default_request_timeout() -> u64 {
    30
}

/// Database configuration
#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    /// Database URL
    pub url: String,

    /// Maximum pool size
    #[serde(default = "default_db_pool_size")]
    pub max_pool_size: u32,

    /// Minimum pool size
    #[serde(default = "default_db_min_pool_size")]
    pub min_pool_size: u32,

    /// Connection timeout in seconds
    #[serde(default = "default_db_connect_timeout")]
    pub connect_timeout_secs: u64,

    /// Idle timeout in seconds
    #[serde(default = "default_db_idle_timeout")]
    pub idle_timeout_secs: u64,

    /// Enable SSL
    #[serde(default)]
    pub ssl_enabled: bool,
}

fn default_db_pool_size() -> u32 {
    20
}

fn default_db_min_pool_size() -> u32 {
    5
}

fn default_db_connect_timeout() -> u64 {
    10
}

fn default_db_idle_timeout() -> u64 {
    300
}

/// Redis configuration
#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    /// Redis URL
    pub url: String,

    /// Pool size
    #[serde(default = "default_redis_pool_size")]
    pub pool_size: usize,

    /// Connection timeout in seconds
    #[serde(default = "default_redis_timeout")]
    pub timeout_secs: u64,

    /// Enable cluster mode
    #[serde(default)]
    pub cluster_enabled: bool,

    /// Cluster nodes (if cluster mode enabled)
    #[serde(default)]
    pub cluster_nodes: Vec<String>,
}

fn default_redis_pool_size() -> usize {
    10
}

fn default_redis_timeout() -> u64 {
    5
}

/// Telemetry configuration
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TelemetryConfig {
    /// Enable OpenTelemetry tracing
    #[serde(default)]
    pub tracing_enabled: bool,

    /// OTLP endpoint
    pub otlp_endpoint: Option<String>,

    /// Log level
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Enable JSON logging
    #[serde(default)]
    pub json_logs: bool,
}

fn default_log_level() -> String {
    "info".to_string()
}

/// Metrics configuration
#[derive(Debug, Clone, Deserialize)]
pub struct MetricsConfig {
    /// Enable Prometheus metrics
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Metrics endpoint path
    #[serde(default = "default_metrics_path")]
    pub path: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: default_metrics_path(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_metrics_path() -> String {
    "/metrics".to_string()
}

impl Config {
    /// Load configuration from environment and files
    pub fn load(service_name: &str) -> Result<Self, config::ConfigError> {
        let environment = env::var("PISTON_ENV").unwrap_or_else(|_| "development".to_string());

        let config_builder = config::Config::builder()
            // Start with default values
            .set_default("service_name", service_name)?
            .set_default("environment", environment.clone())?
            // Load from config directory
            .add_source(
                config::File::with_name(&format!("config/{}", service_name))
                    .required(false),
            )
            // Load environment-specific config
            .add_source(
                config::File::with_name(&format!("config/{}_{}", service_name, environment))
                    .required(false),
            )
            // Override with environment variables (prefix: PISTON_)
            .add_source(
                config::Environment::with_prefix("PISTON")
                    .separator("__")
                    .try_parsing(true),
            );

        config_builder.build()?.try_deserialize()
    }

    /// Check if running in production
    pub fn is_production(&self) -> bool {
        self.environment == "production"
    }

    /// Check if running in development
    pub fn is_development(&self) -> bool {
        self.environment == "development"
    }

    /// Get the gRPC server address
    pub fn grpc_addr(&self) -> String {
        format!("{}:{}", self.server.host, self.server.grpc_port)
    }

    /// Get the HTTP server address
    pub fn http_addr(&self) -> String {
        format!("{}:{}", self.server.host, self.server.http_port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let server = ServerConfig::default();
        assert_eq!(server.host, "0.0.0.0");
        assert_eq!(server.grpc_port, 50051);
        assert_eq!(server.http_port, 8080);
    }
}
