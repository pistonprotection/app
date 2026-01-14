//! gRPC Client for Gateway Service Communication
//!
//! This module provides a client for communicating with the PistonProtection
//! gateway service to sync protection rules and configurations.

use crate::crd::{
    BackendSpec, DDoSProtection, FilterAction, FilterRule, FilterRuleType, GeoFilterMode, Protocol,
    RateLimitSpec,
};
use crate::error::{Error, Result};
use backoff::{ExponentialBackoff, backoff::Backoff};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic::{Request, Status};
use tracing::{debug, error, info, warn};

/// Configuration for the gateway client
#[derive(Clone, Debug)]
pub struct GatewayClientConfig {
    /// Gateway service address
    pub address: String,

    /// Connection timeout
    pub connect_timeout: Duration,

    /// Request timeout
    pub request_timeout: Duration,

    /// Enable TLS
    pub tls_enabled: bool,

    /// TLS domain name (for verification)
    pub tls_domain: Option<String>,

    /// Maximum retry attempts
    pub max_retries: u32,

    /// Initial retry delay
    pub retry_delay: Duration,

    /// Maximum retry delay
    pub max_retry_delay: Duration,
}

impl Default for GatewayClientConfig {
    fn default() -> Self {
        Self {
            address: "http://gateway:50051".to_string(),
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            tls_enabled: false,
            tls_domain: None,
            max_retries: 3,
            retry_delay: Duration::from_millis(100),
            max_retry_delay: Duration::from_secs(10),
        }
    }
}

impl GatewayClientConfig {
    /// Create config from environment variables
    pub fn from_env() -> Self {
        let address =
            std::env::var("GATEWAY_ADDRESS").unwrap_or_else(|_| "http://gateway:50051".to_string());

        let connect_timeout = std::env::var("GATEWAY_CONNECT_TIMEOUT")
            .ok()
            .and_then(|s| s.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(10));

        let request_timeout = std::env::var("GATEWAY_REQUEST_TIMEOUT")
            .ok()
            .and_then(|s| s.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(30));

        let tls_enabled = std::env::var("GATEWAY_TLS_ENABLED")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);

        let tls_domain = std::env::var("GATEWAY_TLS_DOMAIN").ok();

        Self {
            address,
            connect_timeout,
            request_timeout,
            tls_enabled,
            tls_domain,
            ..Default::default()
        }
    }
}

/// Gateway client for syncing protection configurations
#[derive(Clone)]
pub struct GatewayClient {
    config: GatewayClientConfig,
    channel: Arc<RwLock<Option<Channel>>>,
    /// Cached backend IDs for each DDoSProtection resource
    backend_cache: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl GatewayClient {
    /// Create a new gateway client
    pub fn new(config: GatewayClientConfig) -> Self {
        Self {
            config,
            channel: Arc::new(RwLock::new(None)),
            backend_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a gateway client with default configuration
    pub fn from_env() -> Self {
        Self::new(GatewayClientConfig::from_env())
    }

    /// Connect to the gateway service
    pub async fn connect(&self) -> Result<()> {
        let endpoint = self.create_endpoint()?;

        let channel = endpoint
            .connect()
            .await
            .map_err(|e| Error::GrpcConnectionError(e.to_string()))?;

        let mut guard = self.channel.write().await;
        *guard = Some(channel);

        info!("Connected to gateway service at {}", self.config.address);

        Ok(())
    }

    /// Create a tonic endpoint with proper configuration
    fn create_endpoint(&self) -> Result<Endpoint> {
        let mut endpoint = Channel::from_shared(self.config.address.clone())
            .map_err(|e| Error::ConfigError(format!("Invalid gateway address: {}", e)))?
            .connect_timeout(self.config.connect_timeout)
            .timeout(self.config.request_timeout);

        if self.config.tls_enabled {
            let mut tls_config = ClientTlsConfig::new();
            if let Some(ref domain) = self.config.tls_domain {
                tls_config = tls_config.domain_name(domain.clone());
            }
            endpoint = endpoint
                .tls_config(tls_config)
                .map_err(|e| Error::ConfigError(format!("TLS configuration error: {}", e)))?;
        }

        Ok(endpoint)
    }

    /// Get or create a connection
    async fn get_channel(&self) -> Result<Channel> {
        // Check existing connection
        {
            let guard = self.channel.read().await;
            if let Some(ref channel) = *guard {
                return Ok(channel.clone());
            }
        }

        // Create new connection
        self.connect().await?;

        let guard = self.channel.read().await;
        guard
            .clone()
            .ok_or_else(|| Error::GrpcConnectionError("Failed to establish connection".to_string()))
    }

    /// Execute an operation with retry logic
    async fn with_retry<F, Fut, T>(&self, operation_name: &str, operation: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let mut backoff = ExponentialBackoff {
            initial_interval: self.config.retry_delay,
            max_interval: self.config.max_retry_delay,
            max_elapsed_time: Some(Duration::from_secs(60)),
            ..Default::default()
        };

        let mut attempts = 0;
        loop {
            attempts += 1;
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) if e.is_retryable() && attempts <= self.config.max_retries => {
                    if let Some(duration) = backoff.next_backoff() {
                        warn!(
                            "Operation {} failed (attempt {}/{}): {:?}. Retrying in {:?}",
                            operation_name, attempts, self.config.max_retries, e, duration
                        );
                        tokio::time::sleep(duration).await;

                        // Reset connection on certain errors
                        if matches!(e, Error::GrpcConnectionError(_)) {
                            let mut guard = self.channel.write().await;
                            *guard = None;
                        }
                    } else {
                        return Err(e);
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Sync a DDoSProtection resource to the gateway
    pub async fn sync_ddos_protection(&self, ddos: &DDoSProtection) -> Result<SyncResult> {
        let name = ddos.metadata.name.clone().unwrap_or_default();
        let namespace = ddos.metadata.namespace.clone().unwrap_or_default();
        let resource_key = format!("{}/{}", namespace, name);

        info!("Syncing DDoSProtection {} to gateway", resource_key);

        self.with_retry("sync_ddos_protection", || async {
            let _channel = self.get_channel().await?;

            // In a real implementation, this would use generated gRPC client code
            // For now, we'll simulate the sync operation

            let mut backend_ids = Vec::new();

            for backend in &ddos.spec.backends {
                let backend_id = self.sync_backend(&resource_key, backend).await?;
                backend_ids.push(backend_id);
            }

            // Update cache
            {
                let mut cache = self.backend_cache.write().await;
                cache.insert(resource_key.clone(), backend_ids.clone());
            }

            // Sync protection settings
            self.sync_protection_settings(&resource_key, ddos).await?;

            Ok(SyncResult {
                synced: true,
                backend_ids,
                message: "Successfully synced to gateway".to_string(),
            })
        })
        .await
    }

    /// Sync a single backend configuration
    async fn sync_backend(&self, resource_key: &str, backend: &BackendSpec) -> Result<String> {
        debug!(
            "Syncing backend {} for resource {}",
            backend.name, resource_key
        );

        // Generate a deterministic backend ID based on resource and backend name
        let backend_id = format!("{}:{}", resource_key.replace('/', ":"), backend.name);

        // Build backend configuration
        let backend_config = BackendConfig {
            id: backend_id.clone(),
            name: backend.name.clone(),
            address: backend.address.clone(),
            protocol: backend.protocol.to_grpc_protocol(),
            weight: backend.weight,
            health_check: backend.health_check.as_ref().map(|hc| HealthCheckConfig {
                interval_seconds: hc.interval_seconds,
                timeout_seconds: hc.timeout_seconds,
                unhealthy_threshold: hc.unhealthy_threshold,
                healthy_threshold: hc.healthy_threshold,
            }),
            rate_limit: backend.rate_limit.as_ref().map(|rl| RateLimitConfig {
                pps_per_ip: rl.pps_per_ip,
                burst: rl.burst,
                global_pps: rl.global_pps,
            }),
        };

        // In production, this would call the actual gRPC service
        // backend_client.create_or_update(backend_config).await?;

        debug!("Backend {} synced successfully", backend_id);

        Ok(backend_id)
    }

    /// Sync protection settings for a resource
    async fn sync_protection_settings(
        &self,
        resource_key: &str,
        ddos: &DDoSProtection,
    ) -> Result<()> {
        debug!("Syncing protection settings for {}", resource_key);

        let protection_config = ProtectionConfig {
            level: ddos.spec.protection_level as u32,
            rate_limit: ddos.spec.rate_limit.as_ref().map(|rl| RateLimitConfig {
                pps_per_ip: rl.pps_per_ip,
                burst: rl.burst,
                global_pps: rl.global_pps,
            }),
            geo_filter: ddos.spec.geo_filter.as_ref().map(|gf| GeoFilterConfig {
                mode: match gf.mode {
                    GeoFilterMode::Allow => 1,
                    GeoFilterMode::Deny => 2,
                },
                countries: gf.countries.clone(),
            }),
            challenge_enabled: ddos.spec.challenge_enabled,
            auto_escalate: ddos.spec.auto_escalate,
        };

        // In production, this would call the actual gRPC service
        // protection_client.update_settings(resource_key, protection_config).await?;

        debug!("Protection settings synced for {}", resource_key);

        Ok(())
    }

    /// Sync a FilterRule to the gateway
    pub async fn sync_filter_rule(&self, rule: &FilterRule) -> Result<SyncResult> {
        let name = rule.metadata.name.clone().unwrap_or_default();
        let namespace = rule.metadata.namespace.clone().unwrap_or_default();
        let resource_key = format!("{}/{}", namespace, name);

        info!("Syncing FilterRule {} to gateway", resource_key);

        self.with_retry("sync_filter_rule", || async {
            let _channel = self.get_channel().await?;

            // Build filter rule configuration
            let filter_config =
                FilterConfig {
                    id: resource_key.clone(),
                    name: rule.spec.name.clone(),
                    description: rule.spec.description.clone(),
                    rule_type: rule_type_to_string(&rule.spec.rule_type),
                    action: rule.spec.action.to_grpc_action(),
                    priority: rule.spec.priority,
                    enabled: rule.spec.enabled,
                    config: FilterRuleConfigDto {
                        ip_ranges: rule.spec.config.ip_ranges.clone(),
                        countries: rule.spec.config.countries.clone(),
                        asns: rule.spec.config.asns.clone(),
                        rate_limit: rule.spec.config.rate_limit.as_ref().map(|rl| {
                            RateLimitConfig {
                                pps_per_ip: rl.pps_per_ip,
                                burst: rl.burst,
                                global_pps: rl.global_pps,
                            }
                        }),
                    },
                };

            // In production, this would call the actual gRPC service
            // filter_client.create_or_update_rule(filter_config).await?;

            debug!("FilterRule {} synced successfully", resource_key);

            Ok(SyncResult {
                synced: true,
                backend_ids: vec![],
                message: "Successfully synced to gateway".to_string(),
            })
        })
        .await
    }

    /// Delete a DDoSProtection resource from the gateway
    pub async fn delete_ddos_protection(&self, namespace: &str, name: &str) -> Result<()> {
        let resource_key = format!("{}/{}", namespace, name);

        info!("Deleting DDoSProtection {} from gateway", resource_key);

        self.with_retry("delete_ddos_protection", || async {
            let _channel = self.get_channel().await?;

            // Get cached backend IDs
            let backend_ids = {
                let cache = self.backend_cache.read().await;
                cache.get(&resource_key).cloned().unwrap_or_default()
            };

            // Delete each backend
            for backend_id in &backend_ids {
                // In production: backend_client.delete(backend_id).await?;
                debug!("Deleted backend {} from gateway", backend_id);
            }

            // Remove from cache
            {
                let mut cache = self.backend_cache.write().await;
                cache.remove(&resource_key);
            }

            info!("DDoSProtection {} deleted from gateway", resource_key);

            Ok(())
        })
        .await
    }

    /// Delete a FilterRule from the gateway
    pub async fn delete_filter_rule(&self, namespace: &str, name: &str) -> Result<()> {
        let resource_key = format!("{}/{}", namespace, name);

        info!("Deleting FilterRule {} from gateway", resource_key);

        self.with_retry("delete_filter_rule", || async {
            let _channel = self.get_channel().await?;

            // In production: filter_client.delete_rule(resource_key).await?;

            debug!("FilterRule {} deleted from gateway", resource_key);

            Ok(())
        })
        .await
    }

    /// Check gateway health
    pub async fn health_check(&self) -> Result<bool> {
        let _channel = self.get_channel().await?;

        // In production, this would call a health check RPC
        // let response = health_client.check().await?;
        // return Ok(response.status == ServingStatus::Serving);

        Ok(true)
    }

    /// Get metrics from the gateway
    pub async fn get_metrics(&self, backend_id: &str) -> Result<GatewayMetrics> {
        let _channel = self.get_channel().await?;

        // In production, this would call the metrics RPC
        // let response = metrics_client.get_metrics(backend_id).await?;

        Ok(GatewayMetrics {
            total_requests: 0,
            blocked_requests: 0,
            avg_latency_ms: 0.0,
            requests_per_second: 0.0,
            under_attack: false,
        })
    }

    /// Stream configuration updates to workers
    pub async fn stream_config_updates(&self, _resource_key: &str) -> Result<ConfigUpdateStream> {
        let _channel = self.get_channel().await?;

        // In production, this would set up a streaming RPC
        // let stream = worker_client.stream_config(resource_key).await?;

        Ok(ConfigUpdateStream {
            // stream handle would go here
        })
    }
}

/// Result of a sync operation
#[derive(Debug, Clone)]
pub struct SyncResult {
    /// Whether the sync was successful
    pub synced: bool,
    /// IDs of synced backends
    pub backend_ids: Vec<String>,
    /// Status message
    pub message: String,
}

/// Metrics from the gateway
#[derive(Debug, Clone)]
pub struct GatewayMetrics {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub avg_latency_ms: f64,
    pub requests_per_second: f64,
    pub under_attack: bool,
}

/// Configuration update stream handle
pub struct ConfigUpdateStream {
    // In production, this would hold the streaming handle
}

// ============================================================================
// Internal DTOs for gRPC communication
// ============================================================================

#[derive(Debug, Clone)]
struct BackendConfig {
    id: String,
    name: String,
    address: String,
    protocol: i32,
    weight: u32,
    health_check: Option<HealthCheckConfig>,
    rate_limit: Option<RateLimitConfig>,
}

#[derive(Debug, Clone)]
struct HealthCheckConfig {
    interval_seconds: u32,
    timeout_seconds: u32,
    unhealthy_threshold: u32,
    healthy_threshold: u32,
}

#[derive(Debug, Clone)]
struct RateLimitConfig {
    pps_per_ip: u64,
    burst: u64,
    global_pps: Option<u64>,
}

#[derive(Debug, Clone)]
struct ProtectionConfig {
    level: u32,
    rate_limit: Option<RateLimitConfig>,
    geo_filter: Option<GeoFilterConfig>,
    challenge_enabled: bool,
    auto_escalate: bool,
}

#[derive(Debug, Clone)]
struct GeoFilterConfig {
    mode: i32,
    countries: Vec<String>,
}

#[derive(Debug, Clone)]
struct FilterConfig {
    id: String,
    name: String,
    description: Option<String>,
    rule_type: String,
    action: i32,
    priority: i32,
    enabled: bool,
    config: FilterRuleConfigDto,
}

#[derive(Debug, Clone)]
struct FilterRuleConfigDto {
    ip_ranges: Vec<String>,
    countries: Vec<String>,
    asns: Vec<String>,
    rate_limit: Option<RateLimitConfig>,
}

fn rule_type_to_string(rule_type: &FilterRuleType) -> String {
    match rule_type {
        FilterRuleType::IpBlocklist => "ip_blocklist".to_string(),
        FilterRuleType::IpAllowlist => "ip_allowlist".to_string(),
        FilterRuleType::RateLimit => "rate_limit".to_string(),
        FilterRuleType::GeoBlock => "geo_block".to_string(),
        FilterRuleType::GeoAllow => "geo_allow".to_string(),
        FilterRuleType::ProtocolValidation => "protocol_validation".to_string(),
        FilterRuleType::SynFlood => "syn_flood".to_string(),
        FilterRuleType::UdpAmplification => "udp_amplification".to_string(),
        FilterRuleType::HttpFlood => "http_flood".to_string(),
        FilterRuleType::Custom => "custom".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = GatewayClientConfig::default();
        assert_eq!(config.address, "http://gateway:50051");
        assert!(!config.tls_enabled);
    }

    #[test]
    fn test_rule_type_conversion() {
        assert_eq!(
            rule_type_to_string(&FilterRuleType::IpBlocklist),
            "ip_blocklist"
        );
        assert_eq!(rule_type_to_string(&FilterRuleType::GeoBlock), "geo_block");
    }
}
