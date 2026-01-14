//! Worker Management Module
//!
//! This module handles:
//! - Worker pod discovery via Kubernetes API
//! - gRPC communication with worker pods
//! - Configuration push to workers
//! - Health monitoring and metrics collection

use crate::crd::{Backend, DDoSProtection, FilterRule, IPBlocklist};
use crate::error::{Error, Result};

use k8s_openapi::api::core::v1::Pod;
use kube::{
    Client, ResourceExt,
    api::{Api, ListParams},
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Worker pod information
#[derive(Clone, Debug)]
pub struct WorkerInfo {
    /// Pod name
    pub name: String,
    /// Namespace
    pub namespace: String,
    /// Pod IP address
    pub ip: String,
    /// gRPC port
    pub grpc_port: u16,
    /// Node name where pod is running
    pub node_name: Option<String>,
    /// Whether worker is ready
    pub ready: bool,
    /// Labels from the pod
    pub labels: HashMap<String, String>,
    /// Last heartbeat time
    pub last_heartbeat: Option<chrono::DateTime<chrono::Utc>>,
    /// Configuration version the worker has
    pub config_version: u32,
}

impl WorkerInfo {
    /// Get the gRPC endpoint address
    pub fn grpc_endpoint(&self) -> String {
        format!("{}:{}", self.ip, self.grpc_port)
    }
}

/// Worker status from heartbeat
#[derive(Clone, Debug, Default)]
pub struct WorkerStatus {
    /// CPU usage percentage
    pub cpu_percent: f32,
    /// Memory usage percentage
    pub memory_percent: f32,
    /// Packets processed per second
    pub packets_per_second: u64,
    /// Bytes processed per second
    pub bytes_per_second: u64,
    /// Number of active connections
    pub active_connections: u64,
    /// XDP program attached
    pub xdp_attached: bool,
    /// Current configuration version
    pub config_version: u32,
}

/// Filter configuration to push to workers
#[derive(Clone, Debug)]
pub struct WorkerFilterConfig {
    /// Configuration version
    pub version: u32,
    /// Backend configurations
    pub backends: Vec<WorkerBackendConfig>,
    /// Global filter rules
    pub global_rules: Vec<WorkerFilterRule>,
    /// IP blocklist entries
    pub blocklist_entries: Vec<WorkerBlocklistEntry>,
    /// Global settings
    pub settings: WorkerGlobalSettings,
}

/// Backend configuration for worker
#[derive(Clone, Debug)]
pub struct WorkerBackendConfig {
    /// Backend ID (namespace/name)
    pub id: String,
    /// Display name
    pub name: String,
    /// Protocol type
    pub protocol: i32,
    /// Destination addresses (CIDR format)
    pub destination_ips: Vec<String>,
    /// Destination ports
    pub destination_ports: Vec<PortRange>,
    /// Protection level (0-5)
    pub protection_level: u32,
    /// Rate limit configuration
    pub rate_limit: Option<WorkerRateLimit>,
    /// GeoIP blocked countries
    pub blocked_countries: Vec<u16>,
    /// Backend-specific filter rules
    pub rules: Vec<WorkerFilterRule>,
}

/// Port range
#[derive(Clone, Debug)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

/// Rate limit configuration for worker
#[derive(Clone, Debug)]
pub struct WorkerRateLimit {
    /// Tokens per second
    pub tokens_per_second: u64,
    /// Bucket size (burst)
    pub bucket_size: u64,
}

/// Filter rule for worker
#[derive(Clone, Debug)]
pub struct WorkerFilterRule {
    /// Rule ID
    pub id: String,
    /// Rule name
    pub name: String,
    /// Priority (lower = higher priority)
    pub priority: u32,
    /// Action (1=allow, 2=drop, 3=rate_limit, 4=challenge, 5=log)
    pub action: i32,
    /// Source IP ranges
    pub source_ips: Vec<String>,
    /// Destination ports
    pub destination_ports: Vec<PortRange>,
    /// Protocols
    pub protocols: Vec<i32>,
    /// Whether rule is enabled
    pub enabled: bool,
}

/// IP blocklist entry for worker
#[derive(Clone, Debug)]
pub struct WorkerBlocklistEntry {
    /// IP address or CIDR
    pub ip: String,
    /// Action (2=drop, 3=rate_limit, 5=log)
    pub action: i32,
    /// Expiration timestamp (0 = never)
    pub expires_at: u64,
}

/// Global settings for workers
#[derive(Clone, Debug, Default)]
pub struct WorkerGlobalSettings {
    /// Default action for unmatched traffic (1=allow, 2=drop)
    pub default_action: i32,
    /// Log sampling rate (1 in N packets)
    pub log_sampling_rate: u32,
    /// Emergency mode threshold (PPS)
    pub emergency_pps_threshold: u64,
}

/// Result of a worker sync operation
#[derive(Clone, Debug)]
pub struct WorkerSyncResult {
    /// Worker name
    pub worker_name: String,
    /// Whether sync was successful
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Time taken for sync
    pub duration_ms: u64,
}

/// Worker manager handles discovery and communication with worker pods
pub struct WorkerManager {
    /// Kubernetes client
    client: Client,
    /// Namespace to watch for worker pods
    worker_namespace: String,
    /// Label selector for worker pods
    worker_selector: String,
    /// gRPC port on worker pods
    worker_grpc_port: u16,
    /// Cache of discovered workers
    workers: Arc<RwLock<HashMap<String, WorkerInfo>>>,
    /// Current configuration version
    config_version: Arc<RwLock<u32>>,
}

impl WorkerManager {
    /// Create a new worker manager
    pub fn new(
        client: Client,
        worker_namespace: String,
        worker_selector: String,
        worker_grpc_port: u16,
    ) -> Self {
        Self {
            client,
            worker_namespace,
            worker_selector,
            worker_grpc_port,
            workers: Arc::new(RwLock::new(HashMap::new())),
            config_version: Arc::new(RwLock::new(0)),
        }
    }

    /// Create with default settings
    pub fn with_defaults(client: Client) -> Self {
        Self::new(
            client,
            "pistonprotection-system".to_string(),
            "app.kubernetes.io/component=worker".to_string(),
            50052,
        )
    }

    /// Discover worker pods
    pub async fn discover_workers(&self) -> Result<Vec<WorkerInfo>> {
        let pods_api: Api<Pod> = Api::namespaced(self.client.clone(), &self.worker_namespace);

        let list_params = ListParams::default().labels(&self.worker_selector);

        let pods = pods_api
            .list(&list_params)
            .await
            .map_err(Error::KubeError)?;

        let mut workers = Vec::new();

        for pod in pods.items {
            let name = pod.name_any();
            let namespace = pod.namespace().unwrap_or_default();

            // Get pod IP
            let ip = pod
                .status
                .as_ref()
                .and_then(|s| s.pod_ip.clone())
                .unwrap_or_default();

            if ip.is_empty() {
                debug!("Skipping worker pod {} - no IP assigned", name);
                continue;
            }

            // Check if pod is ready
            let ready = pod
                .status
                .as_ref()
                .and_then(|s| s.conditions.as_ref())
                .map(|conditions| {
                    conditions
                        .iter()
                        .any(|c| c.type_ == "Ready" && c.status == "True")
                })
                .unwrap_or(false);

            // Get node name
            let node_name = pod.spec.as_ref().and_then(|s| s.node_name.clone());

            // Get labels
            let labels = pod
                .metadata
                .labels
                .clone()
                .unwrap_or_default()
                .into_iter()
                .collect();

            workers.push(WorkerInfo {
                name: name.clone(),
                namespace,
                ip,
                grpc_port: self.worker_grpc_port,
                node_name,
                ready,
                labels,
                last_heartbeat: None,
                config_version: 0,
            });
        }

        // Update cache
        let mut cache = self.workers.write().await;
        cache.clear();
        for worker in &workers {
            cache.insert(worker.name.clone(), worker.clone());
        }

        info!("Discovered {} worker pods", workers.len());

        Ok(workers)
    }

    /// Get cached workers
    pub async fn get_workers(&self) -> Vec<WorkerInfo> {
        let cache = self.workers.read().await;
        cache.values().cloned().collect()
    }

    /// Get ready workers only
    pub async fn get_ready_workers(&self) -> Vec<WorkerInfo> {
        let cache = self.workers.read().await;
        cache.values().filter(|w| w.ready).cloned().collect()
    }

    /// Get worker count
    pub async fn worker_count(&self) -> usize {
        let cache = self.workers.read().await;
        cache.len()
    }

    /// Get ready worker count
    pub async fn ready_worker_count(&self) -> usize {
        let cache = self.workers.read().await;
        cache.values().filter(|w| w.ready).count()
    }

    /// Build filter configuration from CRDs
    pub fn build_filter_config(
        &self,
        ddos_protections: &[DDoSProtection],
        backends: &[Backend],
        filter_rules: &[FilterRule],
        ip_blocklists: &[IPBlocklist],
        config_version: u32,
    ) -> WorkerFilterConfig {
        let mut worker_backends = Vec::new();
        let mut global_rules = Vec::new();
        let mut blocklist_entries = Vec::new();

        // Convert DDoSProtection resources to worker backend configs
        for protection in ddos_protections {
            let namespace = protection
                .metadata
                .namespace
                .as_deref()
                .unwrap_or("default");
            let name = protection.metadata.name.as_deref().unwrap_or("unknown");
            let id = format!("{}/{}", namespace, name);

            for backend_spec in &protection.spec.backends {
                let rate_limit = protection
                    .spec
                    .rate_limit
                    .as_ref()
                    .map(|rl| WorkerRateLimit {
                        tokens_per_second: rl.pps_per_ip as u64,
                        bucket_size: rl.burst as u64,
                    });

                let blocked_countries = protection
                    .spec
                    .geo_filter
                    .as_ref()
                    .filter(|g| g.mode == crate::crd::GeoFilterMode::Deny)
                    .map(|g| {
                        g.countries
                            .iter()
                            .filter_map(|c| country_code_to_id(c))
                            .collect()
                    })
                    .unwrap_or_default();

                // Parse address into IP and port
                let (dest_ip, dest_port) = parse_address(&backend_spec.address);

                worker_backends.push(WorkerBackendConfig {
                    id: format!("{}/{}", id, backend_spec.name),
                    name: backend_spec.name.clone(),
                    protocol: backend_spec.protocol.to_grpc_protocol(),
                    destination_ips: vec![dest_ip],
                    destination_ports: vec![PortRange {
                        start: dest_port,
                        end: dest_port,
                    }],
                    protection_level: protection.spec.protection_level as u32,
                    rate_limit,
                    blocked_countries,
                    rules: Vec::new(), // Will be populated from FilterRules
                });
            }
        }

        // Convert standalone Backend resources
        for backend in backends {
            let namespace = backend.metadata.namespace.as_deref().unwrap_or("default");
            let name = backend.metadata.name.as_deref().unwrap_or("unknown");
            let id = format!("{}/{}", namespace, name);

            let dest_ips: Vec<String> = backend
                .spec
                .endpoints
                .iter()
                .filter(|e| e.enabled)
                .map(|e| e.address.clone())
                .collect();

            let dest_ports: Vec<PortRange> = backend
                .spec
                .endpoints
                .iter()
                .filter(|e| e.enabled)
                .map(|e| PortRange {
                    start: e.port,
                    end: e.port,
                })
                .collect();

            worker_backends.push(WorkerBackendConfig {
                id,
                name: backend.spec.display_name.clone(),
                protocol: backend.spec.protocol.to_grpc_protocol(),
                destination_ips: dest_ips,
                destination_ports: dest_ports,
                protection_level: 3, // Default medium protection
                rate_limit: None,
                blocked_countries: Vec::new(),
                rules: Vec::new(),
            });
        }

        // Convert FilterRules
        for rule in filter_rules {
            if !rule.spec.enabled {
                continue;
            }

            let namespace = rule.metadata.namespace.as_deref().unwrap_or("default");
            let name = rule.metadata.name.as_deref().unwrap_or("unknown");

            let dest_ports: Vec<PortRange> = rule
                .spec
                .config
                .ports
                .iter()
                .map(|p| PortRange {
                    start: p.start,
                    end: p.end,
                })
                .collect();

            let protocols: Vec<i32> = rule
                .spec
                .config
                .protocols
                .iter()
                .map(|p| p.to_grpc_protocol())
                .collect();

            global_rules.push(WorkerFilterRule {
                id: format!("{}/{}", namespace, name),
                name: rule.spec.name.clone(),
                priority: rule.spec.priority as u32,
                action: rule.spec.action.to_grpc_action(),
                source_ips: rule.spec.config.ip_ranges.clone(),
                destination_ports: dest_ports,
                protocols,
                enabled: rule.spec.enabled,
            });
        }

        // Sort rules by priority
        global_rules.sort_by_key(|r| r.priority);

        // Convert IP blocklists
        for blocklist in ip_blocklists {
            if !blocklist.spec.enabled {
                continue;
            }

            for entry in &blocklist.spec.entries {
                // Check if entry is expired
                if let Some(ref expires_at) = entry.expires_at {
                    if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(expires_at) {
                        if chrono::Utc::now() > expiry {
                            continue; // Skip expired entries
                        }
                    }
                }

                let action = entry
                    .action
                    .as_ref()
                    .unwrap_or(&blocklist.spec.action)
                    .to_grpc_action();

                let expires_at = entry
                    .expires_at
                    .as_ref()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.timestamp() as u64)
                    .unwrap_or(0);

                blocklist_entries.push(WorkerBlocklistEntry {
                    ip: entry.ip.clone(),
                    action,
                    expires_at,
                });
            }
        }

        WorkerFilterConfig {
            version: config_version,
            backends: worker_backends,
            global_rules,
            blocklist_entries,
            settings: WorkerGlobalSettings {
                default_action: 1, // Allow by default
                log_sampling_rate: 1000,
                emergency_pps_threshold: 1_000_000,
            },
        }
    }

    /// Push configuration to all ready workers
    pub async fn push_config_to_workers(
        &self,
        config: &WorkerFilterConfig,
    ) -> Vec<WorkerSyncResult> {
        let workers = self.get_ready_workers().await;
        let mut results = Vec::new();

        for worker in workers {
            let start = std::time::Instant::now();
            let result = self.push_config_to_worker(&worker, config).await;
            let duration_ms = start.elapsed().as_millis() as u64;

            let (success, error) = match result {
                Ok(_) => {
                    // Update worker's config version in cache
                    let mut cache = self.workers.write().await;
                    if let Some(w) = cache.get_mut(&worker.name) {
                        w.config_version = config.version;
                        w.last_heartbeat = Some(chrono::Utc::now());
                    }
                    (true, None)
                }
                Err(e) => (false, Some(e.to_string())),
            };

            results.push(WorkerSyncResult {
                worker_name: worker.name.clone(),
                success,
                error,
                duration_ms,
            });
        }

        // Update global config version
        *self.config_version.write().await = config.version;

        results
    }

    /// Push configuration to a single worker
    async fn push_config_to_worker(
        &self,
        worker: &WorkerInfo,
        _config: &WorkerFilterConfig,
    ) -> Result<()> {
        // In production, this would use a real gRPC client
        // For now, we simulate a successful push
        debug!(
            "Pushing config version {} to worker {}",
            _config.version, worker.name
        );

        // Simulate gRPC call
        // let channel = tonic::transport::Channel::from_shared(worker.grpc_endpoint())
        //     .map_err(|e| Error::GrpcConnectionError(e.to_string()))?
        //     .connect()
        //     .await
        //     .map_err(|e| Error::GrpcConnectionError(e.to_string()))?;
        //
        // let mut client = WorkerServiceClient::new(channel);
        // client.apply_config(config.into()).await?;

        Ok(())
    }

    /// Get worker status via heartbeat
    pub async fn get_worker_status(&self, worker: &WorkerInfo) -> Result<WorkerStatus> {
        // In production, this would call the worker's gRPC endpoint
        debug!("Getting status from worker {}", worker.name);

        // Simulated status
        Ok(WorkerStatus {
            cpu_percent: 25.0,
            memory_percent: 40.0,
            packets_per_second: 100_000,
            bytes_per_second: 100_000_000,
            active_connections: 5000,
            xdp_attached: true,
            config_version: worker.config_version,
        })
    }

    /// Block an IP on all workers
    pub async fn block_ip_on_workers(
        &self,
        ip: &str,
        reason: &str,
        duration_seconds: u32,
    ) -> Vec<WorkerSyncResult> {
        let workers = self.get_ready_workers().await;
        let mut results = Vec::new();

        for worker in workers {
            let start = std::time::Instant::now();
            let result = self
                .block_ip_on_worker(&worker, ip, reason, duration_seconds)
                .await;
            let duration_ms = start.elapsed().as_millis() as u64;

            let (success, error) = match result {
                Ok(_) => (true, None),
                Err(e) => (false, Some(e.to_string())),
            };

            results.push(WorkerSyncResult {
                worker_name: worker.name.clone(),
                success,
                error,
                duration_ms,
            });
        }

        results
    }

    /// Block an IP on a single worker
    async fn block_ip_on_worker(
        &self,
        worker: &WorkerInfo,
        ip: &str,
        _reason: &str,
        _duration_seconds: u32,
    ) -> Result<()> {
        debug!("Blocking IP {} on worker {}", ip, worker.name);

        // In production, this would call the worker's gRPC endpoint
        // client.block_ip(BlockIpRequest { ip, reason, duration_seconds }).await?;

        Ok(())
    }

    /// Unblock an IP on all workers
    pub async fn unblock_ip_on_workers(&self, ip: &str) -> Vec<WorkerSyncResult> {
        let workers = self.get_ready_workers().await;
        let mut results = Vec::new();

        for worker in workers {
            let start = std::time::Instant::now();
            let result = self.unblock_ip_on_worker(&worker, ip).await;
            let duration_ms = start.elapsed().as_millis() as u64;

            let (success, error) = match result {
                Ok(_) => (true, None),
                Err(e) => (false, Some(e.to_string())),
            };

            results.push(WorkerSyncResult {
                worker_name: worker.name.clone(),
                success,
                error,
                duration_ms,
            });
        }

        results
    }

    /// Unblock an IP on a single worker
    async fn unblock_ip_on_worker(&self, worker: &WorkerInfo, ip: &str) -> Result<()> {
        debug!("Unblocking IP {} on worker {}", ip, worker.name);

        // In production, this would call the worker's gRPC endpoint
        // client.unblock_ip(UnblockIpRequest { ip }).await?;

        Ok(())
    }

    /// Increment and get next config version
    pub async fn next_config_version(&self) -> u32 {
        let mut version = self.config_version.write().await;
        *version += 1;
        *version
    }

    /// Get current config version
    pub async fn current_config_version(&self) -> u32 {
        *self.config_version.read().await
    }
}

/// Parse an address string into IP and port
fn parse_address(address: &str) -> (String, u16) {
    if let Some((ip, port)) = address.rsplit_once(':') {
        let port = port.parse().unwrap_or(0);
        (ip.to_string(), port)
    } else {
        (address.to_string(), 0)
    }
}

/// Convert ISO 3166-1 alpha-2 country code to numeric ID
/// This is a simplified version - in production, use a proper GeoIP database
fn country_code_to_id(code: &str) -> Option<u16> {
    // Simplified mapping - in production, use a full mapping
    let code = code.to_uppercase();
    match code.as_str() {
        "AF" => Some(4),
        "AL" => Some(8),
        "DZ" => Some(12),
        "AS" => Some(16),
        "AD" => Some(20),
        "AO" => Some(24),
        "AU" => Some(36),
        "AT" => Some(40),
        "BE" => Some(56),
        "BR" => Some(76),
        "CA" => Some(124),
        "CN" => Some(156),
        "DE" => Some(276),
        "FR" => Some(250),
        "GB" => Some(826),
        "IN" => Some(356),
        "JP" => Some(392),
        "KR" => Some(410),
        "NL" => Some(528),
        "RU" => Some(643),
        "US" => Some(840),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_address() {
        let (ip, port) = parse_address("10.0.0.1:8080");
        assert_eq!(ip, "10.0.0.1");
        assert_eq!(port, 8080);

        let (ip, port) = parse_address("10.0.0.1");
        assert_eq!(ip, "10.0.0.1");
        assert_eq!(port, 0);

        let (ip, port) = parse_address("[::1]:8080");
        assert_eq!(ip, "[::1]");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_country_code_to_id() {
        assert_eq!(country_code_to_id("US"), Some(840));
        assert_eq!(country_code_to_id("us"), Some(840));
        assert_eq!(country_code_to_id("CN"), Some(156));
        assert_eq!(country_code_to_id("XX"), None);
    }

    #[test]
    fn test_worker_info_grpc_endpoint() {
        let worker = WorkerInfo {
            name: "worker-1".to_string(),
            namespace: "default".to_string(),
            ip: "10.0.0.1".to_string(),
            grpc_port: 50052,
            node_name: None,
            ready: true,
            labels: HashMap::new(),
            last_heartbeat: None,
            config_version: 0,
        };

        assert_eq!(worker.grpc_endpoint(), "10.0.0.1:50052");
    }

    #[test]
    fn test_worker_global_settings_default() {
        let settings = WorkerGlobalSettings::default();
        assert_eq!(settings.default_action, 0);
        assert_eq!(settings.log_sampling_rate, 0);
        assert_eq!(settings.emergency_pps_threshold, 0);
    }
}
