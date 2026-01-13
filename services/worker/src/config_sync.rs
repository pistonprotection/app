//! Configuration Synchronization Module
//!
//! Handles receiving configuration updates from the control plane and
//! applying them to eBPF maps. Manages version tracking and ensures
//! atomic updates where possible.

use crate::ebpf::{
    loader::EbpfLoader,
    maps::{BackendConfig, MapManager},
};
use parking_lot::RwLock;
use pistonprotection_common::error::{Error, Result};
use pistonprotection_proto::worker::{
    BackendFilter, FilterConfig, GlobalFilterSettings, MapOperation, MapUpdate,
};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Notify;
use tracing::{debug, error, info, warn};

/// Configuration version tracking
#[derive(Debug, Clone)]
pub struct ConfigVersion {
    /// Current configuration version
    pub version: u32,
    /// Configuration ID
    pub config_id: String,
    /// Timestamp when applied
    pub applied_at: chrono::DateTime<chrono::Utc>,
    /// Hash of configuration (for integrity)
    pub config_hash: u64,
}

/// Applied backend filter state
#[derive(Debug, Clone)]
pub struct AppliedBackendFilter {
    pub backend_id: String,
    pub protection_level: u8,
    pub enabled: bool,
    pub rule_count: usize,
    pub applied_at: chrono::DateTime<chrono::Utc>,
}

/// Configuration Synchronization Manager
///
/// Responsible for:
/// - Receiving configuration updates from the control plane
/// - Translating protocol messages into eBPF map entries
/// - Applying updates atomically where possible
/// - Tracking configuration versions
/// - Managing rollback on failure
pub struct ConfigSyncManager {
    /// eBPF loader reference
    loader: Arc<RwLock<EbpfLoader>>,
    /// Current configuration version
    current_version: Arc<RwLock<Option<ConfigVersion>>>,
    /// Current filter configuration (cached)
    current_config: Arc<RwLock<Option<FilterConfig>>>,
    /// Applied backend filters
    applied_backends: Arc<RwLock<HashMap<String, AppliedBackendFilter>>>,
    /// Global settings
    global_settings: Arc<RwLock<Option<GlobalFilterSettings>>>,
    /// Sync trigger notification
    sync_notify: Arc<Notify>,
    /// Pending updates queue
    pending_updates: Arc<RwLock<Vec<MapUpdate>>>,
    /// Sync in progress flag
    sync_in_progress: Arc<AtomicBool>,
    /// Statistics
    stats: Arc<RwLock<SyncStats>>,
}

/// Synchronization statistics
#[derive(Debug, Clone, Default)]
pub struct SyncStats {
    /// Total configurations applied
    pub configs_applied: u64,
    /// Total map updates applied
    pub map_updates_applied: u64,
    /// Total backends configured
    pub backends_configured: u64,
    /// Total rules configured
    pub rules_configured: u64,
    /// Failed sync attempts
    pub sync_failures: u64,
    /// Last sync timestamp
    pub last_sync: Option<chrono::DateTime<chrono::Utc>>,
    /// Last error message
    pub last_error: Option<String>,
}

impl ConfigSyncManager {
    /// Create a new configuration sync manager
    pub fn new(loader: Arc<RwLock<EbpfLoader>>) -> Self {
        Self {
            loader,
            current_version: Arc::new(RwLock::new(None)),
            current_config: Arc::new(RwLock::new(None)),
            applied_backends: Arc::new(RwLock::new(HashMap::new())),
            global_settings: Arc::new(RwLock::new(None)),
            sync_notify: Arc::new(Notify::new()),
            pending_updates: Arc::new(RwLock::new(Vec::new())),
            sync_in_progress: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(RwLock::new(SyncStats::default())),
        }
    }

    /// Get the current configuration version
    pub fn current_version(&self) -> Option<ConfigVersion> {
        self.current_version.read().clone()
    }

    /// Get the current filter configuration
    pub fn current_config(&self) -> Option<FilterConfig> {
        self.current_config.read().clone()
    }

    /// Get applied backends
    pub fn applied_backends(&self) -> HashMap<String, AppliedBackendFilter> {
        self.applied_backends.read().clone()
    }

    /// Get global settings
    pub fn global_settings(&self) -> Option<GlobalFilterSettings> {
        *self.global_settings.read()
    }

    /// Get sync statistics
    pub fn stats(&self) -> SyncStats {
        self.stats.read().clone()
    }

    /// Trigger a configuration sync
    pub fn trigger_sync(&self) {
        self.sync_notify.notify_one();
    }

    /// Wait for sync trigger
    pub async fn wait_for_sync_trigger(&self) {
        self.sync_notify.notified().await;
    }

    /// Check if sync is in progress
    pub fn is_syncing(&self) -> bool {
        self.sync_in_progress.load(Ordering::SeqCst)
    }

    /// Apply a complete configuration from the control plane
    pub async fn apply_config(&self, config: &FilterConfig) -> Result<()> {
        // Prevent concurrent syncs
        if self.sync_in_progress.swap(true, Ordering::SeqCst) {
            return Err(Error::Internal("Sync already in progress".to_string()));
        }

        let result = self.apply_config_internal(config).await;

        self.sync_in_progress.store(false, Ordering::SeqCst);

        // Update stats
        let mut stats = self.stats.write();
        stats.last_sync = Some(chrono::Utc::now());

        match &result {
            Ok(_) => {
                stats.configs_applied += 1;
            }
            Err(e) => {
                stats.sync_failures += 1;
                stats.last_error = Some(e.to_string());
            }
        }

        result
    }

    /// Internal configuration application
    async fn apply_config_internal(&self, config: &FilterConfig) -> Result<()> {
        info!(
            "Applying configuration: id={}, version={}",
            config.config_id, config.version
        );

        // Check version
        if let Some(current) = self.current_version.read().as_ref()
            && config.version <= current.version
            && !config.config_id.is_empty()
        {
            debug!(
                "Configuration version {} <= current {}, skipping",
                config.version, current.version
            );
            return Ok(());
        }

        // Get loader and map manager
        let loader = self.loader.write();
        let maps = loader.maps();
        let mut map_manager = maps.write();

        // Track what backends we're updating
        let mut updated_backends = HashSet::new();

        // Apply backend filters
        for backend_filter in &config.backends {
            match self.apply_backend_filter(&mut map_manager, backend_filter) {
                Ok(_) => {
                    updated_backends.insert(backend_filter.backend_id.clone());
                    info!("Applied filter for backend: {}", backend_filter.backend_id);
                }
                Err(e) => {
                    error!(
                        "Failed to apply filter for backend {}: {}",
                        backend_filter.backend_id, e
                    );
                    // Continue with other backends
                }
            }
        }

        // Apply global settings
        if let Some(ref global) = config.global {
            self.apply_global_settings(&mut map_manager, global)?;
            *self.global_settings.write() = Some(*global);
        }

        // Update version tracking
        let config_hash = calculate_config_hash(config);
        *self.current_version.write() = Some(ConfigVersion {
            version: config.version,
            config_id: config.config_id.clone(),
            applied_at: chrono::Utc::now(),
            config_hash,
        });

        // Cache the configuration
        *self.current_config.write() = Some(config.clone());

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.backends_configured = updated_backends.len() as u64;
            stats.rules_configured = config.backends.iter().map(|b| b.rules.len() as u64).sum();
        }

        info!(
            "Configuration applied successfully: {} backends, {} rules",
            updated_backends.len(),
            config.backends.iter().map(|b| b.rules.len()).sum::<usize>()
        );

        Ok(())
    }

    /// Apply a single backend filter
    fn apply_backend_filter(
        &self,
        map_manager: &mut MapManager,
        backend: &BackendFilter,
    ) -> Result<()> {
        // Extract protection config
        let protection = backend.protection.as_ref();

        // Build backend config for eBPF
        let backend_config = BackendConfig {
            id: backend.backend_id.clone(),
            protection_level: protection.map(|p| p.level as u8).unwrap_or(0),
            rate_limit_pps: protection
                .and_then(|p| p.per_ip_rate.as_ref())
                .map(|r| r.tokens_per_second)
                .unwrap_or(10000),
            rate_limit_bps: protection
                .and_then(|p| p.global_rate.as_ref())
                .map(|r| r.tokens_per_second)
                .unwrap_or(0),
            blocked_countries: protection
                .map(|p| p.blocked_country_ids.iter().map(|&id| id as u16).collect())
                .unwrap_or_default(),
        };

        map_manager.update_backend(backend_config);

        // Apply filter rules
        for rule in &backend.rules {
            self.apply_filter_rule(map_manager, &backend.backend_id, rule)?;
        }

        // Track applied backend
        let mut applied = self.applied_backends.write();
        applied.insert(
            backend.backend_id.clone(),
            AppliedBackendFilter {
                backend_id: backend.backend_id.clone(),
                protection_level: protection.map(|p| p.level as u8).unwrap_or(0),
                enabled: protection.map(|p| p.enabled).unwrap_or(false),
                rule_count: backend.rules.len(),
                applied_at: chrono::Utc::now(),
            },
        );

        Ok(())
    }

    /// Apply a single filter rule
    fn apply_filter_rule(
        &self,
        map_manager: &mut MapManager,
        backend_id: &str,
        rule: &pistonprotection_proto::filter::FilterRule,
    ) -> Result<()> {
        debug!(
            "Applying filter rule: {} for backend {}",
            rule.id, backend_id
        );

        // Extract matching criteria
        if let Some(ref filter_match) = rule.r#match {
            // Handle source IP blocking
            for ip_network in &filter_match.source_ip_blacklist {
                if let Some(ref addr) = ip_network.address
                    && let Ok(ip) = std::net::IpAddr::try_from(addr)
                {
                    map_manager.block_ip(
                        ip,
                        &format!("rule:{}", rule.id),
                        None, // Permanent block from rule
                    )?;
                }
            }

            // Handle country-based blocking (would need GeoIP lookup)
            // This is handled at the eBPF level using country IDs
        }

        // Handle rate limiting rules
        // This is configured per-backend via protection config

        Ok(())
    }

    /// Apply global filter settings
    fn apply_global_settings(
        &self,
        _map_manager: &mut MapManager,
        settings: &GlobalFilterSettings,
    ) -> Result<()> {
        info!(
            "Applying global settings: default_action={:?}, emergency_mode={}",
            settings.default_action, settings.emergency_mode
        );

        // Global settings are typically applied to all backends
        // In eBPF, this would be a global configuration map

        if settings.emergency_mode {
            warn!(
                "Emergency mode enabled, PPS threshold: {}",
                settings.emergency_pps_threshold
            );
        }

        Ok(())
    }

    /// Apply incremental map updates
    pub async fn apply_map_updates(&self, updates: &[MapUpdate]) -> Result<()> {
        if updates.is_empty() {
            return Ok(());
        }

        info!("Applying {} map updates", updates.len());

        let loader = self.loader.write();
        let maps = loader.maps();
        let mut map_manager = maps.write();

        let mut success_count = 0;
        let mut error_count = 0;

        for update in updates {
            match self.apply_single_map_update(&mut map_manager, update) {
                Ok(_) => {
                    success_count += 1;
                    debug!("Applied update to map: {}", update.map_name);
                }
                Err(e) => {
                    error_count += 1;
                    error!("Failed to apply update to map {}: {}", update.map_name, e);
                }
            }
        }

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.map_updates_applied += success_count;
        }

        if error_count > 0 {
            warn!(
                "Map updates: {} succeeded, {} failed",
                success_count, error_count
            );
        }

        Ok(())
    }

    /// Apply a single map update
    fn apply_single_map_update(
        &self,
        map_manager: &mut MapManager,
        update: &MapUpdate,
    ) -> Result<()> {
        let operation =
            MapOperation::try_from(update.operation).unwrap_or(MapOperation::Unspecified);

        match update.map_name.as_str() {
            "blocked_ips" | "ip_blocklist" => {
                self.apply_ip_blocklist_update(map_manager, operation, &update.key, &update.value)
            }
            "rate_limits" | "per_ip_rate" => {
                self.apply_rate_limit_update(map_manager, operation, &update.key, &update.value)
            }
            "backends" | "backend_config" => {
                self.apply_backend_config_update(map_manager, operation, &update.key, &update.value)
            }
            _ => {
                debug!("Unknown map type: {}, storing raw update", update.map_name);
                // Store in pending updates for later processing
                self.pending_updates.write().push(update.clone());
                Ok(())
            }
        }
    }

    /// Apply IP blocklist update
    fn apply_ip_blocklist_update(
        &self,
        map_manager: &mut MapManager,
        operation: MapOperation,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        // Parse key as IP address
        let ip = parse_ip_from_bytes(key)?;

        match operation {
            MapOperation::Update => {
                // Value could contain reason and duration
                let (reason, duration) = parse_block_value(value);
                map_manager.block_ip(ip, &reason, duration)?;
            }
            MapOperation::Delete => {
                map_manager.unblock_ip(&ip)?;
            }
            _ => {
                debug!("Unsupported operation {:?} for IP blocklist", operation);
            }
        }

        Ok(())
    }

    /// Apply rate limit update
    fn apply_rate_limit_update(
        &self,
        map_manager: &mut MapManager,
        operation: MapOperation,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        let ip = parse_ip_from_bytes(key)?;

        match operation {
            MapOperation::Update => {
                let (tokens, packets, bytes) = parse_rate_limit_value(value);
                map_manager.update_rate_limit(ip, tokens, packets, bytes);
            }
            MapOperation::Delete => {
                // Remove rate limit (by setting high limit)
                map_manager.update_rate_limit(ip, u64::MAX, 0, 0);
            }
            _ => {
                debug!("Unsupported operation {:?} for rate limits", operation);
            }
        }

        Ok(())
    }

    /// Apply backend configuration update
    fn apply_backend_config_update(
        &self,
        map_manager: &mut MapManager,
        operation: MapOperation,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        let backend_id = String::from_utf8_lossy(key).to_string();

        match operation {
            MapOperation::Update => {
                let config = parse_backend_config_value(&backend_id, value)?;
                map_manager.update_backend(config);
            }
            MapOperation::Delete => {
                // Mark backend as disabled rather than removing
                debug!("Backend {} marked for removal", backend_id);
            }
            _ => {
                debug!("Unsupported operation {:?} for backend config", operation);
            }
        }

        Ok(())
    }

    /// Get pending updates that couldn't be applied
    pub fn pending_updates(&self) -> Vec<MapUpdate> {
        self.pending_updates.read().clone()
    }

    /// Clear pending updates
    pub fn clear_pending_updates(&self) {
        self.pending_updates.write().clear();
    }

    /// Validate a configuration before applying
    pub fn validate_config(&self, config: &FilterConfig) -> Result<Vec<String>> {
        let mut warnings = Vec::new();

        // Check version
        if config.version == 0 {
            warnings.push("Configuration version is 0".to_string());
        }

        // Check backends
        if config.backends.is_empty() {
            warnings.push("No backends defined in configuration".to_string());
        }

        for backend in &config.backends {
            if backend.backend_id.is_empty() {
                warnings.push("Backend with empty ID found".to_string());
            }

            if let Some(ref protection) = backend.protection
                && protection.level > 5
            {
                warnings.push(format!(
                    "Backend {} has protection level > 5",
                    backend.backend_id
                ));
            }
        }

        Ok(warnings)
    }

    /// Export current configuration state
    pub fn export_state(&self) -> ConfigSyncState {
        ConfigSyncState {
            version: self.current_version.read().clone(),
            backends: self.applied_backends.read().clone(),
            global_settings: *self.global_settings.read(),
            stats: self.stats.read().clone(),
            pending_updates_count: self.pending_updates.read().len(),
        }
    }
}

/// Exported configuration state
#[derive(Debug, Clone)]
pub struct ConfigSyncState {
    pub version: Option<ConfigVersion>,
    pub backends: HashMap<String, AppliedBackendFilter>,
    pub global_settings: Option<GlobalFilterSettings>,
    pub stats: SyncStats,
    pub pending_updates_count: usize,
}

/// Calculate a hash of the configuration for integrity checking
fn calculate_config_hash(config: &FilterConfig) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();

    // Hash relevant fields
    config.config_id.hash(&mut hasher);
    config.version.hash(&mut hasher);

    for backend in &config.backends {
        backend.backend_id.hash(&mut hasher);
        if let Some(ref protection) = backend.protection {
            protection.level.hash(&mut hasher);
            protection.enabled.hash(&mut hasher);
        }
        for rule in &backend.rules {
            rule.id.hash(&mut hasher);
            rule.priority.hash(&mut hasher);
        }
    }

    hasher.finish()
}

/// Parse IP address from bytes
fn parse_ip_from_bytes(bytes: &[u8]) -> Result<IpAddr> {
    match bytes.len() {
        4 => {
            let octets: [u8; 4] = bytes
                .try_into()
                .map_err(|_| Error::Internal("Invalid IPv4 bytes".to_string()))?;
            Ok(IpAddr::V4(std::net::Ipv4Addr::from(octets)))
        }
        16 => {
            let octets: [u8; 16] = bytes
                .try_into()
                .map_err(|_| Error::Internal("Invalid IPv6 bytes".to_string()))?;
            Ok(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        _ => Err(Error::Internal(format!(
            "Invalid IP address length: {}",
            bytes.len()
        ))),
    }
}

/// Parse block value (reason and optional duration)
fn parse_block_value(value: &[u8]) -> (String, Option<u32>) {
    if value.is_empty() {
        return ("control_plane".to_string(), None);
    }

    // Simple format: first 4 bytes = duration (0 = permanent), rest = reason
    if value.len() >= 4 {
        let duration_bytes: [u8; 4] = value[..4].try_into().unwrap_or([0; 4]);
        let duration = u32::from_be_bytes(duration_bytes);
        let reason = if value.len() > 4 {
            String::from_utf8_lossy(&value[4..]).to_string()
        } else {
            "control_plane".to_string()
        };

        let duration = if duration == 0 { None } else { Some(duration) };
        (reason, duration)
    } else {
        (String::from_utf8_lossy(value).to_string(), None)
    }
}

/// Parse rate limit value
fn parse_rate_limit_value(value: &[u8]) -> (u64, u64, u64) {
    // Format: 8 bytes tokens, 8 bytes packets, 8 bytes bytes
    if value.len() >= 24 {
        let tokens = u64::from_be_bytes(value[0..8].try_into().unwrap_or([0; 8]));
        let packets = u64::from_be_bytes(value[8..16].try_into().unwrap_or([0; 8]));
        let bytes = u64::from_be_bytes(value[16..24].try_into().unwrap_or([0; 8]));
        (tokens, packets, bytes)
    } else {
        (10000, 0, 0) // Default values
    }
}

/// Parse backend configuration from bytes
fn parse_backend_config_value(backend_id: &str, value: &[u8]) -> Result<BackendConfig> {
    // Simple binary format:
    // 1 byte: protection level
    // 8 bytes: rate_limit_pps
    // 8 bytes: rate_limit_bps
    // rest: blocked country IDs (2 bytes each)

    if value.len() < 17 {
        return Ok(BackendConfig {
            id: backend_id.to_string(),
            protection_level: 0,
            rate_limit_pps: 10000,
            rate_limit_bps: 0,
            blocked_countries: vec![],
        });
    }

    let protection_level = value[0];
    let rate_limit_pps = u64::from_be_bytes(value[1..9].try_into().unwrap_or([0; 8]));
    let rate_limit_bps = u64::from_be_bytes(value[9..17].try_into().unwrap_or([0; 8]));

    let mut blocked_countries = Vec::new();
    let mut offset = 17;
    while offset + 1 < value.len() {
        let country_id = u16::from_be_bytes([value[offset], value[offset + 1]]);
        if country_id > 0 {
            blocked_countries.push(country_id);
        }
        offset += 2;
    }

    Ok(BackendConfig {
        id: backend_id.to_string(),
        protection_level,
        rate_limit_pps,
        rate_limit_bps,
        blocked_countries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_config_hash() {
        let config1 = FilterConfig {
            config_id: "test".to_string(),
            version: 1,
            backends: vec![],
            global: None,
            generated_at: None,
        };

        let config2 = FilterConfig {
            config_id: "test".to_string(),
            version: 1,
            backends: vec![],
            global: None,
            generated_at: None,
        };

        let config3 = FilterConfig {
            config_id: "test".to_string(),
            version: 2,
            backends: vec![],
            global: None,
            generated_at: None,
        };

        assert_eq!(
            calculate_config_hash(&config1),
            calculate_config_hash(&config2)
        );
        assert_ne!(
            calculate_config_hash(&config1),
            calculate_config_hash(&config3)
        );
    }

    #[test]
    fn test_parse_ip_from_bytes() {
        let ipv4_bytes = [192, 168, 1, 1];
        let ip = parse_ip_from_bytes(&ipv4_bytes).unwrap();
        assert_eq!(ip.to_string(), "192.168.1.1");

        let ipv6_bytes = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let ip = parse_ip_from_bytes(&ipv6_bytes).unwrap();
        assert!(ip.is_ipv6());
    }

    #[test]
    fn test_parse_block_value() {
        let value = [0, 0, 0, 60, b't', b'e', b's', b't'];
        let (reason, duration) = parse_block_value(&value);
        assert_eq!(duration, Some(60));
        assert_eq!(reason, "test");

        let empty_value: [u8; 0] = [];
        let (reason, duration) = parse_block_value(&empty_value);
        assert_eq!(reason, "control_plane");
        assert_eq!(duration, None);
    }

    #[test]
    fn test_parse_rate_limit_value() {
        let mut value = Vec::new();
        value.extend_from_slice(&1000u64.to_be_bytes());
        value.extend_from_slice(&500u64.to_be_bytes());
        value.extend_from_slice(&10000u64.to_be_bytes());

        let (tokens, packets, bytes) = parse_rate_limit_value(&value);
        assert_eq!(tokens, 1000);
        assert_eq!(packets, 500);
        assert_eq!(bytes, 10000);
    }

    #[test]
    fn test_parse_backend_config_value() {
        let mut value = Vec::new();
        value.push(3u8); // protection level
        value.extend_from_slice(&5000u64.to_be_bytes()); // pps
        value.extend_from_slice(&0u64.to_be_bytes()); // bps
        value.extend_from_slice(&1u16.to_be_bytes()); // country 1
        value.extend_from_slice(&2u16.to_be_bytes()); // country 2

        let config = parse_backend_config_value("test", &value).unwrap();
        assert_eq!(config.id, "test");
        assert_eq!(config.protection_level, 3);
        assert_eq!(config.rate_limit_pps, 5000);
        assert_eq!(config.blocked_countries, vec![1, 2]);
    }
}
