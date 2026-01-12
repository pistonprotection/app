//! Worker service handlers
//!
//! Contains HTTP handlers for health checks, metrics, and status endpoints,
//! as well as the worker state management.

pub mod http;

use crate::config_sync::ConfigSyncManager;
use crate::control_plane::{ConnectionState, ControlPlaneClient};
use crate::ebpf::{interface::NetworkInterface, loader::EbpfLoader};
use deadpool_redis::Pool as RedisPool;
use parking_lot::RwLock;
use pistonprotection_common::{config::Config, error::Result, redis::CacheService};
use std::sync::Arc;

/// Worker state shared across handlers
#[derive(Clone)]
pub struct WorkerState {
    /// eBPF loader for program management
    pub loader: Arc<RwLock<EbpfLoader>>,
    /// Configuration synchronization manager
    pub config_sync: Arc<ConfigSyncManager>,
    /// Control plane client for communication with gateway
    pub control_plane: Arc<ControlPlaneClient>,
    /// Redis cache service (optional)
    pub cache: Option<CacheService>,
    /// Application configuration
    pub config: Arc<Config>,
    /// Network interfaces on this worker
    pub interfaces: Arc<Vec<NetworkInterface>>,
}

impl WorkerState {
    /// Create a new worker state
    pub fn new(
        loader: Arc<RwLock<EbpfLoader>>,
        config_sync: Arc<ConfigSyncManager>,
        control_plane: Arc<ControlPlaneClient>,
        redis: Option<RedisPool>,
        config: Arc<Config>,
        interfaces: Arc<Vec<NetworkInterface>>,
    ) -> Self {
        let cache = redis.map(|pool| CacheService::new(pool, "piston:worker"));

        Self {
            loader,
            config_sync,
            control_plane,
            cache,
            config,
            interfaces,
        }
    }

    /// Get the assigned worker ID from control plane
    pub fn worker_id(&self) -> Option<String> {
        self.control_plane.worker_id()
    }

    /// Check if connected to control plane
    pub fn is_connected(&self) -> bool {
        self.control_plane.is_connected()
    }

    /// Get current connection state
    pub fn connection_state(&self) -> ConnectionState {
        self.control_plane.connection_state()
    }

    /// Get current configuration version
    pub fn config_version(&self) -> u32 {
        self.control_plane.config_version()
    }

    /// Check if the worker is healthy
    pub fn is_healthy(&self) -> bool {
        // In standalone mode, always healthy
        let is_standalone = std::env::var("PISTON_STANDALONE").is_ok();

        if is_standalone {
            return true;
        }

        // Check control plane connection (allow brief disconnections)
        let seconds_since_heartbeat = self.control_plane.seconds_since_last_heartbeat();
        let heartbeat_healthy = seconds_since_heartbeat < 60; // Allow 1 minute without heartbeat

        // Check eBPF loader status (basic check - loader exists and can be accessed)
        let loader_healthy = {
            let _loader = self.loader.read();
            // Basic health check - loader exists and lock can be acquired
            true
        };

        heartbeat_healthy && loader_healthy
    }

    /// Check if the worker is ready to serve traffic
    pub fn is_ready(&self) -> bool {
        let is_standalone = std::env::var("PISTON_STANDALONE").is_ok();

        if is_standalone {
            return true;
        }

        // Must be connected and have configuration
        self.is_connected() && self.config_sync.current_version().is_some()
    }

    /// Get eBPF map statistics
    pub fn map_stats(&self) -> crate::ebpf::maps::MapStats {
        let loader = self.loader.read();
        let maps = loader.maps();
        let map_manager = maps.read();
        map_manager.stats()
    }

    /// Get configuration sync statistics
    pub fn sync_stats(&self) -> crate::config_sync::SyncStats {
        self.config_sync.stats()
    }

    /// Get the list of configured backends
    pub fn configured_backends(&self) -> Vec<String> {
        self.config_sync
            .applied_backends()
            .keys()
            .cloned()
            .collect()
    }

    /// Get XDP-capable interfaces
    pub fn xdp_interfaces(&self) -> Vec<&NetworkInterface> {
        self.interfaces
            .iter()
            .filter(|i| i.supports_xdp())
            .collect()
    }

    /// Get attached XDP programs count
    pub fn attached_programs_count(&self) -> usize {
        let loader = self.loader.read();
        loader.list_attached().len()
    }

    /// Trigger a configuration refresh
    pub fn trigger_config_refresh(&self) {
        self.config_sync.trigger_sync();
    }

    /// Block an IP address locally
    pub fn block_ip(
        &self,
        ip: std::net::IpAddr,
        reason: &str,
        duration_secs: Option<u32>,
    ) -> Result<()> {
        let loader = self.loader.read();
        let maps = loader.maps();
        let mut map_manager = maps.write();
        map_manager.block_ip(ip, reason, duration_secs)
    }

    /// Unblock an IP address locally
    pub fn unblock_ip(&self, ip: &std::net::IpAddr) -> Result<()> {
        let loader = self.loader.read();
        let maps = loader.maps();
        let mut map_manager = maps.write();
        map_manager.unblock_ip(ip)
    }

    /// Check if an IP is blocked
    pub fn is_ip_blocked(&self, ip: &std::net::IpAddr) -> bool {
        let loader = self.loader.read();
        let maps = loader.maps();
        let map_manager = maps.read();
        map_manager.is_blocked(ip)
    }

    /// Get list of blocked IPs
    pub fn list_blocked_ips(&self) -> Vec<crate::ebpf::maps::BlockedIpEntry> {
        let loader = self.loader.read();
        let maps = loader.maps();
        let map_manager = maps.read();
        map_manager
            .list_blocked_ips()
            .into_iter()
            .cloned()
            .collect()
    }
}

/// Extended health check response
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    /// Overall health status
    pub healthy: bool,
    /// Whether worker is ready to serve traffic
    pub ready: bool,
    /// Control plane connection status
    pub control_plane_connected: bool,
    /// Seconds since last successful heartbeat
    pub seconds_since_heartbeat: u64,
    /// Current configuration version
    pub config_version: u32,
    /// Number of configured backends
    pub backends_count: usize,
    /// Number of attached XDP programs
    pub xdp_programs_count: usize,
    /// eBPF map entry counts
    pub map_stats: MapStatsInfo,
}

#[derive(Debug, Clone)]
pub struct MapStatsInfo {
    pub blocked_ips: usize,
    pub rate_limits: usize,
    pub conntrack_entries: usize,
    pub backends: usize,
}

impl WorkerState {
    /// Perform comprehensive health check
    pub fn health_check(&self) -> HealthCheckResult {
        let is_standalone = std::env::var("PISTON_STANDALONE").is_ok();
        let map_stats = self.map_stats();

        let control_plane_connected = if is_standalone {
            true // Treat as connected in standalone mode
        } else {
            self.is_connected()
        };

        let seconds_since_heartbeat = if is_standalone {
            0
        } else {
            self.control_plane.seconds_since_last_heartbeat()
        };

        let healthy = self.is_healthy();
        let ready = self.is_ready();

        HealthCheckResult {
            healthy,
            ready,
            control_plane_connected,
            seconds_since_heartbeat,
            config_version: self.config_version(),
            backends_count: self.configured_backends().len(),
            xdp_programs_count: self.attached_programs_count(),
            map_stats: MapStatsInfo {
                blocked_ips: map_stats.blocked_ips,
                rate_limits: map_stats.rate_limits,
                conntrack_entries: map_stats.conntrack_entries,
                backends: map_stats.backends,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests would go here
}
