//! eBPF map management

use pistonprotection_common::error::{Error, Result};
use std::collections::HashMap;
use std::net::IpAddr;
use tracing::{debug, info};

/// eBPF map manager
pub struct MapManager {
    /// Blocked IPs (for IP blocklist map)
    blocked_ips: HashMap<IpAddr, BlockedIpEntry>,
    /// Rate limit entries
    rate_limits: HashMap<IpAddr, RateLimitEntry>,
    /// Connection tracking entries
    conntrack: HashMap<ConnTrackKey, ConnTrackEntry>,
    /// Backend configurations
    backends: HashMap<String, BackendConfig>,
}

/// Blocked IP entry
#[derive(Debug, Clone)]
pub struct BlockedIpEntry {
    pub ip: IpAddr,
    pub reason: String,
    pub blocked_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub packets_blocked: u64,
}

/// Rate limit entry
#[derive(Debug, Clone)]
pub struct RateLimitEntry {
    pub tokens: u64,
    pub last_update: u64, // timestamp in ns
    pub packets: u64,
    pub bytes: u64,
}

/// Connection tracking key
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ConnTrackKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

/// Connection tracking entry
#[derive(Debug, Clone)]
pub struct ConnTrackEntry {
    pub state: ConnTrackState,
    pub packets: u64,
    pub bytes: u64,
    pub created_at: u64,
    pub last_seen: u64,
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnTrackState {
    New,
    Established,
    Related,
    Closing,
    Closed,
}

/// Backend configuration for eBPF
#[derive(Debug, Clone)]
pub struct BackendConfig {
    pub id: String,
    pub protection_level: u8,
    pub rate_limit_pps: u64,
    pub rate_limit_bps: u64,
    pub blocked_countries: Vec<u16>,
}

impl MapManager {
    pub fn new() -> Self {
        Self {
            blocked_ips: HashMap::new(),
            rate_limits: HashMap::new(),
            conntrack: HashMap::new(),
            backends: HashMap::new(),
        }
    }

    /// Block an IP address
    pub fn block_ip(&mut self, ip: IpAddr, reason: &str, duration_secs: Option<u32>) -> Result<()> {
        let now = chrono::Utc::now();
        let expires_at = duration_secs.map(|d| now + chrono::Duration::seconds(d as i64));

        info!(ip = %ip, reason = %reason, "Blocking IP");

        self.blocked_ips.insert(
            ip,
            BlockedIpEntry {
                ip,
                reason: reason.to_string(),
                blocked_at: now,
                expires_at,
                packets_blocked: 0,
            },
        );

        Ok(())
    }

    /// Unblock an IP address
    pub fn unblock_ip(&mut self, ip: &IpAddr) -> Result<()> {
        if self.blocked_ips.remove(ip).is_some() {
            info!(ip = %ip, "Unblocked IP");
            Ok(())
        } else {
            Err(Error::not_found("Blocked IP", ip.to_string()))
        }
    }

    /// Check if an IP is blocked
    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        if let Some(entry) = self.blocked_ips.get(ip) {
            // Check expiration
            if let Some(expires_at) = entry.expires_at {
                if chrono::Utc::now() > expires_at {
                    return false;
                }
            }
            true
        } else {
            false
        }
    }

    /// Get all blocked IPs
    pub fn list_blocked_ips(&self) -> Vec<&BlockedIpEntry> {
        self.blocked_ips.values().collect()
    }

    /// Clean up expired entries
    pub fn cleanup_expired(&mut self) {
        let now = chrono::Utc::now();

        // Clean expired blocked IPs
        self.blocked_ips.retain(|_, entry| {
            if let Some(expires_at) = entry.expires_at {
                now <= expires_at
            } else {
                true
            }
        });

        // Clean old conntrack entries (older than 5 minutes)
        let five_mins_ago = (now - chrono::Duration::minutes(5)).timestamp_nanos_opt().unwrap_or(0) as u64;
        self.conntrack.retain(|_, entry| entry.last_seen > five_mins_ago);
    }

    /// Update rate limit for an IP
    pub fn update_rate_limit(&mut self, ip: IpAddr, tokens: u64, packets: u64, bytes: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        self.rate_limits.insert(
            ip,
            RateLimitEntry {
                tokens,
                last_update: now,
                packets,
                bytes,
            },
        );
    }

    /// Get rate limit entry for an IP
    pub fn get_rate_limit(&self, ip: &IpAddr) -> Option<&RateLimitEntry> {
        self.rate_limits.get(ip)
    }

    /// Update connection tracking entry
    pub fn update_conntrack(&mut self, key: ConnTrackKey, state: ConnTrackState, packets: u64, bytes: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        if let Some(entry) = self.conntrack.get_mut(&key) {
            entry.state = state;
            entry.packets = packets;
            entry.bytes = bytes;
            entry.last_seen = now;
        } else {
            self.conntrack.insert(
                key,
                ConnTrackEntry {
                    state,
                    packets,
                    bytes,
                    created_at: now,
                    last_seen: now,
                },
            );
        }
    }

    /// Get connection tracking entry
    pub fn get_conntrack(&self, key: &ConnTrackKey) -> Option<&ConnTrackEntry> {
        self.conntrack.get(key)
    }

    /// Update backend configuration
    pub fn update_backend(&mut self, config: BackendConfig) {
        debug!(backend_id = %config.id, "Updating backend config");
        self.backends.insert(config.id.clone(), config);
    }

    /// Get backend configuration
    pub fn get_backend(&self, id: &str) -> Option<&BackendConfig> {
        self.backends.get(id)
    }

    /// Get statistics
    pub fn stats(&self) -> MapStats {
        MapStats {
            blocked_ips: self.blocked_ips.len(),
            rate_limits: self.rate_limits.len(),
            conntrack_entries: self.conntrack.len(),
            backends: self.backends.len(),
        }
    }
}

/// Map statistics
#[derive(Debug)]
pub struct MapStats {
    pub blocked_ips: usize,
    pub rate_limits: usize,
    pub conntrack_entries: usize,
    pub backends: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_ip() {
        let mut manager = MapManager::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        manager.block_ip(ip, "Test block", Some(60)).unwrap();
        assert!(manager.is_blocked(&ip));

        manager.unblock_ip(&ip).unwrap();
        assert!(!manager.is_blocked(&ip));
    }

    #[test]
    fn test_conntrack() {
        let mut manager = MapManager::new();
        let key = ConnTrackKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            protocol: 6, // TCP
        };

        manager.update_conntrack(key.clone(), ConnTrackState::New, 1, 64);
        let entry = manager.get_conntrack(&key).unwrap();
        assert_eq!(entry.state, ConnTrackState::New);
        assert_eq!(entry.packets, 1);
    }
}
