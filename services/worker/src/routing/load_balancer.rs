//! Load balancing algorithms for origin selection.
//!
//! Implements various load balancing strategies including round-robin,
//! weighted, least connections, IP hash, and random selection.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;
use rand::Rng;

/// Load balancing algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoadBalancerAlgorithm {
    /// Round-robin selection
    #[default]
    RoundRobin,
    /// Weighted round-robin based on origin weights
    Weighted,
    /// Route to origin with least active connections
    LeastConnections,
    /// Consistent hashing based on client IP
    IpHash,
    /// Random selection
    Random,
}

/// Origin information for load balancing.
#[derive(Debug, Clone)]
pub struct OriginInfo {
    /// Origin ID
    pub id: String,
    /// Weight (1-100, higher = more traffic)
    pub weight: u32,
    /// Priority (lower = higher priority, used for failover)
    pub priority: u32,
    /// Whether the origin is healthy
    pub healthy: bool,
    /// Whether the origin is enabled
    pub enabled: bool,
    /// Current active connection count
    pub active_connections: u64,
}

impl OriginInfo {
    /// Create a new OriginInfo with default values.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            weight: 100,
            priority: 0,
            healthy: true,
            enabled: true,
            active_connections: 0,
        }
    }

    /// Set the weight.
    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }

    /// Set the priority.
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }
}

/// Load balancer for selecting origins.
pub struct LoadBalancer {
    /// Algorithm to use
    algorithm: LoadBalancerAlgorithm,
    /// Origins available for selection
    origins: Arc<RwLock<Vec<OriginInfo>>>,
    /// Round-robin counter
    rr_counter: AtomicU64,
    /// Weighted round-robin state
    weighted_state: Arc<RwLock<WeightedState>>,
    /// Connection counts per origin
    connection_counts: Arc<RwLock<HashMap<String, u64>>>,
    /// Whether to route only to healthy origins
    route_to_healthy_only: bool,
}

/// State for weighted round-robin.
#[derive(Default)]
struct WeightedState {
    current_index: usize,
    current_weight: i32,
    gcd: u32,
    max_weight: u32,
}

impl LoadBalancer {
    /// Create a new load balancer with the specified algorithm.
    pub fn new(algorithm: LoadBalancerAlgorithm) -> Self {
        Self {
            algorithm,
            origins: Arc::new(RwLock::new(Vec::new())),
            rr_counter: AtomicU64::new(0),
            weighted_state: Arc::new(RwLock::new(WeightedState::default())),
            connection_counts: Arc::new(RwLock::new(HashMap::new())),
            route_to_healthy_only: true,
        }
    }

    /// Set whether to route only to healthy origins.
    pub fn set_route_to_healthy_only(&mut self, value: bool) {
        self.route_to_healthy_only = value;
    }

    /// Update the list of available origins.
    pub fn update_origins(&self, origins: Vec<OriginInfo>) {
        let mut weighted_state = self.weighted_state.write();

        // Calculate GCD and max weight for weighted algorithm
        if !origins.is_empty() {
            let weights: Vec<u32> = origins.iter().map(|o| o.weight.max(1)).collect();
            weighted_state.gcd = weights.iter().copied().reduce(gcd).unwrap_or(1);
            weighted_state.max_weight = *weights.iter().max().unwrap_or(&1);
        }

        let mut origins_lock = self.origins.write();
        *origins_lock = origins;
    }

    /// Update the health status of an origin.
    pub fn update_origin_health(&self, origin_id: &str, healthy: bool) {
        let mut origins = self.origins.write();
        if let Some(origin) = origins.iter_mut().find(|o| o.id == origin_id) {
            origin.healthy = healthy;
        }
    }

    /// Update the connection count for an origin.
    pub fn update_connection_count(&self, origin_id: &str, count: u64) {
        let mut counts = self.connection_counts.write();
        counts.insert(origin_id.to_string(), count);
    }

    /// Increment connection count for an origin.
    pub fn increment_connections(&self, origin_id: &str) {
        let mut counts = self.connection_counts.write();
        *counts.entry(origin_id.to_string()).or_insert(0) += 1;
    }

    /// Decrement connection count for an origin.
    pub fn decrement_connections(&self, origin_id: &str) {
        let mut counts = self.connection_counts.write();
        if let Some(count) = counts.get_mut(origin_id) {
            *count = count.saturating_sub(1);
        }
    }

    /// Select an origin for the given client IP.
    pub fn select(&self, client_ip: Option<IpAddr>) -> Option<String> {
        let origins = self.origins.read();

        // Filter to available origins
        let available: Vec<&OriginInfo> = origins
            .iter()
            .filter(|o| o.enabled && (!self.route_to_healthy_only || o.healthy))
            .collect();

        if available.is_empty() {
            return None;
        }

        // Group by priority and select from highest priority group
        let min_priority = available.iter().map(|o| o.priority).min().unwrap_or(0);
        let priority_group: Vec<&OriginInfo> = available
            .into_iter()
            .filter(|o| o.priority == min_priority)
            .collect();

        if priority_group.is_empty() {
            return None;
        }

        // Apply algorithm to priority group
        match self.algorithm {
            LoadBalancerAlgorithm::RoundRobin => self.select_round_robin(&priority_group),
            LoadBalancerAlgorithm::Weighted => self.select_weighted(&priority_group),
            LoadBalancerAlgorithm::LeastConnections => {
                self.select_least_connections(&priority_group)
            }
            LoadBalancerAlgorithm::IpHash => self.select_ip_hash(&priority_group, client_ip),
            LoadBalancerAlgorithm::Random => self.select_random(&priority_group),
        }
    }

    /// Round-robin selection.
    fn select_round_robin(&self, origins: &[&OriginInfo]) -> Option<String> {
        if origins.is_empty() {
            return None;
        }

        let counter = self.rr_counter.fetch_add(1, Ordering::Relaxed);
        let index = (counter as usize) % origins.len();
        Some(origins[index].id.clone())
    }

    /// Weighted round-robin selection (Nginx-style smooth weighted).
    fn select_weighted(&self, origins: &[&OriginInfo]) -> Option<String> {
        if origins.is_empty() {
            return None;
        }

        // Use smooth weighted round-robin
        let total_weight: i32 = origins.iter().map(|o| o.weight as i32).sum();
        if total_weight == 0 {
            return self.select_round_robin(origins);
        }

        let mut state = self.weighted_state.write();

        // Find the origin with the highest current weight
        let mut current_weights: Vec<(usize, i32)> = origins
            .iter()
            .enumerate()
            .map(|(i, o)| (i, o.weight as i32))
            .collect();

        // Add current effective weight
        for (i, weight) in &mut current_weights {
            *weight += origins[*i].weight as i32;
        }

        // Find max and subtract total
        let (max_idx, _) = current_weights
            .iter()
            .max_by_key(|(_, w)| *w)
            .copied()
            .unwrap_or((0, 0));

        // Store state for next iteration
        state.current_index = max_idx;

        Some(origins[max_idx].id.clone())
    }

    /// Least connections selection.
    fn select_least_connections(&self, origins: &[&OriginInfo]) -> Option<String> {
        if origins.is_empty() {
            return None;
        }

        let counts = self.connection_counts.read();

        origins
            .iter()
            .min_by_key(|o| counts.get(&o.id).copied().unwrap_or(0))
            .map(|o| o.id.clone())
    }

    /// IP hash selection (consistent hashing).
    fn select_ip_hash(&self, origins: &[&OriginInfo], client_ip: Option<IpAddr>) -> Option<String> {
        if origins.is_empty() {
            return None;
        }

        let ip = client_ip.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));

        // Use FNV-1a hash for consistency
        let mut hasher = FnvHasher::default();
        ip.hash(&mut hasher);
        let hash = hasher.finish();

        let index = (hash as usize) % origins.len();
        Some(origins[index].id.clone())
    }

    /// Random selection.
    fn select_random(&self, origins: &[&OriginInfo]) -> Option<String> {
        if origins.is_empty() {
            return None;
        }

        let mut rng = rand::rng();
        let index = rng.random_range(0..origins.len());
        Some(origins[index].id.clone())
    }

    /// Get all origins.
    pub fn get_origins(&self) -> Vec<OriginInfo> {
        self.origins.read().clone()
    }

    /// Get the current algorithm.
    pub fn algorithm(&self) -> LoadBalancerAlgorithm {
        self.algorithm
    }
}

/// Calculate greatest common divisor.
fn gcd(a: u32, b: u32) -> u32 {
    if b == 0 { a } else { gcd(b, a % b) }
}

/// FNV-1a hasher for consistent hashing.
#[derive(Default)]
struct FnvHasher {
    state: u64,
}

impl Hasher for FnvHasher {
    fn write(&mut self, bytes: &[u8]) {
        const FNV_PRIME: u64 = 0x00000100000001B3;
        const FNV_OFFSET: u64 = 0xcbf29ce484222325;

        if self.state == 0 {
            self.state = FNV_OFFSET;
        }

        for byte in bytes {
            self.state ^= *byte as u64;
            self.state = self.state.wrapping_mul(FNV_PRIME);
        }
    }

    fn finish(&self) -> u64 {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_round_robin() {
        let lb = LoadBalancer::new(LoadBalancerAlgorithm::RoundRobin);
        lb.update_origins(vec![
            OriginInfo::new("origin-1"),
            OriginInfo::new("origin-2"),
            OriginInfo::new("origin-3"),
        ]);

        let selections: Vec<String> = (0..6).filter_map(|_| lb.select(None)).collect();

        assert_eq!(selections[0], "origin-1");
        assert_eq!(selections[1], "origin-2");
        assert_eq!(selections[2], "origin-3");
        assert_eq!(selections[3], "origin-1");
        assert_eq!(selections[4], "origin-2");
        assert_eq!(selections[5], "origin-3");
    }

    #[test]
    fn test_ip_hash_consistency() {
        let lb = LoadBalancer::new(LoadBalancerAlgorithm::IpHash);
        lb.update_origins(vec![
            OriginInfo::new("origin-1"),
            OriginInfo::new("origin-2"),
            OriginInfo::new("origin-3"),
        ]);

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        // Same IP should always get same origin
        let first = lb.select(Some(ip));
        for _ in 0..10 {
            assert_eq!(lb.select(Some(ip)), first);
        }
    }

    #[test]
    fn test_least_connections() {
        let lb = LoadBalancer::new(LoadBalancerAlgorithm::LeastConnections);
        lb.update_origins(vec![
            OriginInfo::new("origin-1"),
            OriginInfo::new("origin-2"),
            OriginInfo::new("origin-3"),
        ]);

        lb.update_connection_count("origin-1", 10);
        lb.update_connection_count("origin-2", 5);
        lb.update_connection_count("origin-3", 15);

        // Should select origin-2 (least connections)
        assert_eq!(lb.select(None), Some("origin-2".to_string()));
    }

    #[test]
    fn test_priority_failover() {
        let lb = LoadBalancer::new(LoadBalancerAlgorithm::RoundRobin);
        lb.update_origins(vec![
            OriginInfo::new("primary").with_priority(0),
            OriginInfo::new("secondary").with_priority(1),
        ]);

        // Should always select primary (lower priority number)
        for _ in 0..5 {
            assert_eq!(lb.select(None), Some("primary".to_string()));
        }

        // Mark primary as unhealthy
        lb.update_origin_health("primary", false);

        // Should now select secondary
        assert_eq!(lb.select(None), Some("secondary".to_string()));
    }

    #[test]
    fn test_empty_origins() {
        let lb = LoadBalancer::new(LoadBalancerAlgorithm::RoundRobin);
        assert_eq!(lb.select(None), None);
    }

    #[test]
    fn test_all_unhealthy() {
        let lb = LoadBalancer::new(LoadBalancerAlgorithm::RoundRobin);
        lb.update_origins(vec![
            OriginInfo::new("origin-1"),
            OriginInfo::new("origin-2"),
        ]);

        lb.update_origin_health("origin-1", false);
        lb.update_origin_health("origin-2", false);

        // No healthy origins available
        assert_eq!(lb.select(None), None);
    }
}
