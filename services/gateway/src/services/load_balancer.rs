//! Load Balancer Implementation
//!
//! Provides multiple load balancing algorithms for distributing traffic
//! across backend origins:
//! - Round Robin: Simple sequential distribution
//! - Weighted Round Robin: Distribution based on origin weights
//! - Least Connections: Route to origin with fewest active connections
//! - Random: Random origin selection
//! - IP Hash: Consistent hashing based on client IP

use crate::services::circuit_breaker::{CircuitBreakerManager, CircuitState};
use parking_lot::RwLock;
use pistonprotection_common::error::{Error, Result};
use pistonprotection_proto::backend::Origin;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use tracing::{debug, warn};

/// Load balancing algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoadBalancingAlgorithm {
    #[default]
    RoundRobin,
    WeightedRoundRobin,
    LeastConnections,
    Random,
    IpHash,
}

impl std::fmt::Display for LoadBalancingAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadBalancingAlgorithm::RoundRobin => write!(f, "RoundRobin"),
            LoadBalancingAlgorithm::WeightedRoundRobin => write!(f, "WeightedRoundRobin"),
            LoadBalancingAlgorithm::LeastConnections => write!(f, "LeastConnections"),
            LoadBalancingAlgorithm::Random => write!(f, "Random"),
            LoadBalancingAlgorithm::IpHash => write!(f, "IpHash"),
        }
    }
}

impl TryFrom<i32> for LoadBalancingAlgorithm {
    type Error = Error;

    fn try_from(value: i32) -> Result<Self> {
        match value {
            0 => Ok(LoadBalancingAlgorithm::RoundRobin),
            1 => Ok(LoadBalancingAlgorithm::WeightedRoundRobin),
            2 => Ok(LoadBalancingAlgorithm::LeastConnections),
            3 => Ok(LoadBalancingAlgorithm::Random),
            4 => Ok(LoadBalancingAlgorithm::IpHash),
            _ => Err(Error::InvalidInput(format!(
                "Invalid load balancing algorithm: {}",
                value
            ))),
        }
    }
}

/// Tracked origin with connection count and weight
#[derive(Debug)]
struct TrackedOrigin {
    origin: Origin,
    active_connections: AtomicU64,
    current_weight: AtomicU32,
    effective_weight: AtomicU32,
}

impl TrackedOrigin {
    fn new(origin: Origin) -> Self {
        let weight = origin.weight.max(1);
        Self {
            origin,
            active_connections: AtomicU64::new(0),
            current_weight: AtomicU32::new(0),
            effective_weight: AtomicU32::new(weight),
        }
    }

    fn increment_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    fn decrement_connections(&self) {
        // Use saturating subtraction to avoid underflow
        let current = self.active_connections.load(Ordering::Relaxed);
        if current > 0 {
            self.active_connections.fetch_sub(1, Ordering::Relaxed);
        }
    }

    fn get_connections(&self) -> u64 {
        self.active_connections.load(Ordering::Relaxed)
    }
}

/// Load balancer for a single backend
#[derive(Debug)]
pub struct LoadBalancer {
    backend_id: String,
    algorithm: RwLock<LoadBalancingAlgorithm>,
    origins: RwLock<Vec<Arc<TrackedOrigin>>>,
    circuit_breakers: Arc<CircuitBreakerManager>,
    round_robin_index: AtomicU64,
}

impl LoadBalancer {
    /// Create a new load balancer for a backend
    pub fn new(
        backend_id: String,
        algorithm: LoadBalancingAlgorithm,
        circuit_breakers: Arc<CircuitBreakerManager>,
    ) -> Self {
        Self {
            backend_id,
            algorithm: RwLock::new(algorithm),
            origins: RwLock::new(Vec::new()),
            circuit_breakers,
            round_robin_index: AtomicU64::new(0),
        }
    }

    /// Set the load balancing algorithm
    pub fn set_algorithm(&self, algorithm: LoadBalancingAlgorithm) {
        *self.algorithm.write() = algorithm;
        debug!(
            backend_id = %self.backend_id,
            algorithm = %algorithm,
            "Updated load balancing algorithm"
        );
    }

    /// Get the current algorithm
    pub fn algorithm(&self) -> LoadBalancingAlgorithm {
        *self.algorithm.read()
    }

    /// Update the list of origins
    pub fn update_origins(&self, origins: Vec<Origin>) {
        let tracked: Vec<_> = origins
            .into_iter()
            .filter(|o| o.enabled)
            .map(|o| Arc::new(TrackedOrigin::new(o)))
            .collect();

        debug!(
            backend_id = %self.backend_id,
            origin_count = tracked.len(),
            "Updated origin list"
        );

        *self.origins.write() = tracked;
    }

    /// Add an origin
    pub fn add_origin(&self, origin: Origin) {
        if origin.enabled {
            let mut origins = self.origins.write();
            origins.push(Arc::new(TrackedOrigin::new(origin)));
        }
    }

    /// Remove an origin by ID
    pub fn remove_origin(&self, origin_id: &str) {
        let mut origins = self.origins.write();
        origins.retain(|o| o.origin.id != origin_id);
    }

    /// Select an origin for a request
    pub fn select(&self, client_ip: Option<&str>) -> Result<SelectedOrigin> {
        let algorithm = *self.algorithm.read();
        let origins = self.origins.read();

        // Filter to healthy origins (circuit breaker is closed or half-open)
        let healthy_origins: Vec<_> = origins
            .iter()
            .filter(|o| {
                let cb = self.circuit_breakers.get_or_create(&o.origin.id);
                let state = cb.state();
                matches!(state, CircuitState::Closed | CircuitState::HalfOpen)
            })
            .collect();

        if healthy_origins.is_empty() {
            warn!(
                backend_id = %self.backend_id,
                total_origins = origins.len(),
                "No healthy origins available"
            );
            return Err(Error::Internal("No healthy origins available".to_string()));
        }

        let selected = match algorithm {
            LoadBalancingAlgorithm::RoundRobin => self.select_round_robin(&healthy_origins),
            LoadBalancingAlgorithm::WeightedRoundRobin => {
                self.select_weighted_round_robin(&healthy_origins)
            }
            LoadBalancingAlgorithm::LeastConnections => {
                self.select_least_connections(&healthy_origins)
            }
            LoadBalancingAlgorithm::Random => self.select_random(&healthy_origins),
            LoadBalancingAlgorithm::IpHash => self.select_ip_hash(&healthy_origins, client_ip),
        };

        let tracked = Arc::clone(selected);
        tracked.increment_connections();

        let origin_id = tracked.origin.id.clone();
        Ok(SelectedOrigin {
            origin: tracked.origin.clone(),
            tracker: tracked,
            circuit_breaker: self.circuit_breakers.get_or_create(&origin_id),
        })
    }

    /// Simple round-robin selection
    fn select_round_robin<'a>(&self, origins: &[&'a Arc<TrackedOrigin>]) -> &'a Arc<TrackedOrigin> {
        let index = self.round_robin_index.fetch_add(1, Ordering::Relaxed);
        let idx = (index as usize) % origins.len();
        origins[idx]
    }

    /// Weighted round-robin selection (smooth weighted round-robin)
    fn select_weighted_round_robin<'a>(
        &self,
        origins: &[&'a Arc<TrackedOrigin>],
    ) -> &'a Arc<TrackedOrigin> {
        // Smooth weighted round-robin algorithm
        // Each origin has:
        // - effective_weight: the configured weight (may be reduced on failures)
        // - current_weight: the running weight for selection

        let total_weight: u32 = origins
            .iter()
            .map(|o| o.effective_weight.load(Ordering::Relaxed))
            .sum();

        if total_weight == 0 {
            // Fall back to simple round-robin if all weights are 0
            return self.select_round_robin(origins);
        }

        // Find the origin with the highest current_weight
        let mut best_idx = 0;
        let mut best_weight = 0i64;

        for (idx, origin) in origins.iter().enumerate() {
            let ew = origin.effective_weight.load(Ordering::Relaxed) as i64;
            let cw = origin
                .current_weight
                .fetch_add(ew as u32, Ordering::Relaxed) as i64;
            let new_cw = cw + ew;

            if new_cw > best_weight {
                best_weight = new_cw;
                best_idx = idx;
            }
        }

        // Reduce the selected origin's current_weight by total_weight
        origins[best_idx]
            .current_weight
            .fetch_sub(total_weight, Ordering::Relaxed);

        origins[best_idx]
    }

    /// Least connections selection
    fn select_least_connections<'a>(
        &self,
        origins: &[&'a Arc<TrackedOrigin>],
    ) -> &'a Arc<TrackedOrigin> {
        origins
            .iter()
            .min_by_key(|o| {
                // Consider weight in least connections
                // Lower connections per weight = better
                let conns = o.get_connections();
                let weight = o.origin.weight.max(1) as u64;
                conns * 1000 / weight // Scale up to avoid integer division issues
            })
            .copied()
            .unwrap_or(origins[0])
    }

    /// Random selection
    fn select_random<'a>(&self, origins: &[&'a Arc<TrackedOrigin>]) -> &'a Arc<TrackedOrigin> {
        use std::time::{SystemTime, UNIX_EPOCH};

        // Simple pseudo-random using time
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);

        let idx = (nanos as usize) % origins.len();
        origins[idx]
    }

    /// IP hash selection (consistent hashing)
    fn select_ip_hash<'a>(
        &self,
        origins: &[&'a Arc<TrackedOrigin>],
        client_ip: Option<&str>,
    ) -> &'a Arc<TrackedOrigin> {
        let hash = match client_ip {
            Some(ip) => {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                ip.hash(&mut hasher);
                hasher.finish()
            }
            None => {
                // No IP provided, fall back to round-robin
                return self.select_round_robin(origins);
            }
        };

        let idx = (hash as usize) % origins.len();
        origins[idx]
    }

    /// Get statistics about the load balancer
    pub fn stats(&self) -> LoadBalancerStats {
        let origins = self.origins.read();
        let origin_stats: Vec<_> = origins
            .iter()
            .map(|o| {
                let cb = self.circuit_breakers.get_or_create(&o.origin.id);
                OriginStats {
                    origin_id: o.origin.id.clone(),
                    name: o.origin.name.clone(),
                    active_connections: o.get_connections(),
                    weight: o.origin.weight,
                    circuit_state: cb.state(),
                }
            })
            .collect();

        LoadBalancerStats {
            backend_id: self.backend_id.clone(),
            algorithm: *self.algorithm.read(),
            total_origins: origins.len(),
            healthy_origins: origin_stats
                .iter()
                .filter(|s| {
                    matches!(
                        s.circuit_state,
                        CircuitState::Closed | CircuitState::HalfOpen
                    )
                })
                .count(),
            origin_stats,
        }
    }
}

/// Selected origin with connection tracking
pub struct SelectedOrigin {
    pub origin: Origin,
    tracker: Arc<TrackedOrigin>,
    pub circuit_breaker: Arc<crate::services::circuit_breaker::CircuitBreaker>,
}

impl SelectedOrigin {
    /// Mark the request as complete (decrement connection count)
    pub fn complete(&self, success: bool) {
        self.tracker.decrement_connections();
        if success {
            self.circuit_breaker.record_success();
        } else {
            self.circuit_breaker.record_failure();
        }
    }
}

impl Drop for SelectedOrigin {
    fn drop(&mut self) {
        // Note: This doesn't decrement connections automatically
        // because we need to know if the request succeeded or failed.
        // The caller must call complete() explicitly.
    }
}

/// Statistics for a single origin
#[derive(Debug, Clone)]
pub struct OriginStats {
    pub origin_id: String,
    pub name: String,
    pub active_connections: u64,
    pub weight: u32,
    pub circuit_state: CircuitState,
}

/// Statistics for the load balancer
#[derive(Debug, Clone)]
pub struct LoadBalancerStats {
    pub backend_id: String,
    pub algorithm: LoadBalancingAlgorithm,
    pub total_origins: usize,
    pub healthy_origins: usize,
    pub origin_stats: Vec<OriginStats>,
}

/// Manager for multiple load balancers
#[derive(Debug, Clone)]
pub struct LoadBalancerManager {
    balancers: Arc<RwLock<HashMap<String, Arc<LoadBalancer>>>>,
    circuit_breakers: Arc<CircuitBreakerManager>,
    default_algorithm: LoadBalancingAlgorithm,
}

impl LoadBalancerManager {
    /// Create a new load balancer manager
    pub fn new(
        circuit_breakers: Arc<CircuitBreakerManager>,
        default_algorithm: LoadBalancingAlgorithm,
    ) -> Self {
        Self {
            balancers: Arc::new(RwLock::new(HashMap::new())),
            circuit_breakers,
            default_algorithm,
        }
    }

    /// Get or create a load balancer for a backend
    pub fn get_or_create(&self, backend_id: &str) -> Arc<LoadBalancer> {
        {
            let balancers = self.balancers.read();
            if let Some(balancer) = balancers.get(backend_id) {
                return Arc::clone(balancer);
            }
        }

        let mut balancers = self.balancers.write();
        // Double-check after acquiring write lock
        if let Some(balancer) = balancers.get(backend_id) {
            return Arc::clone(balancer);
        }

        let balancer = Arc::new(LoadBalancer::new(
            backend_id.to_string(),
            self.default_algorithm,
            Arc::clone(&self.circuit_breakers),
        ));
        balancers.insert(backend_id.to_string(), Arc::clone(&balancer));
        balancer
    }

    /// Get a load balancer if it exists
    pub fn get(&self, backend_id: &str) -> Option<Arc<LoadBalancer>> {
        let balancers = self.balancers.read();
        balancers.get(backend_id).cloned()
    }

    /// Remove a load balancer
    pub fn remove(&self, backend_id: &str) -> Option<Arc<LoadBalancer>> {
        let mut balancers = self.balancers.write();
        balancers.remove(backend_id)
    }

    /// Get statistics for all load balancers
    pub fn all_stats(&self) -> Vec<LoadBalancerStats> {
        let balancers = self.balancers.read();
        balancers.values().map(|lb| lb.stats()).collect()
    }
}

impl Default for LoadBalancerManager {
    fn default() -> Self {
        Self::new(
            Arc::new(CircuitBreakerManager::default()),
            LoadBalancingAlgorithm::default(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_origin(id: &str, weight: u32, enabled: bool) -> Origin {
        Origin {
            id: id.to_string(),
            name: format!("Origin {}", id),
            weight,
            enabled,
            ..Default::default()
        }
    }

    #[test]
    fn test_round_robin() {
        let cb_manager = Arc::new(CircuitBreakerManager::default());
        let lb = LoadBalancer::new(
            "test-backend".to_string(),
            LoadBalancingAlgorithm::RoundRobin,
            cb_manager,
        );

        lb.update_origins(vec![
            create_origin("origin-1", 1, true),
            create_origin("origin-2", 1, true),
            create_origin("origin-3", 1, true),
        ]);

        // Round robin should cycle through origins
        let mut ids = Vec::new();
        for _ in 0..6 {
            let selected = lb.select(None).unwrap();
            ids.push(selected.origin.id.clone());
            selected.complete(true);
        }

        // Should see each origin twice
        assert_eq!(ids.iter().filter(|id| *id == "origin-1").count(), 2);
        assert_eq!(ids.iter().filter(|id| *id == "origin-2").count(), 2);
        assert_eq!(ids.iter().filter(|id| *id == "origin-3").count(), 2);
    }

    #[test]
    fn test_least_connections() {
        let cb_manager = Arc::new(CircuitBreakerManager::default());
        let lb = LoadBalancer::new(
            "test-backend".to_string(),
            LoadBalancingAlgorithm::LeastConnections,
            cb_manager,
        );

        lb.update_origins(vec![
            create_origin("origin-1", 1, true),
            create_origin("origin-2", 1, true),
        ]);

        // First two requests should go to different origins
        let s1 = lb.select(None).unwrap();
        let s2 = lb.select(None).unwrap();

        // With same weight, should distribute evenly initially
        // After that, should prefer origin with fewer connections
        s1.complete(true);

        // Now origin-1 has 0 connections, origin-2 has 1
        let s3 = lb.select(None).unwrap();
        // Should prefer the one with fewer connections
        s3.complete(true);
        s2.complete(true);
    }

    #[test]
    fn test_ip_hash_consistency() {
        let cb_manager = Arc::new(CircuitBreakerManager::default());
        let lb = LoadBalancer::new(
            "test-backend".to_string(),
            LoadBalancingAlgorithm::IpHash,
            cb_manager,
        );

        lb.update_origins(vec![
            create_origin("origin-1", 1, true),
            create_origin("origin-2", 1, true),
            create_origin("origin-3", 1, true),
        ]);

        // Same IP should always go to same origin
        let ip = "192.168.1.100";
        let s1 = lb.select(Some(ip)).unwrap();
        let first_id = s1.origin.id.clone();
        s1.complete(true);

        for _ in 0..10 {
            let selected = lb.select(Some(ip)).unwrap();
            assert_eq!(selected.origin.id, first_id);
            selected.complete(true);
        }
    }

    #[test]
    fn test_disabled_origin_excluded() {
        let cb_manager = Arc::new(CircuitBreakerManager::default());
        let lb = LoadBalancer::new(
            "test-backend".to_string(),
            LoadBalancingAlgorithm::RoundRobin,
            cb_manager,
        );

        lb.update_origins(vec![
            create_origin("origin-1", 1, true),
            create_origin("origin-2", 1, false), // Disabled
            create_origin("origin-3", 1, true),
        ]);

        // Disabled origin should never be selected
        for _ in 0..10 {
            let selected = lb.select(None).unwrap();
            assert_ne!(selected.origin.id, "origin-2");
            selected.complete(true);
        }
    }

    #[test]
    fn test_no_healthy_origins_error() {
        let cb_manager = Arc::new(CircuitBreakerManager::default());
        let lb = LoadBalancer::new(
            "test-backend".to_string(),
            LoadBalancingAlgorithm::RoundRobin,
            Arc::clone(&cb_manager),
        );

        lb.update_origins(vec![create_origin("origin-1", 1, true)]);

        // Force circuit breaker open
        let cb = cb_manager.get_or_create("origin-1");
        cb.force_open();

        // Should fail with no healthy origins
        let result = lb.select(None);
        assert!(result.is_err());
    }
}
