//! Circuit Breaker Pattern Implementation
//!
//! Implements the circuit breaker pattern for backend health management,
//! preventing cascading failures when backends become unhealthy.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Circuit is closed, requests flow normally
    Closed,
    /// Circuit is open, requests are rejected
    Open,
    /// Circuit is half-open, allowing probe requests
    HalfOpen,
}

impl std::fmt::Display for CircuitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitState::Closed => write!(f, "Closed"),
            CircuitState::Open => write!(f, "Open"),
            CircuitState::HalfOpen => write!(f, "HalfOpen"),
        }
    }
}

/// Configuration for circuit breaker behavior
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures to open the circuit
    pub failure_threshold: u32,
    /// Number of consecutive successes to close the circuit (in half-open state)
    pub success_threshold: u32,
    /// Duration the circuit stays open before transitioning to half-open
    pub open_timeout: Duration,
    /// Duration to track failures within (sliding window)
    pub failure_window: Duration,
    /// Maximum number of requests allowed in half-open state
    pub half_open_max_requests: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 3,
            open_timeout: Duration::from_secs(30),
            failure_window: Duration::from_secs(60),
            half_open_max_requests: 3,
        }
    }
}

/// Internal state tracking for a circuit
#[derive(Debug)]
struct CircuitInternalState {
    state: CircuitState,
    failure_count: u32,
    success_count: u32,
    last_failure_time: Option<Instant>,
    last_state_change: Instant,
    half_open_requests: u32,
    failure_timestamps: Vec<Instant>,
}

impl Default for CircuitInternalState {
    fn default() -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            success_count: 0,
            last_failure_time: None,
            last_state_change: Instant::now(),
            half_open_requests: 0,
            failure_timestamps: Vec::new(),
        }
    }
}

/// Circuit breaker for a single origin/backend
#[derive(Debug)]
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: RwLock<CircuitInternalState>,
    origin_id: String,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with default configuration
    pub fn new(origin_id: String) -> Self {
        Self::with_config(origin_id, CircuitBreakerConfig::default())
    }

    /// Create a new circuit breaker with custom configuration
    pub fn with_config(origin_id: String, config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: RwLock::new(CircuitInternalState::default()),
            origin_id,
        }
    }

    /// Get the current state of the circuit
    pub fn state(&self) -> CircuitState {
        let state = self.state.read();
        self.compute_current_state(&state)
    }

    /// Check if a request is allowed through the circuit
    pub fn allow_request(&self) -> bool {
        let mut state = self.state.write();
        let current_state = self.compute_current_state(&state);

        match current_state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if timeout has elapsed
                if state.last_state_change.elapsed() >= self.config.open_timeout {
                    // Transition to half-open
                    info!(
                        origin_id = %self.origin_id,
                        "Circuit transitioning from Open to HalfOpen"
                    );
                    state.state = CircuitState::HalfOpen;
                    state.half_open_requests = 0;
                    state.success_count = 0;
                    state.last_state_change = Instant::now();
                    true
                } else {
                    debug!(
                        origin_id = %self.origin_id,
                        remaining_secs = (self.config.open_timeout - state.last_state_change.elapsed()).as_secs(),
                        "Circuit is Open, request rejected"
                    );
                    false
                }
            }
            CircuitState::HalfOpen => {
                // Allow limited requests in half-open state
                if state.half_open_requests < self.config.half_open_max_requests {
                    state.half_open_requests += 1;
                    debug!(
                        origin_id = %self.origin_id,
                        request_num = state.half_open_requests,
                        max_requests = self.config.half_open_max_requests,
                        "HalfOpen: allowing probe request"
                    );
                    true
                } else {
                    debug!(
                        origin_id = %self.origin_id,
                        "HalfOpen: max probe requests reached, rejecting"
                    );
                    false
                }
            }
        }
    }

    /// Record a successful request
    pub fn record_success(&self) {
        let mut state = self.state.write();
        let current_state = self.compute_current_state(&state);

        match current_state {
            CircuitState::Closed => {
                // Reset failure tracking on success
                state.failure_count = 0;
                self.prune_old_failures(&mut state);
            }
            CircuitState::HalfOpen => {
                state.success_count += 1;
                debug!(
                    origin_id = %self.origin_id,
                    success_count = state.success_count,
                    threshold = self.config.success_threshold,
                    "HalfOpen: recorded success"
                );

                if state.success_count >= self.config.success_threshold {
                    info!(
                        origin_id = %self.origin_id,
                        "Circuit transitioning from HalfOpen to Closed"
                    );
                    state.state = CircuitState::Closed;
                    state.failure_count = 0;
                    state.success_count = 0;
                    state.failure_timestamps.clear();
                    state.last_state_change = Instant::now();
                }
            }
            CircuitState::Open => {
                // This shouldn't happen normally, but reset just in case
                warn!(
                    origin_id = %self.origin_id,
                    "Received success while circuit is Open"
                );
            }
        }
    }

    /// Record a failed request
    pub fn record_failure(&self) {
        let mut state = self.state.write();
        let current_state = self.compute_current_state(&state);

        // Track failure timestamp
        let now = Instant::now();
        state.failure_timestamps.push(now);
        state.last_failure_time = Some(now);

        // Prune old failures outside the window
        self.prune_old_failures(&mut state);

        match current_state {
            CircuitState::Closed => {
                state.failure_count = state.failure_timestamps.len() as u32;
                debug!(
                    origin_id = %self.origin_id,
                    failure_count = state.failure_count,
                    threshold = self.config.failure_threshold,
                    "Closed: recorded failure"
                );

                if state.failure_count >= self.config.failure_threshold {
                    warn!(
                        origin_id = %self.origin_id,
                        failure_count = state.failure_count,
                        "Circuit transitioning from Closed to Open"
                    );
                    state.state = CircuitState::Open;
                    state.last_state_change = Instant::now();
                }
            }
            CircuitState::HalfOpen => {
                warn!(
                    origin_id = %self.origin_id,
                    "Circuit transitioning from HalfOpen to Open (probe failed)"
                );
                state.state = CircuitState::Open;
                state.success_count = 0;
                state.half_open_requests = 0;
                state.last_state_change = Instant::now();
            }
            CircuitState::Open => {
                // Already open, just update timestamps
                debug!(
                    origin_id = %self.origin_id,
                    "Recorded failure while circuit is Open"
                );
            }
        }
    }

    /// Force the circuit to open state (e.g., from health check failure)
    pub fn force_open(&self) {
        let mut state = self.state.write();
        if state.state != CircuitState::Open {
            warn!(
                origin_id = %self.origin_id,
                previous_state = %state.state,
                "Circuit forced to Open state"
            );
            state.state = CircuitState::Open;
            state.last_state_change = Instant::now();
        }
    }

    /// Force the circuit to closed state (e.g., manual reset)
    pub fn force_close(&self) {
        let mut state = self.state.write();
        if state.state != CircuitState::Closed {
            info!(
                origin_id = %self.origin_id,
                previous_state = %state.state,
                "Circuit forced to Closed state"
            );
            state.state = CircuitState::Closed;
            state.failure_count = 0;
            state.success_count = 0;
            state.failure_timestamps.clear();
            state.last_state_change = Instant::now();
        }
    }

    /// Get statistics about the circuit breaker
    pub fn stats(&self) -> CircuitBreakerStats {
        let state = self.state.read();
        CircuitBreakerStats {
            state: self.compute_current_state(&state),
            failure_count: state.failure_count,
            success_count: state.success_count,
            last_failure_time: state.last_failure_time,
            time_in_current_state: state.last_state_change.elapsed(),
            failures_in_window: state.failure_timestamps.len(),
        }
    }

    /// Compute the actual current state, considering timeouts
    fn compute_current_state(&self, state: &CircuitInternalState) -> CircuitState {
        match state.state {
            CircuitState::Open => {
                if state.last_state_change.elapsed() >= self.config.open_timeout {
                    CircuitState::HalfOpen
                } else {
                    CircuitState::Open
                }
            }
            other => other,
        }
    }

    /// Remove failures outside the sliding window
    fn prune_old_failures(&self, state: &mut CircuitInternalState) {
        let cutoff = Instant::now() - self.config.failure_window;
        state.failure_timestamps.retain(|&ts| ts > cutoff);
    }
}

/// Statistics about a circuit breaker
#[derive(Debug, Clone)]
pub struct CircuitBreakerStats {
    pub state: CircuitState,
    pub failure_count: u32,
    pub success_count: u32,
    pub last_failure_time: Option<Instant>,
    pub time_in_current_state: Duration,
    pub failures_in_window: usize,
}

/// Manager for multiple circuit breakers
#[derive(Debug, Clone)]
pub struct CircuitBreakerManager {
    breakers: Arc<RwLock<HashMap<String, Arc<CircuitBreaker>>>>,
    config: CircuitBreakerConfig,
}

impl CircuitBreakerManager {
    /// Create a new circuit breaker manager
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            breakers: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Get or create a circuit breaker for an origin
    pub fn get_or_create(&self, origin_id: &str) -> Arc<CircuitBreaker> {
        {
            // Try read lock first
            let breakers = self.breakers.read();
            if let Some(breaker) = breakers.get(origin_id) {
                return Arc::clone(breaker);
            }
        }

        // Need to create
        let mut breakers = self.breakers.write();
        // Double-check after acquiring write lock
        if let Some(breaker) = breakers.get(origin_id) {
            return Arc::clone(breaker);
        }

        let breaker = Arc::new(CircuitBreaker::with_config(
            origin_id.to_string(),
            self.config.clone(),
        ));
        breakers.insert(origin_id.to_string(), Arc::clone(&breaker));
        breaker
    }

    /// Get a circuit breaker if it exists
    pub fn get(&self, origin_id: &str) -> Option<Arc<CircuitBreaker>> {
        let breakers = self.breakers.read();
        breakers.get(origin_id).cloned()
    }

    /// Remove a circuit breaker
    pub fn remove(&self, origin_id: &str) -> Option<Arc<CircuitBreaker>> {
        let mut breakers = self.breakers.write();
        breakers.remove(origin_id)
    }

    /// Get all circuit breaker statistics
    pub fn all_stats(&self) -> HashMap<String, CircuitBreakerStats> {
        let breakers = self.breakers.read();
        breakers
            .iter()
            .map(|(id, breaker)| (id.clone(), breaker.stats()))
            .collect()
    }

    /// Get all origins in a specific state
    pub fn origins_in_state(&self, state: CircuitState) -> Vec<String> {
        let breakers = self.breakers.read();
        breakers
            .iter()
            .filter(|(_, breaker)| breaker.state() == state)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Count origins by state
    pub fn count_by_state(&self) -> HashMap<CircuitState, usize> {
        let breakers = self.breakers.read();
        let mut counts = HashMap::new();
        counts.insert(CircuitState::Closed, 0);
        counts.insert(CircuitState::Open, 0);
        counts.insert(CircuitState::HalfOpen, 0);

        for breaker in breakers.values() {
            *counts.entry(breaker.state()).or_insert(0) += 1;
        }

        counts
    }
}

impl Default for CircuitBreakerManager {
    fn default() -> Self {
        Self::new(CircuitBreakerConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_starts_closed() {
        let cb = CircuitBreaker::new("test-origin".to_string());
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());
    }

    #[test]
    fn test_circuit_opens_after_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let cb = CircuitBreaker::with_config("test-origin".to_string(), config);

        // Record failures
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.allow_request());
    }

    #[test]
    fn test_circuit_resets_on_success() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let cb = CircuitBreaker::with_config("test-origin".to_string(), config);

        cb.record_failure();
        cb.record_failure();
        cb.record_success(); // Should reset failure count
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed); // Not open yet
    }

    #[test]
    fn test_half_open_transitions() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 2,
            open_timeout: Duration::from_millis(10),
            half_open_max_requests: 5,
            ..Default::default()
        };
        let cb = CircuitBreaker::with_config("test-origin".to_string(), config);

        // Open the circuit
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(15));

        // Should transition to half-open
        assert!(cb.allow_request());
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Record successes to close
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_half_open_failure_reopens() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            open_timeout: Duration::from_millis(10),
            ..Default::default()
        };
        let cb = CircuitBreaker::with_config("test-origin".to_string(), config);

        // Open the circuit
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(15));

        // Transition to half-open
        cb.allow_request();
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Failure should reopen
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn test_force_open_close() {
        let cb = CircuitBreaker::new("test-origin".to_string());
        assert_eq!(cb.state(), CircuitState::Closed);

        cb.force_open();
        assert_eq!(cb.state(), CircuitState::Open);

        cb.force_close();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_manager_get_or_create() {
        let manager = CircuitBreakerManager::default();

        let cb1 = manager.get_or_create("origin-1");
        let cb2 = manager.get_or_create("origin-1");
        let cb3 = manager.get_or_create("origin-2");

        assert!(Arc::ptr_eq(&cb1, &cb2));
        assert!(!Arc::ptr_eq(&cb1, &cb3));
    }
}
