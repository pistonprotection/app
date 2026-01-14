//! Connection Pool for Backend Origins
//!
//! Provides connection pooling for HTTP and gRPC connections to backend origins,
//! with health checking, connection reuse, and automatic cleanup.

use crate::services::circuit_breaker::{CircuitBreaker, CircuitBreakerManager};
use parking_lot::{Mutex, RwLock};
use pistonprotection_common::error::{Error, Result};
use pistonprotection_proto::backend::Origin;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

/// Configuration for connection pools
#[derive(Debug, Clone)]
pub struct ConnectionPoolConfig {
    /// Maximum connections per origin
    pub max_connections_per_origin: u32,
    /// Minimum connections to keep alive per origin
    pub min_connections_per_origin: u32,
    /// Connection idle timeout before cleanup
    pub idle_timeout: Duration,
    /// Connection lifetime before forced recycling
    pub max_lifetime: Duration,
    /// Timeout for establishing new connections
    pub connect_timeout: Duration,
    /// Timeout for acquiring a connection from pool
    pub acquire_timeout: Duration,
    /// Health check interval
    pub health_check_interval: Duration,
    /// Whether to enable health checks
    pub health_check_enabled: bool,
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_origin: 100,
            min_connections_per_origin: 5,
            idle_timeout: Duration::from_secs(60),
            max_lifetime: Duration::from_secs(3600),
            connect_timeout: Duration::from_secs(10),
            acquire_timeout: Duration::from_secs(5),
            health_check_interval: Duration::from_secs(30),
            health_check_enabled: true,
        }
    }
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connection is available for use
    Available,
    /// Connection is in use
    InUse,
    /// Connection is being health-checked
    HealthCheck,
    /// Connection is marked for removal
    Closing,
}

/// A single pooled connection
#[derive(Debug)]
pub struct PooledConnection {
    id: u64,
    origin_id: String,
    created_at: Instant,
    last_used: RwLock<Instant>,
    state: RwLock<ConnectionState>,
    use_count: AtomicU64,
}

impl PooledConnection {
    fn new(id: u64, origin_id: String) -> Self {
        let now = Instant::now();
        Self {
            id,
            origin_id,
            created_at: now,
            last_used: RwLock::new(now),
            state: RwLock::new(ConnectionState::Available),
            use_count: AtomicU64::new(0),
        }
    }

    fn mark_used(&self) {
        *self.last_used.write() = Instant::now();
        self.use_count.fetch_add(1, Ordering::Relaxed);
        *self.state.write() = ConnectionState::InUse;
    }

    fn release(&self) {
        *self.last_used.write() = Instant::now();
        *self.state.write() = ConnectionState::Available;
    }

    fn is_expired(&self, max_lifetime: Duration, idle_timeout: Duration) -> bool {
        let state = *self.state.read();
        if state == ConnectionState::Closing {
            return true;
        }

        if self.created_at.elapsed() > max_lifetime {
            return true;
        }

        if state == ConnectionState::Available {
            let last_used = *self.last_used.read();
            if last_used.elapsed() > idle_timeout {
                return true;
            }
        }

        false
    }
}

/// Connection pool for a single origin
#[derive(Debug)]
pub struct OriginConnectionPool {
    origin: RwLock<Origin>,
    config: ConnectionPoolConfig,
    connections: RwLock<Vec<Arc<PooledConnection>>>,
    semaphore: Arc<Semaphore>,
    next_conn_id: AtomicU64,
    total_connections_created: AtomicU64,
    total_connections_closed: AtomicU64,
    circuit_breaker: Arc<CircuitBreaker>,
    is_healthy: AtomicBool,
}

impl OriginConnectionPool {
    /// Create a new connection pool for an origin
    pub fn new(
        origin: Origin,
        config: ConnectionPoolConfig,
        circuit_breaker: Arc<CircuitBreaker>,
    ) -> Self {
        let max_conns = config.max_connections_per_origin;
        Self {
            origin: RwLock::new(origin),
            config,
            connections: RwLock::new(Vec::new()),
            semaphore: Arc::new(Semaphore::new(max_conns as usize)),
            next_conn_id: AtomicU64::new(0),
            total_connections_created: AtomicU64::new(0),
            total_connections_closed: AtomicU64::new(0),
            circuit_breaker,
            is_healthy: AtomicBool::new(true),
        }
    }

    /// Acquire a connection from the pool
    pub async fn acquire(&self) -> Result<ConnectionGuard> {
        // Check circuit breaker first
        if !self.circuit_breaker.allow_request() {
            return Err(Error::Internal(format!(
                "Circuit breaker is open for origin {}",
                self.origin.read().id
            )));
        }

        // Try to acquire a permit
        let permit = tokio::time::timeout(
            self.config.acquire_timeout,
            self.semaphore.clone().acquire_owned(),
        )
        .await
        .map_err(|_| Error::Timeout("Connection pool acquire timeout".to_string()))?
        .map_err(|_| Error::Internal("Semaphore closed".to_string()))?;

        // Try to get an existing available connection
        {
            let connections = self.connections.read();
            for conn in connections.iter() {
                let mut state = conn.state.write();
                if *state == ConnectionState::Available {
                    *state = ConnectionState::InUse;
                    drop(state);
                    conn.mark_used();
                    debug!(
                        origin_id = %self.origin.read().id,
                        conn_id = conn.id,
                        "Reused existing connection"
                    );
                    return Ok(ConnectionGuard::new(Arc::clone(conn), permit, self));
                }
            }
        }

        // Create a new connection
        let conn = self.create_connection().await?;
        debug!(
            origin_id = %self.origin.read().id,
            conn_id = conn.id,
            "Created new connection"
        );

        Ok(ConnectionGuard::new(conn, permit, self))
    }

    /// Create a new connection
    async fn create_connection(&self) -> Result<Arc<PooledConnection>> {
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let origin_id = self.origin.read().id.clone();

        // In a real implementation, this would establish an actual connection
        // For now, we create a tracked connection object
        let conn = Arc::new(PooledConnection::new(conn_id, origin_id.clone()));
        conn.mark_used();

        self.total_connections_created
            .fetch_add(1, Ordering::Relaxed);

        {
            let mut connections = self.connections.write();
            connections.push(Arc::clone(&conn));
        }

        Ok(conn)
    }

    /// Release a connection back to the pool
    fn release_connection(&self, conn: &Arc<PooledConnection>, success: bool) {
        if success {
            self.circuit_breaker.record_success();
            conn.release();
        } else {
            self.circuit_breaker.record_failure();
            // Mark connection for removal on failure
            *conn.state.write() = ConnectionState::Closing;
        }
    }

    /// Remove expired connections
    pub fn cleanup_expired(&self) -> usize {
        let mut connections = self.connections.write();
        let before = connections.len();

        connections.retain(|conn| {
            let expired = conn.is_expired(self.config.max_lifetime, self.config.idle_timeout);
            if expired {
                self.total_connections_closed
                    .fetch_add(1, Ordering::Relaxed);
                debug!(
                    origin_id = %self.origin.read().id,
                    conn_id = conn.id,
                    "Connection expired and removed"
                );
            }
            !expired
        });

        before - connections.len()
    }

    /// Ensure minimum connections are maintained
    pub async fn ensure_min_connections(&self) {
        let current_count = self.connections.read().len();
        let min_count = self.config.min_connections_per_origin as usize;

        if current_count < min_count {
            let needed = min_count - current_count;
            for _ in 0..needed {
                if let Ok(conn) = self.create_connection().await {
                    conn.release(); // Mark as available
                }
            }
        }
    }

    /// Perform health check on the origin
    pub async fn health_check(&self) -> bool {
        let origin = self.origin.read().clone();

        // In a real implementation, this would make an actual health check request
        // For now, simulate based on circuit breaker state
        let healthy = self.circuit_breaker.allow_request();

        if healthy != self.is_healthy.load(Ordering::Relaxed) {
            self.is_healthy.store(healthy, Ordering::Relaxed);
            if healthy {
                info!(origin_id = %origin.id, name = %origin.name, "Origin is now healthy");
            } else {
                warn!(origin_id = %origin.id, name = %origin.name, "Origin is now unhealthy");
            }
        }

        healthy
    }

    /// Get pool statistics
    pub fn stats(&self) -> OriginPoolStats {
        let connections = self.connections.read();
        let available = connections
            .iter()
            .filter(|c| *c.state.read() == ConnectionState::Available)
            .count();
        let in_use = connections
            .iter()
            .filter(|c| *c.state.read() == ConnectionState::InUse)
            .count();

        OriginPoolStats {
            origin_id: self.origin.read().id.clone(),
            origin_name: self.origin.read().name.clone(),
            total_connections: connections.len(),
            available_connections: available,
            in_use_connections: in_use,
            total_created: self.total_connections_created.load(Ordering::Relaxed),
            total_closed: self.total_connections_closed.load(Ordering::Relaxed),
            is_healthy: self.is_healthy.load(Ordering::Relaxed),
        }
    }

    /// Update the origin configuration
    pub fn update_origin(&self, origin: Origin) {
        *self.origin.write() = origin;
    }
}

/// Guard that automatically releases connection when dropped
pub struct ConnectionGuard<'a> {
    conn: Arc<PooledConnection>,
    _permit: tokio::sync::OwnedSemaphorePermit,
    pool: &'a OriginConnectionPool,
    success: Mutex<Option<bool>>,
}

impl<'a> ConnectionGuard<'a> {
    fn new(
        conn: Arc<PooledConnection>,
        permit: tokio::sync::OwnedSemaphorePermit,
        pool: &'a OriginConnectionPool,
    ) -> Self {
        Self {
            conn,
            _permit: permit,
            pool,
            success: Mutex::new(None),
        }
    }

    /// Mark the connection as successful
    pub fn mark_success(&self) {
        *self.success.lock() = Some(true);
    }

    /// Mark the connection as failed
    pub fn mark_failure(&self) {
        *self.success.lock() = Some(false);
    }

    /// Get the connection ID
    pub fn id(&self) -> u64 {
        self.conn.id
    }

    /// Get the origin ID
    pub fn origin_id(&self) -> &str {
        &self.conn.origin_id
    }
}

impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        let success = self.success.lock().unwrap_or(true);
        self.pool.release_connection(&self.conn, success);
    }
}

/// Statistics for an origin's connection pool
#[derive(Debug, Clone)]
pub struct OriginPoolStats {
    pub origin_id: String,
    pub origin_name: String,
    pub total_connections: usize,
    pub available_connections: usize,
    pub in_use_connections: usize,
    pub total_created: u64,
    pub total_closed: u64,
    pub is_healthy: bool,
}

/// Manager for all connection pools
#[derive(Debug)]
pub struct ConnectionPoolManager {
    pools: RwLock<HashMap<String, Arc<OriginConnectionPool>>>,
    config: ConnectionPoolConfig,
    circuit_breakers: Arc<CircuitBreakerManager>,
    cleanup_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl ConnectionPoolManager {
    /// Create a new connection pool manager
    pub fn new(
        config: ConnectionPoolConfig,
        circuit_breakers: Arc<CircuitBreakerManager>,
    ) -> Arc<Self> {
        let manager = Arc::new(Self {
            pools: RwLock::new(HashMap::new()),
            config,
            circuit_breakers,
            cleanup_handle: Mutex::new(None),
        });

        // Start background cleanup task
        let manager_clone = Arc::clone(&manager);
        let handle = tokio::spawn(async move {
            manager_clone.run_maintenance().await;
        });
        *manager.cleanup_handle.lock() = Some(handle);

        manager
    }

    /// Get or create a connection pool for an origin
    pub fn get_or_create(&self, origin: &Origin) -> Arc<OriginConnectionPool> {
        {
            let pools = self.pools.read();
            if let Some(pool) = pools.get(&origin.id) {
                return Arc::clone(pool);
            }
        }

        let mut pools = self.pools.write();
        // Double-check after acquiring write lock
        if let Some(pool) = pools.get(&origin.id) {
            return Arc::clone(pool);
        }

        let cb = self.circuit_breakers.get_or_create(&origin.id);
        let pool = Arc::new(OriginConnectionPool::new(
            origin.clone(),
            self.config.clone(),
            cb,
        ));
        pools.insert(origin.id.clone(), Arc::clone(&pool));

        info!(
            origin_id = %origin.id,
            name = %origin.name,
            "Created connection pool"
        );

        pool
    }

    /// Get a connection pool if it exists
    pub fn get(&self, origin_id: &str) -> Option<Arc<OriginConnectionPool>> {
        let pools = self.pools.read();
        pools.get(origin_id).cloned()
    }

    /// Remove a connection pool
    pub fn remove(&self, origin_id: &str) -> Option<Arc<OriginConnectionPool>> {
        let mut pools = self.pools.write();
        let pool = pools.remove(origin_id);
        if pool.is_some() {
            info!(origin_id = %origin_id, "Removed connection pool");
        }
        pool
    }

    /// Update an origin's configuration
    pub fn update_origin(&self, origin: &Origin) {
        if let Some(pool) = self.get(&origin.id) {
            pool.update_origin(origin.clone());
        }
    }

    /// Run periodic maintenance tasks
    async fn run_maintenance(&self) {
        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(30));
        let mut health_check_interval = tokio::time::interval(self.config.health_check_interval);

        loop {
            tokio::select! {
                _ = cleanup_interval.tick() => {
                    self.cleanup_all();
                }
                _ = health_check_interval.tick() => {
                    if self.config.health_check_enabled {
                        self.health_check_all().await;
                    }
                }
            }
        }
    }

    /// Clean up expired connections in all pools
    fn cleanup_all(&self) {
        let pools = self.pools.read();
        let mut total_cleaned = 0;

        for pool in pools.values() {
            total_cleaned += pool.cleanup_expired();
        }

        if total_cleaned > 0 {
            debug!(cleaned = total_cleaned, "Cleaned up expired connections");
        }
    }

    /// Run health checks on all origins
    async fn health_check_all(&self) {
        let pools: Vec<_> = {
            let pools = self.pools.read();
            pools.values().cloned().collect()
        };

        for pool in pools {
            pool.health_check().await;
        }
    }

    /// Get statistics for all pools
    pub fn all_stats(&self) -> Vec<OriginPoolStats> {
        let pools = self.pools.read();
        pools.values().map(|p| p.stats()).collect()
    }

    /// Get aggregated statistics
    pub fn aggregate_stats(&self) -> AggregatePoolStats {
        let stats = self.all_stats();
        AggregatePoolStats {
            total_pools: stats.len(),
            total_connections: stats.iter().map(|s| s.total_connections).sum(),
            available_connections: stats.iter().map(|s| s.available_connections).sum(),
            in_use_connections: stats.iter().map(|s| s.in_use_connections).sum(),
            healthy_origins: stats.iter().filter(|s| s.is_healthy).count(),
            unhealthy_origins: stats.iter().filter(|s| !s.is_healthy).count(),
        }
    }
}

/// Aggregated statistics across all pools
#[derive(Debug, Clone)]
pub struct AggregatePoolStats {
    pub total_pools: usize,
    pub total_connections: usize,
    pub available_connections: usize,
    pub in_use_connections: usize,
    pub healthy_origins: usize,
    pub unhealthy_origins: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_origin(id: &str) -> Origin {
        Origin {
            id: id.to_string(),
            name: format!("Test Origin {}", id),
            enabled: true,
            weight: 1,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_acquire_release() {
        let cb = Arc::new(CircuitBreaker::new("test-origin".to_string()));
        let config = ConnectionPoolConfig {
            max_connections_per_origin: 5,
            min_connections_per_origin: 0,
            ..Default::default()
        };
        let pool = OriginConnectionPool::new(create_test_origin("test-origin"), config, cb);

        // Acquire a connection
        let guard = pool.acquire().await.unwrap();
        let _conn_id = guard.id();
        guard.mark_success();
        drop(guard);

        // Connection should be returned to pool
        let stats = pool.stats();
        assert_eq!(stats.total_connections, 1);
        assert_eq!(stats.available_connections, 1);
    }

    #[tokio::test]
    async fn test_connection_limit() {
        let cb = Arc::new(CircuitBreaker::new("test-origin".to_string()));
        let config = ConnectionPoolConfig {
            max_connections_per_origin: 2,
            min_connections_per_origin: 0,
            acquire_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let pool = OriginConnectionPool::new(create_test_origin("test-origin"), config, cb);

        // Acquire max connections
        let g1 = pool.acquire().await.unwrap();
        let _g2 = pool.acquire().await.unwrap();

        // Third should timeout
        let result = pool.acquire().await;
        assert!(result.is_err());

        // Release one
        drop(g1);

        // Now should succeed
        let _g3 = pool.acquire().await.unwrap();
    }

    #[tokio::test]
    async fn test_circuit_breaker_blocks() {
        let cb = Arc::new(CircuitBreaker::new("test-origin".to_string()));
        cb.force_open();

        let pool = OriginConnectionPool::new(
            create_test_origin("test-origin"),
            ConnectionPoolConfig::default(),
            cb,
        );

        let result = pool.acquire().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connection_reuse() {
        let cb = Arc::new(CircuitBreaker::new("test-origin".to_string()));
        let pool = OriginConnectionPool::new(
            create_test_origin("test-origin"),
            ConnectionPoolConfig::default(),
            cb,
        );

        // First acquire creates new connection
        let g1 = pool.acquire().await.unwrap();
        let first_id = g1.id();
        g1.mark_success();
        drop(g1);

        // Second acquire should reuse
        let g2 = pool.acquire().await.unwrap();
        assert_eq!(g2.id(), first_id);
    }
}
