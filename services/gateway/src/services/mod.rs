//! Service layer for the gateway

use deadpool_redis::Pool as RedisPool;
use pistonprotection_common::{config::Config, redis::CacheService};
use sqlx::PgPool;
use std::sync::Arc;

pub mod backend;
pub mod circuit_breaker;
pub mod connection_pool;
pub mod filter;
pub mod load_balancer;
pub mod metrics;

use circuit_breaker::{CircuitBreakerConfig, CircuitBreakerManager};
use connection_pool::{ConnectionPoolConfig, ConnectionPoolManager};
use load_balancer::{LoadBalancerManager, LoadBalancingAlgorithm};

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub db: Option<PgPool>,
    pub cache: Option<CacheService>,
    pub config: Arc<Config>,
    pub circuit_breakers: Arc<CircuitBreakerManager>,
    pub load_balancers: Arc<LoadBalancerManager>,
    pub connection_pools: Arc<ConnectionPoolManager>,
}

impl AppState {
    /// Create new application state
    pub fn new(db: Option<PgPool>, redis: Option<RedisPool>, config: Config) -> Self {
        let cache = redis.map(|pool| CacheService::new(pool, "piston"));

        // Initialize circuit breaker manager with default config
        let circuit_breaker_config = CircuitBreakerConfig::default();
        let circuit_breakers = Arc::new(CircuitBreakerManager::new(circuit_breaker_config));

        // Initialize load balancer manager
        let load_balancers = Arc::new(LoadBalancerManager::new(
            Arc::clone(&circuit_breakers),
            LoadBalancingAlgorithm::RoundRobin,
        ));

        // Initialize connection pool manager
        let connection_pool_config = ConnectionPoolConfig::default();
        let connection_pools = ConnectionPoolManager::new(
            connection_pool_config,
            Arc::clone(&circuit_breakers),
        );

        Self {
            db,
            cache,
            config: Arc::new(config),
            circuit_breakers,
            load_balancers,
            connection_pools,
        }
    }

    /// Create application state with custom configuration
    pub fn with_config(
        db: Option<PgPool>,
        redis: Option<RedisPool>,
        config: Config,
        circuit_breaker_config: CircuitBreakerConfig,
        connection_pool_config: ConnectionPoolConfig,
        load_balancing_algorithm: LoadBalancingAlgorithm,
    ) -> Self {
        let cache = redis.map(|pool| CacheService::new(pool, "piston"));

        let circuit_breakers = Arc::new(CircuitBreakerManager::new(circuit_breaker_config));

        let load_balancers = Arc::new(LoadBalancerManager::new(
            Arc::clone(&circuit_breakers),
            load_balancing_algorithm,
        ));

        let connection_pools = ConnectionPoolManager::new(
            connection_pool_config,
            Arc::clone(&circuit_breakers),
        );

        Self {
            db,
            cache,
            config: Arc::new(config),
            circuit_breakers,
            load_balancers,
            connection_pools,
        }
    }

    /// Check if database is available
    pub fn has_db(&self) -> bool {
        self.db.is_some()
    }

    /// Check if cache is available
    pub fn has_cache(&self) -> bool {
        self.cache.is_some()
    }

    /// Get database pool or error
    pub fn db(&self) -> Result<&PgPool, tonic::Status> {
        self.db
            .as_ref()
            .ok_or_else(|| tonic::Status::unavailable("Database not configured"))
    }

    /// Get cache service or error
    pub fn cache(&self) -> Result<&CacheService, tonic::Status> {
        self.cache
            .as_ref()
            .ok_or_else(|| tonic::Status::unavailable("Cache not configured"))
    }

    /// Get circuit breaker manager
    pub fn circuit_breakers(&self) -> &CircuitBreakerManager {
        &self.circuit_breakers
    }

    /// Get load balancer manager
    pub fn load_balancers(&self) -> &LoadBalancerManager {
        &self.load_balancers
    }

    /// Get connection pool manager
    pub fn connection_pools(&self) -> &ConnectionPoolManager {
        &self.connection_pools
    }
}
