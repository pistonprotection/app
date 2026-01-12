//! Service layer for the gateway

use deadpool_redis::Pool as RedisPool;
use pistonprotection_common::{config::Config, redis::CacheService};
use sqlx::PgPool;
use std::sync::Arc;

pub mod backend;
pub mod filter;
pub mod metrics;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub db: Option<PgPool>,
    pub cache: Option<CacheService>,
    pub config: Arc<Config>,
}

impl AppState {
    /// Create new application state
    pub fn new(db: Option<PgPool>, redis: Option<RedisPool>, config: Config) -> Self {
        let cache = redis.map(|pool| CacheService::new(pool, "piston"));

        Self {
            db,
            cache,
            config: Arc::new(config),
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
}
