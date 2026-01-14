//! Redis connection and caching utilities

use crate::config::RedisConfig;
use crate::error::{Error, Result};
use deadpool_redis::{Config as DeadpoolConfig, Pool, Runtime, redis, redis::AsyncCommands};
use serde::{Serialize, de::DeserializeOwned};
use std::time::Duration;
use tracing::info;

/// Create a Redis connection pool
pub async fn create_pool(config: &RedisConfig) -> Result<Pool> {
    info!("Connecting to Redis with pool size: {}", config.pool_size);

    let cfg = DeadpoolConfig::from_url(&config.url);
    let pool = cfg
        .builder()
        .map_err(|e| Error::Internal(format!("Redis pool builder error: {}", e)))?
        .max_size(config.pool_size)
        .runtime(Runtime::Tokio1)
        .build()
        .map_err(|e| Error::Internal(format!("Redis pool build error: {}", e)))?;

    // Test connection
    let mut conn = pool
        .get()
        .await
        .map_err(|e| Error::Internal(format!("Redis connection error: {}", e)))?;
    let _: String = redis::cmd("PING")
        .query_async(&mut *conn)
        .await
        .map_err(|e| Error::Internal(format!("Redis ping error: {}", e)))?;

    info!("Redis connection established");
    Ok(pool)
}

/// Cache service for Redis operations
#[derive(Clone)]
pub struct CacheService {
    pool: Pool,
    prefix: String,
}

impl CacheService {
    /// Create a new cache service
    pub fn new(pool: Pool, prefix: &str) -> Self {
        Self {
            pool,
            prefix: prefix.to_string(),
        }
    }

    /// Build a cache key with prefix
    fn key(&self, key: &str) -> String {
        format!("{}:{}", self.prefix, key)
    }

    /// Get a value from cache
    pub async fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Internal(format!("Redis connection error: {}", e)))?;

        let value: Option<String> = conn.get(self.key(key)).await?;

        match value {
            Some(v) => {
                let parsed: T = serde_json::from_str(&v)
                    .map_err(|e| Error::Internal(format!("Cache deserialization error: {}", e)))?;
                Ok(Some(parsed))
            }
            None => Ok(None),
        }
    }

    /// Set a value in cache with TTL
    pub async fn set<T: Serialize>(&self, key: &str, value: &T, ttl: Duration) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Internal(format!("Redis connection error: {}", e)))?;

        let json = serde_json::to_string(value)
            .map_err(|e| Error::Internal(format!("Cache serialization error: {}", e)))?;

        let _: () = conn.set_ex(self.key(key), json, ttl.as_secs()).await?;
        Ok(())
    }

    /// Delete a value from cache
    pub async fn delete(&self, key: &str) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Internal(format!("Redis connection error: {}", e)))?;

        let _: () = conn.del(self.key(key)).await?;
        Ok(())
    }

    /// Delete multiple values matching a pattern
    pub async fn delete_pattern(&self, pattern: &str) -> Result<u64> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Internal(format!("Redis connection error: {}", e)))?;

        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(self.key(pattern))
            .query_async(&mut *conn)
            .await?;

        if keys.is_empty() {
            return Ok(0);
        }

        let count: u64 = conn.del(&keys).await?;
        Ok(count)
    }

    /// Increment a counter
    pub async fn incr(&self, key: &str, delta: i64) -> Result<i64> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Internal(format!("Redis connection error: {}", e)))?;

        let value: i64 = conn.incr(self.key(key), delta).await?;
        Ok(value)
    }

    /// Set expiration on a key
    pub async fn expire(&self, key: &str, ttl: Duration) -> Result<bool> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Internal(format!("Redis connection error: {}", e)))?;

        let result: bool = conn.expire(self.key(key), ttl.as_secs() as i64).await?;
        Ok(result)
    }

    /// Check if key exists
    pub async fn exists(&self, key: &str) -> Result<bool> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Internal(format!("Redis connection error: {}", e)))?;

        let exists: bool = conn.exists(self.key(key)).await?;
        Ok(exists)
    }

    /// Add to a set
    pub async fn sadd(&self, key: &str, member: &str) -> Result<bool> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Internal(format!("Redis connection error: {}", e)))?;

        let added: bool = conn.sadd(self.key(key), member).await?;
        Ok(added)
    }

    /// Check if member is in set
    pub async fn sismember(&self, key: &str, member: &str) -> Result<bool> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Internal(format!("Redis connection error: {}", e)))?;

        let is_member: bool = conn.sismember(self.key(key), member).await?;
        Ok(is_member)
    }

    /// Get all members of a set
    pub async fn smembers(&self, key: &str) -> Result<Vec<String>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Internal(format!("Redis connection error: {}", e)))?;

        let members: Vec<String> = conn.smembers(self.key(key)).await?;
        Ok(members)
    }

    /// Publish a message to a channel
    pub async fn publish(&self, channel: &str, message: &str) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Internal(format!("Redis connection error: {}", e)))?;

        let _: () = conn.publish(channel, message).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_cache_key_format() {
        // Test key format: prefix:key
        let prefix = "test";
        let key = "mykey";
        let expected = format!("{}:{}", prefix, key);
        assert_eq!(expected, "test:mykey");
    }
}
