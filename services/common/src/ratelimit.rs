//! Rate limiting utilities

use crate::error::{Error, Result};
use dashmap::DashMap;
use governor::{
    Quota, RateLimiter,
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

/// Rate limit configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per second
    pub requests_per_second: u32,
    /// Burst size (token bucket capacity)
    pub burst_size: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 100,
            burst_size: 200,
        }
    }
}

/// Global rate limiter (not keyed by IP)
pub struct GlobalRateLimiter {
    limiter: RateLimiter<NotKeyed, InMemoryState, DefaultClock>,
}

impl GlobalRateLimiter {
    /// Create a new global rate limiter
    pub fn new(config: &RateLimitConfig) -> Result<Self> {
        let quota =
            Quota::per_second(NonZeroU32::new(config.requests_per_second).ok_or_else(|| {
                Error::validation("Invalid rate limit: requests_per_second must be > 0")
            })?)
            .allow_burst(
                NonZeroU32::new(config.burst_size).ok_or_else(|| {
                    Error::validation("Invalid rate limit: burst_size must be > 0")
                })?,
            );

        Ok(Self {
            limiter: RateLimiter::direct(quota),
        })
    }

    /// Check if a request is allowed
    pub fn check(&self) -> bool {
        self.limiter.check().is_ok()
    }

    /// Wait until a request is allowed
    pub async fn wait(&self) {
        self.limiter.until_ready().await;
    }
}

/// Per-IP rate limiter
pub struct IpRateLimiter {
    limiters: DashMap<IpAddr, Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>>,
    config: RateLimitConfig,
    #[allow(dead_code)]
    cleanup_interval: Duration,
}

impl IpRateLimiter {
    /// Create a new per-IP rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            limiters: DashMap::new(),
            config,
            cleanup_interval: Duration::from_secs(60),
        }
    }

    /// Check if a request from the given IP is allowed
    pub fn check(&self, ip: IpAddr) -> bool {
        let limiter = self.get_or_create(ip);
        limiter.check().is_ok()
    }

    /// Wait until a request from the given IP is allowed
    pub async fn wait(&self, ip: IpAddr) {
        let limiter = self.get_or_create(ip);
        limiter.until_ready().await;
    }

    /// Get or create a rate limiter for an IP
    fn get_or_create(&self, ip: IpAddr) -> Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>> {
        if let Some(limiter) = self.limiters.get(&ip) {
            return Arc::clone(&*limiter);
        }

        let quota = Quota::per_second(
            NonZeroU32::new(self.config.requests_per_second)
                .unwrap_or(NonZeroU32::new(100).unwrap()),
        )
        .allow_burst(
            NonZeroU32::new(self.config.burst_size).unwrap_or(NonZeroU32::new(200).unwrap()),
        );

        let limiter = Arc::new(RateLimiter::direct(quota));
        self.limiters.insert(ip, Arc::clone(&limiter));
        limiter
    }

    /// Remove rate limiters for inactive IPs
    pub fn cleanup(&self) {
        // In a production system, we'd track last access time and remove old entries
        // For now, just limit the map size
        if self.limiters.len() > 100_000 {
            // Remove random entries to prevent unbounded growth
            let mut to_remove = Vec::new();
            for entry in self.limiters.iter().take(10_000) {
                to_remove.push(*entry.key());
            }
            for ip in to_remove {
                self.limiters.remove(&ip);
            }
        }
    }

    /// Get the number of tracked IPs
    pub fn len(&self) -> usize {
        self.limiters.len()
    }

    /// Check if the limiter is empty
    pub fn is_empty(&self) -> bool {
        self.limiters.is_empty()
    }
}

/// Sliding window rate limiter using Redis
pub struct RedisRateLimiter {
    pool: deadpool_redis::Pool,
    prefix: String,
    window_seconds: u64,
    max_requests: u64,
}

impl RedisRateLimiter {
    /// Create a new Redis-backed rate limiter
    pub fn new(
        pool: deadpool_redis::Pool,
        prefix: &str,
        window_seconds: u64,
        max_requests: u64,
    ) -> Self {
        Self {
            pool,
            prefix: prefix.to_string(),
            window_seconds,
            max_requests,
        }
    }

    /// Check if a request is allowed and increment counter
    pub async fn check(&self, key: &str) -> Result<bool> {
        use deadpool_redis::redis::AsyncCommands;

        let full_key = format!("{}:{}", self.prefix, key);
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Internal(format!("Redis connection error: {}", e)))?;

        // Increment counter
        let count: u64 = conn.incr(&full_key, 1u64).await?;

        // Set expiry on first increment
        if count == 1 {
            let _: () = conn.expire(&full_key, self.window_seconds as i64).await?;
        }

        Ok(count <= self.max_requests)
    }

    /// Get the current count for a key
    pub async fn get_count(&self, key: &str) -> Result<u64> {
        use deadpool_redis::redis::AsyncCommands;

        let full_key = format!("{}:{}", self.prefix, key);
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Internal(format!("Redis connection error: {}", e)))?;

        let count: Option<u64> = conn.get(&full_key).await?;
        Ok(count.unwrap_or(0))
    }

    /// Reset the counter for a key
    pub async fn reset(&self, key: &str) -> Result<()> {
        use deadpool_redis::redis::AsyncCommands;

        let full_key = format!("{}:{}", self.prefix, key);
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Internal(format!("Redis connection error: {}", e)))?;

        let _: () = conn.del(&full_key).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_rate_limiter() {
        let config = RateLimitConfig {
            requests_per_second: 10,
            burst_size: 20,
        };

        let limiter = GlobalRateLimiter::new(&config).unwrap();

        // Should allow burst
        for _ in 0..20 {
            assert!(limiter.check());
        }

        // Should be rate limited after burst
        assert!(!limiter.check());
    }

    #[test]
    fn test_ip_rate_limiter() {
        let config = RateLimitConfig {
            requests_per_second: 5,
            burst_size: 10,
        };

        let limiter = IpRateLimiter::new(config);

        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // Each IP should have its own limit
        for _ in 0..10 {
            assert!(limiter.check(ip1));
        }
        assert!(!limiter.check(ip1));

        // IP2 should still have its full quota
        for _ in 0..10 {
            assert!(limiter.check(ip2));
        }
        assert!(!limiter.check(ip2));
    }
}
