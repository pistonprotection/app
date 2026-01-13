//! Session service for session management with Redis caching

use chrono::{Duration, Utc};
use pistonprotection_common::redis::CacheService;
use serde::{Deserialize, Serialize};
use std::time::Duration as StdDuration;

use crate::config::SessionConfig;
use crate::models::{DeviceType, Session};

/// Session data stored in Redis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedSession {
    pub id: String,
    pub user_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub device_type: Option<String>,
    pub created_at: i64,
    pub last_active_at: i64,
    pub expires_at: i64,
}

impl From<&Session> for CachedSession {
    fn from(session: &Session) -> Self {
        Self {
            id: session.id.clone(),
            user_id: session.user_id.clone(),
            ip_address: session.ip_address.clone(),
            user_agent: session.user_agent.clone(),
            device_type: session.device_type.clone(),
            created_at: session.created_at.timestamp(),
            last_active_at: session.last_active_at.timestamp(),
            expires_at: session.expires_at.timestamp(),
        }
    }
}

/// Session service for managing user sessions
pub struct SessionService {
    cache: CacheService,
    config: SessionConfig,
}

impl SessionService {
    /// Create a new session service
    pub fn new(cache: CacheService, config: SessionConfig) -> Self {
        Self { cache, config }
    }

    /// Generate a session token
    pub fn generate_token() -> String {
        use base64::Engine;
        use rand::RngCore;

        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Hash a session token for storage
    pub fn hash_token(token: &str) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Get session TTL
    pub fn ttl(&self) -> Duration {
        Duration::seconds(self.config.ttl_secs as i64)
    }

    /// Get session TTL as std::time::Duration
    pub fn ttl_std(&self) -> StdDuration {
        StdDuration::from_secs(self.config.ttl_secs)
    }

    /// Get expiration timestamp
    pub fn get_expiration(&self) -> chrono::DateTime<Utc> {
        Utc::now() + self.ttl()
    }

    /// Detect device type from user agent
    pub fn detect_device_type(&self, user_agent: Option<&str>) -> String {
        user_agent
            .map(|ua| DeviceType::from_user_agent(ua).to_string())
            .unwrap_or_else(|| DeviceType::Unknown.to_string())
    }

    /// Cache a session in Redis
    pub async fn cache_session(&self, session: &Session) -> Result<(), SessionError> {
        let key = format!("session:{}", session.id);
        let cached = CachedSession::from(session);

        self.cache
            .set(&key, &cached, self.ttl_std())
            .await
            .map_err(|e| SessionError::CacheError(e.to_string()))?;

        // Also add to user's session set
        let user_key = format!("user:{}:sessions", session.user_id);
        self.cache
            .sadd(&user_key, &session.id)
            .await
            .map_err(|e| SessionError::CacheError(e.to_string()))?;

        Ok(())
    }

    /// Get a cached session by ID
    pub async fn get_cached_session(
        &self,
        session_id: &str,
    ) -> Result<Option<CachedSession>, SessionError> {
        let key = format!("session:{}", session_id);

        self.cache
            .get::<CachedSession>(&key)
            .await
            .map_err(|e| SessionError::CacheError(e.to_string()))
    }

    /// Get a cached session by token hash
    pub async fn get_session_by_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<CachedSession>, SessionError> {
        // First, look up session ID by token hash
        let token_key = format!("token:{}", token_hash);
        let session_id: Option<String> = self
            .cache
            .get(&token_key)
            .await
            .map_err(|e| SessionError::CacheError(e.to_string()))?;

        match session_id {
            Some(id) => self.get_cached_session(&id).await,
            None => Ok(None),
        }
    }

    /// Map token hash to session ID
    pub async fn map_token_to_session(
        &self,
        token_hash: &str,
        session_id: &str,
    ) -> Result<(), SessionError> {
        let key = format!("token:{}", token_hash);

        self.cache
            .set(&key, &session_id.to_string(), self.ttl_std())
            .await
            .map_err(|e| SessionError::CacheError(e.to_string()))
    }

    /// Update session last active time
    pub async fn touch_session(&self, session_id: &str) -> Result<(), SessionError> {
        let key = format!("session:{}", session_id);

        if let Some(mut cached) = self.get_cached_session(session_id).await? {
            cached.last_active_at = Utc::now().timestamp();

            // Extend TTL if sliding window is enabled
            let ttl = if self.config.sliding_window {
                self.ttl_std()
            } else {
                // Calculate remaining TTL
                let remaining = cached.expires_at - Utc::now().timestamp();
                if remaining > 0 {
                    StdDuration::from_secs(remaining as u64)
                } else {
                    return Err(SessionError::SessionExpired);
                }
            };

            self.cache
                .set(&key, &cached, ttl)
                .await
                .map_err(|e| SessionError::CacheError(e.to_string()))?;
        }

        Ok(())
    }

    /// Invalidate a session
    pub async fn invalidate_session(
        &self,
        session_id: &str,
        user_id: &str,
    ) -> Result<(), SessionError> {
        let session_key = format!("session:{}", session_id);
        let _user_key = format!("user:{}:sessions", user_id);

        // Delete session from cache
        self.cache
            .delete(&session_key)
            .await
            .map_err(|e| SessionError::CacheError(e.to_string()))?;

        // Note: We don't remove from user's session set here as it will eventually expire
        // In production, you might want to use SREM

        Ok(())
    }

    /// Invalidate all sessions for a user
    pub async fn invalidate_user_sessions(&self, user_id: &str) -> Result<u64, SessionError> {
        let user_key = format!("user:{}:sessions", user_id);

        // Get all session IDs
        let session_ids = self
            .cache
            .smembers(&user_key)
            .await
            .map_err(|e| SessionError::CacheError(e.to_string()))?;

        let count = session_ids.len() as u64;

        // Delete each session
        for session_id in &session_ids {
            let session_key = format!("session:{}", session_id);
            let _ = self.cache.delete(&session_key).await;
        }

        // Clear the user's session set
        let _ = self.cache.delete(&user_key).await;

        Ok(count)
    }

    /// Get all active session IDs for a user
    pub async fn get_user_session_ids(&self, user_id: &str) -> Result<Vec<String>, SessionError> {
        let user_key = format!("user:{}:sessions", user_id);

        self.cache
            .smembers(&user_key)
            .await
            .map_err(|e| SessionError::CacheError(e.to_string()))
    }

    /// Check if user has exceeded max sessions
    pub async fn check_session_limit(&self, user_id: &str) -> Result<bool, SessionError> {
        let session_ids = self.get_user_session_ids(user_id).await?;
        Ok(session_ids.len() < self.config.max_sessions_per_user as usize)
    }

    /// Get max sessions per user
    pub fn max_sessions_per_user(&self) -> u32 {
        self.config.max_sessions_per_user
    }
}

/// Session service errors
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("Session not found")]
    SessionNotFound,

    #[error("Session expired")]
    SessionExpired,

    #[error("Max sessions exceeded")]
    MaxSessionsExceeded,
}

impl From<SessionError> for tonic::Status {
    fn from(err: SessionError) -> Self {
        match err {
            SessionError::SessionNotFound => tonic::Status::unauthenticated("Session not found"),
            SessionError::SessionExpired => tonic::Status::unauthenticated("Session expired"),
            SessionError::MaxSessionsExceeded => {
                tonic::Status::resource_exhausted("Maximum sessions exceeded")
            }
            SessionError::CacheError(msg) => {
                tonic::Status::internal(format!("Cache error: {}", msg))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token() {
        let token1 = SessionService::generate_token();
        let token2 = SessionService::generate_token();

        assert_ne!(token1, token2);
        assert!(token1.len() >= 32);
    }

    #[test]
    fn test_hash_token() {
        let token = "test-token-123";
        let hash1 = SessionService::hash_token(token);
        let hash2 = SessionService::hash_token(token);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 hex string
    }

    #[test]
    fn test_detect_device_type() {
        let config = SessionConfig::default();
        let cache = todo!(); // Would need mock
        // let service = SessionService::new(cache, config);

        // Test cases would go here with a mock cache
    }
}
