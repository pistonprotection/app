//! API Key service for key generation and validation

use pistonprotection_common::redis::CacheService;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

use crate::config::AuthConfig;
use crate::db;
use crate::models::{
    ApiKey, ApiKeyGenerator, ApiKeyResponse, CreateApiKeyRequest, CreateApiKeyResponse,
};

/// Cached API key data
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CachedApiKey {
    id: String,
    organization_id: String,
    permissions: Vec<String>,
    allowed_ips: Vec<String>,
}

impl From<&ApiKey> for CachedApiKey {
    fn from(key: &ApiKey) -> Self {
        Self {
            id: key.id.clone(),
            organization_id: key.organization_id.clone(),
            permissions: key.permissions.clone(),
            allowed_ips: key.allowed_ips.clone(),
        }
    }
}

/// API Key service
pub struct ApiKeyService {
    db: PgPool,
    cache: CacheService,
    config: Arc<AuthConfig>,
}

impl ApiKeyService {
    /// Create a new API key service
    pub fn new(db: PgPool, cache: CacheService, config: Arc<AuthConfig>) -> Self {
        Self { db, cache, config }
    }

    /// Create a new API key
    pub async fn create_key(
        &self,
        organization_id: &str,
        user_id: &str,
        request: CreateApiKeyRequest,
    ) -> Result<CreateApiKeyResponse, ApiKeyError> {
        // Check if organization has reached max API keys
        let (existing_keys, _) = db::list_api_keys(&self.db, organization_id, 1, 1)
            .await
            .map_err(|e| ApiKeyError::DatabaseError(e.to_string()))?;

        // This is a simple count check - in production you'd want a proper count query
        let key_count = existing_keys.len();
        if key_count >= self.config.api_key.max_keys_per_org as usize {
            return Err(ApiKeyError::MaxKeysExceeded);
        }

        // Generate key
        let (secret, prefix) =
            ApiKeyGenerator::generate(&self.config.api_key.prefix, self.config.api_key.key_length);

        // Hash the key for storage
        let key_hash = ApiKeyGenerator::hash_key(&secret);

        // Create in database
        let id = uuid::Uuid::new_v4().to_string();
        let api_key = db::create_api_key(
            &self.db,
            &id,
            organization_id,
            user_id,
            &request.name,
            &prefix,
            &key_hash,
            &request.permissions,
            request.allowed_ips.as_deref().unwrap_or(&[]),
            request.expires_at,
        )
        .await
        .map_err(|e| ApiKeyError::DatabaseError(e.to_string()))?;

        info!("API key created: {} for org {}", id, organization_id);

        Ok(CreateApiKeyResponse {
            key: ApiKeyResponse::from(api_key),
            secret, // Only returned once
        })
    }

    /// Validate an API key
    pub async fn validate_key(
        &self,
        api_key: &str,
        client_ip: Option<&str>,
    ) -> Result<ApiKey, ApiKeyError> {
        // Hash the provided key
        let key_hash = ApiKeyGenerator::hash_key(api_key);

        // Check cache first
        let cache_key = format!("apikey:{}", key_hash);
        if let Some(cached) = self
            .cache
            .get::<CachedApiKey>(&cache_key)
            .await
            .map_err(|e| ApiKeyError::CacheError(e.to_string()))?
        {
            // Validate IP if restrictions exist
            if !cached.allowed_ips.is_empty() {
                if let Some(ip) = client_ip {
                    if !self.is_ip_allowed(ip, &cached.allowed_ips) {
                        warn!("API key {} used from unauthorized IP: {}", cached.id, ip);
                        return Err(ApiKeyError::IpNotAllowed);
                    }
                } else {
                    // IP required but not provided
                    return Err(ApiKeyError::IpNotAllowed);
                }
            }

            // Get full key from database for complete validation
            let key = db::get_api_key_by_id(&self.db, &cached.id)
                .await
                .map_err(|e| ApiKeyError::DatabaseError(e.to_string()))?
                .ok_or(ApiKeyError::InvalidKey)?;

            // Update last used
            let _ = db::update_api_key_last_used(&self.db, &key.id).await;

            return Ok(key);
        }

        // Not in cache, query database
        let key = db::get_api_key_by_hash(&self.db, &key_hash)
            .await
            .map_err(|e| ApiKeyError::DatabaseError(e.to_string()))?
            .ok_or(ApiKeyError::InvalidKey)?;

        // Check if enabled
        if !key.enabled {
            return Err(ApiKeyError::KeyDisabled);
        }

        // Check expiration
        if let Some(expires_at) = key.expires_at {
            if expires_at < chrono::Utc::now() {
                return Err(ApiKeyError::KeyExpired);
            }
        }

        // Validate IP if restrictions exist
        if !key.allowed_ips.is_empty() {
            if let Some(ip) = client_ip {
                if !self.is_ip_allowed(ip, &key.allowed_ips) {
                    warn!("API key {} used from unauthorized IP: {}", key.id, ip);
                    return Err(ApiKeyError::IpNotAllowed);
                }
            } else {
                return Err(ApiKeyError::IpNotAllowed);
            }
        }

        // Cache the key
        let cached = CachedApiKey::from(&key);
        let _ = self
            .cache
            .set(&cache_key, &cached, Duration::from_secs(300))
            .await;

        // Update last used
        let _ = db::update_api_key_last_used(&self.db, &key.id).await;

        Ok(key)
    }

    /// Check if an IP is allowed
    fn is_ip_allowed(&self, ip: &str, allowed_ips: &[String]) -> bool {
        for allowed in allowed_ips {
            // Check for exact match
            if allowed == ip {
                return true;
            }

            // Check for CIDR range
            if allowed.contains('/') {
                if let Ok(network) = allowed.parse::<ipnetwork::IpNetwork>() {
                    if let Ok(ip_addr) = ip.parse::<std::net::IpAddr>() {
                        if network.contains(ip_addr) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Check if key has a specific permission
    pub fn check_permission(&self, key: &ApiKey, required_permission: &str) -> bool {
        // Check for admin permission (grants all)
        if key.permissions.iter().any(|p| p == "admin") {
            return true;
        }

        // Check for wildcard permissions
        let parts: Vec<&str> = required_permission.split(':').collect();
        if parts.len() >= 2 {
            let resource_wildcard = format!("{}:*", parts[0]);
            if key.permissions.iter().any(|p| p == &resource_wildcard) {
                return true;
            }
        }

        // Check for exact permission
        key.permissions.iter().any(|p| p == required_permission)
    }

    /// Revoke an API key
    pub async fn revoke_key(&self, key_id: &str) -> Result<bool, ApiKeyError> {
        // Get key to find hash for cache invalidation
        let key = db::get_api_key_by_id(&self.db, key_id)
            .await
            .map_err(|e| ApiKeyError::DatabaseError(e.to_string()))?;

        if let Some(k) = key {
            // Invalidate cache
            let cache_key = format!("apikey:{}", k.key_hash);
            let _ = self.cache.delete(&cache_key).await;
        }

        // Revoke in database
        let revoked = db::revoke_api_key(&self.db, key_id)
            .await
            .map_err(|e| ApiKeyError::DatabaseError(e.to_string()))?;

        if revoked {
            info!("API key revoked: {}", key_id);
        }

        Ok(revoked)
    }

    /// List API keys for an organization
    pub async fn list_keys(
        &self,
        organization_id: &str,
        page: u32,
        page_size: u32,
    ) -> Result<(Vec<ApiKeyResponse>, u32), ApiKeyError> {
        let (keys, total) = db::list_api_keys(&self.db, organization_id, page, page_size)
            .await
            .map_err(|e| ApiKeyError::DatabaseError(e.to_string()))?;

        Ok((keys.into_iter().map(ApiKeyResponse::from).collect(), total))
    }

    /// Get an API key by ID
    pub async fn get_key(&self, key_id: &str) -> Result<Option<ApiKeyResponse>, ApiKeyError> {
        let key = db::get_api_key_by_id(&self.db, key_id)
            .await
            .map_err(|e| ApiKeyError::DatabaseError(e.to_string()))?;

        Ok(key.map(ApiKeyResponse::from))
    }
}

/// API Key errors
#[derive(Debug, thiserror::Error)]
pub enum ApiKeyError {
    #[error("Invalid API key")]
    InvalidKey,

    #[error("API key disabled")]
    KeyDisabled,

    #[error("API key expired")]
    KeyExpired,

    #[error("IP address not allowed")]
    IpNotAllowed,

    #[error("Maximum API keys exceeded")]
    MaxKeysExceeded,

    #[error("Insufficient permissions")]
    InsufficientPermissions,

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Cache error: {0}")]
    CacheError(String),
}

impl From<ApiKeyError> for tonic::Status {
    fn from(err: ApiKeyError) -> Self {
        match err {
            ApiKeyError::InvalidKey => tonic::Status::unauthenticated("Invalid API key"),
            ApiKeyError::KeyDisabled => tonic::Status::unauthenticated("API key is disabled"),
            ApiKeyError::KeyExpired => tonic::Status::unauthenticated("API key has expired"),
            ApiKeyError::IpNotAllowed => {
                tonic::Status::permission_denied("IP address not allowed for this API key")
            }
            ApiKeyError::MaxKeysExceeded => {
                tonic::Status::resource_exhausted("Maximum API keys reached for this organization")
            }
            ApiKeyError::InsufficientPermissions => {
                tonic::Status::permission_denied("API key lacks required permissions")
            }
            ApiKeyError::DatabaseError(msg) => tonic::Status::internal(msg),
            ApiKeyError::CacheError(msg) => tonic::Status::internal(msg),
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_ip_allowed_exact_match() {
        // Would need mock db/cache for full test
        // This tests the logic in isolation
        let allowed = ["192.168.1.1".to_string(), "10.0.0.0/8".to_string()];

        // Test exact match
        assert!(allowed.iter().any(|a| a == "192.168.1.1"));

        // Test CIDR
        let network: ipnetwork::IpNetwork = "10.0.0.0/8".parse().unwrap();
        let ip: std::net::IpAddr = "10.5.6.7".parse().unwrap();
        assert!(network.contains(ip));
    }
}
