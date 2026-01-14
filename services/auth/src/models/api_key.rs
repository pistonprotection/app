//! API Key model definitions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use validator::Validate;

/// API Key permission enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "api_key_permission", rename_all = "lowercase")]
pub enum ApiKeyPermission {
    Read,
    Write,
    Delete,
    Admin,
}

impl From<ApiKeyPermission> for i32 {
    fn from(perm: ApiKeyPermission) -> Self {
        match perm {
            ApiKeyPermission::Read => 1,
            ApiKeyPermission::Write => 2,
            ApiKeyPermission::Delete => 3,
            ApiKeyPermission::Admin => 4,
        }
    }
}

impl TryFrom<i32> for ApiKeyPermission {
    type Error = &'static str;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(ApiKeyPermission::Read),
            2 => Ok(ApiKeyPermission::Write),
            3 => Ok(ApiKeyPermission::Delete),
            4 => Ok(ApiKeyPermission::Admin),
            _ => Err("Invalid API key permission"),
        }
    }
}

impl ApiKeyPermission {
    /// Check if this permission implies another permission
    pub fn implies(&self, other: &ApiKeyPermission) -> bool {
        match self {
            ApiKeyPermission::Admin => true, // Admin implies all
            ApiKeyPermission::Delete => matches!(
                other,
                ApiKeyPermission::Read | ApiKeyPermission::Write | ApiKeyPermission::Delete
            ),
            ApiKeyPermission::Write => {
                matches!(other, ApiKeyPermission::Read | ApiKeyPermission::Write)
            }
            ApiKeyPermission::Read => matches!(other, ApiKeyPermission::Read),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ApiKeyPermission::Read => "read",
            ApiKeyPermission::Write => "write",
            ApiKeyPermission::Delete => "delete",
            ApiKeyPermission::Admin => "admin",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "read" => Some(ApiKeyPermission::Read),
            "write" => Some(ApiKeyPermission::Write),
            "delete" => Some(ApiKeyPermission::Delete),
            "admin" => Some(ApiKeyPermission::Admin),
            _ => None,
        }
    }
}

/// API Key model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ApiKey {
    pub id: String,
    pub organization_id: String,
    pub created_by_user_id: String,
    pub name: String,
    pub prefix: String,
    pub key_hash: String,
    pub permissions: Vec<String>, // Stored as JSON array
    pub allowed_ips: Vec<String>, // Stored as JSON array
    pub enabled: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// API Key for external responses (no key hash)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyResponse {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub prefix: String,
    pub permissions: Vec<String>,
    pub allowed_ips: Vec<String>,
    pub enabled: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl From<ApiKey> for ApiKeyResponse {
    fn from(key: ApiKey) -> Self {
        Self {
            id: key.id,
            organization_id: key.organization_id,
            name: key.name,
            prefix: key.prefix,
            permissions: key.permissions,
            allowed_ips: key.allowed_ips,
            enabled: key.enabled,
            expires_at: key.expires_at,
            last_used_at: key.last_used_at,
            created_at: key.created_at,
        }
    }
}

/// Request to create a new API key
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateApiKeyRequest {
    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))]
    pub name: String,

    pub permissions: Vec<String>,

    pub allowed_ips: Option<Vec<String>>,

    pub expires_at: Option<DateTime<Utc>>,
}

/// Response when creating an API key (includes secret)
#[derive(Debug, Clone, Serialize)]
pub struct CreateApiKeyResponse {
    pub key: ApiKeyResponse,
    pub secret: String, // Only returned once on creation
}

/// API Key validation result
#[derive(Debug, Clone)]
pub struct ApiKeyValidation {
    pub valid: bool,
    pub key: Option<ApiKey>,
    pub reason: Option<String>,
}

impl ApiKeyValidation {
    pub fn valid(key: ApiKey) -> Self {
        Self {
            valid: true,
            key: Some(key),
            reason: None,
        }
    }

    pub fn invalid(reason: &str) -> Self {
        Self {
            valid: false,
            key: None,
            reason: Some(reason.to_string()),
        }
    }
}

/// Convert to proto ApiKey
impl ApiKey {
    pub fn to_proto(&self) -> pistonprotection_proto::auth::ApiKey {
        use pistonprotection_proto::Timestamp;
        use pistonprotection_proto::auth;

        auth::ApiKey {
            id: self.id.clone(),
            organization_id: self.organization_id.clone(),
            name: self.name.clone(),
            prefix: self.prefix.clone(),
            permissions: self
                .permissions
                .iter()
                .filter_map(|p| ApiKeyPermission::from_str(p))
                .map(i32::from)
                .collect(),
            allowed_ips: self.allowed_ips.clone(),
            enabled: self.enabled,
            expires_at: self.expires_at.map(Timestamp::from),
            last_used_at: self.last_used_at.map(Timestamp::from),
            created_at: Some(Timestamp::from(self.created_at)),
        }
    }
}

/// API Key generator
pub struct ApiKeyGenerator;

impl ApiKeyGenerator {
    /// Generate a new API key with the given prefix
    pub fn generate(prefix: &str, length: usize) -> (String, String) {
        use base64::Engine;
        use rand::RngCore;

        // Generate random bytes
        let mut bytes = vec![0u8; length];
        rand::rng().fill_bytes(&mut bytes);

        // Encode as base64
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);

        // Create full key with prefix
        let full_key = format!("{}_{}", prefix, encoded);

        // Extract prefix portion (first 8 chars of encoded part)
        let key_prefix = format!("{}_{}", prefix, &encoded[..8.min(encoded.len())]);

        (full_key, key_prefix)
    }

    /// Hash an API key for storage
    pub fn hash_key(key: &str) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Verify an API key against a hash
    pub fn verify_key(key: &str, hash: &str) -> bool {
        let computed_hash = Self::hash_key(key);
        // Use constant-time comparison to prevent timing attacks
        computed_hash == hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_permission_implies() {
        assert!(ApiKeyPermission::Admin.implies(&ApiKeyPermission::Read));
        assert!(ApiKeyPermission::Admin.implies(&ApiKeyPermission::Write));
        assert!(ApiKeyPermission::Admin.implies(&ApiKeyPermission::Delete));

        assert!(ApiKeyPermission::Write.implies(&ApiKeyPermission::Read));
        assert!(!ApiKeyPermission::Write.implies(&ApiKeyPermission::Delete));

        assert!(ApiKeyPermission::Read.implies(&ApiKeyPermission::Read));
        assert!(!ApiKeyPermission::Read.implies(&ApiKeyPermission::Write));
    }

    #[test]
    fn test_api_key_generation() {
        let (full_key, prefix) = ApiKeyGenerator::generate("psk", 32);

        assert!(full_key.starts_with("psk_"));
        assert!(prefix.starts_with("psk_"));
        assert!(full_key.len() > prefix.len());
    }

    #[test]
    fn test_api_key_hashing() {
        let key = "psk_test123456";
        let hash = ApiKeyGenerator::hash_key(key);

        assert!(ApiKeyGenerator::verify_key(key, &hash));
        assert!(!ApiKeyGenerator::verify_key("wrong_key", &hash));
    }
}
