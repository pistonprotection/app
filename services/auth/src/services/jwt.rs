//! JWT service for token generation and validation

use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::config::JwtConfig;
use crate::models::UserRole;

/// JWT claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: String,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Not before (Unix timestamp)
    pub nbf: i64,
    /// JWT ID
    pub jti: String,
    /// User email
    pub email: String,
    /// User role
    pub role: String,
    /// Organization IDs the user belongs to
    #[serde(default)]
    pub orgs: Vec<String>,
    /// Session ID (for session-based JWTs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// Token type (access, refresh)
    pub typ: String,
}

/// Token type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    Access,
    Refresh,
}

impl TokenType {
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenType::Access => "access",
            TokenType::Refresh => "refresh",
        }
    }
}

/// JWT service for token operations
pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    issuer: String,
    audience: String,
    access_token_ttl: Duration,
    refresh_token_ttl: Duration,
}

impl JwtService {
    /// Create a new JWT service
    pub fn new(config: &JwtConfig) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(config.secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(config.secret.as_bytes()),
            issuer: config.issuer.clone(),
            audience: config.audience.clone(),
            access_token_ttl: Duration::seconds(config.access_token_ttl_secs as i64),
            refresh_token_ttl: Duration::seconds(config.refresh_token_ttl_secs as i64),
        }
    }

    /// Generate an access token
    pub fn generate_access_token(
        &self,
        user_id: &str,
        email: &str,
        role: UserRole,
        orgs: Vec<String>,
        session_id: Option<&str>,
    ) -> Result<String, JwtError> {
        self.generate_token(user_id, email, role, orgs, session_id, TokenType::Access)
    }

    /// Generate a refresh token
    pub fn generate_refresh_token(
        &self,
        user_id: &str,
        email: &str,
        role: UserRole,
        orgs: Vec<String>,
        session_id: Option<&str>,
    ) -> Result<String, JwtError> {
        self.generate_token(user_id, email, role, orgs, session_id, TokenType::Refresh)
    }

    /// Generate a token with specified type
    fn generate_token(
        &self,
        user_id: &str,
        email: &str,
        role: UserRole,
        orgs: Vec<String>,
        session_id: Option<&str>,
        token_type: TokenType,
    ) -> Result<String, JwtError> {
        let now = Utc::now();
        let ttl = match token_type {
            TokenType::Access => self.access_token_ttl,
            TokenType::Refresh => self.refresh_token_ttl,
        };
        let exp = now + ttl;

        let claims = Claims {
            sub: user_id.to_string(),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            jti: uuid::Uuid::new_v4().to_string(),
            email: email.to_string(),
            role: match role {
                UserRole::User => "user".to_string(),
                UserRole::Admin => "admin".to_string(),
            },
            orgs,
            sid: session_id.map(|s| s.to_string()),
            typ: token_type.as_str().to_string(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| JwtError::EncodingError(e.to_string()))
    }

    /// Validate and decode a token
    pub fn validate_token(&self, token: &str) -> Result<Claims, JwtError> {
        let mut validation = Validation::default();
        validation.set_issuer(&[&self.issuer]);
        let mut audiences = HashSet::new();
        audiences.insert(self.audience.clone());
        validation.set_audience(&[&self.audience]);
        validation.validate_exp = true;
        validation.validate_nbf = true;

        let token_data: TokenData<Claims> = decode(token, &self.decoding_key, &validation)
            .map_err(|e| JwtError::ValidationError(e.to_string()))?;

        Ok(token_data.claims)
    }

    /// Validate an access token specifically
    pub fn validate_access_token(&self, token: &str) -> Result<Claims, JwtError> {
        let claims = self.validate_token(token)?;

        if claims.typ != "access" {
            return Err(JwtError::InvalidTokenType(
                "Expected access token".to_string(),
            ));
        }

        Ok(claims)
    }

    /// Validate a refresh token specifically
    pub fn validate_refresh_token(&self, token: &str) -> Result<Claims, JwtError> {
        let claims = self.validate_token(token)?;

        if claims.typ != "refresh" {
            return Err(JwtError::InvalidTokenType(
                "Expected refresh token".to_string(),
            ));
        }

        Ok(claims)
    }

    /// Get the access token TTL in seconds
    pub fn access_token_ttl_secs(&self) -> i64 {
        self.access_token_ttl.num_seconds()
    }

    /// Get the refresh token TTL in seconds
    pub fn refresh_token_ttl_secs(&self) -> i64 {
        self.refresh_token_ttl.num_seconds()
    }

    /// Extract user ID from token without full validation
    /// (useful for token refresh scenarios)
    pub fn extract_user_id(&self, token: &str) -> Result<String, JwtError> {
        let mut validation = Validation::default();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.insecure_disable_signature_validation();

        let token_data: TokenData<Claims> = decode(token, &self.decoding_key, &validation)
            .map_err(|e| JwtError::ValidationError(e.to_string()))?;

        Ok(token_data.claims.sub)
    }
}

/// JWT errors
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("Token encoding error: {0}")]
    EncodingError(String),

    #[error("Token validation error: {0}")]
    ValidationError(String),

    #[error("Invalid token type: {0}")]
    InvalidTokenType(String),

    #[error("Token expired")]
    TokenExpired,
}

impl From<JwtError> for tonic::Status {
    fn from(err: JwtError) -> Self {
        match err {
            JwtError::TokenExpired => tonic::Status::unauthenticated("Token expired"),
            JwtError::InvalidTokenType(_) => tonic::Status::unauthenticated("Invalid token type"),
            JwtError::ValidationError(_) => tonic::Status::unauthenticated("Invalid token"),
            JwtError::EncodingError(_) => tonic::Status::internal("Token generation failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> JwtConfig {
        JwtConfig {
            secret: "test-secret-key-for-testing-only".to_string(),
            issuer: "test-issuer".to_string(),
            audience: "test-audience".to_string(),
            access_token_ttl_secs: 3600,
            refresh_token_ttl_secs: 86400,
            algorithm: "HS256".to_string(),
        }
    }

    #[test]
    fn test_generate_and_validate_access_token() {
        let service = JwtService::new(&test_config());

        let token = service
            .generate_access_token("user123", "test@example.com", UserRole::User, vec![], None)
            .unwrap();

        let claims = service.validate_access_token(&token).unwrap();

        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.email, "test@example.com");
        assert_eq!(claims.typ, "access");
    }

    #[test]
    fn test_generate_and_validate_refresh_token() {
        let service = JwtService::new(&test_config());

        let token = service
            .generate_refresh_token(
                "user123",
                "test@example.com",
                UserRole::Admin,
                vec!["org1".to_string()],
                Some("session123"),
            )
            .unwrap();

        let claims = service.validate_refresh_token(&token).unwrap();

        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.role, "admin");
        assert_eq!(claims.typ, "refresh");
        assert_eq!(claims.sid, Some("session123".to_string()));
    }

    #[test]
    fn test_invalid_token_type() {
        let service = JwtService::new(&test_config());

        let refresh_token = service
            .generate_refresh_token("user123", "test@example.com", UserRole::User, vec![], None)
            .unwrap();

        // Should fail when validating refresh token as access token
        let result = service.validate_access_token(&refresh_token);
        assert!(result.is_err());
    }
}
