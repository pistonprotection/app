//! Authentication middleware for gRPC
//!
//! This middleware validates JWT tokens and API keys for all incoming requests.
//! It extracts user identity and attaches it to the request for downstream handlers.

use std::collections::HashSet;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use jsonwebtoken::{DecodingKey, TokenData, Validation, decode};
use pistonprotection_common::config::AuthConfig;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tower::{Layer, Service};
use tracing::{debug, error, warn};

type BoxBody = UnsyncBoxBody<Bytes, tonic::Status>;

/// JWT claims structure (must match auth service claims)
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

/// Authentication context extracted from the request
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// User ID
    pub user_id: String,
    /// User email
    pub email: String,
    /// User role
    pub role: String,
    /// Organizations the user belongs to
    pub organizations: Vec<String>,
    /// Authentication method used
    pub auth_method: AuthMethod,
}

/// Authentication method
#[derive(Debug, Clone)]
pub enum AuthMethod {
    /// JWT token (from Authorization header)
    Jwt,
    /// API key (from x-api-key header)
    ApiKey,
}

/// JWT validation service
pub struct JwtValidator {
    decoding_key: DecodingKey,
    validation: Validation,
}

impl JwtValidator {
    /// Create a new JWT validator
    pub fn new(config: &AuthConfig) -> Self {
        let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());

        let mut validation = Validation::default();
        validation.set_issuer(&[&config.jwt_issuer]);
        validation.set_audience(&[&config.jwt_audience]);
        validation.validate_exp = true;
        validation.validate_nbf = true;

        Self {
            decoding_key,
            validation,
        }
    }

    /// Validate a JWT token and return the claims
    pub fn validate(&self, token: &str) -> Result<Claims, AuthError> {
        let token_data: TokenData<Claims> = decode(token, &self.decoding_key, &self.validation)
            .map_err(|e| {
                debug!(error = %e, "JWT validation failed");
                AuthError::InvalidToken(e.to_string())
            })?;

        // Ensure it's an access token
        if token_data.claims.typ != "access" {
            return Err(AuthError::InvalidTokenType);
        }

        Ok(token_data.claims)
    }
}

/// API key validation using database
pub struct ApiKeyValidator {
    db_pool: Option<Arc<PgPool>>,
}

impl ApiKeyValidator {
    /// Create a new API key validator
    pub fn new(db_pool: Option<Arc<PgPool>>) -> Self {
        Self { db_pool }
    }

    /// Validate an API key and return auth context
    pub async fn validate(&self, api_key: &str) -> Result<AuthContext, AuthError> {
        let pool = self
            .db_pool
            .as_ref()
            .ok_or(AuthError::DatabaseNotAvailable)?;

        // Query the database for the API key
        let result = sqlx::query_as::<_, ApiKeyRow>(
            r#"
            SELECT
                ak.id,
                ak.user_id,
                ak.organization_id,
                ak.name,
                ak.scopes,
                ak.expires_at,
                ak.last_used_at,
                u.email,
                u.role as user_role
            FROM api_keys ak
            JOIN users u ON ak.user_id = u.id
            WHERE ak.key_hash = encode(sha256($1::bytea), 'hex')
            AND ak.revoked_at IS NULL
            AND (ak.expires_at IS NULL OR ak.expires_at > NOW())
            "#,
        )
        .bind(api_key.as_bytes())
        .fetch_optional(pool.as_ref())
        .await
        .map_err(|e| {
            error!(error = %e, "Database error validating API key");
            AuthError::DatabaseError(e.to_string())
        })?;

        let api_key_row = result.ok_or(AuthError::InvalidApiKey)?;

        // Update last used timestamp (fire and forget)
        let pool_clone = pool.clone();
        let key_id = api_key_row.id.clone();
        tokio::spawn(async move {
            let _ = sqlx::query("UPDATE api_keys SET last_used_at = NOW() WHERE id = $1")
                .bind(&key_id)
                .execute(pool_clone.as_ref())
                .await;
        });

        Ok(AuthContext {
            user_id: api_key_row.user_id,
            email: api_key_row.email,
            role: api_key_row.user_role,
            organizations: api_key_row
                .organization_id
                .map(|id| vec![id])
                .unwrap_or_default(),
            auth_method: AuthMethod::ApiKey,
        })
    }
}

/// Database row for API key queries
#[derive(Debug, sqlx::FromRow)]
struct ApiKeyRow {
    id: String,
    user_id: String,
    organization_id: Option<String>,
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    scopes: Option<Vec<String>>,
    #[allow(dead_code)]
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[allow(dead_code)]
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    email: String,
    user_role: String,
}

/// Authentication errors
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Missing authorization header")]
    MissingAuth,

    #[error("Invalid token: {0}")]
    InvalidToken(String),

    #[error("Invalid token type")]
    InvalidTokenType,

    #[error("Invalid API key")]
    InvalidApiKey,

    #[error("Database not available")]
    DatabaseNotAvailable,

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Token expired")]
    TokenExpired,
}

impl From<AuthError> for tonic::Status {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::MissingAuth => tonic::Status::unauthenticated("Missing authorization"),
            AuthError::InvalidToken(_) => tonic::Status::unauthenticated("Invalid token"),
            AuthError::InvalidTokenType => tonic::Status::unauthenticated("Invalid token type"),
            AuthError::InvalidApiKey => tonic::Status::unauthenticated("Invalid API key"),
            AuthError::TokenExpired => tonic::Status::unauthenticated("Token expired"),
            AuthError::DatabaseNotAvailable => {
                tonic::Status::unavailable("Authentication service unavailable")
            }
            AuthError::DatabaseError(_) => tonic::Status::internal("Authentication error"),
        }
    }
}

/// Authentication state shared across middleware instances
#[derive(Clone)]
pub struct AuthState {
    jwt_validator: Option<Arc<JwtValidator>>,
    api_key_validator: Arc<ApiKeyValidator>,
    public_paths: HashSet<String>,
    skip_auth: bool,
    is_production: bool,
}

impl AuthState {
    /// Create a new auth state
    pub fn new(
        config: Option<&AuthConfig>,
        db_pool: Option<Arc<PgPool>>,
        is_production: bool,
    ) -> Self {
        let (jwt_validator, public_paths, skip_auth) = match config {
            Some(cfg) => {
                let validator = Arc::new(JwtValidator::new(cfg));
                let paths: HashSet<String> = cfg.public_paths.iter().cloned().collect();
                let skip = cfg.skip_auth && !is_production;
                (Some(validator), paths, skip)
            }
            None => {
                warn!(
                    "No auth configuration provided, authentication will be skipped in development"
                );
                (None, HashSet::new(), !is_production)
            }
        };

        Self {
            jwt_validator,
            api_key_validator: Arc::new(ApiKeyValidator::new(db_pool)),
            public_paths,
            skip_auth,
            is_production,
        }
    }

    /// Check if a path is public (doesn't require authentication)
    fn is_public_path(&self, path: &str) -> bool {
        self.public_paths.iter().any(|p| path.starts_with(p))
    }

    /// Validate the request and return auth context
    async fn authenticate(
        &self,
        headers: &http::HeaderMap,
    ) -> Result<Option<AuthContext>, AuthError> {
        // Try JWT first (Authorization: Bearer <token>)
        if let Some(auth_header) = headers.get("authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if let Some(token) = auth_str.strip_prefix("Bearer ") {
                    if let Some(ref validator) = self.jwt_validator {
                        let claims = validator.validate(token)?;
                        return Ok(Some(AuthContext {
                            user_id: claims.sub,
                            email: claims.email,
                            role: claims.role,
                            organizations: claims.orgs,
                            auth_method: AuthMethod::Jwt,
                        }));
                    }
                }
            }
        }

        // Try API key (x-api-key header)
        if let Some(api_key_header) = headers.get("x-api-key") {
            if let Ok(api_key) = api_key_header.to_str() {
                let context = self.api_key_validator.validate(api_key).await?;
                return Ok(Some(context));
            }
        }

        // No authentication provided
        Ok(None)
    }
}

/// Authentication middleware
#[derive(Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
    state: AuthState,
}

impl<S> AuthMiddleware<S> {
    pub fn new(inner: S, state: AuthState) -> Self {
        Self { inner, state }
    }
}

impl<S, ReqBody> Service<http::Request<ReqBody>> for AuthMiddleware<S>
where
    S: Service<http::Request<ReqBody>, Response = http::Response<BoxBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = futures::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<ReqBody>) -> Self::Future {
        let mut inner = self.inner.clone();
        let state = self.state.clone();

        Box::pin(async move {
            let path = req.uri().path().to_string();

            // Skip auth for public paths
            if state.is_public_path(&path) {
                debug!(path = %path, "Skipping auth for public path");
                return inner.call(req).await;
            }

            // Skip auth if configured (development only)
            if state.skip_auth {
                if state.is_production {
                    error!("Auth bypass attempted in production - this should never happen!");
                    // Fall through to require authentication
                } else {
                    debug!(path = %path, "Skipping auth (development mode)");
                    return inner.call(req).await;
                }
            }

            // Authenticate the request
            match state.authenticate(req.headers()).await {
                Ok(Some(context)) => {
                    debug!(
                        user_id = %context.user_id,
                        method = ?context.auth_method,
                        path = %path,
                        "Request authenticated"
                    );

                    // Add auth context to request extensions for handlers to access
                    req.extensions_mut().insert(context);
                    inner.call(req).await
                }
                Ok(None) => {
                    warn!(path = %path, "Unauthorized request - no credentials provided");

                    // Return unauthenticated error. Builder should never fail with valid inputs.
                    let response = http::Response::builder()
                        .status(http::StatusCode::UNAUTHORIZED)
                        .header("content-type", "application/grpc")
                        .header("grpc-status", "16") // UNAUTHENTICATED
                        .header("grpc-message", "Missing authorization")
                        .body(UnsyncBoxBody::default())
                        .expect("auth error response should always build with valid inputs");

                    Ok(response)
                }
                Err(e) => {
                    // Log only the error category, not full details to avoid information leakage
                    warn!(path = %path, error_category = ?e, "Authentication failed");

                    let status: tonic::Status = e.into();
                    let response = http::Response::builder()
                        .status(http::StatusCode::UNAUTHORIZED)
                        .header("content-type", "application/grpc")
                        .header("grpc-status", "16") // UNAUTHENTICATED
                        .header("grpc-message", status.message())
                        .body(UnsyncBoxBody::default())
                        .expect("auth error response should always build with valid inputs");

                    Ok(response)
                }
            }
        })
    }
}

/// Layer for authentication middleware
#[derive(Clone)]
pub struct AuthLayer {
    state: AuthState,
}

impl AuthLayer {
    /// Create a new auth layer with the given configuration
    pub fn new(
        config: Option<&AuthConfig>,
        db_pool: Option<Arc<PgPool>>,
        is_production: bool,
    ) -> Self {
        Self {
            state: AuthState::new(config, db_pool, is_production),
        }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        AuthMiddleware::new(service, self.state.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_validator_creation() {
        let config = AuthConfig {
            jwt_secret: "test-secret".to_string(),
            jwt_issuer: "test-issuer".to_string(),
            jwt_audience: "test-audience".to_string(),
            skip_auth: false,
            public_paths: vec![],
        };

        let validator = JwtValidator::new(&config);
        // Just verify it doesn't panic
        assert!(validator.validate("invalid-token").is_err());
    }

    #[test]
    fn test_auth_state_public_paths() {
        let config = AuthConfig {
            jwt_secret: "test-secret".to_string(),
            jwt_issuer: "test-issuer".to_string(),
            jwt_audience: "test-audience".to_string(),
            skip_auth: false,
            public_paths: vec!["/health".to_string(), "/metrics".to_string()],
        };

        let state = AuthState::new(Some(&config), None, false);

        assert!(state.is_public_path("/health"));
        assert!(state.is_public_path("/health/ready"));
        assert!(state.is_public_path("/metrics"));
        assert!(!state.is_public_path("/api/v1/backends"));
    }

    #[test]
    fn test_auth_error_conversion() {
        let status: tonic::Status = AuthError::MissingAuth.into();
        assert_eq!(status.code(), tonic::Code::Unauthenticated);

        let status: tonic::Status = AuthError::InvalidApiKey.into();
        assert_eq!(status.code(), tonic::Code::Unauthenticated);

        let status: tonic::Status = AuthError::DatabaseNotAvailable.into();
        assert_eq!(status.code(), tonic::Code::Unavailable);
    }
}
