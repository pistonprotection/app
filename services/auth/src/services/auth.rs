//! Authentication service for login, logout, and token management

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{info, warn};

use crate::config::AuthConfig;
use crate::db;
use crate::models::{CreateSession, Session, TokenPair, User, UserRole};
use crate::services::{JwtService, SessionService};

/// Authentication service
pub struct AuthService {
    db: PgPool,
    jwt_service: Arc<JwtService>,
    session_service: Arc<SessionService>,
    config: Arc<AuthConfig>,
}

impl AuthService {
    /// Create a new authentication service
    pub fn new(
        db: PgPool,
        jwt_service: Arc<JwtService>,
        session_service: Arc<SessionService>,
        config: Arc<AuthConfig>,
    ) -> Self {
        Self {
            db,
            jwt_service,
            session_service,
            config,
        }
    }

    /// Hash a password using Argon2
    pub fn hash_password(&self, password: &str) -> Result<String, AuthError> {
        let salt = SaltString::generate(&mut OsRng);

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                self.config.password.argon2_memory_cost,
                self.config.password.argon2_time_cost,
                self.config.password.argon2_parallelism,
                None,
            )
            .map_err(|e| AuthError::PasswordHashError(e.to_string()))?,
        );

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::PasswordHashError(e.to_string()))?
            .to_string();

        Ok(password_hash)
    }

    /// Verify a password against a hash
    pub fn verify_password(&self, password: &str, hash: &str) -> Result<bool, AuthError> {
        let parsed_hash =
            PasswordHash::new(hash).map_err(|e| AuthError::PasswordHashError(e.to_string()))?;

        let argon2 = Argon2::default();

        match argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(_) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(AuthError::PasswordHashError(e.to_string())),
        }
    }

    /// Validate password against policy
    pub fn validate_password(&self, password: &str) -> Result<(), AuthError> {
        let policy = &self.config.password;

        if password.len() < policy.min_length {
            return Err(AuthError::WeakPassword(format!(
                "Password must be at least {} characters",
                policy.min_length
            )));
        }

        if password.len() > policy.max_length {
            return Err(AuthError::WeakPassword(format!(
                "Password must be at most {} characters",
                policy.max_length
            )));
        }

        if policy.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            return Err(AuthError::WeakPassword(
                "Password must contain at least one uppercase letter".to_string(),
            ));
        }

        if policy.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            return Err(AuthError::WeakPassword(
                "Password must contain at least one lowercase letter".to_string(),
            ));
        }

        if policy.require_digit && !password.chars().any(|c| c.is_numeric()) {
            return Err(AuthError::WeakPassword(
                "Password must contain at least one digit".to_string(),
            ));
        }

        if policy.require_special && !password.chars().any(|c| !c.is_alphanumeric()) {
            return Err(AuthError::WeakPassword(
                "Password must contain at least one special character".to_string(),
            ));
        }

        Ok(())
    }

    /// Login with email and password
    pub async fn login(
        &self,
        email: &str,
        password: &str,
        session_info: CreateSession,
    ) -> Result<(User, TokenPair, Session), AuthError> {
        // Get user by email
        let user = db::get_user_by_email(&self.db, email)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?
            .ok_or_else(|| AuthError::InvalidCredentials)?;

        // Check if user has a password (not OAuth-only account)
        let password_hash = user
            .password_hash
            .as_ref()
            .ok_or_else(|| AuthError::InvalidCredentials)?;

        // Verify password
        if !self.verify_password(password, password_hash)? {
            warn!("Failed login attempt for user: {}", email);
            return Err(AuthError::InvalidCredentials);
        }

        // Check session limit
        if !self
            .session_service
            .check_session_limit(&user.id)
            .await
            .map_err(|e| AuthError::SessionError(e.to_string()))?
        {
            return Err(AuthError::MaxSessionsExceeded);
        }

        // Create session
        let session_token = SessionService::generate_token();
        let token_hash = SessionService::hash_token(&session_token);
        let session_id = uuid::Uuid::new_v4().to_string();
        let expires_at = self.session_service.get_expiration();

        let device_type = self
            .session_service
            .detect_device_type(session_info.user_agent.as_deref());

        let session = db::create_session(
            &self.db,
            &session_id,
            &user.id,
            &token_hash,
            session_info.ip_address.as_deref(),
            session_info.user_agent.as_deref(),
            Some(&device_type),
            expires_at,
        )
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Cache session
        self.session_service
            .cache_session(&session)
            .await
            .map_err(|e| AuthError::SessionError(e.to_string()))?;

        // Map token to session
        self.session_service
            .map_token_to_session(&token_hash, &session_id)
            .await
            .map_err(|e| AuthError::SessionError(e.to_string()))?;

        // Get user's organizations
        let orgs: Vec<String> = db::list_user_organizations(&self.db, &user.id)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?
            .into_iter()
            .map(|o| o.id)
            .collect();

        // Generate tokens
        let access_token = self
            .jwt_service
            .generate_access_token(
                &user.id,
                &user.email,
                user.role,
                orgs.clone(),
                Some(&session_id),
            )
            .map_err(|e| AuthError::TokenError(e.to_string()))?;

        let refresh_token = self
            .jwt_service
            .generate_refresh_token(&user.id, &user.email, user.role, orgs, Some(&session_id))
            .map_err(|e| AuthError::TokenError(e.to_string()))?;

        let token_pair = TokenPair::new(
            access_token,
            refresh_token,
            self.jwt_service.access_token_ttl_secs(),
        );

        // Update last login
        db::update_user_last_login(&self.db, &user.id)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        info!("User logged in: {}", user.email);

        Ok((user, token_pair, session))
    }

    /// Logout (invalidate session)
    pub async fn logout(&self, session_id: &str, user_id: &str) -> Result<(), AuthError> {
        // Invalidate session in database
        db::invalidate_session(&self.db, session_id)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Invalidate session in cache
        self.session_service
            .invalidate_session(session_id, user_id)
            .await
            .map_err(|e| AuthError::SessionError(e.to_string()))?;

        info!("User session invalidated: {}", session_id);

        Ok(())
    }

    /// Logout all sessions for a user
    pub async fn logout_all(&self, user_id: &str) -> Result<u64, AuthError> {
        // Invalidate all sessions in database
        let count = db::invalidate_user_sessions(&self.db, user_id)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Invalidate all sessions in cache
        self.session_service
            .invalidate_user_sessions(user_id)
            .await
            .map_err(|e| AuthError::SessionError(e.to_string()))?;

        info!("All sessions invalidated for user: {}", user_id);

        Ok(count)
    }

    /// Refresh access token using refresh token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenPair, AuthError> {
        // Validate refresh token
        let claims = self
            .jwt_service
            .validate_refresh_token(refresh_token)
            .map_err(|e| AuthError::TokenError(e.to_string()))?;

        // Get user
        let user = db::get_user_by_id(&self.db, &claims.sub)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?
            .ok_or_else(|| AuthError::UserNotFound)?;

        // Check if session is still valid (if session ID in token)
        if let Some(session_id) = &claims.sid {
            let session = self
                .session_service
                .get_cached_session(session_id)
                .await
                .map_err(|e| AuthError::SessionError(e.to_string()))?;

            if session.is_none() {
                return Err(AuthError::SessionExpired);
            }
        }

        // Get user's organizations
        let orgs: Vec<String> = db::list_user_organizations(&self.db, &user.id)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?
            .into_iter()
            .map(|o| o.id)
            .collect();

        // Generate new tokens
        let access_token = self
            .jwt_service
            .generate_access_token(
                &user.id,
                &user.email,
                user.role,
                orgs.clone(),
                claims.sid.as_deref(),
            )
            .map_err(|e| AuthError::TokenError(e.to_string()))?;

        let new_refresh_token = self
            .jwt_service
            .generate_refresh_token(
                &user.id,
                &user.email,
                user.role,
                orgs,
                claims.sid.as_deref(),
            )
            .map_err(|e| AuthError::TokenError(e.to_string()))?;

        let token_pair = TokenPair::new(
            access_token,
            new_refresh_token,
            self.jwt_service.access_token_ttl_secs(),
        );

        Ok(token_pair)
    }

    /// Validate access token and return user
    pub async fn validate_token(&self, access_token: &str) -> Result<(User, Session), AuthError> {
        // Validate token
        let claims = self
            .jwt_service
            .validate_access_token(access_token)
            .map_err(|e| AuthError::TokenError(e.to_string()))?;

        // Get user
        let user = db::get_user_by_id(&self.db, &claims.sub)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?
            .ok_or_else(|| AuthError::UserNotFound)?;

        // Get session if session ID in token
        let session = if let Some(session_id) = &claims.sid {
            let cached = self
                .session_service
                .get_cached_session(session_id)
                .await
                .map_err(|e| AuthError::SessionError(e.to_string()))?
                .ok_or_else(|| AuthError::SessionExpired)?;

            // Touch session to update last active time
            self.session_service
                .touch_session(session_id)
                .await
                .map_err(|e| AuthError::SessionError(e.to_string()))?;

            Session {
                id: cached.id,
                user_id: cached.user_id,
                token_hash: String::new(), // Don't expose
                ip_address: cached.ip_address,
                user_agent: cached.user_agent,
                device_type: cached.device_type,
                active: true,
                expires_at: chrono::DateTime::from_timestamp(cached.expires_at, 0)
                    .unwrap_or_else(chrono::Utc::now),
                created_at: chrono::DateTime::from_timestamp(cached.created_at, 0)
                    .unwrap_or_else(chrono::Utc::now),
                last_active_at: chrono::DateTime::from_timestamp(cached.last_active_at, 0)
                    .unwrap_or_else(chrono::Utc::now),
            }
        } else {
            // Create a minimal session object for stateless tokens
            Session {
                id: String::new(),
                user_id: user.id.clone(),
                token_hash: String::new(),
                ip_address: None,
                user_agent: None,
                device_type: None,
                active: true,
                expires_at: chrono::DateTime::from_timestamp(claims.exp, 0)
                    .unwrap_or_else(chrono::Utc::now),
                created_at: chrono::DateTime::from_timestamp(claims.iat, 0)
                    .unwrap_or_else(chrono::Utc::now),
                last_active_at: chrono::Utc::now(),
            }
        };

        Ok((user, session))
    }

    /// Change user password
    pub async fn change_password(
        &self,
        user_id: &str,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), AuthError> {
        // Get user
        let user = db::get_user_by_id(&self.db, user_id)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?
            .ok_or_else(|| AuthError::UserNotFound)?;

        // Verify current password
        let current_hash = user
            .password_hash
            .as_ref()
            .ok_or_else(|| AuthError::InvalidCredentials)?;

        if !self.verify_password(current_password, current_hash)? {
            return Err(AuthError::InvalidCredentials);
        }

        // Validate new password
        self.validate_password(new_password)?;

        // Hash new password
        let new_hash = self.hash_password(new_password)?;

        // Update password
        db::update_user_password(&self.db, user_id, &new_hash)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Invalidate all sessions except current
        self.logout_all(user_id).await?;

        info!("Password changed for user: {}", user_id);

        Ok(())
    }
}

/// Authentication errors
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("User not found")]
    UserNotFound,

    #[error("Session expired")]
    SessionExpired,

    #[error("Maximum sessions exceeded")]
    MaxSessionsExceeded,

    #[error("Weak password: {0}")]
    WeakPassword(String),

    #[error("Password hash error: {0}")]
    PasswordHashError(String),

    #[error("Token error: {0}")]
    TokenError(String),

    #[error("Session error: {0}")]
    SessionError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),
}

impl From<AuthError> for tonic::Status {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::InvalidCredentials => {
                tonic::Status::unauthenticated("Invalid email or password")
            }
            AuthError::UserNotFound => tonic::Status::not_found("User not found"),
            AuthError::SessionExpired => tonic::Status::unauthenticated("Session expired"),
            AuthError::MaxSessionsExceeded => tonic::Status::resource_exhausted(
                "Maximum sessions exceeded. Please logout from another device.",
            ),
            AuthError::WeakPassword(msg) => tonic::Status::invalid_argument(msg),
            AuthError::PasswordHashError(msg) => {
                tonic::Status::internal(format!("Password processing error: {}", msg))
            }
            AuthError::TokenError(msg) => tonic::Status::unauthenticated(msg),
            AuthError::SessionError(msg) => tonic::Status::internal(msg),
            AuthError::DatabaseError(msg) => tonic::Status::internal(msg),
        }
    }
}
