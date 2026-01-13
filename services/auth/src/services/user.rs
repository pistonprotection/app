//! User service for user management

use sqlx::PgPool;
use std::sync::Arc;
use tracing::info;
use validator::Validate;

use crate::config::AuthConfig;
use crate::db;
use crate::models::{CreateUserRequest, UpdateUserRequest, User, UserResponse, UserRole};

/// User service
pub struct UserService {
    db: PgPool,
    config: Arc<AuthConfig>,
}

impl UserService {
    /// Create a new user service
    pub fn new(db: PgPool, config: Arc<AuthConfig>) -> Self {
        Self { db, config }
    }

    /// Create a new user
    pub async fn create_user(&self, request: CreateUserRequest) -> Result<UserResponse, UserError> {
        // Validate request
        request
            .validate()
            .map_err(|e| UserError::ValidationError(e.to_string()))?;

        // Check if email already exists
        if let Some(_) = db::get_user_by_email(&self.db, &request.email)
            .await
            .map_err(|e| UserError::DatabaseError(e.to_string()))?
        {
            return Err(UserError::EmailExists);
        }

        // Check if username already exists
        if let Some(_) = db::get_user_by_username(&self.db, &request.username)
            .await
            .map_err(|e| UserError::DatabaseError(e.to_string()))?
        {
            return Err(UserError::UsernameExists);
        }

        // Create auth service for password hashing
        // Note: In a real implementation, you might want to share the argon2 instance
        let auth_service = self.create_temp_auth_service();

        // Validate password against policy
        auth_service.validate_password(&request.password)?;

        // Hash password
        let password_hash = auth_service.hash_password(&request.password)?;

        // Generate ID
        let id = uuid::Uuid::new_v4().to_string();

        // Create user
        let user = db::create_user(
            &self.db,
            &id,
            &request.email,
            &request.username,
            &request.name,
            Some(&password_hash),
            request.avatar_url.as_deref(),
        )
        .await
        .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        info!("User created: {} ({})", user.id, user.email);

        Ok(UserResponse::from(user))
    }

    /// Get user by ID
    pub async fn get_user(&self, user_id: &str) -> Result<Option<UserResponse>, UserError> {
        let user = db::get_user_by_id(&self.db, user_id)
            .await
            .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        Ok(user.map(UserResponse::from))
    }

    /// Get user by email
    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<UserResponse>, UserError> {
        let user = db::get_user_by_email(&self.db, email)
            .await
            .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        Ok(user.map(UserResponse::from))
    }

    /// Get full user (internal use, includes password hash)
    pub async fn get_user_internal(&self, user_id: &str) -> Result<Option<User>, UserError> {
        db::get_user_by_id(&self.db, user_id)
            .await
            .map_err(|e| UserError::DatabaseError(e.to_string()))
    }

    /// Update user
    pub async fn update_user(
        &self,
        user_id: &str,
        request: UpdateUserRequest,
    ) -> Result<UserResponse, UserError> {
        // Validate request
        request
            .validate()
            .map_err(|e| UserError::ValidationError(e.to_string()))?;

        // Check if user exists
        let existing = db::get_user_by_id(&self.db, user_id)
            .await
            .map_err(|e| UserError::DatabaseError(e.to_string()))?
            .ok_or(UserError::NotFound)?;

        // Check email uniqueness if changing
        if let Some(ref email) = request.email {
            if email != &existing.email {
                if let Some(_) = db::get_user_by_email(&self.db, email)
                    .await
                    .map_err(|e| UserError::DatabaseError(e.to_string()))?
                {
                    return Err(UserError::EmailExists);
                }
            }
        }

        // Check username uniqueness if changing
        if let Some(ref username) = request.username {
            if username != &existing.username {
                if let Some(_) = db::get_user_by_username(&self.db, username)
                    .await
                    .map_err(|e| UserError::DatabaseError(e.to_string()))?
                {
                    return Err(UserError::UsernameExists);
                }
            }
        }

        // Update user
        let user = db::update_user(
            &self.db,
            user_id,
            request.email.as_deref(),
            request.username.as_deref(),
            request.name.as_deref(),
            request.avatar_url.as_deref(),
            request.role,
        )
        .await
        .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        info!("User updated: {}", user.id);

        Ok(UserResponse::from(user))
    }

    /// Delete user
    pub async fn delete_user(&self, user_id: &str) -> Result<bool, UserError> {
        let deleted = db::delete_user(&self.db, user_id)
            .await
            .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        if deleted {
            info!("User deleted: {}", user_id);
        }

        Ok(deleted)
    }

    /// List users with pagination
    pub async fn list_users(
        &self,
        page: u32,
        page_size: u32,
    ) -> Result<(Vec<UserResponse>, u32), UserError> {
        let (users, total) = db::list_users(&self.db, page, page_size)
            .await
            .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        Ok((users.into_iter().map(UserResponse::from).collect(), total))
    }

    /// Verify user email
    pub async fn verify_email(&self, user_id: &str) -> Result<(), UserError> {
        db::verify_user_email(&self.db, user_id)
            .await
            .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        info!("Email verified for user: {}", user_id);

        Ok(())
    }

    /// Update user role (admin only)
    pub async fn update_role(
        &self,
        user_id: &str,
        role: UserRole,
    ) -> Result<UserResponse, UserError> {
        let user = db::update_user(&self.db, user_id, None, None, None, None, Some(role))
            .await
            .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        info!("User role updated: {} -> {:?}", user_id, role);

        Ok(UserResponse::from(user))
    }

    /// Helper to create a temporary auth service for password operations
    fn create_temp_auth_service(&self) -> TempAuthService {
        TempAuthService {
            config: self.config.clone(),
        }
    }
}

/// Temporary auth service wrapper for password operations
struct TempAuthService {
    config: Arc<AuthConfig>,
}

impl TempAuthService {
    fn validate_password(&self, password: &str) -> Result<(), UserError> {
        let policy = &self.config.password;

        if password.len() < policy.min_length {
            return Err(UserError::WeakPassword(format!(
                "Password must be at least {} characters",
                policy.min_length
            )));
        }

        if password.len() > policy.max_length {
            return Err(UserError::WeakPassword(format!(
                "Password must be at most {} characters",
                policy.max_length
            )));
        }

        if policy.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            return Err(UserError::WeakPassword(
                "Password must contain at least one uppercase letter".to_string(),
            ));
        }

        if policy.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            return Err(UserError::WeakPassword(
                "Password must contain at least one lowercase letter".to_string(),
            ));
        }

        if policy.require_digit && !password.chars().any(|c| c.is_numeric()) {
            return Err(UserError::WeakPassword(
                "Password must contain at least one digit".to_string(),
            ));
        }

        if policy.require_special && !password.chars().any(|c| !c.is_alphanumeric()) {
            return Err(UserError::WeakPassword(
                "Password must contain at least one special character".to_string(),
            ));
        }

        Ok(())
    }

    fn hash_password(&self, password: &str) -> Result<String, UserError> {
        use argon2::{
            Argon2,
            password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
        };

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
            .map_err(|e| UserError::PasswordError(e.to_string()))?,
        );

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| UserError::PasswordError(e.to_string()))?
            .to_string();

        Ok(password_hash)
    }
}

/// User service errors
#[derive(Debug, thiserror::Error)]
pub enum UserError {
    #[error("User not found")]
    NotFound,

    #[error("Email already exists")]
    EmailExists,

    #[error("Username already exists")]
    UsernameExists,

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Weak password: {0}")]
    WeakPassword(String),

    #[error("Password error: {0}")]
    PasswordError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),
}

impl From<UserError> for tonic::Status {
    fn from(err: UserError) -> Self {
        match err {
            UserError::NotFound => tonic::Status::not_found("User not found"),
            UserError::EmailExists => tonic::Status::already_exists("Email already in use"),
            UserError::UsernameExists => tonic::Status::already_exists("Username already taken"),
            UserError::ValidationError(msg) => tonic::Status::invalid_argument(msg),
            UserError::WeakPassword(msg) => tonic::Status::invalid_argument(msg),
            UserError::PasswordError(msg) => tonic::Status::internal(msg),
            UserError::DatabaseError(msg) => tonic::Status::internal(msg),
        }
    }
}

// Implement From for auth errors
impl From<crate::services::auth::AuthError> for UserError {
    fn from(err: crate::services::auth::AuthError) -> Self {
        match err {
            crate::services::auth::AuthError::WeakPassword(msg) => UserError::WeakPassword(msg),
            crate::services::auth::AuthError::PasswordHashError(msg) => {
                UserError::PasswordError(msg)
            }
            _ => UserError::PasswordError(err.to_string()),
        }
    }
}
