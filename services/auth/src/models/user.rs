//! User model definitions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use validator::Validate;

/// User role enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
#[derive(Default)]
pub enum UserRole {
    #[default]
    User,
    Admin,
}

impl From<UserRole> for i32 {
    fn from(role: UserRole) -> Self {
        match role {
            UserRole::User => 1,
            UserRole::Admin => 2,
        }
    }
}

impl TryFrom<i32> for UserRole {
    type Error = &'static str;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(UserRole::User),
            2 => Ok(UserRole::Admin),
            _ => Err("Invalid user role"),
        }
    }
}

/// User account model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: String,
    pub email: String,
    pub username: String,
    pub name: String,
    pub avatar_url: Option<String>,
    pub password_hash: Option<String>,
    pub email_verified: bool,
    pub two_factor_enabled: bool,
    pub two_factor_secret: Option<String>,
    pub role: UserRole,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// User for external responses (no sensitive data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub username: String,
    pub name: String,
    pub avatar_url: Option<String>,
    pub email_verified: bool,
    pub two_factor_enabled: bool,
    pub role: UserRole,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            username: user.username,
            name: user.name,
            avatar_url: user.avatar_url,
            email_verified: user.email_verified,
            two_factor_enabled: user.two_factor_enabled,
            role: user.role,
            created_at: user.created_at,
            updated_at: user.updated_at,
            last_login_at: user.last_login_at,
        }
    }
}

/// Request to create a new user
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateUserRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: String,

    #[validate(length(min = 3, max = 50, message = "Username must be 3-50 characters"))]
    #[validate(custom(function = "validate_username"))]
    pub username: String,

    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))]
    pub name: String,

    #[validate(length(min = 8, max = 128, message = "Password must be 8-128 characters"))]
    pub password: String,

    pub avatar_url: Option<String>,
}

/// Request to update an existing user
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateUserRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: Option<String>,

    #[validate(length(min = 3, max = 50, message = "Username must be 3-50 characters"))]
    pub username: Option<String>,

    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))]
    pub name: Option<String>,

    pub avatar_url: Option<String>,

    pub role: Option<UserRole>,
}

/// Validate username format
fn validate_username(username: &str) -> Result<(), validator::ValidationError> {
    // Username must start with a letter
    if !username
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic())
    {
        return Err(validator::ValidationError::new("username_start_letter"));
    }

    // Username can only contain alphanumeric characters, underscores, and hyphens
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(validator::ValidationError::new("username_invalid_chars"));
    }

    Ok(())
}

/// User with OAuth provider information
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserOAuthProvider {
    pub id: String,
    pub user_id: String,
    pub provider: String,
    pub provider_user_id: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Convert to proto User
impl User {
    pub fn to_proto(&self) -> pistonprotection_proto::auth::User {
        use pistonprotection_proto::Timestamp;
        use pistonprotection_proto::auth;

        auth::User {
            id: self.id.clone(),
            email: self.email.clone(),
            username: self.username.clone(),
            name: self.name.clone(),
            avatar_url: self.avatar_url.clone().unwrap_or_default(),
            email_verified: self.email_verified,
            two_factor_enabled: self.two_factor_enabled,
            role: match self.role {
                UserRole::User => auth::UserRole::User as i32,
                UserRole::Admin => auth::UserRole::Admin as i32,
            },
            created_at: Some(Timestamp::from(self.created_at)),
            updated_at: Some(Timestamp::from(self.updated_at)),
            last_login_at: self.last_login_at.map(Timestamp::from),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_role_conversion() {
        assert_eq!(i32::from(UserRole::User), 1);
        assert_eq!(i32::from(UserRole::Admin), 2);
        assert_eq!(UserRole::try_from(1).unwrap(), UserRole::User);
        assert_eq!(UserRole::try_from(2).unwrap(), UserRole::Admin);
    }

    #[test]
    fn test_validate_username() {
        assert!(validate_username("john_doe").is_ok());
        assert!(validate_username("john-doe").is_ok());
        assert!(validate_username("JohnDoe123").is_ok());
        assert!(validate_username("123john").is_err()); // starts with number
        assert!(validate_username("john@doe").is_err()); // invalid char
    }
}
