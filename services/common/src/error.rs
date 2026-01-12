//! Error types for PistonProtection services

use thiserror::Error;
use tonic::Status;

/// Result type alias using our Error type
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for PistonProtection services
#[derive(Debug, Error)]
pub enum Error {
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("gRPC error: {0}")]
    Grpc(#[from] tonic::Status),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Not found: {entity} with id {id}")]
    NotFound { entity: String, id: String },

    #[error("Already exists: {entity} with {field} = {value}")]
    AlreadyExists {
        entity: String,
        field: String,
        value: String,
    },

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Rate limited: {0}")]
    RateLimited(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("External service error: {service} - {message}")]
    ExternalService { service: String, message: String },

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl Error {
    /// Create a validation error
    pub fn validation<S: Into<String>>(msg: S) -> Self {
        Error::Validation(msg.into())
    }

    /// Create a not found error
    pub fn not_found<E: Into<String>, I: Into<String>>(entity: E, id: I) -> Self {
        Error::NotFound {
            entity: entity.into(),
            id: id.into(),
        }
    }

    /// Create an already exists error
    pub fn already_exists<E: Into<String>, F: Into<String>, V: Into<String>>(
        entity: E,
        field: F,
        value: V,
    ) -> Self {
        Error::AlreadyExists {
            entity: entity.into(),
            field: field.into(),
            value: value.into(),
        }
    }

    /// Create an unauthorized error
    pub fn unauthorized<S: Into<String>>(msg: S) -> Self {
        Error::Unauthorized(msg.into())
    }

    /// Create a forbidden error
    pub fn forbidden<S: Into<String>>(msg: S) -> Self {
        Error::Forbidden(msg.into())
    }

    /// Create an internal error
    pub fn internal<S: Into<String>>(msg: S) -> Self {
        Error::Internal(msg.into())
    }
}

impl From<Error> for Status {
    fn from(err: Error) -> Self {
        match err {
            Error::Config(e) => Status::internal(format!("Configuration error: {}", e)),
            Error::Database(e) => Status::internal(format!("Database error: {}", e)),
            Error::Redis(e) => Status::internal(format!("Cache error: {}", e)),
            Error::Grpc(s) => s,
            Error::Validation(msg) => Status::invalid_argument(msg),
            Error::NotFound { entity, id } => {
                Status::not_found(format!("{} with id {} not found", entity, id))
            }
            Error::AlreadyExists {
                entity,
                field,
                value,
            } => Status::already_exists(format!(
                "{} with {} = {} already exists",
                entity, field, value
            )),
            Error::Unauthorized(msg) => Status::unauthenticated(msg),
            Error::Forbidden(msg) => Status::permission_denied(msg),
            Error::RateLimited(msg) => Status::resource_exhausted(msg),
            Error::Internal(msg) => Status::internal(msg),
            Error::ExternalService { service, message } => {
                Status::unavailable(format!("{} service error: {}", service, message))
            }
            Error::InvalidInput(msg) => Status::invalid_argument(msg),
            Error::Timeout(msg) => Status::deadline_exceeded(msg),
            Error::Other(e) => Status::internal(format!("Internal error: {}", e)),
        }
    }
}

impl From<validator::ValidationErrors> for Error {
    fn from(err: validator::ValidationErrors) -> Self {
        Error::Validation(err.to_string())
    }
}

/// Extension trait for Result types
pub trait ResultExt<T> {
    /// Convert error to gRPC status
    fn map_grpc_err(self) -> std::result::Result<T, Status>;
}

impl<T> ResultExt<T> for Result<T> {
    fn map_grpc_err(self) -> std::result::Result<T, Status> {
        self.map_err(|e| e.into())
    }
}
