//! Error types for PistonProtection services
//!
//! This module provides a unified error handling system for all PistonProtection
//! services, with automatic conversion to gRPC status codes and support for
//! error context and chaining.

use std::fmt::Display;
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

    /// Create a timeout error
    pub fn timeout<S: Into<String>>(msg: S) -> Self {
        Error::Timeout(msg.into())
    }

    /// Create a rate limited error
    pub fn rate_limited<S: Into<String>>(msg: S) -> Self {
        Error::RateLimited(msg.into())
    }

    /// Create an external service error
    pub fn external_service<S: Into<String>, M: Into<String>>(service: S, message: M) -> Self {
        Error::ExternalService {
            service: service.into(),
            message: message.into(),
        }
    }

    /// Create an invalid input error
    pub fn invalid_input<S: Into<String>>(msg: S) -> Self {
        Error::InvalidInput(msg.into())
    }

    /// Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Error::Database(_)
                | Error::Redis(_)
                | Error::Timeout(_)
                | Error::ExternalService { .. }
                | Error::RateLimited(_)
        )
    }

    /// Check if error is a client error (4xx equivalent)
    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            Error::Validation(_)
                | Error::NotFound { .. }
                | Error::AlreadyExists { .. }
                | Error::Unauthorized(_)
                | Error::Forbidden(_)
                | Error::InvalidInput(_)
        )
    }

    /// Check if error is a server error (5xx equivalent)
    pub fn is_server_error(&self) -> bool {
        matches!(
            self,
            Error::Config(_)
                | Error::Database(_)
                | Error::Redis(_)
                | Error::Internal(_)
                | Error::ExternalService { .. }
        )
    }

    /// Get the HTTP status code equivalent
    pub fn http_status_code(&self) -> u16 {
        match self {
            Error::Validation(_) | Error::InvalidInput(_) => 400,
            Error::Unauthorized(_) => 401,
            Error::Forbidden(_) => 403,
            Error::NotFound { .. } => 404,
            Error::AlreadyExists { .. } => 409,
            Error::RateLimited(_) => 429,
            Error::Config(_) | Error::Database(_) | Error::Redis(_) | Error::Internal(_) => 500,
            Error::ExternalService { .. } => 502,
            Error::Timeout(_) => 504,
            Error::Grpc(status) => match status.code() {
                tonic::Code::InvalidArgument => 400,
                tonic::Code::Unauthenticated => 401,
                tonic::Code::PermissionDenied => 403,
                tonic::Code::NotFound => 404,
                tonic::Code::AlreadyExists => 409,
                tonic::Code::ResourceExhausted => 429,
                tonic::Code::Unavailable => 503,
                tonic::Code::DeadlineExceeded => 504,
                _ => 500,
            },
            Error::Other(_) => 500,
        }
    }

    /// Get a short error code string for logging/metrics
    pub fn error_code(&self) -> &'static str {
        match self {
            Error::Config(_) => "CONFIG_ERROR",
            Error::Database(_) => "DATABASE_ERROR",
            Error::Redis(_) => "REDIS_ERROR",
            Error::Grpc(_) => "GRPC_ERROR",
            Error::Validation(_) => "VALIDATION_ERROR",
            Error::NotFound { .. } => "NOT_FOUND",
            Error::AlreadyExists { .. } => "ALREADY_EXISTS",
            Error::Unauthorized(_) => "UNAUTHORIZED",
            Error::Forbidden(_) => "FORBIDDEN",
            Error::RateLimited(_) => "RATE_LIMITED",
            Error::Internal(_) => "INTERNAL_ERROR",
            Error::ExternalService { .. } => "EXTERNAL_SERVICE_ERROR",
            Error::InvalidInput(_) => "INVALID_INPUT",
            Error::Timeout(_) => "TIMEOUT",
            Error::Other(_) => "UNKNOWN_ERROR",
        }
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

/// Extension trait for adding context to errors
pub trait ErrorContext<T, E> {
    /// Add context to an error
    fn with_context<C, F>(self, context: F) -> Result<T>
    where
        C: Display,
        F: FnOnce() -> C;

    /// Add context to an error with a static message
    fn context<C: Display>(self, context: C) -> Result<T>;
}

impl<T, E: Into<Error>> ErrorContext<T, E> for std::result::Result<T, E> {
    fn with_context<C, F>(self, context: F) -> Result<T>
    where
        C: Display,
        F: FnOnce() -> C,
    {
        self.map_err(|e| {
            let err: Error = e.into();
            Error::Internal(format!("{}: {}", context(), err))
        })
    }

    fn context<C: Display>(self, context: C) -> Result<T> {
        self.map_err(|e| {
            let err: Error = e.into();
            Error::Internal(format!("{}: {}", context, err))
        })
    }
}

impl<T> ErrorContext<T, ()> for Option<T> {
    fn with_context<C, F>(self, context: F) -> Result<T>
    where
        C: Display,
        F: FnOnce() -> C,
    {
        self.ok_or_else(|| Error::Internal(context().to_string()))
    }

    fn context<C: Display>(self, context: C) -> Result<T> {
        self.ok_or_else(|| Error::Internal(context.to_string()))
    }
}

/// Trait for converting errors to internal errors with context
pub trait IntoInternal {
    fn into_internal(self) -> Error;
    fn internal_with_context<C: Display>(self, context: C) -> Error;
}

impl<E: std::error::Error> IntoInternal for E {
    fn into_internal(self) -> Error {
        Error::Internal(self.to_string())
    }

    fn internal_with_context<C: Display>(self, context: C) -> Error {
        Error::Internal(format!("{}: {}", context, self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = Error::not_found("User", "123");
        assert!(matches!(err, Error::NotFound { .. }));
        assert_eq!(err.error_code(), "NOT_FOUND");
        assert_eq!(err.http_status_code(), 404);
        assert!(err.is_client_error());
        assert!(!err.is_server_error());
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_validation_error() {
        let err = Error::validation("Invalid email format");
        assert!(matches!(err, Error::Validation(_)));
        assert_eq!(err.error_code(), "VALIDATION_ERROR");
        assert_eq!(err.http_status_code(), 400);
        assert!(err.is_client_error());
    }

    #[test]
    fn test_internal_error() {
        let err = Error::internal("Something went wrong");
        assert!(matches!(err, Error::Internal(_)));
        assert_eq!(err.error_code(), "INTERNAL_ERROR");
        assert_eq!(err.http_status_code(), 500);
        assert!(err.is_server_error());
    }

    #[test]
    fn test_retryable_errors() {
        let timeout = Error::timeout("Connection timed out");
        assert!(timeout.is_retryable());

        let rate_limited = Error::rate_limited("Too many requests");
        assert!(rate_limited.is_retryable());

        let external = Error::external_service("Stripe", "API error");
        assert!(external.is_retryable());

        let not_found = Error::not_found("User", "123");
        assert!(!not_found.is_retryable());
    }

    #[test]
    fn test_grpc_conversion() {
        let err = Error::not_found("Backend", "abc123");
        let status: Status = err.into();
        assert_eq!(status.code(), tonic::Code::NotFound);

        let err = Error::unauthorized("Invalid token");
        let status: Status = err.into();
        assert_eq!(status.code(), tonic::Code::Unauthenticated);

        let err = Error::validation("Invalid format");
        let status: Status = err.into();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn test_context_extension() {
        let result: std::result::Result<(), std::io::Error> =
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "file not found"));

        let with_context = result.context("Failed to read configuration");
        assert!(with_context.is_err());

        let err = with_context.unwrap_err();
        assert!(err.to_string().contains("Failed to read configuration"));
    }

    #[test]
    fn test_option_context() {
        let opt: Option<i32> = None;
        let result = opt.context("Value was missing");
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "Internal error: Value was missing");
    }
}
