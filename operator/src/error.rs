//! Error types for the PistonProtection Operator
//!
//! This module defines comprehensive error types with proper categorization
//! for retry logic and status reporting.

use std::time::Duration;
use thiserror::Error;

/// Result type alias for operator operations
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for the operator
#[derive(Error, Debug)]
pub enum Error {
    // ========================================================================
    // Kubernetes API Errors
    // ========================================================================
    /// Error communicating with the Kubernetes API
    #[error("Kubernetes API error: {0}")]
    KubeError(#[from] kube::Error),

    /// Error watching Kubernetes resources
    #[error("Kubernetes watch error: {0}")]
    WatchError(String),

    /// Error applying server-side patch
    #[error("Patch error: {0}")]
    PatchError(String),

    /// Error with finalizer operations
    #[error("Finalizer error: {0}")]
    FinalizerError(String),

    // ========================================================================
    // Resource Errors
    // ========================================================================
    /// Resource not found
    #[error("Resource not found: {kind}/{namespace}/{name}")]
    NotFound {
        kind: String,
        namespace: String,
        name: String,
    },

    /// Invalid resource configuration
    #[error("Invalid resource: {0}")]
    InvalidResource(String),

    /// Resource validation failed
    #[error("Validation error: {field}: {message}")]
    ValidationError { field: String, message: String },

    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// Resource already exists
    #[error("Resource already exists: {0}")]
    AlreadyExists(String),

    /// Conflict during update
    #[error("Resource conflict: {0}")]
    Conflict(String),

    // ========================================================================
    // gRPC/Gateway Errors
    // ========================================================================
    /// Error connecting to gRPC service
    #[error("gRPC connection error: {0}")]
    GrpcConnectionError(String),

    /// gRPC request failed
    #[error("gRPC request error: {0}")]
    GrpcRequestError(String),

    /// gRPC response error
    #[error("gRPC response error (code={code}): {message}")]
    GrpcStatusError { code: i32, message: String },

    /// Gateway sync failed
    #[error("Gateway sync failed: {0}")]
    GatewaySyncError(String),

    /// Gateway health check failed
    #[error("Gateway health check failed: {0}")]
    GatewayHealthError(String),

    // ========================================================================
    // Reconciliation Errors
    // ========================================================================
    /// General reconciliation failure
    #[error("Reconciliation failed: {0}")]
    ReconciliationFailed(String),

    /// Reconciliation timeout
    #[error("Reconciliation timeout after {0:?}")]
    ReconciliationTimeout(Duration),

    /// Dependency not ready
    #[error("Dependency not ready: {0}")]
    DependencyNotReady(String),

    /// Worker deployment failed
    #[error("Worker deployment failed: {0}")]
    DeploymentError(String),

    // ========================================================================
    // Configuration Errors
    // ========================================================================
    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Environment variable error
    #[error("Environment error: {0}")]
    EnvError(String),

    // ========================================================================
    // Serialization Errors
    // ========================================================================
    /// JSON serialization error
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// YAML serialization error
    #[error("YAML error: {0}")]
    YamlError(#[from] serde_yaml::Error),

    // ========================================================================
    // Internal Errors
    // ========================================================================
    /// Internal error (should not happen in normal operation)
    #[error("Internal error: {0}")]
    InternalError(String),

    /// Leader election error
    #[error("Leader election error: {0}")]
    LeaderElectionError(String),

    /// Metrics error
    #[error("Metrics error: {0}")]
    MetricsError(String),

    /// Permanent error that should not be retried
    #[error("Permanent error: {0}")]
    Permanent(String),
}

impl Error {
    /// Check if this error is retryable
    ///
    /// Returns true for transient errors that may succeed on retry
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Error::KubeError(_)
                | Error::WatchError(_)
                | Error::GrpcConnectionError(_)
                | Error::GrpcRequestError(_)
                | Error::GatewaySyncError(_)
                | Error::ReconciliationFailed(_)
                | Error::ReconciliationTimeout(_)
                | Error::DependencyNotReady(_)
                | Error::Conflict(_)
        )
    }

    /// Check if this is a permanent error that should not be retried
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            Error::InvalidResource(_)
                | Error::ValidationError { .. }
                | Error::MissingField(_)
                | Error::ConfigError(_)
                | Error::Permanent(_)
        )
    }

    /// Get the recommended retry delay for this error
    pub fn retry_delay(&self) -> Duration {
        match self {
            // Fast retry for transient errors
            Error::GrpcConnectionError(_) => Duration::from_millis(500),
            Error::GrpcRequestError(_) => Duration::from_secs(1),

            // Medium delay for API errors
            Error::KubeError(_) => Duration::from_secs(5),
            Error::Conflict(_) => Duration::from_secs(2),

            // Longer delay for dependency issues
            Error::DependencyNotReady(_) => Duration::from_secs(15),
            Error::DeploymentError(_) => Duration::from_secs(30),

            // Default retry delay
            _ => Duration::from_secs(10),
        }
    }

    /// Convert error to a status message for CRD status updates
    pub fn to_status_message(&self) -> String {
        match self {
            Error::NotFound {
                kind,
                namespace,
                name,
            } => {
                format!("Required {} {}/{} not found", kind, namespace, name)
            }
            Error::ValidationError { field, message } => {
                format!("Validation failed for {}: {}", field, message)
            }
            Error::GrpcConnectionError(_) => "Unable to connect to gateway service".to_string(),
            Error::GatewaySyncError(msg) => format!("Failed to sync with gateway: {}", msg),
            Error::DependencyNotReady(dep) => format!("Waiting for dependency: {}", dep),
            Error::DeploymentError(msg) => format!("Worker deployment failed: {}", msg),
            _ => self.to_string(),
        }
    }

    /// Get the error category for metrics
    pub fn category(&self) -> &'static str {
        match self {
            Error::KubeError(_)
            | Error::WatchError(_)
            | Error::PatchError(_)
            | Error::FinalizerError(_) => "kubernetes",

            Error::NotFound { .. }
            | Error::InvalidResource(_)
            | Error::ValidationError { .. }
            | Error::MissingField(_)
            | Error::AlreadyExists(_)
            | Error::Conflict(_) => "resource",

            Error::GrpcConnectionError(_)
            | Error::GrpcRequestError(_)
            | Error::GrpcStatusError { .. }
            | Error::GatewaySyncError(_)
            | Error::GatewayHealthError(_) => "grpc",

            Error::ReconciliationFailed(_)
            | Error::ReconciliationTimeout(_)
            | Error::DependencyNotReady(_)
            | Error::DeploymentError(_) => "reconciliation",

            Error::ConfigError(_) | Error::EnvError(_) => "configuration",

            Error::JsonError(_) | Error::YamlError(_) => "serialization",

            Error::InternalError(_)
            | Error::LeaderElectionError(_)
            | Error::MetricsError(_)
            | Error::Permanent(_) => "internal",
        }
    }

    /// Create a not found error
    pub fn not_found(kind: &str, namespace: &str, name: &str) -> Self {
        Error::NotFound {
            kind: kind.to_string(),
            namespace: namespace.to_string(),
            name: name.to_string(),
        }
    }

    /// Create a validation error
    pub fn validation(field: &str, message: &str) -> Self {
        Error::ValidationError {
            field: field.to_string(),
            message: message.to_string(),
        }
    }

    /// Create a gRPC status error from tonic Status
    pub fn from_grpc_status(status: tonic::Status) -> Self {
        Error::GrpcStatusError {
            code: status.code() as i32,
            message: status.message().to_string(),
        }
    }
}

/// Extension trait for converting various errors to operator errors
pub trait ResultExt<T> {
    /// Convert to operator Result with context
    fn with_context<F: FnOnce() -> String>(self, f: F) -> Result<T>;
}

impl<T, E: std::error::Error + 'static> ResultExt<T> for std::result::Result<T, E> {
    fn with_context<F: FnOnce() -> String>(self, f: F) -> Result<T> {
        self.map_err(|e| Error::InternalError(format!("{}: {}", f(), e)))
    }
}

/// Action to take after an error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorAction {
    /// Requeue for retry after specified duration
    Requeue(Duration),
    /// Don't requeue, error is permanent
    NoRequeue,
    /// Skip this reconciliation cycle
    Skip,
}

impl From<&Error> for ErrorAction {
    fn from(error: &Error) -> Self {
        if error.is_permanent() {
            ErrorAction::NoRequeue
        } else {
            ErrorAction::Requeue(error.retry_delay())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_retryable() {
        assert!(Error::GrpcConnectionError("test".into()).is_retryable());
        assert!(
            Error::KubeError(kube::Error::Api(Box::new(kube::core::Status {
                status: None,
                message: String::new(),
                reason: String::new(),
                code: 500,
                metadata: None,
                details: None,
            })))
            .is_retryable()
        );

        assert!(!Error::InvalidResource("test".into()).is_retryable());
        assert!(!Error::MissingField("test".into()).is_retryable());
    }

    #[test]
    fn test_error_permanent() {
        assert!(Error::InvalidResource("test".into()).is_permanent());
        assert!(Error::ValidationError {
            field: "test".into(),
            message: "invalid".into(),
        }
        .is_permanent());

        assert!(!Error::GrpcConnectionError("test".into()).is_permanent());
    }

    #[test]
    fn test_error_category() {
        assert_eq!(
            Error::KubeError(kube::Error::Api(Box::new(kube::core::Status {
                status: None,
                message: String::new(),
                reason: String::new(),
                code: 500,
                metadata: None,
                details: None,
            })))
            .category(),
            "kubernetes"
        );

        assert_eq!(Error::GrpcConnectionError("test".into()).category(), "grpc");
        assert_eq!(Error::InvalidResource("test".into()).category(), "resource");
    }

    #[test]
    fn test_error_action() {
        let err = Error::GrpcConnectionError("test".into());
        let action: ErrorAction = (&err).into();
        assert!(matches!(action, ErrorAction::Requeue(_)));

        let err = Error::InvalidResource("test".into());
        let action: ErrorAction = (&err).into();
        assert_eq!(action, ErrorAction::NoRequeue);
    }

    #[test]
    fn test_not_found_constructor() {
        let err = Error::not_found("DDoSProtection", "default", "my-protection");
        assert!(matches!(err, Error::NotFound { .. }));
        assert_eq!(
            err.to_string(),
            "Resource not found: DDoSProtection/default/my-protection"
        );
    }
}
