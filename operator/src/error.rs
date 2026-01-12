//! Operator error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Kubernetes API error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Invalid resource: {0}")]
    InvalidResource(String),

    #[error("Reconciliation failed: {0}")]
    ReconciliationFailed(String),
}

impl Error {
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Error::KubeError(_) | Error::ReconciliationFailed(_)
        )
    }
}
