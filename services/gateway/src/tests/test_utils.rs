//! Test utilities for gateway tests

use crate::services::AppState;
use pistonprotection_common::config::Config;

/// Test configuration constants
pub mod constants {
    pub const TEST_ORG_ID: &str = "test-org-123";
    pub const TEST_BACKEND_ID: &str = "test-backend-456";
    pub const TEST_FILTER_ID: &str = "test-filter-789";
    pub const TEST_USER_ID: &str = "test-user-001";
}

/// Create a minimal test app state without database connections
pub fn create_test_app_state() -> AppState {
    // Create a test config
    let config = Config {
        service_name: "gateway-test".to_string(),
        environment: "test".to_string(),
        server: Default::default(),
        database: None,
        redis: None,
        auth: None,
        telemetry: Default::default(),
        metrics: Default::default(),
    };
    AppState::new(None, None, config)
}

/// Test fixture builder for creating consistent test data
pub struct TestFixture {
    pub org_id: String,
    pub backend_id: String,
}

impl Default for TestFixture {
    fn default() -> Self {
        Self {
            org_id: constants::TEST_ORG_ID.to_string(),
            backend_id: constants::TEST_BACKEND_ID.to_string(),
        }
    }
}

impl TestFixture {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_org_id(mut self, org_id: &str) -> Self {
        self.org_id = org_id.to_string();
        self
    }

    pub fn with_backend_id(mut self, backend_id: &str) -> Self {
        self.backend_id = backend_id.to_string();
        self
    }
}

/// Helper to create test request metadata
pub fn create_test_metadata() -> tonic::metadata::MetadataMap {
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert("authorization", "Bearer test-token".parse().unwrap());
    metadata.insert("x-org-id", constants::TEST_ORG_ID.parse().unwrap());
    metadata
}

/// Helper to create test gRPC request with metadata
pub fn create_test_request<T>(inner: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(inner);
    *request.metadata_mut() = create_test_metadata();
    request
}

/// Assert helper for gRPC status codes
pub fn assert_grpc_status_code(result: &tonic::Status, expected: tonic::Code) {
    assert_eq!(
        result.code(),
        expected,
        "Expected gRPC status {:?}, got {:?}: {}",
        expected,
        result.code(),
        result.message()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixture_default() {
        let fixture = TestFixture::default();
        assert_eq!(fixture.org_id, constants::TEST_ORG_ID);
        assert_eq!(fixture.backend_id, constants::TEST_BACKEND_ID);
    }

    #[test]
    fn test_fixture_builder() {
        let fixture = TestFixture::new()
            .with_org_id("custom-org")
            .with_backend_id("custom-backend");
        assert_eq!(fixture.org_id, "custom-org");
        assert_eq!(fixture.backend_id, "custom-backend");
    }

    #[test]
    fn test_create_test_metadata() {
        let metadata = create_test_metadata();
        assert!(metadata.get("authorization").is_some());
        assert!(metadata.get("x-org-id").is_some());
    }
}
