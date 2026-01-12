//! gRPC client tests

use super::test_utils::{constants, create_test_ddos_protection, create_test_filter_rule};
use crate::crd::{DDoSProtection, FilterRule, Protocol};
use std::time::Duration;

/// Mock gRPC client for testing
struct MockGatewayClient {
    connected: bool,
    backends: Vec<MockBackend>,
    filter_rules: Vec<MockFilterRule>,
    should_fail_connect: bool,
    should_fail_sync: bool,
}

#[derive(Clone, Debug)]
struct MockBackend {
    id: String,
    name: String,
    address: String,
    protocol: i32,
}

#[derive(Clone, Debug)]
struct MockFilterRule {
    id: String,
    backend_id: String,
    name: String,
    priority: i32,
    enabled: bool,
}

impl MockGatewayClient {
    fn new() -> Self {
        Self {
            connected: false,
            backends: Vec::new(),
            filter_rules: Vec::new(),
            should_fail_connect: false,
            should_fail_sync: false,
        }
    }

    fn set_fail_connect(&mut self, fail: bool) {
        self.should_fail_connect = fail;
    }

    fn set_fail_sync(&mut self, fail: bool) {
        self.should_fail_sync = fail;
    }

    async fn connect(&mut self, _address: &str) -> Result<(), String> {
        if self.should_fail_connect {
            return Err("Connection failed".to_string());
        }
        self.connected = true;
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<(), String> {
        self.connected = false;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    async fn sync_backend(
        &mut self,
        org_id: &str,
        backend: &MockBackend,
    ) -> Result<String, String> {
        if !self.connected {
            return Err("Not connected".to_string());
        }
        if self.should_fail_sync {
            return Err("Sync failed".to_string());
        }

        // Check if backend exists
        if let Some(existing) = self.backends.iter_mut().find(|b| b.id == backend.id) {
            *existing = backend.clone();
        } else {
            self.backends.push(backend.clone());
        }

        Ok(backend.id.clone())
    }

    async fn delete_backend(&mut self, backend_id: &str) -> Result<(), String> {
        if !self.connected {
            return Err("Not connected".to_string());
        }

        self.backends.retain(|b| b.id != backend_id);
        Ok(())
    }

    async fn sync_filter_rule(
        &mut self,
        backend_id: &str,
        rule: &MockFilterRule,
    ) -> Result<String, String> {
        if !self.connected {
            return Err("Not connected".to_string());
        }
        if self.should_fail_sync {
            return Err("Sync failed".to_string());
        }

        let mut rule = rule.clone();
        rule.backend_id = backend_id.to_string();
        let rule_id = rule.id.clone();

        if let Some(existing) = self.filter_rules.iter_mut().find(|r| r.id == rule.id) {
            *existing = rule;
        } else {
            self.filter_rules.push(rule);
        }

        Ok(rule_id)
    }

    async fn delete_filter_rule(&mut self, rule_id: &str) -> Result<(), String> {
        if !self.connected {
            return Err("Not connected".to_string());
        }

        self.filter_rules.retain(|r| r.id != rule_id);
        Ok(())
    }

    async fn health_check(&self) -> Result<bool, String> {
        if !self.connected {
            return Err("Not connected".to_string());
        }
        Ok(true)
    }

    fn list_backends(&self) -> &[MockBackend] {
        &self.backends
    }

    fn list_filter_rules(&self, backend_id: &str) -> Vec<&MockFilterRule> {
        self.filter_rules
            .iter()
            .filter(|r| r.backend_id == backend_id)
            .collect()
    }
}

// ============================================================================
// Connection Tests
// ============================================================================

#[cfg(test)]
mod connection_tests {
    use super::*;

    /// Test successful connection
    #[tokio::test]
    async fn test_connect_success() {
        let mut client = MockGatewayClient::new();

        let result = client.connect(constants::TEST_GATEWAY_ADDRESS).await;

        assert!(result.is_ok());
        assert!(client.is_connected());
    }

    /// Test connection failure
    #[tokio::test]
    async fn test_connect_failure() {
        let mut client = MockGatewayClient::new();
        client.set_fail_connect(true);

        let result = client.connect(constants::TEST_GATEWAY_ADDRESS).await;

        assert!(result.is_err());
        assert!(!client.is_connected());
    }

    /// Test disconnect
    #[tokio::test]
    async fn test_disconnect() {
        let mut client = MockGatewayClient::new();
        client.connect(constants::TEST_GATEWAY_ADDRESS).await.unwrap();

        let result = client.disconnect().await;

        assert!(result.is_ok());
        assert!(!client.is_connected());
    }

    /// Test reconnection
    #[tokio::test]
    async fn test_reconnect() {
        let mut client = MockGatewayClient::new();

        client.connect(constants::TEST_GATEWAY_ADDRESS).await.unwrap();
        client.disconnect().await.unwrap();
        let result = client.connect(constants::TEST_GATEWAY_ADDRESS).await;

        assert!(result.is_ok());
        assert!(client.is_connected());
    }

    /// Test health check
    #[tokio::test]
    async fn test_health_check() {
        let mut client = MockGatewayClient::new();
        client.connect(constants::TEST_GATEWAY_ADDRESS).await.unwrap();

        let result = client.health_check().await;

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    /// Test health check without connection
    #[tokio::test]
    async fn test_health_check_disconnected() {
        let client = MockGatewayClient::new();

        let result = client.health_check().await;

        assert!(result.is_err());
    }
}

// ============================================================================
// Backend Sync Tests
// ============================================================================

#[cfg(test)]
mod backend_sync_tests {
    use super::*;

    /// Test syncing a backend
    #[tokio::test]
    async fn test_sync_backend() {
        let mut client = MockGatewayClient::new();
        client.connect(constants::TEST_GATEWAY_ADDRESS).await.unwrap();

        let backend = MockBackend {
            id: "backend-1".to_string(),
            name: "Game Server".to_string(),
            address: "10.0.0.1:25565".to_string(),
            protocol: Protocol::MinecraftJava.to_grpc_protocol(),
        };

        let result = client.sync_backend("org-1", &backend).await;

        assert!(result.is_ok());
        assert_eq!(client.list_backends().len(), 1);
    }

    /// Test updating a backend
    #[tokio::test]
    async fn test_update_backend() {
        let mut client = MockGatewayClient::new();
        client.connect(constants::TEST_GATEWAY_ADDRESS).await.unwrap();

        let backend = MockBackend {
            id: "backend-1".to_string(),
            name: "Game Server".to_string(),
            address: "10.0.0.1:25565".to_string(),
            protocol: Protocol::MinecraftJava.to_grpc_protocol(),
        };

        client.sync_backend("org-1", &backend).await.unwrap();

        // Update address
        let updated = MockBackend {
            id: "backend-1".to_string(),
            name: "Game Server".to_string(),
            address: "10.0.0.2:25565".to_string(), // Changed
            protocol: Protocol::MinecraftJava.to_grpc_protocol(),
        };

        client.sync_backend("org-1", &updated).await.unwrap();

        assert_eq!(client.list_backends().len(), 1);
        assert_eq!(client.list_backends()[0].address, "10.0.0.2:25565");
    }

    /// Test deleting a backend
    #[tokio::test]
    async fn test_delete_backend() {
        let mut client = MockGatewayClient::new();
        client.connect(constants::TEST_GATEWAY_ADDRESS).await.unwrap();

        let backend = MockBackend {
            id: "backend-1".to_string(),
            name: "Game Server".to_string(),
            address: "10.0.0.1:25565".to_string(),
            protocol: Protocol::MinecraftJava.to_grpc_protocol(),
        };

        client.sync_backend("org-1", &backend).await.unwrap();
        let result = client.delete_backend("backend-1").await;

        assert!(result.is_ok());
        assert!(client.list_backends().is_empty());
    }

    /// Test sync without connection fails
    #[tokio::test]
    async fn test_sync_backend_disconnected() {
        let mut client = MockGatewayClient::new();

        let backend = MockBackend {
            id: "backend-1".to_string(),
            name: "Game Server".to_string(),
            address: "10.0.0.1:25565".to_string(),
            protocol: Protocol::MinecraftJava.to_grpc_protocol(),
        };

        let result = client.sync_backend("org-1", &backend).await;

        assert!(result.is_err());
    }

    /// Test sync failure handling
    #[tokio::test]
    async fn test_sync_backend_failure() {
        let mut client = MockGatewayClient::new();
        client.connect(constants::TEST_GATEWAY_ADDRESS).await.unwrap();
        client.set_fail_sync(true);

        let backend = MockBackend {
            id: "backend-1".to_string(),
            name: "Game Server".to_string(),
            address: "10.0.0.1:25565".to_string(),
            protocol: Protocol::MinecraftJava.to_grpc_protocol(),
        };

        let result = client.sync_backend("org-1", &backend).await;

        assert!(result.is_err());
    }
}

// ============================================================================
// Filter Rule Sync Tests
// ============================================================================

#[cfg(test)]
mod filter_rule_sync_tests {
    use super::*;

    /// Test syncing a filter rule
    #[tokio::test]
    async fn test_sync_filter_rule() {
        let mut client = MockGatewayClient::new();
        client.connect(constants::TEST_GATEWAY_ADDRESS).await.unwrap();

        let rule = MockFilterRule {
            id: "rule-1".to_string(),
            backend_id: "".to_string(),
            name: "Block Bad IPs".to_string(),
            priority: 100,
            enabled: true,
        };

        let result = client.sync_filter_rule("backend-1", &rule).await;

        assert!(result.is_ok());
        assert_eq!(client.list_filter_rules("backend-1").len(), 1);
    }

    /// Test updating a filter rule
    #[tokio::test]
    async fn test_update_filter_rule() {
        let mut client = MockGatewayClient::new();
        client.connect(constants::TEST_GATEWAY_ADDRESS).await.unwrap();

        let rule = MockFilterRule {
            id: "rule-1".to_string(),
            backend_id: "".to_string(),
            name: "Block Bad IPs".to_string(),
            priority: 100,
            enabled: true,
        };

        client.sync_filter_rule("backend-1", &rule).await.unwrap();

        let updated = MockFilterRule {
            id: "rule-1".to_string(),
            backend_id: "".to_string(),
            name: "Block Bad IPs".to_string(),
            priority: 50, // Changed
            enabled: true,
        };

        client.sync_filter_rule("backend-1", &updated).await.unwrap();

        let rules = client.list_filter_rules("backend-1");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].priority, 50);
    }

    /// Test deleting a filter rule
    #[tokio::test]
    async fn test_delete_filter_rule() {
        let mut client = MockGatewayClient::new();
        client.connect(constants::TEST_GATEWAY_ADDRESS).await.unwrap();

        let rule = MockFilterRule {
            id: "rule-1".to_string(),
            backend_id: "".to_string(),
            name: "Block Bad IPs".to_string(),
            priority: 100,
            enabled: true,
        };

        client.sync_filter_rule("backend-1", &rule).await.unwrap();
        let result = client.delete_filter_rule("rule-1").await;

        assert!(result.is_ok());
        assert!(client.list_filter_rules("backend-1").is_empty());
    }

    /// Test multiple filter rules per backend
    #[tokio::test]
    async fn test_multiple_filter_rules() {
        let mut client = MockGatewayClient::new();
        client.connect(constants::TEST_GATEWAY_ADDRESS).await.unwrap();

        for i in 1..=5 {
            let rule = MockFilterRule {
                id: format!("rule-{}", i),
                backend_id: "".to_string(),
                name: format!("Rule {}", i),
                priority: 100 - i * 10,
                enabled: true,
            };
            client.sync_filter_rule("backend-1", &rule).await.unwrap();
        }

        let rules = client.list_filter_rules("backend-1");
        assert_eq!(rules.len(), 5);
    }

    /// Test filter rules are scoped to backend
    #[tokio::test]
    async fn test_filter_rules_scoped() {
        let mut client = MockGatewayClient::new();
        client.connect(constants::TEST_GATEWAY_ADDRESS).await.unwrap();

        let rule1 = MockFilterRule {
            id: "rule-1".to_string(),
            backend_id: "".to_string(),
            name: "Rule 1".to_string(),
            priority: 100,
            enabled: true,
        };

        let rule2 = MockFilterRule {
            id: "rule-2".to_string(),
            backend_id: "".to_string(),
            name: "Rule 2".to_string(),
            priority: 100,
            enabled: true,
        };

        client.sync_filter_rule("backend-1", &rule1).await.unwrap();
        client.sync_filter_rule("backend-2", &rule2).await.unwrap();

        assert_eq!(client.list_filter_rules("backend-1").len(), 1);
        assert_eq!(client.list_filter_rules("backend-2").len(), 1);
        assert_eq!(client.list_filter_rules("backend-1")[0].id, "rule-1");
        assert_eq!(client.list_filter_rules("backend-2")[0].id, "rule-2");
    }
}

// ============================================================================
// CRD to gRPC Conversion Tests
// ============================================================================

#[cfg(test)]
mod conversion_tests {
    use super::*;

    /// Test converting DDoSProtection to gRPC backend
    #[test]
    fn test_convert_protection_to_backend() {
        let protection = create_test_ddos_protection("test", "default");
        let backend = &protection.spec.backends[0];

        let grpc_backend = MockBackend {
            id: format!(
                "{}/{}",
                protection.metadata.namespace.as_deref().unwrap_or("default"),
                protection.metadata.name.as_deref().unwrap_or("unknown")
            ),
            name: backend.name.clone(),
            address: backend.address.clone(),
            protocol: backend.protocol.to_grpc_protocol(),
        };

        assert!(!grpc_backend.id.is_empty());
        assert_eq!(grpc_backend.protocol, Protocol::MinecraftJava.to_grpc_protocol());
    }

    /// Test converting FilterRule to gRPC rule
    #[test]
    fn test_convert_filter_rule() {
        let rule = create_test_filter_rule("test", "default");

        let grpc_rule = MockFilterRule {
            id: format!(
                "{}/{}",
                rule.metadata.namespace.as_deref().unwrap_or("default"),
                rule.metadata.name.as_deref().unwrap_or("unknown")
            ),
            backend_id: "".to_string(), // Set later
            name: rule.spec.name.clone(),
            priority: rule.spec.priority,
            enabled: rule.spec.enabled,
        };

        assert!(!grpc_rule.id.is_empty());
        assert_eq!(grpc_rule.priority, 50);
    }
}
