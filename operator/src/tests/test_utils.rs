//! Test utilities for operator tests

use crate::crd::{
    BackendSpec, DDoSProtection, DDoSProtectionSpec, DDoSProtectionStatus, FilterRule,
    FilterRuleSpec, FilterRuleStatus, Protocol, RateLimitSpec,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use std::collections::BTreeMap;

/// Test configuration constants
pub mod constants {
    pub const TEST_NAMESPACE: &str = "test-namespace";
    pub const TEST_RESOURCE_NAME: &str = "test-protection";
    pub const TEST_BACKEND_ADDRESS: &str = "10.0.0.1:25565";
    pub const TEST_GATEWAY_ADDRESS: &str = "gateway.pistonprotection.svc.cluster.local:50051";
}

/// Create a test DDoSProtection resource
pub fn create_test_ddos_protection(name: &str, namespace: &str) -> DDoSProtection {
    DDoSProtection {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            generation: Some(1),
            ..Default::default()
        },
        spec: DDoSProtectionSpec {
            backends: vec![BackendSpec {
                name: "game-server".to_string(),
                address: constants::TEST_BACKEND_ADDRESS.to_string(),
                protocol: Protocol::MinecraftJava,
                weight: 1,
                health_check: None,
                rate_limit: None,
                proxy_protocol: None,
                metadata: None,
            }],
            protection_level: 3,
            rate_limit: Some(RateLimitSpec {
                pps_per_ip: 1000,
                burst: 5000,
                global_pps: Some(100000),
                window_seconds: 1,
            }),
            protocol: None,
            geo_filter: None,
            node_selector: None,
            replicas: 2,
            challenge_enabled: false,
            auto_escalate: true,
            annotations: None,
            resources: None,
        },
        status: Some(DDoSProtectionStatus::default()),
    }
}

/// Create a test FilterRule resource
pub fn create_test_filter_rule(name: &str, namespace: &str) -> FilterRule {
    use crate::crd::{FilterAction, FilterRuleConfig, FilterRuleType};

    FilterRule {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            generation: Some(1),
            ..Default::default()
        },
        spec: FilterRuleSpec {
            name: format!("Test Rule {}", name),
            description: Some("A test filter rule".to_string()),
            rule_type: FilterRuleType::IpBlocklist,
            action: FilterAction::Drop,
            priority: 50,
            config: FilterRuleConfig {
                ip_ranges: vec!["192.168.1.0/24".to_string()],
                countries: vec![],
                asns: vec![],
                rate_limit: None,
                ports: vec![],
                protocols: vec![],
                http_match: None,
                custom_program: None,
            },
            selector: None,
            enabled: true,
            schedule: None,
            expires_at: None,
        },
        status: Some(FilterRuleStatus::default()),
    }
}

/// Create object metadata for testing
pub fn create_test_metadata(name: &str, namespace: &str) -> ObjectMeta {
    ObjectMeta {
        name: Some(name.to_string()),
        namespace: Some(namespace.to_string()),
        uid: Some(uuid::Uuid::new_v4().to_string()),
        resource_version: Some("12345".to_string()),
        generation: Some(1),
        ..Default::default()
    }
}

/// Create metadata with labels
pub fn create_labeled_metadata(
    name: &str,
    namespace: &str,
    labels: BTreeMap<String, String>,
) -> ObjectMeta {
    ObjectMeta {
        name: Some(name.to_string()),
        namespace: Some(namespace.to_string()),
        labels: Some(labels),
        ..Default::default()
    }
}

/// Create a test Kubernetes client (mock)
pub struct MockKubeClient {
    pub ddos_protections: Vec<DDoSProtection>,
    pub filter_rules: Vec<FilterRule>,
    pub should_fail_get: bool,
    pub should_fail_create: bool,
    pub should_fail_update: bool,
    pub should_fail_delete: bool,
}

impl MockKubeClient {
    pub fn new() -> Self {
        Self {
            ddos_protections: Vec::new(),
            filter_rules: Vec::new(),
            should_fail_get: false,
            should_fail_create: false,
            should_fail_update: false,
            should_fail_delete: false,
        }
    }

    pub fn with_ddos_protection(mut self, protection: DDoSProtection) -> Self {
        self.ddos_protections.push(protection);
        self
    }

    pub fn with_filter_rule(mut self, rule: FilterRule) -> Self {
        self.filter_rules.push(rule);
        self
    }

    pub fn get_ddos_protection(&self, name: &str, namespace: &str) -> Option<&DDoSProtection> {
        if self.should_fail_get {
            return None;
        }
        self.ddos_protections.iter().find(|p| {
            p.metadata.name.as_deref() == Some(name)
                && p.metadata.namespace.as_deref() == Some(namespace)
        })
    }

    pub fn list_ddos_protections(&self, namespace: &str) -> Vec<&DDoSProtection> {
        if self.should_fail_get {
            return Vec::new();
        }
        self.ddos_protections
            .iter()
            .filter(|p| p.metadata.namespace.as_deref() == Some(namespace))
            .collect()
    }
}

impl Default for MockKubeClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_ddos_protection() {
        let protection = create_test_ddos_protection("test", "default");

        assert_eq!(protection.metadata.name, Some("test".to_string()));
        assert_eq!(protection.metadata.namespace, Some("default".to_string()));
        assert_eq!(protection.spec.backends.len(), 1);
        assert_eq!(protection.spec.protection_level, 3);
    }

    #[test]
    fn test_create_filter_rule() {
        let rule = create_test_filter_rule("block-list", "default");

        assert_eq!(rule.metadata.name, Some("block-list".to_string()));
        assert_eq!(rule.spec.priority, 50);
        assert!(rule.spec.enabled);
    }

    #[test]
    fn test_mock_kube_client() {
        let protection = create_test_ddos_protection("test", "default");
        let client = MockKubeClient::new().with_ddos_protection(protection);

        let found = client.get_ddos_protection("test", "default");
        assert!(found.is_some());
        assert_eq!(found.unwrap().spec.backends.len(), 1);
    }

    #[test]
    fn test_mock_kube_client_failure() {
        let mut client = MockKubeClient::new();
        client.should_fail_get = true;

        let found = client.get_ddos_protection("test", "default");
        assert!(found.is_none());
    }
}
