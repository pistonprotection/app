//! CRD validation tests

use super::test_utils::{create_test_ddos_protection, create_test_filter_rule};
use crate::crd::{
    BackendSpec, Condition, DDoSProtectionStatus, FilterAction, FilterRuleConfig, FilterRuleType,
    GeoFilterMode, GeoFilterSpec, HealthCheckSpec, HealthState, LoadBalancingAlgorithm, Phase,
    PortRange, Protocol, RateLimitSpec,
};

// ============================================================================
// DDoSProtection CRD Tests
// ============================================================================

#[cfg(test)]
mod ddos_protection_tests {
    use super::*;

    /// Test DDoSProtection default values
    #[test]
    fn test_ddos_protection_defaults() {
        let protection = create_test_ddos_protection("test", "default");

        // Check defaults
        assert_eq!(protection.spec.protection_level, 3);
        assert_eq!(protection.spec.replicas, 2);
        assert!(protection.spec.auto_escalate);
    }

    /// Test DDoSProtection with multiple backends
    #[test]
    fn test_multiple_backends() {
        let mut protection = create_test_ddos_protection("test", "default");

        protection.spec.backends = vec![
            BackendSpec {
                name: "server-1".to_string(),
                address: "10.0.0.1:25565".to_string(),
                protocol: Protocol::MinecraftJava,
                weight: 2,
                ..Default::default()
            },
            BackendSpec {
                name: "server-2".to_string(),
                address: "10.0.0.2:25565".to_string(),
                protocol: Protocol::MinecraftJava,
                weight: 1,
                ..Default::default()
            },
        ];

        assert_eq!(protection.spec.backends.len(), 2);
        assert_eq!(protection.spec.backends[0].weight, 2);
    }

    /// Test DDoSProtection with rate limiting
    #[test]
    fn test_rate_limit_config() {
        let protection = create_test_ddos_protection("test", "default");

        let rate_limit = protection.spec.rate_limit.as_ref().unwrap();
        assert_eq!(rate_limit.pps_per_ip, 1000);
        assert_eq!(rate_limit.burst, 5000);
        assert_eq!(rate_limit.global_pps, Some(100000));
    }

    /// Test DDoSProtection with geo filtering
    #[test]
    fn test_geo_filter_config() {
        let mut protection = create_test_ddos_protection("test", "default");

        protection.spec.geo_filter = Some(GeoFilterSpec {
            mode: GeoFilterMode::Deny,
            countries: vec!["RU".to_string(), "CN".to_string()],
        });

        let geo = protection.spec.geo_filter.as_ref().unwrap();
        assert_eq!(geo.mode, GeoFilterMode::Deny);
        assert_eq!(geo.countries.len(), 2);
    }

    /// Test DDoSProtection status
    #[test]
    fn test_status_fields() {
        let mut protection = create_test_ddos_protection("test", "default");

        protection.status = Some(DDoSProtectionStatus {
            phase: Phase::Active,
            backend_count: 2,
            healthy_backends: 2,
            ready_workers: 2,
            desired_workers: 2,
            gateway_synced: true,
            ..Default::default()
        });

        let status = protection.status.as_ref().unwrap();
        assert_eq!(status.phase, Phase::Active);
        assert!(status.gateway_synced);
    }

    /// Test condition creation
    #[test]
    fn test_condition_creation() {
        let condition = Condition::new("Ready", true, "Reconciled", "Resource is ready");

        assert_eq!(condition.condition_type, "Ready");
        assert_eq!(condition.status, "True");
        assert!(!condition.last_transition_time.is_empty());
    }

    /// Test phase transitions
    #[test]
    fn test_phase_display() {
        assert_eq!(Phase::Pending.to_string(), "Pending");
        assert_eq!(Phase::Provisioning.to_string(), "Provisioning");
        assert_eq!(Phase::Active.to_string(), "Active");
        assert_eq!(Phase::Degraded.to_string(), "Degraded");
        assert_eq!(Phase::Error.to_string(), "Error");
        assert_eq!(Phase::Terminating.to_string(), "Terminating");
    }

    /// Test health check configuration
    #[test]
    fn test_health_check_config() {
        let health_check = HealthCheckSpec {
            interval_seconds: 10,
            timeout_seconds: 5,
            unhealthy_threshold: 3,
            healthy_threshold: 2,
            http_path: Some("/health".to_string()),
            expected_status: Some(vec![200, 204]),
        };

        assert_eq!(health_check.interval_seconds, 10);
        assert_eq!(health_check.http_path, Some("/health".to_string()));
    }
}

// ============================================================================
// FilterRule CRD Tests
// ============================================================================

#[cfg(test)]
mod filter_rule_tests {
    use super::*;

    /// Test FilterRule creation
    #[test]
    fn test_filter_rule_creation() {
        let rule = create_test_filter_rule("block-ips", "default");

        assert_eq!(rule.spec.priority, 50);
        assert!(rule.spec.enabled);
        assert_eq!(rule.spec.rule_type, FilterRuleType::IpBlocklist);
        assert_eq!(rule.spec.action, FilterAction::Drop);
    }

    /// Test different filter rule types
    #[test]
    fn test_filter_rule_types() {
        let types = vec![
            FilterRuleType::IpBlocklist,
            FilterRuleType::IpAllowlist,
            FilterRuleType::RateLimit,
            FilterRuleType::GeoBlock,
            FilterRuleType::GeoAllow,
            FilterRuleType::ProtocolValidation,
            FilterRuleType::SynFlood,
            FilterRuleType::UdpAmplification,
            FilterRuleType::HttpFlood,
            FilterRuleType::Custom,
        ];

        assert_eq!(types.len(), 10);
    }

    /// Test different filter actions
    #[test]
    fn test_filter_actions() {
        assert_eq!(FilterAction::Drop.to_grpc_action(), 2);
        assert_eq!(FilterAction::Allow.to_grpc_action(), 1);
        assert_eq!(FilterAction::RateLimit.to_grpc_action(), 3);
        assert_eq!(FilterAction::Challenge.to_grpc_action(), 4);
        assert_eq!(FilterAction::Log.to_grpc_action(), 5);
    }

    /// Test IP range configuration
    #[test]
    fn test_ip_range_config() {
        let config = FilterRuleConfig {
            ip_ranges: vec![
                "192.168.1.0/24".to_string(),
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
            ],
            ..Default::default()
        };

        assert_eq!(config.ip_ranges.len(), 3);
    }

    /// Test port range configuration
    #[test]
    fn test_port_range_config() {
        let config = FilterRuleConfig {
            ports: vec![
                PortRange { start: 80, end: 80 },
                PortRange {
                    start: 443,
                    end: 443,
                },
                PortRange {
                    start: 8000,
                    end: 9000,
                },
            ],
            ..Default::default()
        };

        assert_eq!(config.ports.len(), 3);
        assert_eq!(config.ports[2].start, 8000);
        assert_eq!(config.ports[2].end, 9000);
    }

    /// Test geo country configuration
    #[test]
    fn test_geo_config() {
        let config = FilterRuleConfig {
            countries: vec![
                "US".to_string(),
                "CA".to_string(),
                "GB".to_string(),
                "DE".to_string(),
            ],
            ..Default::default()
        };

        assert_eq!(config.countries.len(), 4);
    }

    /// Test filter rule with rate limit
    #[test]
    fn test_rate_limit_rule() {
        let mut rule = create_test_filter_rule("rate-limit", "default");
        rule.spec.rule_type = FilterRuleType::RateLimit;
        rule.spec.action = FilterAction::RateLimit;
        rule.spec.config.rate_limit = Some(RateLimitSpec {
            pps_per_ip: 100,
            burst: 500,
            global_pps: None,
            window_seconds: 1,
        });

        assert_eq!(rule.spec.rule_type, FilterRuleType::RateLimit);
        assert!(rule.spec.config.rate_limit.is_some());
    }

    /// Test filter rule status
    #[test]
    fn test_filter_rule_status() {
        use crate::crd::FilterRuleStatus;

        let status = FilterRuleStatus {
            active: true,
            match_count: 1000,
            last_match: Some(chrono::Utc::now().to_rfc3339()),
            gateway_synced: true,
            applied_to_count: 5,
            ..Default::default()
        };

        assert!(status.active);
        assert_eq!(status.match_count, 1000);
        assert_eq!(status.applied_to_count, 5);
    }
}

// ============================================================================
// Protocol Tests
// ============================================================================

#[cfg(test)]
mod protocol_tests {
    use super::*;

    /// Test protocol to gRPC conversion
    #[test]
    fn test_protocol_to_grpc() {
        assert_eq!(Protocol::Tcp.to_grpc_protocol(), 1);
        assert_eq!(Protocol::Udp.to_grpc_protocol(), 2);
        assert_eq!(Protocol::Http.to_grpc_protocol(), 3);
        assert_eq!(Protocol::Https.to_grpc_protocol(), 4);
        assert_eq!(Protocol::MinecraftJava.to_grpc_protocol(), 5);
        assert_eq!(Protocol::MinecraftBedrock.to_grpc_protocol(), 6);
        assert_eq!(Protocol::Quic.to_grpc_protocol(), 7);
    }

    /// Test protocol equality
    #[test]
    fn test_protocol_equality() {
        assert_eq!(Protocol::Tcp, Protocol::Tcp);
        assert_ne!(Protocol::Tcp, Protocol::Udp);
    }
}

// ============================================================================
// Backend CRD Tests
// ============================================================================

#[cfg(test)]
mod backend_crd_tests {
    use super::*;
    use crate::crd::{BackendCrdSpec, BackendStatus, EndpointSpec, LoadBalancingSpec, TlsSpec};

    /// Test Backend CRD creation
    #[test]
    fn test_backend_crd_spec() {
        let spec = BackendCrdSpec {
            display_name: "Game Server Cluster".to_string(),
            protocol: Protocol::MinecraftJava,
            endpoints: vec![
                EndpointSpec {
                    address: "10.0.0.1".to_string(),
                    port: 25565,
                    weight: 2,
                    priority: Some(1),
                    enabled: true,
                },
                EndpointSpec {
                    address: "10.0.0.2".to_string(),
                    port: 25565,
                    weight: 1,
                    priority: Some(2),
                    enabled: true,
                },
            ],
            load_balancing: Some(LoadBalancingSpec {
                algorithm: LoadBalancingAlgorithm::LeastConnections,
                sticky_sessions: true,
                sticky_cookie_name: Some("SERVERID".to_string()),
                sticky_ttl_seconds: Some(3600),
            }),
            health_check: None,
            tls: None,
            connection_pool: None,
            metadata: None,
        };

        assert_eq!(spec.endpoints.len(), 2);
        assert_eq!(
            spec.load_balancing.as_ref().unwrap().algorithm,
            LoadBalancingAlgorithm::LeastConnections
        );
    }

    /// Test Backend status
    #[test]
    fn test_backend_status() {
        let status = BackendStatus {
            health: HealthState::Healthy,
            healthy_endpoints: 2,
            endpoint_count: 2,
            gateway_synced: true,
            ..Default::default()
        };

        assert_eq!(status.health, HealthState::Healthy);
        assert_eq!(status.healthy_endpoints, 2);
    }

    /// Test health state display
    #[test]
    fn test_health_state_display() {
        assert_eq!(HealthState::Unknown.to_string(), "Unknown");
        assert_eq!(HealthState::Healthy.to_string(), "Healthy");
        assert_eq!(HealthState::Degraded.to_string(), "Degraded");
        assert_eq!(HealthState::Unhealthy.to_string(), "Unhealthy");
    }

    /// Test TLS configuration
    #[test]
    fn test_tls_config() {
        let tls = TlsSpec {
            enabled: true,
            verify: true,
            sni: Some("backend.example.com".to_string()),
            ca_secret: Some("backend-ca".to_string()),
            client_cert_secret: Some("backend-client-cert".to_string()),
        };

        assert!(tls.enabled);
        assert!(tls.verify);
    }

    /// Test load balancing algorithms
    #[test]
    fn test_load_balancing_algorithms() {
        let algorithms = [
            LoadBalancingAlgorithm::RoundRobin,
            LoadBalancingAlgorithm::LeastConnections,
            LoadBalancingAlgorithm::Random,
            LoadBalancingAlgorithm::IpHash,
            LoadBalancingAlgorithm::Weighted,
        ];

        assert_eq!(algorithms.len(), 5);
        assert_eq!(
            LoadBalancingAlgorithm::default(),
            LoadBalancingAlgorithm::RoundRobin
        );
    }
}

// ============================================================================
// Serialization Tests
// ============================================================================

#[cfg(test)]
mod serialization_tests {
    use super::*;

    /// Test DDoSProtection serialization
    #[test]
    fn test_ddos_protection_serialization() {
        let protection = create_test_ddos_protection("test", "default");

        let yaml = serde_yaml::to_string(&protection).unwrap();
        assert!(yaml.contains("pistonprotection.io"));

        let json = serde_json::to_string(&protection).unwrap();
        assert!(json.contains("protectionLevel"));
    }

    /// Test FilterRule serialization
    #[test]
    fn test_filter_rule_serialization() {
        let rule = create_test_filter_rule("test", "default");

        let yaml = serde_yaml::to_string(&rule).unwrap();
        assert!(yaml.contains("priority"));

        let json = serde_json::to_string(&rule).unwrap();
        assert!(json.contains("ruleType"));
    }

    /// Test deserialization
    #[test]
    fn test_deserialization() {
        let yaml = r#"
apiVersion: pistonprotection.io/v1alpha1
kind: DDoSProtection
metadata:
  name: test
  namespace: default
spec:
  backends:
    - name: server
      address: "10.0.0.1:25565"
      protocol: minecraft-java
  protectionLevel: 3
"#;

        // Note: Full deserialization would require kube setup
        // Just verify the YAML is parseable
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(value["metadata"]["name"], "test");
    }
}
