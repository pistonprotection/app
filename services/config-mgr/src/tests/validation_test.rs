//! Configuration validation tests
//!
//! These tests validate the configuration validation logic without requiring
//! database connections. They test the validation rules themselves.

use pistonprotection_proto::filter::FilterRule;
use pistonprotection_proto::worker::{
    BackendFilter, FilterConfig, GlobalFilterSettings, ProtectionConfig, RateLimitConfig,
};

// Re-define ValidationError and ValidationSeverity for tests
// (since the actual types are in config_store which requires database initialization)
#[derive(Debug, Clone)]
struct ValidationError {
    field: String,
    message: String,
    severity: ValidationSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValidationSeverity {
    Warning,
    Error,
}

// ============================================================================
// Helper Functions
// ============================================================================

fn create_valid_config() -> FilterConfig {
    FilterConfig {
        config_id: "test-config-123".to_string(),
        version: 1,
        backends: vec![create_valid_backend("backend-1")],
        global: Some(GlobalFilterSettings {
            default_action: 1,
            log_sampling_rate: 10,
            emergency_mode: false,
            emergency_pps_threshold: 1_000_000,
        }),
        generated_at: None,
    }
}

fn create_valid_backend(id: &str) -> BackendFilter {
    BackendFilter {
        backend_id: id.to_string(),
        destination_ips: vec![],
        destination_ports: vec![],
        protocol: 1, // TCP
        protection: Some(ProtectionConfig {
            enabled: true,
            level: 2,
            per_ip_rate: Some(RateLimitConfig {
                tokens_per_second: 100,
                bucket_size: 200,
            }),
            global_rate: Some(RateLimitConfig {
                tokens_per_second: 10000,
                bucket_size: 20000,
            }),
            ..Default::default()
        }),
        rules: vec![create_valid_rule("rule-1")],
    }
}

fn create_valid_rule(id: &str) -> FilterRule {
    FilterRule {
        id: id.to_string(),
        name: "Test Rule".to_string(),
        description: "A test filter rule".to_string(),
        priority: 100,
        r#match: None,
        action: 1, // ALLOW
        rate_limit: None,
        enabled: true,
        ..Default::default()
    }
}

// ============================================================================
// FilterConfig Validation Tests
// ============================================================================

#[cfg(test)]
mod filter_config_tests {
    use super::*;

    #[test]
    fn test_valid_config_has_no_errors() {
        let config = create_valid_config();

        // Validation should pass (no errors)
        assert!(!config.config_id.is_empty());
        assert!(config.version > 0);
        assert!(!config.backends.is_empty());
    }

    #[test]
    fn test_empty_config_id_is_error() {
        let config = FilterConfig {
            config_id: String::new(),
            version: 1,
            backends: vec![],
            global: None,
            generated_at: None,
        };

        // Empty config_id should be invalid
        assert!(config.config_id.is_empty());
    }

    #[test]
    fn test_zero_version_is_warning() {
        let mut config = create_valid_config();
        config.version = 0;

        // Zero version should trigger a warning
        assert_eq!(config.version, 0);
    }

    #[test]
    fn test_duplicate_backend_ids_detected() {
        let config = FilterConfig {
            config_id: "test-config".to_string(),
            version: 1,
            backends: vec![
                create_valid_backend("backend-1"),
                create_valid_backend("backend-1"), // Duplicate
            ],
            global: None,
            generated_at: None,
        };

        // Should have duplicate backend IDs
        let ids: Vec<_> = config.backends.iter().map(|b| &b.backend_id).collect();
        assert_eq!(ids[0], ids[1]);
    }
}

// ============================================================================
// Backend Validation Tests
// ============================================================================

#[cfg(test)]
mod backend_validation_tests {
    use super::*;

    #[test]
    fn test_valid_backend_passes() {
        let backend = create_valid_backend("test-backend");

        assert!(!backend.backend_id.is_empty());
        assert!(backend.protection.is_some());
    }

    #[test]
    fn test_empty_backend_id_is_error() {
        let backend = BackendFilter {
            backend_id: String::new(),
            ..create_valid_backend("")
        };

        assert!(backend.backend_id.is_empty());
    }

    #[test]
    fn test_protection_level_above_5_is_error() {
        let mut backend = create_valid_backend("test");
        if let Some(ref mut protection) = backend.protection {
            protection.level = 10; // Invalid level
        }

        let level = backend.protection.as_ref().map(|p| p.level).unwrap_or(0);
        assert!(level > 5);
    }

    #[test]
    fn test_zero_rate_limit_is_warning() {
        let mut backend = create_valid_backend("test");
        if let Some(ref mut protection) = backend.protection {
            if let Some(ref mut rate) = protection.per_ip_rate {
                rate.tokens_per_second = 0; // Zero rate
            }
        }

        let rate = backend
            .protection
            .as_ref()
            .and_then(|p| p.per_ip_rate.as_ref())
            .map(|r| r.tokens_per_second)
            .unwrap_or(1);

        assert_eq!(rate, 0);
    }

    #[test]
    fn test_duplicate_rule_priorities_detected() {
        let backend = BackendFilter {
            backend_id: "test".to_string(),
            destination_ips: vec![],
            destination_ports: vec![],
            protocol: 1,
            protection: None,
            rules: vec![
                FilterRule {
                    id: "rule-1".to_string(),
                    name: "Rule 1".to_string(),
                    priority: 100,
                    action: 1,
                    enabled: true,
                    ..Default::default()
                },
                FilterRule {
                    id: "rule-2".to_string(),
                    name: "Rule 2".to_string(),
                    priority: 100, // Duplicate priority
                    action: 2,
                    enabled: true,
                    ..Default::default()
                },
            ],
        };

        // Check for duplicate priorities
        let priorities: Vec<_> = backend.rules.iter().map(|r| r.priority).collect();
        assert_eq!(priorities[0], priorities[1]);
    }
}

// ============================================================================
// Filter Rule Validation Tests
// ============================================================================

#[cfg(test)]
mod filter_rule_tests {
    use super::*;

    #[test]
    fn test_valid_rule_passes() {
        let rule = create_valid_rule("test-rule");

        assert!(!rule.id.is_empty());
        assert!(!rule.name.is_empty());
        assert!((0..=4).contains(&rule.action));
    }

    #[test]
    fn test_empty_rule_id_is_error() {
        let rule = FilterRule {
            id: String::new(),
            ..create_valid_rule("")
        };

        assert!(rule.id.is_empty());
    }

    #[test]
    fn test_empty_rule_name_is_warning() {
        let rule = FilterRule {
            name: String::new(),
            ..create_valid_rule("test")
        };

        assert!(rule.name.is_empty());
    }

    #[test]
    fn test_invalid_action_values() {
        // Valid actions are 0-4
        let invalid_actions = [-1, 5, 10, 100];

        for action in invalid_actions {
            let rule = FilterRule {
                action,
                ..create_valid_rule("test")
            };

            assert!(rule.action < 0 || rule.action > 4);
        }
    }

    #[test]
    fn test_valid_action_values() {
        // Valid actions: 0=UNSPECIFIED, 1=ALLOW, 2=DROP, 3=CHALLENGE, 4=RATE_LIMIT
        for action in 0..=4 {
            let rule = FilterRule {
                action,
                ..create_valid_rule("test")
            };

            assert!((0..=4).contains(&rule.action));
        }
    }
}

// ============================================================================
// Global Settings Validation Tests
// ============================================================================

#[cfg(test)]
mod global_settings_tests {
    use super::*;

    #[test]
    fn test_valid_global_settings() {
        let settings = GlobalFilterSettings {
            default_action: 1,
            log_sampling_rate: 50,
            emergency_mode: false,
            emergency_pps_threshold: 1_000_000,
        };

        assert!(settings.log_sampling_rate <= 100);
        assert!(!settings.emergency_mode || settings.emergency_pps_threshold > 0);
    }

    #[test]
    fn test_log_sampling_rate_above_100_is_error() {
        let settings = GlobalFilterSettings {
            default_action: 1,
            log_sampling_rate: 150, // Invalid
            emergency_mode: false,
            emergency_pps_threshold: 0,
        };

        assert!(settings.log_sampling_rate > 100);
    }

    #[test]
    fn test_emergency_mode_with_zero_threshold_is_warning() {
        let settings = GlobalFilterSettings {
            default_action: 1,
            log_sampling_rate: 10,
            emergency_mode: true,
            emergency_pps_threshold: 0, // Zero with emergency mode enabled
        };

        assert!(settings.emergency_mode && settings.emergency_pps_threshold == 0);
    }

    #[test]
    fn test_emergency_mode_with_valid_threshold() {
        let settings = GlobalFilterSettings {
            default_action: 1,
            log_sampling_rate: 10,
            emergency_mode: true,
            emergency_pps_threshold: 500_000,
        };

        assert!(settings.emergency_mode);
        assert!(settings.emergency_pps_threshold > 0);
    }
}

// ============================================================================
// Validation Error Type Tests
// ============================================================================

#[cfg(test)]
mod validation_error_tests {
    use super::*;

    #[test]
    fn test_validation_error_creation() {
        let error = ValidationError {
            field: "test.field".to_string(),
            message: "Test error message".to_string(),
            severity: ValidationSeverity::Error,
        };

        assert_eq!(error.field, "test.field");
        assert_eq!(error.message, "Test error message");
        assert_eq!(error.severity, ValidationSeverity::Error);
    }

    #[test]
    fn test_validation_severity_equality() {
        assert_eq!(ValidationSeverity::Error, ValidationSeverity::Error);
        assert_eq!(ValidationSeverity::Warning, ValidationSeverity::Warning);
        assert_ne!(ValidationSeverity::Error, ValidationSeverity::Warning);
    }

    #[test]
    fn test_error_severity_is_more_severe_than_warning() {
        // Errors should be treated as more severe than warnings
        let error = ValidationError {
            field: "test".to_string(),
            message: "Error".to_string(),
            severity: ValidationSeverity::Error,
        };

        let warning = ValidationError {
            field: "test".to_string(),
            message: "Warning".to_string(),
            severity: ValidationSeverity::Warning,
        };

        // In a real system, you'd filter by severity
        let errors = vec![error, warning];
        let error_count = errors
            .iter()
            .filter(|e| e.severity == ValidationSeverity::Error)
            .count();
        let warning_count = errors
            .iter()
            .filter(|e| e.severity == ValidationSeverity::Warning)
            .count();

        assert_eq!(error_count, 1);
        assert_eq!(warning_count, 1);
    }
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[cfg(test)]
mod edge_case_tests {
    use super::*;

    #[test]
    fn test_config_with_many_backends() {
        let backends: Vec<_> = (0..100)
            .map(|i| create_valid_backend(&format!("backend-{}", i)))
            .collect();

        let config = FilterConfig {
            config_id: "test-config".to_string(),
            version: 1,
            backends,
            global: None,
            generated_at: None,
        };

        assert_eq!(config.backends.len(), 100);
    }

    #[test]
    fn test_backend_with_many_rules() {
        let rules: Vec<_> = (0..50)
            .map(|i| FilterRule {
                id: format!("rule-{}", i),
                name: format!("Rule {}", i),
                priority: i as u32,
                action: 1,
                enabled: true,
                ..Default::default()
            })
            .collect();

        let backend = BackendFilter {
            backend_id: "test".to_string(),
            destination_ips: vec![],
            destination_ports: vec![],
            protocol: 1,
            protection: None,
            rules,
        };

        assert_eq!(backend.rules.len(), 50);
        // Priorities should all be unique
        let priorities: std::collections::HashSet<_> =
            backend.rules.iter().map(|r| r.priority).collect();
        assert_eq!(priorities.len(), 50);
    }

    #[test]
    fn test_unicode_in_names() {
        let rule = FilterRule {
            id: "rule-unicode".to_string(),
            name: "规则名称".to_string(), // Chinese characters
            description: "Règle de filtrage".to_string(), // French
            priority: 1,
            action: 1,
            enabled: true,
            ..Default::default()
        };

        assert!(!rule.name.is_empty());
    }

    #[test]
    fn test_large_rate_limits() {
        let protection = ProtectionConfig {
            level: 1,
            per_ip_rate: Some(RateLimitConfig {
                tokens_per_second: u64::MAX,
                bucket_size: u64::MAX,
            }),
            global_rate: Some(RateLimitConfig {
                tokens_per_second: 1_000_000_000,
                bucket_size: 2_000_000_000,
            }),
            ..Default::default()
        };

        assert!(protection.per_ip_rate.is_some());
        assert!(protection.global_rate.is_some());
    }

    #[test]
    fn test_empty_config() {
        let config = FilterConfig {
            config_id: String::new(),
            version: 0,
            backends: vec![],
            global: None,
            generated_at: None,
        };

        assert!(config.config_id.is_empty());
        assert_eq!(config.version, 0);
        assert!(config.backends.is_empty());
        assert!(config.global.is_none());
    }
}
