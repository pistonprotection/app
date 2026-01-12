//! Controller reconciliation tests (mock k8s)

use super::test_utils::{
    constants, create_test_ddos_protection, create_test_filter_rule, MockKubeClient,
};
use crate::crd::{
    Condition, DDoSProtection, DDoSProtectionSpec, DDoSProtectionStatus, FilterRule,
    FilterRuleSpec, FilterRuleStatus, Phase, FINALIZER,
};
use std::collections::BTreeMap;

/// Mock reconciler for testing controller logic
struct MockReconciler {
    pub client: MockKubeClient,
    pub gateway_synced: bool,
    pub workers_created: u32,
    pub errors: Vec<String>,
}

impl MockReconciler {
    fn new(client: MockKubeClient) -> Self {
        Self {
            client,
            gateway_synced: false,
            workers_created: 0,
            errors: Vec::new(),
        }
    }

    /// Reconcile a DDoSProtection resource
    fn reconcile_ddos_protection(
        &mut self,
        protection: &DDoSProtection,
    ) -> Result<DDoSProtectionStatus, String> {
        // Check if being deleted
        if protection.metadata.deletion_timestamp.is_some() {
            return self.handle_deletion(protection);
        }

        // Ensure finalizer
        if !self.has_finalizer(protection) {
            // Would add finalizer here
        }

        // Validate spec
        if let Err(e) = self.validate_spec(&protection.spec) {
            return Err(e);
        }

        // Create/update workers
        let workers = self.reconcile_workers(protection)?;
        self.workers_created = workers;

        // Sync with gateway
        self.gateway_synced = self.sync_to_gateway(protection)?;

        // Build status
        let status = DDoSProtectionStatus {
            phase: if self.gateway_synced && workers > 0 {
                Phase::Active
            } else if workers > 0 {
                Phase::Provisioning
            } else {
                Phase::Pending
            },
            backend_count: protection.spec.backends.len() as i32,
            healthy_backends: protection.spec.backends.len() as i32,
            ready_workers: workers as i32,
            desired_workers: protection.spec.replicas,
            gateway_synced: self.gateway_synced,
            observed_generation: protection.metadata.generation,
            conditions: vec![Condition::new(
                "Ready",
                self.gateway_synced && workers > 0,
                "Reconciled",
                "Resource has been reconciled",
            )],
            ..Default::default()
        };

        Ok(status)
    }

    fn has_finalizer(&self, protection: &DDoSProtection) -> bool {
        protection
            .metadata
            .finalizers
            .as_ref()
            .map(|f: &Vec<String>| f.contains(&FINALIZER.to_string()))
            .unwrap_or(false)
    }

    fn handle_deletion(
        &mut self,
        protection: &DDoSProtection,
    ) -> Result<DDoSProtectionStatus, String> {
        // Cleanup gateway
        self.gateway_synced = false;

        // Delete workers
        self.workers_created = 0;

        // Return terminating status
        Ok(DDoSProtectionStatus {
            phase: Phase::Terminating,
            ..Default::default()
        })
    }

    fn validate_spec(
        &self,
        spec: &DDoSProtectionSpec,
    ) -> Result<(), String> {
        if spec.backends.is_empty() {
            return Err("At least one backend is required".to_string());
        }

        if spec.protection_level < 1 || spec.protection_level > 5 {
            return Err("Protection level must be between 1 and 5".to_string());
        }

        if spec.replicas < 1 {
            return Err("At least one replica is required".to_string());
        }

        for backend in &spec.backends {
            if backend.name.is_empty() {
                return Err("Backend name is required".to_string());
            }
            if backend.address.is_empty() {
                return Err("Backend address is required".to_string());
            }
        }

        Ok(())
    }

    fn reconcile_workers(&self, protection: &DDoSProtection) -> Result<u32, String> {
        // Mock worker creation
        Ok(protection.spec.replicas as u32)
    }

    fn sync_to_gateway(&self, _protection: &DDoSProtection) -> Result<bool, String> {
        // Mock gateway sync
        Ok(true)
    }

    /// Reconcile a FilterRule resource
    fn reconcile_filter_rule(
        &mut self,
        rule: &FilterRule,
    ) -> Result<FilterRuleStatus, String> {
        // Validate rule
        if let Err(e) = self.validate_filter_rule(&rule.spec) {
            return Err(e);
        }

        // Sync to gateway
        let synced = self.sync_filter_rule_to_gateway(rule)?;

        Ok(FilterRuleStatus {
            active: rule.spec.enabled && synced,
            gateway_synced: synced,
            observed_generation: rule.metadata.generation,
            conditions: vec![Condition::new(
                "Synced",
                synced,
                "Reconciled",
                "Rule has been synced",
            )],
            ..Default::default()
        })
    }

    fn validate_filter_rule(&self, spec: &FilterRuleSpec) -> Result<(), String> {
        if spec.name.is_empty() {
            return Err("Rule name is required".to_string());
        }

        if spec.priority < 0 || spec.priority > 100 {
            return Err("Priority must be between 0 and 100".to_string());
        }

        Ok(())
    }

    fn sync_filter_rule_to_gateway(&self, _rule: &FilterRule) -> Result<bool, String> {
        Ok(true)
    }
}

// ============================================================================
// DDoSProtection Reconciliation Tests
// ============================================================================

#[cfg(test)]
mod ddos_reconciliation_tests {
    use super::*;

    /// Test successful reconciliation
    #[test]
    fn test_reconcile_success() {
        let client = MockKubeClient::new();
        let mut reconciler = MockReconciler::new(client);

        let protection = create_test_ddos_protection("test", "default");
        let result = reconciler.reconcile_ddos_protection(&protection);

        assert!(result.is_ok());
        let status = result.unwrap();
        assert_eq!(status.phase, Phase::Active);
        assert!(status.gateway_synced);
    }

    /// Test reconciliation with no backends fails
    #[test]
    fn test_reconcile_no_backends() {
        let client = MockKubeClient::new();
        let mut reconciler = MockReconciler::new(client);

        let mut protection = create_test_ddos_protection("test", "default");
        protection.spec.backends.clear();

        let result = reconciler.reconcile_ddos_protection(&protection);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("backend"));
    }

    /// Test reconciliation with invalid protection level
    #[test]
    fn test_reconcile_invalid_protection_level() {
        let client = MockKubeClient::new();
        let mut reconciler = MockReconciler::new(client);

        let mut protection = create_test_ddos_protection("test", "default");
        protection.spec.protection_level = 10; // Invalid

        let result = reconciler.reconcile_ddos_protection(&protection);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Protection level"));
    }

    /// Test worker count matches spec
    #[test]
    fn test_worker_count() {
        let client = MockKubeClient::new();
        let mut reconciler = MockReconciler::new(client);

        let mut protection = create_test_ddos_protection("test", "default");
        protection.spec.replicas = 5;

        let result = reconciler.reconcile_ddos_protection(&protection);

        assert!(result.is_ok());
        let status = result.unwrap();
        assert_eq!(status.desired_workers, 5);
        assert_eq!(status.ready_workers, 5);
    }

    /// Test backend count in status
    #[test]
    fn test_backend_count_in_status() {
        let client = MockKubeClient::new();
        let mut reconciler = MockReconciler::new(client);

        let protection = create_test_ddos_protection("test", "default");
        let result = reconciler.reconcile_ddos_protection(&protection);

        assert!(result.is_ok());
        let status = result.unwrap();
        assert_eq!(status.backend_count, 1);
    }

    /// Test observed generation is set
    #[test]
    fn test_observed_generation() {
        let client = MockKubeClient::new();
        let mut reconciler = MockReconciler::new(client);

        let protection = create_test_ddos_protection("test", "default");
        let result = reconciler.reconcile_ddos_protection(&protection);

        assert!(result.is_ok());
        let status = result.unwrap();
        assert_eq!(status.observed_generation, Some(1));
    }

    /// Test conditions are populated
    #[test]
    fn test_conditions() {
        let client = MockKubeClient::new();
        let mut reconciler = MockReconciler::new(client);

        let protection = create_test_ddos_protection("test", "default");
        let result = reconciler.reconcile_ddos_protection(&protection);

        assert!(result.is_ok());
        let status = result.unwrap();
        assert!(!status.conditions.is_empty());

        let ready_condition = status
            .conditions
            .iter()
            .find(|c| c.condition_type == "Ready");
        assert!(ready_condition.is_some());
        assert_eq!(ready_condition.unwrap().status, "True");
    }
}

// ============================================================================
// FilterRule Reconciliation Tests
// ============================================================================

#[cfg(test)]
mod filter_rule_reconciliation_tests {
    use super::*;

    /// Test successful filter rule reconciliation
    #[test]
    fn test_reconcile_filter_rule_success() {
        let client = MockKubeClient::new();
        let mut reconciler = MockReconciler::new(client);

        let rule = create_test_filter_rule("block-list", "default");
        let result = reconciler.reconcile_filter_rule(&rule);

        assert!(result.is_ok());
        let status = result.unwrap();
        assert!(status.active);
        assert!(status.gateway_synced);
    }

    /// Test filter rule with empty name fails
    #[test]
    fn test_reconcile_filter_rule_no_name() {
        let client = MockKubeClient::new();
        let mut reconciler = MockReconciler::new(client);

        let mut rule = create_test_filter_rule("test", "default");
        rule.spec.name = "".to_string();

        let result = reconciler.reconcile_filter_rule(&rule);

        assert!(result.is_err());
    }

    /// Test disabled rule is not active
    #[test]
    fn test_disabled_filter_rule() {
        let client = MockKubeClient::new();
        let mut reconciler = MockReconciler::new(client);

        let mut rule = create_test_filter_rule("test", "default");
        rule.spec.enabled = false;

        let result = reconciler.reconcile_filter_rule(&rule);

        assert!(result.is_ok());
        let status = result.unwrap();
        assert!(!status.active); // Disabled rules are not active
    }

    /// Test filter rule priority validation
    #[test]
    fn test_filter_rule_priority() {
        let client = MockKubeClient::new();
        let mut reconciler = MockReconciler::new(client);

        let mut rule = create_test_filter_rule("test", "default");
        rule.spec.priority = 150; // Invalid

        let result = reconciler.reconcile_filter_rule(&rule);

        assert!(result.is_err());
    }
}

// ============================================================================
// Deletion Handling Tests
// ============================================================================

#[cfg(test)]
mod deletion_tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;

    /// Test deletion handling
    #[test]
    fn test_handle_deletion() {
        let client = MockKubeClient::new();
        let mut reconciler = MockReconciler::new(client);

        let mut protection = create_test_ddos_protection("test", "default");
        protection.metadata.deletion_timestamp = Some(Time(chrono::Utc::now()));

        let result = reconciler.reconcile_ddos_protection(&protection);

        assert!(result.is_ok());
        let status = result.unwrap();
        assert_eq!(status.phase, Phase::Terminating);
    }

    /// Test cleanup on deletion
    #[test]
    fn test_cleanup_on_deletion() {
        let client = MockKubeClient::new();
        let mut reconciler = MockReconciler::new(client);

        // First create
        let protection = create_test_ddos_protection("test", "default");
        let _ = reconciler.reconcile_ddos_protection(&protection);

        // Then delete
        let mut to_delete = protection.clone();
        to_delete.metadata.deletion_timestamp = Some(Time(chrono::Utc::now()));

        let result = reconciler.reconcile_ddos_protection(&to_delete);

        assert!(result.is_ok());
        assert!(!reconciler.gateway_synced);
        assert_eq!(reconciler.workers_created, 0);
    }
}

// ============================================================================
// Phase Transition Tests
// ============================================================================

#[cfg(test)]
mod phase_transition_tests {
    use super::*;

    /// Test phase transitions
    #[test]
    fn test_phase_transitions() {
        // Pending -> Provisioning -> Active is the happy path
        let phases = vec![Phase::Pending, Phase::Provisioning, Phase::Active];

        for i in 0..phases.len() - 1 {
            // Each phase should be different
            assert_ne!(phases[i], phases[i + 1]);
        }
    }

    /// Test error phase
    #[test]
    fn test_error_phase() {
        assert_ne!(Phase::Error, Phase::Active);
        assert_ne!(Phase::Error, Phase::Pending);
    }

    /// Test degraded phase
    #[test]
    fn test_degraded_phase() {
        // Degraded is when some but not all workers are ready
        assert_ne!(Phase::Degraded, Phase::Active);
        assert_ne!(Phase::Degraded, Phase::Error);
    }
}

// ============================================================================
// Resource Owner Reference Tests
// ============================================================================

#[cfg(test)]
mod owner_reference_tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;

    /// Test owner reference creation
    #[test]
    fn test_create_owner_reference() {
        let protection = create_test_ddos_protection("test", "default");

        let owner_ref = OwnerReference {
            api_version: "pistonprotection.io/v1alpha1".to_string(),
            kind: "DDoSProtection".to_string(),
            name: protection.metadata.name.clone().unwrap_or_default(),
            uid: protection.metadata.uid.clone().unwrap_or_default(),
            controller: Some(true),
            block_owner_deletion: Some(true),
        };

        assert_eq!(owner_ref.kind, "DDoSProtection");
        assert!(owner_ref.controller.unwrap_or(false));
    }
}
