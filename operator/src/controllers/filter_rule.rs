//! FilterRule Controller
//!
//! This controller manages FilterRule custom resources, handling:
//! - Rule validation and processing
//! - Gateway synchronization
//! - Selector matching with DDoSProtection resources
//! - Status updates

use chrono::Datelike;

use crate::client::GatewayClient;
use crate::crd::{
    Condition, DDoSProtection, FINALIZER, FilterRule, FilterRuleStatus, FilterRuleType,
};
use crate::error::{Error, Result};
use crate::metrics::{Metrics, ReconciliationTimer};

use kube::{
    Client, Resource, ResourceExt,
    api::{Api, ListParams, Patch, PatchParams},
    runtime::{
        controller::Action,
        events::{Event, EventType, Recorder, Reporter},
        finalizer::{Event as FinalizerEvent, finalizer},
    },
};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Context shared across reconciliation calls
pub struct Context {
    /// Kubernetes client
    pub client: Client,
    /// Gateway gRPC client
    pub gateway_client: GatewayClient,
    /// Metrics collector
    pub metrics: Arc<Metrics>,
    /// Event reporter
    pub reporter: Reporter,
}

impl Context {
    /// Create a new context
    pub fn new(
        client: Client,
        gateway_client: GatewayClient,
        metrics: Arc<Metrics>,
        reporter: Reporter,
    ) -> Self {
        Self {
            client,
            gateway_client,
            metrics,
            reporter,
        }
    }

    /// Create a recorder for events
    fn recorder(&self) -> Recorder {
        Recorder::new(self.client.clone(), self.reporter.clone())
    }
}

/// Reconcile a FilterRule resource
pub async fn reconcile(
    rule: Arc<FilterRule>,
    ctx: Arc<Context>,
) -> std::result::Result<Action, Error> {
    let name = rule.name_any();
    let namespace = rule.namespace().unwrap_or_else(|| "default".to_string());

    info!(
        "Reconciling FilterRule {}/{} (generation: {:?})",
        namespace, name, rule.metadata.generation
    );

    let timer = ReconciliationTimer::new(&ctx.metrics, "FilterRule", &namespace);

    // Create recorder for events
    let recorder = ctx.recorder();

    // Get API for this namespace
    let rule_api: Api<FilterRule> = Api::namespaced(ctx.client.clone(), &namespace);

    // Handle finalizer
    let result = finalizer(&rule_api, FINALIZER, rule, |event| async {
        match event {
            FinalizerEvent::Apply(rule) => {
                reconcile_apply(&rule, &ctx, &recorder, &namespace, &name).await
            }
            FinalizerEvent::Cleanup(rule) => {
                reconcile_cleanup(&rule, &ctx, &recorder, &namespace, &name).await
            }
        }
    })
    .await;

    match result {
        Ok(action) => {
            timer.success();
            Ok(action)
        }
        Err(e) => {
            let error = match e {
                kube::runtime::finalizer::Error::ApplyFailed(e) => e,
                kube::runtime::finalizer::Error::CleanupFailed(e) => e,
                kube::runtime::finalizer::Error::AddFinalizer(e) => Error::KubeError(e),
                kube::runtime::finalizer::Error::RemoveFinalizer(e) => Error::KubeError(e),
                kube::runtime::finalizer::Error::UnnamedObject => {
                    Error::Permanent("Resource has no name".to_string())
                }
                kube::runtime::finalizer::Error::InvalidFinalizer => {
                    Error::Permanent("Invalid finalizer".to_string())
                }
            };
            timer.error(error.category());
            Err(error)
        }
    }
}

/// Apply reconciliation - handle create/update
async fn reconcile_apply(
    rule: &FilterRule,
    ctx: &Context,
    recorder: &Recorder,
    namespace: &str,
    name: &str,
) -> Result<Action> {
    info!("Applying FilterRule {}/{}", namespace, name);

    // Validate the rule
    validate_filter_rule(rule)?;

    // Check if rule is expired
    if is_rule_expired(rule) {
        info!(
            "FilterRule {}/{} has expired, skipping sync",
            namespace, name
        );
        let status = build_status(rule, false, false, Some("Rule has expired".to_string()));
        update_status(&ctx.client, namespace, name, status).await?;
        return Ok(Action::await_change());
    }

    // Check if rule should be active based on schedule
    let should_be_active = rule.spec.enabled && is_rule_scheduled_active(rule);

    // Create object reference for events
    let obj_ref = rule.object_ref(&());

    // Record event
    recorder
        .publish(
            &Event {
                type_: EventType::Normal,
                reason: "Reconciling".to_string(),
                note: Some(format!("Processing filter rule: {}", rule.spec.name)),
                action: "Reconcile".to_string(),
                secondary: None,
            },
            &obj_ref,
        )
        .await
        .ok();

    // Find matching DDoSProtection resources
    let matching_ddos = find_matching_ddos_protections(&ctx.client, rule, namespace).await?;
    let applied_to_count = matching_ddos.len() as i32;

    info!(
        "FilterRule {}/{} matches {} DDoSProtection resources",
        namespace, name, applied_to_count
    );

    // Sync to gateway
    let sync_start = std::time::Instant::now();
    let gateway_synced = if should_be_active {
        match ctx.gateway_client.sync_filter_rule(rule).await {
            Ok(result) => {
                info!(
                    "Successfully synced FilterRule {}/{} to gateway: {}",
                    namespace, name, result.message
                );
                ctx.metrics.record_gateway_sync(
                    "FilterRule",
                    namespace,
                    name,
                    sync_start.elapsed().as_secs_f64(),
                    true,
                );
                true
            }
            Err(e) => {
                warn!(
                    "Failed to sync FilterRule {}/{} to gateway: {}",
                    namespace, name, e
                );
                ctx.metrics.record_gateway_sync(
                    "FilterRule",
                    namespace,
                    name,
                    sync_start.elapsed().as_secs_f64(),
                    false,
                );
                ctx.metrics
                    .record_gateway_sync_error("FilterRule", e.category());
                false
            }
        }
    } else {
        debug!(
            "FilterRule {}/{} is not active, skipping gateway sync",
            namespace, name
        );
        true // Consider it "synced" if we intentionally skip
    };

    // Update status
    let status = build_status_full(
        rule,
        should_be_active,
        gateway_synced,
        applied_to_count,
        None,
    );
    update_status(&ctx.client, namespace, name, status).await?;

    // Record success event
    recorder
        .publish(
            &Event {
                type_: EventType::Normal,
                reason: "Reconciled".to_string(),
                note: Some(format!(
                    "FilterRule {} applied to {} protection resources",
                    rule.spec.name, applied_to_count
                )),
                action: "Reconcile".to_string(),
                secondary: None,
            },
            &obj_ref,
        )
        .await
        .ok();

    // Determine requeue interval
    let requeue_after = if gateway_synced {
        // Check if rule has a schedule that needs periodic checking
        if rule.spec.schedule.is_some() {
            Duration::from_secs(60) // Check schedule every minute
        } else if rule.spec.expires_at.is_some() {
            Duration::from_secs(60) // Check expiration every minute
        } else {
            Duration::from_secs(300) // 5 minutes when stable
        }
    } else {
        Duration::from_secs(30) // Retry sooner when not synced
    };

    Ok(Action::requeue(requeue_after))
}

/// Cleanup reconciliation - handle delete
async fn reconcile_cleanup(
    rule: &FilterRule,
    ctx: &Context,
    recorder: &Recorder,
    namespace: &str,
    name: &str,
) -> Result<Action> {
    info!("Cleaning up FilterRule {}/{}", namespace, name);

    // Create object reference for events
    let obj_ref = rule.object_ref(&());

    // Record event
    recorder
        .publish(
            &Event {
                type_: EventType::Normal,
                reason: "Deleting".to_string(),
                note: Some("Removing filter rule from gateway".to_string()),
                action: "Delete".to_string(),
                secondary: None,
            },
            &obj_ref,
        )
        .await
        .ok();

    // Remove from gateway
    if let Err(e) = ctx.gateway_client.delete_filter_rule(namespace, name).await {
        warn!(
            "Failed to remove FilterRule {}/{} from gateway: {}",
            namespace, name, e
        );
        // Continue with cleanup even if gateway sync fails
    }

    info!("Cleanup complete for FilterRule {}/{}", namespace, name);

    Ok(Action::await_change())
}

/// Validate FilterRule resource
fn validate_filter_rule(rule: &FilterRule) -> Result<()> {
    // Validate name
    if rule.spec.name.is_empty() {
        return Err(Error::validation("name", "rule name is required"));
    }

    // Validate IP ranges
    for ip_range in &rule.spec.config.ip_ranges {
        if !is_valid_ip_or_cidr(ip_range) {
            return Err(Error::validation(
                "config.ipRanges",
                &format!("invalid IP range: {}", ip_range),
            ));
        }
    }

    // Validate country codes
    for country in &rule.spec.config.countries {
        if country.len() != 2 {
            return Err(Error::validation(
                "config.countries",
                &format!(
                    "invalid country code: {} (must be ISO 3166-1 alpha-2)",
                    country
                ),
            ));
        }
    }

    // Validate rate limit config for rate limit rules
    if rule.spec.rule_type == FilterRuleType::RateLimit && rule.spec.config.rate_limit.is_none() {
        return Err(Error::validation(
            "config.rateLimit",
            "rate limit configuration is required for rate_limit rule type",
        ));
    }

    // Validate port ranges
    for port_range in &rule.spec.config.ports {
        if port_range.start > port_range.end {
            return Err(Error::validation(
                "config.ports",
                &format!(
                    "invalid port range: {}-{} (start must be <= end)",
                    port_range.start, port_range.end
                ),
            ));
        }
    }

    // Validate priority
    if rule.spec.priority < 0 || rule.spec.priority > 100 {
        return Err(Error::validation("priority", "must be between 0 and 100"));
    }

    Ok(())
}

/// Check if string is a valid IP address or CIDR range
fn is_valid_ip_or_cidr(s: &str) -> bool {
    if s.contains('/') {
        // CIDR notation
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 {
            return false;
        }

        let ip = match parts[0].parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => return false,
        };

        let max_prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        let prefix_valid = parts[1]
            .parse::<u8>()
            .map(|p| p <= max_prefix)
            .unwrap_or(false);

        prefix_valid
    } else {
        s.parse::<IpAddr>().is_ok()
    }
}

/// Check if rule has expired
fn is_rule_expired(rule: &FilterRule) -> bool {
    if let Some(ref expires_at) = rule.spec.expires_at {
        if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(expires_at) {
            return chrono::Utc::now() > expiry;
        }
    }
    false
}

/// Check if rule should be active based on schedule
fn is_rule_scheduled_active(rule: &FilterRule) -> bool {
    let schedule = match &rule.spec.schedule {
        Some(s) => s,
        None => return true, // No schedule means always active
    };

    let now = chrono::Utc::now();

    // Check days of week
    if !schedule.days_of_week.is_empty() {
        let today = now.weekday().num_days_from_sunday() as u8;
        if !schedule.days_of_week.contains(&today) {
            return false;
        }
    }

    // Check time range
    if let (Some(start_time), Some(end_time)) = (&schedule.start_time, &schedule.end_time) {
        let current_time = now.format("%H:%M").to_string();

        // Simple string comparison works for HH:MM format
        if current_time < *start_time || current_time > *end_time {
            return false;
        }
    }

    true
}

/// Find DDoSProtection resources that match this rule's selector
async fn find_matching_ddos_protections(
    client: &Client,
    rule: &FilterRule,
    namespace: &str,
) -> Result<Vec<DDoSProtection>> {
    let api: Api<DDoSProtection> = Api::namespaced(client.clone(), namespace);

    let selector = match &rule.spec.selector {
        Some(s) => s,
        None => {
            // No selector means match all in namespace
            let list = api
                .list(&ListParams::default())
                .await
                .map_err(Error::KubeError)?;
            return Ok(list.items);
        }
    };

    // Build label selector string
    let label_selector: String = selector
        .match_labels
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join(",");

    let list_params = if label_selector.is_empty() {
        ListParams::default()
    } else {
        ListParams::default().labels(&label_selector)
    };

    let list = api.list(&list_params).await.map_err(Error::KubeError)?;

    // Apply match expressions if any
    let filtered = list
        .items
        .into_iter()
        .filter(|ddos| {
            for expr in &selector.match_expressions {
                let labels = ddos
                    .metadata
                    .labels
                    .as_ref()
                    .map(|l| l.clone())
                    .unwrap_or_default();

                let matches = match expr.operator.as_str() {
                    "In" => labels
                        .get(&expr.key)
                        .map(|v| expr.values.contains(v))
                        .unwrap_or(false),
                    "NotIn" => labels
                        .get(&expr.key)
                        .map(|v| !expr.values.contains(v))
                        .unwrap_or(true),
                    "Exists" => labels.contains_key(&expr.key),
                    "DoesNotExist" => !labels.contains_key(&expr.key),
                    _ => true,
                };

                if !matches {
                    return false;
                }
            }
            true
        })
        .collect();

    Ok(filtered)
}

/// Update the status of a FilterRule resource
async fn update_status(
    client: &Client,
    namespace: &str,
    name: &str,
    status: FilterRuleStatus,
) -> Result<()> {
    let api: Api<FilterRule> = Api::namespaced(client.clone(), namespace);

    let patch = serde_json::json!({
        "status": status
    });

    api.patch_status(
        name,
        &PatchParams::apply("pistonprotection-operator"),
        &Patch::Merge(&patch),
    )
    .await
    .map_err(Error::KubeError)?;

    debug!("Status updated for FilterRule {}/{}", namespace, name);

    Ok(())
}

/// Build status object (simple version)
fn build_status(
    rule: &FilterRule,
    active: bool,
    gateway_synced: bool,
    error_message: Option<String>,
) -> FilterRuleStatus {
    build_status_full(rule, active, gateway_synced, 0, error_message)
}

/// Build status object with all fields
fn build_status_full(
    rule: &FilterRule,
    active: bool,
    gateway_synced: bool,
    applied_to_count: i32,
    error_message: Option<String>,
) -> FilterRuleStatus {
    let now = chrono::Utc::now().to_rfc3339();

    let mut conditions = Vec::new();

    // Ready condition
    conditions.push(Condition::new(
        "Ready",
        active && gateway_synced,
        if active && gateway_synced {
            "RuleActive"
        } else if !active {
            "RuleDisabled"
        } else {
            "SyncFailed"
        },
        if active && gateway_synced {
            "Filter rule is active and synced"
        } else if !active {
            "Filter rule is disabled or scheduled inactive"
        } else {
            "Failed to sync filter rule to gateway"
        },
    ));

    // GatewaySynced condition
    conditions.push(Condition::new(
        "GatewaySynced",
        gateway_synced,
        if gateway_synced {
            "SyncSucceeded"
        } else {
            "SyncFailed"
        },
        if gateway_synced {
            "Rule synced to gateway"
        } else {
            "Failed to sync rule to gateway"
        },
    ));

    // Validated condition
    conditions.push(Condition::new(
        "Validated",
        error_message.is_none(),
        if error_message.is_none() {
            "ValidationPassed"
        } else {
            "ValidationFailed"
        },
        error_message.as_deref().unwrap_or("Rule validation passed"),
    ));

    FilterRuleStatus {
        active,
        match_count: 0, // Will be populated from gateway metrics
        last_match: None,
        observed_generation: rule.metadata.generation,
        gateway_synced,
        last_synced: if gateway_synced {
            Some(now.clone())
        } else {
            None
        },
        last_error: error_message,
        applied_to_count,
        conditions,
    }
}

/// Error policy for the controller
pub fn error_policy(rule: Arc<FilterRule>, error: &Error, _ctx: Arc<Context>) -> Action {
    let name = rule.name_any();
    let namespace = rule.namespace().unwrap_or_default();

    warn!(
        "Reconciliation error for FilterRule {}/{}: {:?}",
        namespace, name, error
    );

    let delay = error.retry_delay();

    if error.is_permanent() {
        warn!(
            "Permanent error for FilterRule {}/{}, not requeuing",
            namespace, name
        );
        Action::await_change()
    } else {
        info!("Requeuing FilterRule {}/{} in {:?}", namespace, name, delay);
        Action::requeue(delay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{FilterAction, FilterRuleConfig};
    use kube::api::ObjectMeta;

    fn create_test_rule() -> FilterRule {
        FilterRule {
            metadata: ObjectMeta {
                name: Some("test-rule".to_string()),
                namespace: Some("default".to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: crate::crd::FilterRuleSpec {
                name: "Test Rule".to_string(),
                description: Some("A test rule".to_string()),
                rule_type: FilterRuleType::IpBlocklist,
                action: FilterAction::Drop,
                priority: 50,
                config: FilterRuleConfig {
                    ip_ranges: vec!["10.0.0.0/8".to_string()],
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
            status: None,
        }
    }

    #[test]
    fn test_validate_filter_rule() {
        let rule = create_test_rule();
        assert!(validate_filter_rule(&rule).is_ok());
    }

    #[test]
    fn test_validate_empty_name() {
        let mut rule = create_test_rule();
        rule.spec.name = "".to_string();
        assert!(validate_filter_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_invalid_ip() {
        let mut rule = create_test_rule();
        rule.spec.config.ip_ranges = vec!["invalid".to_string()];
        assert!(validate_filter_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_invalid_country() {
        let mut rule = create_test_rule();
        rule.spec.config.countries = vec!["USA".to_string()]; // Should be 2 chars
        assert!(validate_filter_rule(&rule).is_err());
    }

    #[test]
    fn test_is_valid_ip_or_cidr() {
        assert!(is_valid_ip_or_cidr("10.0.0.1"));
        assert!(is_valid_ip_or_cidr("10.0.0.0/8"));
        assert!(is_valid_ip_or_cidr("192.168.1.0/24"));
        assert!(is_valid_ip_or_cidr("::1"));
        assert!(is_valid_ip_or_cidr("2001:db8::/32"));

        assert!(!is_valid_ip_or_cidr("invalid"));
        assert!(!is_valid_ip_or_cidr("10.0.0.0/"));
        assert!(!is_valid_ip_or_cidr("10.0.0.0/33")); // Invalid prefix for IPv4
    }

    #[test]
    fn test_is_rule_expired() {
        let mut rule = create_test_rule();

        // No expiration
        assert!(!is_rule_expired(&rule));

        // Future expiration
        let future = chrono::Utc::now() + chrono::Duration::hours(1);
        rule.spec.expires_at = Some(future.to_rfc3339());
        assert!(!is_rule_expired(&rule));

        // Past expiration
        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        rule.spec.expires_at = Some(past.to_rfc3339());
        assert!(is_rule_expired(&rule));
    }

    #[test]
    fn test_is_rule_scheduled_active() {
        let mut rule = create_test_rule();

        // No schedule means always active
        assert!(is_rule_scheduled_active(&rule));

        // With schedule
        rule.spec.schedule = Some(crate::crd::ScheduleSpec {
            cron: None,
            days_of_week: vec![0, 1, 2, 3, 4, 5, 6], // All days
            start_time: Some("00:00".to_string()),
            end_time: Some("23:59".to_string()),
            timezone: "UTC".to_string(),
        });
        assert!(is_rule_scheduled_active(&rule));
    }

    #[test]
    fn test_validate_priority() {
        let mut rule = create_test_rule();

        rule.spec.priority = 0;
        assert!(validate_filter_rule(&rule).is_ok());

        rule.spec.priority = 100;
        assert!(validate_filter_rule(&rule).is_ok());

        rule.spec.priority = 101;
        assert!(validate_filter_rule(&rule).is_err());

        rule.spec.priority = -1;
        assert!(validate_filter_rule(&rule).is_err());
    }
}
