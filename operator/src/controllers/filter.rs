//! FilterRule controller implementation

use crate::{FilterRule, FilterRuleStatus, Error};
use kube::{
    api::{Api, Patch, PatchParams},
    Client, ResourceExt,
};
use tracing::info;

/// Reconcile a FilterRule resource
pub async fn reconcile(
    client: &Client,
    rule: &FilterRule,
) -> Result<FilterRuleStatus, Error> {
    let name = rule.name_any();
    let namespace = rule.namespace().unwrap_or_default();

    info!("Processing FilterRule {}/{}", namespace, name);

    // Validate rule configuration
    validate_rule(rule)?;

    // Apply rule to workers
    apply_rule_to_workers(client, rule).await?;

    Ok(FilterRuleStatus {
        active: true,
        match_count: 0,
        last_match: None,
    })
}

/// Validate filter rule configuration
fn validate_rule(rule: &FilterRule) -> Result<(), Error> {
    // Validate IP ranges if present
    for ip_range in &rule.spec.config.ip_ranges {
        if !is_valid_ip_or_cidr(ip_range) {
            return Err(Error::InvalidResource(format!(
                "Invalid IP range: {}",
                ip_range
            )));
        }
    }

    // Validate country codes if present
    for country in &rule.spec.config.countries {
        if country.len() != 2 {
            return Err(Error::InvalidResource(format!(
                "Invalid country code: {} (must be ISO 3166-1 alpha-2)",
                country
            )));
        }
    }

    Ok(())
}

/// Check if string is a valid IP address or CIDR range
fn is_valid_ip_or_cidr(s: &str) -> bool {
    // Simple validation - could be more thorough
    if s.contains('/') {
        // CIDR notation
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 {
            return false;
        }
        parts[0].parse::<std::net::IpAddr>().is_ok()
            && parts[1].parse::<u8>().is_ok()
    } else {
        s.parse::<std::net::IpAddr>().is_ok()
    }
}

/// Apply filter rule to all relevant workers
async fn apply_rule_to_workers(
    _client: &Client,
    rule: &FilterRule,
) -> Result<(), Error> {
    info!(
        "Applying filter rule {} with action {:?}",
        rule.spec.name, rule.spec.action
    );

    // In a real implementation, this would:
    // 1. Find all DDoSProtection resources matching the selector
    // 2. For each matching resource, find the worker pods
    // 3. Send the filter rule configuration to each worker via gRPC or HTTP

    Ok(())
}
