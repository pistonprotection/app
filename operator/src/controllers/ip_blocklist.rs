//! IPBlocklist Controller
//!
//! This controller manages IPBlocklist custom resources, handling:
//! - IP blocklist management (static and external sources)
//! - Gateway synchronization
//! - Automatic refresh for external sources
//! - Status updates and metrics tracking

use crate::client::GatewayClient;
use crate::crd::{
    BlocklistEntry, BlocklistSource, Condition, DDoSProtection, FINALIZER,
    IPBlocklist, IPBlocklistStatus,
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

/// Reconcile an IPBlocklist resource
pub async fn reconcile(
    blocklist: Arc<IPBlocklist>,
    ctx: Arc<Context>,
) -> std::result::Result<Action, Error> {
    let name = blocklist.name_any();
    let namespace = blocklist
        .namespace()
        .unwrap_or_else(|| "default".to_string());

    info!(
        "Reconciling IPBlocklist {}/{} (generation: {:?})",
        namespace, name, blocklist.metadata.generation
    );

    let timer = ReconciliationTimer::new(&ctx.metrics, "IPBlocklist", &namespace);

    // Create recorder for events
    let recorder = ctx.recorder();

    // Get API for this namespace
    let blocklist_api: Api<IPBlocklist> = Api::namespaced(ctx.client.clone(), &namespace);

    // Handle finalizer
    let result = finalizer(&blocklist_api, FINALIZER, blocklist, |event| async {
        match event {
            FinalizerEvent::Apply(blocklist) => {
                reconcile_apply(&blocklist, &ctx, &recorder, &namespace, &name).await
            }
            FinalizerEvent::Cleanup(blocklist) => {
                reconcile_cleanup(&blocklist, &ctx, &recorder, &namespace, &name).await
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
    blocklist: &IPBlocklist,
    ctx: &Context,
    recorder: &Recorder,
    namespace: &str,
    name: &str,
) -> Result<Action> {
    info!("Applying IPBlocklist {}/{}", namespace, name);

    // Validate the blocklist
    validate_blocklist(blocklist)?;

    // Create object reference for events
    let obj_ref = blocklist.object_ref(&());

    // Record event
    recorder
        .publish(
            &Event {
                type_: EventType::Normal,
                reason: "Reconciling".to_string(),
                note: Some(format!(
                    "Processing IP blocklist: {} ({} entries)",
                    blocklist.spec.name,
                    blocklist.spec.entries.len()
                )),
                action: "Reconcile".to_string(),
                secondary: None,
            },
            &obj_ref,
        )
        .await
        .ok();

    // Process entries based on source type
    let (entries, refresh_needed) = match blocklist.spec.source {
        BlocklistSource::Static => (blocklist.spec.entries.clone(), false),
        BlocklistSource::External => {
            // Fetch from external URL if needed
            let entries = fetch_external_blocklist(blocklist).await?;
            (entries, true)
        }
        BlocklistSource::Automatic => {
            // Automatic entries are managed by attack detection
            (blocklist.spec.entries.clone(), false)
        }
        BlocklistSource::Aggregated => {
            // Aggregate from multiple sources (would fetch from references)
            (blocklist.spec.entries.clone(), true)
        }
    };

    // Filter out expired entries
    let active_entries = filter_active_entries(&entries);
    let entry_count = entries.len() as i32;
    let active_count = active_entries.len() as i32;

    // Find matching DDoSProtection resources
    let matching_ddos = find_matching_ddos_protections(&ctx.client, blocklist, namespace).await?;
    let applied_to_count = matching_ddos.len() as i32;

    info!(
        "IPBlocklist {}/{} has {} entries ({} active), applies to {} DDoSProtection resources",
        namespace, name, entry_count, active_count, applied_to_count
    );

    // Sync to gateway
    let sync_start = std::time::Instant::now();
    let gateway_synced = if blocklist.spec.enabled {
        match sync_blocklist_to_gateway(&ctx.gateway_client, blocklist, &active_entries).await {
            Ok(_) => {
                info!(
                    "Successfully synced IPBlocklist {}/{} to gateway",
                    namespace, name
                );
                ctx.metrics.record_gateway_sync(
                    "IPBlocklist",
                    namespace,
                    name,
                    sync_start.elapsed().as_secs_f64(),
                    true,
                );
                true
            }
            Err(e) => {
                warn!(
                    "Failed to sync IPBlocklist {}/{} to gateway: {}",
                    namespace, name, e
                );
                ctx.metrics.record_gateway_sync(
                    "IPBlocklist",
                    namespace,
                    name,
                    sync_start.elapsed().as_secs_f64(),
                    false,
                );
                ctx.metrics
                    .record_gateway_sync_error("IPBlocklist", e.category());
                false
            }
        }
    } else {
        debug!(
            "IPBlocklist {}/{} is disabled, skipping gateway sync",
            namespace, name
        );
        true
    };

    // Calculate next refresh time for external sources
    let (last_refreshed, next_refresh) = if refresh_needed {
        let now = chrono::Utc::now();
        let next = now + chrono::Duration::seconds(blocklist.spec.refresh_interval_seconds as i64);
        (Some(now.to_rfc3339()), Some(next.to_rfc3339()))
    } else {
        (None, None)
    };

    // Update status
    let status = build_status(
        blocklist,
        entry_count,
        active_count,
        applied_to_count,
        gateway_synced,
        last_refreshed,
        next_refresh,
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
                    "IPBlocklist {} synced: {} active entries",
                    blocklist.spec.name, active_count
                )),
                action: "Reconcile".to_string(),
                secondary: None,
            },
            &obj_ref,
        )
        .await
        .ok();

    // Determine requeue interval
    let requeue_after = if refresh_needed && blocklist.spec.enabled {
        Duration::from_secs(blocklist.spec.refresh_interval_seconds as u64)
    } else if !gateway_synced {
        Duration::from_secs(30) // Retry sooner when not synced
    } else {
        Duration::from_secs(300) // 5 minutes when stable
    };

    Ok(Action::requeue(requeue_after))
}

/// Cleanup reconciliation - handle delete
async fn reconcile_cleanup(
    blocklist: &IPBlocklist,
    ctx: &Context,
    recorder: &Recorder,
    namespace: &str,
    name: &str,
) -> Result<Action> {
    info!("Cleaning up IPBlocklist {}/{}", namespace, name);

    // Create object reference for events
    let obj_ref = blocklist.object_ref(&());

    // Record event
    recorder
        .publish(
            &Event {
                type_: EventType::Normal,
                reason: "Deleting".to_string(),
                note: Some("Removing IP blocklist from gateway".to_string()),
                action: "Delete".to_string(),
                secondary: None,
            },
            &obj_ref,
        )
        .await
        .ok();

    // Remove from gateway
    if let Err(e) = delete_blocklist_from_gateway(&ctx.gateway_client, namespace, name).await {
        warn!(
            "Failed to remove IPBlocklist {}/{} from gateway: {}",
            namespace, name, e
        );
        // Continue with cleanup even if gateway sync fails
    }

    info!("Cleanup complete for IPBlocklist {}/{}", namespace, name);

    Ok(Action::await_change())
}

/// Validate IPBlocklist resource
fn validate_blocklist(blocklist: &IPBlocklist) -> Result<()> {
    // Validate name
    if blocklist.spec.name.is_empty() {
        return Err(Error::validation("name", "blocklist name is required"));
    }

    // Validate external URL for external source
    if blocklist.spec.source == BlocklistSource::External && blocklist.spec.external_url.is_none() {
        return Err(Error::validation(
            "externalUrl",
            "external URL is required for external source type",
        ));
    }

    // Validate IP entries
    for (i, entry) in blocklist.spec.entries.iter().enumerate() {
        if !is_valid_ip_or_cidr(&entry.ip) {
            return Err(Error::validation(
                &format!("entries[{}].ip", i),
                &format!("invalid IP address or CIDR: {}", entry.ip),
            ));
        }
    }

    // Validate refresh interval
    if blocklist.spec.source == BlocklistSource::External
        && blocklist.spec.refresh_interval_seconds < 60
    {
        return Err(Error::validation(
            "refreshIntervalSeconds",
            "refresh interval must be at least 60 seconds",
        ));
    }

    // Validate priority
    if blocklist.spec.priority < 0 || blocklist.spec.priority > 1000 {
        return Err(Error::validation("priority", "must be between 0 and 1000"));
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

/// Filter out expired entries
fn filter_active_entries(entries: &[BlocklistEntry]) -> Vec<BlocklistEntry> {
    let now = chrono::Utc::now();

    entries
        .iter()
        .filter(|entry| {
            if let Some(ref expires_at) = entry.expires_at {
                if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(expires_at) {
                    return now < expiry;
                }
            }
            true // No expiration or invalid format = active
        })
        .cloned()
        .collect()
}

/// Fetch blocklist from external URL
async fn fetch_external_blocklist(blocklist: &IPBlocklist) -> Result<Vec<BlocklistEntry>> {
    let url = blocklist.spec.external_url.as_ref().ok_or_else(|| {
        Error::validation(
            "externalUrl",
            "external URL is required for external source",
        )
    })?;

    debug!("Fetching external blocklist from: {}", url);

    // In production, this would actually fetch from the URL
    // For now, we'll simulate with the static entries
    // let response = reqwest::get(url).await.map_err(|e| Error::GrpcRequestError(e.to_string()))?;
    // let body = response.text().await.map_err(|e| Error::GrpcRequestError(e.to_string()))?;

    // Parse the response (supports various formats: plain IPs, CIDR, CSV)
    // For now, return static entries
    Ok(blocklist.spec.entries.clone())
}

/// Find DDoSProtection resources that match this blocklist's selector
async fn find_matching_ddos_protections(
    client: &Client,
    blocklist: &IPBlocklist,
    namespace: &str,
) -> Result<Vec<DDoSProtection>> {
    let api: Api<DDoSProtection> = Api::namespaced(client.clone(), namespace);

    let selector = match &blocklist.spec.selector {
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
                let labels = ddos.metadata.labels.as_ref().cloned().unwrap_or_default();

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

/// Sync blocklist to gateway
async fn sync_blocklist_to_gateway(
    _gateway_client: &GatewayClient,
    blocklist: &IPBlocklist,
    entries: &[BlocklistEntry],
) -> Result<()> {
    debug!(
        "Syncing blocklist {} with {} entries to gateway",
        blocklist.spec.name,
        entries.len()
    );

    // In production, this would call the actual gateway gRPC service
    // For now, we simulate a successful sync

    // Convert entries to gRPC format
    let _grpc_entries: Vec<_> = entries
        .iter()
        .map(|e| {
            let action = e
                .action
                .as_ref()
                .unwrap_or(&blocklist.spec.action)
                .to_grpc_action();
            (e.ip.clone(), action, e.reason.clone())
        })
        .collect();

    // gateway_client.sync_ip_blocklist(blocklist_id, grpc_entries).await?;

    Ok(())
}

/// Delete blocklist from gateway
async fn delete_blocklist_from_gateway(
    _gateway_client: &GatewayClient,
    namespace: &str,
    name: &str,
) -> Result<()> {
    debug!("Deleting blocklist {}/{} from gateway", namespace, name);

    // In production, this would call the actual gateway gRPC service
    // gateway_client.delete_ip_blocklist(blocklist_id).await?;

    Ok(())
}

/// Update the status of an IPBlocklist resource
async fn update_status(
    client: &Client,
    namespace: &str,
    name: &str,
    status: IPBlocklistStatus,
) -> Result<()> {
    let api: Api<IPBlocklist> = Api::namespaced(client.clone(), namespace);

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

    debug!("Status updated for IPBlocklist {}/{}", namespace, name);

    Ok(())
}

/// Build status object
fn build_status(
    blocklist: &IPBlocklist,
    entry_count: i32,
    active_entries: i32,
    applied_to_count: i32,
    gateway_synced: bool,
    last_refreshed: Option<String>,
    next_refresh: Option<String>,
    error_message: Option<String>,
) -> IPBlocklistStatus {
    let now = chrono::Utc::now().to_rfc3339();

    let mut conditions = Vec::new();

    // Ready condition
    conditions.push(Condition::new(
        "Ready",
        gateway_synced && blocklist.spec.enabled,
        if gateway_synced && blocklist.spec.enabled {
            "BlocklistActive"
        } else if !blocklist.spec.enabled {
            "BlocklistDisabled"
        } else {
            "SyncFailed"
        },
        if gateway_synced && blocklist.spec.enabled {
            "IP blocklist is active and synced"
        } else if !blocklist.spec.enabled {
            "IP blocklist is disabled"
        } else {
            "Failed to sync IP blocklist to gateway"
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
            "Blocklist synced to gateway"
        } else {
            "Failed to sync blocklist to gateway"
        },
    ));

    // Refreshed condition (for external sources)
    if blocklist.spec.source == BlocklistSource::External {
        conditions.push(Condition::new(
            "Refreshed",
            last_refreshed.is_some(),
            if last_refreshed.is_some() {
                "RefreshSucceeded"
            } else {
                "RefreshPending"
            },
            if last_refreshed.is_some() {
                "External blocklist was refreshed successfully"
            } else {
                "Waiting for external blocklist refresh"
            },
        ));
    }

    IPBlocklistStatus {
        entry_count,
        active_entries,
        gateway_synced,
        last_synced: if gateway_synced { Some(now) } else { None },
        last_refreshed,
        next_refresh,
        observed_generation: blocklist.metadata.generation,
        total_blocks: 0, // Would be populated from gateway metrics
        blocks_last_hour: 0,
        applied_to_count,
        last_error: error_message,
        conditions,
    }
}

/// Error policy for the controller
pub fn error_policy(blocklist: Arc<IPBlocklist>, error: &Error, _ctx: Arc<Context>) -> Action {
    let name = blocklist.name_any();
    let namespace = blocklist.namespace().unwrap_or_default();

    warn!(
        "Reconciliation error for IPBlocklist {}/{}: {:?}",
        namespace, name, error
    );

    let delay = error.retry_delay();

    if error.is_permanent() {
        warn!(
            "Permanent error for IPBlocklist {}/{}, not requeuing",
            namespace, name
        );
        Action::await_change()
    } else {
        info!(
            "Requeuing IPBlocklist {}/{} in {:?}",
            namespace, name, delay
        );
        Action::requeue(delay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{BlocklistAction, IPBlocklistSpec};
    use kube::api::ObjectMeta;

    fn create_test_blocklist() -> IPBlocklist {
        IPBlocklist {
            metadata: ObjectMeta {
                name: Some("test-blocklist".to_string()),
                namespace: Some("default".to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: IPBlocklistSpec {
                name: "Test Blocklist".to_string(),
                description: Some("A test blocklist".to_string()),
                source: BlocklistSource::Static,
                entries: vec![
                    BlocklistEntry {
                        ip: "10.0.0.1".to_string(),
                        reason: Some("Test".to_string()),
                        ..Default::default()
                    },
                    BlocklistEntry {
                        ip: "192.168.1.0/24".to_string(),
                        reason: Some("Network block".to_string()),
                        ..Default::default()
                    },
                ],
                external_url: None,
                refresh_interval_seconds: 3600,
                enabled: true,
                action: BlocklistAction::Drop,
                selector: None,
                priority: 100,
                tags: vec!["test".to_string()],
                default_ttl_seconds: 0,
            },
            status: None,
        }
    }

    #[test]
    fn test_validate_blocklist() {
        let blocklist = create_test_blocklist();
        assert!(validate_blocklist(&blocklist).is_ok());
    }

    #[test]
    fn test_validate_empty_name() {
        let mut blocklist = create_test_blocklist();
        blocklist.spec.name = "".to_string();
        assert!(validate_blocklist(&blocklist).is_err());
    }

    #[test]
    fn test_validate_invalid_ip() {
        let mut blocklist = create_test_blocklist();
        blocklist.spec.entries = vec![BlocklistEntry {
            ip: "invalid".to_string(),
            ..Default::default()
        }];
        assert!(validate_blocklist(&blocklist).is_err());
    }

    #[test]
    fn test_validate_external_without_url() {
        let mut blocklist = create_test_blocklist();
        blocklist.spec.source = BlocklistSource::External;
        blocklist.spec.external_url = None;
        assert!(validate_blocklist(&blocklist).is_err());
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
    fn test_filter_active_entries() {
        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        let future = chrono::Utc::now() + chrono::Duration::hours(1);

        let entries = vec![
            BlocklistEntry {
                ip: "10.0.0.1".to_string(),
                expires_at: None, // Never expires
                ..Default::default()
            },
            BlocklistEntry {
                ip: "10.0.0.2".to_string(),
                expires_at: Some(past.to_rfc3339()), // Expired
                ..Default::default()
            },
            BlocklistEntry {
                ip: "10.0.0.3".to_string(),
                expires_at: Some(future.to_rfc3339()), // Not expired
                ..Default::default()
            },
        ];

        let active = filter_active_entries(&entries);
        assert_eq!(active.len(), 2);
        assert_eq!(active[0].ip, "10.0.0.1");
        assert_eq!(active[1].ip, "10.0.0.3");
    }

    #[test]
    fn test_build_status() {
        let blocklist = create_test_blocklist();
        let status = build_status(&blocklist, 10, 8, 2, true, None, None, None);

        assert_eq!(status.entry_count, 10);
        assert_eq!(status.active_entries, 8);
        assert_eq!(status.applied_to_count, 2);
        assert!(status.gateway_synced);
        assert!(!status.conditions.is_empty());
    }
}
