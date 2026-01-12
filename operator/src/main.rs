//! PistonProtection Kubernetes Operator
//!
//! Manages DDoS protection resources in Kubernetes clusters.

use anyhow::Result;
use futures::StreamExt;
use kube::{
    api::{Api, ListParams, Patch, PatchParams, ResourceExt},
    runtime::{
        controller::{Action, Controller},
        finalizer::{finalizer, Event},
        watcher::Config,
    },
    Client, CustomResource, CustomResourceExt,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tracing::{error, info, warn};

mod controllers;
mod error;
mod metrics;

use error::Error;

/// DDoSProtection Custom Resource Definition
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "pistonprotection.io",
    version = "v1alpha1",
    kind = "DDoSProtection",
    namespaced,
    status = "DDoSProtectionStatus",
    shortname = "ddos",
    printcolumn = r#"{"name":"Status", "type":"string", "jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Backends", "type":"integer", "jsonPath":".status.backendCount"}"#,
    printcolumn = r#"{"name":"Age", "type":"date", "jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct DDoSProtectionSpec {
    /// Backends to protect
    pub backends: Vec<BackendSpec>,

    /// Protection level (1-5, higher is stricter)
    #[serde(default = "default_protection_level")]
    pub protection_level: u8,

    /// Rate limiting configuration
    #[serde(default)]
    pub rate_limit: Option<RateLimitSpec>,

    /// Protocol-specific settings
    #[serde(default)]
    pub protocol: Option<ProtocolSpec>,

    /// Geographic filtering
    #[serde(default)]
    pub geo_filter: Option<GeoFilterSpec>,

    /// Worker node selector
    #[serde(default)]
    pub node_selector: Option<std::collections::BTreeMap<String, String>>,

    /// Number of worker replicas
    #[serde(default = "default_replicas")]
    pub replicas: i32,
}

fn default_protection_level() -> u8 {
    3
}

fn default_replicas() -> i32 {
    2
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackendSpec {
    /// Backend name
    pub name: String,

    /// Backend address (IP:port or hostname:port)
    pub address: String,

    /// Protocol type
    pub protocol: Protocol,

    /// Health check configuration
    #[serde(default)]
    pub health_check: Option<HealthCheckSpec>,

    /// Backend-specific rate limit (overrides global)
    #[serde(default)]
    pub rate_limit: Option<RateLimitSpec>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Http,
    Https,
    MinecraftJava,
    MinecraftBedrock,
    Quic,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitSpec {
    /// Packets per second limit per IP
    pub pps_per_ip: u64,

    /// Burst size
    pub burst: u64,

    /// Global PPS limit
    #[serde(default)]
    pub global_pps: Option<u64>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolSpec {
    /// Enable Minecraft protocol validation
    #[serde(default)]
    pub minecraft_validation: bool,

    /// Minecraft protocol version range
    #[serde(default)]
    pub minecraft_versions: Option<MinecraftVersionRange>,

    /// Enable QUIC protocol handling
    #[serde(default)]
    pub quic_enabled: bool,

    /// Enable TCP SYN cookie protection
    #[serde(default = "default_true")]
    pub syn_cookies: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MinecraftVersionRange {
    pub min: u32,
    pub max: u32,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GeoFilterSpec {
    /// Mode: allow or deny
    pub mode: GeoFilterMode,

    /// Country codes (ISO 3166-1 alpha-2)
    pub countries: Vec<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum GeoFilterMode {
    Allow,
    Deny,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HealthCheckSpec {
    /// Health check interval in seconds
    #[serde(default = "default_interval")]
    pub interval_seconds: u32,

    /// Health check timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u32,

    /// Unhealthy threshold
    #[serde(default = "default_threshold")]
    pub unhealthy_threshold: u32,
}

fn default_interval() -> u32 {
    10
}

fn default_timeout() -> u32 {
    5
}

fn default_threshold() -> u32 {
    3
}

/// Status of the DDoSProtection resource
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DDoSProtectionStatus {
    /// Current phase
    pub phase: String,

    /// Number of protected backends
    pub backend_count: i32,

    /// Number of ready worker pods
    pub ready_workers: i32,

    /// Last update timestamp
    pub last_updated: Option<String>,

    /// Conditions
    #[serde(default)]
    pub conditions: Vec<Condition>,

    /// Metrics summary
    #[serde(default)]
    pub metrics: Option<MetricsSummary>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    pub r#type: String,
    pub status: String,
    pub reason: String,
    pub message: String,
    pub last_transition_time: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MetricsSummary {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub avg_latency_ms: f64,
}

/// FilterRule Custom Resource Definition
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "pistonprotection.io",
    version = "v1alpha1",
    kind = "FilterRule",
    namespaced,
    status = "FilterRuleStatus",
    shortname = "fr"
)]
#[serde(rename_all = "camelCase")]
pub struct FilterRuleSpec {
    /// Rule name
    pub name: String,

    /// Rule type
    pub rule_type: FilterRuleType,

    /// Action to take
    pub action: FilterAction,

    /// Priority (higher = processed first)
    #[serde(default = "default_priority")]
    pub priority: i32,

    /// Rule configuration
    pub config: FilterRuleConfig,

    /// Selector for DDoSProtection resources this rule applies to
    #[serde(default)]
    pub selector: Option<LabelSelector>,
}

fn default_priority() -> i32 {
    50
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FilterRuleType {
    IpBlocklist,
    IpAllowlist,
    RateLimit,
    GeoBlock,
    ProtocolValidation,
    SynFlood,
    UdpAmplification,
    Custom,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum FilterAction {
    Drop,
    Allow,
    RateLimit,
    Log,
    Challenge,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FilterRuleConfig {
    /// IP addresses or CIDR ranges
    #[serde(default)]
    pub ip_ranges: Vec<String>,

    /// Country codes for geo filtering
    #[serde(default)]
    pub countries: Vec<String>,

    /// Rate limit settings
    #[serde(default)]
    pub rate_limit: Option<RateLimitSpec>,

    /// Custom eBPF program (base64 encoded)
    #[serde(default)]
    pub custom_program: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelector {
    #[serde(default)]
    pub match_labels: std::collections::BTreeMap<String, String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FilterRuleStatus {
    pub active: bool,
    pub match_count: u64,
    pub last_match: Option<String>,
}

/// Operator context
struct Context {
    client: Client,
    metrics: metrics::Metrics,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("pistonprotection_operator=info".parse()?)
                .add_directive("kube=info".parse()?),
        )
        .json()
        .init();

    info!("Starting PistonProtection Operator");

    // Create Kubernetes client
    let client = Client::try_default().await?;
    info!("Connected to Kubernetes cluster");

    // Initialize metrics
    let metrics = metrics::Metrics::new();

    // Create context
    let ctx = Arc::new(Context { client: client.clone(), metrics });

    // Create APIs
    let ddos_api: Api<DDoSProtection> = Api::all(client.clone());
    let filter_api: Api<FilterRule> = Api::all(client.clone());

    // Start DDoSProtection controller
    let ddos_controller = Controller::new(ddos_api, Config::default())
        .run(reconcile_ddos, error_policy, ctx.clone())
        .for_each(|res| async move {
            match res {
                Ok(o) => info!("Reconciled DDoSProtection: {:?}", o),
                Err(e) => error!("Reconcile error: {:?}", e),
            }
        });

    // Start FilterRule controller
    let filter_controller = Controller::new(filter_api, Config::default())
        .run(reconcile_filter, error_policy, ctx.clone())
        .for_each(|res| async move {
            match res {
                Ok(o) => info!("Reconciled FilterRule: {:?}", o),
                Err(e) => error!("Reconcile error: {:?}", e),
            }
        });

    // Run controllers concurrently
    tokio::select! {
        _ = ddos_controller => {},
        _ = filter_controller => {},
    }

    Ok(())
}

/// Reconcile DDoSProtection resources
async fn reconcile_ddos(
    ddos: Arc<DDoSProtection>,
    ctx: Arc<Context>,
) -> Result<Action, Error> {
    let name = ddos.name_any();
    let namespace = ddos.namespace().unwrap_or_default();

    info!("Reconciling DDoSProtection {}/{}", namespace, name);
    ctx.metrics.reconciliations_total.inc();

    let client = &ctx.client;

    // Check if resource is being deleted
    if ddos.metadata.deletion_timestamp.is_some() {
        info!("DDoSProtection {}/{} is being deleted", namespace, name);
        return Ok(Action::await_change());
    }

    // Reconciliation logic
    // 1. Create/update worker Deployment
    // 2. Create/update worker Service
    // 3. Update ConfigMap with backend configuration
    // 4. Update status

    // Update status
    let status = DDoSProtectionStatus {
        phase: "Active".to_string(),
        backend_count: ddos.spec.backends.len() as i32,
        ready_workers: ddos.spec.replicas,
        last_updated: Some(chrono::Utc::now().to_rfc3339()),
        conditions: vec![Condition {
            r#type: "Ready".to_string(),
            status: "True".to_string(),
            reason: "Reconciled".to_string(),
            message: "DDoS protection is active".to_string(),
            last_transition_time: chrono::Utc::now().to_rfc3339(),
        }],
        metrics: None,
    };

    let api: Api<DDoSProtection> = Api::namespaced(client.clone(), &namespace);
    let patch = serde_json::json!({
        "status": status
    });

    api.patch_status(
        &name,
        &PatchParams::apply("pistonprotection-operator"),
        &Patch::Merge(&patch),
    )
    .await
    .map_err(Error::KubeError)?;

    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Reconcile FilterRule resources
async fn reconcile_filter(
    rule: Arc<FilterRule>,
    ctx: Arc<Context>,
) -> Result<Action, Error> {
    let name = rule.name_any();
    let namespace = rule.namespace().unwrap_or_default();

    info!("Reconciling FilterRule {}/{}", namespace, name);

    // Update status
    let status = FilterRuleStatus {
        active: true,
        match_count: 0,
        last_match: None,
    };

    let api: Api<FilterRule> = Api::namespaced(ctx.client.clone(), &namespace);
    let patch = serde_json::json!({
        "status": status
    });

    api.patch_status(
        &name,
        &PatchParams::apply("pistonprotection-operator"),
        &Patch::Merge(&patch),
    )
    .await
    .map_err(Error::KubeError)?;

    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Error policy for controller
fn error_policy(_obj: Arc<DDoSProtection>, error: &Error, _ctx: Arc<Context>) -> Action {
    warn!("Reconciliation error: {:?}", error);
    Action::requeue(Duration::from_secs(60))
}

fn error_policy_filter(_obj: Arc<FilterRule>, error: &Error, _ctx: Arc<Context>) -> Action {
    warn!("FilterRule reconciliation error: {:?}", error);
    Action::requeue(Duration::from_secs(60))
}
