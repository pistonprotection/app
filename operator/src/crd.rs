//! Custom Resource Definitions for PistonProtection
//!
//! This module defines all CRDs used by the PistonProtection operator:
//! - DDoSProtection: Main protection configuration for backends
//! - FilterRule: Custom filtering rules
//! - Backend: Backend service definitions (optional)

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ============================================================================
// DDoSProtection CRD
// ============================================================================

/// DDoSProtection Custom Resource Definition
///
/// Defines DDoS protection configuration for a set of backend services.
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
    printcolumn = r#"{"name":"Protection", "type":"integer", "jsonPath":".spec.protectionLevel"}"#,
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
    pub node_selector: Option<BTreeMap<String, String>>,

    /// Number of worker replicas
    #[serde(default = "default_replicas")]
    pub replicas: i32,

    /// Enable challenge-response for suspicious traffic
    #[serde(default)]
    pub challenge_enabled: bool,

    /// Automatic protection level escalation during attacks
    #[serde(default = "default_true")]
    pub auto_escalate: bool,

    /// Custom annotations for created resources
    #[serde(default)]
    pub annotations: Option<BTreeMap<String, String>>,

    /// Resource limits for worker pods
    #[serde(default)]
    pub resources: Option<ResourceSpec>,
}

fn default_protection_level() -> u8 {
    3
}

fn default_replicas() -> i32 {
    2
}

fn default_true() -> bool {
    true
}

/// Backend specification within DDoSProtection
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackendSpec {
    /// Backend name (unique within this DDoSProtection)
    pub name: String,

    /// Backend address (IP:port or hostname:port)
    pub address: String,

    /// Protocol type
    pub protocol: Protocol,

    /// Weight for load balancing (default: 1)
    #[serde(default = "default_weight")]
    pub weight: u32,

    /// Health check configuration
    #[serde(default)]
    pub health_check: Option<HealthCheckSpec>,

    /// Backend-specific rate limit (overrides global)
    #[serde(default)]
    pub rate_limit: Option<RateLimitSpec>,

    /// Enable proxy protocol (v1 or v2)
    #[serde(default)]
    pub proxy_protocol: Option<u8>,

    /// Additional backend metadata
    #[serde(default)]
    pub metadata: Option<BTreeMap<String, String>>,
}

impl Default for BackendSpec {
    fn default() -> Self {
        Self {
            name: String::new(),
            address: String::new(),
            protocol: Protocol::Tcp,
            weight: default_weight(),
            health_check: None,
            rate_limit: None,
            proxy_protocol: None,
            metadata: None,
        }
    }
}

fn default_weight() -> u32 {
    1
}

/// Supported protocols
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq, Eq, Hash)]
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

impl Protocol {
    /// Convert to gRPC protocol enum value
    pub fn to_grpc_protocol(&self) -> i32 {
        match self {
            Protocol::Tcp => 1,
            Protocol::Udp => 2,
            Protocol::Http => 3,
            Protocol::Https => 4,
            Protocol::MinecraftJava => 5,
            Protocol::MinecraftBedrock => 6,
            Protocol::Quic => 7,
        }
    }
}

/// Rate limiting specification
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitSpec {
    /// Packets per second limit per IP
    pub pps_per_ip: u64,

    /// Burst size (token bucket capacity)
    pub burst: u64,

    /// Global PPS limit for the backend
    #[serde(default)]
    pub global_pps: Option<u64>,

    /// Time window in seconds for rate calculation
    #[serde(default = "default_window")]
    pub window_seconds: u32,
}

fn default_window() -> u32 {
    1
}

/// Protocol-specific settings
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
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

    /// Maximum packet size (for UDP amplification protection)
    #[serde(default)]
    pub max_packet_size: Option<u32>,

    /// Enable connection tracking
    #[serde(default = "default_true")]
    pub connection_tracking: bool,
}

/// Minecraft protocol version range
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MinecraftVersionRange {
    pub min: u32,
    pub max: u32,
}

/// Geographic filtering specification
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GeoFilterSpec {
    /// Mode: allow or deny
    pub mode: GeoFilterMode,

    /// Country codes (ISO 3166-1 alpha-2)
    pub countries: Vec<String>,
}

/// Geographic filter mode
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum GeoFilterMode {
    Allow,
    Deny,
}

/// Health check specification
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HealthCheckSpec {
    /// Health check interval in seconds
    #[serde(default = "default_interval")]
    pub interval_seconds: u32,

    /// Health check timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u32,

    /// Number of failures before marking unhealthy
    #[serde(default = "default_threshold")]
    pub unhealthy_threshold: u32,

    /// Number of successes before marking healthy
    #[serde(default = "default_threshold")]
    pub healthy_threshold: u32,

    /// HTTP path for HTTP health checks
    #[serde(default)]
    pub http_path: Option<String>,

    /// Expected HTTP status codes
    #[serde(default)]
    pub expected_status: Option<Vec<u16>>,
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

/// Resource specification for worker pods
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceSpec {
    /// CPU request
    #[serde(default)]
    pub cpu_request: Option<String>,

    /// Memory request
    #[serde(default)]
    pub memory_request: Option<String>,

    /// CPU limit
    #[serde(default)]
    pub cpu_limit: Option<String>,

    /// Memory limit
    #[serde(default)]
    pub memory_limit: Option<String>,
}

/// Status of the DDoSProtection resource
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DDoSProtectionStatus {
    /// Current phase of the protection
    #[serde(default)]
    pub phase: Phase,

    /// Number of protected backends
    #[serde(default)]
    pub backend_count: i32,

    /// Number of healthy backends
    #[serde(default)]
    pub healthy_backends: i32,

    /// Number of ready worker pods
    #[serde(default)]
    pub ready_workers: i32,

    /// Number of desired worker pods
    #[serde(default)]
    pub desired_workers: i32,

    /// Last update timestamp
    #[serde(default)]
    pub last_updated: Option<String>,

    /// Observed generation
    #[serde(default)]
    pub observed_generation: Option<i64>,

    /// Status conditions
    #[serde(default)]
    pub conditions: Vec<Condition>,

    /// Metrics summary
    #[serde(default)]
    pub metrics: Option<MetricsSummary>,

    /// Gateway sync status
    #[serde(default)]
    pub gateway_synced: bool,

    /// Last error message (if any)
    #[serde(default)]
    pub last_error: Option<String>,

    /// Current protection level (may differ from spec during escalation)
    #[serde(default)]
    pub current_protection_level: Option<u8>,
}

/// Phase of the DDoSProtection resource
#[derive(Deserialize, Serialize, Clone, Copy, Debug, Default, JsonSchema, PartialEq, Eq)]
pub enum Phase {
    #[default]
    Pending,
    Provisioning,
    Active,
    Degraded,
    Error,
    Terminating,
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Phase::Pending => write!(f, "Pending"),
            Phase::Provisioning => write!(f, "Provisioning"),
            Phase::Active => write!(f, "Active"),
            Phase::Degraded => write!(f, "Degraded"),
            Phase::Error => write!(f, "Error"),
            Phase::Terminating => write!(f, "Terminating"),
        }
    }
}

/// Condition for status reporting
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    /// Type of condition
    #[serde(rename = "type")]
    pub condition_type: String,

    /// Status of the condition (True, False, Unknown)
    pub status: String,

    /// Reason for the condition
    pub reason: String,

    /// Human-readable message
    pub message: String,

    /// Last time this condition transitioned
    pub last_transition_time: String,

    /// Last time this condition was probed
    #[serde(default)]
    pub last_probe_time: Option<String>,
}

impl Condition {
    /// Create a new condition
    pub fn new(
        condition_type: &str,
        status: bool,
        reason: &str,
        message: &str,
    ) -> Self {
        Self {
            condition_type: condition_type.to_string(),
            status: if status { "True".to_string() } else { "False".to_string() },
            reason: reason.to_string(),
            message: message.to_string(),
            last_transition_time: chrono::Utc::now().to_rfc3339(),
            last_probe_time: Some(chrono::Utc::now().to_rfc3339()),
        }
    }
}

/// Metrics summary in status
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MetricsSummary {
    /// Total requests processed
    pub total_requests: u64,

    /// Total requests blocked
    pub blocked_requests: u64,

    /// Average latency in milliseconds
    pub avg_latency_ms: f64,

    /// Requests per second (current)
    #[serde(default)]
    pub requests_per_second: Option<f64>,

    /// Whether currently under attack
    #[serde(default)]
    pub under_attack: bool,
}

// ============================================================================
// FilterRule CRD
// ============================================================================

/// FilterRule Custom Resource Definition
///
/// Defines custom filtering rules that can be applied to DDoSProtection resources.
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "pistonprotection.io",
    version = "v1alpha1",
    kind = "FilterRule",
    namespaced,
    status = "FilterRuleStatus",
    shortname = "fr",
    printcolumn = r#"{"name":"Active", "type":"boolean", "jsonPath":".status.active"}"#,
    printcolumn = r#"{"name":"Type", "type":"string", "jsonPath":".spec.ruleType"}"#,
    printcolumn = r#"{"name":"Action", "type":"string", "jsonPath":".spec.action"}"#,
    printcolumn = r#"{"name":"Priority", "type":"integer", "jsonPath":".spec.priority"}"#,
    printcolumn = r#"{"name":"Matches", "type":"integer", "jsonPath":".status.matchCount"}"#,
    printcolumn = r#"{"name":"Age", "type":"date", "jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct FilterRuleSpec {
    /// Rule name (for display)
    pub name: String,

    /// Optional description
    #[serde(default)]
    pub description: Option<String>,

    /// Rule type
    pub rule_type: FilterRuleType,

    /// Action to take when rule matches
    pub action: FilterAction,

    /// Priority (higher = processed first, default: 50)
    #[serde(default = "default_priority")]
    pub priority: i32,

    /// Rule configuration
    pub config: FilterRuleConfig,

    /// Selector for DDoSProtection resources this rule applies to
    #[serde(default)]
    pub selector: Option<LabelSelector>,

    /// Whether the rule is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Time-based activation
    #[serde(default)]
    pub schedule: Option<ScheduleSpec>,

    /// Expiration time (ISO 8601)
    #[serde(default)]
    pub expires_at: Option<String>,
}

fn default_priority() -> i32 {
    50
}

/// Filter rule types
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FilterRuleType {
    IpBlocklist,
    IpAllowlist,
    RateLimit,
    GeoBlock,
    GeoAllow,
    ProtocolValidation,
    SynFlood,
    UdpAmplification,
    HttpFlood,
    Custom,
}

/// Filter actions
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FilterAction {
    Drop,
    Allow,
    RateLimit,
    Log,
    Challenge,
    Redirect,
    Tarpit,
}

impl FilterAction {
    /// Convert to gRPC action value
    pub fn to_grpc_action(&self) -> i32 {
        match self {
            FilterAction::Drop => 2,
            FilterAction::Allow => 1,
            FilterAction::RateLimit => 3,
            FilterAction::Log => 5,
            FilterAction::Challenge => 4,
            FilterAction::Redirect => 6,
            FilterAction::Tarpit => 2, // Treated as drop for now
        }
    }
}

/// Filter rule configuration
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FilterRuleConfig {
    /// IP addresses or CIDR ranges
    #[serde(default)]
    pub ip_ranges: Vec<String>,

    /// Country codes for geo filtering
    #[serde(default)]
    pub countries: Vec<String>,

    /// ASN numbers for filtering
    #[serde(default)]
    pub asns: Vec<String>,

    /// Rate limit settings (if action is RateLimit)
    #[serde(default)]
    pub rate_limit: Option<RateLimitSpec>,

    /// Port ranges to match
    #[serde(default)]
    pub ports: Vec<PortRange>,

    /// Protocols to match
    #[serde(default)]
    pub protocols: Vec<Protocol>,

    /// HTTP-specific matching
    #[serde(default)]
    pub http_match: Option<HttpMatchConfig>,

    /// Custom eBPF program (base64 encoded)
    #[serde(default)]
    pub custom_program: Option<String>,
}

/// Port range specification
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

/// HTTP matching configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpMatchConfig {
    /// HTTP methods to match
    #[serde(default)]
    pub methods: Vec<String>,

    /// Path patterns (regex)
    #[serde(default)]
    pub paths: Vec<String>,

    /// Host header patterns
    #[serde(default)]
    pub hosts: Vec<String>,

    /// User-agent patterns
    #[serde(default)]
    pub user_agents: Vec<String>,

    /// Header matching
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

/// Label selector for matching DDoSProtection resources
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelector {
    #[serde(default)]
    pub match_labels: BTreeMap<String, String>,

    #[serde(default)]
    pub match_expressions: Vec<LabelSelectorRequirement>,
}

/// Label selector requirement
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelectorRequirement {
    pub key: String,
    pub operator: String,
    #[serde(default)]
    pub values: Vec<String>,
}

/// Schedule specification for time-based rules
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleSpec {
    /// Cron expression for when rule is active
    #[serde(default)]
    pub cron: Option<String>,

    /// Days of week (0-6, Sunday = 0)
    #[serde(default)]
    pub days_of_week: Vec<u8>,

    /// Start time (HH:MM in UTC)
    #[serde(default)]
    pub start_time: Option<String>,

    /// End time (HH:MM in UTC)
    #[serde(default)]
    pub end_time: Option<String>,

    /// Timezone (IANA timezone)
    #[serde(default = "default_timezone")]
    pub timezone: String,
}

fn default_timezone() -> String {
    "UTC".to_string()
}

/// Status of the FilterRule resource
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FilterRuleStatus {
    /// Whether the rule is currently active
    #[serde(default)]
    pub active: bool,

    /// Number of times rule has matched
    #[serde(default)]
    pub match_count: u64,

    /// Last time the rule matched
    #[serde(default)]
    pub last_match: Option<String>,

    /// Observed generation
    #[serde(default)]
    pub observed_generation: Option<i64>,

    /// Gateway sync status
    #[serde(default)]
    pub gateway_synced: bool,

    /// Last sync time
    #[serde(default)]
    pub last_synced: Option<String>,

    /// Last error message
    #[serde(default)]
    pub last_error: Option<String>,

    /// Number of DDoSProtection resources this rule applies to
    #[serde(default)]
    pub applied_to_count: i32,

    /// Status conditions
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

// ============================================================================
// Backend CRD (Optional)
// ============================================================================

/// Backend Custom Resource Definition
///
/// Defines a backend service that can be referenced by DDoSProtection resources.
/// This is optional - backends can also be defined inline in DDoSProtection.
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "pistonprotection.io",
    version = "v1alpha1",
    kind = "Backend",
    namespaced,
    status = "BackendStatus",
    shortname = "be",
    printcolumn = r#"{"name":"Health", "type":"string", "jsonPath":".status.health"}"#,
    printcolumn = r#"{"name":"Endpoints", "type":"integer", "jsonPath":".status.endpointCount"}"#,
    printcolumn = r#"{"name":"Protocol", "type":"string", "jsonPath":".spec.protocol"}"#,
    printcolumn = r#"{"name":"Age", "type":"date", "jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct BackendCrdSpec {
    /// Backend display name
    pub display_name: String,

    /// Protocol type
    pub protocol: Protocol,

    /// Backend endpoints
    pub endpoints: Vec<EndpointSpec>,

    /// Load balancing algorithm
    #[serde(default)]
    pub load_balancing: Option<LoadBalancingSpec>,

    /// Health check configuration
    #[serde(default)]
    pub health_check: Option<HealthCheckSpec>,

    /// TLS configuration
    #[serde(default)]
    pub tls: Option<TlsSpec>,

    /// Connection pool settings
    #[serde(default)]
    pub connection_pool: Option<ConnectionPoolSpec>,

    /// Additional metadata
    #[serde(default)]
    pub metadata: Option<BTreeMap<String, String>>,
}

/// Endpoint specification
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EndpointSpec {
    /// Endpoint address (IP or hostname)
    pub address: String,

    /// Port number
    pub port: u16,

    /// Weight for load balancing
    #[serde(default = "default_weight")]
    pub weight: u32,

    /// Priority for failover
    #[serde(default)]
    pub priority: Option<u32>,

    /// Whether endpoint is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Load balancing specification
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LoadBalancingSpec {
    /// Algorithm to use
    #[serde(default)]
    pub algorithm: LoadBalancingAlgorithm,

    /// Enable sticky sessions
    #[serde(default)]
    pub sticky_sessions: bool,

    /// Sticky session cookie name
    #[serde(default)]
    pub sticky_cookie_name: Option<String>,

    /// Sticky session TTL in seconds
    #[serde(default)]
    pub sticky_ttl_seconds: Option<u32>,
}

/// Load balancing algorithms
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancingAlgorithm {
    #[default]
    RoundRobin,
    LeastConnections,
    Random,
    IpHash,
    Weighted,
}

/// TLS specification
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TlsSpec {
    /// Enable TLS
    pub enabled: bool,

    /// Verify server certificate
    #[serde(default = "default_true")]
    pub verify: bool,

    /// SNI hostname
    #[serde(default)]
    pub sni: Option<String>,

    /// Secret name containing CA certificate
    #[serde(default)]
    pub ca_secret: Option<String>,

    /// Secret name containing client certificate
    #[serde(default)]
    pub client_cert_secret: Option<String>,
}

/// Connection pool specification
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionPoolSpec {
    /// Maximum connections per endpoint
    #[serde(default)]
    pub max_connections: Option<u32>,

    /// Maximum idle connections per endpoint
    #[serde(default)]
    pub max_idle_connections: Option<u32>,

    /// Idle timeout in seconds
    #[serde(default)]
    pub idle_timeout_seconds: Option<u32>,

    /// Connect timeout in milliseconds
    #[serde(default)]
    pub connect_timeout_ms: Option<u32>,
}

/// Status of the Backend resource
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackendStatus {
    /// Overall health status
    #[serde(default)]
    pub health: HealthState,

    /// Number of healthy endpoints
    #[serde(default)]
    pub healthy_endpoints: i32,

    /// Total number of endpoints
    #[serde(default)]
    pub endpoint_count: i32,

    /// Observed generation
    #[serde(default)]
    pub observed_generation: Option<i64>,

    /// Gateway sync status
    #[serde(default)]
    pub gateway_synced: bool,

    /// Last sync time
    #[serde(default)]
    pub last_synced: Option<String>,

    /// Endpoint statuses
    #[serde(default)]
    pub endpoints: Vec<EndpointStatus>,

    /// Status conditions
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

/// Health state
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema, PartialEq)]
pub enum HealthState {
    #[default]
    Unknown,
    Healthy,
    Degraded,
    Unhealthy,
}

impl std::fmt::Display for HealthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthState::Unknown => write!(f, "Unknown"),
            HealthState::Healthy => write!(f, "Healthy"),
            HealthState::Degraded => write!(f, "Degraded"),
            HealthState::Unhealthy => write!(f, "Unhealthy"),
        }
    }
}

/// Status of an individual endpoint
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EndpointStatus {
    /// Endpoint address
    pub address: String,

    /// Endpoint port
    pub port: u16,

    /// Health status
    pub health: HealthState,

    /// Last health check time
    #[serde(default)]
    pub last_check: Option<String>,

    /// Last health check error (if any)
    #[serde(default)]
    pub last_error: Option<String>,

    /// Consecutive failures
    #[serde(default)]
    pub consecutive_failures: i32,
}

// ============================================================================
// IPBlocklist CRD
// ============================================================================

/// IPBlocklist Custom Resource Definition
///
/// Manages IP blocklists that can be applied to filter traffic.
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "pistonprotection.io",
    version = "v1alpha1",
    kind = "IPBlocklist",
    namespaced,
    status = "IPBlocklistStatus",
    shortname = "ipbl",
    printcolumn = r#"{"name":"Entries", "type":"integer", "jsonPath":".status.entryCount"}"#,
    printcolumn = r#"{"name":"Source", "type":"string", "jsonPath":".spec.source"}"#,
    printcolumn = r#"{"name":"Synced", "type":"boolean", "jsonPath":".status.gatewaySynced"}"#,
    printcolumn = r#"{"name":"Age", "type":"date", "jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct IPBlocklistSpec {
    /// Display name for the blocklist
    pub name: String,

    /// Optional description
    #[serde(default)]
    pub description: Option<String>,

    /// Source of the blocklist
    #[serde(default)]
    pub source: BlocklistSource,

    /// Static IP addresses or CIDR ranges
    #[serde(default)]
    pub entries: Vec<BlocklistEntry>,

    /// External URL to fetch blocklist from (for external source)
    #[serde(default)]
    pub external_url: Option<String>,

    /// Refresh interval for external sources (in seconds)
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval_seconds: u32,

    /// Whether the blocklist is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Default action for matched IPs
    #[serde(default)]
    pub action: BlocklistAction,

    /// Selector for DDoSProtection resources this blocklist applies to
    #[serde(default)]
    pub selector: Option<LabelSelector>,

    /// Priority (higher = processed first)
    #[serde(default = "default_blocklist_priority")]
    pub priority: i32,

    /// Tags for categorization
    #[serde(default)]
    pub tags: Vec<String>,

    /// Expiration time for entries (0 = never expire)
    #[serde(default)]
    pub default_ttl_seconds: u32,
}

fn default_refresh_interval() -> u32 {
    3600 // 1 hour
}

fn default_blocklist_priority() -> i32 {
    100
}

/// Blocklist source type
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BlocklistSource {
    /// Manually managed entries
    #[default]
    Static,
    /// Fetched from external URL
    External,
    /// Automatically populated by attack detection
    Automatic,
    /// Aggregated from multiple sources
    Aggregated,
}

impl std::fmt::Display for BlocklistSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlocklistSource::Static => write!(f, "static"),
            BlocklistSource::External => write!(f, "external"),
            BlocklistSource::Automatic => write!(f, "automatic"),
            BlocklistSource::Aggregated => write!(f, "aggregated"),
        }
    }
}

/// Action to take for blocked IPs
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BlocklistAction {
    /// Drop packets silently
    #[default]
    Drop,
    /// Reject with ICMP/TCP RST
    Reject,
    /// Rate limit traffic
    RateLimit,
    /// Redirect to tarpit/honeypot
    Tarpit,
    /// Log only (monitor mode)
    Log,
}

impl BlocklistAction {
    /// Convert to gRPC action value
    pub fn to_grpc_action(&self) -> i32 {
        match self {
            BlocklistAction::Drop => 2,
            BlocklistAction::Reject => 7,
            BlocklistAction::RateLimit => 3,
            BlocklistAction::Tarpit => 8,
            BlocklistAction::Log => 5,
        }
    }
}

/// Individual blocklist entry
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BlocklistEntry {
    /// IP address or CIDR range
    pub ip: String,

    /// Reason for blocking
    #[serde(default)]
    pub reason: Option<String>,

    /// When this entry was added (ISO 8601)
    #[serde(default)]
    pub added_at: Option<String>,

    /// When this entry expires (ISO 8601, None = never)
    #[serde(default)]
    pub expires_at: Option<String>,

    /// Source that added this entry
    #[serde(default)]
    pub source: Option<String>,

    /// Custom action for this entry (overrides blocklist default)
    #[serde(default)]
    pub action: Option<BlocklistAction>,

    /// Additional metadata
    #[serde(default)]
    pub metadata: Option<BTreeMap<String, String>>,
}

impl Default for BlocklistEntry {
    fn default() -> Self {
        Self {
            ip: String::new(),
            reason: None,
            added_at: Some(chrono::Utc::now().to_rfc3339()),
            expires_at: None,
            source: None,
            action: None,
            metadata: None,
        }
    }
}

/// Status of the IPBlocklist resource
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IPBlocklistStatus {
    /// Number of entries in the blocklist
    #[serde(default)]
    pub entry_count: i32,

    /// Number of active (non-expired) entries
    #[serde(default)]
    pub active_entries: i32,

    /// Gateway sync status
    #[serde(default)]
    pub gateway_synced: bool,

    /// Last sync time
    #[serde(default)]
    pub last_synced: Option<String>,

    /// Last refresh time (for external sources)
    #[serde(default)]
    pub last_refreshed: Option<String>,

    /// Next scheduled refresh (for external sources)
    #[serde(default)]
    pub next_refresh: Option<String>,

    /// Observed generation
    #[serde(default)]
    pub observed_generation: Option<i64>,

    /// Total blocks performed
    #[serde(default)]
    pub total_blocks: u64,

    /// Blocks in the last hour
    #[serde(default)]
    pub blocks_last_hour: u64,

    /// Number of DDoSProtection resources this blocklist applies to
    #[serde(default)]
    pub applied_to_count: i32,

    /// Last error message
    #[serde(default)]
    pub last_error: Option<String>,

    /// Status conditions
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

// ============================================================================
// Constants
// ============================================================================

/// Finalizer used by the operator
pub const FINALIZER: &str = "pistonprotection.io/finalizer";

/// Label for managed resources
pub const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
pub const MANAGED_BY_VALUE: &str = "pistonprotection-operator";

/// Label for component identification
pub const COMPONENT_LABEL: &str = "app.kubernetes.io/component";
pub const INSTANCE_LABEL: &str = "app.kubernetes.io/instance";
pub const NAME_LABEL: &str = "app.kubernetes.io/name";

/// Worker image
pub const WORKER_IMAGE: &str = "pistonprotection/worker:latest";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_conversion() {
        assert_eq!(Protocol::Tcp.to_grpc_protocol(), 1);
        assert_eq!(Protocol::Udp.to_grpc_protocol(), 2);
        assert_eq!(Protocol::MinecraftJava.to_grpc_protocol(), 5);
    }

    #[test]
    fn test_action_conversion() {
        assert_eq!(FilterAction::Drop.to_grpc_action(), 2);
        assert_eq!(FilterAction::Allow.to_grpc_action(), 1);
        assert_eq!(FilterAction::Challenge.to_grpc_action(), 4);
    }

    #[test]
    fn test_condition_creation() {
        let condition = Condition::new("Ready", true, "Reconciled", "Resource is ready");
        assert_eq!(condition.condition_type, "Ready");
        assert_eq!(condition.status, "True");
    }

    #[test]
    fn test_blocklist_source_display() {
        assert_eq!(BlocklistSource::Static.to_string(), "static");
        assert_eq!(BlocklistSource::External.to_string(), "external");
        assert_eq!(BlocklistSource::Automatic.to_string(), "automatic");
        assert_eq!(BlocklistSource::Aggregated.to_string(), "aggregated");
    }

    #[test]
    fn test_blocklist_action_conversion() {
        assert_eq!(BlocklistAction::Drop.to_grpc_action(), 2);
        assert_eq!(BlocklistAction::RateLimit.to_grpc_action(), 3);
        assert_eq!(BlocklistAction::Log.to_grpc_action(), 5);
    }

    #[test]
    fn test_blocklist_entry_default() {
        let entry = BlocklistEntry::default();
        assert!(entry.ip.is_empty());
        assert!(entry.added_at.is_some());
        assert!(entry.expires_at.is_none());
    }
}
