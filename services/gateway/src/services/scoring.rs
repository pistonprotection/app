//! IP Scoring Service
//!
//! Provides gRPC API for IP threat scoring, blocking, and intelligence.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use chrono::Duration;
use pistonprotection_common::scoring::{
    ActionType as ScoringActionType, BehaviorCategory as ScoringBehaviorCategory, IPRecord,
    ScoringEngine, ThreatIntelEntry, ThreatIntelFeed,
};
use tracing::info;

use super::AppState;

/// Service for IP scoring operations
pub struct ScoringService {
    state: AppState,
    threat_intel: Arc<ThreatIntelFeed>,
}

impl ScoringService {
    /// Create a new scoring service
    pub fn new(state: AppState) -> Self {
        Self {
            state,
            threat_intel: Arc::new(ThreatIntelFeed::new()),
        }
    }

    /// Get the scoring engine
    fn engine(&self) -> &ScoringEngine {
        self.state.scoring_engine()
    }

    /// Get threat score for an IP
    pub fn get_ip_score(&self, ip: IpAddr, include_history: bool) -> Option<IPRecord> {
        let record = self.engine().get(&ip)?;
        if include_history {
            Some(record)
        } else {
            // Return record without detailed event history
            let mut r = record;
            r.recent_events.clear();
            Some(r)
        }
    }

    /// Get threat scores for multiple IPs
    pub fn get_ip_scores_batch(&self, ips: &[IpAddr]) -> Vec<(IpAddr, Option<IPRecord>)> {
        ips.iter().map(|ip| (*ip, self.engine().get(ip))).collect()
    }

    /// Record an action taken on an IP
    pub fn record_action(
        &self,
        ip: IpAddr,
        action: ScoringActionType,
        category: ScoringBehaviorCategory,
        backend_id: Option<&str>,
        protocol: Option<&str>,
    ) -> (u8, bool) {
        let score = self
            .engine()
            .record_action(ip, action, category, backend_id, protocol);

        // Check if IP was auto-blocked
        let auto_blocked = self.engine().is_blocked(&ip);

        (score, auto_blocked)
    }

    /// Block an IP manually
    pub fn block_ip(&self, ip: IpAddr, duration_seconds: u64, reason: &str) -> bool {
        let duration = if duration_seconds == 0 {
            Duration::days(365 * 10) // "Permanent" block = 10 years
        } else {
            Duration::seconds(duration_seconds as i64)
        };

        self.engine().block_ip(ip, duration, reason);
        true
    }

    /// Unblock an IP
    pub fn unblock_ip(&self, ip: IpAddr) -> bool {
        self.engine().unblock_ip(&ip)
    }

    /// Check if an IP is blocked
    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        self.engine().is_blocked(ip)
    }

    /// Get list of blocked IPs
    pub fn get_blocked_ips(&self) -> Vec<IPRecord> {
        self.engine().get_blocked_ips()
    }

    /// Get top threat IPs
    pub fn get_top_threats(&self, limit: usize) -> Vec<IPRecord> {
        self.engine().get_top_threats(limit)
    }

    /// Get scoring statistics
    pub fn get_stats(&self) -> ScoringStats {
        let stats = self.engine().stats();
        ScoringStats {
            total_ips: stats.total_ips,
            blocked_ips: stats.blocked_ips,
            high_threat_count: stats.high_threat_count,
            medium_threat_count: stats.medium_threat_count,
            low_threat_count: stats.low_threat_count,
        }
    }

    /// Add threat intel entry
    pub fn add_threat_intel(&self, entry: ThreatIntelEntry) {
        self.threat_intel.add_entry(entry);
    }

    /// Check threat intel for an IP
    pub fn check_threat_intel(&self, ip: &IpAddr) -> Option<ThreatIntelEntry> {
        self.threat_intel.is_known_bad(ip)
    }

    /// Get threat intel count
    pub fn threat_intel_count(&self) -> usize {
        self.threat_intel.count()
    }

    /// Run cleanup of expired data
    pub fn cleanup(&self) {
        self.engine().cleanup();
    }
}

/// Scoring statistics
#[derive(Debug, Clone)]
pub struct ScoringStats {
    pub total_ips: u64,
    pub blocked_ips: u64,
    pub high_threat_count: u64,
    pub medium_threat_count: u64,
    pub low_threat_count: u64,
}

/// REST API handlers for scoring service
pub mod api {
    use super::*;
    use axum::{
        Json, Router,
        extract::{Path, Query, State},
        http::StatusCode,
        response::IntoResponse,
        routing::{delete, get, post},
    };
    use serde::{Deserialize, Serialize};

    /// Create scoring API router
    pub fn router(state: AppState) -> Router {
        let scoring_service = Arc::new(ScoringService::new(state));

        Router::new()
            .route("/ip/:ip", get(get_ip_score))
            .route("/ip/:ip/block", post(block_ip))
            .route("/ip/:ip/unblock", delete(unblock_ip))
            .route("/ip/:ip/action", post(record_action))
            .route("/blocked", get(list_blocked))
            .route("/top-threats", get(list_top_threats))
            .route("/stats", get(get_stats))
            .route("/threat-intel/check/:ip", get(check_threat_intel))
            .with_state(scoring_service)
    }

    #[derive(Serialize)]
    pub struct IPScoreResponse {
        pub ip: String,
        pub found: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub threat_score: Option<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub is_blocked: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub total_requests: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub blocked_requests: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub country_code: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub asn: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub asn_org: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub is_tor_exit: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub is_vpn_proxy: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub is_datacenter: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub block_reason: Option<String>,
    }

    impl From<Option<&IPRecord>> for IPScoreResponse {
        fn from(record: Option<&IPRecord>) -> Self {
            match record {
                Some(r) => Self {
                    ip: r.ip.to_string(),
                    found: true,
                    threat_score: Some(r.threat_score),
                    is_blocked: Some(r.is_blocked),
                    total_requests: Some(r.total_requests),
                    blocked_requests: Some(r.blocked_requests),
                    country_code: r.country_code.clone(),
                    asn: r.asn,
                    asn_org: r.asn_org.clone(),
                    is_tor_exit: Some(r.is_tor_exit),
                    is_vpn_proxy: Some(r.is_vpn_proxy),
                    is_datacenter: Some(r.is_datacenter),
                    block_reason: r.block_reason.clone(),
                },
                None => Self {
                    ip: String::new(),
                    found: false,
                    threat_score: None,
                    is_blocked: None,
                    total_requests: None,
                    blocked_requests: None,
                    country_code: None,
                    asn: None,
                    asn_org: None,
                    is_tor_exit: None,
                    is_vpn_proxy: None,
                    is_datacenter: None,
                    block_reason: None,
                },
            }
        }
    }

    #[derive(Deserialize)]
    pub struct GetIPScoreQuery {
        #[serde(default)]
        pub include_history: bool,
    }

    async fn get_ip_score(
        State(service): State<Arc<ScoringService>>,
        Path(ip_str): Path<String>,
        Query(query): Query<GetIPScoreQuery>,
    ) -> impl IntoResponse {
        let ip = match IpAddr::from_str(&ip_str) {
            Ok(ip) => ip,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "Invalid IP address"})),
                )
                    .into_response();
            }
        };

        let record = service.get_ip_score(ip, query.include_history);
        let response = IPScoreResponse::from(record.as_ref());

        (StatusCode::OK, Json(response)).into_response()
    }

    #[derive(Deserialize)]
    pub struct BlockIPRequest {
        pub duration_seconds: Option<u64>,
        pub reason: String,
    }

    #[derive(Serialize)]
    pub struct BlockIPResponse {
        pub success: bool,
        pub message: String,
    }

    async fn block_ip(
        State(service): State<Arc<ScoringService>>,
        Path(ip_str): Path<String>,
        Json(request): Json<BlockIPRequest>,
    ) -> impl IntoResponse {
        let ip = match IpAddr::from_str(&ip_str) {
            Ok(ip) => ip,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(BlockIPResponse {
                        success: false,
                        message: "Invalid IP address".to_string(),
                    }),
                );
            }
        };

        service.block_ip(
            ip,
            request.duration_seconds.unwrap_or(3600),
            &request.reason,
        );

        info!(ip = %ip, reason = %request.reason, "IP blocked via API");

        (
            StatusCode::OK,
            Json(BlockIPResponse {
                success: true,
                message: format!("IP {} blocked: {}", ip, request.reason),
            }),
        )
    }

    async fn unblock_ip(
        State(service): State<Arc<ScoringService>>,
        Path(ip_str): Path<String>,
    ) -> impl IntoResponse {
        let ip = match IpAddr::from_str(&ip_str) {
            Ok(ip) => ip,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(BlockIPResponse {
                        success: false,
                        message: "Invalid IP address".to_string(),
                    }),
                );
            }
        };

        let was_blocked = service.unblock_ip(ip);

        if was_blocked {
            info!(ip = %ip, "IP unblocked via API");
            (
                StatusCode::OK,
                Json(BlockIPResponse {
                    success: true,
                    message: format!("IP {} unblocked", ip),
                }),
            )
        } else {
            (
                StatusCode::OK,
                Json(BlockIPResponse {
                    success: false,
                    message: format!("IP {} was not blocked", ip),
                }),
            )
        }
    }

    #[derive(Deserialize)]
    pub struct RecordActionRequest {
        pub action: String,
        pub category: String,
        #[serde(default)]
        pub backend_id: Option<String>,
        #[serde(default)]
        pub protocol: Option<String>,
    }

    #[derive(Serialize)]
    pub struct RecordActionResponse {
        pub threat_score: u8,
        pub auto_blocked: bool,
    }

    async fn record_action(
        State(service): State<Arc<ScoringService>>,
        Path(ip_str): Path<String>,
        Json(request): Json<RecordActionRequest>,
    ) -> impl IntoResponse {
        let ip = match IpAddr::from_str(&ip_str) {
            Ok(ip) => ip,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "Invalid IP address"})),
                )
                    .into_response();
            }
        };

        let action = match request.action.to_lowercase().as_str() {
            "allowed" => ScoringActionType::Allowed,
            "blocked" => ScoringActionType::Blocked,
            "rate_limited" | "ratelimited" => ScoringActionType::RateLimited,
            "challenged" => ScoringActionType::Challenged,
            "challenge_passed" | "challengepassed" => ScoringActionType::ChallengePassed,
            "challenge_failed" | "challengefailed" => ScoringActionType::ChallengeFailed,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "Invalid action type"})),
                )
                    .into_response();
            }
        };

        let category = match request.category.to_lowercase().as_str() {
            "normal" => ScoringBehaviorCategory::Normal,
            "high_rate" | "highrate" => ScoringBehaviorCategory::HighRate,
            "connection_flood" | "connectionflood" => ScoringBehaviorCategory::ConnectionFlood,
            "protocol_violation" | "protocolviolation" => {
                ScoringBehaviorCategory::ProtocolViolation
            }
            "suspicious" => ScoringBehaviorCategory::Suspicious,
            "attack" => ScoringBehaviorCategory::Attack,
            "bot" => ScoringBehaviorCategory::Bot,
            "tor_exit" | "torexit" => ScoringBehaviorCategory::TorExitNode,
            "vpn_proxy" | "vpnproxy" => ScoringBehaviorCategory::VpnProxy,
            "residential_proxy" | "residentialproxy" => ScoringBehaviorCategory::ResidentialProxy,
            "datacenter" => ScoringBehaviorCategory::Datacenter,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "Invalid category"})),
                )
                    .into_response();
            }
        };

        let (threat_score, auto_blocked) = service.record_action(
            ip,
            action,
            category,
            request.backend_id.as_deref(),
            request.protocol.as_deref(),
        );

        (
            StatusCode::OK,
            Json(RecordActionResponse {
                threat_score,
                auto_blocked,
            }),
        )
            .into_response()
    }

    #[derive(Serialize)]
    pub struct BlockedIPsResponse {
        pub count: usize,
        pub ips: Vec<BlockedIPEntry>,
    }

    #[derive(Serialize)]
    pub struct BlockedIPEntry {
        pub ip: String,
        pub threat_score: u8,
        pub block_reason: Option<String>,
        pub total_requests: u64,
        pub blocked_requests: u64,
    }

    async fn list_blocked(State(service): State<Arc<ScoringService>>) -> impl IntoResponse {
        let blocked = service.get_blocked_ips();
        let entries: Vec<BlockedIPEntry> = blocked
            .iter()
            .map(|r| BlockedIPEntry {
                ip: r.ip.to_string(),
                threat_score: r.threat_score,
                block_reason: r.block_reason.clone(),
                total_requests: r.total_requests,
                blocked_requests: r.blocked_requests,
            })
            .collect();

        (
            StatusCode::OK,
            Json(BlockedIPsResponse {
                count: entries.len(),
                ips: entries,
            }),
        )
    }

    #[derive(Deserialize)]
    pub struct TopThreatsQuery {
        #[serde(default = "default_limit")]
        pub limit: usize,
    }

    fn default_limit() -> usize {
        10
    }

    async fn list_top_threats(
        State(service): State<Arc<ScoringService>>,
        Query(query): Query<TopThreatsQuery>,
    ) -> impl IntoResponse {
        let limit = query.limit.min(100);
        let threats = service.get_top_threats(limit);

        let entries: Vec<BlockedIPEntry> = threats
            .iter()
            .map(|r| BlockedIPEntry {
                ip: r.ip.to_string(),
                threat_score: r.threat_score,
                block_reason: r.block_reason.clone(),
                total_requests: r.total_requests,
                blocked_requests: r.blocked_requests,
            })
            .collect();

        (
            StatusCode::OK,
            Json(BlockedIPsResponse {
                count: entries.len(),
                ips: entries,
            }),
        )
    }

    #[derive(Serialize)]
    pub struct StatsResponse {
        pub total_ips: u64,
        pub blocked_ips: u64,
        pub high_threat_count: u64,
        pub medium_threat_count: u64,
        pub low_threat_count: u64,
    }

    async fn get_stats(State(service): State<Arc<ScoringService>>) -> impl IntoResponse {
        let stats = service.get_stats();

        (
            StatusCode::OK,
            Json(StatsResponse {
                total_ips: stats.total_ips,
                blocked_ips: stats.blocked_ips,
                high_threat_count: stats.high_threat_count,
                medium_threat_count: stats.medium_threat_count,
                low_threat_count: stats.low_threat_count,
            }),
        )
    }

    #[derive(Serialize)]
    pub struct ThreatIntelResponse {
        pub is_known_bad: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub threat_type: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub confidence: Option<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub source: Option<String>,
    }

    async fn check_threat_intel(
        State(service): State<Arc<ScoringService>>,
        Path(ip_str): Path<String>,
    ) -> impl IntoResponse {
        let ip = match IpAddr::from_str(&ip_str) {
            Ok(ip) => ip,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "Invalid IP address"})),
                )
                    .into_response();
            }
        };

        match service.check_threat_intel(&ip) {
            Some(entry) => (
                StatusCode::OK,
                Json(ThreatIntelResponse {
                    is_known_bad: true,
                    threat_type: Some(entry.threat_type),
                    confidence: Some(entry.confidence),
                    source: Some(entry.source),
                }),
            )
                .into_response(),
            None => (
                StatusCode::OK,
                Json(ThreatIntelResponse {
                    is_known_bad: false,
                    threat_type: None,
                    confidence: None,
                    source: None,
                }),
            )
                .into_response(),
        }
    }
}
