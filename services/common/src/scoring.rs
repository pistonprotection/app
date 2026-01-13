//! IP Scoring and Reputation System
//!
//! This module provides an IP reputation system that tracks and scores
//! IP addresses based on their behavior patterns. It's used for:
//! - Identifying potentially malicious traffic
//! - Adaptive rate limiting
//! - Automated blocking decisions
//! - Attack detection and classification

use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;
use tracing::info;

/// Scoring errors
#[derive(Debug, Error)]
pub enum ScoringError {
    #[error("IP not found: {0}")]
    NotFound(String),

    #[error("Invalid score value: {0}")]
    InvalidScore(String),

    #[error("Storage error: {0}")]
    Storage(String),
}

/// IP reputation score (0-100, higher = more suspicious)
pub type ThreatScore = u8;

/// IP behavior categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BehaviorCategory {
    /// Normal traffic patterns
    Normal,
    /// High request rate
    HighRate,
    /// Connection flooding
    ConnectionFlood,
    /// Protocol violations
    ProtocolViolation,
    /// Suspicious patterns (e.g., scanning)
    Suspicious,
    /// Known attack patterns
    Attack,
    /// Bot behavior
    Bot,
    /// Tor exit node
    TorExitNode,
    /// VPN/Proxy
    VpnProxy,
    /// Residential proxy
    ResidentialProxy,
    /// Datacenter IP
    Datacenter,
}

impl BehaviorCategory {
    /// Get base score contribution for this category
    pub fn base_score(&self) -> ThreatScore {
        match self {
            Self::Normal => 0,
            Self::HighRate => 15,
            Self::ConnectionFlood => 25,
            Self::ProtocolViolation => 30,
            Self::Suspicious => 20,
            Self::Attack => 50,
            Self::Bot => 10,
            Self::TorExitNode => 20,
            Self::VpnProxy => 15,
            Self::ResidentialProxy => 25,
            Self::Datacenter => 5,
        }
    }
}

/// Action taken on an IP
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType {
    /// Request allowed
    Allowed,
    /// Request blocked
    Blocked,
    /// Request rate limited
    RateLimited,
    /// Request challenged
    Challenged,
    /// Challenge passed
    ChallengePassed,
    /// Challenge failed
    ChallengeFailed,
}

impl ActionType {
    /// Get score modification for this action
    pub fn score_delta(&self) -> i8 {
        match self {
            Self::Allowed => 0,
            Self::Blocked => 5,
            Self::RateLimited => 3,
            Self::Challenged => 2,
            Self::ChallengePassed => -5,
            Self::ChallengeFailed => 10,
        }
    }
}

/// A single event in an IP's history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPEvent {
    /// When the event occurred
    pub timestamp: DateTime<Utc>,
    /// Action taken
    pub action: ActionType,
    /// Associated backend
    pub backend_id: Option<String>,
    /// Request protocol
    pub protocol: Option<String>,
    /// Behavior category detected
    pub category: BehaviorCategory,
    /// Score delta from this event
    pub score_delta: i8,
}

/// Complete IP record with history and scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPRecord {
    /// IP address
    pub ip: IpAddr,
    /// Current threat score (0-100)
    pub threat_score: ThreatScore,
    /// Total requests observed
    pub total_requests: u64,
    /// Blocked requests
    pub blocked_requests: u64,
    /// Rate limited requests
    pub rate_limited_requests: u64,
    /// Challenged requests
    pub challenged_requests: u64,
    /// Successful challenges
    pub challenges_passed: u64,
    /// Failed challenges
    pub challenges_failed: u64,
    /// First seen timestamp
    pub first_seen: DateTime<Utc>,
    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,
    /// GeoIP country code
    pub country_code: Option<String>,
    /// ASN number
    pub asn: Option<u32>,
    /// ASN organization
    pub asn_org: Option<String>,
    /// Is known tor exit node
    pub is_tor_exit: bool,
    /// Is known VPN/proxy
    pub is_vpn_proxy: bool,
    /// Is datacenter IP
    pub is_datacenter: bool,
    /// Recent events (limited sliding window)
    pub recent_events: VecDeque<IPEvent>,
    /// Active behavior categories
    pub active_categories: Vec<BehaviorCategory>,
    /// Is currently blocked
    pub is_blocked: bool,
    /// Block expiration time
    pub block_expires: Option<DateTime<Utc>>,
    /// Block reason
    pub block_reason: Option<String>,
}

impl IPRecord {
    /// Create a new IP record
    pub fn new(ip: IpAddr) -> Self {
        let now = Utc::now();
        Self {
            ip,
            threat_score: 0,
            total_requests: 0,
            blocked_requests: 0,
            rate_limited_requests: 0,
            challenged_requests: 0,
            challenges_passed: 0,
            challenges_failed: 0,
            first_seen: now,
            last_seen: now,
            country_code: None,
            asn: None,
            asn_org: None,
            is_tor_exit: false,
            is_vpn_proxy: false,
            is_datacenter: false,
            recent_events: VecDeque::with_capacity(100),
            active_categories: Vec::new(),
            is_blocked: false,
            block_expires: None,
            block_reason: None,
        }
    }

    /// Update the threat score based on behavior
    pub fn update_score(&mut self) {
        // Start with base score from active categories
        let mut score: i32 = self
            .active_categories
            .iter()
            .map(|c| c.base_score() as i32)
            .sum();

        // Add modifier for recent actions
        let recent_score: i32 = self
            .recent_events
            .iter()
            .take(20)
            .map(|e| e.score_delta as i32)
            .sum();
        score += recent_score;

        // Add modifier for challenge failure rate
        if self.challenges_passed + self.challenges_failed > 0 {
            let failure_rate = self.challenges_failed as f64
                / (self.challenges_passed + self.challenges_failed) as f64;
            score += (failure_rate * 20.0) as i32;
        }

        // Add modifier for block rate
        if self.total_requests > 10 {
            let block_rate = self.blocked_requests as f64 / self.total_requests as f64;
            score += (block_rate * 30.0) as i32;
        }

        // Known bad actor modifiers
        if self.is_tor_exit {
            score += BehaviorCategory::TorExitNode.base_score() as i32;
        }
        if self.is_vpn_proxy {
            score += BehaviorCategory::VpnProxy.base_score() as i32;
        }
        if self.is_datacenter {
            score += BehaviorCategory::Datacenter.base_score() as i32;
        }

        // Decay over time (reduce score for inactive IPs)
        let hours_since_last = (Utc::now() - self.last_seen).num_hours();
        if hours_since_last > 1 {
            score = (score as f64 * (0.95_f64).powi(hours_since_last as i32)) as i32;
        }

        // Clamp to valid range
        self.threat_score = score.clamp(0, 100) as ThreatScore;
    }

    /// Record an action on this IP
    pub fn record_action(
        &mut self,
        action: ActionType,
        category: BehaviorCategory,
        backend_id: Option<&str>,
        protocol: Option<&str>,
    ) {
        let now = Utc::now();
        self.last_seen = now;
        self.total_requests += 1;

        match action {
            ActionType::Blocked => self.blocked_requests += 1,
            ActionType::RateLimited => self.rate_limited_requests += 1,
            ActionType::Challenged => self.challenged_requests += 1,
            ActionType::ChallengePassed => self.challenges_passed += 1,
            ActionType::ChallengeFailed => self.challenges_failed += 1,
            ActionType::Allowed => {}
        }

        // Add to recent events
        let event = IPEvent {
            timestamp: now,
            action,
            backend_id: backend_id.map(String::from),
            protocol: protocol.map(String::from),
            category,
            score_delta: action.score_delta(),
        };

        // Keep only last 100 events
        if self.recent_events.len() >= 100 {
            self.recent_events.pop_back();
        }
        self.recent_events.push_front(event);

        // Update active categories
        if category != BehaviorCategory::Normal && !self.active_categories.contains(&category) {
            self.active_categories.push(category);
        }

        // Recalculate score
        self.update_score();
    }

    /// Check if this IP should be auto-blocked
    pub fn should_auto_block(&self) -> bool {
        // Auto-block if score exceeds threshold
        if self.threat_score >= 80 {
            return true;
        }

        // Auto-block if too many blocks in short time
        let recent_blocks = self
            .recent_events
            .iter()
            .filter(|e| e.timestamp > Utc::now() - Duration::minutes(5))
            .filter(|e| e.action == ActionType::Blocked)
            .count();

        if recent_blocks >= 10 {
            return true;
        }

        // Auto-block if too many challenge failures
        let recent_challenge_failures = self
            .recent_events
            .iter()
            .filter(|e| e.timestamp > Utc::now() - Duration::minutes(5))
            .filter(|e| e.action == ActionType::ChallengeFailed)
            .count();

        if recent_challenge_failures >= 3 {
            return true;
        }

        false
    }

    /// Block this IP
    pub fn block(&mut self, duration: Duration, reason: &str) {
        self.is_blocked = true;
        self.block_expires = Some(Utc::now() + duration);
        self.block_reason = Some(reason.to_string());
    }

    /// Unblock this IP
    pub fn unblock(&mut self) {
        self.is_blocked = false;
        self.block_expires = None;
        self.block_reason = None;
    }

    /// Check if block has expired
    pub fn check_block_expiry(&mut self) -> bool {
        if let Some(expires) = self.block_expires {
            if Utc::now() > expires {
                self.unblock();
                return true;
            }
        }
        false
    }
}

/// Configuration for the scoring engine
#[derive(Debug, Clone)]
pub struct ScoringConfig {
    /// Score threshold for auto-blocking
    pub auto_block_threshold: ThreatScore,
    /// Duration for auto-blocks
    pub auto_block_duration: Duration,
    /// Maximum events to keep per IP
    pub max_events_per_ip: usize,
    /// Score decay rate per hour
    pub decay_rate: f64,
    /// Challenge success score bonus
    pub challenge_success_bonus: i8,
    /// Enable auto-blocking
    pub auto_block_enabled: bool,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            auto_block_threshold: 80,
            auto_block_duration: Duration::hours(1),
            max_events_per_ip: 100,
            decay_rate: 0.95,
            challenge_success_bonus: -5,
            auto_block_enabled: true,
        }
    }
}

/// IP Scoring Engine
pub struct ScoringEngine {
    /// IP records storage
    records: DashMap<IpAddr, IPRecord>,
    /// Configuration
    config: ScoringConfig,
    /// Total IPs tracked
    total_ips: AtomicU64,
    /// Total blocked IPs
    blocked_ips: AtomicU64,
}

impl ScoringEngine {
    /// Create a new scoring engine
    pub fn new(config: ScoringConfig) -> Self {
        Self {
            records: DashMap::new(),
            config,
            total_ips: AtomicU64::new(0),
            blocked_ips: AtomicU64::new(0),
        }
    }

    /// Get or create an IP record
    pub fn get_or_create(&self, ip: IpAddr) -> IPRecord {
        self.records
            .entry(ip)
            .or_insert_with(|| {
                self.total_ips.fetch_add(1, Ordering::Relaxed);
                IPRecord::new(ip)
            })
            .clone()
    }

    /// Get an IP record if it exists
    pub fn get(&self, ip: &IpAddr) -> Option<IPRecord> {
        self.records.get(ip).map(|r| r.clone())
    }

    /// Check if an IP is currently blocked
    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        if let Some(mut record) = self.records.get_mut(ip) {
            // Check and clear expired blocks
            if record.check_block_expiry() {
                self.blocked_ips.fetch_sub(1, Ordering::Relaxed);
                return false;
            }
            return record.is_blocked;
        }
        false
    }

    /// Get the threat score for an IP
    pub fn get_threat_score(&self, ip: &IpAddr) -> ThreatScore {
        self.records.get(ip).map(|r| r.threat_score).unwrap_or(0)
    }

    /// Record an action for an IP
    pub fn record_action(
        &self,
        ip: IpAddr,
        action: ActionType,
        category: BehaviorCategory,
        backend_id: Option<&str>,
        protocol: Option<&str>,
    ) -> ThreatScore {
        let mut record = self.records.entry(ip).or_insert_with(|| {
            self.total_ips.fetch_add(1, Ordering::Relaxed);
            IPRecord::new(ip)
        });

        record.record_action(action, category, backend_id, protocol);

        // Check for auto-block
        if self.config.auto_block_enabled && !record.is_blocked && record.should_auto_block() {
            let reason = format!(
                "Auto-blocked due to threat score {} and suspicious activity",
                record.threat_score
            );
            record.block(self.config.auto_block_duration, &reason);
            self.blocked_ips.fetch_add(1, Ordering::Relaxed);
            info!(ip = %ip, score = record.threat_score, "IP auto-blocked");
        }

        record.threat_score
    }

    /// Block an IP manually
    pub fn block_ip(&self, ip: IpAddr, duration: Duration, reason: &str) {
        let mut record = self.records.entry(ip).or_insert_with(|| {
            self.total_ips.fetch_add(1, Ordering::Relaxed);
            IPRecord::new(ip)
        });

        if !record.is_blocked {
            self.blocked_ips.fetch_add(1, Ordering::Relaxed);
        }
        record.block(duration, reason);
        info!(ip = %ip, duration = ?duration, reason = reason, "IP manually blocked");
    }

    /// Unblock an IP manually
    pub fn unblock_ip(&self, ip: &IpAddr) -> bool {
        if let Some(mut record) = self.records.get_mut(ip) {
            if record.is_blocked {
                record.unblock();
                self.blocked_ips.fetch_sub(1, Ordering::Relaxed);
                info!(ip = %ip, "IP manually unblocked");
                return true;
            }
        }
        false
    }

    /// Update GeoIP information for an IP
    pub fn update_geoip(
        &self,
        ip: &IpAddr,
        country_code: Option<&str>,
        asn: Option<u32>,
        asn_org: Option<&str>,
    ) {
        if let Some(mut record) = self.records.get_mut(ip) {
            record.country_code = country_code.map(String::from);
            record.asn = asn;
            record.asn_org = asn_org.map(String::from);
        }
    }

    /// Mark an IP as a known Tor exit node
    pub fn mark_tor_exit(&self, ip: &IpAddr, is_tor: bool) {
        if let Some(mut record) = self.records.get_mut(ip) {
            record.is_tor_exit = is_tor;
            record.update_score();
        }
    }

    /// Mark an IP as a known VPN/proxy
    pub fn mark_vpn_proxy(&self, ip: &IpAddr, is_vpn: bool) {
        if let Some(mut record) = self.records.get_mut(ip) {
            record.is_vpn_proxy = is_vpn;
            record.update_score();
        }
    }

    /// Mark an IP as a datacenter IP
    pub fn mark_datacenter(&self, ip: &IpAddr, is_dc: bool) {
        if let Some(mut record) = self.records.get_mut(ip) {
            record.is_datacenter = is_dc;
            record.update_score();
        }
    }

    /// Get top threat IPs
    pub fn get_top_threats(&self, limit: usize) -> Vec<IPRecord> {
        let mut records: Vec<_> = self.records.iter().map(|r| r.value().clone()).collect();
        records.sort_by(|a, b| b.threat_score.cmp(&a.threat_score));
        records.truncate(limit);
        records
    }

    /// Get all blocked IPs
    pub fn get_blocked_ips(&self) -> Vec<IPRecord> {
        self.records
            .iter()
            .filter(|r| r.is_blocked)
            .map(|r| r.value().clone())
            .collect()
    }

    /// Get statistics
    pub fn stats(&self) -> ScoringStats {
        let mut high_threat = 0;
        let mut medium_threat = 0;
        let mut low_threat = 0;

        for record in self.records.iter() {
            match record.threat_score {
                0..=30 => low_threat += 1,
                31..=60 => medium_threat += 1,
                _ => high_threat += 1,
            }
        }

        ScoringStats {
            total_ips: self.total_ips.load(Ordering::Relaxed),
            blocked_ips: self.blocked_ips.load(Ordering::Relaxed),
            high_threat_count: high_threat,
            medium_threat_count: medium_threat,
            low_threat_count: low_threat,
        }
    }

    /// Cleanup expired blocks and old records
    pub fn cleanup(&self) {
        let cutoff = Utc::now() - Duration::hours(24);
        let mut to_remove = Vec::new();

        for mut record in self.records.iter_mut() {
            // Clear expired blocks
            if record.check_block_expiry() {
                self.blocked_ips.fetch_sub(1, Ordering::Relaxed);
            }

            // Mark old inactive records for removal
            if record.last_seen < cutoff && record.threat_score < 10 && !record.is_blocked {
                to_remove.push(*record.key());
            }
        }

        // Remove old records
        for ip in to_remove {
            self.records.remove(&ip);
            self.total_ips.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Scoring statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringStats {
    pub total_ips: u64,
    pub blocked_ips: u64,
    pub high_threat_count: u64,
    pub medium_threat_count: u64,
    pub low_threat_count: u64,
}

/// Threat intelligence feed integration
pub struct ThreatIntelFeed {
    /// Known bad IPs from feeds
    known_bad_ips: DashMap<IpAddr, ThreatIntelEntry>,
    /// Last update time
    last_updated: std::sync::RwLock<DateTime<Utc>>,
}

/// Entry from threat intelligence feed
#[derive(Debug, Clone)]
pub struct ThreatIntelEntry {
    pub ip: IpAddr,
    pub threat_type: String,
    pub confidence: u8,
    pub source: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl ThreatIntelFeed {
    /// Create a new threat intel feed
    pub fn new() -> Self {
        Self {
            known_bad_ips: DashMap::new(),
            last_updated: std::sync::RwLock::new(Utc::now()),
        }
    }

    /// Check if an IP is in the threat feed
    pub fn is_known_bad(&self, ip: &IpAddr) -> Option<ThreatIntelEntry> {
        self.known_bad_ips.get(ip).map(|e| e.clone())
    }

    /// Add an IP to the threat feed
    pub fn add_entry(&self, entry: ThreatIntelEntry) {
        self.known_bad_ips.insert(entry.ip, entry);
    }

    /// Remove an IP from the threat feed
    pub fn remove_entry(&self, ip: &IpAddr) -> bool {
        self.known_bad_ips.remove(ip).is_some()
    }

    /// Get count of known bad IPs
    pub fn count(&self) -> usize {
        self.known_bad_ips.len()
    }

    /// Update last updated time
    pub fn mark_updated(&self) {
        *self.last_updated.write().unwrap() = Utc::now();
    }

    /// Get last updated time
    pub fn last_updated(&self) -> DateTime<Utc> {
        *self.last_updated.read().unwrap()
    }
}

impl Default for ThreatIntelFeed {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
    }

    #[test]
    fn test_new_ip_record() {
        let record = IPRecord::new(test_ip());
        assert_eq!(record.threat_score, 0);
        assert_eq!(record.total_requests, 0);
        assert!(!record.is_blocked);
    }

    #[test]
    fn test_record_action() {
        let mut record = IPRecord::new(test_ip());
        record.record_action(ActionType::Blocked, BehaviorCategory::Attack, None, None);

        assert_eq!(record.total_requests, 1);
        assert_eq!(record.blocked_requests, 1);
        assert!(record.threat_score > 0);
    }

    #[test]
    fn test_auto_block_threshold() {
        let engine = ScoringEngine::new(ScoringConfig::default());
        let ip = test_ip();

        // Record many blocked requests
        for _ in 0..20 {
            engine.record_action(
                ip,
                ActionType::Blocked,
                BehaviorCategory::Attack,
                None,
                None,
            );
        }

        assert!(engine.is_blocked(&ip));
    }

    #[test]
    fn test_manual_block_unblock() {
        let engine = ScoringEngine::new(ScoringConfig::default());
        let ip = test_ip();

        engine.block_ip(ip, Duration::hours(1), "Test block");
        assert!(engine.is_blocked(&ip));

        engine.unblock_ip(&ip);
        assert!(!engine.is_blocked(&ip));
    }

    #[test]
    fn test_threat_score_categories() {
        let mut record = IPRecord::new(test_ip());
        record.active_categories.push(BehaviorCategory::Attack);
        record.update_score();

        assert!(record.threat_score >= BehaviorCategory::Attack.base_score());
    }

    #[test]
    fn test_challenge_affects_score() {
        let mut record = IPRecord::new(test_ip());

        // Passing challenges should reduce score
        record.record_action(
            ActionType::ChallengePassed,
            BehaviorCategory::Normal,
            None,
            None,
        );
        let score_after_pass = record.threat_score;

        // Failing challenges should increase score
        let mut record2 = IPRecord::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
        record2.record_action(
            ActionType::ChallengeFailed,
            BehaviorCategory::Normal,
            None,
            None,
        );
        let score_after_fail = record2.threat_score;

        assert!(score_after_fail > score_after_pass);
    }

    #[test]
    fn test_stats() {
        let engine = ScoringEngine::new(ScoringConfig::default());
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        engine.record_action(
            ip1,
            ActionType::Allowed,
            BehaviorCategory::Normal,
            None,
            None,
        );
        engine.record_action(
            ip2,
            ActionType::Blocked,
            BehaviorCategory::Attack,
            None,
            None,
        );

        let stats = engine.stats();
        assert_eq!(stats.total_ips, 2);
    }
}
