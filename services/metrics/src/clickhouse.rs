//! ClickHouse Integration for High-Volume Event Analytics
//!
//! This module provides ClickHouse integration for storing and querying:
//! - Request events (all traffic)
//! - Attack events (blocked/challenged requests)
//! - Connection events (TCP/UDP sessions)
//! - Filter match events (rule hits)
//!
//! ClickHouse's columnar storage is ideal for analytics workloads with
//! high insert rates and complex aggregation queries.

use chrono::{DateTime, Utc};
use clickhouse::{Client, Row};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

/// ClickHouse errors
#[derive(Debug, Error)]
pub enum ClickHouseError {
    #[error("ClickHouse client error: {0}")]
    Client(#[from] clickhouse::error::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Query error: {0}")]
    Query(String),
}

/// ClickHouse configuration
#[derive(Debug, Clone)]
pub struct ClickHouseConfig {
    /// ClickHouse HTTP URL (e.g., http://localhost:8123)
    pub url: String,
    /// Database name
    pub database: String,
    /// Optional username
    pub username: Option<String>,
    /// Optional password
    pub password: Option<String>,
    /// Batch insert size
    pub batch_size: usize,
    /// Flush interval
    pub flush_interval: Duration,
    /// TTL for raw events (in days)
    pub raw_ttl_days: u32,
    /// TTL for aggregated events (in days)
    pub aggregated_ttl_days: u32,
}

impl Default for ClickHouseConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:8123".to_string(),
            database: "pistonprotection".to_string(),
            username: None,
            password: None,
            batch_size: 10000,
            flush_interval: Duration::from_secs(5),
            raw_ttl_days: 7,
            aggregated_ttl_days: 365,
        }
    }
}

/// Request event for ClickHouse storage
#[derive(Debug, Clone, Row, Serialize, Deserialize)]
pub struct RequestEvent {
    /// Event timestamp
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    pub timestamp: DateTime<Utc>,
    /// Backend ID
    pub backend_id: String,
    /// Worker ID that processed the request
    pub worker_id: String,
    /// Source IP address (as string for ClickHouse IPv6 type)
    pub source_ip: String,
    /// Source port
    pub source_port: u16,
    /// Destination port
    pub dest_port: u16,
    /// Protocol (tcp, udp, http, etc.)
    pub protocol: String,
    /// HTTP method (if applicable)
    pub http_method: String,
    /// HTTP path (if applicable)
    pub http_path: String,
    /// HTTP status code (if applicable)
    pub http_status: u16,
    /// Request size in bytes
    pub request_bytes: u64,
    /// Response size in bytes
    pub response_bytes: u64,
    /// Latency in microseconds
    pub latency_us: u64,
    /// Action taken (allow, block, challenge, rate_limit)
    pub action: String,
    /// Filter ID that matched (if any)
    pub filter_id: String,
    /// GeoIP country code
    pub country_code: String,
    /// ASN number
    pub asn: u32,
    /// ASN organization name
    pub asn_org: String,
    /// User agent (for HTTP)
    pub user_agent: String,
    /// Is this request part of an attack
    pub is_attack: bool,
    /// Attack type classification
    pub attack_type: String,
    /// Threat score (0-100)
    pub threat_score: u8,
}

/// Attack event for ClickHouse storage
#[derive(Debug, Clone, Row, Serialize, Deserialize)]
pub struct AttackEventRecord {
    /// Event ID
    pub event_id: String,
    /// Start timestamp
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    pub started_at: DateTime<Utc>,
    /// End timestamp (nullable)
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis::option")]
    pub ended_at: Option<DateTime<Utc>>,
    /// Backend ID
    pub backend_id: String,
    /// Attack type
    pub attack_type: String,
    /// Severity (1-5)
    pub severity: u8,
    /// Peak packets per second
    pub peak_pps: u64,
    /// Peak bits per second
    pub peak_bps: u64,
    /// Total packets during attack
    pub total_packets: u64,
    /// Total bytes during attack
    pub total_bytes: u64,
    /// Packets mitigated
    pub packets_mitigated: u64,
    /// Mitigation rate (0-100)
    pub mitigation_rate: f32,
    /// Unique source IPs
    pub unique_sources: u32,
    /// Top attacking countries (comma-separated)
    pub top_countries: String,
    /// Top attacking ASNs (comma-separated)
    pub top_asns: String,
}

/// Connection event for session tracking
#[derive(Debug, Clone, Row, Serialize, Deserialize)]
pub struct ConnectionEvent {
    /// Event timestamp
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    pub timestamp: DateTime<Utc>,
    /// Connection ID
    pub connection_id: String,
    /// Backend ID
    pub backend_id: String,
    /// Worker ID
    pub worker_id: String,
    /// Source IP
    pub source_ip: String,
    /// Source port
    pub source_port: u16,
    /// Destination port
    pub dest_port: u16,
    /// Protocol
    pub protocol: String,
    /// Event type (connect, disconnect, timeout)
    pub event_type: String,
    /// Duration in milliseconds (for disconnect events)
    pub duration_ms: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Country code
    pub country_code: String,
    /// ASN
    pub asn: u32,
}

/// Filter match event
#[derive(Debug, Clone, Row, Serialize, Deserialize)]
pub struct FilterMatchEvent {
    /// Event timestamp
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    pub timestamp: DateTime<Utc>,
    /// Filter ID
    pub filter_id: String,
    /// Filter name
    pub filter_name: String,
    /// Backend ID
    pub backend_id: String,
    /// Source IP
    pub source_ip: String,
    /// Action taken
    pub action: String,
    /// Match reason
    pub match_reason: String,
    /// Match details (JSON)
    pub match_details: String,
}

/// ClickHouse analytics client
pub struct ClickHouseAnalytics {
    /// ClickHouse client
    client: Client,
    /// Configuration
    config: ClickHouseConfig,
    /// Request event buffer
    request_buffer: Arc<RwLock<Vec<RequestEvent>>>,
    /// Connection event buffer
    connection_buffer: Arc<RwLock<Vec<ConnectionEvent>>>,
    /// Filter match buffer
    filter_buffer: Arc<RwLock<Vec<FilterMatchEvent>>>,
}

impl ClickHouseAnalytics {
    /// Create a new ClickHouse analytics client
    pub async fn new(config: ClickHouseConfig) -> Result<Self, ClickHouseError> {
        let mut client = Client::default()
            .with_url(&config.url)
            .with_database(&config.database);

        if let Some(ref username) = config.username {
            client = client.with_user(username);
        }
        if let Some(ref password) = config.password {
            client = client.with_password(password);
        }

        let analytics = Self {
            client,
            config,
            request_buffer: Arc::new(RwLock::new(Vec::with_capacity(10000))),
            connection_buffer: Arc::new(RwLock::new(Vec::with_capacity(1000))),
            filter_buffer: Arc::new(RwLock::new(Vec::with_capacity(1000))),
        };

        // Initialize tables
        analytics.initialize_tables().await?;

        info!("ClickHouse analytics client initialized");
        Ok(analytics)
    }

    /// Initialize ClickHouse tables
    async fn initialize_tables(&self) -> Result<(), ClickHouseError> {
        // Request events table
        self.client
            .query(
                r#"
                CREATE TABLE IF NOT EXISTS request_events (
                    timestamp DateTime64(3),
                    backend_id LowCardinality(String),
                    worker_id LowCardinality(String),
                    source_ip IPv6,
                    source_port UInt16,
                    dest_port UInt16,
                    protocol LowCardinality(String),
                    http_method LowCardinality(String),
                    http_path String,
                    http_status UInt16,
                    request_bytes UInt64,
                    response_bytes UInt64,
                    latency_us UInt64,
                    action LowCardinality(String),
                    filter_id String,
                    country_code LowCardinality(String),
                    asn UInt32,
                    asn_org String,
                    user_agent String,
                    is_attack Bool,
                    attack_type LowCardinality(String),
                    threat_score UInt8,

                    INDEX idx_backend_id backend_id TYPE bloom_filter GRANULARITY 1,
                    INDEX idx_source_ip source_ip TYPE bloom_filter GRANULARITY 1,
                    INDEX idx_action action TYPE set(0) GRANULARITY 1,
                    INDEX idx_is_attack is_attack TYPE set(0) GRANULARITY 1
                )
                ENGINE = MergeTree()
                PARTITION BY toYYYYMMDD(timestamp)
                ORDER BY (backend_id, timestamp, source_ip)
                TTL toDateTime(timestamp) + INTERVAL ? DAY
                SETTINGS index_granularity = 8192
                "#,
            )
            .bind(self.config.raw_ttl_days)
            .execute()
            .await?;

        // Attack events table
        self.client
            .query(
                r#"
                CREATE TABLE IF NOT EXISTS attack_events (
                    event_id String,
                    started_at DateTime64(3),
                    ended_at Nullable(DateTime64(3)),
                    backend_id LowCardinality(String),
                    attack_type LowCardinality(String),
                    severity UInt8,
                    peak_pps UInt64,
                    peak_bps UInt64,
                    total_packets UInt64,
                    total_bytes UInt64,
                    packets_mitigated UInt64,
                    mitigation_rate Float32,
                    unique_sources UInt32,
                    top_countries String,
                    top_asns String,

                    INDEX idx_backend attack_type TYPE set(0) GRANULARITY 1
                )
                ENGINE = MergeTree()
                PARTITION BY toYYYYMM(started_at)
                ORDER BY (backend_id, started_at)
                TTL toDateTime(started_at) + INTERVAL ? DAY
                "#,
            )
            .bind(self.config.aggregated_ttl_days)
            .execute()
            .await?;

        // Connection events table
        self.client
            .query(
                r#"
                CREATE TABLE IF NOT EXISTS connection_events (
                    timestamp DateTime64(3),
                    connection_id String,
                    backend_id LowCardinality(String),
                    worker_id LowCardinality(String),
                    source_ip IPv6,
                    source_port UInt16,
                    dest_port UInt16,
                    protocol LowCardinality(String),
                    event_type LowCardinality(String),
                    duration_ms UInt64,
                    bytes_sent UInt64,
                    bytes_received UInt64,
                    country_code LowCardinality(String),
                    asn UInt32
                )
                ENGINE = MergeTree()
                PARTITION BY toYYYYMMDD(timestamp)
                ORDER BY (backend_id, timestamp, connection_id)
                TTL toDateTime(timestamp) + INTERVAL ? DAY
                "#,
            )
            .bind(self.config.raw_ttl_days)
            .execute()
            .await?;

        // Filter match events table
        self.client
            .query(
                r#"
                CREATE TABLE IF NOT EXISTS filter_match_events (
                    timestamp DateTime64(3),
                    filter_id String,
                    filter_name String,
                    backend_id LowCardinality(String),
                    source_ip IPv6,
                    action LowCardinality(String),
                    match_reason String,
                    match_details String
                )
                ENGINE = MergeTree()
                PARTITION BY toYYYYMMDD(timestamp)
                ORDER BY (backend_id, filter_id, timestamp)
                TTL toDateTime(timestamp) + INTERVAL ? DAY
                "#,
            )
            .bind(self.config.raw_ttl_days)
            .execute()
            .await?;

        // Create materialized views for aggregations
        self.create_aggregation_views().await?;

        info!("ClickHouse tables initialized");
        Ok(())
    }

    /// Create materialized views for efficient aggregations
    async fn create_aggregation_views(&self) -> Result<(), ClickHouseError> {
        // Hourly traffic aggregation
        self.client
            .query(
                r#"
                CREATE MATERIALIZED VIEW IF NOT EXISTS traffic_hourly
                ENGINE = SummingMergeTree()
                PARTITION BY toYYYYMM(hour)
                ORDER BY (backend_id, hour, protocol, country_code)
                AS SELECT
                    toStartOfHour(timestamp) as hour,
                    backend_id,
                    protocol,
                    country_code,
                    count() as request_count,
                    sum(request_bytes) as total_request_bytes,
                    sum(response_bytes) as total_response_bytes,
                    sum(latency_us) as total_latency_us,
                    countIf(action = 'block') as blocked_count,
                    countIf(action = 'challenge') as challenged_count,
                    countIf(action = 'rate_limit') as rate_limited_count,
                    countIf(is_attack) as attack_count,
                    uniqExact(source_ip) as unique_ips
                FROM request_events
                GROUP BY hour, backend_id, protocol, country_code
                "#,
            )
            .execute()
            .await
            .ok(); // Ignore if already exists

        // Daily traffic aggregation
        self.client
            .query(
                r#"
                CREATE MATERIALIZED VIEW IF NOT EXISTS traffic_daily
                ENGINE = SummingMergeTree()
                PARTITION BY toYYYYMM(day)
                ORDER BY (backend_id, day)
                AS SELECT
                    toStartOfDay(timestamp) as day,
                    backend_id,
                    count() as request_count,
                    sum(request_bytes) as total_request_bytes,
                    sum(response_bytes) as total_response_bytes,
                    avg(latency_us) as avg_latency_us,
                    max(latency_us) as max_latency_us,
                    countIf(action = 'block') as blocked_count,
                    countIf(is_attack) as attack_count,
                    uniqExact(source_ip) as unique_ips
                FROM request_events
                GROUP BY day, backend_id
                "#,
            )
            .execute()
            .await
            .ok();

        // Top attackers aggregation
        self.client
            .query(
                r#"
                CREATE MATERIALIZED VIEW IF NOT EXISTS top_attackers_hourly
                ENGINE = SummingMergeTree()
                PARTITION BY toYYYYMMDD(hour)
                ORDER BY (backend_id, hour, source_ip)
                AS SELECT
                    toStartOfHour(timestamp) as hour,
                    backend_id,
                    source_ip,
                    country_code,
                    asn,
                    count() as request_count,
                    countIf(action = 'block') as blocked_count,
                    sum(threat_score) as total_threat_score
                FROM request_events
                WHERE is_attack = true OR action = 'block'
                GROUP BY hour, backend_id, source_ip, country_code, asn
                "#,
            )
            .execute()
            .await
            .ok();

        // Filter effectiveness
        self.client
            .query(
                r#"
                CREATE MATERIALIZED VIEW IF NOT EXISTS filter_effectiveness
                ENGINE = SummingMergeTree()
                PARTITION BY toYYYYMMDD(hour)
                ORDER BY (backend_id, filter_id, hour)
                AS SELECT
                    toStartOfHour(timestamp) as hour,
                    backend_id,
                    filter_id,
                    action,
                    count() as match_count
                FROM filter_match_events
                GROUP BY hour, backend_id, filter_id, action
                "#,
            )
            .execute()
            .await
            .ok();

        Ok(())
    }

    /// Add a request event to the buffer
    pub async fn record_request(&self, event: RequestEvent) {
        let mut buffer = self.request_buffer.write().await;
        buffer.push(event);

        if buffer.len() >= self.config.batch_size {
            let events = std::mem::take(&mut *buffer);
            drop(buffer);
            if let Err(e) = self.flush_request_events(events).await {
                error!("Failed to flush request events: {}", e);
            }
        }
    }

    /// Add a connection event to the buffer
    pub async fn record_connection(&self, event: ConnectionEvent) {
        let mut buffer = self.connection_buffer.write().await;
        buffer.push(event);

        if buffer.len() >= self.config.batch_size / 10 {
            let events = std::mem::take(&mut *buffer);
            drop(buffer);
            if let Err(e) = self.flush_connection_events(events).await {
                error!("Failed to flush connection events: {}", e);
            }
        }
    }

    /// Add a filter match event to the buffer
    pub async fn record_filter_match(&self, event: FilterMatchEvent) {
        let mut buffer = self.filter_buffer.write().await;
        buffer.push(event);

        if buffer.len() >= self.config.batch_size / 10 {
            let events = std::mem::take(&mut *buffer);
            drop(buffer);
            if let Err(e) = self.flush_filter_events(events).await {
                error!("Failed to flush filter events: {}", e);
            }
        }
    }

    /// Record an attack event
    pub async fn record_attack(&self, event: AttackEventRecord) -> Result<(), ClickHouseError> {
        let mut inserter = self.client.inserter("attack_events")?;
        inserter.write(&event)?;
        inserter.end().await?;
        Ok(())
    }

    /// Flush request events to ClickHouse
    async fn flush_request_events(&self, events: Vec<RequestEvent>) -> Result<(), ClickHouseError> {
        if events.is_empty() {
            return Ok(());
        }

        debug!("Flushing {} request events to ClickHouse", events.len());

        let mut inserter = self.client.inserter("request_events")?;
        for event in events {
            inserter.write(&event)?;
        }
        inserter.end().await?;

        Ok(())
    }

    /// Flush connection events to ClickHouse
    async fn flush_connection_events(
        &self,
        events: Vec<ConnectionEvent>,
    ) -> Result<(), ClickHouseError> {
        if events.is_empty() {
            return Ok(());
        }

        debug!("Flushing {} connection events to ClickHouse", events.len());

        let mut inserter = self.client.inserter("connection_events")?;
        for event in events {
            inserter.write(&event)?;
        }
        inserter.end().await?;

        Ok(())
    }

    /// Flush filter match events to ClickHouse
    async fn flush_filter_events(
        &self,
        events: Vec<FilterMatchEvent>,
    ) -> Result<(), ClickHouseError> {
        if events.is_empty() {
            return Ok(());
        }

        debug!("Flushing {} filter events to ClickHouse", events.len());

        let mut inserter = self.client.inserter("filter_match_events")?;
        for event in events {
            inserter.write(&event)?;
        }
        inserter.end().await?;

        Ok(())
    }

    /// Flush all buffered events
    pub async fn flush_all(&self) -> Result<(), ClickHouseError> {
        // Flush request events
        let events = {
            let mut buffer = self.request_buffer.write().await;
            std::mem::take(&mut *buffer)
        };
        self.flush_request_events(events).await?;

        // Flush connection events
        let events = {
            let mut buffer = self.connection_buffer.write().await;
            std::mem::take(&mut *buffer)
        };
        self.flush_connection_events(events).await?;

        // Flush filter events
        let events = {
            let mut buffer = self.filter_buffer.write().await;
            std::mem::take(&mut *buffer)
        };
        self.flush_filter_events(events).await?;

        Ok(())
    }

    /// Query traffic stats for a backend
    pub async fn get_traffic_stats(
        &self,
        backend_id: &str,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> Result<TrafficStats, ClickHouseError> {
        let stats: TrafficStats = self
            .client
            .query(
                r#"
                SELECT
                    count() as total_requests,
                    sum(request_bytes) as total_request_bytes,
                    sum(response_bytes) as total_response_bytes,
                    avg(latency_us) as avg_latency_us,
                    max(latency_us) as max_latency_us,
                    min(latency_us) as min_latency_us,
                    quantile(0.95)(latency_us) as p95_latency_us,
                    quantile(0.99)(latency_us) as p99_latency_us,
                    countIf(action = 'allow') as allowed_requests,
                    countIf(action = 'block') as blocked_requests,
                    countIf(action = 'challenge') as challenged_requests,
                    countIf(action = 'rate_limit') as rate_limited_requests,
                    uniqExact(source_ip) as unique_ips
                FROM request_events
                WHERE backend_id = ? AND timestamp >= ? AND timestamp <= ?
                "#,
            )
            .bind(backend_id)
            .bind(start_time)
            .bind(end_time)
            .fetch_one()
            .await?;

        Ok(stats)
    }

    /// Query top source IPs for a backend
    pub async fn get_top_sources(
        &self,
        backend_id: &str,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<SourceStats>, ClickHouseError> {
        let sources: Vec<SourceStats> = self
            .client
            .query(
                r#"
                SELECT
                    source_ip,
                    country_code,
                    asn,
                    asn_org,
                    count() as request_count,
                    sum(request_bytes) as total_bytes,
                    countIf(action = 'block') as blocked_count,
                    avg(threat_score) as avg_threat_score
                FROM request_events
                WHERE backend_id = ? AND timestamp >= ? AND timestamp <= ?
                GROUP BY source_ip, country_code, asn, asn_org
                ORDER BY request_count DESC
                LIMIT ?
                "#,
            )
            .bind(backend_id)
            .bind(start_time)
            .bind(end_time)
            .bind(limit)
            .fetch_all()
            .await?;

        Ok(sources)
    }

    /// Query traffic by country for a backend
    pub async fn get_traffic_by_country(
        &self,
        backend_id: &str,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> Result<Vec<CountryStats>, ClickHouseError> {
        let countries: Vec<CountryStats> = self
            .client
            .query(
                r#"
                SELECT
                    country_code,
                    count() as request_count,
                    sum(request_bytes) as total_bytes,
                    countIf(action = 'block') as blocked_count,
                    uniqExact(source_ip) as unique_ips
                FROM request_events
                WHERE backend_id = ? AND timestamp >= ? AND timestamp <= ?
                GROUP BY country_code
                ORDER BY request_count DESC
                "#,
            )
            .bind(backend_id)
            .bind(start_time)
            .bind(end_time)
            .fetch_all()
            .await?;

        Ok(countries)
    }

    /// Query traffic time series
    pub async fn get_traffic_time_series(
        &self,
        backend_id: &str,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        interval_seconds: u32,
    ) -> Result<Vec<TimeSeriesPoint>, ClickHouseError> {
        let points: Vec<TimeSeriesPoint> = self
            .client
            .query(
                r#"
                SELECT
                    toStartOfInterval(timestamp, INTERVAL ? SECOND) as interval_start,
                    count() as request_count,
                    sum(request_bytes) as bytes_in,
                    sum(response_bytes) as bytes_out,
                    avg(latency_us) as avg_latency,
                    countIf(action = 'block') as blocked
                FROM request_events
                WHERE backend_id = ? AND timestamp >= ? AND timestamp <= ?
                GROUP BY interval_start
                ORDER BY interval_start
                "#,
            )
            .bind(interval_seconds)
            .bind(backend_id)
            .bind(start_time)
            .bind(end_time)
            .fetch_all()
            .await?;

        Ok(points)
    }

    /// Query attack events for a backend
    pub async fn get_attack_events(
        &self,
        backend_id: &str,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<AttackEventRecord>, ClickHouseError> {
        let events: Vec<AttackEventRecord> = self
            .client
            .query(
                r#"
                SELECT *
                FROM attack_events
                WHERE backend_id = ? AND started_at >= ? AND started_at <= ?
                ORDER BY started_at DESC
                LIMIT ?
                "#,
            )
            .bind(backend_id)
            .bind(start_time)
            .bind(end_time)
            .bind(limit)
            .fetch_all()
            .await?;

        Ok(events)
    }

    /// Query filter effectiveness
    pub async fn get_filter_stats(
        &self,
        backend_id: &str,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> Result<Vec<FilterStats>, ClickHouseError> {
        let stats: Vec<FilterStats> = self
            .client
            .query(
                r#"
                SELECT
                    filter_id,
                    filter_name,
                    count() as match_count,
                    countIf(action = 'block') as blocked_count,
                    countIf(action = 'allow') as allowed_count,
                    countIf(action = 'challenge') as challenged_count
                FROM filter_match_events
                WHERE backend_id = ? AND timestamp >= ? AND timestamp <= ?
                GROUP BY filter_id, filter_name
                ORDER BY match_count DESC
                "#,
            )
            .bind(backend_id)
            .bind(start_time)
            .bind(end_time)
            .fetch_all()
            .await?;

        Ok(stats)
    }

    /// Get real-time request rate
    pub async fn get_request_rate(
        &self,
        backend_id: &str,
        window_seconds: u32,
    ) -> Result<f64, ClickHouseError> {
        #[derive(Row, Deserialize)]
        struct RateResult {
            rate: f64,
        }

        let result: RateResult = self
            .client
            .query(
                r#"
                SELECT count() / ? as rate
                FROM request_events
                WHERE backend_id = ? AND timestamp >= now() - INTERVAL ? SECOND
                "#,
            )
            .bind(window_seconds)
            .bind(backend_id)
            .bind(window_seconds)
            .fetch_one()
            .await?;

        Ok(result.rate)
    }

    /// Get unique IP count
    pub async fn get_unique_ip_count(
        &self,
        backend_id: &str,
        window_seconds: u32,
    ) -> Result<u64, ClickHouseError> {
        #[derive(Row, Deserialize)]
        struct CountResult {
            count: u64,
        }

        let result: CountResult = self
            .client
            .query(
                r#"
                SELECT uniqExact(source_ip) as count
                FROM request_events
                WHERE backend_id = ? AND timestamp >= now() - INTERVAL ? SECOND
                "#,
            )
            .bind(backend_id)
            .bind(window_seconds)
            .fetch_one()
            .await?;

        Ok(result.count)
    }
}

/// Traffic statistics result
#[derive(Debug, Clone, Row, Serialize, Deserialize)]
pub struct TrafficStats {
    pub total_requests: u64,
    pub total_request_bytes: u64,
    pub total_response_bytes: u64,
    pub avg_latency_us: f64,
    pub max_latency_us: u64,
    pub min_latency_us: u64,
    pub p95_latency_us: f64,
    pub p99_latency_us: f64,
    pub allowed_requests: u64,
    pub blocked_requests: u64,
    pub challenged_requests: u64,
    pub rate_limited_requests: u64,
    pub unique_ips: u64,
}

/// Source IP statistics
#[derive(Debug, Clone, Row, Serialize, Deserialize)]
pub struct SourceStats {
    pub source_ip: String,
    pub country_code: String,
    pub asn: u32,
    pub asn_org: String,
    pub request_count: u64,
    pub total_bytes: u64,
    pub blocked_count: u64,
    pub avg_threat_score: f64,
}

/// Country traffic statistics
#[derive(Debug, Clone, Row, Serialize, Deserialize)]
pub struct CountryStats {
    pub country_code: String,
    pub request_count: u64,
    pub total_bytes: u64,
    pub blocked_count: u64,
    pub unique_ips: u64,
}

/// Time series data point
#[derive(Debug, Clone, Row, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    pub interval_start: DateTime<Utc>,
    pub request_count: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub avg_latency: f64,
    pub blocked: u64,
}

/// Filter effectiveness statistics
#[derive(Debug, Clone, Row, Serialize, Deserialize)]
pub struct FilterStats {
    pub filter_id: String,
    pub filter_name: String,
    pub match_count: u64,
    pub blocked_count: u64,
    pub allowed_count: u64,
    pub challenged_count: u64,
}

/// Start the background flush task
pub fn start_flush_task(analytics: Arc<ClickHouseAnalytics>, flush_interval: Duration) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(flush_interval);
        loop {
            interval.tick().await;
            if let Err(e) = analytics.flush_all().await {
                error!("ClickHouse flush error: {}", e);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ClickHouseConfig::default();
        assert_eq!(config.database, "pistonprotection");
        assert_eq!(config.batch_size, 10000);
    }

    #[test]
    fn test_request_event_creation() {
        let event = RequestEvent {
            timestamp: Utc::now(),
            backend_id: "backend-1".to_string(),
            worker_id: "worker-1".to_string(),
            source_ip: "192.168.1.1".to_string(),
            source_port: 12345,
            dest_port: 80,
            protocol: "http".to_string(),
            http_method: "GET".to_string(),
            http_path: "/api/test".to_string(),
            http_status: 200,
            request_bytes: 1024,
            response_bytes: 2048,
            latency_us: 5000,
            action: "allow".to_string(),
            filter_id: String::new(),
            country_code: "US".to_string(),
            asn: 15169,
            asn_org: "Google".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            is_attack: false,
            attack_type: String::new(),
            threat_score: 0,
        };

        assert_eq!(event.backend_id, "backend-1");
        assert_eq!(event.http_status, 200);
    }
}
