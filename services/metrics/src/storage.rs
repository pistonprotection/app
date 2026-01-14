//! Time-series data storage with Redis and PostgreSQL
//!
//! This module handles persistent storage of metrics data for historical
//! analysis, including time-series queries and attack event logging.

use crate::aggregator::{GeoTrafficData, RawAttackMetrics, RawTrafficMetrics, RawWorkerMetrics};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use deadpool_redis::Pool as RedisPool;
use deadpool_redis::redis::AsyncCommands;
use pistonprotection_proto::{
    common::{Pagination, PaginationInfo, Timestamp},
    metrics::*,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use sqlx::postgres::PgPool;
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info};
use uuid::Uuid;

/// Storage errors
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Redis error: {0}")]
    Redis(#[from] deadpool_redis::redis::RedisError),

    #[error("Redis pool error: {0}")]
    RedisPool(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Time-series data point for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TimeSeriesPoint {
    timestamp: i64,
    value: f64,
}

/// Attack event record for database storage
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttackEventRecord {
    id: String,
    backend_id: String,
    started_at: DateTime<Utc>,
    ended_at: Option<DateTime<Utc>>,
    duration_seconds: Option<u32>,
    attack_type: String,
    severity: i32,
    peak_pps: u64,
    peak_bps: u64,
    total_packets: u64,
    total_bytes: u64,
    packets_mitigated: u64,
    mitigation_rate: f32,
    unique_sources: u32,
    top_countries: Vec<String>,
    top_asns: Vec<String>,
}

/// Time-series storage service
pub struct TimeSeriesStorage {
    /// PostgreSQL connection pool for long-term storage
    db_pool: Option<PgPool>,

    /// Redis connection pool for real-time time-series
    redis_pool: Option<RedisPool>,

    /// Redis key prefix
    key_prefix: String,

    /// Retention configuration
    retention: RetentionConfig,
}

/// Retention configuration for different granularities
#[derive(Debug, Clone)]
pub struct RetentionConfig {
    /// Raw data retention (1-minute granularity)
    pub raw_retention: Duration,
    /// 5-minute aggregates retention
    pub five_min_retention: Duration,
    /// Hourly aggregates retention
    pub hourly_retention: Duration,
    /// Daily aggregates retention
    pub daily_retention: Duration,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            raw_retention: Duration::from_secs(24 * 60 * 60), // 24 hours
            five_min_retention: Duration::from_secs(7 * 24 * 60 * 60), // 7 days
            hourly_retention: Duration::from_secs(30 * 24 * 60 * 60), // 30 days
            daily_retention: Duration::from_secs(365 * 24 * 60 * 60), // 1 year
        }
    }
}

impl TimeSeriesStorage {
    /// Create a new time-series storage instance
    pub fn new(
        db_pool: Option<PgPool>,
        redis_pool: Option<RedisPool>,
        key_prefix: &str,
        retention: RetentionConfig,
    ) -> Self {
        Self {
            db_pool,
            redis_pool,
            key_prefix: key_prefix.to_string(),
            retention,
        }
    }

    /// Build a Redis key with prefix
    fn redis_key(&self, parts: &[&str]) -> String {
        format!("{}:{}", self.key_prefix, parts.join(":"))
    }

    /// Get the bucket timestamp for a given granularity
    fn bucket_timestamp(ts: DateTime<Utc>, granularity: TimeGranularity) -> i64 {
        let secs = ts.timestamp();
        match granularity {
            TimeGranularity::Unspecified | TimeGranularity::Minute => secs - (secs % 60),
            TimeGranularity::FiveMinutes => secs - (secs % 300),
            TimeGranularity::FifteenMinutes => secs - (secs % 900),
            TimeGranularity::Hour => secs - (secs % 3600),
            TimeGranularity::Day => secs - (secs % 86400),
        }
    }

    /// Store worker metrics time-series data
    pub async fn store_worker_metrics(&self, raw: &RawWorkerMetrics) -> Result<(), StorageError> {
        let timestamp = raw.timestamp.timestamp();

        // Store in Redis for real-time queries
        if let Some(ref pool) = self.redis_pool {
            let mut conn = pool
                .get()
                .await
                .map_err(|e| StorageError::RedisPool(e.to_string()))?;

            // Store CPU metrics
            let cpu_key = self.redis_key(&["worker", &raw.worker_id, "cpu"]);
            let _: () = conn
                .zadd(&cpu_key, timestamp.to_string(), raw.cpu_percent as f64)
                .await?;
            let _: () = conn
                .expire(&cpu_key, self.retention.raw_retention.as_secs() as i64)
                .await?;

            // Store memory metrics
            let mem_key = self.redis_key(&["worker", &raw.worker_id, "memory"]);
            let _: () = conn
                .zadd(&mem_key, timestamp.to_string(), raw.memory_percent as f64)
                .await?;
            let _: () = conn
                .expire(&mem_key, self.retention.raw_retention.as_secs() as i64)
                .await?;

            // Store XDP packets processed
            let xdp_key = self.redis_key(&["worker", &raw.worker_id, "xdp_processed"]);
            let _: () = conn
                .zadd(
                    &xdp_key,
                    timestamp.to_string(),
                    raw.xdp_packets_processed as f64,
                )
                .await?;
            let _: () = conn
                .expire(&xdp_key, self.retention.raw_retention.as_secs() as i64)
                .await?;
        }

        // Store in PostgreSQL for long-term storage
        if let Some(ref pool) = self.db_pool {
            sqlx::query(
                r#"
                INSERT INTO worker_metrics_ts (
                    worker_id, timestamp, cpu_percent, memory_percent, memory_bytes,
                    network_rx_bytes, network_tx_bytes, xdp_packets_processed,
                    xdp_packets_dropped, xdp_latency_avg_ns
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT (worker_id, timestamp) DO UPDATE SET
                    cpu_percent = EXCLUDED.cpu_percent,
                    memory_percent = EXCLUDED.memory_percent,
                    memory_bytes = EXCLUDED.memory_bytes,
                    network_rx_bytes = EXCLUDED.network_rx_bytes,
                    network_tx_bytes = EXCLUDED.network_tx_bytes,
                    xdp_packets_processed = EXCLUDED.xdp_packets_processed,
                    xdp_packets_dropped = EXCLUDED.xdp_packets_dropped,
                    xdp_latency_avg_ns = EXCLUDED.xdp_latency_avg_ns
                "#,
            )
            .bind(&raw.worker_id)
            .bind(raw.timestamp)
            .bind(raw.cpu_percent)
            .bind(raw.memory_percent)
            .bind(raw.memory_bytes as i64)
            .bind(raw.network_rx_bytes as i64)
            .bind(raw.network_tx_bytes as i64)
            .bind(raw.xdp_packets_processed as i64)
            .bind(raw.xdp_packets_dropped as i64)
            .bind(raw.xdp_latency_avg_ns as i64)
            .execute(pool)
            .await?;
        }

        Ok(())
    }

    /// Store traffic metrics time-series data
    pub async fn store_traffic_metrics(&self, raw: &RawTrafficMetrics) -> Result<(), StorageError> {
        let timestamp = raw.timestamp.timestamp();

        // Store in Redis
        if let Some(ref pool) = self.redis_pool {
            let mut conn = pool
                .get()
                .await
                .map_err(|e| StorageError::RedisPool(e.to_string()))?;

            // Store requests per second
            let rps_key = self.redis_key(&["traffic", &raw.backend_id, "rps"]);
            let _: () = conn
                .zadd(
                    &rps_key,
                    timestamp.to_string(),
                    raw.requests_per_second as f64,
                )
                .await?;
            let _: () = conn
                .expire(&rps_key, self.retention.raw_retention.as_secs() as i64)
                .await?;

            // Store bytes in
            let bytes_in_key = self.redis_key(&["traffic", &raw.backend_id, "bytes_in"]);
            let _: () = conn
                .zadd(
                    &bytes_in_key,
                    timestamp.to_string(),
                    raw.bytes_per_second_in as f64,
                )
                .await?;
            let _: () = conn
                .expire(&bytes_in_key, self.retention.raw_retention.as_secs() as i64)
                .await?;

            // Store bytes out
            let bytes_out_key = self.redis_key(&["traffic", &raw.backend_id, "bytes_out"]);
            let _: () = conn
                .zadd(
                    &bytes_out_key,
                    timestamp.to_string(),
                    raw.bytes_per_second_out as f64,
                )
                .await?;
            let _: () = conn
                .expire(
                    &bytes_out_key,
                    self.retention.raw_retention.as_secs() as i64,
                )
                .await?;

            // Store active connections
            let conn_key = self.redis_key(&["traffic", &raw.backend_id, "connections"]);
            let _: () = conn
                .zadd(
                    &conn_key,
                    timestamp.to_string(),
                    raw.active_connections as f64,
                )
                .await?;
            let _: () = conn
                .expire(&conn_key, self.retention.raw_retention.as_secs() as i64)
                .await?;

            // Store packets per second
            let pps_key = self.redis_key(&["traffic", &raw.backend_id, "pps"]);
            let _: () = conn
                .zadd(
                    &pps_key,
                    timestamp.to_string(),
                    raw.packets_per_second as f64,
                )
                .await?;
            let _: () = conn
                .expire(&pps_key, self.retention.raw_retention.as_secs() as i64)
                .await?;
        }

        // Store in PostgreSQL
        if let Some(ref pool) = self.db_pool {
            let protocols_json = serde_json::to_value(&raw.requests_by_protocol)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;

            sqlx::query(
                r#"
                INSERT INTO traffic_metrics_ts (
                    backend_id, worker_id, timestamp, requests_total, requests_per_second,
                    bytes_in, bytes_out, packets_in, packets_out,
                    active_connections, requests_by_protocol
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                ON CONFLICT (backend_id, worker_id, timestamp) DO UPDATE SET
                    requests_total = EXCLUDED.requests_total,
                    requests_per_second = EXCLUDED.requests_per_second,
                    bytes_in = EXCLUDED.bytes_in,
                    bytes_out = EXCLUDED.bytes_out,
                    packets_in = EXCLUDED.packets_in,
                    packets_out = EXCLUDED.packets_out,
                    active_connections = EXCLUDED.active_connections,
                    requests_by_protocol = EXCLUDED.requests_by_protocol
                "#,
            )
            .bind(&raw.backend_id)
            .bind(&raw.worker_id)
            .bind(raw.timestamp)
            .bind(raw.requests_total as i64)
            .bind(raw.requests_per_second as i64)
            .bind(raw.bytes_in as i64)
            .bind(raw.bytes_out as i64)
            .bind(raw.packets_in as i64)
            .bind(raw.packets_out as i64)
            .bind(raw.active_connections as i64)
            .bind(protocols_json)
            .execute(pool)
            .await?;
        }

        Ok(())
    }

    /// Store attack metrics time-series data
    pub async fn store_attack_metrics(&self, raw: &RawAttackMetrics) -> Result<(), StorageError> {
        let timestamp = raw.timestamp.timestamp();

        // Store in Redis
        if let Some(ref pool) = self.redis_pool {
            let mut conn = pool
                .get()
                .await
                .map_err(|e| StorageError::RedisPool(e.to_string()))?;

            // Store attack PPS
            let pps_key = self.redis_key(&["attack", &raw.backend_id, "pps"]);
            let _: () = conn
                .zadd(&pps_key, timestamp.to_string(), raw.attack_pps as f64)
                .await?;
            let _: () = conn
                .expire(&pps_key, self.retention.raw_retention.as_secs() as i64)
                .await?;

            // Store attack BPS
            let bps_key = self.redis_key(&["attack", &raw.backend_id, "bps"]);
            let _: () = conn
                .zadd(&bps_key, timestamp.to_string(), raw.attack_bps as f64)
                .await?;
            let _: () = conn
                .expire(&bps_key, self.retention.raw_retention.as_secs() as i64)
                .await?;

            // Store dropped requests
            let dropped_key = self.redis_key(&["attack", &raw.backend_id, "dropped"]);
            let _: () = conn
                .zadd(
                    &dropped_key,
                    timestamp.to_string(),
                    raw.requests_dropped as f64,
                )
                .await?;
            let _: () = conn
                .expire(&dropped_key, self.retention.raw_retention.as_secs() as i64)
                .await?;

            // Store unique attack IPs
            let ips_key = self.redis_key(&["attack", &raw.backend_id, "unique_ips"]);
            let _: () = conn
                .zadd(
                    &ips_key,
                    timestamp.to_string(),
                    raw.unique_attack_ips as f64,
                )
                .await?;
            let _: () = conn
                .expire(&ips_key, self.retention.raw_retention.as_secs() as i64)
                .await?;
        }

        // Store in PostgreSQL
        if let Some(ref pool) = self.db_pool {
            let top_sources_json = serde_json::to_value(&raw.top_sources)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;

            sqlx::query(
                r#"
                INSERT INTO attack_metrics_ts (
                    backend_id, worker_id, timestamp, under_attack, attack_type,
                    severity, attack_requests, attack_bytes, attack_pps, attack_bps,
                    requests_dropped, requests_challenged, requests_rate_limited,
                    unique_attack_ips, top_sources
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                ON CONFLICT (backend_id, worker_id, timestamp) DO UPDATE SET
                    under_attack = EXCLUDED.under_attack,
                    attack_type = EXCLUDED.attack_type,
                    severity = EXCLUDED.severity,
                    attack_requests = EXCLUDED.attack_requests,
                    attack_bytes = EXCLUDED.attack_bytes,
                    attack_pps = EXCLUDED.attack_pps,
                    attack_bps = EXCLUDED.attack_bps,
                    requests_dropped = EXCLUDED.requests_dropped,
                    requests_challenged = EXCLUDED.requests_challenged,
                    requests_rate_limited = EXCLUDED.requests_rate_limited,
                    unique_attack_ips = EXCLUDED.unique_attack_ips,
                    top_sources = EXCLUDED.top_sources
                "#,
            )
            .bind(&raw.backend_id)
            .bind(&raw.worker_id)
            .bind(raw.timestamp)
            .bind(raw.under_attack)
            .bind(&raw.attack_type)
            .bind(raw.severity)
            .bind(raw.attack_requests as i64)
            .bind(raw.attack_bytes as i64)
            .bind(raw.attack_pps as i64)
            .bind(raw.attack_bps as i64)
            .bind(raw.requests_dropped as i64)
            .bind(raw.requests_challenged as i64)
            .bind(raw.requests_rate_limited as i64)
            .bind(raw.unique_attack_ips as i32)
            .bind(top_sources_json)
            .execute(pool)
            .await?;
        }

        Ok(())
    }

    /// Store traffic snapshot (aggregated)
    pub async fn store_traffic_snapshot(
        &self,
        metrics: &TrafficMetrics,
    ) -> Result<(), StorageError> {
        if let Some(ref pool) = self.db_pool {
            let protocols_json = serde_json::to_value(&metrics.requests_by_protocol)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;

            sqlx::query(
                r#"
                INSERT INTO traffic_snapshots (
                    backend_id, timestamp, requests_total, requests_per_second,
                    bytes_in, bytes_out, packets_in, packets_out,
                    active_connections, requests_by_protocol
                ) VALUES ($1, NOW(), $2, $3, $4, $5, $6, $7, $8, $9)
                "#,
            )
            .bind(&metrics.backend_id)
            .bind(metrics.requests_total as i64)
            .bind(metrics.requests_per_second as i64)
            .bind(metrics.bytes_in as i64)
            .bind(metrics.bytes_out as i64)
            .bind(metrics.packets_in as i64)
            .bind(metrics.packets_out as i64)
            .bind(metrics.active_connections as i64)
            .bind(protocols_json)
            .execute(pool)
            .await?;
        }

        Ok(())
    }

    /// Store attack snapshot (aggregated)
    pub async fn store_attack_snapshot(&self, metrics: &AttackMetrics) -> Result<(), StorageError> {
        if let Some(ref pool) = self.db_pool {
            let top_sources_json = serde_json::to_value(&metrics.top_sources)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;

            sqlx::query(
                r#"
                INSERT INTO attack_snapshots (
                    backend_id, timestamp, under_attack, attack_type, severity,
                    attack_requests, attack_bytes, attack_pps, attack_bps,
                    requests_dropped, unique_attack_ips, top_sources
                ) VALUES ($1, NOW(), $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                "#,
            )
            .bind(&metrics.backend_id)
            .bind(metrics.under_attack)
            .bind(&metrics.attack_type)
            .bind(metrics.severity)
            .bind(metrics.attack_requests as i64)
            .bind(metrics.attack_bytes as i64)
            .bind(metrics.attack_pps as i64)
            .bind(metrics.attack_bps as i64)
            .bind(metrics.requests_dropped as i64)
            .bind(metrics.unique_attack_ips as i32)
            .bind(top_sources_json)
            .execute(pool)
            .await?;
        }

        Ok(())
    }

    /// Store geo traffic data
    pub async fn store_geo_traffic(
        &self,
        backend_id: &str,
        country_code: &str,
        data: &GeoTrafficData,
    ) -> Result<(), StorageError> {
        if let Some(ref pool) = self.db_pool {
            sqlx::query(
                r#"
                INSERT INTO geo_traffic (
                    backend_id, country_code, timestamp, requests, bytes, unique_ips, blocked
                ) VALUES ($1, $2, NOW(), $3, $4, $5, $6)
                ON CONFLICT (backend_id, country_code, timestamp) DO UPDATE SET
                    requests = geo_traffic.requests + EXCLUDED.requests,
                    bytes = geo_traffic.bytes + EXCLUDED.bytes,
                    unique_ips = GREATEST(geo_traffic.unique_ips, EXCLUDED.unique_ips),
                    blocked = EXCLUDED.blocked
                "#,
            )
            .bind(backend_id)
            .bind(country_code)
            .bind(data.requests as i64)
            .bind(data.bytes as i64)
            .bind(data.unique_ips as i64)
            .bind(data.blocked)
            .execute(pool)
            .await?;
        }

        Ok(())
    }

    /// Query time-series data for traffic metrics
    pub async fn query_time_series(
        &self,
        query: &TimeSeriesQuery,
    ) -> Result<Vec<TimeSeries>, StorageError> {
        let backend_id = &query.backend_id;
        let granularity =
            TimeGranularity::try_from(query.granularity).unwrap_or(TimeGranularity::Minute);

        let start_time = query
            .start_time
            .as_ref()
            .map(DateTime::<Utc>::from)
            .unwrap_or_else(|| Utc::now() - ChronoDuration::hours(1));

        let end_time = query
            .end_time
            .as_ref()
            .map(DateTime::<Utc>::from)
            .unwrap_or_else(Utc::now);

        let metrics_to_fetch = if query.metrics.is_empty() {
            vec![
                "rps".to_string(),
                "bytes_in".to_string(),
                "connections".to_string(),
            ]
        } else {
            query.metrics.clone()
        };

        let mut result = Vec::new();

        for metric_name in metrics_to_fetch {
            let points = self
                .query_metric_time_series(
                    "traffic",
                    backend_id,
                    &metric_name,
                    start_time,
                    end_time,
                    granularity,
                )
                .await?;

            result.push(TimeSeries {
                metric_name,
                points,
            });
        }

        Ok(result)
    }

    /// Query time-series data for attack metrics
    pub async fn query_attack_time_series(
        &self,
        query: &TimeSeriesQuery,
    ) -> Result<Vec<TimeSeries>, StorageError> {
        let backend_id = &query.backend_id;
        let granularity =
            TimeGranularity::try_from(query.granularity).unwrap_or(TimeGranularity::Minute);

        let start_time = query
            .start_time
            .as_ref()
            .map(DateTime::<Utc>::from)
            .unwrap_or_else(|| Utc::now() - ChronoDuration::hours(1));

        let end_time = query
            .end_time
            .as_ref()
            .map(DateTime::<Utc>::from)
            .unwrap_or_else(Utc::now);

        let metrics_to_fetch = if query.metrics.is_empty() {
            vec!["pps".to_string(), "bps".to_string(), "dropped".to_string()]
        } else {
            query.metrics.clone()
        };

        let mut result = Vec::new();

        for metric_name in metrics_to_fetch {
            let points = self
                .query_metric_time_series(
                    "attack",
                    backend_id,
                    &metric_name,
                    start_time,
                    end_time,
                    granularity,
                )
                .await?;

            result.push(TimeSeries {
                metric_name,
                points,
            });
        }

        Ok(result)
    }

    /// Query a specific metric time-series
    async fn query_metric_time_series(
        &self,
        category: &str,
        backend_id: &str,
        metric_name: &str,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        granularity: TimeGranularity,
    ) -> Result<Vec<DataPoint>, StorageError> {
        // Try Redis first for recent data
        if let Some(ref pool) = self.redis_pool {
            let mut conn = pool
                .get()
                .await
                .map_err(|e| StorageError::RedisPool(e.to_string()))?;

            let key = self.redis_key(&[category, backend_id, metric_name]);
            let start_score = start_time.timestamp();
            let end_score = end_time.timestamp();

            let raw_points: Vec<(String, f64)> = conn
                .zrangebyscore_withscores(&key, start_score, end_score)
                .await?;

            if !raw_points.is_empty() {
                let points = self.aggregate_points(raw_points, granularity);
                return Ok(points);
            }
        }

        // Fall back to PostgreSQL for historical data
        if let Some(ref pool) = self.db_pool {
            let table = match category {
                "traffic" => "traffic_metrics_ts",
                "attack" => "attack_metrics_ts",
                "worker" => "worker_metrics_ts",
                _ => {
                    return Err(StorageError::Internal(format!(
                        "Unknown category: {}",
                        category
                    )));
                }
            };

            let column = self.metric_name_to_column(metric_name);
            let bucket_seconds = self.granularity_to_seconds(granularity);

            let query = format!(
                r#"
                SELECT
                    (EXTRACT(EPOCH FROM timestamp)::bigint / {bucket}) * {bucket} as bucket_ts,
                    AVG({column}) as value
                FROM {table}
                WHERE backend_id = $1 AND timestamp >= $2 AND timestamp <= $3
                GROUP BY bucket_ts
                ORDER BY bucket_ts
                "#,
                bucket = bucket_seconds,
                column = column,
                table = table,
            );

            let rows = sqlx::query(&query)
                .bind(backend_id)
                .bind(start_time)
                .bind(end_time)
                .fetch_all(pool)
                .await?;

            let points = rows
                .iter()
                .map(|row| {
                    let bucket_ts: i64 = row.get("bucket_ts");
                    let value: f64 = row.get("value");
                    DataPoint {
                        timestamp: Some(Timestamp {
                            seconds: bucket_ts,
                            nanos: 0,
                        }),
                        value,
                    }
                })
                .collect();

            return Ok(points);
        }

        Ok(Vec::new())
    }

    /// Aggregate raw points to the specified granularity
    fn aggregate_points(
        &self,
        raw_points: Vec<(String, f64)>,
        granularity: TimeGranularity,
    ) -> Vec<DataPoint> {
        let bucket_seconds = self.granularity_to_seconds(granularity);
        let mut buckets: HashMap<i64, Vec<f64>> = HashMap::new();

        for (ts_str, value) in raw_points {
            if let Ok(ts) = ts_str.parse::<i64>() {
                let bucket = (ts / bucket_seconds) * bucket_seconds;
                buckets.entry(bucket).or_default().push(value);
            }
        }

        let mut points: Vec<DataPoint> = buckets
            .into_iter()
            .map(|(bucket, values)| {
                let avg = values.iter().sum::<f64>() / values.len() as f64;
                DataPoint {
                    timestamp: Some(Timestamp {
                        seconds: bucket,
                        nanos: 0,
                    }),
                    value: avg,
                }
            })
            .collect();

        points.sort_by_key(|p| p.timestamp.as_ref().map(|t| t.seconds).unwrap_or(0));
        points
    }

    /// Convert granularity enum to seconds
    fn granularity_to_seconds(&self, granularity: TimeGranularity) -> i64 {
        match granularity {
            TimeGranularity::Unspecified | TimeGranularity::Minute => 60,
            TimeGranularity::FiveMinutes => 300,
            TimeGranularity::FifteenMinutes => 900,
            TimeGranularity::Hour => 3600,
            TimeGranularity::Day => 86400,
        }
    }

    /// Convert metric name to database column
    fn metric_name_to_column(&self, metric_name: &str) -> &'static str {
        match metric_name {
            "rps" | "requests_per_second" => "requests_per_second",
            "bytes_in" => "bytes_in",
            "bytes_out" => "bytes_out",
            "connections" | "active_connections" => "active_connections",
            "pps" | "packets_per_second" => "packets_per_second",
            "attack_pps" => "attack_pps",
            "attack_bps" => "attack_bps",
            "dropped" | "requests_dropped" => "requests_dropped",
            "unique_ips" | "unique_attack_ips" => "unique_attack_ips",
            "cpu" | "cpu_percent" => "cpu_percent",
            "memory" | "memory_percent" => "memory_percent",
            _ => "requests_per_second",
        }
    }

    /// Start recording an attack event
    pub async fn start_attack_event(
        &self,
        backend_id: &str,
        attack_type: &str,
        severity: i32,
    ) -> Result<String, StorageError> {
        let event_id = Uuid::new_v4().to_string();

        if let Some(ref pool) = self.db_pool {
            sqlx::query(
                r#"
                INSERT INTO attack_events (
                    id, backend_id, started_at, attack_type, severity
                ) VALUES ($1, $2, NOW(), $3, $4)
                "#,
            )
            .bind(&event_id)
            .bind(backend_id)
            .bind(attack_type)
            .bind(severity)
            .execute(pool)
            .await?;

            info!(event_id = %event_id, backend_id = %backend_id, "Attack event started");
        }

        // Also store in Redis for quick lookup
        if let Some(ref pool) = self.redis_pool {
            let mut conn = pool
                .get()
                .await
                .map_err(|e| StorageError::RedisPool(e.to_string()))?;

            let key = self.redis_key(&["active_attack", backend_id]);
            let _: () = conn.set_ex(&key, &event_id, 86400).await?;
        }

        Ok(event_id)
    }

    /// End an attack event
    pub async fn end_attack_event(
        &self,
        backend_id: &str,
        duration_seconds: u32,
    ) -> Result<(), StorageError> {
        // Get the active attack event ID
        let event_id = if let Some(ref pool) = self.redis_pool {
            let mut conn = pool
                .get()
                .await
                .map_err(|e| StorageError::RedisPool(e.to_string()))?;

            let key = self.redis_key(&["active_attack", backend_id]);
            let id: Option<String> = conn.get(&key).await?;
            let _: () = conn.del(&key).await?;
            id
        } else {
            None
        };

        if let (Some(pool), Some(event_id)) = (&self.db_pool, &event_id) {
            sqlx::query(
                r#"
                UPDATE attack_events
                SET ended_at = NOW(),
                    duration_seconds = $1
                WHERE id = $2
                "#,
            )
            .bind(duration_seconds as i32)
            .bind(event_id)
            .execute(pool)
            .await?;

            info!(event_id = %event_id, duration = %duration_seconds, "Attack event ended");
        }

        Ok(())
    }

    /// Get an attack event by ID
    pub async fn get_attack_event(&self, event_id: &str) -> Result<AttackEvent, StorageError> {
        let pool = self
            .db_pool
            .as_ref()
            .ok_or_else(|| StorageError::Internal("Database not configured".to_string()))?;

        let row = sqlx::query(
            r#"
            SELECT id, backend_id, started_at, ended_at, duration_seconds,
                   attack_type, severity, peak_pps, peak_bps, total_packets,
                   total_bytes, packets_mitigated, mitigation_rate, unique_sources,
                   top_countries, top_asns
            FROM attack_events
            WHERE id = $1
            "#,
        )
        .bind(event_id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| StorageError::NotFound(format!("Attack event not found: {}", event_id)))?;

        Ok(self.row_to_attack_event(&row))
    }

    /// List attack events for a backend
    pub async fn list_attack_events(
        &self,
        backend_id: &str,
        start_time: Option<Timestamp>,
        end_time: Option<Timestamp>,
        pagination: Option<Pagination>,
    ) -> Result<(Vec<AttackEvent>, PaginationInfo), StorageError> {
        let pool = self
            .db_pool
            .as_ref()
            .ok_or_else(|| StorageError::Internal("Database not configured".to_string()))?;

        let page = pagination.as_ref().map(|p| p.page).unwrap_or(1).max(1);
        let page_size = pagination
            .as_ref()
            .map(|p| p.page_size)
            .unwrap_or(20)
            .clamp(1, 100);
        let offset = (page - 1) * page_size;

        let start = start_time
            .as_ref()
            .map(DateTime::<Utc>::from)
            .unwrap_or_else(|| Utc::now() - ChronoDuration::days(30));

        let end = end_time
            .as_ref()
            .map(DateTime::<Utc>::from)
            .unwrap_or_else(Utc::now);

        // Get total count
        let count_row = sqlx::query(
            r#"
            SELECT COUNT(*) as count
            FROM attack_events
            WHERE backend_id = $1 AND started_at >= $2 AND started_at <= $3
            "#,
        )
        .bind(backend_id)
        .bind(start)
        .bind(end)
        .fetch_one(pool)
        .await?;

        let total_count: i64 = count_row.get("count");

        // Get events
        let rows = sqlx::query(
            r#"
            SELECT id, backend_id, started_at, ended_at, duration_seconds,
                   attack_type, severity, peak_pps, peak_bps, total_packets,
                   total_bytes, packets_mitigated, mitigation_rate, unique_sources,
                   top_countries, top_asns
            FROM attack_events
            WHERE backend_id = $1 AND started_at >= $2 AND started_at <= $3
            ORDER BY started_at DESC
            LIMIT $4 OFFSET $5
            "#,
        )
        .bind(backend_id)
        .bind(start)
        .bind(end)
        .bind(page_size as i32)
        .bind(offset as i32)
        .fetch_all(pool)
        .await?;

        let events: Vec<AttackEvent> = rows
            .iter()
            .map(|row| self.row_to_attack_event(row))
            .collect();

        let has_next = (offset + page_size) < total_count as u32;

        Ok((
            events,
            PaginationInfo {
                total_count: total_count as u32,
                page,
                page_size,
                has_next,
                next_cursor: String::new(),
            },
        ))
    }

    /// Convert database row to AttackEvent
    fn row_to_attack_event(&self, row: &sqlx::postgres::PgRow) -> AttackEvent {
        let started_at: DateTime<Utc> = row.get("started_at");
        let ended_at: Option<DateTime<Utc>> = row.get("ended_at");
        let top_countries: Vec<String> = row.try_get("top_countries").unwrap_or_default();
        let top_asns: Vec<String> = row.try_get("top_asns").unwrap_or_default();

        AttackEvent {
            id: row.get("id"),
            backend_id: row.get("backend_id"),
            started_at: Some(Timestamp::from(started_at)),
            ended_at: ended_at.map(Timestamp::from),
            duration_seconds: row.try_get::<i32, _>("duration_seconds").unwrap_or(0) as u32,
            attack_type: row.get("attack_type"),
            severity: row.get("severity"),
            peak_pps: row.try_get::<i64, _>("peak_pps").unwrap_or(0) as u64,
            peak_bps: row.try_get::<i64, _>("peak_bps").unwrap_or(0) as u64,
            total_packets: row.try_get::<i64, _>("total_packets").unwrap_or(0) as u64,
            total_bytes: row.try_get::<i64, _>("total_bytes").unwrap_or(0) as u64,
            packets_mitigated: row.try_get::<i64, _>("packets_mitigated").unwrap_or(0) as u64,
            mitigation_rate: row.try_get::<f32, _>("mitigation_rate").unwrap_or(0.0),
            unique_sources: row.try_get::<i32, _>("unique_sources").unwrap_or(0) as u32,
            top_countries,
            top_asns,
        }
    }

    /// Get geo metrics from storage
    pub async fn get_geo_metrics(
        &self,
        backend_id: &str,
        start_time: Option<Timestamp>,
        end_time: Option<Timestamp>,
    ) -> Result<GeoMetrics, StorageError> {
        let pool = self
            .db_pool
            .as_ref()
            .ok_or_else(|| StorageError::Internal("Database not configured".to_string()))?;

        let start = start_time
            .as_ref()
            .map(DateTime::<Utc>::from)
            .unwrap_or_else(|| Utc::now() - ChronoDuration::hours(24));

        let end = end_time
            .as_ref()
            .map(DateTime::<Utc>::from)
            .unwrap_or_else(Utc::now);

        let rows = sqlx::query(
            r#"
            SELECT country_code,
                   SUM(requests) as requests,
                   SUM(bytes) as bytes,
                   MAX(unique_ips) as unique_ips,
                   BOOL_OR(blocked) as blocked
            FROM geo_traffic
            WHERE backend_id = $1 AND timestamp >= $2 AND timestamp <= $3
            GROUP BY country_code
            ORDER BY requests DESC
            "#,
        )
        .bind(backend_id)
        .bind(start)
        .bind(end)
        .fetch_all(pool)
        .await?;

        let countries: Vec<CountryMetrics> = rows
            .iter()
            .map(|row| {
                let country_code: String = row.get("country_code");
                CountryMetrics {
                    country_code: country_code.clone(),
                    country_name: country_code_to_name(&country_code).to_string(),
                    requests: row.get::<i64, _>("requests") as u64,
                    bytes: row.get::<i64, _>("bytes") as u64,
                    unique_ips: row.get::<i64, _>("unique_ips") as u64,
                    blocked: row.get("blocked"),
                }
            })
            .collect();

        Ok(GeoMetrics {
            backend_id: backend_id.to_string(),
            timestamp: Some(Timestamp::from(Utc::now())),
            countries,
        })
    }

    /// Clean up old data based on retention policy
    pub async fn cleanup_old_data(&self) -> Result<(), StorageError> {
        info!("Running data cleanup based on retention policy");

        // Clean up Redis
        if let Some(ref pool) = self.redis_pool {
            let mut conn = pool
                .get()
                .await
                .map_err(|e| StorageError::RedisPool(e.to_string()))?;

            let now = Utc::now().timestamp();
            let cutoff = now - self.retention.raw_retention.as_secs() as i64;

            // Clean up traffic metrics
            let pattern = self.redis_key(&["traffic", "*", "*"]);
            let keys: Vec<String> = deadpool_redis::redis::cmd("KEYS")
                .arg(&pattern)
                .query_async(&mut *conn)
                .await?;

            for key in keys {
                let _: () = deadpool_redis::redis::cmd("ZREMRANGEBYSCORE")
                    .arg(&key)
                    .arg("-inf")
                    .arg(cutoff)
                    .query_async(&mut *conn)
                    .await?;
            }

            // Clean up attack metrics
            let pattern = self.redis_key(&["attack", "*", "*"]);
            let keys: Vec<String> = deadpool_redis::redis::cmd("KEYS")
                .arg(&pattern)
                .query_async(&mut *conn)
                .await?;

            for key in keys {
                let _: () = deadpool_redis::redis::cmd("ZREMRANGEBYSCORE")
                    .arg(&key)
                    .arg("-inf")
                    .arg(cutoff)
                    .query_async(&mut *conn)
                    .await?;
            }
        }

        // Clean up PostgreSQL
        if let Some(ref pool) = self.db_pool {
            let raw_cutoff =
                Utc::now() - ChronoDuration::from_std(self.retention.raw_retention).unwrap();

            // Clean traffic metrics
            let result = sqlx::query("DELETE FROM traffic_metrics_ts WHERE timestamp < $1")
                .bind(raw_cutoff)
                .execute(pool)
                .await?;
            debug!(
                "Cleaned {} rows from traffic_metrics_ts",
                result.rows_affected()
            );

            // Clean attack metrics
            let result = sqlx::query("DELETE FROM attack_metrics_ts WHERE timestamp < $1")
                .bind(raw_cutoff)
                .execute(pool)
                .await?;
            debug!(
                "Cleaned {} rows from attack_metrics_ts",
                result.rows_affected()
            );

            // Clean worker metrics
            let result = sqlx::query("DELETE FROM worker_metrics_ts WHERE timestamp < $1")
                .bind(raw_cutoff)
                .execute(pool)
                .await?;
            debug!(
                "Cleaned {} rows from worker_metrics_ts",
                result.rows_affected()
            );

            // Clean geo traffic (keep longer)
            let geo_cutoff =
                Utc::now() - ChronoDuration::from_std(self.retention.daily_retention).unwrap();
            let result = sqlx::query("DELETE FROM geo_traffic WHERE timestamp < $1")
                .bind(geo_cutoff)
                .execute(pool)
                .await?;
            debug!("Cleaned {} rows from geo_traffic", result.rows_affected());
        }

        info!("Data cleanup completed");
        Ok(())
    }
}

/// Convert country code to name
fn country_code_to_name(code: &str) -> &'static str {
    match code.to_uppercase().as_str() {
        "US" => "United States",
        "CA" => "Canada",
        "GB" => "United Kingdom",
        "DE" => "Germany",
        "FR" => "France",
        "NL" => "Netherlands",
        "AU" => "Australia",
        "JP" => "Japan",
        "KR" => "South Korea",
        "SG" => "Singapore",
        "BR" => "Brazil",
        "IN" => "India",
        "RU" => "Russia",
        "CN" => "China",
        "HK" => "Hong Kong",
        "TW" => "Taiwan",
        "VN" => "Vietnam",
        "ID" => "Indonesia",
        "TH" => "Thailand",
        "PH" => "Philippines",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket_timestamp() {
        let ts = DateTime::from_timestamp(1234567890, 0).unwrap();

        let bucket = TimeSeriesStorage::bucket_timestamp(ts, TimeGranularity::Minute);
        assert_eq!(bucket % 60, 0);

        let bucket = TimeSeriesStorage::bucket_timestamp(ts, TimeGranularity::Hour);
        assert_eq!(bucket % 3600, 0);
    }

    #[test]
    fn test_country_code_to_name() {
        assert_eq!(country_code_to_name("US"), "United States");
        assert_eq!(country_code_to_name("us"), "United States");
        assert_eq!(country_code_to_name("ZZ"), "Unknown");
    }
}
