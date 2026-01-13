//! Metrics aggregation from worker nodes
//!
//! This module handles collecting, aggregating, and caching metrics from
//! multiple worker nodes to provide real-time and historical metrics.

use crate::storage::TimeSeriesStorage;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use pistonprotection_common::{geoip::GeoIpService, redis::CacheService};
use pistonprotection_proto::{
    common::{HealthStatus, Pagination, PaginationInfo, Timestamp},
    metrics::*,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

/// Aggregation errors
#[derive(Debug, Error)]
pub enum AggregatorError {
    #[error("Backend not found: {0}")]
    BackendNotFound(String),

    #[error("Worker not found: {0}")]
    WorkerNotFound(String),

    #[error("Origin not found: {0}")]
    OriginNotFound(String),

    #[error("Cache error: {0}")]
    Cache(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Cached metrics entry with timestamp
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedMetrics<T> {
    metrics: T,
    timestamp: DateTime<Utc>,
}

impl<T> CachedMetrics<T> {
    fn new(metrics: T) -> Self {
        Self {
            metrics,
            timestamp: Utc::now(),
        }
    }

    fn is_stale(&self, max_age: Duration) -> bool {
        let age = Utc::now().signed_duration_since(self.timestamp);
        age.to_std().unwrap_or(Duration::MAX) > max_age
    }
}

/// Raw metrics data received from workers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawWorkerMetrics {
    pub worker_id: String,
    pub node_name: String,
    pub timestamp: DateTime<Utc>,
    pub cpu_percent: f32,
    pub memory_percent: f32,
    pub memory_bytes: u64,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    pub network_rx_pps: u64,
    pub network_tx_pps: u64,
    pub xdp_packets_processed: u64,
    pub xdp_packets_passed: u64,
    pub xdp_packets_dropped: u64,
    pub xdp_packets_redirected: u64,
    pub xdp_packets_error: u64,
    pub xdp_latency_avg_ns: u64,
    pub xdp_latency_p99_ns: u64,
    pub drops_by_filter: HashMap<String, u64>,
    pub health: i32,
}

/// Raw traffic metrics from workers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawTrafficMetrics {
    pub backend_id: String,
    pub worker_id: String,
    pub timestamp: DateTime<Utc>,
    pub requests_total: u64,
    pub requests_per_second: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub bytes_per_second_in: u64,
    pub bytes_per_second_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub packets_per_second: u64,
    pub active_connections: u64,
    pub new_connections: u64,
    pub closed_connections: u64,
    pub requests_by_protocol: HashMap<String, u64>,
}

/// Raw attack metrics from workers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawAttackMetrics {
    pub backend_id: String,
    pub worker_id: String,
    pub timestamp: DateTime<Utc>,
    pub under_attack: bool,
    pub attack_type: String,
    pub severity: i32,
    pub attack_requests: u64,
    pub attack_bytes: u64,
    pub attack_pps: u64,
    pub attack_bps: u64,
    pub requests_dropped: u64,
    pub requests_challenged: u64,
    pub requests_rate_limited: u64,
    pub unique_attack_ips: u32,
    pub top_sources: Vec<RawAttackSource>,
}

/// Raw attack source info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawAttackSource {
    pub ip: String,
    pub country: String,
    pub asn: String,
    pub requests: u64,
    pub bytes: u64,
    pub action_taken: i32,
}

/// Geo traffic data for aggregation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoTrafficData {
    pub requests: u64,
    pub bytes: u64,
    pub unique_ips: u64,
    pub blocked: bool,
}

/// Metrics aggregator service
pub struct MetricsAggregator {
    /// In-memory cache for worker metrics
    worker_metrics: DashMap<String, CachedMetrics<WorkerMetrics>>,

    /// In-memory cache for traffic metrics by backend
    traffic_metrics: DashMap<String, CachedMetrics<TrafficMetrics>>,

    /// In-memory cache for attack metrics by backend
    attack_metrics: DashMap<String, CachedMetrics<AttackMetrics>>,

    /// In-memory cache for origin metrics (backend_id:origin_id -> metrics)
    origin_metrics: DashMap<String, CachedMetrics<OriginMetrics>>,

    /// In-memory cache for geo metrics by backend
    geo_metrics: DashMap<String, CachedMetrics<GeoMetrics>>,

    /// Per-country traffic aggregation (backend_id:country -> data)
    geo_traffic: DashMap<String, GeoTrafficData>,

    /// Redis cache for distributed caching
    cache: Option<CacheService>,

    /// Time-series storage
    storage: Arc<TimeSeriesStorage>,

    /// GeoIP service for IP lookups
    geoip: Arc<GeoIpService>,

    /// Broadcast channel for metrics updates
    traffic_updates: broadcast::Sender<TrafficMetrics>,
    attack_updates: broadcast::Sender<AttackMetrics>,

    /// Attack detection state
    attack_state: DashMap<String, AttackDetectionState>,

    /// Configuration
    config: AggregatorConfig,
}

/// Attack detection state per backend
#[derive(Debug, Clone)]
struct AttackDetectionState {
    /// Whether currently under attack
    under_attack: bool,
    /// Attack start time
    attack_start: Option<DateTime<Utc>>,
    /// Baseline request rate (rolling average)
    baseline_rps: f64,
    /// Baseline packet rate
    baseline_pps: f64,
    /// Current severity
    severity: AttackSeverity,
    /// Recent samples for baseline calculation
    rps_samples: Vec<u64>,
    pps_samples: Vec<u64>,
}

impl Default for AttackDetectionState {
    fn default() -> Self {
        Self {
            under_attack: false,
            attack_start: None,
            baseline_rps: 0.0,
            baseline_pps: 0.0,
            severity: AttackSeverity::Unspecified,
            rps_samples: Vec::with_capacity(60),
            pps_samples: Vec::with_capacity(60),
        }
    }
}

/// Aggregator configuration
#[derive(Debug, Clone)]
pub struct AggregatorConfig {
    /// Cache TTL for metrics
    pub cache_ttl: Duration,
    /// Stale threshold for in-memory cache
    pub stale_threshold: Duration,
    /// Attack detection threshold multiplier
    pub attack_threshold_multiplier: f64,
    /// Minimum baseline samples before detection
    pub min_baseline_samples: usize,
    /// Number of samples for rolling baseline
    pub baseline_window_size: usize,
}

impl Default for AggregatorConfig {
    fn default() -> Self {
        Self {
            cache_ttl: Duration::from_secs(5),
            stale_threshold: Duration::from_secs(10),
            attack_threshold_multiplier: 3.0,
            min_baseline_samples: 30,
            baseline_window_size: 60,
        }
    }
}

impl MetricsAggregator {
    /// Create a new metrics aggregator
    pub fn new(
        storage: Arc<TimeSeriesStorage>,
        cache: Option<CacheService>,
        geoip: Arc<GeoIpService>,
        config: AggregatorConfig,
    ) -> Self {
        let (traffic_updates, _) = broadcast::channel(1000);
        let (attack_updates, _) = broadcast::channel(1000);

        Self {
            worker_metrics: DashMap::new(),
            traffic_metrics: DashMap::new(),
            attack_metrics: DashMap::new(),
            origin_metrics: DashMap::new(),
            geo_metrics: DashMap::new(),
            geo_traffic: DashMap::new(),
            cache,
            storage,
            geoip,
            traffic_updates,
            attack_updates,
            attack_state: DashMap::new(),
            config,
        }
    }

    /// Subscribe to traffic metrics updates
    pub fn subscribe_traffic(&self) -> broadcast::Receiver<TrafficMetrics> {
        self.traffic_updates.subscribe()
    }

    /// Subscribe to attack metrics updates
    pub fn subscribe_attack(&self) -> broadcast::Receiver<AttackMetrics> {
        self.attack_updates.subscribe()
    }

    /// Ingest worker metrics
    pub async fn ingest_worker_metrics(
        &self,
        raw: RawWorkerMetrics,
    ) -> Result<(), AggregatorError> {
        let metrics = WorkerMetrics {
            worker_id: raw.worker_id.clone(),
            node_name: raw.node_name.clone(),
            timestamp: Some(Timestamp::from(raw.timestamp)),
            cpu_percent: raw.cpu_percent,
            memory_percent: raw.memory_percent,
            memory_bytes: raw.memory_bytes,
            network_rx_bytes: raw.network_rx_bytes,
            network_tx_bytes: raw.network_tx_bytes,
            network_rx_pps: raw.network_rx_pps,
            network_tx_pps: raw.network_tx_pps,
            xdp_stats: Some(XdpStats {
                packets_processed: raw.xdp_packets_processed,
                packets_passed: raw.xdp_packets_passed,
                packets_dropped: raw.xdp_packets_dropped,
                packets_redirected: raw.xdp_packets_redirected,
                packets_error: raw.xdp_packets_error,
                latency_avg_ns: raw.xdp_latency_avg_ns,
                latency_p99_ns: raw.xdp_latency_p99_ns,
                drops_by_filter: raw.drops_by_filter.clone(),
            }),
            health: raw.health,
        };

        // Store in memory cache
        self.worker_metrics
            .insert(raw.worker_id.clone(), CachedMetrics::new(metrics.clone()));

        // Store in Redis if available
        if let Some(ref cache) = self.cache {
            let key = format!("worker_metrics:{}", raw.worker_id);
            if let Err(e) = cache.set(&key, &metrics, self.config.cache_ttl).await {
                warn!("Failed to cache worker metrics: {}", e);
            }
        }

        // Store time-series data
        if let Err(e) = self.storage.store_worker_metrics(&raw).await {
            warn!("Failed to store worker metrics time-series: {}", e);
        }

        debug!(worker_id = %raw.worker_id, "Ingested worker metrics");
        Ok(())
    }

    /// Ingest traffic metrics from a worker
    pub async fn ingest_traffic_metrics(
        &self,
        raw: RawTrafficMetrics,
    ) -> Result<(), AggregatorError> {
        // Aggregate into backend-level metrics
        let mut entry = self
            .traffic_metrics
            .entry(raw.backend_id.clone())
            .or_insert_with(|| {
                CachedMetrics::new(TrafficMetrics {
                    backend_id: raw.backend_id.clone(),
                    timestamp: Some(Timestamp::from(raw.timestamp)),
                    ..Default::default()
                })
            });

        // Aggregate metrics from this worker
        entry.metrics.requests_total = entry
            .metrics
            .requests_total
            .saturating_add(raw.requests_total);
        entry.metrics.requests_per_second = entry
            .metrics
            .requests_per_second
            .saturating_add(raw.requests_per_second);
        entry.metrics.bytes_in = entry.metrics.bytes_in.saturating_add(raw.bytes_in);
        entry.metrics.bytes_out = entry.metrics.bytes_out.saturating_add(raw.bytes_out);
        entry.metrics.bytes_per_second_in = entry
            .metrics
            .bytes_per_second_in
            .saturating_add(raw.bytes_per_second_in);
        entry.metrics.bytes_per_second_out = entry
            .metrics
            .bytes_per_second_out
            .saturating_add(raw.bytes_per_second_out);
        entry.metrics.packets_in = entry.metrics.packets_in.saturating_add(raw.packets_in);
        entry.metrics.packets_out = entry.metrics.packets_out.saturating_add(raw.packets_out);
        entry.metrics.packets_per_second = entry
            .metrics
            .packets_per_second
            .saturating_add(raw.packets_per_second);
        entry.metrics.active_connections = entry
            .metrics
            .active_connections
            .saturating_add(raw.active_connections);
        entry.metrics.new_connections = entry
            .metrics
            .new_connections
            .saturating_add(raw.new_connections);
        entry.metrics.closed_connections = entry
            .metrics
            .closed_connections
            .saturating_add(raw.closed_connections);
        entry.metrics.timestamp = Some(Timestamp::from(raw.timestamp));

        // Merge protocol breakdown
        for (protocol, count) in &raw.requests_by_protocol {
            *entry
                .metrics
                .requests_by_protocol
                .entry(protocol.clone())
                .or_insert(0) += count;
        }

        entry.timestamp = Utc::now();

        let updated_metrics = entry.metrics.clone();
        drop(entry);

        // Broadcast update
        let _ = self.traffic_updates.send(updated_metrics.clone());

        // Store in Redis
        if let Some(ref cache) = self.cache {
            let key = format!("traffic_metrics:{}", raw.backend_id);
            if let Err(e) = cache
                .set(&key, &updated_metrics, self.config.cache_ttl)
                .await
            {
                warn!("Failed to cache traffic metrics: {}", e);
            }
        }

        // Store time-series
        if let Err(e) = self.storage.store_traffic_metrics(&raw).await {
            warn!("Failed to store traffic metrics time-series: {}", e);
        }

        // Update attack detection baseline
        self.update_attack_baseline(
            &raw.backend_id,
            raw.requests_per_second,
            raw.packets_per_second,
        );

        debug!(backend_id = %raw.backend_id, worker_id = %raw.worker_id, "Ingested traffic metrics");
        Ok(())
    }

    /// Ingest attack metrics from a worker
    pub async fn ingest_attack_metrics(
        &self,
        raw: RawAttackMetrics,
    ) -> Result<(), AggregatorError> {
        let top_sources: Vec<AttackSource> = raw
            .top_sources
            .iter()
            .map(|s| {
                let ip_addr: Option<std::net::IpAddr> = s.ip.parse().ok();
                AttackSource {
                    ip: ip_addr.map(|a| a.into()),
                    country: s.country.clone(),
                    asn: s.asn.clone(),
                    requests: s.requests,
                    bytes: s.bytes,
                    action_taken: s.action_taken,
                }
            })
            .collect();

        let metrics = AttackMetrics {
            backend_id: raw.backend_id.clone(),
            timestamp: Some(Timestamp::from(raw.timestamp)),
            under_attack: raw.under_attack,
            attack_type: raw.attack_type.clone(),
            severity: raw.severity,
            attack_requests: raw.attack_requests,
            attack_bytes: raw.attack_bytes,
            attack_pps: raw.attack_pps,
            attack_bps: raw.attack_bps,
            requests_dropped: raw.requests_dropped,
            requests_challenged: raw.requests_challenged,
            requests_rate_limited: raw.requests_rate_limited,
            unique_attack_ips: raw.unique_attack_ips,
            top_sources,
        };

        // Store in cache
        self.attack_metrics
            .insert(raw.backend_id.clone(), CachedMetrics::new(metrics.clone()));

        // Broadcast update
        let _ = self.attack_updates.send(metrics.clone());

        // Check for attack state changes
        self.detect_attack(&raw.backend_id, &metrics).await;

        // Store in Redis
        if let Some(ref cache) = self.cache {
            let key = format!("attack_metrics:{}", raw.backend_id);
            if let Err(e) = cache.set(&key, &metrics, self.config.cache_ttl).await {
                warn!("Failed to cache attack metrics: {}", e);
            }
        }

        // Store time-series
        if let Err(e) = self.storage.store_attack_metrics(&raw).await {
            warn!("Failed to store attack metrics time-series: {}", e);
        }

        debug!(backend_id = %raw.backend_id, under_attack = %raw.under_attack, "Ingested attack metrics");
        Ok(())
    }

    /// Ingest geo traffic data
    pub async fn ingest_geo_traffic(
        &self,
        backend_id: &str,
        ip: std::net::IpAddr,
        bytes: u64,
        blocked: bool,
    ) -> Result<(), AggregatorError> {
        // Look up country from IP
        let geo_info = self.geoip.lookup(ip);
        let country_code = geo_info.country_code.unwrap_or_else(|| "XX".to_string());

        let key = format!("{}:{}", backend_id, country_code);
        let mut entry = self.geo_traffic.entry(key).or_default();
        entry.requests += 1;
        entry.bytes += bytes;
        if blocked {
            entry.blocked = true;
        }

        Ok(())
    }

    /// Update attack detection baseline
    fn update_attack_baseline(&self, backend_id: &str, rps: u64, pps: u64) {
        let mut state = self.attack_state.entry(backend_id.to_string()).or_default();

        // Only update baseline when not under attack
        if !state.under_attack {
            state.rps_samples.push(rps);
            state.pps_samples.push(pps);

            // Keep window size bounded
            if state.rps_samples.len() > self.config.baseline_window_size {
                state.rps_samples.remove(0);
            }
            if state.pps_samples.len() > self.config.baseline_window_size {
                state.pps_samples.remove(0);
            }

            // Calculate rolling average
            if !state.rps_samples.is_empty() {
                state.baseline_rps =
                    state.rps_samples.iter().sum::<u64>() as f64 / state.rps_samples.len() as f64;
            }
            if !state.pps_samples.is_empty() {
                state.baseline_pps =
                    state.pps_samples.iter().sum::<u64>() as f64 / state.pps_samples.len() as f64;
            }
        }
    }

    /// Detect attack based on metrics
    async fn detect_attack(&self, backend_id: &str, metrics: &AttackMetrics) {
        let mut state = self.attack_state.entry(backend_id.to_string()).or_default();

        let previous_under_attack = state.under_attack;

        // Update attack state based on worker reports
        if metrics.under_attack {
            if !state.under_attack {
                // Attack started
                state.under_attack = true;
                state.attack_start = Some(Utc::now());
                state.severity =
                    AttackSeverity::try_from(metrics.severity).unwrap_or(AttackSeverity::Medium);

                info!(
                    backend_id = %backend_id,
                    attack_type = %metrics.attack_type,
                    severity = ?state.severity,
                    "Attack detected"
                );

                // Record attack event start
                if let Err(e) = self
                    .storage
                    .start_attack_event(backend_id, &metrics.attack_type, metrics.severity)
                    .await
                {
                    warn!("Failed to record attack event start: {}", e);
                }
            }
        } else if previous_under_attack {
            // Attack ended
            state.under_attack = false;
            let duration = state
                .attack_start
                .map(|start| Utc::now().signed_duration_since(start).num_seconds() as u32)
                .unwrap_or(0);
            state.attack_start = None;

            info!(
                backend_id = %backend_id,
                duration_seconds = %duration,
                "Attack ended"
            );

            // Record attack event end
            if let Err(e) = self.storage.end_attack_event(backend_id, duration).await {
                warn!("Failed to record attack event end: {}", e);
            }
        }
    }

    /// Get traffic metrics for a backend
    pub async fn get_traffic_metrics(
        &self,
        backend_id: &str,
    ) -> Result<TrafficMetrics, AggregatorError> {
        // Check in-memory cache first
        if let Some(entry) = self.traffic_metrics.get(backend_id) {
            if !entry.is_stale(self.config.stale_threshold) {
                return Ok(entry.metrics.clone());
            }
        }

        // Check Redis cache
        if let Some(ref cache) = self.cache {
            let key = format!("traffic_metrics:{}", backend_id);
            if let Ok(Some(metrics)) = cache.get::<TrafficMetrics>(&key).await {
                // Update in-memory cache
                self.traffic_metrics
                    .insert(backend_id.to_string(), CachedMetrics::new(metrics.clone()));
                return Ok(metrics);
            }
        }

        // Return empty metrics if not found (new backend)
        Ok(TrafficMetrics {
            backend_id: backend_id.to_string(),
            timestamp: Some(Timestamp::from(Utc::now())),
            ..Default::default()
        })
    }

    /// Get attack metrics for a backend
    pub async fn get_attack_metrics(
        &self,
        backend_id: &str,
    ) -> Result<AttackMetrics, AggregatorError> {
        // Check in-memory cache
        if let Some(entry) = self.attack_metrics.get(backend_id) {
            if !entry.is_stale(self.config.stale_threshold) {
                return Ok(entry.metrics.clone());
            }
        }

        // Check Redis cache
        if let Some(ref cache) = self.cache {
            let key = format!("attack_metrics:{}", backend_id);
            if let Ok(Some(metrics)) = cache.get::<AttackMetrics>(&key).await {
                self.attack_metrics
                    .insert(backend_id.to_string(), CachedMetrics::new(metrics.clone()));
                return Ok(metrics);
            }
        }

        // Return default metrics
        Ok(AttackMetrics {
            backend_id: backend_id.to_string(),
            timestamp: Some(Timestamp::from(Utc::now())),
            under_attack: false,
            ..Default::default()
        })
    }

    /// Get origin metrics
    pub async fn get_origin_metrics(
        &self,
        backend_id: &str,
        origin_id: &str,
    ) -> Result<OriginMetrics, AggregatorError> {
        let key = format!("{}:{}", backend_id, origin_id);

        // Check in-memory cache
        if let Some(entry) = self.origin_metrics.get(&key) {
            if !entry.is_stale(self.config.stale_threshold) {
                return Ok(entry.metrics.clone());
            }
        }

        // Check Redis cache
        if let Some(ref cache) = self.cache {
            let cache_key = format!("origin_metrics:{}", key);
            if let Ok(Some(metrics)) = cache.get::<OriginMetrics>(&cache_key).await {
                self.origin_metrics
                    .insert(key, CachedMetrics::new(metrics.clone()));
                return Ok(metrics);
            }
        }

        // Return default metrics
        Ok(OriginMetrics {
            backend_id: backend_id.to_string(),
            origin_id: origin_id.to_string(),
            timestamp: Some(Timestamp::from(Utc::now())),
            health: HealthStatus::Healthy as i32,
            ..Default::default()
        })
    }

    /// Get worker metrics
    pub async fn get_worker_metrics(
        &self,
        worker_id: &str,
    ) -> Result<WorkerMetrics, AggregatorError> {
        // Check in-memory cache
        if let Some(entry) = self.worker_metrics.get(worker_id) {
            if !entry.is_stale(self.config.stale_threshold) {
                return Ok(entry.metrics.clone());
            }
        }

        // Check Redis cache
        if let Some(ref cache) = self.cache {
            let key = format!("worker_metrics:{}", worker_id);
            if let Ok(Some(metrics)) = cache.get::<WorkerMetrics>(&key).await {
                self.worker_metrics
                    .insert(worker_id.to_string(), CachedMetrics::new(metrics.clone()));
                return Ok(metrics);
            }
        }

        Err(AggregatorError::WorkerNotFound(worker_id.to_string()))
    }

    /// List all worker metrics
    pub async fn list_worker_metrics(
        &self,
        pagination: Option<Pagination>,
    ) -> Result<(Vec<WorkerMetrics>, PaginationInfo), AggregatorError> {
        let page = pagination.as_ref().map(|p| p.page).unwrap_or(1).max(1);
        let page_size = pagination
            .as_ref()
            .map(|p| p.page_size)
            .unwrap_or(20)
            .clamp(1, 100);

        let mut workers: Vec<WorkerMetrics> = self
            .worker_metrics
            .iter()
            .map(|entry| entry.metrics.clone())
            .collect();

        // Sort by worker_id for consistent ordering
        workers.sort_by(|a, b| a.worker_id.cmp(&b.worker_id));

        let total_count = workers.len() as u32;
        let offset = ((page - 1) * page_size) as usize;
        let workers: Vec<WorkerMetrics> = workers
            .into_iter()
            .skip(offset)
            .take(page_size as usize)
            .collect();

        let has_next = offset + workers.len() < total_count as usize;

        Ok((
            workers,
            PaginationInfo {
                total_count,
                page,
                page_size,
                has_next,
                next_cursor: String::new(),
            },
        ))
    }

    /// Get geo metrics for a backend
    pub async fn get_geo_metrics(
        &self,
        backend_id: &str,
        start_time: Option<Timestamp>,
        end_time: Option<Timestamp>,
    ) -> Result<GeoMetrics, AggregatorError> {
        // If time range specified, query from storage
        if start_time.is_some() || end_time.is_some() {
            return self
                .storage
                .get_geo_metrics(backend_id, start_time, end_time)
                .await
                .map_err(|e| AggregatorError::Storage(e.to_string()));
        }

        // Otherwise, aggregate from in-memory data
        let prefix = format!("{}:", backend_id);
        let mut countries: Vec<CountryMetrics> = Vec::new();

        for entry in self.geo_traffic.iter() {
            let key = entry.key();
            if key.starts_with(&prefix) {
                let country_code = key.strip_prefix(&prefix).unwrap_or("XX");
                let data = entry.value();

                countries.push(CountryMetrics {
                    country_code: country_code.to_string(),
                    country_name: country_code_to_name(country_code).to_string(),
                    requests: data.requests,
                    bytes: data.bytes,
                    unique_ips: data.unique_ips,
                    blocked: data.blocked,
                });
            }
        }

        // Sort by requests descending
        countries.sort_by(|a, b| b.requests.cmp(&a.requests));

        Ok(GeoMetrics {
            backend_id: backend_id.to_string(),
            timestamp: Some(Timestamp::from(Utc::now())),
            countries,
        })
    }

    /// Flush aggregated metrics to storage
    pub async fn flush_to_storage(&self) -> Result<(), AggregatorError> {
        info!("Flushing metrics to storage");

        // Flush traffic metrics
        for entry in self.traffic_metrics.iter() {
            if let Err(e) = self.storage.store_traffic_snapshot(&entry.metrics).await {
                warn!(backend_id = %entry.key(), "Failed to flush traffic metrics: {}", e);
            }
        }

        // Flush attack metrics
        for entry in self.attack_metrics.iter() {
            if let Err(e) = self.storage.store_attack_snapshot(&entry.metrics).await {
                warn!(backend_id = %entry.key(), "Failed to flush attack metrics: {}", e);
            }
        }

        // Flush geo metrics
        for entry in self.geo_traffic.iter() {
            let key = entry.key();
            let parts: Vec<&str> = key.split(':').collect();
            if parts.len() == 2 {
                if let Err(e) = self
                    .storage
                    .store_geo_traffic(parts[0], parts[1], entry.value())
                    .await
                {
                    warn!(key = %key, "Failed to flush geo traffic: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Reset metrics for periodic aggregation
    pub fn reset_periodic_counters(&self) {
        // Reset per-second counters in traffic metrics
        for mut entry in self.traffic_metrics.iter_mut() {
            entry.metrics.requests_per_second = 0;
            entry.metrics.bytes_per_second_in = 0;
            entry.metrics.bytes_per_second_out = 0;
            entry.metrics.packets_per_second = 0;
            entry.metrics.new_connections = 0;
            entry.metrics.closed_connections = 0;
        }
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
        "XX" => "Unknown",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_metrics_staleness() {
        let cached = CachedMetrics::new(42);
        assert!(!cached.is_stale(Duration::from_secs(10)));

        // This test would need time manipulation for a thorough check
    }

    #[test]
    fn test_country_code_to_name() {
        assert_eq!(country_code_to_name("US"), "United States");
        assert_eq!(country_code_to_name("us"), "United States");
        assert_eq!(country_code_to_name("ZZ"), "Unknown");
    }

    #[test]
    fn test_attack_detection_state_default() {
        let state = AttackDetectionState::default();
        assert!(!state.under_attack);
        assert!(state.attack_start.is_none());
        assert_eq!(state.baseline_rps, 0.0);
    }
}
