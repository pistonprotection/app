//! Metrics aggregation service

use crate::services::AppState;
use pistonprotection_common::error::Result;
use pistonprotection_proto::metrics::*;
use sqlx::Row;
use tracing::instrument;

/// Metrics service implementation
pub struct MetricsService {
    state: AppState,
}

impl MetricsService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    /// Get current traffic metrics for a backend
    #[instrument(skip(self))]
    pub async fn get_traffic_metrics(&self, backend_id: &str) -> Result<TrafficMetrics> {
        // Try to get from Redis (real-time metrics)
        if let Some(cache) = &self.state.cache {
            if let Ok(Some(metrics)) = cache
                .get::<TrafficMetrics>(&format!("metrics:traffic:{}", backend_id))
                .await
            {
                return Ok(metrics);
            }
        }

        // Fallback to default/empty metrics
        Ok(TrafficMetrics {
            backend_id: backend_id.to_string(),
            timestamp: Some(chrono::Utc::now().into()),
            ..Default::default()
        })
    }

    /// Get attack metrics for a backend
    #[instrument(skip(self))]
    pub async fn get_attack_metrics(&self, backend_id: &str) -> Result<AttackMetrics> {
        if let Some(cache) = &self.state.cache {
            if let Ok(Some(metrics)) = cache
                .get::<AttackMetrics>(&format!("metrics:attack:{}", backend_id))
                .await
            {
                return Ok(metrics);
            }
        }

        Ok(AttackMetrics {
            backend_id: backend_id.to_string(),
            timestamp: Some(chrono::Utc::now().into()),
            under_attack: false,
            ..Default::default()
        })
    }

    /// Get geographic traffic distribution
    #[instrument(skip(self))]
    pub async fn get_geo_metrics(
        &self,
        backend_id: &str,
        start_time: chrono::DateTime<chrono::Utc>,
        end_time: chrono::DateTime<chrono::Utc>,
    ) -> Result<GeoMetrics> {
        let db = self.state.db()?;

        let rows = sqlx::query(
            r#"
            SELECT country_code, country_name,
                   SUM(requests) as requests,
                   SUM(bytes) as bytes,
                   COUNT(DISTINCT source_ip) as unique_ips
            FROM traffic_geo
            WHERE backend_id = $1
              AND timestamp >= $2
              AND timestamp < $3
            GROUP BY country_code, country_name
            ORDER BY requests DESC
            LIMIT 100
            "#,
        )
        .bind(backend_id)
        .bind(start_time)
        .bind(end_time)
        .fetch_all(db)
        .await?;

        let countries = rows
            .iter()
            .map(|row| CountryMetrics {
                country_code: row.get("country_code"),
                country_name: row.get("country_name"),
                requests: row.get::<i64, _>("requests") as u64,
                bytes: row.get::<i64, _>("bytes") as u64,
                unique_ips: row.get::<i64, _>("unique_ips") as u64,
                blocked: false,
            })
            .collect();

        Ok(GeoMetrics {
            backend_id: backend_id.to_string(),
            timestamp: Some(chrono::Utc::now().into()),
            countries,
        })
    }

    /// Get time series data for a metric
    #[instrument(skip(self))]
    pub async fn get_time_series(
        &self,
        backend_id: &str,
        metric_name: &str,
        start_time: chrono::DateTime<chrono::Utc>,
        end_time: chrono::DateTime<chrono::Utc>,
        granularity: TimeGranularity,
    ) -> Result<TimeSeries> {
        let db = self.state.db()?;

        let interval = match granularity {
            TimeGranularity::Minute => "1 minute",
            TimeGranularity::FiveMinutes => "5 minutes",
            TimeGranularity::FifteenMinutes => "15 minutes",
            TimeGranularity::Hour => "1 hour",
            TimeGranularity::Day => "1 day",
            _ => "5 minutes",
        };

        let rows = sqlx::query(&format!(
            r#"
            SELECT
                time_bucket('{}'::interval, timestamp) as bucket,
                AVG(value) as value
            FROM metrics_timeseries
            WHERE backend_id = $1
              AND metric_name = $2
              AND timestamp >= $3
              AND timestamp < $4
            GROUP BY bucket
            ORDER BY bucket
            "#,
            interval
        ))
        .bind(backend_id)
        .bind(metric_name)
        .bind(start_time)
        .bind(end_time)
        .fetch_all(db)
        .await?;

        let points = rows
            .iter()
            .map(|row| {
                let ts: chrono::DateTime<chrono::Utc> = row.get("bucket");
                DataPoint {
                    timestamp: Some(ts.into()),
                    value: row.get("value"),
                }
            })
            .collect();

        Ok(TimeSeries {
            metric_name: metric_name.to_string(),
            points,
        })
    }

    /// List attack events
    #[instrument(skip(self))]
    pub async fn list_attack_events(
        &self,
        backend_id: &str,
        start_time: chrono::DateTime<chrono::Utc>,
        end_time: chrono::DateTime<chrono::Utc>,
        page: u32,
        page_size: u32,
    ) -> Result<Vec<AttackEvent>> {
        let db = self.state.db()?;
        let offset = (page.saturating_sub(1)) * page_size;

        let rows = sqlx::query(
            r#"
            SELECT id, backend_id, started_at, ended_at, duration_seconds,
                   attack_type, severity, peak_pps, peak_bps,
                   total_packets, total_bytes, packets_mitigated,
                   mitigation_rate, unique_sources
            FROM attack_events
            WHERE backend_id = $1
              AND started_at >= $2
              AND started_at < $3
            ORDER BY started_at DESC
            LIMIT $4 OFFSET $5
            "#,
        )
        .bind(backend_id)
        .bind(start_time)
        .bind(end_time)
        .bind(page_size as i64)
        .bind(offset as i64)
        .fetch_all(db)
        .await?;

        let events = rows
            .iter()
            .map(|row| {
                let started_at: chrono::DateTime<chrono::Utc> = row.get("started_at");
                let ended_at: Option<chrono::DateTime<chrono::Utc>> = row.get("ended_at");

                AttackEvent {
                    id: row.get("id"),
                    backend_id: row.get("backend_id"),
                    started_at: Some(started_at.into()),
                    ended_at: ended_at.map(|t| t.into()),
                    duration_seconds: row.get::<i32, _>("duration_seconds") as u32,
                    attack_type: row.get("attack_type"),
                    severity: row.get::<i32, _>("severity"),
                    peak_pps: row.get::<i64, _>("peak_pps") as u64,
                    peak_bps: row.get::<i64, _>("peak_bps") as u64,
                    total_packets: row.get::<i64, _>("total_packets") as u64,
                    total_bytes: row.get::<i64, _>("total_bytes") as u64,
                    packets_mitigated: row.get::<i64, _>("packets_mitigated") as u64,
                    mitigation_rate: row.get("mitigation_rate"),
                    unique_sources: row.get::<i32, _>("unique_sources") as u32,
                    ..Default::default()
                }
            })
            .collect();

        Ok(events)
    }

    /// Record metrics from worker
    pub async fn record_traffic_metrics(&self, metrics: &TrafficMetrics) -> Result<()> {
        // Store in Redis for real-time access
        if let Some(cache) = &self.state.cache {
            cache
                .set(
                    &format!("metrics:traffic:{}", metrics.backend_id),
                    metrics,
                    std::time::Duration::from_secs(60),
                )
                .await?;
        }

        // Also persist to database for historical analysis
        if let Some(db) = &self.state.db {
            sqlx::query(
                r#"
                INSERT INTO traffic_metrics (
                    backend_id, timestamp, requests_total, requests_per_second,
                    bytes_in, bytes_out, packets_in, packets_out, active_connections
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                "#,
            )
            .bind(&metrics.backend_id)
            .bind(chrono::Utc::now())
            .bind(metrics.requests_total as i64)
            .bind(metrics.requests_per_second as i64)
            .bind(metrics.bytes_in as i64)
            .bind(metrics.bytes_out as i64)
            .bind(metrics.packets_in as i64)
            .bind(metrics.packets_out as i64)
            .bind(metrics.active_connections as i64)
            .execute(db)
            .await?;
        }

        Ok(())
    }

    /// Record attack metrics
    pub async fn record_attack_metrics(&self, metrics: &AttackMetrics) -> Result<()> {
        if let Some(cache) = &self.state.cache {
            cache
                .set(
                    &format!("metrics:attack:{}", metrics.backend_id),
                    metrics,
                    std::time::Duration::from_secs(60),
                )
                .await?;
        }

        // Update Prometheus metrics
        pistonprotection_common::metrics::ATTACK_DETECTED
            .with_label_values(&[&metrics.backend_id, &metrics.attack_type])
            .set(if metrics.under_attack { 1.0 } else { 0.0 });

        Ok(())
    }

    /// Get origin health metrics
    #[instrument(skip(self))]
    pub async fn get_origin_metrics(
        &self,
        backend_id: &str,
        origin_id: &str,
    ) -> Result<OriginMetrics> {
        if let Some(cache) = &self.state.cache {
            if let Ok(Some(metrics)) = cache
                .get::<OriginMetrics>(&format!("metrics:origin:{}:{}", backend_id, origin_id))
                .await
            {
                return Ok(metrics);
            }
        }

        Ok(OriginMetrics {
            backend_id: backend_id.to_string(),
            origin_id: origin_id.to_string(),
            timestamp: Some(chrono::Utc::now().into()),
            ..Default::default()
        })
    }

    /// Get worker metrics
    #[instrument(skip(self))]
    pub async fn get_worker_metrics(&self, worker_id: &str) -> Result<WorkerMetrics> {
        if let Some(cache) = &self.state.cache {
            if let Ok(Some(metrics)) = cache
                .get::<WorkerMetrics>(&format!("metrics:worker:{}", worker_id))
                .await
            {
                return Ok(metrics);
            }
        }

        Ok(WorkerMetrics {
            worker_id: worker_id.to_string(),
            timestamp: Some(chrono::Utc::now().into()),
            ..Default::default()
        })
    }

    /// List all worker metrics
    #[instrument(skip(self))]
    pub async fn list_worker_metrics(
        &self,
        _page: u32,
        _page_size: u32,
    ) -> Result<Vec<WorkerMetrics>> {
        if let Some(cache) = &self.state.cache {
            // Get all worker IDs from cache
            if let Ok(Some(worker_ids)) = cache.get::<Vec<String>>("workers:active").await {
                let mut workers = Vec::new();
                for id in &worker_ids {
                    if let Ok(metrics) = self.get_worker_metrics(id).await {
                        workers.push(metrics);
                    }
                }
                return Ok(workers);
            }
        }

        Ok(vec![])
    }

    /// Get single attack event
    #[instrument(skip(self))]
    pub async fn get_attack_event(&self, event_id: &str) -> Result<Option<AttackEvent>> {
        let db = self.state.db()?;

        let row = sqlx::query(
            r#"
            SELECT id, backend_id, started_at, ended_at, duration_seconds,
                   attack_type, severity, peak_pps, peak_bps,
                   total_packets, total_bytes, packets_mitigated,
                   mitigation_rate, unique_sources
            FROM attack_events
            WHERE id = $1
            "#,
        )
        .bind(event_id)
        .fetch_optional(db)
        .await?;

        if let Some(row) = row {
            let started_at: chrono::DateTime<chrono::Utc> = row.get("started_at");
            let ended_at: Option<chrono::DateTime<chrono::Utc>> = row.get("ended_at");

            return Ok(Some(AttackEvent {
                id: row.get("id"),
                backend_id: row.get("backend_id"),
                started_at: Some(started_at.into()),
                ended_at: ended_at.map(|t| t.into()),
                duration_seconds: row.get::<i32, _>("duration_seconds") as u32,
                attack_type: row.get("attack_type"),
                severity: row.get::<i32, _>("severity"),
                peak_pps: row.get::<i64, _>("peak_pps") as u64,
                peak_bps: row.get::<i64, _>("peak_bps") as u64,
                total_packets: row.get::<i64, _>("total_packets") as u64,
                total_bytes: row.get::<i64, _>("total_bytes") as u64,
                packets_mitigated: row.get::<i64, _>("packets_mitigated") as u64,
                mitigation_rate: row.get("mitigation_rate"),
                unique_sources: row.get::<i32, _>("unique_sources") as u32,
                ..Default::default()
            }));
        }

        Ok(None)
    }
}

impl Clone for MetricsService {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}
