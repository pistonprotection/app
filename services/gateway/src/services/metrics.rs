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

    /// List attack events with pagination
    /// Returns (events, total_count)
    #[instrument(skip(self))]
    pub async fn list_attack_events(
        &self,
        backend_id: &str,
        start_time: chrono::DateTime<chrono::Utc>,
        end_time: chrono::DateTime<chrono::Utc>,
        page: u32,
        page_size: u32,
    ) -> Result<(Vec<AttackEvent>, u64)> {
        let db = self.state.db()?;
        let offset = (page.saturating_sub(1)) * page_size;

        // Get total count for pagination
        let count_row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)
            FROM attack_events
            WHERE backend_id = $1
              AND started_at >= $2
              AND started_at < $3
            "#,
        )
        .bind(backend_id)
        .bind(start_time)
        .bind(end_time)
        .fetch_one(db)
        .await?;
        let total = count_row.0 as u64;

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

        Ok((events, total))
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

    /// List all worker metrics with pagination
    /// Returns (workers, total_count)
    #[instrument(skip(self))]
    pub async fn list_worker_metrics(
        &self,
        page: u32,
        page_size: u32,
    ) -> Result<(Vec<WorkerMetrics>, u64)> {
        if let Some(cache) = &self.state.cache {
            // Get all worker IDs from cache
            if let Ok(Some(worker_ids)) = cache.get::<Vec<String>>("workers:active").await {
                let total = worker_ids.len() as u64;
                let offset = ((page.saturating_sub(1)) * page_size) as usize;
                let limit = page_size as usize;

                let mut workers = Vec::new();
                for id in worker_ids.iter().skip(offset).take(limit) {
                    if let Ok(metrics) = self.get_worker_metrics(id).await {
                        workers.push(metrics);
                    }
                }
                return Ok((workers, total));
            }
        }

        Ok((vec![], 0))
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

    // =========================================================================
    // Alert CRUD Operations
    // =========================================================================

    /// Create a new alert
    #[instrument(skip(self))]
    pub async fn create_alert(&self, backend_id: &str, mut alert: Alert) -> Result<Alert> {
        let db = self.state.db()?;

        // Generate a new ID if not provided
        if alert.id.is_empty() {
            alert.id = uuid::Uuid::new_v4().to_string();
        }
        alert.backend_id = backend_id.to_string();

        let now = chrono::Utc::now();
        alert.created_at = Some(now.into());
        alert.updated_at = Some(now.into());
        alert.state = AlertState::Ok.into();

        // Serialize condition and notifications to JSON
        let condition_json = alert
            .condition
            .as_ref()
            .map(|c| serde_json::to_value(c).unwrap_or_default());
        let notifications_json = serde_json::to_value(&alert.notifications).unwrap_or_default();

        sqlx::query(
            r#"
            INSERT INTO alerts (id, backend_id, name, condition, notifications, enabled, state, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(&alert.id)
        .bind(&alert.backend_id)
        .bind(&alert.name)
        .bind(&condition_json)
        .bind(&notifications_json)
        .bind(alert.enabled)
        .bind(alert.state)
        .bind(now)
        .bind(now)
        .execute(db)
        .await?;

        Ok(alert)
    }

    /// Get an alert by ID
    #[instrument(skip(self))]
    pub async fn get_alert(&self, alert_id: &str) -> Result<Option<Alert>> {
        let db = self.state.db()?;

        let row = sqlx::query(
            r#"
            SELECT id, backend_id, name, condition, notifications, enabled, state,
                   last_triggered, created_at, updated_at
            FROM alerts
            WHERE id = $1
            "#,
        )
        .bind(alert_id)
        .fetch_optional(db)
        .await?;

        if let Some(row) = row {
            return Ok(Some(self.row_to_alert(&row)));
        }

        Ok(None)
    }

    /// Update an existing alert
    #[instrument(skip(self))]
    pub async fn update_alert(&self, alert: Alert) -> Result<Alert> {
        let db = self.state.db()?;

        let now = chrono::Utc::now();
        let condition_json = alert
            .condition
            .as_ref()
            .map(|c| serde_json::to_value(c).unwrap_or_default());
        let notifications_json = serde_json::to_value(&alert.notifications).unwrap_or_default();

        sqlx::query(
            r#"
            UPDATE alerts
            SET name = $2, condition = $3, notifications = $4, enabled = $5, state = $6, updated_at = $7
            WHERE id = $1
            "#,
        )
        .bind(&alert.id)
        .bind(&alert.name)
        .bind(&condition_json)
        .bind(&notifications_json)
        .bind(alert.enabled)
        .bind(alert.state)
        .bind(now)
        .execute(db)
        .await?;

        // Return updated alert
        self.get_alert(&alert.id)
            .await?
            .ok_or_else(|| pistonprotection_common::error::Error::NotFound {
                entity: "Alert".to_string(),
                id: alert.id.clone(),
            })
    }

    /// Delete an alert
    #[instrument(skip(self))]
    pub async fn delete_alert(&self, alert_id: &str) -> Result<bool> {
        let db = self.state.db()?;

        let result = sqlx::query("DELETE FROM alerts WHERE id = $1")
            .bind(alert_id)
            .execute(db)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// List alerts for a backend
    #[instrument(skip(self))]
    pub async fn list_alerts(
        &self,
        backend_id: &str,
        page: u32,
        page_size: u32,
    ) -> Result<(Vec<Alert>, u64)> {
        let db = self.state.db()?;
        let offset = (page.saturating_sub(1)) * page_size;

        // Get total count
        let count_row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM alerts WHERE backend_id = $1")
            .bind(backend_id)
            .fetch_one(db)
            .await?;
        let total = count_row.0 as u64;

        // Get alerts
        let rows = sqlx::query(
            r#"
            SELECT id, backend_id, name, condition, notifications, enabled, state,
                   last_triggered, created_at, updated_at
            FROM alerts
            WHERE backend_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(backend_id)
        .bind(page_size as i64)
        .bind(offset as i64)
        .fetch_all(db)
        .await?;

        let alerts = rows.iter().map(|row| self.row_to_alert(row)).collect();

        Ok((alerts, total))
    }

    /// Helper to convert a database row to an Alert
    fn row_to_alert(&self, row: &sqlx::postgres::PgRow) -> Alert {
        let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
        let updated_at: chrono::DateTime<chrono::Utc> = row.get("updated_at");
        let last_triggered: Option<chrono::DateTime<chrono::Utc>> = row.get("last_triggered");
        let condition_json: Option<serde_json::Value> = row.get("condition");
        let notifications_json: serde_json::Value = row.get("notifications");

        Alert {
            id: row.get("id"),
            backend_id: row.get("backend_id"),
            name: row.get("name"),
            condition: condition_json.and_then(|v| serde_json::from_value(v).ok()),
            notifications: serde_json::from_value(notifications_json).unwrap_or_default(),
            enabled: row.get("enabled"),
            state: row.get::<i32, _>("state"),
            last_triggered: last_triggered.map(|t| t.into()),
            created_at: Some(created_at.into()),
            updated_at: Some(updated_at.into()),
        }
    }
}

impl Clone for MetricsService {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}
