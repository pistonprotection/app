//! Filter rule management service

use crate::services::AppState;
use futures::StreamExt;
use pistonprotection_common::error::{Error, Result};
use pistonprotection_proto::common;
use pistonprotection_proto::filter::*;
use sqlx::Row;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_stream::Stream;
use tokio_stream::wrappers::BroadcastStream;
use tracing::{info, instrument};
use uuid::Uuid;

/// Filter service implementation
pub struct FilterService {
    state: AppState,
}

impl FilterService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    /// Create a new filter rule
    #[instrument(skip(self, rule))]
    pub async fn create(&self, backend_id: &str, rule: FilterRule) -> Result<FilterRule> {
        let db = self.state.db()?;

        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        // Serialize match criteria to JSON
        let match_json = serde_json::to_value(&rule.r#match)
            .map_err(|e| Error::Internal(format!("Failed to serialize match: {}", e)))?;

        // Serialize rate limit to JSON
        let rate_limit_json = serde_json::to_value(rule.rate_limit)
            .map_err(|e| Error::Internal(format!("Failed to serialize rate_limit: {}", e)))?;

        sqlx::query(
            r#"
            INSERT INTO filter_rules (
                id, backend_id, name, description, priority,
                match_criteria, action, rate_limit, enabled, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(&id)
        .bind(backend_id)
        .bind(&rule.name)
        .bind(&rule.description)
        .bind(rule.priority as i32)
        .bind(&match_json)
        .bind(rule.action)
        .bind(&rate_limit_json)
        .bind(rule.enabled)
        .bind(now)
        .bind(now)
        .execute(db)
        .await?;

        info!(rule_id = %id, backend_id = %backend_id, "Created filter rule");

        // Invalidate cache
        self.invalidate_cache(backend_id).await;

        self.get(&id).await
    }

    /// Get a filter rule by ID
    #[instrument(skip(self))]
    pub async fn get(&self, id: &str) -> Result<FilterRule> {
        let db = self.state.db()?;

        let row = sqlx::query(
            r#"
            SELECT id, backend_id, name, description, priority,
                   match_criteria, action, rate_limit, enabled, created_at, updated_at
            FROM filter_rules
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(db)
        .await?
        .ok_or_else(|| Error::not_found("FilterRule", id))?;

        self.row_to_rule(&row)
    }

    /// List filter rules for a backend
    #[instrument(skip(self))]
    pub async fn list(
        &self,
        backend_id: &str,
        include_disabled: bool,
        page: u32,
        page_size: u32,
    ) -> Result<Vec<FilterRule>> {
        let db = self.state.db()?;
        let offset = (page.saturating_sub(1)) * page_size;

        let query = if include_disabled {
            r#"
            SELECT id, backend_id, name, description, priority,
                   match_criteria, action, rate_limit, enabled, created_at, updated_at
            FROM filter_rules
            WHERE backend_id = $1
            ORDER BY priority ASC, created_at ASC
            LIMIT $2 OFFSET $3
            "#
        } else {
            r#"
            SELECT id, backend_id, name, description, priority,
                   match_criteria, action, rate_limit, enabled, created_at, updated_at
            FROM filter_rules
            WHERE backend_id = $1 AND enabled = true
            ORDER BY priority ASC, created_at ASC
            LIMIT $2 OFFSET $3
            "#
        };

        let rows = sqlx::query(query)
            .bind(backend_id)
            .bind(page_size as i64)
            .bind(offset as i64)
            .fetch_all(db)
            .await?;

        rows.iter().map(|row| self.row_to_rule(row)).collect()
    }

    /// Update a filter rule
    #[instrument(skip(self, rule))]
    pub async fn update(&self, rule: FilterRule) -> Result<FilterRule> {
        let db = self.state.db()?;
        let now = chrono::Utc::now();

        let match_json = serde_json::to_value(&rule.r#match)
            .map_err(|e| Error::Internal(format!("Failed to serialize match: {}", e)))?;

        let rate_limit_json = serde_json::to_value(rule.rate_limit)
            .map_err(|e| Error::Internal(format!("Failed to serialize rate_limit: {}", e)))?;

        // First get the backend_id for cache invalidation
        let existing = sqlx::query("SELECT backend_id FROM filter_rules WHERE id = $1")
            .bind(&rule.id)
            .fetch_optional(db)
            .await?
            .ok_or_else(|| Error::not_found("FilterRule", &rule.id))?;

        let backend_id: String = existing.get("backend_id");

        let result = sqlx::query(
            r#"
            UPDATE filter_rules
            SET name = $2, description = $3, priority = $4,
                match_criteria = $5, action = $6, rate_limit = $7,
                enabled = $8, updated_at = $9
            WHERE id = $1
            "#,
        )
        .bind(&rule.id)
        .bind(&rule.name)
        .bind(&rule.description)
        .bind(rule.priority as i32)
        .bind(&match_json)
        .bind(rule.action)
        .bind(&rate_limit_json)
        .bind(rule.enabled)
        .bind(now)
        .execute(db)
        .await?;

        if result.rows_affected() == 0 {
            return Err(Error::not_found("FilterRule", &rule.id));
        }

        info!(rule_id = %rule.id, "Updated filter rule");

        // Invalidate cache
        self.invalidate_cache(&backend_id).await;

        self.get(&rule.id).await
    }

    /// Delete a filter rule
    #[instrument(skip(self))]
    pub async fn delete(&self, id: &str) -> Result<()> {
        let db = self.state.db()?;

        // Get backend_id for cache invalidation
        let existing = sqlx::query("SELECT backend_id FROM filter_rules WHERE id = $1")
            .bind(id)
            .fetch_optional(db)
            .await?
            .ok_or_else(|| Error::not_found("FilterRule", id))?;

        let backend_id: String = existing.get("backend_id");

        let result = sqlx::query("DELETE FROM filter_rules WHERE id = $1")
            .bind(id)
            .execute(db)
            .await?;

        if result.rows_affected() == 0 {
            return Err(Error::not_found("FilterRule", id));
        }

        info!(rule_id = %id, "Deleted filter rule");

        // Invalidate cache
        self.invalidate_cache(&backend_id).await;

        Ok(())
    }

    /// Reorder filter rules
    #[instrument(skip(self, rule_ids))]
    pub async fn reorder(&self, backend_id: &str, rule_ids: Vec<String>) -> Result<()> {
        let db = self.state.db()?;

        // Update priorities based on order
        for (priority, rule_id) in rule_ids.iter().enumerate() {
            sqlx::query(
                r#"
                UPDATE filter_rules
                SET priority = $1, updated_at = now()
                WHERE id = $2 AND backend_id = $3
                "#,
            )
            .bind(priority as i32)
            .bind(rule_id)
            .bind(backend_id)
            .execute(db)
            .await?;
        }

        info!(backend_id = %backend_id, count = rule_ids.len(), "Reordered filter rules");

        // Invalidate cache
        self.invalidate_cache(backend_id).await;

        Ok(())
    }

    /// Convert database row to FilterRule
    fn row_to_rule(&self, row: &sqlx::postgres::PgRow) -> Result<FilterRule> {
        let match_json: serde_json::Value = row.get("match_criteria");
        let rate_limit_json: serde_json::Value = row.get("rate_limit");

        let filter_match: Option<FilterMatch> = serde_json::from_value(match_json)
            .map_err(|e| Error::Internal(format!("Failed to deserialize match: {}", e)))?;

        let rate_limit: Option<pistonprotection_proto::common::RateLimit> =
            serde_json::from_value(rate_limit_json)
                .map_err(|e| Error::Internal(format!("Failed to deserialize rate_limit: {}", e)))?;

        Ok(FilterRule {
            id: row.get("id"),
            name: row.get("name"),
            description: row.get("description"),
            priority: row.get::<i32, _>("priority") as u32,
            r#match: filter_match,
            action: row.get::<i32, _>("action"),
            rate_limit,
            enabled: row.get("enabled"),
            ..Default::default()
        })
    }

    /// Invalidate cache for a backend's filter rules
    async fn invalidate_cache(&self, backend_id: &str) {
        if let Some(cache) = &self.state.cache {
            let _ = cache
                .delete_pattern(&format!("filters:{}:*", backend_id))
                .await;
            // Also publish update event for workers
            let _ = cache
                .publish("filter_updates", &format!("backend:{}", backend_id))
                .await;
        }
    }

    // =========================================================================
    // Bulk Operations
    // =========================================================================

    /// Bulk create multiple filter rules
    #[instrument(skip(self, rules))]
    pub async fn bulk_create(
        &self,
        backend_id: &str,
        rules: Vec<FilterRule>,
    ) -> Result<(Vec<FilterRule>, Vec<common::Error>)> {
        let db = self.state.db()?;
        let now = chrono::Utc::now();

        let mut created_rules = Vec::with_capacity(rules.len());
        let mut errors = Vec::new();

        // Use a transaction for atomicity
        let mut tx = db.begin().await?;

        for (index, rule) in rules.into_iter().enumerate() {
            let id = Uuid::new_v4().to_string();

            // Serialize match criteria to JSON
            let match_json = match serde_json::to_value(&rule.r#match) {
                Ok(json) => json,
                Err(e) => {
                    errors.push(common::Error {
                        code: "SERIALIZATION_ERROR".to_string(),
                        message: format!("Rule {}: Failed to serialize match: {}", index, e),
                        details: std::collections::HashMap::new(),
                    });
                    continue;
                }
            };

            // Serialize rate limit to JSON
            let rate_limit_json = match serde_json::to_value(rule.rate_limit) {
                Ok(json) => json,
                Err(e) => {
                    errors.push(common::Error {
                        code: "SERIALIZATION_ERROR".to_string(),
                        message: format!("Rule {}: Failed to serialize rate_limit: {}", index, e),
                        details: std::collections::HashMap::new(),
                    });
                    continue;
                }
            };

            // Validate rule
            if rule.name.is_empty() {
                errors.push(common::Error {
                    code: "VALIDATION_ERROR".to_string(),
                    message: format!("Rule {}: Name is required", index),
                    details: std::collections::HashMap::new(),
                });
                continue;
            }

            let result = sqlx::query(
                r#"
                INSERT INTO filter_rules (
                    id, backend_id, name, description, priority,
                    match_criteria, action, rate_limit, enabled, created_at, updated_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                "#,
            )
            .bind(&id)
            .bind(backend_id)
            .bind(&rule.name)
            .bind(&rule.description)
            .bind(rule.priority as i32)
            .bind(&match_json)
            .bind(rule.action)
            .bind(&rate_limit_json)
            .bind(rule.enabled)
            .bind(now)
            .bind(now)
            .execute(&mut *tx)
            .await;

            match result {
                Ok(_) => {
                    let mut created_rule = rule;
                    created_rule.id = id;
                    created_rules.push(created_rule);
                }
                Err(e) => {
                    errors.push(common::Error {
                        code: "DATABASE_ERROR".to_string(),
                        message: format!("Rule {}: {}", index, e),
                        details: std::collections::HashMap::new(),
                    });
                }
            }
        }

        // Commit transaction
        tx.commit().await?;

        info!(
            backend_id = %backend_id,
            created = created_rules.len(),
            errors = errors.len(),
            "Bulk created filter rules"
        );

        // Invalidate cache
        self.invalidate_cache(backend_id).await;

        // Publish updates for each created rule
        for rule in &created_rules {
            self.publish_rule_update(backend_id, &rule.id, rule_update::UpdateType::Created)
                .await;
        }

        Ok((created_rules, errors))
    }

    /// Bulk delete multiple filter rules
    #[instrument(skip(self, rule_ids))]
    pub async fn bulk_delete(&self, rule_ids: Vec<String>) -> Result<(u32, Vec<common::Error>)> {
        let db = self.state.db()?;

        let mut deleted_count = 0u32;
        let mut errors = Vec::new();
        let mut affected_backends = std::collections::HashSet::new();

        for rule_id in &rule_ids {
            // First get the backend_id
            let row: Option<(String,)> =
                sqlx::query_as("SELECT backend_id FROM filter_rules WHERE id = $1")
                    .bind(rule_id)
                    .fetch_optional(db)
                    .await?;

            match row {
                Some((backend_id,)) => {
                    let result = sqlx::query("DELETE FROM filter_rules WHERE id = $1")
                        .bind(rule_id)
                        .execute(db)
                        .await;

                    match result {
                        Ok(r) if r.rows_affected() > 0 => {
                            deleted_count += 1;
                            affected_backends.insert(backend_id.clone());

                            // Publish delete event
                            self.publish_rule_update(
                                &backend_id,
                                rule_id,
                                rule_update::UpdateType::Deleted,
                            )
                            .await;
                        }
                        Ok(_) => {
                            errors.push(common::Error {
                                code: "NOT_FOUND".to_string(),
                                message: format!("Rule {} not found", rule_id),
                                details: std::collections::HashMap::new(),
                            });
                        }
                        Err(e) => {
                            errors.push(common::Error {
                                code: "DATABASE_ERROR".to_string(),
                                message: format!("Failed to delete {}: {}", rule_id, e),
                                details: std::collections::HashMap::new(),
                            });
                        }
                    }
                }
                None => {
                    errors.push(common::Error {
                        code: "NOT_FOUND".to_string(),
                        message: format!("Rule {} not found", rule_id),
                        details: std::collections::HashMap::new(),
                    });
                }
            }
        }

        info!(
            deleted = deleted_count,
            errors = errors.len(),
            "Bulk deleted filter rules"
        );

        // Invalidate cache for all affected backends
        for backend_id in affected_backends {
            self.invalidate_cache(&backend_id).await;
        }

        Ok((deleted_count, errors))
    }

    // =========================================================================
    // Statistics
    // =========================================================================

    /// Get statistics for a filter rule
    #[instrument(skip(self))]
    pub async fn get_stats(
        &self,
        rule_id: &str,
        from: Option<chrono::DateTime<chrono::Utc>>,
        to: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(FilterStats, Vec<TimeSeriesPoint>)> {
        let db = self.state.db()?;

        let from = from.unwrap_or_else(|| chrono::Utc::now() - chrono::Duration::hours(24));
        let to = to.unwrap_or_else(chrono::Utc::now);

        // Get aggregate stats
        let stats_row: Option<(i64, i64, i64, i64, i64, i64)> = sqlx::query_as(
            r#"
            SELECT
                COALESCE(SUM(packets_matched), 0) as packets_matched,
                COALESCE(SUM(bytes_matched), 0) as bytes_matched,
                COALESCE(SUM(packets_allowed), 0) as packets_allowed,
                COALESCE(SUM(packets_dropped), 0) as packets_dropped,
                COALESCE(SUM(packets_rate_limited), 0) as packets_rate_limited,
                COALESCE(SUM(packets_challenged), 0) as packets_challenged
            FROM filter_rule_stats
            WHERE rule_id = $1 AND timestamp >= $2 AND timestamp < $3
            "#,
        )
        .bind(rule_id)
        .bind(from)
        .bind(to)
        .fetch_optional(db)
        .await?;

        let stats = match stats_row {
            Some((matched, bytes, allowed, dropped, rate_limited, challenged)) => FilterStats {
                packets_matched: matched as u64,
                bytes_matched: bytes as u64,
                packets_allowed: allowed as u64,
                packets_dropped: dropped as u64,
                packets_rate_limited: rate_limited as u64,
                packets_challenged: challenged as u64,
                last_matched: None,
            },
            None => FilterStats::default(),
        };

        // Get time series data
        let time_series_rows = sqlx::query(
            r#"
            SELECT
                time_bucket('5 minutes', timestamp) as bucket,
                SUM(packets_matched) as packets,
                SUM(bytes_matched) as bytes
            FROM filter_rule_stats
            WHERE rule_id = $1 AND timestamp >= $2 AND timestamp < $3
            GROUP BY bucket
            ORDER BY bucket
            "#,
        )
        .bind(rule_id)
        .bind(from)
        .bind(to)
        .fetch_all(db)
        .await?;

        let time_series: Vec<TimeSeriesPoint> = time_series_rows
            .iter()
            .map(|row| {
                let ts: chrono::DateTime<chrono::Utc> = row.get("bucket");
                TimeSeriesPoint {
                    timestamp: Some(ts.into()),
                    packets: row.get::<i64, _>("packets") as u64,
                    bytes: row.get::<i64, _>("bytes") as u64,
                }
            })
            .collect();

        Ok((stats, time_series))
    }

    // =========================================================================
    // Streaming
    // =========================================================================

    /// Watch for rule updates on a backend
    #[instrument(skip(self))]
    pub async fn watch_rules(
        &self,
        backend_id: &str,
    ) -> Result<impl Stream<Item = Result<RuleUpdate>> + Send + 'static> {
        // Create a broadcast channel for rule updates
        let (tx, rx) = broadcast::channel::<RuleUpdate>(64);

        let backend_id = backend_id.to_string();
        let state = self.state.clone();

        // Spawn a task to listen for Redis pub/sub messages
        tokio::spawn(async move {
            if let Some(cache) = &state.cache {
                // Poll for updates (in production, use Redis SUBSCRIBE)
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                let _last_update_key = format!("filter_last_update:{}", backend_id);

                loop {
                    interval.tick().await;

                    // Check for updates in Redis
                    if let Ok(Some(update_json)) = cache
                        .get::<String>(&format!("filter_update:{}", backend_id))
                        .await
                    {
                        if let Ok(update) = serde_json::from_str::<RuleUpdate>(&update_json) {
                            if tx.send(update).is_err() {
                                // No receivers left
                                break;
                            }
                        }
                    }
                }
            }
        });

        // Convert broadcast receiver to stream
        let stream = BroadcastStream::new(rx).filter_map(|result| async move {
            match result {
                Ok(update) => Some(Ok(update)),
                Err(_) => None, // BroadcastStreamRecvError (lagged or closed)
            }
        });

        Ok(stream)
    }

    /// Publish a rule update event
    async fn publish_rule_update(
        &self,
        backend_id: &str,
        rule_id: &str,
        update_type: rule_update::UpdateType,
    ) {
        if let Some(cache) = &self.state.cache {
            // Get the rule if it exists (for created/updated events)
            let rule = if update_type != rule_update::UpdateType::Deleted {
                self.get(rule_id).await.ok()
            } else {
                // For deleted events, create a minimal rule with just the ID
                Some(FilterRule {
                    id: rule_id.to_string(),
                    ..Default::default()
                })
            };

            let update = RuleUpdate {
                r#type: update_type as i32,
                rule,
            };

            if let Ok(json) = serde_json::to_string(&update) {
                // Store the update for watchers to poll
                let key = format!("filter_update:{}", backend_id);
                let _ = cache.set(&key, &json, Duration::from_secs(60)).await;

                // Also publish for real-time subscribers
                let _ = cache.publish("filter_updates", &json).await;
            }
        }
    }
}
