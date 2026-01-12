//! Filter rule management service

use crate::services::AppState;
use pistonprotection_common::error::{Error, Result};
use pistonprotection_proto::filter::*;
use sqlx::Row;
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
        let rate_limit_json = serde_json::to_value(&rule.rate_limit)
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
        .bind(rule.action as i32)
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

        let rate_limit_json = serde_json::to_value(&rule.rate_limit)
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
        .bind(rule.action as i32)
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
            let _ = cache.delete_pattern(&format!("filters:{}:*", backend_id)).await;
            // Also publish update event for workers
            let _ = cache
                .publish("filter_updates", &format!("backend:{}", backend_id))
                .await;
        }
    }
}
