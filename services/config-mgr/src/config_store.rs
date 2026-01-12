//! Configuration storage and versioning

use deadpool_redis::Pool as RedisPool;
use pistonprotection_common::{
    error::{Error, Result},
    redis::CacheService,
};
use pistonprotection_proto::worker::{BackendFilter, FilterConfig, GlobalFilterSettings};
use sqlx::{PgPool, Row};
use std::sync::atomic::{AtomicU32, Ordering};
use tracing::{debug, info};

/// Configuration store
pub struct ConfigStore {
    db: PgPool,
    cache: Option<CacheService>,
    current_version: AtomicU32,
}

impl ConfigStore {
    pub fn new(db: PgPool, redis: Option<RedisPool>) -> Self {
        let cache = redis.map(|pool| CacheService::new(pool, "piston:config"));

        Self {
            db,
            cache,
            current_version: AtomicU32::new(1),
        }
    }

    /// Get the current configuration version
    pub fn current_version(&self) -> u32 {
        self.current_version.load(Ordering::SeqCst)
    }

    /// Increment and get new version
    fn next_version(&self) -> u32 {
        self.current_version.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Generate a complete filter configuration for all backends
    pub async fn generate_config(&self) -> Result<FilterConfig> {
        let version = self.current_version();

        // Check cache first
        if let Some(ref cache) = self.cache {
            let cache_key = format!("filter_config:{}", version);
            if let Ok(Some(config)) = cache.get::<FilterConfig>(&cache_key).await {
                return Ok(config);
            }
        }

        // Generate from database
        let backends = self.load_all_backends().await?;

        let config = FilterConfig {
            config_id: uuid::Uuid::new_v4().to_string(),
            version,
            backends,
            global: Some(GlobalFilterSettings {
                default_action: 1, // ALLOW
                log_sampling_rate: 100,
                emergency_mode: false,
                emergency_pps_threshold: 1_000_000,
            }),
            generated_at: Some(chrono::Utc::now().into()),
        };

        // Cache the config
        if let Some(ref cache) = self.cache {
            let cache_key = format!("filter_config:{}", version);
            let _ = cache
                .set(&cache_key, &config, std::time::Duration::from_secs(300))
                .await;
        }

        Ok(config)
    }

    /// Load all backend filter configurations
    async fn load_all_backends(&self) -> Result<Vec<BackendFilter>> {
        let rows = sqlx::query(
            r#"
            SELECT b.id, b.type, b.protection_settings,
                   array_agg(DISTINCT o.ip_address) as origin_ips,
                   array_agg(DISTINCT o.port) as origin_ports
            FROM backends b
            LEFT JOIN origins o ON o.backend_id = b.id
            WHERE b.deleted_at IS NULL
            GROUP BY b.id
            "#,
        )
        .fetch_all(&self.db)
        .await?;

        let mut backends = Vec::new();

        for row in rows {
            let backend_id: String = row.get("id");
            let protection_json: Option<serde_json::Value> = row.get("protection_settings");

            // Load filter rules for this backend
            let rules = self.load_backend_rules(&backend_id).await?;

            let backend_filter = BackendFilter {
                backend_id,
                destination_ips: vec![], // Would be populated from origins
                destination_ports: vec![],
                protocol: row.get::<i32, _>("type"),
                protection: protection_json.and_then(|v| serde_json::from_value(v).ok()),
                rules,
            };

            backends.push(backend_filter);
        }

        Ok(backends)
    }

    /// Load filter rules for a specific backend
    async fn load_backend_rules(
        &self,
        backend_id: &str,
    ) -> Result<Vec<pistonprotection_proto::filter::FilterRule>> {
        let rows = sqlx::query(
            r#"
            SELECT id, name, description, priority, match_criteria,
                   action, rate_limit, enabled
            FROM filter_rules
            WHERE backend_id = $1 AND enabled = true
            ORDER BY priority ASC
            "#,
        )
        .bind(backend_id)
        .fetch_all(&self.db)
        .await?;

        let mut rules = Vec::new();

        for row in rows {
            let rule = pistonprotection_proto::filter::FilterRule {
                id: row.get("id"),
                name: row.get("name"),
                description: row.get("description"),
                priority: row.get::<i32, _>("priority") as u32,
                r#match: row
                    .get::<Option<serde_json::Value>, _>("match_criteria")
                    .and_then(|v| serde_json::from_value(v).ok()),
                action: row.get::<i32, _>("action"),
                rate_limit: row
                    .get::<Option<serde_json::Value>, _>("rate_limit")
                    .and_then(|v| serde_json::from_value(v).ok()),
                enabled: row.get("enabled"),
                ..Default::default()
            };

            rules.push(rule);
        }

        Ok(rules)
    }

    /// Mark configuration as updated (increment version)
    pub async fn mark_updated(&self, backend_id: &str) -> Result<u32> {
        let new_version = self.next_version();

        info!(backend_id = %backend_id, version = new_version, "Configuration updated");

        // Invalidate cache
        if let Some(ref cache) = self.cache {
            let _ = cache.delete_pattern("filter_config:*").await;
            // Publish update notification
            let _ = cache
                .publish("config_updates", &format!("{}:{}", backend_id, new_version))
                .await;
        }

        // Store version in database
        sqlx::query(
            r#"
            INSERT INTO config_versions (version, backend_id, created_at)
            VALUES ($1, $2, now())
            "#,
        )
        .bind(new_version as i32)
        .bind(backend_id)
        .execute(&self.db)
        .await?;

        Ok(new_version)
    }

    /// Get configuration for a specific backend
    pub async fn get_backend_config(&self, backend_id: &str) -> Result<BackendFilter> {
        let row = sqlx::query(
            r#"
            SELECT b.id, b.type, b.protection_settings
            FROM backends b
            WHERE b.id = $1 AND b.deleted_at IS NULL
            "#,
        )
        .bind(backend_id)
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| Error::not_found("Backend", backend_id))?;

        let rules = self.load_backend_rules(backend_id).await?;
        let protection_json: Option<serde_json::Value> = row.get("protection_settings");

        Ok(BackendFilter {
            backend_id: row.get("id"),
            destination_ips: vec![],
            destination_ports: vec![],
            protocol: row.get::<i32, _>("type"),
            protection: protection_json.and_then(|v| serde_json::from_value(v).ok()),
            rules,
        })
    }
}
