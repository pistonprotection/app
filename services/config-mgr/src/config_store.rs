//! Configuration storage and versioning
//!
//! Provides persistent storage for filter configurations with versioning,
//! validation, and caching support.

use deadpool_redis::Pool as RedisPool;
use parking_lot::RwLock;
use pistonprotection_common::{
    error::{Error, Result},
    redis::CacheService,
};
use pistonprotection_proto::worker::{BackendFilter, FilterConfig, GlobalFilterSettings};
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use tracing::info;

/// Configuration validation error
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
    pub severity: ValidationSeverity,
}

/// Validation severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationSeverity {
    Warning,
    Error,
}

/// Configuration version history entry
#[derive(Debug, Clone)]
pub struct ConfigVersionEntry {
    pub version: u32,
    pub backend_id: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub config_hash: u64,
    pub change_description: Option<String>,
}

/// Configuration store
pub struct ConfigStore {
    db: PgPool,
    cache: Option<CacheService>,
    current_version: AtomicU32,
    version_history: RwLock<Vec<ConfigVersionEntry>>,
    validation_cache: RwLock<HashMap<String, Vec<ValidationError>>>,
}

impl ConfigStore {
    pub fn new(db: PgPool, redis: Option<RedisPool>) -> Self {
        let cache = redis.map(|pool| CacheService::new(pool, "piston:config"));

        Self {
            db,
            cache,
            current_version: AtomicU32::new(1),
            version_history: RwLock::new(Vec::new()),
            validation_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Initialize the store by loading the current version from the database
    pub async fn initialize(&self) -> Result<()> {
        // Load the latest version from database
        let row = sqlx::query(
            r#"
            SELECT COALESCE(MAX(version), 0) as max_version
            FROM config_versions
            "#,
        )
        .fetch_one(&self.db)
        .await?;

        let max_version: i32 = row.get("max_version");
        self.current_version
            .store(max_version as u32, Ordering::SeqCst);

        info!(
            version = max_version,
            "Initialized config store with version"
        );

        // Load recent version history
        self.load_version_history(10).await?;

        Ok(())
    }

    /// Load version history from database
    async fn load_version_history(&self, limit: i32) -> Result<()> {
        let rows = sqlx::query(
            r#"
            SELECT version, backend_id, created_at
            FROM config_versions
            ORDER BY version DESC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.db)
        .await?;

        let mut history = self.version_history.write();
        history.clear();

        for row in rows {
            history.push(ConfigVersionEntry {
                version: row.get::<i32, _>("version") as u32,
                backend_id: row.get("backend_id"),
                created_at: row.get("created_at"),
                config_hash: 0, // Not stored in DB yet
                change_description: None,
            });
        }

        Ok(())
    }

    /// Get version history
    pub fn version_history(&self) -> Vec<ConfigVersionEntry> {
        self.version_history.read().clone()
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

    /// Validate a filter configuration
    pub fn validate_config(&self, config: &FilterConfig) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        // Check version
        if config.version == 0 {
            errors.push(ValidationError {
                field: "version".to_string(),
                message: "Configuration version should not be 0".to_string(),
                severity: ValidationSeverity::Warning,
            });
        }

        // Check config_id
        if config.config_id.is_empty() {
            errors.push(ValidationError {
                field: "config_id".to_string(),
                message: "Configuration ID is required".to_string(),
                severity: ValidationSeverity::Error,
            });
        }

        // Validate backends
        for backend in &config.backends {
            errors.extend(self.validate_backend(backend));
        }

        // Validate global settings
        if let Some(ref global) = config.global {
            errors.extend(self.validate_global_settings(global));
        }

        // Check for duplicate backend IDs
        let mut seen_ids = std::collections::HashSet::new();
        for backend in &config.backends {
            if !seen_ids.insert(&backend.backend_id) {
                errors.push(ValidationError {
                    field: format!("backends[{}]", backend.backend_id),
                    message: format!("Duplicate backend ID: {}", backend.backend_id),
                    severity: ValidationSeverity::Error,
                });
            }
        }

        // Cache validation results
        self.validation_cache
            .write()
            .insert(config.config_id.clone(), errors.clone());

        errors
    }

    /// Validate a backend filter
    fn validate_backend(&self, backend: &BackendFilter) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        if backend.backend_id.is_empty() {
            errors.push(ValidationError {
                field: "backend_id".to_string(),
                message: "Backend ID is required".to_string(),
                severity: ValidationSeverity::Error,
            });
        }

        // Validate protection settings
        if let Some(ref protection) = backend.protection {
            if protection.level > 5 {
                errors.push(ValidationError {
                    field: format!("backends[{}].protection.level", backend.backend_id),
                    message: format!("Protection level {} exceeds maximum of 5", protection.level),
                    severity: ValidationSeverity::Error,
                });
            }

            // Validate rate limits
            if let Some(ref per_ip_rate) = protection.per_ip_rate
                && per_ip_rate.tokens_per_second == 0 {
                    errors.push(ValidationError {
                        field: format!("backends[{}].protection.per_ip_rate", backend.backend_id),
                        message: "Per-IP rate limit tokens_per_second cannot be 0".to_string(),
                        severity: ValidationSeverity::Warning,
                    });
                }

            if let Some(ref global_rate) = protection.global_rate
                && global_rate.tokens_per_second == 0 {
                    errors.push(ValidationError {
                        field: format!("backends[{}].protection.global_rate", backend.backend_id),
                        message: "Global rate limit tokens_per_second cannot be 0".to_string(),
                        severity: ValidationSeverity::Warning,
                    });
                }
        }

        // Validate filter rules
        for (idx, rule) in backend.rules.iter().enumerate() {
            errors.extend(self.validate_filter_rule(&backend.backend_id, idx, rule));
        }

        // Check for duplicate rule priorities
        let mut priorities = std::collections::HashSet::new();
        for rule in &backend.rules {
            if !priorities.insert(rule.priority) {
                errors.push(ValidationError {
                    field: format!("backends[{}].rules", backend.backend_id),
                    message: format!("Duplicate rule priority: {}", rule.priority),
                    severity: ValidationSeverity::Warning,
                });
            }
        }

        errors
    }

    /// Validate a filter rule
    fn validate_filter_rule(
        &self,
        backend_id: &str,
        idx: usize,
        rule: &pistonprotection_proto::filter::FilterRule,
    ) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        let field_prefix = format!("backends[{}].rules[{}]", backend_id, idx);

        if rule.id.is_empty() {
            errors.push(ValidationError {
                field: format!("{}.id", field_prefix),
                message: "Rule ID is required".to_string(),
                severity: ValidationSeverity::Error,
            });
        }

        if rule.name.is_empty() {
            errors.push(ValidationError {
                field: format!("{}.name", field_prefix),
                message: "Rule name is required".to_string(),
                severity: ValidationSeverity::Warning,
            });
        }

        // Validate action
        if rule.action < 0 || rule.action > 4 {
            errors.push(ValidationError {
                field: format!("{}.action", field_prefix),
                message: format!("Invalid action value: {}", rule.action),
                severity: ValidationSeverity::Error,
            });
        }

        errors
    }

    /// Validate global filter settings
    fn validate_global_settings(&self, settings: &GlobalFilterSettings) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        if settings.log_sampling_rate > 100 {
            errors.push(ValidationError {
                field: "global.log_sampling_rate".to_string(),
                message: format!(
                    "Log sampling rate {} exceeds maximum of 100",
                    settings.log_sampling_rate
                ),
                severity: ValidationSeverity::Error,
            });
        }

        if settings.emergency_mode && settings.emergency_pps_threshold == 0 {
            errors.push(ValidationError {
                field: "global.emergency_pps_threshold".to_string(),
                message: "Emergency mode enabled but threshold is 0".to_string(),
                severity: ValidationSeverity::Warning,
            });
        }

        errors
    }

    /// Check if a configuration has validation errors (excluding warnings)
    pub fn has_errors(&self, config: &FilterConfig) -> bool {
        let errors = self.validate_config(config);
        errors
            .iter()
            .any(|e| e.severity == ValidationSeverity::Error)
    }

    /// Get cached validation errors for a config
    pub fn get_cached_validation(&self, config_id: &str) -> Option<Vec<ValidationError>> {
        self.validation_cache.read().get(config_id).cloned()
    }

    /// Rollback to a previous configuration version
    pub async fn rollback_to_version(&self, target_version: u32) -> Result<FilterConfig> {
        let current = self.current_version();
        if target_version >= current {
            return Err(Error::InvalidInput(format!(
                "Cannot rollback to version {} (current is {})",
                target_version, current
            )));
        }

        info!(
            from_version = current,
            to_version = target_version,
            "Rolling back configuration"
        );

        // In a real implementation, we would restore from a snapshot
        // For now, regenerate from database and set version
        self.current_version.store(target_version, Ordering::SeqCst);

        // Invalidate cache
        if let Some(ref cache) = self.cache {
            let _ = cache.delete_pattern("filter_config:*").await;
        }

        self.generate_config().await
    }

    /// Get statistics about the configuration store
    pub fn stats(&self) -> ConfigStoreStats {
        ConfigStoreStats {
            current_version: self.current_version(),
            version_history_count: self.version_history.read().len(),
            cached_validations: self.validation_cache.read().len(),
            has_cache: self.cache.is_some(),
        }
    }
}

/// Configuration store statistics
#[derive(Debug, Clone)]
pub struct ConfigStoreStats {
    pub current_version: u32,
    pub version_history_count: usize,
    pub cached_validations: usize,
    pub has_cache: bool,
}
