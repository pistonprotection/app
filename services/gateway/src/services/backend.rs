//! Backend management service

use crate::services::AppState;
use futures::StreamExt;
use pistonprotection_common::error::{Error, Result};
use pistonprotection_proto::backend::*;
use pistonprotection_proto::common::HealthStatus;
use sqlx::Row;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_stream::Stream;
use tokio_stream::wrappers::BroadcastStream;
use tracing::{info, instrument, warn};
use uuid::Uuid;

/// Backend service implementation
pub struct BackendService {
    state: AppState,
}

impl BackendService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    /// Create a new backend
    #[instrument(skip(self))]
    pub async fn create(&self, org_id: &str, backend: Backend) -> Result<Backend> {
        let db = self.state.db()?;

        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        // Insert backend
        sqlx::query(
            r#"
            INSERT INTO backends (id, organization_id, name, description, type, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(&id)
        .bind(org_id)
        .bind(&backend.name)
        .bind(&backend.description)
        .bind(backend.r#type)
        .bind(now)
        .bind(now)
        .execute(db)
        .await?;

        info!(backend_id = %id, org_id = %org_id, "Created backend");

        // Invalidate cache
        if let Some(cache) = &self.state.cache {
            let _ = cache.delete_pattern(&format!("backend:{}:*", org_id)).await;
        }

        // Return created backend
        self.get(&id).await
    }

    /// Get a backend by ID
    #[instrument(skip(self))]
    pub async fn get(&self, id: &str) -> Result<Backend> {
        // Try cache first
        if let Some(cache) = &self.state.cache {
            if let Ok(Some(backend)) = cache.get::<Backend>(&format!("backend:{}", id)).await {
                return Ok(backend);
            }
        }

        let db = self.state.db()?;

        let row = sqlx::query(
            r#"
            SELECT id, organization_id, name, description, type, created_at, updated_at
            FROM backends
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(db)
        .await?
        .ok_or_else(|| Error::not_found("Backend", id))?;

        let backend = Backend {
            id: row.get("id"),
            organization_id: row.get("organization_id"),
            name: row.get("name"),
            description: row.get("description"),
            r#type: row.get::<i32, _>("type"),
            ..Default::default()
        };

        // Cache the result
        if let Some(cache) = &self.state.cache {
            let _ = cache
                .set(
                    &format!("backend:{}", id),
                    &backend,
                    std::time::Duration::from_secs(300),
                )
                .await;
        }

        Ok(backend)
    }

    /// List backends for an organization with pagination
    /// Returns (backends, total_count)
    #[instrument(skip(self))]
    pub async fn list(
        &self,
        org_id: &str,
        page: u32,
        page_size: u32,
    ) -> Result<(Vec<Backend>, u64)> {
        let db = self.state.db()?;

        let offset = (page.saturating_sub(1)) * page_size;

        // Get total count for pagination
        let count_row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM backends WHERE organization_id = $1")
                .bind(org_id)
                .fetch_one(db)
                .await?;
        let total = count_row.0 as u64;

        let rows = sqlx::query(
            r#"
            SELECT id, organization_id, name, description, type, created_at, updated_at
            FROM backends
            WHERE organization_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(org_id)
        .bind(page_size as i64)
        .bind(offset as i64)
        .fetch_all(db)
        .await?;

        let backends = rows
            .iter()
            .map(|row| Backend {
                id: row.get("id"),
                organization_id: row.get("organization_id"),
                name: row.get("name"),
                description: row.get("description"),
                r#type: row.get::<i32, _>("type"),
                ..Default::default()
            })
            .collect();

        Ok((backends, total))
    }

    /// Update a backend
    #[instrument(skip(self))]
    pub async fn update(&self, backend: Backend) -> Result<Backend> {
        let db = self.state.db()?;
        let now = chrono::Utc::now();

        let result = sqlx::query(
            r#"
            UPDATE backends
            SET name = $2, description = $3, type = $4, updated_at = $5
            WHERE id = $1
            "#,
        )
        .bind(&backend.id)
        .bind(&backend.name)
        .bind(&backend.description)
        .bind(backend.r#type)
        .bind(now)
        .execute(db)
        .await?;

        if result.rows_affected() == 0 {
            return Err(Error::not_found("Backend", &backend.id));
        }

        info!(backend_id = %backend.id, "Updated backend");

        // Invalidate cache
        if let Some(cache) = &self.state.cache {
            let _ = cache.delete(&format!("backend:{}", backend.id)).await;
        }

        self.get(&backend.id).await
    }

    /// Delete a backend
    #[instrument(skip(self))]
    pub async fn delete(&self, id: &str) -> Result<()> {
        let db = self.state.db()?;

        let result = sqlx::query("DELETE FROM backends WHERE id = $1")
            .bind(id)
            .execute(db)
            .await?;

        if result.rows_affected() == 0 {
            return Err(Error::not_found("Backend", id));
        }

        info!(backend_id = %id, "Deleted backend");

        // Invalidate cache
        if let Some(cache) = &self.state.cache {
            let _ = cache.delete(&format!("backend:{}", id)).await;
        }

        Ok(())
    }

    // =========================================================================
    // Origin Management
    // =========================================================================

    /// Add an origin to a backend
    #[instrument(skip(self, origin))]
    pub async fn add_origin(&self, backend_id: &str, origin: Origin) -> Result<Origin> {
        let db = self.state.db()?;

        // Verify backend exists
        let _backend = self.get(backend_id).await?;

        let origin_id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        // Serialize origin settings to JSON
        let settings_json = serde_json::to_value(&origin.settings)
            .map_err(|e| Error::Internal(format!("Failed to serialize origin settings: {}", e)))?;

        // Serialize address to JSON
        let address_json = serde_json::to_value(&origin.address)
            .map_err(|e| Error::Internal(format!("Failed to serialize origin address: {}", e)))?;

        sqlx::query(
            r#"
            INSERT INTO backend_origins (
                id, backend_id, name, address, port, hostname,
                weight, priority, settings, enabled, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
        )
        .bind(&origin_id)
        .bind(backend_id)
        .bind(&origin.name)
        .bind(&address_json)
        .bind(origin.port as i32)
        .bind(&origin.hostname)
        .bind(origin.weight as i32)
        .bind(origin.priority as i32)
        .bind(&settings_json)
        .bind(origin.enabled)
        .bind(now)
        .bind(now)
        .execute(db)
        .await?;

        info!(origin_id = %origin_id, backend_id = %backend_id, "Added origin to backend");

        // Invalidate cache
        self.invalidate_backend_cache(backend_id).await;

        // Publish update event
        self.publish_backend_update(backend_id, "origin_added")
            .await;

        let mut created_origin = origin;
        created_origin.id = origin_id;
        Ok(created_origin)
    }

    /// Update an existing origin
    #[instrument(skip(self, origin))]
    pub async fn update_origin(&self, backend_id: &str, origin: Origin) -> Result<Origin> {
        let db = self.state.db()?;

        let now = chrono::Utc::now();

        let settings_json = serde_json::to_value(&origin.settings)
            .map_err(|e| Error::Internal(format!("Failed to serialize origin settings: {}", e)))?;

        let address_json = serde_json::to_value(&origin.address)
            .map_err(|e| Error::Internal(format!("Failed to serialize origin address: {}", e)))?;

        let result = sqlx::query(
            r#"
            UPDATE backend_origins
            SET name = $3, address = $4, port = $5, hostname = $6,
                weight = $7, priority = $8, settings = $9, enabled = $10, updated_at = $11
            WHERE id = $1 AND backend_id = $2
            "#,
        )
        .bind(&origin.id)
        .bind(backend_id)
        .bind(&origin.name)
        .bind(&address_json)
        .bind(origin.port as i32)
        .bind(&origin.hostname)
        .bind(origin.weight as i32)
        .bind(origin.priority as i32)
        .bind(&settings_json)
        .bind(origin.enabled)
        .bind(now)
        .execute(db)
        .await?;

        if result.rows_affected() == 0 {
            return Err(Error::not_found("Origin", &origin.id));
        }

        info!(origin_id = %origin.id, backend_id = %backend_id, "Updated origin");

        // Invalidate cache
        self.invalidate_backend_cache(backend_id).await;

        // Publish update event
        self.publish_backend_update(backend_id, "origin_updated")
            .await;

        Ok(origin)
    }

    /// Remove an origin from a backend
    #[instrument(skip(self))]
    pub async fn remove_origin(&self, backend_id: &str, origin_id: &str) -> Result<()> {
        let db = self.state.db()?;

        let result = sqlx::query("DELETE FROM backend_origins WHERE id = $1 AND backend_id = $2")
            .bind(origin_id)
            .bind(backend_id)
            .execute(db)
            .await?;

        if result.rows_affected() == 0 {
            return Err(Error::not_found("Origin", origin_id));
        }

        info!(origin_id = %origin_id, backend_id = %backend_id, "Removed origin from backend");

        // Invalidate cache
        self.invalidate_backend_cache(backend_id).await;

        // Publish update event
        self.publish_backend_update(backend_id, "origin_removed")
            .await;

        Ok(())
    }

    /// Get all origins for a backend
    #[instrument(skip(self))]
    pub async fn get_origins(&self, backend_id: &str) -> Result<Vec<Origin>> {
        let db = self.state.db()?;

        let rows = sqlx::query(
            r#"
            SELECT id, name, address, port, hostname, weight, priority, settings, enabled
            FROM backend_origins
            WHERE backend_id = $1
            ORDER BY priority ASC, weight DESC
            "#,
        )
        .bind(backend_id)
        .fetch_all(db)
        .await?;

        let origins = rows
            .iter()
            .map(|row| {
                let settings_json: serde_json::Value = row.get("settings");
                let address_json: serde_json::Value = row.get("address");

                let settings: Option<OriginSettings> = serde_json::from_value(settings_json).ok();
                let address: Option<pistonprotection_proto::common::IpAddress> =
                    serde_json::from_value(address_json).ok();

                Origin {
                    id: row.get("id"),
                    name: row.get("name"),
                    address,
                    port: row.get::<i32, _>("port") as u32,
                    hostname: row.get("hostname"),
                    weight: row.get::<i32, _>("weight") as u32,
                    priority: row.get::<i32, _>("priority") as u32,
                    settings,
                    enabled: row.get("enabled"),
                    health_status: HealthStatus::Unspecified as i32,
                }
            })
            .collect();

        Ok(origins)
    }

    // =========================================================================
    // Domain Management
    // =========================================================================

    /// Add a domain to a backend
    #[instrument(skip(self))]
    pub async fn add_domain(
        &self,
        backend_id: &str,
        domain: &str,
    ) -> Result<(String, String, String)> {
        let db = self.state.db()?;

        // Verify backend exists
        let _backend = self.get(backend_id).await?;

        // Validate domain format
        if !Self::is_valid_domain(domain) {
            return Err(Error::validation(format!(
                "Invalid domain format: {}",
                domain
            )));
        }

        // Check if domain already exists
        let existing: Option<(String,)> =
            sqlx::query_as("SELECT backend_id FROM backend_domains WHERE domain = $1")
                .bind(domain)
                .fetch_optional(db)
                .await?;

        if existing.is_some() {
            return Err(Error::already_exists("Domain", "domain", domain));
        }

        // Generate verification token
        let verification_token = format!("piston-verify-{}", Uuid::new_v4());
        let verification_method = "DNS_TXT".to_string();

        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            INSERT INTO backend_domains (
                backend_id, domain, verification_token, verification_method,
                verified, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, false, $5, $6)
            "#,
        )
        .bind(backend_id)
        .bind(domain)
        .bind(&verification_token)
        .bind(&verification_method)
        .bind(now)
        .bind(now)
        .execute(db)
        .await?;

        info!(domain = %domain, backend_id = %backend_id, "Added domain to backend");

        // Invalidate cache
        self.invalidate_backend_cache(backend_id).await;

        Ok((domain.to_string(), verification_token, verification_method))
    }

    /// Remove a domain from a backend
    #[instrument(skip(self))]
    pub async fn remove_domain(&self, backend_id: &str, domain: &str) -> Result<()> {
        let db = self.state.db()?;

        let result =
            sqlx::query("DELETE FROM backend_domains WHERE backend_id = $1 AND domain = $2")
                .bind(backend_id)
                .bind(domain)
                .execute(db)
                .await?;

        if result.rows_affected() == 0 {
            return Err(Error::not_found("Domain", domain));
        }

        info!(domain = %domain, backend_id = %backend_id, "Removed domain from backend");

        // Invalidate cache
        self.invalidate_backend_cache(backend_id).await;

        Ok(())
    }

    /// Verify a domain (DNS TXT record check)
    #[instrument(skip(self))]
    pub async fn verify_domain(&self, backend_id: &str, domain: &str) -> Result<(bool, String)> {
        let db = self.state.db()?;

        // Get verification token
        let row: Option<(String,)> = sqlx::query_as(
            r#"
            SELECT verification_token
            FROM backend_domains
            WHERE backend_id = $1 AND domain = $2
            "#,
        )
        .bind(backend_id)
        .bind(domain)
        .fetch_optional(db)
        .await?;

        let (expected_token,) = row.ok_or_else(|| Error::not_found("Domain", domain))?;

        // Perform DNS TXT record lookup
        let verified = self.check_dns_txt_record(domain, &expected_token).await;

        if verified {
            // Update verification status
            sqlx::query(
                r#"
                UPDATE backend_domains
                SET verified = true, verified_at = NOW(), updated_at = NOW()
                WHERE backend_id = $1 AND domain = $2
                "#,
            )
            .bind(backend_id)
            .bind(domain)
            .execute(db)
            .await?;

            info!(domain = %domain, backend_id = %backend_id, "Domain verified successfully");

            // Invalidate cache
            self.invalidate_backend_cache(backend_id).await;

            Ok((true, String::new()))
        } else {
            Ok((
                false,
                format!(
                    "DNS TXT record not found. Add TXT record '_piston-verify.{}' with value '{}'",
                    domain, expected_token
                ),
            ))
        }
    }

    /// Get all domains for a backend
    #[instrument(skip(self))]
    pub async fn get_domains(&self, backend_id: &str) -> Result<Vec<String>> {
        let db = self.state.db()?;

        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT domain FROM backend_domains WHERE backend_id = $1 AND verified = true",
        )
        .bind(backend_id)
        .fetch_all(db)
        .await?;

        Ok(rows.into_iter().map(|(d,)| d).collect())
    }

    /// Check DNS TXT record for domain verification
    async fn check_dns_txt_record(&self, domain: &str, expected_value: &str) -> bool {
        use hickory_resolver::TokioResolver;

        let lookup_domain = format!("_piston-verify.{}", domain);

        // Create a resolver using the builder pattern (hickory-resolver 0.25+)
        let resolver = match TokioResolver::builder_tokio() {
            Ok(builder) => builder.build(),
            Err(e) => {
                tracing::warn!(error = %e, domain = %domain, "Failed to create DNS resolver");
                return self.check_redis_verification(domain, expected_value).await;
            }
        };

        // Look up TXT records
        match resolver.txt_lookup(&lookup_domain).await {
            Ok(txt_lookup) => {
                // Iterate through all TXT records - iter() returns &TXT items directly
                for txt_record in txt_lookup.iter() {
                    let txt_str = txt_record.to_string();
                    // Remove surrounding quotes if present
                    let txt_clean = txt_str.trim_matches('"').trim();
                    if txt_clean == expected_value {
                        tracing::info!(domain = %domain, "Domain verification successful via DNS TXT");
                        return true;
                    }
                }
                tracing::debug!(
                    domain = %domain,
                    expected = %expected_value,
                    "No matching TXT record found"
                );
                false
            }
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    domain = %domain,
                    "DNS TXT lookup failed, checking Redis fallback"
                );
                // Fall back to Redis for manually set verification (dev/testing)
                self.check_redis_verification(domain, expected_value).await
            }
        }
    }

    /// Fallback verification check using Redis (for development/testing)
    async fn check_redis_verification(&self, domain: &str, expected_value: &str) -> bool {
        if let Some(cache) = &self.state.cache {
            let key = format!("domain_verify:{}", domain);
            if let Ok(Some(token)) = cache.get::<String>(&key).await {
                if token == expected_value {
                    tracing::info!(domain = %domain, "Domain verification successful via Redis");
                    return true;
                }
            }
        }
        false
    }

    /// Validate domain format
    fn is_valid_domain(domain: &str) -> bool {
        if domain.is_empty() || domain.len() > 253 {
            return false;
        }

        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() < 2 {
            return false;
        }

        for part in parts {
            if part.is_empty() || part.len() > 63 {
                return false;
            }
            if !part.chars().all(|c| c.is_alphanumeric() || c == '-') {
                return false;
            }
            if part.starts_with('-') || part.ends_with('-') {
                return false;
            }
        }

        true
    }

    // =========================================================================
    // Protection Settings
    // =========================================================================

    /// Update protection settings for a backend
    #[instrument(skip(self, protection))]
    pub async fn update_protection(
        &self,
        backend_id: &str,
        protection: ProtectionSettings,
    ) -> Result<ProtectionSettings> {
        let db = self.state.db()?;

        // Verify backend exists
        let _backend = self.get(backend_id).await?;

        let protection_json = serde_json::to_value(&protection).map_err(|e| {
            Error::Internal(format!("Failed to serialize protection settings: {}", e))
        })?;

        let now = chrono::Utc::now();

        // Upsert protection settings
        sqlx::query(
            r#"
            INSERT INTO backend_protection (backend_id, settings, updated_at)
            VALUES ($1, $2, $3)
            ON CONFLICT (backend_id)
            DO UPDATE SET settings = $2, updated_at = $3
            "#,
        )
        .bind(backend_id)
        .bind(&protection_json)
        .bind(now)
        .execute(db)
        .await?;

        info!(backend_id = %backend_id, "Updated protection settings");

        // Invalidate cache
        self.invalidate_backend_cache(backend_id).await;

        // Publish update for workers
        self.publish_backend_update(backend_id, "protection_updated")
            .await;

        Ok(protection)
    }

    /// Set protection level (quick toggle)
    #[instrument(skip(self))]
    pub async fn set_protection_level(
        &self,
        backend_id: &str,
        level: ProtectionLevel,
    ) -> Result<ProtectionLevel> {
        let db = self.state.db()?;

        // Verify backend exists
        let _backend = self.get(backend_id).await?;

        let now = chrono::Utc::now();

        // Get current settings or create default
        let row: Option<(serde_json::Value,)> =
            sqlx::query_as("SELECT settings FROM backend_protection WHERE backend_id = $1")
                .bind(backend_id)
                .fetch_optional(db)
                .await?;

        let mut protection: ProtectionSettings = if let Some((json,)) = row {
            serde_json::from_value(json).unwrap_or_default()
        } else {
            ProtectionSettings::default()
        };

        // Update the level
        protection.level = level as i32;

        // Apply level-specific defaults
        match level {
            ProtectionLevel::Off => {
                protection.enabled = false;
            }
            ProtectionLevel::Low => {
                protection.enabled = true;
                // Set lenient rate limits
            }
            ProtectionLevel::Medium => {
                protection.enabled = true;
                // Set moderate rate limits
            }
            ProtectionLevel::High => {
                protection.enabled = true;
                // Set strict rate limits
            }
            ProtectionLevel::UnderAttack => {
                protection.enabled = true;
                // Enable all mitigations, challenges, etc.
                if let Some(challenge) = protection.challenge.as_mut() {
                    challenge.enabled = true;
                } else {
                    protection.challenge = Some(ChallengeSettings {
                        enabled: true,
                        r#type: ChallengeType::Javascript as i32,
                        difficulty: 5,
                        validity_seconds: 300,
                    });
                }
            }
            _ => {}
        }

        let protection_json = serde_json::to_value(&protection).map_err(|e| {
            Error::Internal(format!("Failed to serialize protection settings: {}", e))
        })?;

        sqlx::query(
            r#"
            INSERT INTO backend_protection (backend_id, settings, updated_at)
            VALUES ($1, $2, $3)
            ON CONFLICT (backend_id)
            DO UPDATE SET settings = $2, updated_at = $3
            "#,
        )
        .bind(backend_id)
        .bind(&protection_json)
        .bind(now)
        .execute(db)
        .await?;

        info!(backend_id = %backend_id, level = ?level, "Set protection level");

        // Invalidate cache
        self.invalidate_backend_cache(backend_id).await;

        // Publish update for workers
        self.publish_backend_update(backend_id, "protection_level_changed")
            .await;

        Ok(level)
    }

    /// Get protection settings for a backend
    #[instrument(skip(self))]
    pub async fn get_protection(&self, backend_id: &str) -> Result<ProtectionSettings> {
        let db = self.state.db()?;

        let row: Option<(serde_json::Value,)> =
            sqlx::query_as("SELECT settings FROM backend_protection WHERE backend_id = $1")
                .bind(backend_id)
                .fetch_optional(db)
                .await?;

        match row {
            Some((json,)) => serde_json::from_value(json)
                .map_err(|e| Error::Internal(format!("Failed to deserialize protection: {}", e))),
            None => Ok(ProtectionSettings::default()),
        }
    }

    // =========================================================================
    // Status and Streaming
    // =========================================================================

    /// Get current backend status
    #[instrument(skip(self))]
    pub async fn get_status(&self, backend_id: &str) -> Result<BackendStatus> {
        // Try to get from Redis (real-time status)
        if let Some(cache) = &self.state.cache {
            if let Ok(Some(status)) = cache
                .get::<BackendStatus>(&format!("backend_status:{}", backend_id))
                .await
            {
                return Ok(status);
            }
        }

        // Get origin health info from database
        let db = self.state.db()?;

        let row: Option<(i64, i64)> = sqlx::query_as(
            r#"
            SELECT
                COUNT(*) FILTER (WHERE enabled = true) as total_origins,
                COUNT(*) FILTER (WHERE enabled = true AND health_status = 1) as healthy_origins
            FROM backend_origins
            WHERE backend_id = $1
            "#,
        )
        .bind(backend_id)
        .fetch_optional(db)
        .await?;

        let (total_origins, healthy_origins) = row.unwrap_or((0, 0));

        let health = if total_origins == 0 {
            HealthStatus::Unhealthy
        } else if healthy_origins == total_origins {
            HealthStatus::Healthy
        } else if healthy_origins > 0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Unhealthy
        };

        Ok(BackendStatus {
            health: health as i32,
            healthy_origins: healthy_origins as u32,
            total_origins: total_origins as u32,
            requests_per_second: 0,
            bytes_per_second: 0,
            under_attack: false,
            attack_type: String::new(),
            attack_pps: 0,
            last_updated: Some(chrono::Utc::now().into()),
        })
    }

    /// Create a stream of backend status updates
    #[instrument(skip(self))]
    pub async fn watch_status(
        &self,
        backend_id: &str,
    ) -> Result<impl Stream<Item = Result<BackendStatus>> + Send + 'static> {
        // Create a broadcast channel for status updates
        let (tx, rx) = broadcast::channel::<BackendStatus>(32);

        let backend_id = backend_id.to_string();
        let state = self.state.clone();

        // Spawn a task to poll for status updates and publish them
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));

            loop {
                interval.tick().await;

                // Get current status from cache
                if let Some(cache) = &state.cache {
                    if let Ok(Some(status)) = cache
                        .get::<BackendStatus>(&format!("backend_status:{}", backend_id))
                        .await
                    {
                        if tx.send(status).is_err() {
                            // No receivers left, stop the task
                            break;
                        }
                    }
                }
            }
        });

        // Convert broadcast receiver to stream
        let stream = BroadcastStream::new(rx).filter_map(|result| async move {
            match result {
                Ok(status) => Some(Ok(status)),
                Err(_) => None, // BroadcastStreamRecvError (lagged or closed)
            }
        });

        Ok(stream)
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /// Invalidate all cache entries for a backend
    async fn invalidate_backend_cache(&self, backend_id: &str) {
        if let Some(cache) = &self.state.cache {
            let _ = cache.delete(&format!("backend:{}", backend_id)).await;
            let _ = cache
                .delete(&format!("backend_status:{}", backend_id))
                .await;
            let _ = cache
                .delete_pattern(&format!("backend:{}:*", backend_id))
                .await;
        }
    }

    /// Publish a backend update event for workers to consume
    async fn publish_backend_update(&self, backend_id: &str, event_type: &str) {
        if let Some(cache) = &self.state.cache {
            let message = format!("{}:{}", event_type, backend_id);
            if let Err(e) = cache.publish("backend_updates", &message).await {
                warn!(error = %e, backend_id = %backend_id, "Failed to publish backend update");
            }
        }
    }
}
