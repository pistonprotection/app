//! Backend management service

use crate::services::AppState;
use pistonprotection_common::error::{Error, Result};
use pistonprotection_proto::backend::*;
use sqlx::Row;
use tracing::{info, instrument};
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
        .bind(backend.r#type as i32)
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

    /// List backends for an organization
    #[instrument(skip(self))]
    pub async fn list(&self, org_id: &str, page: u32, page_size: u32) -> Result<Vec<Backend>> {
        let db = self.state.db()?;

        let offset = (page.saturating_sub(1)) * page_size;

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

        Ok(backends)
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
        .bind(backend.r#type as i32)
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
}
