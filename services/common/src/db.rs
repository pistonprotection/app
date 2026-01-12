//! Database connection management

use crate::config::DatabaseConfig;
use crate::error::Result;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;
use tracing::info;

/// Create a PostgreSQL connection pool
pub async fn create_pool(config: &DatabaseConfig) -> Result<PgPool> {
    info!(
        "Connecting to database with pool size: {}-{}",
        config.min_pool_size, config.max_pool_size
    );

    let pool = PgPoolOptions::new()
        .min_connections(config.min_pool_size)
        .max_connections(config.max_pool_size)
        .acquire_timeout(Duration::from_secs(config.connect_timeout_secs))
        .idle_timeout(Duration::from_secs(config.idle_timeout_secs))
        .connect(&config.url)
        .await?;

    // Test connection
    sqlx::query("SELECT 1").fetch_one(&pool).await?;
    info!("Database connection established");

    Ok(pool)
}

/// Run database migrations
pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    info!("Running database migrations");
    sqlx::migrate!("./migrations").run(pool).await?;
    info!("Database migrations completed");
    Ok(())
}

/// Extension trait for common database operations
pub trait DbExt {
    /// Generate a new UUID
    fn generate_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// Get current timestamp
    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }
}

impl DbExt for PgPool {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_id() {
        let id1 = PgPool::generate_id();
        let id2 = PgPool::generate_id();
        assert_ne!(id1, id2);
        assert!(uuid::Uuid::parse_str(&id1).is_ok());
    }
}
