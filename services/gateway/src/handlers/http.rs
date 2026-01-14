//! HTTP handlers for health checks and metrics

use crate::services::AppState;
use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use serde::Serialize;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

/// Create the HTTP router
pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/health", get(health_check))
        .route("/health/live", get(liveness_check))
        .route("/health/ready", get(readiness_check))
        .route("/metrics", get(metrics))
        .route("/version", get(version))
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(cors)
        .with_state(state)
}

/// Health status response
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    database: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redis: Option<&'static str>,
}

/// Main health check endpoint
async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    let mut db_status = None;
    let mut redis_status = None;
    let mut overall_healthy = true;

    // Check database
    if let Some(ref db) = state.db {
        match sqlx::query("SELECT 1").fetch_one(db).await {
            Ok(_) => db_status = Some("healthy"),
            Err(_) => {
                db_status = Some("unhealthy");
                overall_healthy = false;
            }
        }
    }

    // Check Redis
    if let Some(ref cache) = state.cache {
        match cache.exists("health_check").await {
            Ok(_) => redis_status = Some("healthy"),
            Err(_) => {
                redis_status = Some("unhealthy");
                overall_healthy = false;
            }
        }
    }

    let response = HealthResponse {
        status: if overall_healthy {
            "healthy"
        } else {
            "unhealthy"
        },
        service: "gateway",
        version: env!("CARGO_PKG_VERSION"),
        database: db_status,
        redis: redis_status,
    };

    let status_code = if overall_healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status_code, Json(response))
}

/// Kubernetes liveness probe
async fn liveness_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

/// Kubernetes readiness probe
async fn readiness_check(State(state): State<AppState>) -> impl IntoResponse {
    // Check if we can serve requests
    let mut ready = true;

    // If database is configured, it must be reachable
    if let Some(ref db) = state.db {
        if sqlx::query("SELECT 1").fetch_one(db).await.is_err() {
            ready = false;
        }
    }

    // If Redis is configured, it must be reachable
    if let Some(ref cache) = state.cache {
        if cache.exists("ready_check").await.is_err() {
            ready = false;
        }
    }

    if ready {
        (StatusCode::OK, "READY")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "NOT_READY")
    }
}

/// Prometheus metrics endpoint
async fn metrics() -> impl IntoResponse {
    let metrics = pistonprotection_common::metrics::encode_metrics();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        metrics,
    )
}

/// Version information
#[derive(Serialize)]
struct VersionResponse {
    version: &'static str,
    git_commit: &'static str,
    build_time: &'static str,
    rust_version: &'static str,
}

async fn version() -> impl IntoResponse {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION"),
        git_commit: option_env!("GIT_COMMIT").unwrap_or("unknown"),
        build_time: option_env!("BUILD_TIME").unwrap_or("unknown"),
        rust_version: option_env!("RUSTC_VERSION").unwrap_or("unknown"),
    })
}
