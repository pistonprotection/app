//! HTTP handlers for health checks and metrics

use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use serde::Serialize;

use crate::services::AppState;

/// Create the HTTP router
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/health/live", get(liveness_check))
        .route("/health/ready", get(readiness_check))
        .route("/metrics", get(metrics_handler))
        .with_state(state)
}

/// Health check response
#[derive(Serialize)]
struct HealthResponse {
    status: String,
    service: String,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<HealthDetails>,
}

#[derive(Serialize)]
struct HealthDetails {
    database: ComponentHealth,
    redis: ComponentHealth,
}

#[derive(Serialize)]
struct ComponentHealth {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_ms: Option<u64>,
}

/// Main health check endpoint
async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    let start = std::time::Instant::now();

    // Check database
    let db_health = match sqlx::query("SELECT 1").fetch_one(&state.db).await {
        Ok(_) => ComponentHealth {
            status: "healthy".to_string(),
            latency_ms: Some(start.elapsed().as_millis() as u64),
        },
        Err(_) => ComponentHealth {
            status: "unhealthy".to_string(),
            latency_ms: None,
        },
    };

    // Check Redis
    let redis_start = std::time::Instant::now();
    let redis_health = match state.cache.exists("health_check").await {
        Ok(_) => ComponentHealth {
            status: "healthy".to_string(),
            latency_ms: Some(redis_start.elapsed().as_millis() as u64),
        },
        Err(_) => ComponentHealth {
            status: "unhealthy".to_string(),
            latency_ms: None,
        },
    };

    let overall_status = if db_health.status == "healthy" && redis_health.status == "healthy" {
        "healthy"
    } else {
        "degraded"
    };

    let response = HealthResponse {
        status: overall_status.to_string(),
        service: "auth".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        details: Some(HealthDetails {
            database: db_health,
            redis: redis_health,
        }),
    };

    let status_code = if overall_status == "healthy" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status_code, Json(response))
}

/// Kubernetes liveness probe
async fn liveness_check() -> impl IntoResponse {
    let response = HealthResponse {
        status: "alive".to_string(),
        service: "auth".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        details: None,
    };

    (StatusCode::OK, Json(response))
}

/// Kubernetes readiness probe
async fn readiness_check(State(state): State<AppState>) -> impl IntoResponse {
    // Check if database is accessible
    let db_ready = sqlx::query("SELECT 1").fetch_one(&state.db).await.is_ok();

    // Check if Redis is accessible
    let redis_ready = state.cache.exists("health_check").await.is_ok();

    if db_ready && redis_ready {
        let response = HealthResponse {
            status: "ready".to_string(),
            service: "auth".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            details: None,
        };
        (StatusCode::OK, Json(response))
    } else {
        let response = HealthResponse {
            status: "not_ready".to_string(),
            service: "auth".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            details: None,
        };
        (StatusCode::SERVICE_UNAVAILABLE, Json(response))
    }
}

/// Prometheus metrics endpoint
async fn metrics_handler() -> impl IntoResponse {
    use prometheus::{Encoder, TextEncoder};

    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();

    match encoder.encode(&metric_families, &mut buffer) {
        Ok(_) => (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; version=0.0.4",
            )],
            buffer,
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(axum::http::header::CONTENT_TYPE, "text/plain")],
            format!("Failed to encode metrics: {}", e).into_bytes(),
        ),
    }
}
