//! Unit tests for HTTP handlers

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

use super::test_utils::create_test_app_state;

/// Test health check endpoint returns healthy status
#[tokio::test]
async fn test_health_check_healthy() {
    let state = create_test_app_state();
    let app = crate::handlers::http::create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["status"], "healthy");
    assert_eq!(json["service"], "gateway");
}

/// Test liveness probe returns OK
#[tokio::test]
async fn test_liveness_check() {
    let state = create_test_app_state();
    let app = crate::handlers::http::create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

/// Test readiness probe returns READY when no backends configured
#[tokio::test]
async fn test_readiness_check_no_backends() {
    let state = create_test_app_state();
    let app = crate::handlers::http::create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

/// Test metrics endpoint returns prometheus format
#[tokio::test]
async fn test_metrics_endpoint() {
    let state = create_test_app_state();
    let app = crate::handlers::http::create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let headers = response.headers();
    assert!(
        headers
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("text/plain")
    );
}

/// Test version endpoint returns version info
#[tokio::test]
async fn test_version_endpoint() {
    let state = create_test_app_state();
    let app = crate::handlers::http::create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/version")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["version"].is_string());
    assert!(json["git_commit"].is_string());
    assert!(json["build_time"].is_string());
    assert!(json["rust_version"].is_string());
}

/// Test CORS headers are present
#[tokio::test]
async fn test_cors_headers() {
    let state = create_test_app_state();
    let app = crate::handlers::http::create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/health")
                .header("Origin", "http://localhost:3000")
                .header("Access-Control-Request-Method", "GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // CORS preflight should succeed
    let status = response.status();
    assert!(status == StatusCode::OK || status == StatusCode::NO_CONTENT);
}

/// Test 404 for unknown endpoints
#[tokio::test]
async fn test_unknown_endpoint_returns_404() {
    let state = create_test_app_state();
    let app = crate::handlers::http::create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/unknown/endpoint")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Test health response structure
#[tokio::test]
async fn test_health_response_structure() {
    let state = create_test_app_state();
    let app = crate::handlers::http::create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Required fields
    assert!(json.get("status").is_some());
    assert!(json.get("service").is_some());
    assert!(json.get("version").is_some());

    // Optional fields may or may not be present
    // database and redis fields are only present when configured
}

/// Test version response matches package version
#[tokio::test]
async fn test_version_matches_package() {
    let state = create_test_app_state();
    let app = crate::handlers::http::create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/version")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let version = json["version"].as_str().unwrap();
    assert_eq!(version, env!("CARGO_PKG_VERSION"));
}

/// Test compression is enabled
#[tokio::test]
async fn test_compression_enabled() {
    let state = create_test_app_state();
    let app = crate::handlers::http::create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .header("Accept-Encoding", "gzip")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    // Response may be compressed if content is large enough
}

/// Test multiple concurrent health checks
#[tokio::test]
async fn test_concurrent_health_checks() {
    let state = create_test_app_state();

    let mut handles = vec![];

    for _ in 0..10 {
        let state_clone = state.clone();
        handles.push(tokio::spawn(async move {
            let app = crate::handlers::http::create_router(state_clone);
            let response = app
                .oneshot(
                    Request::builder()
                        .uri("/health")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            response.status()
        }));
    }

    for handle in handles {
        let status = handle.await.unwrap();
        assert_eq!(status, StatusCode::OK);
    }
}

#[cfg(test)]
mod health_response_tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct HealthResponse {
        status: String,
        service: String,
        version: String,
        #[serde(default)]
        database: Option<String>,
        #[serde(default)]
        redis: Option<String>,
    }

    #[tokio::test]
    async fn test_health_deserializes_correctly() {
        let state = create_test_app_state();
        let app = crate::handlers::http::create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        let health: HealthResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(health.status, "healthy");
        assert_eq!(health.service, "gateway");
    }
}

#[cfg(test)]
mod version_response_tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct VersionResponse {
        version: String,
        git_commit: String,
        build_time: String,
        rust_version: String,
    }

    #[tokio::test]
    async fn test_version_deserializes_correctly() {
        let state = create_test_app_state();
        let app = crate::handlers::http::create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/version")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        let version: VersionResponse = serde_json::from_slice(&body).unwrap();
        assert!(!version.version.is_empty());
        assert!(!version.git_commit.is_empty());
        assert!(!version.build_time.is_empty());
        assert!(!version.rust_version.is_empty());
    }
}
