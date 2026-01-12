//! Authentication middleware for gRPC

use std::task::{Context, Poll};
use tonic::{body::BoxBody, Status};
use tower::{Layer, Service};
use tracing::warn;

/// Authentication middleware
#[derive(Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
}

impl<S> AuthMiddleware<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, ReqBody> Service<http::Request<ReqBody>> for AuthMiddleware<S>
where
    S: Service<http::Request<ReqBody>, Response = http::Response<BoxBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = futures::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<ReqBody>) -> Self::Future {
        // Clone the service to use in the async block
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Extract authorization header
            let auth_header = req.headers().get("authorization");

            // Skip auth for health checks and reflection
            let path = req.uri().path();
            if path.starts_with("/grpc.health")
                || path.starts_with("/grpc.reflection")
                || path.starts_with("/health")
            {
                return inner.call(req).await;
            }

            // Validate token (placeholder - integrate with better-auth)
            if let Some(_header) = auth_header {
                // TODO: Validate JWT token with better-auth
                // For now, accept any token
                inner.call(req).await
            } else {
                // No auth header - check if it's an API key
                if let Some(_api_key) = req.headers().get("x-api-key") {
                    // TODO: Validate API key
                    inner.call(req).await
                } else {
                    warn!("Unauthorized request to {}", path);
                    // For now, allow all requests during development
                    // In production, return: Err(Status::unauthenticated("Missing authorization").into())
                    inner.call(req).await
                }
            }
        })
    }
}

/// Layer for authentication middleware
#[derive(Clone)]
pub struct AuthLayer;

impl<S> Layer<S> for AuthLayer {
    type Service = AuthMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        AuthMiddleware::new(service)
    }
}
