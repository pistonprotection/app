//! Rate limiting middleware for gRPC

use pistonprotection_common::ratelimit::{GlobalRateLimiter, RateLimitConfig};
use std::sync::Arc;
use std::task::{Context, Poll};
use tonic::body::BoxBody;
use tonic::Status;
use tower::{Layer, Service};
use tracing::warn;

/// Rate limiting middleware
#[derive(Clone)]
pub struct RateLimitMiddleware<S> {
    inner: S,
    limiter: Arc<GlobalRateLimiter>,
}

impl<S> RateLimitMiddleware<S> {
    pub fn new(inner: S, limiter: Arc<GlobalRateLimiter>) -> Self {
        Self { inner, limiter }
    }
}

impl<S, ReqBody> Service<http::Request<ReqBody>> for RateLimitMiddleware<S>
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
        let mut inner = self.inner.clone();
        let limiter = Arc::clone(&self.limiter);
        let path = req.uri().path().to_string();

        Box::pin(async move {
            // Skip rate limiting for health checks
            if path.starts_with("/grpc.health") || path.starts_with("/health") {
                return inner.call(req).await;
            }

            // Check rate limit
            if !limiter.check() {
                warn!(path = %path, "Rate limit exceeded");
                // Create a rate limited response
                let response = http::Response::builder()
                    .status(http::StatusCode::TOO_MANY_REQUESTS)
                    .body(tonic::body::empty_body())
                    .unwrap();
                return Ok(response);
            }

            inner.call(req).await
        })
    }
}

/// Layer for rate limiting middleware
#[derive(Clone)]
pub struct RateLimitLayer {
    limiter: Arc<GlobalRateLimiter>,
}

impl RateLimitLayer {
    pub fn new(config: &RateLimitConfig) -> Result<Self, pistonprotection_common::error::Error> {
        let limiter = GlobalRateLimiter::new(config)?;
        Ok(Self {
            limiter: Arc::new(limiter),
        })
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        RateLimitMiddleware::new(service, Arc::clone(&self.limiter))
    }
}
