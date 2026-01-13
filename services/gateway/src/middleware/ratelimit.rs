//! Rate limiting middleware for gRPC

use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use pistonprotection_common::ratelimit::{GlobalRateLimiter, RateLimitConfig};
use std::sync::Arc;
use std::task::{Context, Poll};

type BoxBody = UnsyncBoxBody<Bytes, tonic::Status>;
use http_body_util::BodyExt;
use tower::{Layer, Service};
use tracing::{error, warn};

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
                // Create a rate limited response with empty body
                let empty_body = http_body_util::Empty::<Bytes>::new()
                    .map_err(|_| tonic::Status::internal("body error"))
                    .boxed_unsync();
                // Build the rate limit response. This should never fail since we're using
                // valid status codes and headers, but we handle it defensively.
                let response = match http::Response::builder()
                    .status(http::StatusCode::TOO_MANY_REQUESTS)
                    .header("content-type", "application/grpc")
                    .header("grpc-status", "8") // RESOURCE_EXHAUSTED
                    .header("grpc-message", "Rate limit exceeded")
                    .body(empty_body)
                {
                    Ok(resp) => resp,
                    Err(e) => {
                        error!("Failed to build rate limit response: {}", e);
                        // Fall back to a minimal response
                        http::Response::builder()
                            .status(http::StatusCode::TOO_MANY_REQUESTS)
                            .body(
                                http_body_util::Empty::<Bytes>::new()
                                    .map_err(|_| tonic::Status::internal("body error"))
                                    .boxed_unsync(),
                            )
                            .expect("minimal response should always build")
                    }
                };
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
