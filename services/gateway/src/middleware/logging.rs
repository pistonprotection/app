//! Logging middleware for gRPC

use std::task::{Context, Poll};
use std::time::Instant;
use tonic::body::BoxBody;
use tower::{Layer, Service};
use tracing::{info, info_span, Instrument};

/// Logging middleware
#[derive(Clone)]
pub struct LoggingMiddleware<S> {
    inner: S,
}

impl<S> LoggingMiddleware<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, ReqBody> Service<http::Request<ReqBody>> for LoggingMiddleware<S>
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
        let method = req.method().clone();
        let uri = req.uri().clone();
        let start = Instant::now();

        let span = info_span!(
            "grpc_request",
            method = %method,
            uri = %uri,
        );

        Box::pin(
            async move {
                let response = inner.call(req).await;
                let elapsed = start.elapsed();

                match &response {
                    Ok(resp) => {
                        let status = resp.status();
                        info!(
                            status = %status,
                            duration_ms = elapsed.as_millis() as u64,
                            "Request completed"
                        );

                        // Record metrics
                        pistonprotection_common::metrics::GRPC_REQUESTS_TOTAL
                            .with_label_values(&["gateway", uri.path(), status.as_str()])
                            .inc();
                        pistonprotection_common::metrics::GRPC_REQUEST_DURATION_SECONDS
                            .with_label_values(&["gateway", uri.path()])
                            .observe(elapsed.as_secs_f64());
                    }
                    Err(_) => {
                        info!(
                            duration_ms = elapsed.as_millis() as u64,
                            "Request failed"
                        );

                        pistonprotection_common::metrics::GRPC_REQUESTS_TOTAL
                            .with_label_values(&["gateway", uri.path(), "error"])
                            .inc();
                    }
                }

                response
            }
            .instrument(span),
        )
    }
}

/// Layer for logging middleware
#[derive(Clone)]
pub struct LoggingLayer;

impl<S> Layer<S> for LoggingLayer {
    type Service = LoggingMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        LoggingMiddleware::new(service)
    }
}
