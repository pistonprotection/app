//! Logging middleware for gRPC

use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use std::task::{Context, Poll};
use std::time::Instant;

type BoxBody = UnsyncBoxBody<Bytes, tonic::Status>;
use tower::{Layer, Service};
use tracing::{Instrument, info, info_span};

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

impl<S, ReqBody, E> Service<http::Request<ReqBody>> for LoggingMiddleware<S>
where
    S: Service<http::Request<ReqBody>, Response = http::Response<BoxBody>, Error = E>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    E: Send + 'static,
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
                let fut = inner.call(req);
                let response: Result<http::Response<BoxBody>, E> = fut.await;
                let elapsed = start.elapsed();

                let is_ok = response.is_ok();
                let status_str: String = if let Ok(ref resp) = response {
                    let resp: &http::Response<BoxBody> = resp;
                    resp.status().as_str().to_string()
                } else {
                    "error".to_string()
                };

                if is_ok {
                    info!(
                        status = %status_str,
                        duration_ms = elapsed.as_millis() as u64,
                        "Request completed"
                    );
                } else {
                    info!(duration_ms = elapsed.as_millis() as u64, "Request failed");
                }

                // Record metrics
                pistonprotection_common::metrics::GRPC_REQUESTS_TOTAL
                    .with_label_values(&["gateway", uri.path(), &status_str])
                    .inc();
                pistonprotection_common::metrics::GRPC_REQUEST_DURATION_SECONDS
                    .with_label_values(&["gateway", uri.path()])
                    .observe(elapsed.as_secs_f64());

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
