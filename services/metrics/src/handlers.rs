//! gRPC handlers for the metrics service

use crate::{
    aggregator::MetricsAggregator, alerts::AlertManager, storage::TimeSeriesStorage,
    streams::MetricsStreamer,
};
use pistonprotection_proto::metrics::{metrics_service_server::MetricsService, *};
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tracing::{error, info, instrument};

/// Metrics gRPC service implementation
pub struct MetricsGrpcService {
    aggregator: Arc<MetricsAggregator>,
    storage: Arc<TimeSeriesStorage>,
    alerts: Arc<AlertManager>,
    streamer: Arc<MetricsStreamer>,
}

impl MetricsGrpcService {
    pub fn new(
        aggregator: Arc<MetricsAggregator>,
        storage: Arc<TimeSeriesStorage>,
        alerts: Arc<AlertManager>,
        streamer: Arc<MetricsStreamer>,
    ) -> Self {
        Self {
            aggregator,
            storage,
            alerts,
            streamer,
        }
    }
}

#[tonic::async_trait]
impl MetricsService for MetricsGrpcService {
    // =========================================================================
    // Traffic Metrics
    // =========================================================================

    #[instrument(skip(self, request), fields(backend_id))]
    async fn get_traffic_metrics(
        &self,
        request: Request<GetTrafficMetricsRequest>,
    ) -> Result<Response<GetTrafficMetricsResponse>, Status> {
        let req = request.into_inner();
        tracing::Span::current().record("backend_id", &req.backend_id);

        let metrics = self
            .aggregator
            .get_traffic_metrics(&req.backend_id)
            .await
            .map_err(|e| {
                error!("Failed to get traffic metrics: {}", e);
                Status::internal(format!("Failed to get traffic metrics: {}", e))
            })?;

        Ok(Response::new(GetTrafficMetricsResponse {
            metrics: Some(metrics),
        }))
    }

    #[instrument(skip(self, request))]
    async fn get_traffic_time_series(
        &self,
        request: Request<TimeSeriesQuery>,
    ) -> Result<Response<GetTimeSeriesResponse>, Status> {
        let query = request.into_inner();

        let series = self.storage.query_time_series(&query).await.map_err(|e| {
            error!("Failed to query traffic time series: {}", e);
            Status::internal(format!("Failed to query time series: {}", e))
        })?;

        Ok(Response::new(GetTimeSeriesResponse { series }))
    }

    type StreamTrafficMetricsStream =
        Pin<Box<dyn Stream<Item = Result<TrafficMetrics, Status>> + Send + 'static>>;

    #[instrument(skip(self, request), fields(backend_id))]
    async fn stream_traffic_metrics(
        &self,
        request: Request<StreamTrafficMetricsRequest>,
    ) -> Result<Response<Self::StreamTrafficMetricsStream>, Status> {
        let req = request.into_inner();
        tracing::Span::current().record("backend_id", &req.backend_id);

        let interval = if req.interval_seconds == 0 {
            1
        } else {
            req.interval_seconds
        };

        let stream = self
            .streamer
            .stream_traffic_metrics(req.backend_id, interval)
            .await
            .map_err(|e| {
                error!("Failed to create traffic metrics stream: {}", e);
                Status::internal(format!("Failed to create stream: {}", e))
            })?;

        Ok(Response::new(Box::pin(stream)))
    }

    // =========================================================================
    // Attack Metrics
    // =========================================================================

    #[instrument(skip(self, request), fields(backend_id))]
    async fn get_attack_metrics(
        &self,
        request: Request<GetAttackMetricsRequest>,
    ) -> Result<Response<GetAttackMetricsResponse>, Status> {
        let req = request.into_inner();
        tracing::Span::current().record("backend_id", &req.backend_id);

        let metrics = self
            .aggregator
            .get_attack_metrics(&req.backend_id)
            .await
            .map_err(|e| {
                error!("Failed to get attack metrics: {}", e);
                Status::internal(format!("Failed to get attack metrics: {}", e))
            })?;

        Ok(Response::new(GetAttackMetricsResponse {
            metrics: Some(metrics),
        }))
    }

    #[instrument(skip(self, request))]
    async fn get_attack_time_series(
        &self,
        request: Request<TimeSeriesQuery>,
    ) -> Result<Response<GetTimeSeriesResponse>, Status> {
        let query = request.into_inner();

        let series = self
            .storage
            .query_attack_time_series(&query)
            .await
            .map_err(|e| {
                error!("Failed to query attack time series: {}", e);
                Status::internal(format!("Failed to query time series: {}", e))
            })?;

        Ok(Response::new(GetTimeSeriesResponse { series }))
    }

    type StreamAttackMetricsStream =
        Pin<Box<dyn Stream<Item = Result<AttackMetrics, Status>> + Send + 'static>>;

    #[instrument(skip(self, request), fields(backend_id))]
    async fn stream_attack_metrics(
        &self,
        request: Request<StreamAttackMetricsRequest>,
    ) -> Result<Response<Self::StreamAttackMetricsStream>, Status> {
        let req = request.into_inner();
        tracing::Span::current().record("backend_id", &req.backend_id);

        let interval = if req.interval_seconds == 0 {
            1
        } else {
            req.interval_seconds
        };

        let stream = self
            .streamer
            .stream_attack_metrics(req.backend_id, interval)
            .await
            .map_err(|e| {
                error!("Failed to create attack metrics stream: {}", e);
                Status::internal(format!("Failed to create stream: {}", e))
            })?;

        Ok(Response::new(Box::pin(stream)))
    }

    // =========================================================================
    // Origin Metrics
    // =========================================================================

    #[instrument(skip(self, request), fields(backend_id, origin_id))]
    async fn get_origin_metrics(
        &self,
        request: Request<GetOriginMetricsRequest>,
    ) -> Result<Response<GetOriginMetricsResponse>, Status> {
        let req = request.into_inner();
        tracing::Span::current().record("backend_id", &req.backend_id);
        tracing::Span::current().record("origin_id", &req.origin_id);

        let metrics = self
            .aggregator
            .get_origin_metrics(&req.backend_id, &req.origin_id)
            .await
            .map_err(|e| {
                error!("Failed to get origin metrics: {}", e);
                Status::internal(format!("Failed to get origin metrics: {}", e))
            })?;

        Ok(Response::new(GetOriginMetricsResponse {
            metrics: Some(metrics),
        }))
    }

    // =========================================================================
    // Worker Metrics
    // =========================================================================

    #[instrument(skip(self, request), fields(worker_id))]
    async fn get_worker_metrics(
        &self,
        request: Request<GetWorkerMetricsRequest>,
    ) -> Result<Response<GetWorkerMetricsResponse>, Status> {
        let req = request.into_inner();
        tracing::Span::current().record("worker_id", &req.worker_id);

        let metrics = self
            .aggregator
            .get_worker_metrics(&req.worker_id)
            .await
            .map_err(|e| {
                error!("Failed to get worker metrics: {}", e);
                Status::internal(format!("Failed to get worker metrics: {}", e))
            })?;

        Ok(Response::new(GetWorkerMetricsResponse {
            metrics: Some(metrics),
        }))
    }

    #[instrument(skip(self, request))]
    async fn list_worker_metrics(
        &self,
        request: Request<ListWorkerMetricsRequest>,
    ) -> Result<Response<ListWorkerMetricsResponse>, Status> {
        let req = request.into_inner();
        let pagination = req.pagination;

        let (workers, pagination_info) = self
            .aggregator
            .list_worker_metrics(pagination)
            .await
            .map_err(|e| {
                error!("Failed to list worker metrics: {}", e);
                Status::internal(format!("Failed to list worker metrics: {}", e))
            })?;

        Ok(Response::new(ListWorkerMetricsResponse {
            workers,
            pagination: Some(pagination_info),
        }))
    }

    // =========================================================================
    // Geo Metrics
    // =========================================================================

    #[instrument(skip(self, request), fields(backend_id))]
    async fn get_geo_metrics(
        &self,
        request: Request<GetGeoMetricsRequest>,
    ) -> Result<Response<GetGeoMetricsResponse>, Status> {
        let req = request.into_inner();
        tracing::Span::current().record("backend_id", &req.backend_id);

        let metrics = self
            .aggregator
            .get_geo_metrics(&req.backend_id, req.start_time, req.end_time)
            .await
            .map_err(|e| {
                error!("Failed to get geo metrics: {}", e);
                Status::internal(format!("Failed to get geo metrics: {}", e))
            })?;

        Ok(Response::new(GetGeoMetricsResponse {
            metrics: Some(metrics),
        }))
    }

    // =========================================================================
    // Alert Management
    // =========================================================================

    #[instrument(skip(self, request), fields(backend_id))]
    async fn create_alert(
        &self,
        request: Request<CreateAlertRequest>,
    ) -> Result<Response<CreateAlertResponse>, Status> {
        let req = request.into_inner();
        tracing::Span::current().record("backend_id", &req.backend_id);

        let alert = req
            .alert
            .ok_or_else(|| Status::invalid_argument("Alert is required"))?;

        let created_alert = self
            .alerts
            .create_alert(&req.backend_id, alert)
            .await
            .map_err(|e| {
                error!("Failed to create alert: {}", e);
                Status::internal(format!("Failed to create alert: {}", e))
            })?;

        info!(alert_id = %created_alert.id, "Alert created");

        Ok(Response::new(CreateAlertResponse {
            alert: Some(created_alert),
        }))
    }

    #[instrument(skip(self, request), fields(alert_id))]
    async fn get_alert(
        &self,
        request: Request<GetAlertRequest>,
    ) -> Result<Response<GetAlertResponse>, Status> {
        let req = request.into_inner();
        tracing::Span::current().record("alert_id", &req.alert_id);

        let alert = self.alerts.get_alert(&req.alert_id).await.map_err(|e| {
            error!("Failed to get alert: {}", e);
            match e {
                crate::alerts::AlertError::NotFound(_) => {
                    Status::not_found(format!("Alert not found: {}", req.alert_id))
                }
                _ => Status::internal(format!("Failed to get alert: {}", e)),
            }
        })?;

        Ok(Response::new(GetAlertResponse { alert: Some(alert) }))
    }

    #[instrument(skip(self, request), fields(alert_id))]
    async fn update_alert(
        &self,
        request: Request<UpdateAlertRequest>,
    ) -> Result<Response<UpdateAlertResponse>, Status> {
        let req = request.into_inner();
        let alert = req
            .alert
            .ok_or_else(|| Status::invalid_argument("Alert is required"))?;

        tracing::Span::current().record("alert_id", &alert.id);

        let updated_alert = self.alerts.update_alert(alert).await.map_err(|e| {
            error!("Failed to update alert: {}", e);
            match e {
                crate::alerts::AlertError::NotFound(_) => Status::not_found("Alert not found"),
                _ => Status::internal(format!("Failed to update alert: {}", e)),
            }
        })?;

        info!(alert_id = %updated_alert.id, "Alert updated");

        Ok(Response::new(UpdateAlertResponse {
            alert: Some(updated_alert),
        }))
    }

    #[instrument(skip(self, request), fields(alert_id))]
    async fn delete_alert(
        &self,
        request: Request<DeleteAlertRequest>,
    ) -> Result<Response<DeleteAlertResponse>, Status> {
        let req = request.into_inner();
        tracing::Span::current().record("alert_id", &req.alert_id);

        self.alerts.delete_alert(&req.alert_id).await.map_err(|e| {
            error!("Failed to delete alert: {}", e);
            Status::internal(format!("Failed to delete alert: {}", e))
        })?;

        info!(alert_id = %req.alert_id, "Alert deleted");

        Ok(Response::new(DeleteAlertResponse { success: true }))
    }

    #[instrument(skip(self, request), fields(backend_id))]
    async fn list_alerts(
        &self,
        request: Request<ListAlertsRequest>,
    ) -> Result<Response<ListAlertsResponse>, Status> {
        let req = request.into_inner();
        tracing::Span::current().record("backend_id", &req.backend_id);

        let (alerts, pagination_info) = self
            .alerts
            .list_alerts(&req.backend_id, req.pagination)
            .await
            .map_err(|e| {
                error!("Failed to list alerts: {}", e);
                Status::internal(format!("Failed to list alerts: {}", e))
            })?;

        Ok(Response::new(ListAlertsResponse {
            alerts,
            pagination: Some(pagination_info),
        }))
    }

    // =========================================================================
    // Attack Events
    // =========================================================================

    #[instrument(skip(self, request), fields(event_id))]
    async fn get_attack_event(
        &self,
        request: Request<GetAttackEventRequest>,
    ) -> Result<Response<GetAttackEventResponse>, Status> {
        let req = request.into_inner();
        tracing::Span::current().record("event_id", &req.event_id);

        let event = self
            .storage
            .get_attack_event(&req.event_id)
            .await
            .map_err(|e| {
                error!("Failed to get attack event: {}", e);
                Status::internal(format!("Failed to get attack event: {}", e))
            })?;

        Ok(Response::new(GetAttackEventResponse { event: Some(event) }))
    }

    #[instrument(skip(self, request), fields(backend_id))]
    async fn list_attack_events(
        &self,
        request: Request<ListAttackEventsRequest>,
    ) -> Result<Response<ListAttackEventsResponse>, Status> {
        let req = request.into_inner();
        tracing::Span::current().record("backend_id", &req.backend_id);

        let (events, pagination_info) = self
            .storage
            .list_attack_events(
                &req.backend_id,
                req.start_time,
                req.end_time,
                req.pagination,
            )
            .await
            .map_err(|e| {
                error!("Failed to list attack events: {}", e);
                Status::internal(format!("Failed to list attack events: {}", e))
            })?;

        Ok(Response::new(ListAttackEventsResponse {
            events,
            pagination: Some(pagination_info),
        }))
    }
}
