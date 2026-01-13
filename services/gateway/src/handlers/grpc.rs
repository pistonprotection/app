//! gRPC service handlers

use crate::services::AppState;
use futures::StreamExt;
use pistonprotection_proto::{
    FILE_DESCRIPTOR_SET,
    backend::{
        backend_service_server::{BackendService as BackendServiceTrait, BackendServiceServer},
        *,
    },
    filter::{
        filter_service_server::{FilterService as FilterServiceTrait, FilterServiceServer},
        *,
    },
    metrics::{
        metrics_service_server::{MetricsService as MetricsServiceTrait, MetricsServiceServer},
        *,
    },
};
use std::pin::Pin;
use tokio_stream::Stream;
use tonic::{Request, Response, Status, transport::Server};
use tonic_health::server::health_reporter;
use tonic_reflection::server::Builder as ReflectionBuilder;
use tracing::{info, instrument};

/// Backend gRPC service implementation
pub struct BackendGrpcService {
    service: crate::services::backend::BackendService,
}

impl BackendGrpcService {
    pub fn new(state: AppState) -> Self {
        Self {
            service: crate::services::backend::BackendService::new(state),
        }
    }
}

#[tonic::async_trait]
impl BackendServiceTrait for BackendGrpcService {
    #[instrument(skip(self, request))]
    async fn create_backend(
        &self,
        request: Request<CreateBackendRequest>,
    ) -> Result<Response<CreateBackendResponse>, Status> {
        let req = request.into_inner();
        let backend = req
            .backend
            .ok_or_else(|| Status::invalid_argument("Backend is required"))?;

        let created = self
            .service
            .create(&req.organization_id, backend)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(CreateBackendResponse {
            backend: Some(created),
        }))
    }

    #[instrument(skip(self, request))]
    async fn get_backend(
        &self,
        request: Request<GetBackendRequest>,
    ) -> Result<Response<GetBackendResponse>, Status> {
        let req = request.into_inner();

        let backend = self
            .service
            .get(&req.backend_id)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(GetBackendResponse {
            backend: Some(backend),
        }))
    }

    #[instrument(skip(self, request))]
    async fn update_backend(
        &self,
        request: Request<UpdateBackendRequest>,
    ) -> Result<Response<UpdateBackendResponse>, Status> {
        let req = request.into_inner();
        let backend = req
            .backend
            .ok_or_else(|| Status::invalid_argument("Backend is required"))?;

        let updated = self
            .service
            .update(backend)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(UpdateBackendResponse {
            backend: Some(updated),
        }))
    }

    #[instrument(skip(self, request))]
    async fn delete_backend(
        &self,
        request: Request<DeleteBackendRequest>,
    ) -> Result<Response<DeleteBackendResponse>, Status> {
        let req = request.into_inner();

        self.service
            .delete(&req.backend_id)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(DeleteBackendResponse { success: true }))
    }

    #[instrument(skip(self, request))]
    async fn list_backends(
        &self,
        request: Request<ListBackendsRequest>,
    ) -> Result<Response<ListBackendsResponse>, Status> {
        let req = request.into_inner();
        let pagination = req.pagination.unwrap_or_default();

        let backends = self
            .service
            .list(
                &req.organization_id,
                pagination.page,
                pagination.page_size.max(1).min(100),
            )
            .await
            .map_err(Status::from)?;

        Ok(Response::new(ListBackendsResponse {
            backends,
            pagination: None,
        }))
    }

    // =========================================================================
    // Origin Management
    // =========================================================================

    #[instrument(skip(self, request))]
    async fn add_origin(
        &self,
        request: Request<AddOriginRequest>,
    ) -> Result<Response<AddOriginResponse>, Status> {
        let req = request.into_inner();
        let origin = req
            .origin
            .ok_or_else(|| Status::invalid_argument("Origin is required"))?;

        let created = self
            .service
            .add_origin(&req.backend_id, origin)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(AddOriginResponse {
            origin: Some(created),
        }))
    }

    #[instrument(skip(self, request))]
    async fn update_origin(
        &self,
        request: Request<UpdateOriginRequest>,
    ) -> Result<Response<UpdateOriginResponse>, Status> {
        let req = request.into_inner();
        let origin = req
            .origin
            .ok_or_else(|| Status::invalid_argument("Origin is required"))?;

        let updated = self
            .service
            .update_origin(&req.backend_id, origin)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(UpdateOriginResponse {
            origin: Some(updated),
        }))
    }

    #[instrument(skip(self, request))]
    async fn remove_origin(
        &self,
        request: Request<RemoveOriginRequest>,
    ) -> Result<Response<RemoveOriginResponse>, Status> {
        let req = request.into_inner();

        self.service
            .remove_origin(&req.backend_id, &req.origin_id)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(RemoveOriginResponse { success: true }))
    }

    // =========================================================================
    // Protection Settings
    // =========================================================================

    #[instrument(skip(self, request))]
    async fn update_protection(
        &self,
        request: Request<UpdateProtectionRequest>,
    ) -> Result<Response<UpdateProtectionResponse>, Status> {
        let req = request.into_inner();
        let protection = req
            .protection
            .ok_or_else(|| Status::invalid_argument("Protection settings are required"))?;

        let updated = self
            .service
            .update_protection(&req.backend_id, protection)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(UpdateProtectionResponse {
            protection: Some(updated),
        }))
    }

    #[instrument(skip(self, request))]
    async fn set_protection_level(
        &self,
        request: Request<SetProtectionLevelRequest>,
    ) -> Result<Response<SetProtectionLevelResponse>, Status> {
        let req = request.into_inner();

        let level = ProtectionLevel::try_from(req.level)
            .map_err(|_| Status::invalid_argument("Invalid protection level"))?;

        let updated_level = self
            .service
            .set_protection_level(&req.backend_id, level)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(SetProtectionLevelResponse {
            level: updated_level as i32,
        }))
    }

    // =========================================================================
    // Status and Streaming
    // =========================================================================

    #[instrument(skip(self, request))]
    async fn get_backend_status(
        &self,
        request: Request<GetBackendStatusRequest>,
    ) -> Result<Response<GetBackendStatusResponse>, Status> {
        let req = request.into_inner();

        let status = self
            .service
            .get_status(&req.backend_id)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(GetBackendStatusResponse {
            status: Some(status),
        }))
    }

    type WatchBackendStatusStream =
        Pin<Box<dyn Stream<Item = Result<BackendStatus, Status>> + Send>>;

    #[instrument(skip(self, request))]
    async fn watch_backend_status(
        &self,
        request: Request<WatchBackendStatusRequest>,
    ) -> Result<Response<Self::WatchBackendStatusStream>, Status> {
        let req = request.into_inner();
        let backend_id = req.backend_id;

        let stream = self
            .service
            .watch_status(&backend_id)
            .await
            .map_err(Status::from)?;

        // Convert Result<BackendStatus> to Result<BackendStatus, Status>
        let mapped_stream = stream.map(|result| result.map_err(Status::from));

        Ok(Response::new(Box::pin(mapped_stream)))
    }

    // =========================================================================
    // Domain Management
    // =========================================================================

    #[instrument(skip(self, request))]
    async fn add_domain(
        &self,
        request: Request<AddDomainRequest>,
    ) -> Result<Response<AddDomainResponse>, Status> {
        let req = request.into_inner();

        if req.domain.is_empty() {
            return Err(Status::invalid_argument("Domain is required"));
        }

        let (domain, verification_token, verification_method) = self
            .service
            .add_domain(&req.backend_id, &req.domain)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(AddDomainResponse {
            domain,
            verification_token,
            verification_method,
        }))
    }

    #[instrument(skip(self, request))]
    async fn remove_domain(
        &self,
        request: Request<RemoveDomainRequest>,
    ) -> Result<Response<RemoveDomainResponse>, Status> {
        let req = request.into_inner();

        self.service
            .remove_domain(&req.backend_id, &req.domain)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(RemoveDomainResponse { success: true }))
    }

    #[instrument(skip(self, request))]
    async fn verify_domain(
        &self,
        request: Request<VerifyDomainRequest>,
    ) -> Result<Response<VerifyDomainResponse>, Status> {
        let req = request.into_inner();

        let (verified, error) = self
            .service
            .verify_domain(&req.backend_id, &req.domain)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(VerifyDomainResponse { verified, error }))
    }
}

/// Filter gRPC service implementation
pub struct FilterGrpcService {
    service: crate::services::filter::FilterService,
}

impl FilterGrpcService {
    pub fn new(state: AppState) -> Self {
        Self {
            service: crate::services::filter::FilterService::new(state),
        }
    }
}

#[tonic::async_trait]
impl FilterServiceTrait for FilterGrpcService {
    #[instrument(skip(self, request))]
    async fn create_rule(
        &self,
        request: Request<CreateRuleRequest>,
    ) -> Result<Response<CreateRuleResponse>, Status> {
        let req = request.into_inner();
        let rule = req
            .rule
            .ok_or_else(|| Status::invalid_argument("Rule is required"))?;

        let created = self
            .service
            .create(&req.backend_id, rule)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(CreateRuleResponse {
            rule: Some(created),
        }))
    }

    #[instrument(skip(self, request))]
    async fn get_rule(
        &self,
        request: Request<GetRuleRequest>,
    ) -> Result<Response<GetRuleResponse>, Status> {
        let req = request.into_inner();

        let rule = self
            .service
            .get(&req.rule_id)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(GetRuleResponse { rule: Some(rule) }))
    }

    #[instrument(skip(self, request))]
    async fn update_rule(
        &self,
        request: Request<UpdateRuleRequest>,
    ) -> Result<Response<UpdateRuleResponse>, Status> {
        let req = request.into_inner();
        let rule = req
            .rule
            .ok_or_else(|| Status::invalid_argument("Rule is required"))?;

        let updated = self
            .service
            .update(rule)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(UpdateRuleResponse {
            rule: Some(updated),
        }))
    }

    #[instrument(skip(self, request))]
    async fn delete_rule(
        &self,
        request: Request<DeleteRuleRequest>,
    ) -> Result<Response<DeleteRuleResponse>, Status> {
        let req = request.into_inner();

        self.service
            .delete(&req.rule_id)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(DeleteRuleResponse { success: true }))
    }

    #[instrument(skip(self, request))]
    async fn list_rules(
        &self,
        request: Request<ListRulesRequest>,
    ) -> Result<Response<ListRulesResponse>, Status> {
        let req = request.into_inner();
        let pagination = req.pagination.unwrap_or_default();

        let rules = self
            .service
            .list(
                &req.backend_id,
                req.include_disabled,
                pagination.page,
                pagination.page_size.max(1).min(100),
            )
            .await
            .map_err(Status::from)?;

        Ok(Response::new(ListRulesResponse {
            rules,
            pagination: None,
        }))
    }

    // =========================================================================
    // Bulk Operations
    // =========================================================================

    #[instrument(skip(self, request))]
    async fn bulk_create_rules(
        &self,
        request: Request<BulkCreateRulesRequest>,
    ) -> Result<Response<BulkCreateRulesResponse>, Status> {
        let req = request.into_inner();

        if req.rules.is_empty() {
            return Err(Status::invalid_argument("At least one rule is required"));
        }

        // Limit bulk operations to prevent abuse
        if req.rules.len() > 100 {
            return Err(Status::invalid_argument(
                "Cannot create more than 100 rules at once",
            ));
        }

        let (created_rules, errors) = self
            .service
            .bulk_create(&req.backend_id, req.rules)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(BulkCreateRulesResponse {
            rules: created_rules,
            errors,
        }))
    }

    #[instrument(skip(self, request))]
    async fn bulk_delete_rules(
        &self,
        request: Request<BulkDeleteRulesRequest>,
    ) -> Result<Response<BulkDeleteRulesResponse>, Status> {
        let req = request.into_inner();

        if req.rule_ids.is_empty() {
            return Err(Status::invalid_argument("At least one rule ID is required"));
        }

        // Limit bulk operations to prevent abuse
        if req.rule_ids.len() > 100 {
            return Err(Status::invalid_argument(
                "Cannot delete more than 100 rules at once",
            ));
        }

        let (deleted_count, errors) = self
            .service
            .bulk_delete(req.rule_ids)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(BulkDeleteRulesResponse {
            deleted_count,
            errors,
        }))
    }

    #[instrument(skip(self, request))]
    async fn reorder_rules(
        &self,
        request: Request<ReorderRulesRequest>,
    ) -> Result<Response<ReorderRulesResponse>, Status> {
        let req = request.into_inner();

        self.service
            .reorder(&req.backend_id, req.rule_ids)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(ReorderRulesResponse { success: true }))
    }

    // =========================================================================
    // Statistics
    // =========================================================================

    #[instrument(skip(self, request))]
    async fn get_rule_stats(
        &self,
        request: Request<GetRuleStatsRequest>,
    ) -> Result<Response<GetRuleStatsResponse>, Status> {
        let req = request.into_inner();

        // Convert proto timestamps to chrono
        let from = req.from.map(|ts| {
            chrono::DateTime::from_timestamp(ts.seconds, ts.nanos as u32)
                .unwrap_or_else(|| chrono::Utc::now() - chrono::Duration::hours(24))
        });

        let to = req.to.map(|ts| {
            chrono::DateTime::from_timestamp(ts.seconds, ts.nanos as u32)
                .unwrap_or_else(chrono::Utc::now)
        });

        let (stats, time_series) = self
            .service
            .get_stats(&req.rule_id, from, to)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(GetRuleStatsResponse {
            stats: Some(stats),
            time_series,
        }))
    }

    // =========================================================================
    // Streaming
    // =========================================================================

    type WatchRulesStream = Pin<Box<dyn Stream<Item = Result<RuleUpdate, Status>> + Send>>;

    #[instrument(skip(self, request))]
    async fn watch_rules(
        &self,
        request: Request<WatchRulesRequest>,
    ) -> Result<Response<Self::WatchRulesStream>, Status> {
        let req = request.into_inner();
        let backend_id = req.backend_id;

        let stream = self
            .service
            .watch_rules(&backend_id)
            .await
            .map_err(Status::from)?;

        // Convert Result<RuleUpdate> to Result<RuleUpdate, Status>
        let mapped_stream = stream.map(|result| result.map_err(Status::from));

        Ok(Response::new(Box::pin(mapped_stream)))
    }
}

/// Metrics gRPC service implementation
pub struct MetricsGrpcService {
    service: crate::services::metrics::MetricsService,
}

impl MetricsGrpcService {
    pub fn new(state: AppState) -> Self {
        Self {
            service: crate::services::metrics::MetricsService::new(state),
        }
    }
}

#[tonic::async_trait]
impl MetricsServiceTrait for MetricsGrpcService {
    #[instrument(skip(self, request))]
    async fn get_traffic_metrics(
        &self,
        request: Request<GetTrafficMetricsRequest>,
    ) -> Result<Response<GetTrafficMetricsResponse>, Status> {
        let req = request.into_inner();

        let metrics = self
            .service
            .get_traffic_metrics(&req.backend_id)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(GetTrafficMetricsResponse {
            metrics: Some(metrics),
        }))
    }

    #[instrument(skip(self, request))]
    async fn get_traffic_time_series(
        &self,
        request: Request<TimeSeriesQuery>,
    ) -> Result<Response<GetTimeSeriesResponse>, Status> {
        let req = request.into_inner();

        let start_time: chrono::DateTime<chrono::Utc> = req
            .start_time
            .as_ref()
            .map(chrono::DateTime::from)
            .ok_or_else(|| Status::invalid_argument("start_time is required"))?;
        let end_time: chrono::DateTime<chrono::Utc> = req
            .end_time
            .as_ref()
            .map(chrono::DateTime::from)
            .ok_or_else(|| Status::invalid_argument("end_time is required"))?;

        let granularity = TimeGranularity::try_from(req.granularity)
            .unwrap_or(TimeGranularity::FiveMinutes);

        let mut series = Vec::new();
        for metric_name in &req.metrics {
            let ts = self
                .service
                .get_time_series(&req.backend_id, metric_name, start_time, end_time, granularity)
                .await
                .map_err(Status::from)?;
            series.push(ts);
        }

        Ok(Response::new(GetTimeSeriesResponse { series }))
    }

    type StreamTrafficMetricsStream =
        Pin<Box<dyn Stream<Item = Result<TrafficMetrics, Status>> + Send>>;

    #[instrument(skip(self, request))]
    async fn stream_traffic_metrics(
        &self,
        request: Request<StreamTrafficMetricsRequest>,
    ) -> Result<Response<Self::StreamTrafficMetricsStream>, Status> {
        let req = request.into_inner();
        let backend_id = req.backend_id;
        let interval = req.interval_seconds.max(1);
        let service = self.service.clone();

        let stream = async_stream::stream! {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval as u64));
            loop {
                ticker.tick().await;
                match service.get_traffic_metrics(&backend_id).await {
                    Ok(metrics) => yield Ok(metrics),
                    Err(e) => yield Err(Status::from(e)),
                }
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }

    #[instrument(skip(self, request))]
    async fn get_attack_metrics(
        &self,
        request: Request<GetAttackMetricsRequest>,
    ) -> Result<Response<GetAttackMetricsResponse>, Status> {
        let req = request.into_inner();

        let metrics = self
            .service
            .get_attack_metrics(&req.backend_id)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(GetAttackMetricsResponse {
            metrics: Some(metrics),
        }))
    }

    #[instrument(skip(self, request))]
    async fn get_attack_time_series(
        &self,
        request: Request<TimeSeriesQuery>,
    ) -> Result<Response<GetTimeSeriesResponse>, Status> {
        let req = request.into_inner();

        let start_time: chrono::DateTime<chrono::Utc> = req
            .start_time
            .as_ref()
            .map(chrono::DateTime::from)
            .ok_or_else(|| Status::invalid_argument("start_time is required"))?;
        let end_time: chrono::DateTime<chrono::Utc> = req
            .end_time
            .as_ref()
            .map(chrono::DateTime::from)
            .ok_or_else(|| Status::invalid_argument("end_time is required"))?;

        let granularity = TimeGranularity::try_from(req.granularity)
            .unwrap_or(TimeGranularity::FiveMinutes);

        let mut series = Vec::new();
        for metric_name in &req.metrics {
            let ts = self
                .service
                .get_time_series(&req.backend_id, metric_name, start_time, end_time, granularity)
                .await
                .map_err(Status::from)?;
            series.push(ts);
        }

        Ok(Response::new(GetTimeSeriesResponse { series }))
    }

    type StreamAttackMetricsStream =
        Pin<Box<dyn Stream<Item = Result<AttackMetrics, Status>> + Send>>;

    #[instrument(skip(self, request))]
    async fn stream_attack_metrics(
        &self,
        request: Request<StreamAttackMetricsRequest>,
    ) -> Result<Response<Self::StreamAttackMetricsStream>, Status> {
        let req = request.into_inner();
        let backend_id = req.backend_id;
        let interval = req.interval_seconds.max(1);
        let service = self.service.clone();

        let stream = async_stream::stream! {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval as u64));
            loop {
                ticker.tick().await;
                match service.get_attack_metrics(&backend_id).await {
                    Ok(metrics) => yield Ok(metrics),
                    Err(e) => yield Err(Status::from(e)),
                }
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }

    #[instrument(skip(self, request))]
    async fn get_origin_metrics(
        &self,
        request: Request<GetOriginMetricsRequest>,
    ) -> Result<Response<GetOriginMetricsResponse>, Status> {
        let req = request.into_inner();

        let metrics = self
            .service
            .get_origin_metrics(&req.backend_id, &req.origin_id)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(GetOriginMetricsResponse {
            metrics: Some(metrics),
        }))
    }

    #[instrument(skip(self, request))]
    async fn get_worker_metrics(
        &self,
        request: Request<GetWorkerMetricsRequest>,
    ) -> Result<Response<GetWorkerMetricsResponse>, Status> {
        let req = request.into_inner();

        let metrics = self
            .service
            .get_worker_metrics(&req.worker_id)
            .await
            .map_err(Status::from)?;

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
        let (page, page_size) = req
            .pagination
            .map(|p| (p.page.max(1), p.page_size.clamp(1, 100)))
            .unwrap_or((1, 20));

        let workers = self
            .service
            .list_worker_metrics(page, page_size)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(ListWorkerMetricsResponse {
            workers,
            pagination: Some(pistonprotection_proto::common::PaginationInfo {
                page,
                page_size,
                total_count: 0, // TODO: implement proper pagination
                has_next: false,
                next_cursor: String::new(),
            }),
        }))
    }

    #[instrument(skip(self, request))]
    async fn get_geo_metrics(
        &self,
        request: Request<GetGeoMetricsRequest>,
    ) -> Result<Response<GetGeoMetricsResponse>, Status> {
        let req = request.into_inner();

        let start_time: chrono::DateTime<chrono::Utc> = req
            .start_time
            .as_ref()
            .map(chrono::DateTime::from)
            .ok_or_else(|| Status::invalid_argument("start_time is required"))?;
        let end_time: chrono::DateTime<chrono::Utc> = req
            .end_time
            .as_ref()
            .map(chrono::DateTime::from)
            .ok_or_else(|| Status::invalid_argument("end_time is required"))?;

        let metrics = self
            .service
            .get_geo_metrics(&req.backend_id, start_time, end_time)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(GetGeoMetricsResponse {
            metrics: Some(metrics),
        }))
    }

    // Alert CRUD - these require a separate AlertService implementation
    async fn create_alert(
        &self,
        _request: Request<CreateAlertRequest>,
    ) -> Result<Response<CreateAlertResponse>, Status> {
        // TODO: Implement alert service
        Err(Status::unimplemented("Alert management not yet implemented"))
    }

    async fn get_alert(
        &self,
        _request: Request<GetAlertRequest>,
    ) -> Result<Response<GetAlertResponse>, Status> {
        Err(Status::unimplemented("Alert management not yet implemented"))
    }

    async fn update_alert(
        &self,
        _request: Request<UpdateAlertRequest>,
    ) -> Result<Response<UpdateAlertResponse>, Status> {
        Err(Status::unimplemented("Alert management not yet implemented"))
    }

    async fn delete_alert(
        &self,
        _request: Request<DeleteAlertRequest>,
    ) -> Result<Response<DeleteAlertResponse>, Status> {
        Err(Status::unimplemented("Alert management not yet implemented"))
    }

    async fn list_alerts(
        &self,
        _request: Request<ListAlertsRequest>,
    ) -> Result<Response<ListAlertsResponse>, Status> {
        Err(Status::unimplemented("Alert management not yet implemented"))
    }

    #[instrument(skip(self, request))]
    async fn get_attack_event(
        &self,
        request: Request<GetAttackEventRequest>,
    ) -> Result<Response<GetAttackEventResponse>, Status> {
        let req = request.into_inner();

        let event = self
            .service
            .get_attack_event(&req.event_id)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found("Attack event not found"))?;

        Ok(Response::new(GetAttackEventResponse { event: Some(event) }))
    }

    #[instrument(skip(self, request))]
    async fn list_attack_events(
        &self,
        request: Request<ListAttackEventsRequest>,
    ) -> Result<Response<ListAttackEventsResponse>, Status> {
        let req = request.into_inner();

        let start_time: chrono::DateTime<chrono::Utc> = req
            .start_time
            .as_ref()
            .map(chrono::DateTime::from)
            .ok_or_else(|| Status::invalid_argument("start_time is required"))?;
        let end_time: chrono::DateTime<chrono::Utc> = req
            .end_time
            .as_ref()
            .map(chrono::DateTime::from)
            .ok_or_else(|| Status::invalid_argument("end_time is required"))?;

        let (page, page_size) = req
            .pagination
            .map(|p| (p.page.max(1), p.page_size.clamp(1, 100)))
            .unwrap_or((1, 20));

        let events = self
            .service
            .list_attack_events(&req.backend_id, start_time, end_time, page, page_size)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(ListAttackEventsResponse {
            events,
            pagination: Some(pistonprotection_proto::common::PaginationInfo {
                page,
                page_size,
                total_count: 0, // TODO: implement proper count
                has_next: false,
                next_cursor: String::new(),
            }),
        }))
    }
}

/// Create the gRPC server
pub async fn create_server(
    state: AppState,
) -> Result<tonic::transport::server::Router, Box<dyn std::error::Error + Send + Sync>> {
    // Health service
    let (health_reporter, health_service) = health_reporter();
    health_reporter
        .set_serving::<BackendServiceServer<BackendGrpcService>>()
        .await;
    health_reporter
        .set_serving::<FilterServiceServer<FilterGrpcService>>()
        .await;
    health_reporter
        .set_serving::<MetricsServiceServer<MetricsGrpcService>>()
        .await;

    // Reflection service
    let reflection_service = ReflectionBuilder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build_v1()?;

    // Create service instances
    let backend_service = BackendGrpcService::new(state.clone());
    let filter_service = FilterGrpcService::new(state.clone());
    let metrics_service = MetricsGrpcService::new(state);

    info!("gRPC services initialized");

    Ok(Server::builder()
        .add_service(health_service)
        .add_service(reflection_service)
        .add_service(BackendServiceServer::new(backend_service))
        .add_service(FilterServiceServer::new(filter_service))
        .add_service(MetricsServiceServer::new(metrics_service)))
}
