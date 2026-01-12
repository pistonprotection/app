//! gRPC service handlers

use crate::services::AppState;
use pistonprotection_proto::{
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
    FILE_DESCRIPTOR_SET,
};
use std::pin::Pin;
use tokio_stream::Stream;
use tonic::{transport::Server, Request, Response, Status};
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
        let backend = req.backend.ok_or_else(|| Status::invalid_argument("Backend is required"))?;

        let created = self
            .service
            .create(&req.organization_id, backend)
            .await
            .map_err(|e| Status::from(e))?;

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
            .map_err(|e| Status::from(e))?;

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
        let backend = req.backend.ok_or_else(|| Status::invalid_argument("Backend is required"))?;

        let updated = self
            .service
            .update(backend)
            .await
            .map_err(|e| Status::from(e))?;

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
            .map_err(|e| Status::from(e))?;

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
            .map_err(|e| Status::from(e))?;

        Ok(Response::new(ListBackendsResponse {
            backends,
            pagination: None,
        }))
    }

    async fn add_origin(
        &self,
        _request: Request<AddOriginRequest>,
    ) -> Result<Response<AddOriginResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }

    async fn update_origin(
        &self,
        _request: Request<UpdateOriginRequest>,
    ) -> Result<Response<UpdateOriginResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }

    async fn remove_origin(
        &self,
        _request: Request<RemoveOriginRequest>,
    ) -> Result<Response<RemoveOriginResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }

    async fn update_protection(
        &self,
        _request: Request<UpdateProtectionRequest>,
    ) -> Result<Response<UpdateProtectionResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }

    async fn set_protection_level(
        &self,
        _request: Request<SetProtectionLevelRequest>,
    ) -> Result<Response<SetProtectionLevelResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }

    async fn get_backend_status(
        &self,
        _request: Request<GetBackendStatusRequest>,
    ) -> Result<Response<GetBackendStatusResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }

    type WatchBackendStatusStream =
        Pin<Box<dyn Stream<Item = Result<BackendStatus, Status>> + Send>>;

    async fn watch_backend_status(
        &self,
        _request: Request<WatchBackendStatusRequest>,
    ) -> Result<Response<Self::WatchBackendStatusStream>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }

    async fn add_domain(
        &self,
        _request: Request<AddDomainRequest>,
    ) -> Result<Response<AddDomainResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }

    async fn remove_domain(
        &self,
        _request: Request<RemoveDomainRequest>,
    ) -> Result<Response<RemoveDomainResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }

    async fn verify_domain(
        &self,
        _request: Request<VerifyDomainRequest>,
    ) -> Result<Response<VerifyDomainResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
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
        let rule = req.rule.ok_or_else(|| Status::invalid_argument("Rule is required"))?;

        let created = self
            .service
            .create(&req.backend_id, rule)
            .await
            .map_err(|e| Status::from(e))?;

        Ok(Response::new(CreateRuleResponse { rule: Some(created) }))
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
            .map_err(|e| Status::from(e))?;

        Ok(Response::new(GetRuleResponse { rule: Some(rule) }))
    }

    #[instrument(skip(self, request))]
    async fn update_rule(
        &self,
        request: Request<UpdateRuleRequest>,
    ) -> Result<Response<UpdateRuleResponse>, Status> {
        let req = request.into_inner();
        let rule = req.rule.ok_or_else(|| Status::invalid_argument("Rule is required"))?;

        let updated = self
            .service
            .update(rule)
            .await
            .map_err(|e| Status::from(e))?;

        Ok(Response::new(UpdateRuleResponse { rule: Some(updated) }))
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
            .map_err(|e| Status::from(e))?;

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
            .map_err(|e| Status::from(e))?;

        Ok(Response::new(ListRulesResponse {
            rules,
            pagination: None,
        }))
    }

    async fn bulk_create_rules(
        &self,
        _request: Request<BulkCreateRulesRequest>,
    ) -> Result<Response<BulkCreateRulesResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }

    async fn bulk_delete_rules(
        &self,
        _request: Request<BulkDeleteRulesRequest>,
    ) -> Result<Response<BulkDeleteRulesResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
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
            .map_err(|e| Status::from(e))?;

        Ok(Response::new(ReorderRulesResponse { success: true }))
    }

    async fn get_rule_stats(
        &self,
        _request: Request<GetRuleStatsRequest>,
    ) -> Result<Response<GetRuleStatsResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }

    type WatchRulesStream = Pin<Box<dyn Stream<Item = Result<RuleUpdate, Status>> + Send>>;

    async fn watch_rules(
        &self,
        _request: Request<WatchRulesRequest>,
    ) -> Result<Response<Self::WatchRulesStream>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
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
            .map_err(|e| Status::from(e))?;

        Ok(Response::new(GetTrafficMetricsResponse {
            metrics: Some(metrics),
        }))
    }

    async fn get_traffic_time_series(
        &self,
        _request: Request<TimeSeriesQuery>,
    ) -> Result<Response<GetTimeSeriesResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }

    type StreamTrafficMetricsStream =
        Pin<Box<dyn Stream<Item = Result<TrafficMetrics, Status>> + Send>>;

    async fn stream_traffic_metrics(
        &self,
        _request: Request<StreamTrafficMetricsRequest>,
    ) -> Result<Response<Self::StreamTrafficMetricsStream>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
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
            .map_err(|e| Status::from(e))?;

        Ok(Response::new(GetAttackMetricsResponse {
            metrics: Some(metrics),
        }))
    }

    async fn get_attack_time_series(
        &self,
        _request: Request<TimeSeriesQuery>,
    ) -> Result<Response<GetTimeSeriesResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }

    type StreamAttackMetricsStream =
        Pin<Box<dyn Stream<Item = Result<AttackMetrics, Status>> + Send>>;

    async fn stream_attack_metrics(
        &self,
        _request: Request<StreamAttackMetricsRequest>,
    ) -> Result<Response<Self::StreamAttackMetricsStream>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }

    async fn get_origin_metrics(
        &self,
        _request: Request<GetOriginMetricsRequest>,
    ) -> Result<Response<GetOriginMetricsResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }

    async fn get_worker_metrics(
        &self,
        _request: Request<GetWorkerMetricsRequest>,
    ) -> Result<Response<GetWorkerMetricsResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }

    async fn list_worker_metrics(
        &self,
        _request: Request<ListWorkerMetricsRequest>,
    ) -> Result<Response<ListWorkerMetricsResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }

    async fn get_geo_metrics(
        &self,
        _request: Request<GetGeoMetricsRequest>,
    ) -> Result<Response<GetGeoMetricsResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }

    async fn create_alert(
        &self,
        _request: Request<CreateAlertRequest>,
    ) -> Result<Response<CreateAlertResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }

    async fn get_alert(
        &self,
        _request: Request<GetAlertRequest>,
    ) -> Result<Response<GetAlertResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }

    async fn update_alert(
        &self,
        _request: Request<UpdateAlertRequest>,
    ) -> Result<Response<UpdateAlertResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }

    async fn delete_alert(
        &self,
        _request: Request<DeleteAlertRequest>,
    ) -> Result<Response<DeleteAlertResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }

    async fn list_alerts(
        &self,
        _request: Request<ListAlertsRequest>,
    ) -> Result<Response<ListAlertsResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }

    async fn get_attack_event(
        &self,
        _request: Request<GetAttackEventRequest>,
    ) -> Result<Response<GetAttackEventResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }

    async fn list_attack_events(
        &self,
        _request: Request<ListAttackEventsRequest>,
    ) -> Result<Response<ListAttackEventsResponse>, Status> {
        Err(Status::unimplemented("Not implemented yet"))
    }
}

/// Create the gRPC server
pub async fn create_server(
    state: AppState,
) -> Result<tonic::transport::server::Router, Box<dyn std::error::Error>> {
    // Health service
    let (mut health_reporter, health_service) = health_reporter();
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
