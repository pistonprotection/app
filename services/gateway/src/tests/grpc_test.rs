//! Integration tests for gRPC services

use super::test_utils::{assert_grpc_status_code, constants, create_test_app_state, create_test_request};
use pistonprotection_proto::backend::*;
use pistonprotection_proto::filter::*;
use pistonprotection_proto::metrics::*;
use tonic::Code;

// ============================================================================
// Backend Service Tests
// ============================================================================

#[cfg(test)]
mod backend_service_tests {
    use super::*;
    use pistonprotection_proto::backend::backend_service_server::BackendService;

    /// Test creating a backend with valid data
    #[tokio::test]
    async fn test_create_backend_success() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::BackendGrpcService::new(state);

        let backend = Backend {
            name: "Test Backend".to_string(),
            description: "A test backend".to_string(),
            r#type: 1, // TCP
            ..Default::default()
        };

        let request = create_test_request(CreateBackendRequest {
            organization_id: constants::TEST_ORG_ID.to_string(),
            backend: Some(backend),
        });

        // Without a real database, this will fail with unavailable error
        // but we can verify the request validation works
        let result = service.create_backend(request).await;

        // In a real test with mock DB, we'd expect Ok
        // For now, we verify the error is from DB, not validation
        if let Err(status) = result {
            // DB not configured should return unavailable error
            assert!(
                status.code() == Code::Unavailable || status.code() == Code::Internal,
                "Unexpected error code: {:?}",
                status.code()
            );
        }
    }

    /// Test creating a backend without required backend field
    #[tokio::test]
    async fn test_create_backend_missing_backend() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::BackendGrpcService::new(state);

        let request = create_test_request(CreateBackendRequest {
            organization_id: constants::TEST_ORG_ID.to_string(),
            backend: None,
        });

        let result = service.create_backend(request).await;

        assert!(result.is_err());
        let status = result.err().unwrap();
        assert_grpc_status_code(&status, Code::InvalidArgument);
        assert!(status.message().contains("Backend is required"));
    }

    /// Test getting a backend that doesn't exist
    #[tokio::test]
    async fn test_get_backend_not_found() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::BackendGrpcService::new(state);

        let request = create_test_request(GetBackendRequest {
            backend_id: "nonexistent-id".to_string(),
        });

        let result = service.get_backend(request).await;

        assert!(result.is_err());
        // Should return Unavailable (DB not configured)
        let status = result.err().unwrap();
        assert!(
            status.code() == Code::Unavailable || status.code() == Code::NotFound,
            "Expected Unavailable or NotFound, got: {:?}",
            status.code()
        );
    }

    /// Test updating a backend without required backend field
    #[tokio::test]
    async fn test_update_backend_missing_backend() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::BackendGrpcService::new(state);

        let request = create_test_request(UpdateBackendRequest { backend: None });

        let result = service.update_backend(request).await;

        assert!(result.is_err());
        let status = result.err().unwrap();
        assert_grpc_status_code(&status, Code::InvalidArgument);
    }

    /// Test deleting a backend
    #[tokio::test]
    async fn test_delete_backend() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::BackendGrpcService::new(state);

        let request = create_test_request(DeleteBackendRequest {
            backend_id: "test-backend-id".to_string(),
        });

        let result = service.delete_backend(request).await;

        // Will fail without DB, but validates request handling
        assert!(result.is_err());
        let status = result.err().unwrap();
        assert!(status.code() == Code::Unavailable || status.code() == Code::NotFound);
    }

    /// Test listing backends with pagination
    #[tokio::test]
    async fn test_list_backends_pagination() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::BackendGrpcService::new(state);

        let request = create_test_request(ListBackendsRequest {
            organization_id: constants::TEST_ORG_ID.to_string(),
            type_filter: 0,
            pagination: Some(pistonprotection_proto::common::Pagination {
                page: 1,
                page_size: 10,
                cursor: String::new(),
            }),
        });

        let result = service.list_backends(request).await;

        // Will fail without DB, but validates request handling
        if let Err(status) = result {
            assert!(status.code() == Code::Unavailable);
        }
    }

    /// Test listing backends bounds page_size
    #[tokio::test]
    async fn test_list_backends_page_size_bounds() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::BackendGrpcService::new(state);

        // Test page_size = 0 (should be bounded to 1)
        let request = create_test_request(ListBackendsRequest {
            organization_id: constants::TEST_ORG_ID.to_string(),
            type_filter: 0,
            pagination: Some(pistonprotection_proto::common::Pagination {
                page: 1,
                page_size: 0,
                cursor: String::new(),
            }),
        });

        let result = service.list_backends(request).await;

        // Request should be valid (page_size bounded), DB error expected
        if let Err(status) = result {
            assert!(
                status.code() == Code::Unavailable,
                "Unexpected error: {:?}",
                status
            );
        }

        // Test page_size > 100 (should be bounded to 100)
        let request = create_test_request(ListBackendsRequest {
            organization_id: constants::TEST_ORG_ID.to_string(),
            type_filter: 0,
            pagination: Some(pistonprotection_proto::common::Pagination {
                page: 1,
                page_size: 500,
                cursor: String::new(),
            }),
        });

        let result = service.list_backends(request).await;

        if let Err(status) = result {
            assert!(
                status.code() == Code::Unavailable,
                "Unexpected error: {:?}",
                status
            );
        }
    }

    /// Test adding origin without required field
    #[tokio::test]
    async fn test_add_origin_missing_origin() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::BackendGrpcService::new(state);

        let request = create_test_request(AddOriginRequest {
            backend_id: "test".to_string(),
            origin: None,
        });

        let result = service.add_origin(request).await;

        assert!(result.is_err());
        let status = result.err().unwrap();
        assert_grpc_status_code(&status, Code::InvalidArgument);
    }

    /// Test updating origin without required field
    #[tokio::test]
    async fn test_update_origin_missing_origin() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::BackendGrpcService::new(state);

        let request = create_test_request(UpdateOriginRequest {
            backend_id: String::new(),
            origin: None,
        });

        let result = service.update_origin(request).await;

        assert!(result.is_err());
        let status = result.err().unwrap();
        assert_grpc_status_code(&status, Code::InvalidArgument);
    }
}

// ============================================================================
// Filter Service Tests
// ============================================================================

#[cfg(test)]
mod filter_service_tests {
    use super::*;
    use pistonprotection_proto::filter::filter_service_server::FilterService;

    /// Test creating a filter rule with valid data
    #[tokio::test]
    async fn test_create_rule_success() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::FilterGrpcService::new(state);

        let rule = FilterRule {
            name: "Block Bad IPs".to_string(),
            description: "Block known malicious IPs".to_string(),
            enabled: true,
            priority: 100,
            ..Default::default()
        };

        let request = create_test_request(CreateRuleRequest {
            backend_id: constants::TEST_BACKEND_ID.to_string(),
            rule: Some(rule),
        });

        let result = service.create_rule(request).await;

        // Without DB, will fail but validates request handling
        if let Err(status) = result {
            assert!(status.code() == Code::Unavailable);
        }
    }

    /// Test creating a rule without required rule field
    #[tokio::test]
    async fn test_create_rule_missing_rule() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::FilterGrpcService::new(state);

        let request = create_test_request(CreateRuleRequest {
            backend_id: constants::TEST_BACKEND_ID.to_string(),
            rule: None,
        });

        let result = service.create_rule(request).await;

        assert!(result.is_err());
        let status = result.err().unwrap();
        assert_grpc_status_code(&status, Code::InvalidArgument);
        assert!(status.message().contains("Rule is required"));
    }

    /// Test getting a rule
    #[tokio::test]
    async fn test_get_rule() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::FilterGrpcService::new(state);

        let request = create_test_request(GetRuleRequest {
            rule_id: "test-rule-id".to_string(),
        });

        let result = service.get_rule(request).await;

        // Will fail without DB
        assert!(result.is_err());
        let status = result.err().unwrap();
        assert!(status.code() == Code::Unavailable || status.code() == Code::NotFound);
    }

    /// Test updating a rule without required rule field
    #[tokio::test]
    async fn test_update_rule_missing_rule() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::FilterGrpcService::new(state);

        let request = create_test_request(UpdateRuleRequest { rule: None });

        let result = service.update_rule(request).await;

        assert!(result.is_err());
        let status = result.err().unwrap();
        assert_grpc_status_code(&status, Code::InvalidArgument);
    }

    /// Test deleting a rule
    #[tokio::test]
    async fn test_delete_rule() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::FilterGrpcService::new(state);

        let request = create_test_request(DeleteRuleRequest {
            rule_id: "test-rule-id".to_string(),
        });

        let result = service.delete_rule(request).await;

        // Will fail without DB
        assert!(result.is_err());
    }

    /// Test listing rules with include_disabled flag
    #[tokio::test]
    async fn test_list_rules_include_disabled() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::FilterGrpcService::new(state);

        let request = create_test_request(ListRulesRequest {
            backend_id: constants::TEST_BACKEND_ID.to_string(),
            include_disabled: true,
            pagination: None,
        });

        let result = service.list_rules(request).await;

        // Will fail without DB
        if let Err(status) = result {
            assert!(status.code() == Code::Unavailable);
        }
    }

    /// Test reordering rules
    #[tokio::test]
    async fn test_reorder_rules() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::FilterGrpcService::new(state);

        let request = create_test_request(ReorderRulesRequest {
            backend_id: constants::TEST_BACKEND_ID.to_string(),
            rule_ids: vec![
                "rule1".to_string(),
                "rule2".to_string(),
                "rule3".to_string(),
            ],
        });

        let result = service.reorder_rules(request).await;

        // Will fail without DB
        if let Err(status) = result {
            assert!(status.code() == Code::Unavailable);
        }
    }

    /// Test bulk create with empty rules list
    #[tokio::test]
    async fn test_bulk_create_empty_rules() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::FilterGrpcService::new(state);

        let request = create_test_request(BulkCreateRulesRequest {
            backend_id: "test".to_string(),
            rules: vec![],
        });

        let result = service.bulk_create_rules(request).await;

        assert!(result.is_err());
        assert_grpc_status_code(&result.err().unwrap(), Code::InvalidArgument);
    }

    /// Test bulk create with too many rules
    #[tokio::test]
    async fn test_bulk_create_too_many_rules() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::FilterGrpcService::new(state);

        // Create 101 rules (over limit)
        let rules: Vec<FilterRule> = (0..101)
            .map(|i| FilterRule {
                name: format!("Rule {}", i),
                ..Default::default()
            })
            .collect();

        let request = create_test_request(BulkCreateRulesRequest {
            backend_id: "test".to_string(),
            rules,
        });

        let result = service.bulk_create_rules(request).await;

        assert!(result.is_err());
        assert_grpc_status_code(&result.err().unwrap(), Code::InvalidArgument);
    }

    /// Test bulk delete with empty rule IDs
    #[tokio::test]
    async fn test_bulk_delete_empty_ids() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::FilterGrpcService::new(state);

        let request = create_test_request(BulkDeleteRulesRequest { rule_ids: vec![] });

        let result = service.bulk_delete_rules(request).await;

        assert!(result.is_err());
        assert_grpc_status_code(&result.err().unwrap(), Code::InvalidArgument);
    }
}

// ============================================================================
// Metrics Service Tests
// ============================================================================

#[cfg(test)]
mod metrics_service_tests {
    use super::*;
    use pistonprotection_proto::metrics::metrics_service_server::MetricsService;

    /// Test getting traffic metrics
    #[tokio::test]
    async fn test_get_traffic_metrics() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::MetricsGrpcService::new(state);

        let request = create_test_request(GetTrafficMetricsRequest {
            backend_id: constants::TEST_BACKEND_ID.to_string(),
        });

        let result = service.get_traffic_metrics(request).await;

        // Should succeed (returns default metrics when cache is not configured)
        assert!(result.is_ok());
    }

    /// Test getting attack metrics
    #[tokio::test]
    async fn test_get_attack_metrics() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::MetricsGrpcService::new(state);

        let request = create_test_request(GetAttackMetricsRequest {
            backend_id: constants::TEST_BACKEND_ID.to_string(),
        });

        let result = service.get_attack_metrics(request).await;

        // Should succeed (returns default metrics when cache is not configured)
        assert!(result.is_ok());
    }

    /// Test getting time series without required timestamps
    #[tokio::test]
    async fn test_get_time_series_missing_times() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::MetricsGrpcService::new(state);

        let request = create_test_request(TimeSeriesQuery {
            backend_id: "test".to_string(),
            start_time: None,
            end_time: None,
            ..Default::default()
        });

        let result = service.get_traffic_time_series(request).await;

        assert!(result.is_err());
        assert_grpc_status_code(&result.err().unwrap(), Code::InvalidArgument);
    }

    /// Test getting geo metrics without required timestamps
    #[tokio::test]
    async fn test_get_geo_metrics_missing_times() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::MetricsGrpcService::new(state);

        let request = create_test_request(GetGeoMetricsRequest {
            backend_id: "test".to_string(),
            start_time: None,
            end_time: None,
        });

        let result = service.get_geo_metrics(request).await;

        assert!(result.is_err());
        assert_grpc_status_code(&result.err().unwrap(), Code::InvalidArgument);
    }

    /// Test alert creation without required field
    #[tokio::test]
    async fn test_create_alert_missing_alert() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::MetricsGrpcService::new(state);

        let request = create_test_request(CreateAlertRequest {
            backend_id: "test".to_string(),
            alert: None,
        });

        let result = service.create_alert(request).await;

        assert!(result.is_err());
        assert_grpc_status_code(&result.err().unwrap(), Code::InvalidArgument);
    }

    /// Test get alert
    #[tokio::test]
    async fn test_get_alert() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::MetricsGrpcService::new(state);

        let request = create_test_request(GetAlertRequest {
            alert_id: "test".to_string(),
        });

        let result = service.get_alert(request).await;

        // Will fail without DB
        assert!(result.is_err());
        let status = result.err().unwrap();
        assert!(status.code() == Code::Unavailable || status.code() == Code::NotFound);
    }

    /// Test list alerts
    #[tokio::test]
    async fn test_list_alerts() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::MetricsGrpcService::new(state);

        let request = create_test_request(ListAlertsRequest {
            backend_id: "test".to_string(),
            pagination: None,
        });

        let result = service.list_alerts(request).await;

        // Will fail without DB
        assert!(result.is_err());
        let status = result.err().unwrap();
        assert!(status.code() == Code::Unavailable);
    }

    /// Test list attack events without required timestamps
    #[tokio::test]
    async fn test_list_attack_events_missing_times() {
        let state = create_test_app_state();
        let service = crate::handlers::grpc::MetricsGrpcService::new(state);

        let request = create_test_request(ListAttackEventsRequest {
            backend_id: "test".to_string(),
            start_time: None,
            end_time: None,
            pagination: None,
        });

        let result = service.list_attack_events(request).await;

        assert!(result.is_err());
        assert_grpc_status_code(&result.err().unwrap(), Code::InvalidArgument);
    }
}

// ============================================================================
// gRPC Server Creation Tests
// ============================================================================

#[cfg(test)]
mod grpc_server_tests {
    use super::*;

    /// Test gRPC server creation succeeds
    #[tokio::test]
    async fn test_create_grpc_server() {
        let state = create_test_app_state();
        let result = crate::handlers::grpc::create_server(state).await;

        assert!(
            result.is_ok(),
            "Failed to create gRPC server: {:?}",
            result.err()
        );
    }
}
