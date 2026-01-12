//! gRPC handlers implementing the AuthService

use pistonprotection_proto::auth::{
    auth_service_server::{AuthService as ProtoAuthService, AuthServiceServer},
    *,
};
use pistonprotection_proto::{PaginationInfo, Timestamp};
use tonic::{Request, Response, Status};
use tracing::{error, info};

use crate::models::{
    AuditLogFilter, CreateApiKeyRequest as ModelCreateApiKeyRequest,
    CreateInvitationRequest as ModelCreateInvitationRequest, InvitationStatus,
    InvitationTokenGenerator, OrganizationRole,
};
use crate::services::AppState;

/// gRPC service implementation
pub struct AuthServiceImpl {
    state: AppState,
}

impl AuthServiceImpl {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl ProtoAuthService for AuthServiceImpl {
    // =========================================================================
    // User Operations
    // =========================================================================

    async fn get_user(
        &self,
        request: Request<GetUserRequest>,
    ) -> Result<Response<GetUserResponse>, Status> {
        let req = request.into_inner();

        let user = self
            .state
            .user_service()
            .get_user_internal(&req.user_id)
            .await
            .map_err(|e| Status::from(e))?
            .ok_or_else(|| Status::not_found("User not found"))?;

        Ok(Response::new(GetUserResponse {
            user: Some(user.to_proto()),
        }))
    }

    async fn get_user_by_email(
        &self,
        request: Request<GetUserByEmailRequest>,
    ) -> Result<Response<GetUserResponse>, Status> {
        let req = request.into_inner();

        let user_service = self.state.user_service();
        let user = user_service
            .get_user_by_email(&req.email)
            .await
            .map_err(|e| Status::from(e))?
            .ok_or_else(|| Status::not_found("User not found"))?;

        // Get internal user for proto conversion
        let internal_user = user_service
            .get_user_internal(&user.id)
            .await
            .map_err(|e| Status::from(e))?
            .ok_or_else(|| Status::not_found("User not found"))?;

        Ok(Response::new(GetUserResponse {
            user: Some(internal_user.to_proto()),
        }))
    }

    // =========================================================================
    // Organization Operations
    // =========================================================================

    async fn get_organization(
        &self,
        request: Request<GetOrganizationRequest>,
    ) -> Result<Response<GetOrganizationResponse>, Status> {
        let req = request.into_inner();

        let org_service = self.state.organization_service();

        let org = org_service
            .get_organization(&req.organization_id)
            .await
            .map_err(|e| Status::from(e))?
            .ok_or_else(|| Status::not_found("Organization not found"))?;

        let subscription = org_service
            .get_subscription(&req.organization_id)
            .await
            .map_err(|e| Status::from(e))?;

        let limits = org_service
            .get_limits(&req.organization_id)
            .await
            .map_err(|e| Status::from(e))?;

        let usage = org_service
            .get_usage(&req.organization_id)
            .await
            .map_err(|e| Status::from(e))?;

        Ok(Response::new(GetOrganizationResponse {
            organization: Some(org.to_proto(
                subscription.as_ref(),
                limits.as_ref(),
                usage.as_ref(),
            )),
        }))
    }

    async fn list_user_organizations(
        &self,
        request: Request<ListUserOrganizationsRequest>,
    ) -> Result<Response<ListUserOrganizationsResponse>, Status> {
        let req = request.into_inner();

        let orgs = self
            .state
            .organization_service()
            .list_user_organizations(&req.user_id)
            .await
            .map_err(|e| Status::from(e))?;

        Ok(Response::new(ListUserOrganizationsResponse {
            organizations: orgs
                .into_iter()
                .map(|o| o.to_proto(None, None, None))
                .collect(),
        }))
    }

    async fn get_organization_member(
        &self,
        request: Request<GetOrganizationMemberRequest>,
    ) -> Result<Response<GetOrganizationMemberResponse>, Status> {
        let req = request.into_inner();

        let member = self
            .state
            .organization_service()
            .get_member(&req.organization_id, &req.user_id)
            .await
            .map_err(|e| Status::from(e))?
            .ok_or_else(|| Status::not_found("Member not found"))?;

        // Get user details
        let user = self
            .state
            .user_service()
            .get_user_internal(&req.user_id)
            .await
            .map_err(|e| Status::from(e))?;

        Ok(Response::new(GetOrganizationMemberResponse {
            member: Some(member.to_proto(user.as_ref())),
        }))
    }

    async fn list_organization_members(
        &self,
        request: Request<ListOrganizationMembersRequest>,
    ) -> Result<Response<ListOrganizationMembersResponse>, Status> {
        let req = request.into_inner();

        let pagination = req.pagination.unwrap_or_default();
        let page = pagination.page.max(1);
        let page_size = pagination.page_size.clamp(1, 100);

        let (members, total) = self
            .state
            .organization_service()
            .list_members(&req.organization_id, page, page_size)
            .await
            .map_err(|e| Status::from(e))?;

        // Get user details for each member
        let user_service = self.state.user_service();
        let mut proto_members = Vec::with_capacity(members.len());

        for member in members {
            let user = user_service
                .get_user_internal(&member.user_id)
                .await
                .map_err(|e| Status::from(e))?;
            proto_members.push(member.to_proto(user.as_ref()));
        }

        Ok(Response::new(ListOrganizationMembersResponse {
            members: proto_members,
            pagination: Some(PaginationInfo {
                total_count: total,
                page,
                page_size,
                has_next: (page * page_size) < total,
                next_cursor: String::new(),
            }),
        }))
    }

    // =========================================================================
    // Authorization
    // =========================================================================

    async fn check_permission(
        &self,
        request: Request<CheckPermissionRequest>,
    ) -> Result<Response<CheckPermissionResponse>, Status> {
        let req = request.into_inner();

        let allowed = self
            .state
            .permission_service
            .check_permission(
                &self.state.db,
                &req.user_id,
                &req.organization_id,
                &req.resource_type,
                &req.action,
            )
            .await
            .map_err(|e| Status::from(e))?;

        Ok(Response::new(CheckPermissionResponse {
            allowed,
            reason: if allowed {
                String::new()
            } else {
                "Permission denied".to_string()
            },
        }))
    }

    async fn validate_token(
        &self,
        request: Request<ValidateTokenRequest>,
    ) -> Result<Response<ValidateTokenResponse>, Status> {
        let req = request.into_inner();

        match self.state.auth_service().validate_token(&req.token).await {
            Ok((user, session)) => Ok(Response::new(ValidateTokenResponse {
                valid: true,
                user: Some(user.to_proto()),
                session: Some(session.to_proto()),
            })),
            Err(e) => {
                info!("Token validation failed: {}", e);
                Ok(Response::new(ValidateTokenResponse {
                    valid: false,
                    user: None,
                    session: None,
                }))
            }
        }
    }

    async fn validate_api_key(
        &self,
        request: Request<ValidateApiKeyRequest>,
    ) -> Result<Response<ValidateApiKeyResponse>, Status> {
        // Extract client IP from request metadata if available (before into_inner consumes request)
        let client_ip = request
            .metadata()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(',').next().unwrap_or(s).trim().to_string());

        let req = request.into_inner();

        match self
            .state
            .api_key_service()
            .validate_key(&req.api_key, client_ip.as_deref())
            .await
        {
            Ok(key) => {
                // Get organization
                let org = self
                    .state
                    .organization_service()
                    .get_organization(&key.organization_id)
                    .await
                    .map_err(|e| Status::from(e))?;

                Ok(Response::new(ValidateApiKeyResponse {
                    valid: true,
                    key: Some(key.to_proto()),
                    organization: org.map(|o| o.to_proto(None, None, None)),
                }))
            }
            Err(e) => {
                info!("API key validation failed: {}", e);
                Ok(Response::new(ValidateApiKeyResponse {
                    valid: false,
                    key: None,
                    organization: None,
                }))
            }
        }
    }

    // =========================================================================
    // API Keys
    // =========================================================================

    async fn create_api_key(
        &self,
        request: Request<CreateApiKeyRequest>,
    ) -> Result<Response<CreateApiKeyResponse>, Status> {
        // Get user from context (in real implementation, extract from auth header)
        // Extract metadata before into_inner consumes request
        let user_id = request
            .metadata()
            .get("x-user-id")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| Status::unauthenticated("User ID required"))?
            .to_string();

        let req = request.into_inner();

        let model_request = ModelCreateApiKeyRequest {
            name: req.name,
            permissions: req
                .permissions
                .into_iter()
                .map(|p| {
                    match p {
                        1 => "read",
                        2 => "write",
                        3 => "delete",
                        4 => "admin",
                        _ => "read",
                    }
                    .to_string()
                })
                .collect(),
            allowed_ips: Some(req.allowed_ips),
            expires_at: req.expires_at.map(|t| {
                chrono::DateTime::from_timestamp(t.seconds, t.nanos as u32)
                    .unwrap_or_else(chrono::Utc::now)
            }),
        };

        let result = self
            .state
            .api_key_service()
            .create_key(&req.organization_id, &user_id, model_request)
            .await
            .map_err(|e| Status::from(e))?;

        // Log the action
        let _ = self
            .state
            .audit_service()
            .log_api_key_action(
                &req.organization_id,
                &user_id,
                None,
                "created",
                &result.key.id,
                &result.key.name,
                None,
                None,
            )
            .await;

        Ok(Response::new(CreateApiKeyResponse {
            key: Some(
                crate::models::ApiKey {
                    id: result.key.id,
                    organization_id: result.key.organization_id,
                    created_by_user_id: String::new(),
                    name: result.key.name,
                    prefix: result.key.prefix,
                    key_hash: String::new(),
                    permissions: result.key.permissions,
                    allowed_ips: result.key.allowed_ips,
                    enabled: result.key.enabled,
                    expires_at: result.key.expires_at,
                    last_used_at: result.key.last_used_at,
                    created_at: result.key.created_at,
                    updated_at: result.key.created_at,
                }
                .to_proto(),
            ),
            secret: result.secret,
        }))
    }

    async fn list_api_keys(
        &self,
        request: Request<ListApiKeysRequest>,
    ) -> Result<Response<ListApiKeysResponse>, Status> {
        let req = request.into_inner();

        let pagination = req.pagination.unwrap_or_default();
        let page = pagination.page.max(1);
        let page_size = pagination.page_size.clamp(1, 100);

        let (keys, total) = self
            .state
            .api_key_service()
            .list_keys(&req.organization_id, page, page_size)
            .await
            .map_err(|e| Status::from(e))?;

        Ok(Response::new(ListApiKeysResponse {
            keys: keys
                .into_iter()
                .map(|k| {
                    crate::models::ApiKey {
                        id: k.id,
                        organization_id: k.organization_id,
                        created_by_user_id: String::new(),
                        name: k.name,
                        prefix: k.prefix,
                        key_hash: String::new(),
                        permissions: k.permissions,
                        allowed_ips: k.allowed_ips,
                        enabled: k.enabled,
                        expires_at: k.expires_at,
                        last_used_at: k.last_used_at,
                        created_at: k.created_at,
                        updated_at: k.created_at,
                    }
                    .to_proto()
                })
                .collect(),
            pagination: Some(PaginationInfo {
                total_count: total,
                page,
                page_size,
                has_next: (page * page_size) < total,
                next_cursor: String::new(),
            }),
        }))
    }

    async fn revoke_api_key(
        &self,
        request: Request<RevokeApiKeyRequest>,
    ) -> Result<Response<RevokeApiKeyResponse>, Status> {
        let req = request.into_inner();

        let success = self
            .state
            .api_key_service()
            .revoke_key(&req.key_id)
            .await
            .map_err(|e| Status::from(e))?;

        Ok(Response::new(RevokeApiKeyResponse { success }))
    }

    // =========================================================================
    // Audit Logging
    // =========================================================================

    async fn create_audit_log(
        &self,
        request: Request<CreateAuditLogRequest>,
    ) -> Result<Response<CreateAuditLogResponse>, Status> {
        let req = request.into_inner();

        let entry = req
            .entry
            .ok_or_else(|| Status::invalid_argument("Entry required"))?;

        let model_entry = crate::models::CreateAuditLogRequest {
            organization_id: entry.organization_id,
            user_id: if entry.user_id.is_empty() {
                None
            } else {
                Some(entry.user_id)
            },
            user_email: if entry.user_email.is_empty() {
                None
            } else {
                Some(entry.user_email)
            },
            action: entry.action,
            resource_type: entry.resource_type,
            resource_id: if entry.resource_id.is_empty() {
                None
            } else {
                Some(entry.resource_id)
            },
            description: entry.description,
            metadata: entry.metadata,
            ip_address: if entry.ip_address.is_empty() {
                None
            } else {
                Some(entry.ip_address)
            },
            user_agent: if entry.user_agent.is_empty() {
                None
            } else {
                Some(entry.user_agent)
            },
        };

        let created_entry = self
            .state
            .audit_service()
            .log(model_entry)
            .await
            .map_err(|e| Status::from(e))?;

        Ok(Response::new(CreateAuditLogResponse {
            entry: Some(created_entry.to_proto()),
        }))
    }

    async fn list_audit_logs(
        &self,
        request: Request<ListAuditLogsRequest>,
    ) -> Result<Response<ListAuditLogsResponse>, Status> {
        let req = request.into_inner();

        let pagination = req.pagination.unwrap_or_default();
        let page = pagination.page.max(1);
        let page_size = pagination.page_size.clamp(1, 100);

        let filter = AuditLogFilter {
            organization_id: req.organization_id,
            user_id: if req.user_id.is_empty() {
                None
            } else {
                Some(req.user_id)
            },
            resource_type: if req.resource_type.is_empty() {
                None
            } else {
                Some(req.resource_type)
            },
            action: None,
            start_time: req.start_time.map(|t| {
                chrono::DateTime::from_timestamp(t.seconds, t.nanos as u32)
                    .unwrap_or_else(chrono::Utc::now)
            }),
            end_time: req.end_time.map(|t| {
                chrono::DateTime::from_timestamp(t.seconds, t.nanos as u32)
                    .unwrap_or_else(chrono::Utc::now)
            }),
        };

        let (entries, total) = self
            .state
            .audit_service()
            .list(&filter, page, page_size)
            .await
            .map_err(|e| Status::from(e))?;

        Ok(Response::new(ListAuditLogsResponse {
            entries: entries.into_iter().map(|e| e.to_proto()).collect(),
            pagination: Some(PaginationInfo {
                total_count: total,
                page,
                page_size,
                has_next: (page * page_size) < total,
                next_cursor: String::new(),
            }),
        }))
    }

    // =========================================================================
    // Invitations
    // =========================================================================

    async fn create_invitation(
        &self,
        request: Request<CreateInvitationRequest>,
    ) -> Result<Response<CreateInvitationResponse>, Status> {
        // Get user from context (extract metadata before into_inner consumes request)
        let user_id = request
            .metadata()
            .get("x-user-id")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| Status::unauthenticated("User ID required"))?
            .to_string();

        let req = request.into_inner();

        let role = OrganizationRole::try_from(req.role).unwrap_or(OrganizationRole::Member);

        // Generate invitation token
        let token = InvitationTokenGenerator::generate();
        let token_hash = InvitationTokenGenerator::hash_token(&token);

        // Set expiration (7 days)
        let expires_at = chrono::Utc::now() + chrono::Duration::days(7);

        // Create in database
        let id = uuid::Uuid::new_v4().to_string();
        let invitation = crate::db::create_invitation(
            &self.state.db,
            &id,
            &req.organization_id,
            &req.email,
            role,
            &user_id,
            &token_hash,
            expires_at,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        info!("Invitation created: {} for {}", id, req.email);

        Ok(Response::new(CreateInvitationResponse {
            invitation: Some(invitation.to_proto()),
        }))
    }

    async fn list_invitations(
        &self,
        request: Request<ListInvitationsRequest>,
    ) -> Result<Response<ListInvitationsResponse>, Status> {
        let req = request.into_inner();

        let pagination = req.pagination.unwrap_or_default();
        let page = pagination.page.max(1);
        let page_size = pagination.page_size.clamp(1, 100);

        let status = if req.status == 0 {
            None
        } else {
            InvitationStatus::try_from(req.status).ok()
        };

        let (invitations, total) = crate::db::list_invitations(
            &self.state.db,
            &req.organization_id,
            status,
            page,
            page_size,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(ListInvitationsResponse {
            invitations: invitations.into_iter().map(|i| i.to_proto()).collect(),
            pagination: Some(PaginationInfo {
                total_count: total,
                page,
                page_size,
                has_next: (page * page_size) < total,
                next_cursor: String::new(),
            }),
        }))
    }

    async fn revoke_invitation(
        &self,
        request: Request<RevokeInvitationRequest>,
    ) -> Result<Response<RevokeInvitationResponse>, Status> {
        let req = request.into_inner();

        let success = crate::db::revoke_invitation(&self.state.db, &req.invitation_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(RevokeInvitationResponse { success }))
    }

    // =========================================================================
    // Billing Operations
    // =========================================================================

    async fn list_plans(
        &self,
        _request: Request<ListPlansRequest>,
    ) -> Result<Response<ListPlansResponse>, Status> {
        // TODO: Implement list_plans
        Ok(Response::new(ListPlansResponse { plans: vec![] }))
    }

    async fn get_plan(
        &self,
        _request: Request<GetPlanRequest>,
    ) -> Result<Response<GetPlanResponse>, Status> {
        // TODO: Implement get_plan
        Err(Status::unimplemented("get_plan not yet implemented"))
    }

    async fn get_subscription(
        &self,
        _request: Request<GetSubscriptionRequest>,
    ) -> Result<Response<GetSubscriptionResponse>, Status> {
        // TODO: Implement get_subscription
        Err(Status::unimplemented("get_subscription not yet implemented"))
    }

    async fn update_subscription(
        &self,
        _request: Request<pistonprotection_proto::auth::UpdateSubscriptionRequest>,
    ) -> Result<Response<UpdateSubscriptionResponse>, Status> {
        // TODO: Implement update_subscription
        Err(Status::unimplemented("update_subscription not yet implemented"))
    }

    async fn cancel_subscription(
        &self,
        _request: Request<pistonprotection_proto::auth::CancelSubscriptionRequest>,
    ) -> Result<Response<CancelSubscriptionResponse>, Status> {
        // TODO: Implement cancel_subscription
        Err(Status::unimplemented("cancel_subscription not yet implemented"))
    }

    async fn resume_subscription(
        &self,
        _request: Request<ResumeSubscriptionRequest>,
    ) -> Result<Response<ResumeSubscriptionResponse>, Status> {
        // TODO: Implement resume_subscription
        Err(Status::unimplemented("resume_subscription not yet implemented"))
    }

    async fn create_checkout_session(
        &self,
        _request: Request<pistonprotection_proto::auth::CreateCheckoutSessionRequest>,
    ) -> Result<Response<CreateCheckoutSessionResponse>, Status> {
        // TODO: Implement create_checkout_session
        Err(Status::unimplemented("create_checkout_session not yet implemented"))
    }

    async fn create_billing_portal_session(
        &self,
        _request: Request<pistonprotection_proto::auth::CreateBillingPortalSessionRequest>,
    ) -> Result<Response<CreateBillingPortalSessionResponse>, Status> {
        // TODO: Implement create_billing_portal_session
        Err(Status::unimplemented("create_billing_portal_session not yet implemented"))
    }

    async fn list_invoices(
        &self,
        _request: Request<ListInvoicesRequest>,
    ) -> Result<Response<ListInvoicesResponse>, Status> {
        // TODO: Implement list_invoices
        Ok(Response::new(ListInvoicesResponse {
            invoices: vec![],
            pagination: None,
        }))
    }

    async fn get_invoice(
        &self,
        _request: Request<GetInvoiceRequest>,
    ) -> Result<Response<GetInvoiceResponse>, Status> {
        // TODO: Implement get_invoice
        Err(Status::unimplemented("get_invoice not yet implemented"))
    }

    async fn get_usage_summary(
        &self,
        _request: Request<GetUsageSummaryRequest>,
    ) -> Result<Response<GetUsageSummaryResponse>, Status> {
        // TODO: Implement get_usage_summary
        Err(Status::unimplemented("get_usage_summary not yet implemented"))
    }

    async fn report_usage(
        &self,
        _request: Request<ReportUsageRequest>,
    ) -> Result<Response<ReportUsageResponse>, Status> {
        // TODO: Implement report_usage
        Err(Status::unimplemented("report_usage not yet implemented"))
    }

    async fn list_payment_methods(
        &self,
        _request: Request<ListPaymentMethodsRequest>,
    ) -> Result<Response<ListPaymentMethodsResponse>, Status> {
        // TODO: Implement list_payment_methods
        Ok(Response::new(ListPaymentMethodsResponse {
            payment_methods: vec![],
        }))
    }
}

/// Create the gRPC server
pub async fn create_server(
    state: AppState,
) -> Result<tonic::transport::server::Router, Box<dyn std::error::Error>> {
    let auth_service = AuthServiceImpl::new(state.clone());

    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(pistonprotection_proto::FILE_DESCRIPTOR_SET)
        .build_v1()?;

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<AuthServiceServer<AuthServiceImpl>>()
        .await;

    let router = tonic::transport::Server::builder()
        .add_service(health_service)
        .add_service(reflection_service)
        .add_service(AuthServiceServer::new(auth_service));

    Ok(router)
}
