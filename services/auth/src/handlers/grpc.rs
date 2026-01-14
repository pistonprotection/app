//! gRPC handlers implementing the AuthService

use pistonprotection_proto::PaginationInfo;
use pistonprotection_proto::auth::{
    auth_service_server::{AuthService as ProtoAuthService, AuthServiceServer},
    *,
};
use tonic::{Request, Response, Status};
use tracing::{error, info};

use crate::models::{
    AuditLogFilter, CreateApiKeyRequest as ModelCreateApiKeyRequest, InvitationStatus,
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
            .map_err(Status::from)?
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
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found("User not found"))?;

        // Get internal user for proto conversion
        let internal_user = user_service
            .get_user_internal(&user.id)
            .await
            .map_err(Status::from)?
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
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found("Organization not found"))?;

        let subscription = org_service
            .get_subscription(&req.organization_id)
            .await
            .map_err(Status::from)?;

        let limits = org_service
            .get_limits(&req.organization_id)
            .await
            .map_err(Status::from)?;

        let usage = org_service
            .get_usage(&req.organization_id)
            .await
            .map_err(Status::from)?;

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
            .map_err(Status::from)?;

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
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found("Member not found"))?;

        // Get user details
        let user = self
            .state
            .user_service()
            .get_user_internal(&req.user_id)
            .await
            .map_err(Status::from)?;

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
            .map_err(Status::from)?;

        // Get user details for each member
        let user_service = self.state.user_service();
        let mut proto_members = Vec::with_capacity(members.len());

        for member in members {
            let user = user_service
                .get_user_internal(&member.user_id)
                .await
                .map_err(Status::from)?;
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
            .map_err(Status::from)?;

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
                    .map_err(Status::from)?;

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
            .map_err(Status::from)?;

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
            .map_err(Status::from)?;

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
            .map_err(Status::from)?;

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
            .map_err(Status::from)?;

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
            .map_err(Status::from)?;

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
        request: Request<ListPlansRequest>,
    ) -> Result<Response<ListPlansResponse>, Status> {
        let stripe_service = self
            .state
            .stripe_service()
            .ok_or_else(|| Status::failed_precondition("Stripe is not configured"))?;

        let req = request.into_inner();

        let plans = stripe_service.list_plans().await.map_err(|e| {
            error!("Failed to list plans: {}", e);
            Status::internal("Failed to list plans")
        })?;

        // Filter inactive plans if not requested
        let plans: Vec<_> = if req.include_inactive {
            plans
        } else {
            plans.into_iter().filter(|p| p.is_active).collect()
        };

        Ok(Response::new(ListPlansResponse {
            plans: plans.into_iter().map(|p| p.to_proto()).collect(),
        }))
    }

    async fn get_plan(
        &self,
        request: Request<GetPlanRequest>,
    ) -> Result<Response<GetPlanResponse>, Status> {
        let stripe_service = self
            .state
            .stripe_service()
            .ok_or_else(|| Status::failed_precondition("Stripe is not configured"))?;

        let req = request.into_inner();

        let plan = stripe_service
            .get_plan_by_id(&req.plan_id)
            .await
            .map_err(|e| {
                error!("Failed to get plan: {}", e);
                Status::not_found("Plan not found")
            })?;

        Ok(Response::new(GetPlanResponse {
            plan: Some(plan.to_proto()),
        }))
    }

    async fn get_subscription(
        &self,
        request: Request<GetSubscriptionRequest>,
    ) -> Result<Response<GetSubscriptionResponse>, Status> {
        let stripe_service = self
            .state
            .stripe_service()
            .ok_or_else(|| Status::failed_precondition("Stripe is not configured"))?;

        let req = request.into_inner();

        let subscription = stripe_service
            .get_subscription_by_org_id(&req.organization_id)
            .await
            .map_err(|e| {
                error!("Failed to get subscription: {}", e);
                Status::internal("Failed to get subscription")
            })?
            .ok_or_else(|| Status::not_found("Subscription not found"))?;

        // Get the plan details
        let plan = stripe_service
            .get_plan_by_id(&subscription.plan_id)
            .await
            .ok();

        Ok(Response::new(GetSubscriptionResponse {
            subscription: Some(subscription.to_proto()),
            plan: plan.map(|p| p.to_proto()),
        }))
    }

    async fn update_subscription(
        &self,
        request: Request<pistonprotection_proto::auth::UpdateSubscriptionRequest>,
    ) -> Result<Response<UpdateSubscriptionResponse>, Status> {
        let stripe_service = self
            .state
            .stripe_service()
            .ok_or_else(|| Status::failed_precondition("Stripe is not configured"))?;

        let req = request.into_inner();

        // Get current subscription
        let subscription = stripe_service
            .get_subscription_by_org_id(&req.organization_id)
            .await
            .map_err(|e| {
                error!("Failed to get subscription: {}", e);
                Status::internal("Failed to get subscription")
            })?
            .ok_or_else(|| Status::not_found("Subscription not found"))?;

        let stripe_sub_id = subscription
            .stripe_subscription_id
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("No Stripe subscription ID"))?;

        // Get new price ID if plan is changing
        let new_price_id = if !req.plan_id.is_empty() {
            let plan = stripe_service
                .get_plan_by_id(&req.plan_id)
                .await
                .map_err(|e| {
                    error!("Failed to get plan: {}", e);
                    Status::not_found("Plan not found")
                })?;

            // Determine price based on billing period
            let price_id = match req.billing_period {
                2 => plan.stripe_price_id_yearly.as_ref(),
                _ => plan.stripe_price_id_monthly.as_ref(),
            };

            price_id.cloned()
        } else {
            None
        };

        // Convert proration behavior
        let proration = match req.proration_behavior {
            2 => crate::models::subscription::ProrationBehavior::None,
            3 => crate::models::subscription::ProrationBehavior::AlwaysInvoice,
            _ => crate::models::subscription::ProrationBehavior::CreateProrations,
        };

        // Update subscription in Stripe
        let _updated_stripe_sub = stripe_service
            .update_subscription(stripe_sub_id, new_price_id.as_deref(), proration)
            .await
            .map_err(|e| {
                error!("Failed to update Stripe subscription: {}", e);
                Status::internal("Failed to update subscription")
            })?;

        // Fetch updated subscription
        let updated_subscription = stripe_service
            .get_subscription_by_org_id(&req.organization_id)
            .await
            .map_err(|e| {
                error!("Failed to get updated subscription: {}", e);
                Status::internal("Failed to get updated subscription")
            })?
            .ok_or_else(|| Status::internal("Subscription not found after update"))?;

        info!(
            organization_id = %req.organization_id,
            "Updated subscription"
        );

        Ok(Response::new(UpdateSubscriptionResponse {
            subscription: Some(updated_subscription.to_proto()),
        }))
    }

    async fn cancel_subscription(
        &self,
        request: Request<pistonprotection_proto::auth::CancelSubscriptionRequest>,
    ) -> Result<Response<CancelSubscriptionResponse>, Status> {
        let stripe_service = self
            .state
            .stripe_service()
            .ok_or_else(|| Status::failed_precondition("Stripe is not configured"))?;

        let req = request.into_inner();

        // Get current subscription
        let subscription = stripe_service
            .get_subscription_by_org_id(&req.organization_id)
            .await
            .map_err(|e| {
                error!("Failed to get subscription: {}", e);
                Status::internal("Failed to get subscription")
            })?
            .ok_or_else(|| Status::not_found("Subscription not found"))?;

        let stripe_sub_id = subscription
            .stripe_subscription_id
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("No Stripe subscription ID"))?;

        // Cancel in Stripe
        let _cancelled = stripe_service
            .cancel_subscription(stripe_sub_id, req.cancel_at_period_end)
            .await
            .map_err(|e| {
                error!("Failed to cancel Stripe subscription: {}", e);
                Status::internal("Failed to cancel subscription")
            })?;

        // Fetch updated subscription
        let updated_subscription = stripe_service
            .get_subscription_by_org_id(&req.organization_id)
            .await
            .map_err(|e| {
                error!("Failed to get updated subscription: {}", e);
                Status::internal("Failed to get updated subscription")
            })?
            .ok_or_else(|| Status::internal("Subscription not found after cancellation"))?;

        info!(
            organization_id = %req.organization_id,
            cancel_at_period_end = %req.cancel_at_period_end,
            "Cancelled subscription"
        );

        Ok(Response::new(CancelSubscriptionResponse {
            subscription: Some(updated_subscription.to_proto()),
        }))
    }

    async fn resume_subscription(
        &self,
        request: Request<ResumeSubscriptionRequest>,
    ) -> Result<Response<ResumeSubscriptionResponse>, Status> {
        let stripe_service = self
            .state
            .stripe_service()
            .ok_or_else(|| Status::failed_precondition("Stripe is not configured"))?;

        let req = request.into_inner();

        // Get current subscription
        let subscription = stripe_service
            .get_subscription_by_org_id(&req.organization_id)
            .await
            .map_err(|e| {
                error!("Failed to get subscription: {}", e);
                Status::internal("Failed to get subscription")
            })?
            .ok_or_else(|| Status::not_found("Subscription not found"))?;

        let stripe_sub_id = subscription
            .stripe_subscription_id
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("No Stripe subscription ID"))?;

        // Resume in Stripe
        let _resumed = stripe_service
            .resume_subscription(stripe_sub_id)
            .await
            .map_err(|e| {
                error!("Failed to resume Stripe subscription: {}", e);
                Status::internal("Failed to resume subscription")
            })?;

        // Fetch updated subscription
        let updated_subscription = stripe_service
            .get_subscription_by_org_id(&req.organization_id)
            .await
            .map_err(|e| {
                error!("Failed to get updated subscription: {}", e);
                Status::internal("Failed to get updated subscription")
            })?
            .ok_or_else(|| Status::internal("Subscription not found after resume"))?;

        info!(
            organization_id = %req.organization_id,
            "Resumed subscription"
        );

        Ok(Response::new(ResumeSubscriptionResponse {
            subscription: Some(updated_subscription.to_proto()),
        }))
    }

    async fn create_checkout_session(
        &self,
        request: Request<pistonprotection_proto::auth::CreateCheckoutSessionRequest>,
    ) -> Result<Response<CreateCheckoutSessionResponse>, Status> {
        let stripe_service = self
            .state
            .stripe_service()
            .ok_or_else(|| Status::failed_precondition("Stripe is not configured"))?;

        let req = request.into_inner();

        // Convert billing period
        let billing_period = match req.billing_period {
            2 => crate::models::subscription::BillingPeriod::Yearly,
            _ => crate::models::subscription::BillingPeriod::Monthly,
        };

        let checkout_request = crate::models::subscription::CreateCheckoutSessionRequest {
            organization_id: req.organization_id.clone(),
            plan_id: req.plan_id.clone(),
            billing_period,
            success_url: req.success_url.clone(),
            cancel_url: req.cancel_url.clone(),
            allow_promotion_codes: req.allow_promotion_codes,
        };

        let session = stripe_service
            .create_checkout_session(&checkout_request)
            .await
            .map_err(|e| {
                error!("Failed to create checkout session: {}", e);
                Status::internal("Failed to create checkout session")
            })?;

        info!(
            organization_id = %req.organization_id,
            plan_id = %req.plan_id,
            session_id = %session.id,
            "Created checkout session"
        );

        Ok(Response::new(CreateCheckoutSessionResponse {
            session: Some(CheckoutSession {
                id: session.id.to_string(),
                url: session.url.unwrap_or_default(),
                expires_at: Some(pistonprotection_proto::Timestamp {
                    seconds: session.expires_at,
                    nanos: 0,
                }),
            }),
        }))
    }

    async fn create_billing_portal_session(
        &self,
        request: Request<pistonprotection_proto::auth::CreateBillingPortalSessionRequest>,
    ) -> Result<Response<CreateBillingPortalSessionResponse>, Status> {
        let stripe_service = self
            .state
            .stripe_service()
            .ok_or_else(|| Status::failed_precondition("Stripe is not configured"))?;

        let req = request.into_inner();

        let portal_request = crate::models::subscription::CreateBillingPortalSessionRequest {
            organization_id: req.organization_id.clone(),
            return_url: req.return_url.clone(),
        };

        let session = stripe_service
            .create_billing_portal_session(&portal_request)
            .await
            .map_err(|e| {
                error!("Failed to create billing portal session: {}", e);
                Status::internal("Failed to create billing portal session")
            })?;

        info!(
            organization_id = %req.organization_id,
            "Created billing portal session"
        );

        Ok(Response::new(CreateBillingPortalSessionResponse {
            session: Some(BillingPortalSession {
                id: session.id.to_string(),
                url: session.url,
            }),
        }))
    }

    async fn list_invoices(
        &self,
        request: Request<ListInvoicesRequest>,
    ) -> Result<Response<ListInvoicesResponse>, Status> {
        let stripe_service = self
            .state
            .stripe_service()
            .ok_or_else(|| Status::failed_precondition("Stripe is not configured"))?;

        let req = request.into_inner();

        let pagination = req.pagination.unwrap_or_default();
        let page = pagination.page.max(1);
        let page_size = pagination.page_size.clamp(1, 100);
        let offset = ((page - 1) * page_size) as i64;

        let invoices = stripe_service
            .get_organization_invoices(&req.organization_id, page_size as i64, offset)
            .await
            .map_err(|e| {
                error!("Failed to list invoices: {}", e);
                Status::internal("Failed to list invoices")
            })?;

        Ok(Response::new(ListInvoicesResponse {
            invoices: invoices.into_iter().map(|i| i.to_proto()).collect(),
            pagination: Some(PaginationInfo {
                total_count: 0, // Would need a count query
                page,
                page_size,
                has_next: false,
                next_cursor: String::new(),
            }),
        }))
    }

    async fn get_invoice(
        &self,
        request: Request<GetInvoiceRequest>,
    ) -> Result<Response<GetInvoiceResponse>, Status> {
        let stripe_service = self
            .state
            .stripe_service()
            .ok_or_else(|| Status::failed_precondition("Stripe is not configured"))?;

        let req = request.into_inner();

        // Fetch from Stripe
        let stripe_invoice = stripe_service
            .get_invoice(&req.invoice_id)
            .await
            .map_err(|e| {
                error!("Failed to get invoice: {}", e);
                Status::not_found("Invoice not found")
            })?;

        // Convert to proto
        let invoice = pistonprotection_proto::auth::Invoice {
            id: stripe_invoice.id.to_string(),
            organization_id: String::new(), // Would need lookup
            subscription_id: stripe_invoice
                .subscription
                .map(|s| match s {
                    stripe_rust::Expandable::Id(id) => id.to_string(),
                    stripe_rust::Expandable::Object(sub) => sub.id.to_string(),
                })
                .unwrap_or_default(),
            stripe_invoice_id: stripe_invoice.id.to_string(),
            number: stripe_invoice.number.unwrap_or_default(),
            status: stripe_invoice
                .status
                .map(|s| crate::models::subscription::InvoiceStatus::from_stripe_status(s.as_ref()))
                .map(i32::from)
                .unwrap_or(0),
            currency: stripe_invoice
                .currency
                .map(|c| c.to_string())
                .unwrap_or_else(|| "usd".to_string()),
            subtotal_cents: stripe_invoice.subtotal.unwrap_or(0),
            tax_cents: stripe_invoice.tax.unwrap_or(0),
            total_cents: stripe_invoice.total.unwrap_or(0),
            amount_paid_cents: stripe_invoice.amount_paid.unwrap_or(0),
            amount_due_cents: stripe_invoice.amount_due.unwrap_or(0),
            description: stripe_invoice.description.unwrap_or_default(),
            invoice_pdf_url: stripe_invoice.invoice_pdf.unwrap_or_default(),
            hosted_invoice_url: stripe_invoice.hosted_invoice_url.unwrap_or_default(),
            period_start: stripe_invoice
                .period_start
                .map(|ts| pistonprotection_proto::Timestamp {
                    seconds: ts,
                    nanos: 0,
                }),
            period_end: stripe_invoice
                .period_end
                .map(|ts| pistonprotection_proto::Timestamp {
                    seconds: ts,
                    nanos: 0,
                }),
            due_date: stripe_invoice
                .due_date
                .map(|ts| pistonprotection_proto::Timestamp {
                    seconds: ts,
                    nanos: 0,
                }),
            paid_at: None,
            created_at: stripe_invoice
                .created
                .map(|ts| pistonprotection_proto::Timestamp {
                    seconds: ts,
                    nanos: 0,
                }),
        };

        Ok(Response::new(GetInvoiceResponse {
            invoice: Some(invoice),
        }))
    }

    async fn get_usage_summary(
        &self,
        request: Request<GetUsageSummaryRequest>,
    ) -> Result<Response<GetUsageSummaryResponse>, Status> {
        let stripe_service = self
            .state
            .stripe_service()
            .ok_or_else(|| Status::failed_precondition("Stripe is not configured"))?;

        let req = request.into_inner();

        use chrono::Datelike;

        // Parse timestamps
        let period_start = req
            .period_start
            .map(|t| {
                chrono::DateTime::from_timestamp(t.seconds, t.nanos as u32)
                    .unwrap_or_else(chrono::Utc::now)
            })
            .unwrap_or_else(|| {
                // Default to start of current month
                let now = chrono::Utc::now();
                now - chrono::Duration::days(now.day0() as i64)
            });

        let period_end = req
            .period_end
            .map(|t| {
                chrono::DateTime::from_timestamp(t.seconds, t.nanos as u32)
                    .unwrap_or_else(chrono::Utc::now)
            })
            .unwrap_or_else(chrono::Utc::now);

        let summary = stripe_service
            .get_usage_summary(&req.organization_id, period_start, period_end)
            .await
            .map_err(|e| {
                error!("Failed to get usage summary: {}", e);
                Status::internal("Failed to get usage summary")
            })?;

        // Get organization limits
        let limits = self
            .state
            .organization_service()
            .get_limits(&req.organization_id)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(GetUsageSummaryResponse {
            summary: summary.map(|s| pistonprotection_proto::auth::UsageSummary {
                id: s.id,
                organization_id: s.organization_id,
                subscription_id: s.subscription_id,
                period_start: Some(pistonprotection_proto::Timestamp::from(s.period_start)),
                period_end: Some(pistonprotection_proto::Timestamp::from(s.period_end)),
                total_requests: s.total_requests,
                total_bandwidth_bytes: s.total_bandwidth_bytes,
                total_blocked_requests: s.total_blocked_requests,
                total_challenges_served: s.total_challenges_served,
                overage_requests: s.overage_requests,
                overage_bandwidth_bytes: s.overage_bandwidth_bytes,
                overage_charges_cents: s.overage_charges_cents,
            }),
            limits: limits.map(|l| l.to_proto()),
        }))
    }

    async fn report_usage(
        &self,
        request: Request<ReportUsageRequest>,
    ) -> Result<Response<ReportUsageResponse>, Status> {
        let stripe_service = self
            .state
            .stripe_service()
            .ok_or_else(|| Status::failed_precondition("Stripe is not configured"))?;

        let req = request.into_inner();

        // Convert metric type
        let metric_type = crate::models::subscription::UsageMetricType::try_from(req.metric_type)
            .unwrap_or(crate::models::subscription::UsageMetricType::Requests);

        // Report usage based on metric type
        match metric_type {
            crate::models::subscription::UsageMetricType::BandwidthBytes => {
                stripe_service
                    .report_bandwidth_usage(&req.organization_id, req.quantity)
                    .await
                    .map_err(|e| {
                        error!("Failed to report bandwidth usage: {}", e);
                        Status::internal("Failed to report usage")
                    })?;
            }
            crate::models::subscription::UsageMetricType::Requests => {
                stripe_service
                    .report_request_usage(&req.organization_id, req.quantity)
                    .await
                    .map_err(|e| {
                        error!("Failed to report request usage: {}", e);
                        Status::internal("Failed to report usage")
                    })?;
            }
            _ => {
                // Other metrics not yet supported for Stripe reporting
            }
        }

        Ok(Response::new(ReportUsageResponse {
            success: true,
            record: Some(pistonprotection_proto::auth::UsageRecord {
                id: uuid::Uuid::new_v4().to_string(),
                organization_id: req.organization_id,
                subscription_id: String::new(),
                metric_type: req.metric_type,
                quantity: req.quantity,
                timestamp: req.timestamp,
            }),
        }))
    }

    async fn list_payment_methods(
        &self,
        request: Request<ListPaymentMethodsRequest>,
    ) -> Result<Response<ListPaymentMethodsResponse>, Status> {
        let stripe_service = self
            .state
            .stripe_service()
            .ok_or_else(|| Status::failed_precondition("Stripe is not configured"))?;

        let req = request.into_inner();

        // Get subscription to find customer ID
        let subscription = stripe_service
            .get_subscription_by_org_id(&req.organization_id)
            .await
            .map_err(|e| {
                error!("Failed to get subscription: {}", e);
                Status::internal("Failed to get subscription")
            })?;

        let customer_id = match subscription {
            Some(ref sub) => sub.stripe_customer_id.as_ref(),
            None => None,
        };

        if customer_id.is_none() {
            return Ok(Response::new(ListPaymentMethodsResponse {
                payment_methods: vec![],
            }));
        }

        // Payment methods would be fetched from local DB or Stripe
        // For now, return empty list (would need to implement Stripe PaymentMethod listing)
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

    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<AuthServiceServer<AuthServiceImpl>>()
        .await;

    let router = tonic::transport::Server::builder()
        .add_service(health_service)
        .add_service(reflection_service)
        .add_service(AuthServiceServer::new(auth_service));

    Ok(router)
}
