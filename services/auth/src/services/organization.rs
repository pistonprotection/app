//! Organization service for organization management

use pistonprotection_common::redis::CacheService;
use sqlx::PgPool;
use std::time::Duration;
use tracing::info;
use validator::Validate;

use crate::db;
use crate::models::{
    CreateOrganizationRequest, Organization, OrganizationLimits, OrganizationMember,
    OrganizationRole, OrganizationUsage, Subscription, UpdateOrganizationRequest,
};

/// Organization service
pub struct OrganizationService {
    db: PgPool,
    cache: CacheService,
}

impl OrganizationService {
    /// Create a new organization service
    pub fn new(db: PgPool, cache: CacheService) -> Self {
        Self { db, cache }
    }

    /// Create a new organization
    pub async fn create_organization(
        &self,
        owner_user_id: &str,
        request: CreateOrganizationRequest,
    ) -> Result<Organization, OrganizationError> {
        // Validate request
        request
            .validate()
            .map_err(|e| OrganizationError::ValidationError(e.to_string()))?;

        // Check if slug already exists
        if let Some(_) = db::get_organization_by_slug(&self.db, &request.slug)
            .await
            .map_err(|e| OrganizationError::DatabaseError(e.to_string()))?
        {
            return Err(OrganizationError::SlugExists);
        }

        // Generate IDs
        let org_id = uuid::Uuid::new_v4().to_string();
        let member_id = uuid::Uuid::new_v4().to_string();
        let limits_id = uuid::Uuid::new_v4().to_string();
        let usage_id = uuid::Uuid::new_v4().to_string();

        // Create organization
        let org = db::create_organization(
            &self.db,
            &org_id,
            &request.name,
            &request.slug,
            request.logo_url.as_deref(),
        )
        .await
        .map_err(|e| OrganizationError::DatabaseError(e.to_string()))?;

        // Add owner as member
        db::add_organization_member(
            &self.db,
            &member_id,
            owner_user_id,
            &org_id,
            OrganizationRole::Owner,
        )
        .await
        .map_err(|e| OrganizationError::DatabaseError(e.to_string()))?;

        // Create default limits
        db::create_organization_limits(&self.db, &limits_id, &org_id)
            .await
            .map_err(|e| OrganizationError::DatabaseError(e.to_string()))?;

        // Create usage tracking
        db::create_organization_usage(&self.db, &usage_id, &org_id)
            .await
            .map_err(|e| OrganizationError::DatabaseError(e.to_string()))?;

        info!("Organization created: {} ({})", org.id, org.slug);

        Ok(org)
    }

    /// Get organization by ID
    pub async fn get_organization(
        &self,
        org_id: &str,
    ) -> Result<Option<Organization>, OrganizationError> {
        // Check cache
        let cache_key = format!("org:{}", org_id);
        if let Some(cached) = self
            .cache
            .get::<Organization>(&cache_key)
            .await
            .map_err(|e| OrganizationError::CacheError(e.to_string()))?
        {
            return Ok(Some(cached));
        }

        let org = db::get_organization_by_id(&self.db, org_id)
            .await
            .map_err(|e| OrganizationError::DatabaseError(e.to_string()))?;

        // Cache result
        if let Some(ref o) = org {
            let _ = self
                .cache
                .set(&cache_key, o, Duration::from_secs(300))
                .await;
        }

        Ok(org)
    }

    /// Get organization by slug
    pub async fn get_organization_by_slug(
        &self,
        slug: &str,
    ) -> Result<Option<Organization>, OrganizationError> {
        db::get_organization_by_slug(&self.db, slug)
            .await
            .map_err(|e| OrganizationError::DatabaseError(e.to_string()))
    }

    /// Update organization
    pub async fn update_organization(
        &self,
        org_id: &str,
        request: UpdateOrganizationRequest,
    ) -> Result<Organization, OrganizationError> {
        // Validate request
        request
            .validate()
            .map_err(|e| OrganizationError::ValidationError(e.to_string()))?;

        // Check if organization exists
        let existing = db::get_organization_by_id(&self.db, org_id)
            .await
            .map_err(|e| OrganizationError::DatabaseError(e.to_string()))?
            .ok_or(OrganizationError::NotFound)?;

        // Check slug uniqueness if changing
        if let Some(ref slug) = request.slug {
            if slug != &existing.slug {
                if let Some(_) = db::get_organization_by_slug(&self.db, slug)
                    .await
                    .map_err(|e| OrganizationError::DatabaseError(e.to_string()))?
                {
                    return Err(OrganizationError::SlugExists);
                }
            }
        }

        // Update organization
        let org = db::update_organization(
            &self.db,
            org_id,
            request.name.as_deref(),
            request.slug.as_deref(),
            request.logo_url.as_deref(),
        )
        .await
        .map_err(|e| OrganizationError::DatabaseError(e.to_string()))?;

        // Invalidate cache
        let cache_key = format!("org:{}", org_id);
        let _ = self.cache.delete(&cache_key).await;

        info!("Organization updated: {}", org_id);

        Ok(org)
    }

    /// Delete organization
    pub async fn delete_organization(&self, org_id: &str) -> Result<bool, OrganizationError> {
        let deleted = db::delete_organization(&self.db, org_id)
            .await
            .map_err(|e| OrganizationError::DatabaseError(e.to_string()))?;

        if deleted {
            // Invalidate cache
            let cache_key = format!("org:{}", org_id);
            let _ = self.cache.delete(&cache_key).await;

            info!("Organization deleted: {}", org_id);
        }

        Ok(deleted)
    }

    /// List organizations for a user
    pub async fn list_user_organizations(
        &self,
        user_id: &str,
    ) -> Result<Vec<Organization>, OrganizationError> {
        db::list_user_organizations(&self.db, user_id)
            .await
            .map_err(|e| OrganizationError::DatabaseError(e.to_string()))
    }

    /// Get organization limits
    pub async fn get_limits(
        &self,
        org_id: &str,
    ) -> Result<Option<OrganizationLimits>, OrganizationError> {
        db::get_organization_limits(&self.db, org_id)
            .await
            .map_err(|e| OrganizationError::DatabaseError(e.to_string()))
    }

    /// Get organization usage
    pub async fn get_usage(
        &self,
        org_id: &str,
    ) -> Result<Option<OrganizationUsage>, OrganizationError> {
        db::get_organization_usage(&self.db, org_id)
            .await
            .map_err(|e| OrganizationError::DatabaseError(e.to_string()))
    }

    /// Get organization subscription
    pub async fn get_subscription(
        &self,
        org_id: &str,
    ) -> Result<Option<Subscription>, OrganizationError> {
        db::get_organization_subscription(&self.db, org_id)
            .await
            .map_err(|e| OrganizationError::DatabaseError(e.to_string()))
    }

    /// Add member to organization
    pub async fn add_member(
        &self,
        org_id: &str,
        user_id: &str,
        role: OrganizationRole,
    ) -> Result<OrganizationMember, OrganizationError> {
        // Check if already a member
        if let Some(_) = db::get_organization_member(&self.db, org_id, user_id)
            .await
            .map_err(|e| OrganizationError::DatabaseError(e.to_string()))?
        {
            return Err(OrganizationError::AlreadyMember);
        }

        let id = uuid::Uuid::new_v4().to_string();

        let member = db::add_organization_member(&self.db, &id, user_id, org_id, role)
            .await
            .map_err(|e| OrganizationError::DatabaseError(e.to_string()))?;

        info!(
            "Member added to organization: user={}, org={}, role={:?}",
            user_id, org_id, role
        );

        Ok(member)
    }

    /// Get organization member
    pub async fn get_member(
        &self,
        org_id: &str,
        user_id: &str,
    ) -> Result<Option<OrganizationMember>, OrganizationError> {
        db::get_organization_member(&self.db, org_id, user_id)
            .await
            .map_err(|e| OrganizationError::DatabaseError(e.to_string()))
    }

    /// Update member role
    pub async fn update_member_role(
        &self,
        org_id: &str,
        user_id: &str,
        role: OrganizationRole,
    ) -> Result<OrganizationMember, OrganizationError> {
        // Check if member exists
        db::get_organization_member(&self.db, org_id, user_id)
            .await
            .map_err(|e| OrganizationError::DatabaseError(e.to_string()))?
            .ok_or(OrganizationError::NotMember)?;

        let member = db::update_organization_member_role(&self.db, org_id, user_id, role)
            .await
            .map_err(|e| OrganizationError::DatabaseError(e.to_string()))?;

        info!(
            "Member role updated: user={}, org={}, role={:?}",
            user_id, org_id, role
        );

        Ok(member)
    }

    /// Remove member from organization
    pub async fn remove_member(
        &self,
        org_id: &str,
        user_id: &str,
    ) -> Result<bool, OrganizationError> {
        // Check if trying to remove owner
        if let Some(member) = db::get_organization_member(&self.db, org_id, user_id)
            .await
            .map_err(|e| OrganizationError::DatabaseError(e.to_string()))?
        {
            if member.role == OrganizationRole::Owner {
                return Err(OrganizationError::CannotRemoveOwner);
            }
        }

        let removed = db::remove_organization_member(&self.db, org_id, user_id)
            .await
            .map_err(|e| OrganizationError::DatabaseError(e.to_string()))?;

        if removed {
            info!(
                "Member removed from organization: user={}, org={}",
                user_id, org_id
            );
        }

        Ok(removed)
    }

    /// List organization members
    pub async fn list_members(
        &self,
        org_id: &str,
        page: u32,
        page_size: u32,
    ) -> Result<(Vec<OrganizationMember>, u32), OrganizationError> {
        db::list_organization_members(&self.db, org_id, page, page_size)
            .await
            .map_err(|e| OrganizationError::DatabaseError(e.to_string()))
    }

    /// Transfer ownership to another member
    pub async fn transfer_ownership(
        &self,
        org_id: &str,
        current_owner_id: &str,
        new_owner_id: &str,
    ) -> Result<(), OrganizationError> {
        // Verify current owner
        let current = db::get_organization_member(&self.db, org_id, current_owner_id)
            .await
            .map_err(|e| OrganizationError::DatabaseError(e.to_string()))?
            .ok_or(OrganizationError::NotMember)?;

        if current.role != OrganizationRole::Owner {
            return Err(OrganizationError::NotOwner);
        }

        // Verify new owner is a member
        db::get_organization_member(&self.db, org_id, new_owner_id)
            .await
            .map_err(|e| OrganizationError::DatabaseError(e.to_string()))?
            .ok_or(OrganizationError::NotMember)?;

        // Update roles
        db::update_organization_member_role(
            &self.db,
            org_id,
            new_owner_id,
            OrganizationRole::Owner,
        )
        .await
        .map_err(|e| OrganizationError::DatabaseError(e.to_string()))?;

        db::update_organization_member_role(
            &self.db,
            org_id,
            current_owner_id,
            OrganizationRole::Admin,
        )
        .await
        .map_err(|e| OrganizationError::DatabaseError(e.to_string()))?;

        info!(
            "Organization ownership transferred: org={}, from={}, to={}",
            org_id, current_owner_id, new_owner_id
        );

        Ok(())
    }
}

/// Organization service errors
#[derive(Debug, thiserror::Error)]
pub enum OrganizationError {
    #[error("Organization not found")]
    NotFound,

    #[error("Slug already exists")]
    SlugExists,

    #[error("User is already a member")]
    AlreadyMember,

    #[error("User is not a member")]
    NotMember,

    #[error("User is not the owner")]
    NotOwner,

    #[error("Cannot remove organization owner")]
    CannotRemoveOwner,

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Cache error: {0}")]
    CacheError(String),
}

impl From<OrganizationError> for tonic::Status {
    fn from(err: OrganizationError) -> Self {
        match err {
            OrganizationError::NotFound => tonic::Status::not_found("Organization not found"),
            OrganizationError::SlugExists => {
                tonic::Status::already_exists("Organization slug already in use")
            }
            OrganizationError::AlreadyMember => {
                tonic::Status::already_exists("User is already a member")
            }
            OrganizationError::NotMember => {
                tonic::Status::not_found("User is not a member of this organization")
            }
            OrganizationError::NotOwner => {
                tonic::Status::permission_denied("Only the owner can perform this action")
            }
            OrganizationError::CannotRemoveOwner => tonic::Status::failed_precondition(
                "Cannot remove the organization owner. Transfer ownership first.",
            ),
            OrganizationError::ValidationError(msg) => tonic::Status::invalid_argument(msg),
            OrganizationError::DatabaseError(msg) => tonic::Status::internal(msg),
            OrganizationError::CacheError(msg) => tonic::Status::internal(msg),
        }
    }
}
