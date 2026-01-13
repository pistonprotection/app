//! Permission service for RBAC

use pistonprotection_common::redis::CacheService;
use sqlx::PgPool;
use std::collections::HashSet;
use std::time::Duration;
use tracing::debug;

use crate::config::RbacConfig;
use crate::db;
use crate::models::{OrganizationRole, PermissionHelper, SystemRoles};

/// Cached user permissions
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CachedPermissions {
    user_id: String,
    organization_id: String,
    role: String,
    permissions: HashSet<String>,
}

/// Permission service for RBAC
pub struct PermissionService {
    cache: CacheService,
    config: RbacConfig,
}

impl PermissionService {
    /// Create a new permission service
    pub fn new(cache: CacheService, config: RbacConfig) -> Self {
        Self { cache, config }
    }

    /// Get user permissions for an organization
    pub async fn get_user_permissions(
        &self,
        db: &PgPool,
        user_id: &str,
        organization_id: &str,
    ) -> Result<HashSet<String>, PermissionError> {
        // Check cache if enabled
        if self.config.cache_permissions {
            let cache_key = format!("perms:{}:{}", user_id, organization_id);
            if let Some(cached) = self
                .cache
                .get::<CachedPermissions>(&cache_key)
                .await
                .map_err(|e| PermissionError::CacheError(e.to_string()))?
            {
                return Ok(cached.permissions);
            }
        }

        // Get organization member
        let member = db::get_organization_member(db, organization_id, user_id)
            .await
            .map_err(|e| PermissionError::DatabaseError(e.to_string()))?
            .ok_or(PermissionError::NotMember)?;

        // Get permissions based on role
        let role_name = match member.role {
            OrganizationRole::Owner => SystemRoles::OWNER,
            OrganizationRole::Admin => SystemRoles::ADMIN,
            OrganizationRole::Member => SystemRoles::MEMBER,
            OrganizationRole::Viewer => SystemRoles::VIEWER,
        };

        let permissions = SystemRoles::get_permissions(role_name);

        // Cache if enabled
        if self.config.cache_permissions {
            let cache_key = format!("perms:{}:{}", user_id, organization_id);
            let cached = CachedPermissions {
                user_id: user_id.to_string(),
                organization_id: organization_id.to_string(),
                role: role_name.to_string(),
                permissions: permissions.clone(),
            };
            let _ = self
                .cache
                .set(
                    &cache_key,
                    &cached,
                    Duration::from_secs(self.config.cache_ttl_secs),
                )
                .await;
        }

        Ok(permissions)
    }

    /// Check if user has a specific permission
    pub async fn check_permission(
        &self,
        db: &PgPool,
        user_id: &str,
        organization_id: &str,
        resource: &str,
        action: &str,
    ) -> Result<bool, PermissionError> {
        let permissions = self
            .get_user_permissions(db, user_id, organization_id)
            .await?;

        let allowed = PermissionHelper::check_permission(&permissions, resource, action);

        debug!(
            "Permission check: user={}, org={}, resource={}, action={}, allowed={}",
            user_id, organization_id, resource, action, allowed
        );

        Ok(allowed)
    }

    /// Check if user has permission with scope
    pub async fn check_scoped_permission(
        &self,
        db: &PgPool,
        user_id: &str,
        organization_id: &str,
        resource: &str,
        action: &str,
        scope: Option<&str>,
    ) -> Result<bool, PermissionError> {
        let permissions = self
            .get_user_permissions(db, user_id, organization_id)
            .await?;

        let allowed =
            PermissionHelper::check_scoped_permission(&permissions, resource, action, scope);

        Ok(allowed)
    }

    /// Require permission (throws error if not allowed)
    pub async fn require_permission(
        &self,
        db: &PgPool,
        user_id: &str,
        organization_id: &str,
        resource: &str,
        action: &str,
    ) -> Result<(), PermissionError> {
        if !self
            .check_permission(db, user_id, organization_id, resource, action)
            .await?
        {
            return Err(PermissionError::PermissionDenied {
                resource: resource.to_string(),
                action: action.to_string(),
            });
        }

        Ok(())
    }

    /// Get user's organization role
    pub async fn get_user_role(
        &self,
        db: &PgPool,
        user_id: &str,
        organization_id: &str,
    ) -> Result<OrganizationRole, PermissionError> {
        let member = db::get_organization_member(db, organization_id, user_id)
            .await
            .map_err(|e| PermissionError::DatabaseError(e.to_string()))?
            .ok_or(PermissionError::NotMember)?;

        Ok(member.role)
    }

    /// Check if user can manage a target role
    pub fn can_manage_role(
        &self,
        actor_role: OrganizationRole,
        target_role: OrganizationRole,
    ) -> bool {
        // Owner can manage all roles
        if actor_role == OrganizationRole::Owner {
            return true;
        }

        // Admin can manage members and viewers
        if actor_role == OrganizationRole::Admin {
            return matches!(
                target_role,
                OrganizationRole::Member | OrganizationRole::Viewer
            );
        }

        // Members and viewers cannot manage anyone
        false
    }

    /// Check if user is at least at a certain role level
    pub fn is_at_least(
        &self,
        user_role: OrganizationRole,
        required_role: OrganizationRole,
    ) -> bool {
        user_role.permission_level() >= required_role.permission_level()
    }

    /// Invalidate cached permissions for a user
    pub async fn invalidate_user_cache(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<(), PermissionError> {
        if self.config.cache_permissions {
            let cache_key = format!("perms:{}:{}", user_id, organization_id);
            self.cache
                .delete(&cache_key)
                .await
                .map_err(|e| PermissionError::CacheError(e.to_string()))?;
        }
        Ok(())
    }

    /// Invalidate all cached permissions for an organization
    pub async fn invalidate_org_cache(&self, organization_id: &str) -> Result<(), PermissionError> {
        if self.config.cache_permissions {
            let pattern = format!("perms:*:{}", organization_id);
            self.cache
                .delete_pattern(&pattern)
                .await
                .map_err(|e| PermissionError::CacheError(e.to_string()))?;
        }
        Ok(())
    }
}

/// Permission errors
#[derive(Debug, thiserror::Error)]
pub enum PermissionError {
    #[error("User is not a member of this organization")]
    NotMember,

    #[error("Permission denied: {resource}:{action}")]
    PermissionDenied { resource: String, action: String },

    #[error("Insufficient role")]
    InsufficientRole,

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Cache error: {0}")]
    CacheError(String),
}

impl From<PermissionError> for tonic::Status {
    fn from(err: PermissionError) -> Self {
        match err {
            PermissionError::NotMember => {
                tonic::Status::permission_denied("Not a member of this organization")
            }
            PermissionError::PermissionDenied { resource, action } => {
                tonic::Status::permission_denied(format!(
                    "Permission denied for {}:{}",
                    resource, action
                ))
            }
            PermissionError::InsufficientRole => {
                tonic::Status::permission_denied("Insufficient role for this action")
            }
            PermissionError::DatabaseError(msg) => tonic::Status::internal(msg),
            PermissionError::CacheError(msg) => tonic::Status::internal(msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_management_hierarchy() {
        let config = RbacConfig::default();
        // Would need mock for full test

        // Test role hierarchy
        assert!(
            OrganizationRole::Owner.permission_level() > OrganizationRole::Admin.permission_level()
        );
        assert!(
            OrganizationRole::Admin.permission_level()
                > OrganizationRole::Member.permission_level()
        );
        assert!(
            OrganizationRole::Member.permission_level()
                > OrganizationRole::Viewer.permission_level()
        );
    }

    #[test]
    fn test_is_at_least() {
        assert!(
            OrganizationRole::Owner.permission_level()
                >= OrganizationRole::Admin.permission_level()
        );
        assert!(
            OrganizationRole::Admin.permission_level()
                >= OrganizationRole::Admin.permission_level()
        );
        assert!(
            !(OrganizationRole::Member.permission_level()
                >= OrganizationRole::Admin.permission_level())
        );
    }
}
