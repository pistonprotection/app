//! Organization model definitions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use validator::Validate;

/// Organization subscription status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "subscription_status", rename_all = "lowercase")]
#[derive(Default)]
pub enum SubscriptionStatus {
    Active,
    #[default]
    Trialing,
    PastDue,
    Canceled,
    Unpaid,
}

impl From<SubscriptionStatus> for i32 {
    fn from(status: SubscriptionStatus) -> Self {
        match status {
            SubscriptionStatus::Active => 1,
            SubscriptionStatus::Trialing => 2,
            SubscriptionStatus::PastDue => 3,
            SubscriptionStatus::Canceled => 4,
            SubscriptionStatus::Unpaid => 5,
        }
    }
}

impl TryFrom<i32> for SubscriptionStatus {
    type Error = &'static str;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(SubscriptionStatus::Active),
            2 => Ok(SubscriptionStatus::Trialing),
            3 => Ok(SubscriptionStatus::PastDue),
            4 => Ok(SubscriptionStatus::Canceled),
            5 => Ok(SubscriptionStatus::Unpaid),
            _ => Err("Invalid subscription status"),
        }
    }
}

/// Organization role enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "organization_role", rename_all = "lowercase")]
#[derive(Default)]
pub enum OrganizationRole {
    Owner,
    Admin,
    #[default]
    Member,
    Viewer,
}

impl From<OrganizationRole> for i32 {
    fn from(role: OrganizationRole) -> Self {
        match role {
            OrganizationRole::Owner => 1,
            OrganizationRole::Admin => 2,
            OrganizationRole::Member => 3,
            OrganizationRole::Viewer => 4,
        }
    }
}

impl TryFrom<i32> for OrganizationRole {
    type Error = &'static str;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(OrganizationRole::Owner),
            2 => Ok(OrganizationRole::Admin),
            3 => Ok(OrganizationRole::Member),
            4 => Ok(OrganizationRole::Viewer),
            _ => Err("Invalid organization role"),
        }
    }
}

impl OrganizationRole {
    /// Check if this role can manage members
    pub fn can_manage_members(&self) -> bool {
        matches!(self, OrganizationRole::Owner | OrganizationRole::Admin)
    }

    /// Check if this role can manage organization settings
    pub fn can_manage_settings(&self) -> bool {
        matches!(self, OrganizationRole::Owner | OrganizationRole::Admin)
    }

    /// Check if this role can create/update resources
    pub fn can_write(&self) -> bool {
        matches!(
            self,
            OrganizationRole::Owner | OrganizationRole::Admin | OrganizationRole::Member
        )
    }

    /// Check if this role can delete resources
    pub fn can_delete(&self) -> bool {
        matches!(self, OrganizationRole::Owner | OrganizationRole::Admin)
    }

    /// Get the role's permission level (higher = more permissions)
    pub fn permission_level(&self) -> u8 {
        match self {
            OrganizationRole::Owner => 4,
            OrganizationRole::Admin => 3,
            OrganizationRole::Member => 2,
            OrganizationRole::Viewer => 1,
        }
    }
}

/// Organization model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub logo_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Organization subscription
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Subscription {
    pub id: String,
    pub organization_id: String,
    pub plan_id: String,
    pub plan_name: String,
    pub status: SubscriptionStatus,
    pub stripe_customer_id: Option<String>,
    pub stripe_subscription_id: Option<String>,
    pub current_period_start: DateTime<Utc>,
    pub current_period_end: DateTime<Utc>,
    pub in_trial: bool,
    pub trial_ends_at: Option<DateTime<Utc>>,
    pub cancel_at_period_end: bool,
    pub canceled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Organization limits based on subscription plan
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct OrganizationLimits {
    pub id: String,
    pub organization_id: String,
    pub max_backends: i32,
    pub max_origins_per_backend: i32,
    pub max_domains: i32,
    pub max_filter_rules: i32,
    pub max_bandwidth_bytes: i64,
    pub max_requests: i64,
    pub advanced_protection: bool,
    pub priority_support: bool,
    pub custom_ssl: bool,
    pub api_access: bool,
    pub data_retention_days: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Default for OrganizationLimits {
    fn default() -> Self {
        Self {
            id: String::new(),
            organization_id: String::new(),
            max_backends: 3,
            max_origins_per_backend: 2,
            max_domains: 5,
            max_filter_rules: 10,
            max_bandwidth_bytes: 10_737_418_240, // 10 GB
            max_requests: 1_000_000,
            advanced_protection: false,
            priority_support: false,
            custom_ssl: false,
            api_access: true,
            data_retention_days: 7,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

/// Organization usage tracking
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct OrganizationUsage {
    pub id: String,
    pub organization_id: String,
    pub backends_count: i32,
    pub domains_count: i32,
    pub filter_rules_count: i32,
    pub bandwidth_used: i64,
    pub requests_used: i64,
    pub usage_reset_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Organization member relationship
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct OrganizationMember {
    pub id: String,
    pub user_id: String,
    pub organization_id: String,
    pub role: OrganizationRole,
    pub joined_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Organization member with user details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationMemberWithUser {
    pub id: String,
    pub user_id: String,
    pub organization_id: String,
    pub role: OrganizationRole,
    pub joined_at: DateTime<Utc>,
    pub user: Option<super::UserResponse>,
}

/// Request to create a new organization
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateOrganizationRequest {
    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))]
    pub name: String,

    #[validate(length(min = 1, max = 50, message = "Slug must be 1-50 characters"))]
    #[validate(custom(function = "validate_slug"))]
    pub slug: String,

    pub logo_url: Option<String>,
}

/// Request to update an organization
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateOrganizationRequest {
    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))]
    pub name: Option<String>,

    #[validate(length(min = 1, max = 50, message = "Slug must be 1-50 characters"))]
    #[validate(custom(function = "validate_slug"))]
    pub slug: Option<String>,

    pub logo_url: Option<String>,
}

/// Validate slug format
fn validate_slug(slug: &str) -> Result<(), validator::ValidationError> {
    // Slug must start with a letter
    if !slug.chars().next().is_some_and(|c| c.is_ascii_lowercase()) {
        return Err(validator::ValidationError::new("slug_start_letter"));
    }

    // Slug can only contain lowercase letters, numbers, and hyphens
    if !slug
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(validator::ValidationError::new("slug_invalid_chars"));
    }

    // Slug cannot end with a hyphen
    if slug.ends_with('-') {
        return Err(validator::ValidationError::new("slug_end_hyphen"));
    }

    // No consecutive hyphens
    if slug.contains("--") {
        return Err(validator::ValidationError::new("slug_consecutive_hyphens"));
    }

    Ok(())
}

/// Convert Organization to proto
impl Organization {
    pub fn to_proto(
        &self,
        subscription: Option<&Subscription>,
        limits: Option<&OrganizationLimits>,
        usage: Option<&OrganizationUsage>,
    ) -> pistonprotection_proto::auth::Organization {
        use pistonprotection_proto::Timestamp;
        use pistonprotection_proto::auth;

        auth::Organization {
            id: self.id.clone(),
            name: self.name.clone(),
            slug: self.slug.clone(),
            logo_url: self.logo_url.clone().unwrap_or_default(),
            subscription: subscription.map(|s| auth::Subscription {
                id: s.id.clone(),
                plan_id: s.plan_id.clone(),
                plan_name: s.plan_name.clone(),
                status: i32::from(s.status),
                stripe_customer_id: s.stripe_customer_id.clone().unwrap_or_default(),
                stripe_subscription_id: s.stripe_subscription_id.clone().unwrap_or_default(),
                current_period_start: Some(Timestamp::from(s.current_period_start)),
                current_period_end: Some(Timestamp::from(s.current_period_end)),
                in_trial: s.in_trial,
                trial_ends_at: s.trial_ends_at.map(Timestamp::from),
                cancel_at_period_end: s.cancel_at_period_end,
                canceled_at: s.canceled_at.map(Timestamp::from),
            }),
            limits: limits.map(|l| auth::OrganizationLimits {
                max_backends: l.max_backends as u32,
                max_origins_per_backend: l.max_origins_per_backend as u32,
                max_domains: l.max_domains as u32,
                max_filter_rules: l.max_filter_rules as u32,
                max_bandwidth_bytes: l.max_bandwidth_bytes as u64,
                max_requests: l.max_requests as u64,
                advanced_protection: l.advanced_protection,
                priority_support: l.priority_support,
                custom_ssl: l.custom_ssl,
                api_access: l.api_access,
                data_retention_days: l.data_retention_days as u32,
            }),
            usage: usage.map(|u| auth::OrganizationUsage {
                backends_count: u.backends_count as u32,
                domains_count: u.domains_count as u32,
                filter_rules_count: u.filter_rules_count as u32,
                bandwidth_used: u.bandwidth_used as u64,
                requests_used: u.requests_used as u64,
                usage_reset_at: Some(Timestamp::from(u.usage_reset_at)),
            }),
            created_at: Some(Timestamp::from(self.created_at)),
            updated_at: Some(Timestamp::from(self.updated_at)),
        }
    }
}

impl OrganizationMember {
    pub fn to_proto(
        &self,
        user: Option<&super::User>,
    ) -> pistonprotection_proto::auth::OrganizationMember {
        use pistonprotection_proto::Timestamp;
        use pistonprotection_proto::auth;

        auth::OrganizationMember {
            id: self.id.clone(),
            user_id: self.user_id.clone(),
            organization_id: self.organization_id.clone(),
            role: i32::from(self.role),
            user: user.map(|u| u.to_proto()),
            joined_at: Some(Timestamp::from(self.joined_at)),
        }
    }
}

impl Subscription {
    pub fn to_proto(&self) -> pistonprotection_proto::auth::Subscription {
        use pistonprotection_proto::Timestamp;
        use pistonprotection_proto::auth::Subscription as ProtoSubscription;

        ProtoSubscription {
            id: self.id.clone(),
            plan_id: self.plan_id.clone(),
            plan_name: self.plan_name.clone(),
            status: i32::from(self.status),
            stripe_customer_id: self.stripe_customer_id.clone().unwrap_or_default(),
            stripe_subscription_id: self.stripe_subscription_id.clone().unwrap_or_default(),
            current_period_start: Some(Timestamp::from(self.current_period_start)),
            current_period_end: Some(Timestamp::from(self.current_period_end)),
            in_trial: self.in_trial,
            trial_ends_at: self.trial_ends_at.map(Timestamp::from),
            cancel_at_period_end: self.cancel_at_period_end,
            canceled_at: self.canceled_at.map(Timestamp::from),
        }
    }
}

impl OrganizationLimits {
    pub fn to_proto(&self) -> pistonprotection_proto::auth::OrganizationLimits {
        pistonprotection_proto::auth::OrganizationLimits {
            max_backends: self.max_backends as u32,
            max_origins_per_backend: self.max_origins_per_backend as u32,
            max_domains: self.max_domains as u32,
            max_filter_rules: self.max_filter_rules as u32,
            max_bandwidth_bytes: self.max_bandwidth_bytes as u64,
            max_requests: self.max_requests as u64,
            advanced_protection: self.advanced_protection,
            priority_support: self.priority_support,
            custom_ssl: self.custom_ssl,
            api_access: self.api_access,
            data_retention_days: self.data_retention_days as u32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_organization_role_permissions() {
        assert!(OrganizationRole::Owner.can_manage_members());
        assert!(OrganizationRole::Admin.can_manage_members());
        assert!(!OrganizationRole::Member.can_manage_members());
        assert!(!OrganizationRole::Viewer.can_manage_members());

        assert!(OrganizationRole::Member.can_write());
        assert!(!OrganizationRole::Viewer.can_write());
    }

    #[test]
    fn test_validate_slug() {
        assert!(validate_slug("my-org").is_ok());
        assert!(validate_slug("org123").is_ok());
        assert!(validate_slug("My-Org").is_err()); // uppercase
        assert!(validate_slug("123org").is_err()); // starts with number
        assert!(validate_slug("my--org").is_err()); // consecutive hyphens
        assert!(validate_slug("my-org-").is_err()); // ends with hyphen
    }
}
