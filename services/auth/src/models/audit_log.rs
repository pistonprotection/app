//! Audit log model definitions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::collections::HashMap;

/// Audit log entry model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditLogEntry {
    pub id: String,
    pub organization_id: String,
    pub user_id: Option<String>,
    pub user_email: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub description: String,
    #[sqlx(json)]
    pub metadata: HashMap<String, String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// Request to create an audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAuditLogRequest {
    pub organization_id: String,
    pub user_id: Option<String>,
    pub user_email: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub description: String,
    pub metadata: HashMap<String, String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Audit log filter for queries
#[derive(Debug, Clone, Default)]
pub struct AuditLogFilter {
    pub organization_id: String,
    pub user_id: Option<String>,
    pub resource_type: Option<String>,
    pub action: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
}

impl AuditLogFilter {
    pub fn new(organization_id: &str) -> Self {
        Self {
            organization_id: organization_id.to_string(),
            ..Default::default()
        }
    }

    pub fn with_user(mut self, user_id: &str) -> Self {
        self.user_id = Some(user_id.to_string());
        self
    }

    pub fn with_resource_type(mut self, resource_type: &str) -> Self {
        self.resource_type = Some(resource_type.to_string());
        self
    }

    pub fn with_action(mut self, action: &str) -> Self {
        self.action = Some(action.to_string());
        self
    }

    pub fn with_time_range(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.start_time = Some(start);
        self.end_time = Some(end);
        self
    }
}

/// Common audit actions
pub struct AuditActions;

impl AuditActions {
    // User actions
    pub const USER_CREATED: &'static str = "user.created";
    pub const USER_UPDATED: &'static str = "user.updated";
    pub const USER_DELETED: &'static str = "user.deleted";
    pub const USER_LOGIN: &'static str = "user.login";
    pub const USER_LOGOUT: &'static str = "user.logout";
    pub const USER_PASSWORD_CHANGED: &'static str = "user.password_changed";
    pub const USER_PASSWORD_RESET: &'static str = "user.password_reset";
    pub const USER_2FA_ENABLED: &'static str = "user.2fa_enabled";
    pub const USER_2FA_DISABLED: &'static str = "user.2fa_disabled";

    // Organization actions
    pub const ORG_CREATED: &'static str = "organization.created";
    pub const ORG_UPDATED: &'static str = "organization.updated";
    pub const ORG_DELETED: &'static str = "organization.deleted";

    // Member actions
    pub const MEMBER_ADDED: &'static str = "member.added";
    pub const MEMBER_REMOVED: &'static str = "member.removed";
    pub const MEMBER_ROLE_CHANGED: &'static str = "member.role_changed";

    // Invitation actions
    pub const INVITATION_CREATED: &'static str = "invitation.created";
    pub const INVITATION_ACCEPTED: &'static str = "invitation.accepted";
    pub const INVITATION_REVOKED: &'static str = "invitation.revoked";

    // API Key actions
    pub const API_KEY_CREATED: &'static str = "api_key.created";
    pub const API_KEY_REVOKED: &'static str = "api_key.revoked";
    pub const API_KEY_USED: &'static str = "api_key.used";

    // Session actions
    pub const SESSION_CREATED: &'static str = "session.created";
    pub const SESSION_REVOKED: &'static str = "session.revoked";

    // Resource actions
    pub const BACKEND_CREATED: &'static str = "backend.created";
    pub const BACKEND_UPDATED: &'static str = "backend.updated";
    pub const BACKEND_DELETED: &'static str = "backend.deleted";

    pub const DOMAIN_CREATED: &'static str = "domain.created";
    pub const DOMAIN_UPDATED: &'static str = "domain.updated";
    pub const DOMAIN_DELETED: &'static str = "domain.deleted";

    pub const FILTER_CREATED: &'static str = "filter.created";
    pub const FILTER_UPDATED: &'static str = "filter.updated";
    pub const FILTER_DELETED: &'static str = "filter.deleted";

    // Settings actions
    pub const SETTINGS_UPDATED: &'static str = "settings.updated";

    // Billing actions
    pub const SUBSCRIPTION_CREATED: &'static str = "subscription.created";
    pub const SUBSCRIPTION_UPDATED: &'static str = "subscription.updated";
    pub const SUBSCRIPTION_CANCELED: &'static str = "subscription.canceled";
}

/// Audit log builder for easy creation
pub struct AuditLogBuilder {
    entry: CreateAuditLogRequest,
}

impl AuditLogBuilder {
    pub fn new(organization_id: &str, action: &str, resource_type: &str) -> Self {
        Self {
            entry: CreateAuditLogRequest {
                organization_id: organization_id.to_string(),
                user_id: None,
                user_email: None,
                action: action.to_string(),
                resource_type: resource_type.to_string(),
                resource_id: None,
                description: String::new(),
                metadata: HashMap::new(),
                ip_address: None,
                user_agent: None,
            },
        }
    }

    pub fn user(mut self, user_id: &str, email: Option<&str>) -> Self {
        self.entry.user_id = Some(user_id.to_string());
        self.entry.user_email = email.map(|e| e.to_string());
        self
    }

    pub fn resource(mut self, resource_id: &str) -> Self {
        self.entry.resource_id = Some(resource_id.to_string());
        self
    }

    pub fn description(mut self, description: &str) -> Self {
        self.entry.description = description.to_string();
        self
    }

    pub fn metadata(mut self, key: &str, value: &str) -> Self {
        self.entry
            .metadata
            .insert(key.to_string(), value.to_string());
        self
    }

    pub fn request_info(mut self, ip: Option<&str>, user_agent: Option<&str>) -> Self {
        self.entry.ip_address = ip.map(|s| s.to_string());
        self.entry.user_agent = user_agent.map(|s| s.to_string());
        self
    }

    pub fn build(self) -> CreateAuditLogRequest {
        self.entry
    }
}

/// Convert to proto AuditLogEntry
impl AuditLogEntry {
    pub fn to_proto(&self) -> pistonprotection_proto::auth::AuditLogEntry {
        use pistonprotection_proto::Timestamp;
        use pistonprotection_proto::auth;

        auth::AuditLogEntry {
            id: self.id.clone(),
            organization_id: self.organization_id.clone(),
            user_id: self.user_id.clone().unwrap_or_default(),
            user_email: self.user_email.clone().unwrap_or_default(),
            action: self.action.clone(),
            resource_type: self.resource_type.clone(),
            resource_id: self.resource_id.clone().unwrap_or_default(),
            description: self.description.clone(),
            metadata: self.metadata.clone(),
            ip_address: self.ip_address.clone().unwrap_or_default(),
            user_agent: self.user_agent.clone().unwrap_or_default(),
            timestamp: Some(Timestamp::from(self.timestamp)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log_builder() {
        let entry = AuditLogBuilder::new("org123", AuditActions::USER_LOGIN, "user")
            .user("user456", Some("test@example.com"))
            .description("User logged in successfully")
            .metadata("method", "password")
            .request_info(Some("192.168.1.1"), Some("Mozilla/5.0"))
            .build();

        assert_eq!(entry.organization_id, "org123");
        assert_eq!(entry.action, "user.login");
        assert_eq!(entry.user_id, Some("user456".to_string()));
        assert_eq!(entry.metadata.get("method"), Some(&"password".to_string()));
    }

    #[test]
    fn test_audit_log_filter() {
        let filter = AuditLogFilter::new("org123")
            .with_user("user456")
            .with_resource_type("backend")
            .with_action("backend.created");

        assert_eq!(filter.organization_id, "org123");
        assert_eq!(filter.user_id, Some("user456".to_string()));
        assert_eq!(filter.resource_type, Some("backend".to_string()));
    }
}
