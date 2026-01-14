//! Session model definitions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Session model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub device_type: Option<String>,
    pub active: bool,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
}

/// Session for external responses (no token hash)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResponse {
    pub id: String,
    pub user_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub device_type: Option<String>,
    pub active: bool,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
}

impl From<Session> for SessionResponse {
    fn from(session: Session) -> Self {
        Self {
            id: session.id,
            user_id: session.user_id,
            ip_address: session.ip_address,
            user_agent: session.user_agent,
            device_type: session.device_type,
            active: session.active,
            expires_at: session.expires_at,
            created_at: session.created_at,
            last_active_at: session.last_active_at,
        }
    }
}

/// Session creation data
#[derive(Debug, Clone)]
pub struct CreateSession {
    pub user_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

impl CreateSession {
    pub fn new(user_id: &str) -> Self {
        Self {
            user_id: user_id.to_string(),
            ip_address: None,
            user_agent: None,
        }
    }

    pub fn with_ip(mut self, ip: Option<String>) -> Self {
        self.ip_address = ip;
        self
    }

    pub fn with_user_agent(mut self, ua: Option<String>) -> Self {
        self.user_agent = ua;
        self
    }
}

/// Device type enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceType {
    Desktop,
    Mobile,
    Tablet,
    Bot,
    Unknown,
}

impl DeviceType {
    /// Parse device type from user agent string
    pub fn from_user_agent(user_agent: &str) -> Self {
        let ua = user_agent.to_lowercase();

        if ua.contains("bot") || ua.contains("crawler") || ua.contains("spider") {
            return DeviceType::Bot;
        }

        if ua.contains("mobile") || ua.contains("android") || ua.contains("iphone") {
            return DeviceType::Mobile;
        }

        if ua.contains("tablet") || ua.contains("ipad") {
            return DeviceType::Tablet;
        }

        if ua.contains("windows") || ua.contains("macintosh") || ua.contains("linux") {
            return DeviceType::Desktop;
        }

        DeviceType::Unknown
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceType::Desktop => "desktop",
            DeviceType::Mobile => "mobile",
            DeviceType::Tablet => "tablet",
            DeviceType::Bot => "bot",
            DeviceType::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Refresh token model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RefreshToken {
    pub id: String,
    pub user_id: String,
    pub session_id: String,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Token pair returned after successful authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

impl TokenPair {
    pub fn new(access_token: String, refresh_token: String, expires_in: i64) -> Self {
        Self {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in,
        }
    }
}

/// Session with proto conversion
impl Session {
    pub fn to_proto(&self) -> pistonprotection_proto::auth::Session {
        use pistonprotection_proto::Timestamp;
        use pistonprotection_proto::auth;

        auth::Session {
            id: self.id.clone(),
            user_id: self.user_id.clone(),
            token: String::new(), // Never expose token
            ip_address: self.ip_address.clone().unwrap_or_default(),
            user_agent: self.user_agent.clone().unwrap_or_default(),
            device_type: self.device_type.clone().unwrap_or_default(),
            active: self.active,
            expires_at: Some(Timestamp::from(self.expires_at)),
            created_at: Some(Timestamp::from(self.created_at)),
            last_active_at: Some(Timestamp::from(self.last_active_at)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_type_from_user_agent() {
        assert_eq!(
            DeviceType::from_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
            DeviceType::Desktop
        );
        assert_eq!(
            DeviceType::from_user_agent("Mozilla/5.0 (iPhone; CPU iPhone OS 14_0)"),
            DeviceType::Mobile
        );
        assert_eq!(
            DeviceType::from_user_agent("Mozilla/5.0 (iPad; CPU OS 14_0)"),
            DeviceType::Tablet
        );
        assert_eq!(
            DeviceType::from_user_agent("Googlebot/2.1"),
            DeviceType::Bot
        );
    }

    #[test]
    fn test_create_session_builder() {
        let session = CreateSession::new("user123")
            .with_ip(Some("192.168.1.1".to_string()))
            .with_user_agent(Some("Mozilla/5.0".to_string()));

        assert_eq!(session.user_id, "user123");
        assert_eq!(session.ip_address, Some("192.168.1.1".to_string()));
    }
}
