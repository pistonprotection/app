//! Invitation model definitions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use validator::Validate;

use super::OrganizationRole;

/// Invitation status enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "invitation_status", rename_all = "lowercase")]
#[derive(Default)]
pub enum InvitationStatus {
    #[default]
    Pending,
    Accepted,
    Expired,
    Revoked,
}

impl From<InvitationStatus> for i32 {
    fn from(status: InvitationStatus) -> Self {
        match status {
            InvitationStatus::Pending => 1,
            InvitationStatus::Accepted => 2,
            InvitationStatus::Expired => 3,
            InvitationStatus::Revoked => 4,
        }
    }
}

impl TryFrom<i32> for InvitationStatus {
    type Error = &'static str;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(InvitationStatus::Pending),
            2 => Ok(InvitationStatus::Accepted),
            3 => Ok(InvitationStatus::Expired),
            4 => Ok(InvitationStatus::Revoked),
            _ => Err("Invalid invitation status"),
        }
    }
}

/// Invitation model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Invitation {
    pub id: String,
    pub organization_id: String,
    pub email: String,
    pub role: OrganizationRole,
    pub invited_by_user_id: String,
    pub status: InvitationStatus,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Invitation for external responses (no token hash)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitationResponse {
    pub id: String,
    pub organization_id: String,
    pub email: String,
    pub role: OrganizationRole,
    pub invited_by_user_id: String,
    pub status: InvitationStatus,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl From<Invitation> for InvitationResponse {
    fn from(invitation: Invitation) -> Self {
        Self {
            id: invitation.id,
            organization_id: invitation.organization_id,
            email: invitation.email,
            role: invitation.role,
            invited_by_user_id: invitation.invited_by_user_id,
            status: invitation.status,
            expires_at: invitation.expires_at,
            accepted_at: invitation.accepted_at,
            created_at: invitation.created_at,
        }
    }
}

/// Request to create an invitation
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateInvitationRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: String,

    pub role: Option<OrganizationRole>,
}

/// Request to accept an invitation
#[derive(Debug, Clone, Deserialize)]
pub struct AcceptInvitationRequest {
    pub token: String,
}

/// Invitation with organization details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitationWithOrganization {
    pub invitation: InvitationResponse,
    pub organization_name: String,
    pub inviter_name: String,
}

/// Invitation token generator
pub struct InvitationTokenGenerator;

impl InvitationTokenGenerator {
    /// Generate a new invitation token
    pub fn generate() -> String {
        use base64::Engine;
        use rand::RngCore;

        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Hash an invitation token for storage
    pub fn hash_token(token: &str) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Verify an invitation token against a hash
    pub fn verify_token(token: &str, hash: &str) -> bool {
        let computed_hash = Self::hash_token(token);
        computed_hash == hash
    }
}

/// Convert to proto Invitation
impl Invitation {
    pub fn to_proto(&self) -> pistonprotection_proto::auth::Invitation {
        use pistonprotection_proto::Timestamp;
        use pistonprotection_proto::auth;

        auth::Invitation {
            id: self.id.clone(),
            organization_id: self.organization_id.clone(),
            email: self.email.clone(),
            role: i32::from(self.role),
            invited_by_user_id: self.invited_by_user_id.clone(),
            status: i32::from(self.status),
            expires_at: Some(Timestamp::from(self.expires_at)),
            accepted_at: self.accepted_at.map(Timestamp::from),
            created_at: Some(Timestamp::from(self.created_at)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invitation_status_conversion() {
        assert_eq!(i32::from(InvitationStatus::Pending), 1);
        assert_eq!(i32::from(InvitationStatus::Accepted), 2);
        assert_eq!(
            InvitationStatus::try_from(1).unwrap(),
            InvitationStatus::Pending
        );
    }

    #[test]
    fn test_invitation_token_generation() {
        let token1 = InvitationTokenGenerator::generate();
        let token2 = InvitationTokenGenerator::generate();

        assert_ne!(token1, token2);
        assert!(token1.len() >= 32);
    }

    #[test]
    fn test_invitation_token_hashing() {
        let token = InvitationTokenGenerator::generate();
        let hash = InvitationTokenGenerator::hash_token(&token);

        assert!(InvitationTokenGenerator::verify_token(&token, &hash));
        assert!(!InvitationTokenGenerator::verify_token("wrong", &hash));
    }
}
