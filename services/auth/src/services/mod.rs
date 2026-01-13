//! Service layer for the authentication service

use deadpool_redis::Pool as RedisPool;
use pistonprotection_common::{config::Config, redis::CacheService};
use sqlx::PgPool;
use std::sync::Arc;

pub mod apikey;
pub mod audit;
pub mod auth;
pub mod dunning;
pub mod email;
pub mod jwt;
pub mod organization;
pub mod permission;
pub mod session;
pub mod stripe;
pub mod user;

pub use apikey::ApiKeyService;
pub use audit::AuditService;
pub use auth::AuthService;
pub use dunning::{DunningConfig, DunningService};
pub use email::{EmailConfig, EmailService};
pub use jwt::JwtService;
pub use organization::OrganizationService;
pub use permission::PermissionService;
pub use session::SessionService;
pub use stripe::StripeService;
pub use user::UserService;

use crate::config::AuthConfig;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub cache: CacheService,
    pub config: Arc<Config>,
    pub auth_config: Arc<AuthConfig>,
    pub jwt_service: Arc<JwtService>,
    pub session_service: Arc<SessionService>,
    pub permission_service: Arc<PermissionService>,
    pub stripe_service: Option<Arc<StripeService>>,
    pub email_service: Arc<EmailService>,
    pub dunning_service: Option<Arc<DunningService>>,
}

impl AppState {
    /// Create new application state
    pub fn new(db: PgPool, redis: RedisPool, config: Config, auth_config: AuthConfig) -> Self {
        let cache = CacheService::new(redis, "piston:auth");

        let jwt_service = Arc::new(JwtService::new(&auth_config.jwt));
        let session_service = Arc::new(SessionService::new(
            cache.clone(),
            auth_config.session.clone(),
        ));
        let permission_service = Arc::new(PermissionService::new(
            cache.clone(),
            auth_config.rbac.clone(),
        ));

        // Initialize email service
        let email_service = Arc::new(EmailService::new(EmailConfig::default()));

        // Initialize Stripe service if configured
        let stripe_service = if auth_config.stripe.is_configured() {
            Some(Arc::new(StripeService::new(
                auth_config.stripe.clone(),
                db.clone(),
            )))
        } else {
            None
        };

        // Initialize dunning service if Stripe is enabled
        let dunning_service = stripe_service.as_ref().map(|stripe| {
            Arc::new(DunningService::new(
                db.clone(),
                Arc::clone(stripe),
                Arc::clone(&email_service),
                DunningConfig::default(),
            ))
        });

        Self {
            db,
            cache,
            config: Arc::new(config),
            auth_config: Arc::new(auth_config),
            jwt_service,
            session_service,
            permission_service,
            stripe_service,
            email_service,
            dunning_service,
        }
    }

    /// Get a new AuthService instance
    pub fn auth_service(&self) -> AuthService {
        AuthService::new(
            self.db.clone(),
            self.jwt_service.clone(),
            self.session_service.clone(),
            self.auth_config.clone(),
        )
    }

    /// Get a new UserService instance
    pub fn user_service(&self) -> UserService {
        UserService::new(self.db.clone(), self.auth_config.clone())
    }

    /// Get a new OrganizationService instance
    pub fn organization_service(&self) -> OrganizationService {
        OrganizationService::new(self.db.clone(), self.cache.clone())
    }

    /// Get a new ApiKeyService instance
    pub fn api_key_service(&self) -> ApiKeyService {
        ApiKeyService::new(
            self.db.clone(),
            self.cache.clone(),
            self.auth_config.clone(),
        )
    }

    /// Get a new AuditService instance
    pub fn audit_service(&self) -> AuditService {
        AuditService::new(self.db.clone())
    }

    /// Get the Stripe service if configured
    pub fn stripe_service(&self) -> Option<Arc<StripeService>> {
        self.stripe_service.clone()
    }

    /// Check if Stripe is enabled
    pub fn is_stripe_enabled(&self) -> bool {
        self.stripe_service.is_some()
    }

    /// Get the email service
    pub fn email_service(&self) -> Arc<EmailService> {
        Arc::clone(&self.email_service)
    }

    /// Get the dunning service if enabled
    pub fn dunning_service(&self) -> Option<Arc<DunningService>> {
        self.dunning_service.clone()
    }
}
