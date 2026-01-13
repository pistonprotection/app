//! Authentication service configuration

use serde::Deserialize;
use std::env;

/// Auth-specific configuration
#[derive(Debug, Clone, Deserialize)]
#[derive(Default)]
pub struct AuthConfig {
    /// JWT configuration
    #[serde(default)]
    pub jwt: JwtConfig,

    /// Session configuration
    #[serde(default)]
    pub session: SessionConfig,

    /// Password policy configuration
    #[serde(default)]
    pub password: PasswordConfig,

    /// API key configuration
    #[serde(default)]
    pub api_key: ApiKeyConfig,

    /// OAuth providers configuration
    #[serde(default)]
    pub oauth: OAuthConfig,

    /// RBAC configuration
    #[serde(default)]
    pub rbac: RbacConfig,

    /// Stripe configuration
    #[serde(default)]
    pub stripe: StripeConfig,
}


/// JWT configuration
#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    /// Secret key for signing JWTs
    #[serde(default = "default_jwt_secret")]
    pub secret: String,

    /// JWT issuer
    #[serde(default = "default_jwt_issuer")]
    pub issuer: String,

    /// JWT audience
    #[serde(default = "default_jwt_audience")]
    pub audience: String,

    /// Access token TTL in seconds
    #[serde(default = "default_access_token_ttl")]
    pub access_token_ttl_secs: u64,

    /// Refresh token TTL in seconds
    #[serde(default = "default_refresh_token_ttl")]
    pub refresh_token_ttl_secs: u64,

    /// Algorithm for JWT signing
    #[serde(default = "default_jwt_algorithm")]
    pub algorithm: String,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: default_jwt_secret(),
            issuer: default_jwt_issuer(),
            audience: default_jwt_audience(),
            access_token_ttl_secs: default_access_token_ttl(),
            refresh_token_ttl_secs: default_refresh_token_ttl(),
            algorithm: default_jwt_algorithm(),
        }
    }
}

fn default_jwt_secret() -> String {
    env::var("PISTON_AUTH_JWT_SECRET").unwrap_or_else(|_| {
        // In production, this should be set via environment variable
        "change-me-in-production-this-is-insecure".to_string()
    })
}

fn default_jwt_issuer() -> String {
    "pistonprotection".to_string()
}

fn default_jwt_audience() -> String {
    "pistonprotection-api".to_string()
}

fn default_access_token_ttl() -> u64 {
    3600 // 1 hour
}

fn default_refresh_token_ttl() -> u64 {
    604800 // 7 days
}

fn default_jwt_algorithm() -> String {
    "HS256".to_string()
}

/// Session configuration
#[derive(Debug, Clone, Deserialize)]
pub struct SessionConfig {
    /// Session TTL in seconds
    #[serde(default = "default_session_ttl")]
    pub ttl_secs: u64,

    /// Maximum sessions per user
    #[serde(default = "default_max_sessions")]
    pub max_sessions_per_user: u32,

    /// Enable sliding window for session expiration
    #[serde(default = "default_true")]
    pub sliding_window: bool,

    /// Session cookie name
    #[serde(default = "default_session_cookie_name")]
    pub cookie_name: String,

    /// Session cookie domain
    pub cookie_domain: Option<String>,

    /// Secure cookie (HTTPS only)
    #[serde(default = "default_true")]
    pub cookie_secure: bool,

    /// HTTP only cookie
    #[serde(default = "default_true")]
    pub cookie_http_only: bool,

    /// SameSite cookie attribute
    #[serde(default = "default_same_site")]
    pub cookie_same_site: String,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            ttl_secs: default_session_ttl(),
            max_sessions_per_user: default_max_sessions(),
            sliding_window: true,
            cookie_name: default_session_cookie_name(),
            cookie_domain: None,
            cookie_secure: true,
            cookie_http_only: true,
            cookie_same_site: default_same_site(),
        }
    }
}

fn default_session_ttl() -> u64 {
    86400 // 24 hours
}

fn default_max_sessions() -> u32 {
    10
}

fn default_session_cookie_name() -> String {
    "piston_session".to_string()
}

fn default_same_site() -> String {
    "Lax".to_string()
}

fn default_true() -> bool {
    true
}

/// Password policy configuration
#[derive(Debug, Clone, Deserialize)]
pub struct PasswordConfig {
    /// Minimum password length
    #[serde(default = "default_min_password_length")]
    pub min_length: usize,

    /// Maximum password length
    #[serde(default = "default_max_password_length")]
    pub max_length: usize,

    /// Require uppercase letter
    #[serde(default = "default_true")]
    pub require_uppercase: bool,

    /// Require lowercase letter
    #[serde(default = "default_true")]
    pub require_lowercase: bool,

    /// Require digit
    #[serde(default = "default_true")]
    pub require_digit: bool,

    /// Require special character
    #[serde(default)]
    pub require_special: bool,

    /// Argon2 memory cost (KB)
    #[serde(default = "default_argon2_memory_cost")]
    pub argon2_memory_cost: u32,

    /// Argon2 time cost (iterations)
    #[serde(default = "default_argon2_time_cost")]
    pub argon2_time_cost: u32,

    /// Argon2 parallelism
    #[serde(default = "default_argon2_parallelism")]
    pub argon2_parallelism: u32,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            min_length: default_min_password_length(),
            max_length: default_max_password_length(),
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: false,
            argon2_memory_cost: default_argon2_memory_cost(),
            argon2_time_cost: default_argon2_time_cost(),
            argon2_parallelism: default_argon2_parallelism(),
        }
    }
}

fn default_min_password_length() -> usize {
    8
}

fn default_max_password_length() -> usize {
    128
}

fn default_argon2_memory_cost() -> u32 {
    65536 // 64 MB
}

fn default_argon2_time_cost() -> u32 {
    3
}

fn default_argon2_parallelism() -> u32 {
    4
}

/// API key configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ApiKeyConfig {
    /// API key prefix
    #[serde(default = "default_api_key_prefix")]
    pub prefix: String,

    /// API key length (bytes, before encoding)
    #[serde(default = "default_api_key_length")]
    pub key_length: usize,

    /// Default API key TTL in seconds (0 for no expiration)
    #[serde(default)]
    pub default_ttl_secs: u64,

    /// Maximum API keys per organization
    #[serde(default = "default_max_api_keys")]
    pub max_keys_per_org: u32,
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            prefix: default_api_key_prefix(),
            key_length: default_api_key_length(),
            default_ttl_secs: 0,
            max_keys_per_org: default_max_api_keys(),
        }
    }
}

fn default_api_key_prefix() -> String {
    "psk".to_string() // PistonProtection Secret Key
}

fn default_api_key_length() -> usize {
    32
}

fn default_max_api_keys() -> u32 {
    100
}

/// OAuth providers configuration
#[derive(Debug, Clone, Deserialize, Default)]
pub struct OAuthConfig {
    /// GitHub OAuth configuration
    pub github: Option<OAuthProviderConfig>,

    /// Google OAuth configuration
    pub google: Option<OAuthProviderConfig>,

    /// GitLab OAuth configuration
    pub gitlab: Option<OAuthProviderConfig>,
}

/// OAuth provider configuration
#[derive(Debug, Clone, Deserialize)]
pub struct OAuthProviderConfig {
    /// Client ID
    pub client_id: String,

    /// Client secret
    pub client_secret: String,

    /// Redirect URI
    pub redirect_uri: String,

    /// Authorization URL (optional, for custom providers)
    pub auth_url: Option<String>,

    /// Token URL (optional, for custom providers)
    pub token_url: Option<String>,

    /// User info URL (optional, for custom providers)
    pub user_info_url: Option<String>,

    /// Scopes
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// RBAC configuration
#[derive(Debug, Clone, Deserialize)]
pub struct RbacConfig {
    /// Enable strict RBAC enforcement
    #[serde(default = "default_true")]
    pub strict_mode: bool,

    /// Cache permissions in Redis
    #[serde(default = "default_true")]
    pub cache_permissions: bool,

    /// Permission cache TTL in seconds
    #[serde(default = "default_permission_cache_ttl")]
    pub cache_ttl_secs: u64,

    /// Default role for new organization members
    #[serde(default = "default_member_role")]
    pub default_member_role: String,
}

impl Default for RbacConfig {
    fn default() -> Self {
        Self {
            strict_mode: true,
            cache_permissions: true,
            cache_ttl_secs: default_permission_cache_ttl(),
            default_member_role: default_member_role(),
        }
    }
}

fn default_permission_cache_ttl() -> u64 {
    300 // 5 minutes
}

fn default_member_role() -> String {
    "member".to_string()
}

/// Stripe configuration for billing integration
#[derive(Debug, Clone, Deserialize)]
pub struct StripeConfig {
    /// Stripe secret API key (sk_live_* or sk_test_*)
    #[serde(default = "default_stripe_secret_key")]
    pub secret_key: String,

    /// Stripe publishable API key (pk_live_* or pk_test_*)
    #[serde(default = "default_stripe_publishable_key")]
    pub publishable_key: String,

    /// Stripe webhook signing secret (whsec_*)
    #[serde(default = "default_stripe_webhook_secret")]
    pub webhook_secret: String,

    /// Enable Stripe integration
    #[serde(default)]
    pub enabled: bool,

    /// Test mode (uses test API keys)
    #[serde(default = "default_true")]
    pub test_mode: bool,

    /// Default trial period in days for new subscriptions
    #[serde(default = "default_trial_days")]
    pub default_trial_days: u32,

    /// Plan configuration
    #[serde(default)]
    pub plans: StripePlansConfig,

    /// Checkout configuration
    #[serde(default)]
    pub checkout: StripeCheckoutConfig,

    /// Billing portal configuration
    #[serde(default)]
    pub billing_portal: StripeBillingPortalConfig,
}

impl Default for StripeConfig {
    fn default() -> Self {
        Self {
            secret_key: default_stripe_secret_key(),
            publishable_key: default_stripe_publishable_key(),
            webhook_secret: default_stripe_webhook_secret(),
            enabled: false,
            test_mode: true,
            default_trial_days: default_trial_days(),
            plans: StripePlansConfig::default(),
            checkout: StripeCheckoutConfig::default(),
            billing_portal: StripeBillingPortalConfig::default(),
        }
    }
}

fn default_stripe_secret_key() -> String {
    env::var("STRIPE_SECRET_KEY").unwrap_or_else(|_| String::new())
}

fn default_stripe_publishable_key() -> String {
    env::var("STRIPE_PUBLISHABLE_KEY").unwrap_or_else(|_| String::new())
}

fn default_stripe_webhook_secret() -> String {
    env::var("STRIPE_WEBHOOK_SECRET").unwrap_or_else(|_| String::new())
}

fn default_trial_days() -> u32 {
    14
}

/// Stripe plan IDs configuration
#[derive(Debug, Clone, Deserialize)]
pub struct StripePlansConfig {
    /// Free plan ID (internal, no Stripe product)
    #[serde(default = "default_free_plan_id")]
    pub free_plan_id: String,

    /// Starter plan Stripe product ID
    #[serde(default)]
    pub starter_product_id: Option<String>,

    /// Starter plan monthly price ID
    #[serde(default)]
    pub starter_price_monthly: Option<String>,

    /// Starter plan yearly price ID
    #[serde(default)]
    pub starter_price_yearly: Option<String>,

    /// Pro plan Stripe product ID
    #[serde(default)]
    pub pro_product_id: Option<String>,

    /// Pro plan monthly price ID
    #[serde(default)]
    pub pro_price_monthly: Option<String>,

    /// Pro plan yearly price ID
    #[serde(default)]
    pub pro_price_yearly: Option<String>,

    /// Enterprise plan Stripe product ID
    #[serde(default)]
    pub enterprise_product_id: Option<String>,

    /// Enterprise plan monthly price ID
    #[serde(default)]
    pub enterprise_price_monthly: Option<String>,

    /// Enterprise plan yearly price ID
    #[serde(default)]
    pub enterprise_price_yearly: Option<String>,

    /// Usage-based pricing - requests price ID (per 1000 requests)
    #[serde(default)]
    pub usage_requests_price: Option<String>,

    /// Usage-based pricing - bandwidth price ID (per GB)
    #[serde(default)]
    pub usage_bandwidth_price: Option<String>,
}

impl Default for StripePlansConfig {
    fn default() -> Self {
        Self {
            free_plan_id: default_free_plan_id(),
            starter_product_id: env::var("STRIPE_STARTER_PRODUCT_ID").ok(),
            starter_price_monthly: env::var("STRIPE_STARTER_PRICE_MONTHLY").ok(),
            starter_price_yearly: env::var("STRIPE_STARTER_PRICE_YEARLY").ok(),
            pro_product_id: env::var("STRIPE_PRO_PRODUCT_ID").ok(),
            pro_price_monthly: env::var("STRIPE_PRO_PRICE_MONTHLY").ok(),
            pro_price_yearly: env::var("STRIPE_PRO_PRICE_YEARLY").ok(),
            enterprise_product_id: env::var("STRIPE_ENTERPRISE_PRODUCT_ID").ok(),
            enterprise_price_monthly: env::var("STRIPE_ENTERPRISE_PRICE_MONTHLY").ok(),
            enterprise_price_yearly: env::var("STRIPE_ENTERPRISE_PRICE_YEARLY").ok(),
            usage_requests_price: env::var("STRIPE_USAGE_REQUESTS_PRICE").ok(),
            usage_bandwidth_price: env::var("STRIPE_USAGE_BANDWIDTH_PRICE").ok(),
        }
    }
}

fn default_free_plan_id() -> String {
    "plan_free".to_string()
}

/// Stripe checkout configuration
#[derive(Debug, Clone, Deserialize)]
pub struct StripeCheckoutConfig {
    /// Success URL after checkout completion
    #[serde(default = "default_checkout_success_url")]
    pub success_url: String,

    /// Cancel URL if checkout is canceled
    #[serde(default = "default_checkout_cancel_url")]
    pub cancel_url: String,

    /// Allow promotion codes in checkout
    #[serde(default = "default_true")]
    pub allow_promotion_codes: bool,

    /// Collect billing address
    #[serde(default)]
    pub collect_billing_address: bool,

    /// Collect shipping address
    #[serde(default)]
    pub collect_shipping_address: bool,

    /// Automatic tax calculation
    #[serde(default)]
    pub automatic_tax: bool,

    /// Checkout session expiration in seconds (default: 24 hours)
    #[serde(default = "default_checkout_expiration")]
    pub expiration_seconds: u64,
}

impl Default for StripeCheckoutConfig {
    fn default() -> Self {
        Self {
            success_url: default_checkout_success_url(),
            cancel_url: default_checkout_cancel_url(),
            allow_promotion_codes: true,
            collect_billing_address: false,
            collect_shipping_address: false,
            automatic_tax: false,
            expiration_seconds: default_checkout_expiration(),
        }
    }
}

fn default_checkout_success_url() -> String {
    env::var("STRIPE_CHECKOUT_SUCCESS_URL")
        .unwrap_or_else(|_| "https://app.pistonprotection.com/billing/success".to_string())
}

fn default_checkout_cancel_url() -> String {
    env::var("STRIPE_CHECKOUT_CANCEL_URL")
        .unwrap_or_else(|_| "https://app.pistonprotection.com/billing/cancel".to_string())
}

fn default_checkout_expiration() -> u64 {
    86400 // 24 hours
}

/// Stripe billing portal configuration
#[derive(Debug, Clone, Deserialize)]
pub struct StripeBillingPortalConfig {
    /// Return URL after exiting billing portal
    #[serde(default = "default_billing_portal_return_url")]
    pub return_url: String,

    /// Allow customers to cancel subscriptions
    #[serde(default = "default_true")]
    pub allow_cancel: bool,

    /// Allow customers to update payment methods
    #[serde(default = "default_true")]
    pub allow_update_payment_method: bool,

    /// Allow customers to update subscription
    #[serde(default = "default_true")]
    pub allow_update_subscription: bool,

    /// Allow customers to view invoice history
    #[serde(default = "default_true")]
    pub allow_view_invoices: bool,
}

impl Default for StripeBillingPortalConfig {
    fn default() -> Self {
        Self {
            return_url: default_billing_portal_return_url(),
            allow_cancel: true,
            allow_update_payment_method: true,
            allow_update_subscription: true,
            allow_view_invoices: true,
        }
    }
}

fn default_billing_portal_return_url() -> String {
    env::var("STRIPE_BILLING_PORTAL_RETURN_URL")
        .unwrap_or_else(|_| "https://app.pistonprotection.com/settings/billing".to_string())
}

impl StripeConfig {
    /// Check if Stripe is properly configured
    pub fn is_configured(&self) -> bool {
        self.enabled && !self.secret_key.is_empty() && !self.webhook_secret.is_empty()
    }

    /// Get the appropriate API key based on mode
    pub fn api_key(&self) -> &str {
        &self.secret_key
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        if self.secret_key.is_empty() {
            return Err("Stripe secret key is required when Stripe is enabled".to_string());
        }

        if self.webhook_secret.is_empty() {
            return Err("Stripe webhook secret is required when Stripe is enabled".to_string());
        }

        // Validate key format
        if !self.secret_key.starts_with("sk_test_") && !self.secret_key.starts_with("sk_live_") {
            return Err("Invalid Stripe secret key format".to_string());
        }

        if self.test_mode && self.secret_key.starts_with("sk_live_") {
            return Err("Test mode is enabled but using live API key".to_string());
        }

        if !self.test_mode && self.secret_key.starts_with("sk_test_") {
            return Err("Live mode is enabled but using test API key".to_string());
        }

        Ok(())
    }
}

impl AuthConfig {
    /// Load auth configuration from environment and files
    pub fn load() -> Result<Self, config::ConfigError> {
        let config_builder = config::Config::builder()
            // Load from auth config file
            .add_source(config::File::with_name("config/auth").required(false))
            // Override with environment variables (prefix: PISTON_AUTH_)
            .add_source(
                config::Environment::with_prefix("PISTON_AUTH")
                    .separator("__")
                    .try_parsing(true),
            );

        let cfg = config_builder.build()?;

        // Try to deserialize, fall back to defaults
        cfg.try_deserialize().or_else(|_| Ok(AuthConfig::default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AuthConfig::default();
        assert_eq!(config.jwt.access_token_ttl_secs, 3600);
        assert_eq!(config.session.ttl_secs, 86400);
        assert_eq!(config.password.min_length, 8);
        assert_eq!(config.api_key.prefix, "psk");
    }

    #[test]
    fn test_jwt_config_defaults() {
        let jwt = JwtConfig::default();
        assert_eq!(jwt.issuer, "pistonprotection");
        assert_eq!(jwt.algorithm, "HS256");
    }

    #[test]
    fn test_stripe_config_defaults() {
        let stripe = StripeConfig::default();
        assert!(!stripe.enabled);
        assert!(stripe.test_mode);
        assert_eq!(stripe.default_trial_days, 14);
        assert!(stripe.checkout.allow_promotion_codes);
    }

    #[test]
    fn test_stripe_config_validation() {
        // Empty config should be valid (disabled)
        let config = StripeConfig::default();
        assert!(config.validate().is_ok());

        // Enabled without keys should fail
        let mut config = StripeConfig::default();
        config.enabled = true;
        assert!(config.validate().is_err());

        // Enabled with test key in test mode should pass
        let mut config = StripeConfig::default();
        config.enabled = true;
        config.secret_key = "sk_test_1234567890".to_string();
        config.webhook_secret = "whsec_1234567890".to_string();
        config.test_mode = true;
        assert!(config.validate().is_ok());

        // Live key in test mode should fail
        let mut config = StripeConfig::default();
        config.enabled = true;
        config.secret_key = "sk_live_1234567890".to_string();
        config.webhook_secret = "whsec_1234567890".to_string();
        config.test_mode = true;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_stripe_is_configured() {
        let mut config = StripeConfig::default();
        assert!(!config.is_configured());

        config.enabled = true;
        assert!(!config.is_configured()); // Missing keys

        config.secret_key = "sk_test_123".to_string();
        assert!(!config.is_configured()); // Missing webhook secret

        config.webhook_secret = "whsec_123".to_string();
        assert!(config.is_configured());
    }
}
