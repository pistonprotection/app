//! Subscription and billing model definitions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::fmt;

/// Subscription plan types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "plan_type", rename_all = "lowercase")]
#[derive(Default)]
pub enum PlanType {
    #[default]
    Free,
    Starter,
    Pro,
    Enterprise,
}

impl fmt::Display for PlanType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlanType::Free => write!(f, "Free"),
            PlanType::Starter => write!(f, "Starter"),
            PlanType::Pro => write!(f, "Pro"),
            PlanType::Enterprise => write!(f, "Enterprise"),
        }
    }
}

impl From<PlanType> for i32 {
    fn from(plan: PlanType) -> Self {
        match plan {
            PlanType::Free => 0,
            PlanType::Starter => 1,
            PlanType::Pro => 2,
            PlanType::Enterprise => 3,
        }
    }
}

impl TryFrom<i32> for PlanType {
    type Error = &'static str;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PlanType::Free),
            1 => Ok(PlanType::Starter),
            2 => Ok(PlanType::Pro),
            3 => Ok(PlanType::Enterprise),
            _ => Err("Invalid plan type"),
        }
    }
}

impl PlanType {
    /// Get the Stripe price ID for this plan (monthly)
    pub fn stripe_price_id_monthly(&self) -> Option<&'static str> {
        match self {
            PlanType::Free => None,
            PlanType::Starter => Some("price_starter_monthly"),
            PlanType::Pro => Some("price_pro_monthly"),
            PlanType::Enterprise => Some("price_enterprise_monthly"),
        }
    }

    /// Get the Stripe price ID for this plan (yearly)
    pub fn stripe_price_id_yearly(&self) -> Option<&'static str> {
        match self {
            PlanType::Free => None,
            PlanType::Starter => Some("price_starter_yearly"),
            PlanType::Pro => Some("price_pro_yearly"),
            PlanType::Enterprise => Some("price_enterprise_yearly"),
        }
    }

    /// Get default limits for this plan
    pub fn default_limits(&self) -> PlanLimits {
        match self {
            PlanType::Free => PlanLimits {
                max_backends: 1,
                max_origins_per_backend: 1,
                max_domains: 1,
                max_filter_rules: 5,
                max_bandwidth_bytes: 1_073_741_824, // 1 GB
                max_requests: 100_000,
                advanced_protection: false,
                priority_support: false,
                custom_ssl: false,
                api_access: false,
                data_retention_days: 1,
            },
            PlanType::Starter => PlanLimits {
                max_backends: 3,
                max_origins_per_backend: 2,
                max_domains: 5,
                max_filter_rules: 20,
                max_bandwidth_bytes: 10_737_418_240, // 10 GB
                max_requests: 1_000_000,
                advanced_protection: false,
                priority_support: false,
                custom_ssl: false,
                api_access: true,
                data_retention_days: 7,
            },
            PlanType::Pro => PlanLimits {
                max_backends: 10,
                max_origins_per_backend: 5,
                max_domains: 20,
                max_filter_rules: 100,
                max_bandwidth_bytes: 107_374_182_400, // 100 GB
                max_requests: 10_000_000,
                advanced_protection: true,
                priority_support: false,
                custom_ssl: true,
                api_access: true,
                data_retention_days: 30,
            },
            PlanType::Enterprise => PlanLimits {
                max_backends: 100,
                max_origins_per_backend: 20,
                max_domains: 100,
                max_filter_rules: 1000,
                max_bandwidth_bytes: 1_099_511_627_776, // 1 TB
                max_requests: 100_000_000,
                advanced_protection: true,
                priority_support: true,
                custom_ssl: true,
                api_access: true,
                data_retention_days: 365,
            },
        }
    }
}

/// Plan limits structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanLimits {
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
}

/// Billing period
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "billing_period", rename_all = "lowercase")]
#[derive(Default)]
pub enum BillingPeriod {
    #[default]
    Monthly,
    Yearly,
}

impl From<BillingPeriod> for i32 {
    fn from(period: BillingPeriod) -> Self {
        match period {
            BillingPeriod::Monthly => 1,
            BillingPeriod::Yearly => 2,
        }
    }
}

impl TryFrom<i32> for BillingPeriod {
    type Error = &'static str;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(BillingPeriod::Monthly),
            2 => Ok(BillingPeriod::Yearly),
            _ => Err("Invalid billing period"),
        }
    }
}

/// Invoice status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "invoice_status", rename_all = "lowercase")]
#[derive(Default)]
pub enum InvoiceStatus {
    #[default]
    Draft,
    Open,
    Paid,
    Uncollectible,
    Void,
}

impl From<InvoiceStatus> for i32 {
    fn from(status: InvoiceStatus) -> Self {
        match status {
            InvoiceStatus::Draft => 1,
            InvoiceStatus::Open => 2,
            InvoiceStatus::Paid => 3,
            InvoiceStatus::Uncollectible => 4,
            InvoiceStatus::Void => 5,
        }
    }
}

impl TryFrom<i32> for InvoiceStatus {
    type Error = &'static str;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(InvoiceStatus::Draft),
            2 => Ok(InvoiceStatus::Open),
            3 => Ok(InvoiceStatus::Paid),
            4 => Ok(InvoiceStatus::Uncollectible),
            5 => Ok(InvoiceStatus::Void),
            _ => Err("Invalid invoice status"),
        }
    }
}

impl InvoiceStatus {
    /// Convert from Stripe invoice status string
    pub fn from_stripe_status(status: &str) -> Self {
        match status {
            "draft" => InvoiceStatus::Draft,
            "open" => InvoiceStatus::Open,
            "paid" => InvoiceStatus::Paid,
            "uncollectible" => InvoiceStatus::Uncollectible,
            "void" => InvoiceStatus::Void,
            _ => InvoiceStatus::Draft,
        }
    }
}

/// Payment intent status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "payment_status", rename_all = "lowercase")]
#[derive(Default)]
pub enum PaymentStatus {
    #[default]
    RequiresPaymentMethod,
    RequiresConfirmation,
    RequiresAction,
    Processing,
    Succeeded,
    Canceled,
    RequiresCapture,
}

impl PaymentStatus {
    /// Convert from Stripe payment intent status string
    pub fn from_stripe_status(status: &str) -> Self {
        match status {
            "requires_payment_method" => PaymentStatus::RequiresPaymentMethod,
            "requires_confirmation" => PaymentStatus::RequiresConfirmation,
            "requires_action" => PaymentStatus::RequiresAction,
            "processing" => PaymentStatus::Processing,
            "succeeded" => PaymentStatus::Succeeded,
            "canceled" => PaymentStatus::Canceled,
            "requires_capture" => PaymentStatus::RequiresCapture,
            _ => PaymentStatus::RequiresPaymentMethod,
        }
    }
}

/// Subscription plan definition
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Plan {
    pub id: String,
    pub name: String,
    pub plan_type: PlanType,
    pub description: Option<String>,
    pub stripe_product_id: Option<String>,
    pub stripe_price_id_monthly: Option<String>,
    pub stripe_price_id_yearly: Option<String>,
    pub price_monthly_cents: i64,
    pub price_yearly_cents: i64,
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
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Extended subscription model with additional billing fields
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SubscriptionDetails {
    pub id: String,
    pub organization_id: String,
    pub plan_id: String,
    pub plan_name: String,
    pub plan_type: PlanType,
    pub status: super::SubscriptionStatus,
    pub billing_period: BillingPeriod,
    pub stripe_customer_id: Option<String>,
    pub stripe_subscription_id: Option<String>,
    pub stripe_payment_method_id: Option<String>,
    pub current_period_start: DateTime<Utc>,
    pub current_period_end: DateTime<Utc>,
    pub in_trial: bool,
    pub trial_ends_at: Option<DateTime<Utc>>,
    pub cancel_at_period_end: bool,
    pub canceled_at: Option<DateTime<Utc>>,
    pub cancellation_reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Invoice history entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Invoice {
    pub id: String,
    pub organization_id: String,
    pub subscription_id: String,
    pub stripe_invoice_id: Option<String>,
    pub stripe_payment_intent_id: Option<String>,
    pub number: Option<String>,
    pub status: InvoiceStatus,
    pub currency: String,
    pub subtotal_cents: i64,
    pub tax_cents: i64,
    pub total_cents: i64,
    pub amount_paid_cents: i64,
    pub amount_due_cents: i64,
    pub description: Option<String>,
    pub invoice_pdf_url: Option<String>,
    pub hosted_invoice_url: Option<String>,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub due_date: Option<DateTime<Utc>>,
    pub paid_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Usage tracking entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UsageRecord {
    pub id: String,
    pub organization_id: String,
    pub subscription_id: String,
    pub metric_type: UsageMetricType,
    pub quantity: i64,
    pub timestamp: DateTime<Utc>,
    pub stripe_usage_record_id: Option<String>,
    pub idempotency_key: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Usage metric types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "usage_metric_type", rename_all = "snake_case")]
#[derive(Default)]
pub enum UsageMetricType {
    #[default]
    Requests,
    BandwidthBytes,
    BlockedRequests,
    ChallengesServed,
}

impl From<UsageMetricType> for i32 {
    fn from(metric: UsageMetricType) -> Self {
        match metric {
            UsageMetricType::Requests => 1,
            UsageMetricType::BandwidthBytes => 2,
            UsageMetricType::BlockedRequests => 3,
            UsageMetricType::ChallengesServed => 4,
        }
    }
}

impl TryFrom<i32> for UsageMetricType {
    type Error = &'static str;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(UsageMetricType::Requests),
            2 => Ok(UsageMetricType::BandwidthBytes),
            3 => Ok(UsageMetricType::BlockedRequests),
            4 => Ok(UsageMetricType::ChallengesServed),
            _ => Err("Invalid usage metric type"),
        }
    }
}

/// Monthly usage summary
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UsageSummary {
    pub id: String,
    pub organization_id: String,
    pub subscription_id: String,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub total_requests: i64,
    pub total_bandwidth_bytes: i64,
    pub total_blocked_requests: i64,
    pub total_challenges_served: i64,
    pub overage_requests: i64,
    pub overage_bandwidth_bytes: i64,
    pub overage_charges_cents: i64,
    pub reported_to_stripe: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Payment method stored for an organization
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PaymentMethod {
    pub id: String,
    pub organization_id: String,
    pub stripe_payment_method_id: String,
    pub payment_type: String, // card, bank_account, etc.
    pub card_brand: Option<String>,
    pub card_last4: Option<String>,
    pub card_exp_month: Option<i32>,
    pub card_exp_year: Option<i32>,
    pub is_default: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Checkout session request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCheckoutSessionRequest {
    pub organization_id: String,
    pub plan_id: String,
    pub billing_period: BillingPeriod,
    pub success_url: String,
    pub cancel_url: String,
    pub allow_promotion_codes: bool,
}

/// Billing portal session request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateBillingPortalSessionRequest {
    pub organization_id: String,
    pub return_url: String,
}

/// Subscription update request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSubscriptionRequest {
    pub plan_id: Option<String>,
    pub billing_period: Option<BillingPeriod>,
    pub proration_behavior: Option<ProrationBehavior>,
}

/// Proration behavior for subscription changes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ProrationBehavior {
    #[default]
    CreateProrations,
    None,
    AlwaysInvoice,
}

impl ProrationBehavior {
    pub fn as_stripe_str(&self) -> &'static str {
        match self {
            ProrationBehavior::CreateProrations => "create_prorations",
            ProrationBehavior::None => "none",
            ProrationBehavior::AlwaysInvoice => "always_invoice",
        }
    }
}

/// Subscription cancellation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelSubscriptionRequest {
    pub cancel_at_period_end: bool,
    pub cancellation_reason: Option<String>,
    pub feedback: Option<String>,
}

/// Convert subscription details to proto
impl SubscriptionDetails {
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

/// Convert Plan to proto
impl Plan {
    pub fn to_proto(&self) -> pistonprotection_proto::auth::Plan {
        use pistonprotection_proto::auth::Plan as ProtoPlan;

        ProtoPlan {
            id: self.id.clone(),
            name: self.name.clone(),
            plan_type: i32::from(self.plan_type),
            description: self.description.clone().unwrap_or_default(),
            price_monthly_cents: self.price_monthly_cents,
            price_yearly_cents: self.price_yearly_cents,
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
            is_active: self.is_active,
        }
    }
}

/// Convert Invoice to proto
impl Invoice {
    pub fn to_proto(&self) -> pistonprotection_proto::auth::Invoice {
        use pistonprotection_proto::Timestamp;
        use pistonprotection_proto::auth::Invoice as ProtoInvoice;

        ProtoInvoice {
            id: self.id.clone(),
            organization_id: self.organization_id.clone(),
            subscription_id: self.subscription_id.clone(),
            stripe_invoice_id: self.stripe_invoice_id.clone().unwrap_or_default(),
            number: self.number.clone().unwrap_or_default(),
            status: i32::from(self.status),
            currency: self.currency.clone(),
            subtotal_cents: self.subtotal_cents,
            tax_cents: self.tax_cents,
            total_cents: self.total_cents,
            amount_paid_cents: self.amount_paid_cents,
            amount_due_cents: self.amount_due_cents,
            description: self.description.clone().unwrap_or_default(),
            invoice_pdf_url: self.invoice_pdf_url.clone().unwrap_or_default(),
            hosted_invoice_url: self.hosted_invoice_url.clone().unwrap_or_default(),
            period_start: Some(Timestamp::from(self.period_start)),
            period_end: Some(Timestamp::from(self.period_end)),
            due_date: self.due_date.map(Timestamp::from),
            paid_at: self.paid_at.map(Timestamp::from),
            created_at: Some(Timestamp::from(self.created_at)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plan_type_conversion() {
        assert_eq!(i32::from(PlanType::Free), 0);
        assert_eq!(i32::from(PlanType::Starter), 1);
        assert_eq!(i32::from(PlanType::Pro), 2);
        assert_eq!(i32::from(PlanType::Enterprise), 3);

        assert_eq!(PlanType::try_from(0).unwrap(), PlanType::Free);
        assert_eq!(PlanType::try_from(1).unwrap(), PlanType::Starter);
        assert_eq!(PlanType::try_from(2).unwrap(), PlanType::Pro);
        assert_eq!(PlanType::try_from(3).unwrap(), PlanType::Enterprise);
    }

    #[test]
    fn test_plan_limits() {
        let free_limits = PlanType::Free.default_limits();
        assert_eq!(free_limits.max_backends, 1);
        assert!(!free_limits.api_access);

        let pro_limits = PlanType::Pro.default_limits();
        assert_eq!(pro_limits.max_backends, 10);
        assert!(pro_limits.advanced_protection);
    }

    #[test]
    fn test_invoice_status_from_stripe() {
        assert_eq!(
            InvoiceStatus::from_stripe_status("paid"),
            InvoiceStatus::Paid
        );
        assert_eq!(
            InvoiceStatus::from_stripe_status("open"),
            InvoiceStatus::Open
        );
        assert_eq!(
            InvoiceStatus::from_stripe_status("unknown"),
            InvoiceStatus::Draft
        );
    }
}
