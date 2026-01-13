//! Dunning service for handling failed payment recovery
//!
//! Implements a multi-step dunning process to recover failed payments:
//! 1. Initial retry after 1 day
//! 2. Second retry after 3 days with email notification
//! 3. Third retry after 5 days with warning email
//! 4. Final notice after 7 days before account downgrade
//! 5. Account downgrade after 10 days if payment not recovered

use crate::models::SubscriptionStatus;
use crate::services::email::{EmailRecipient, EmailService};
use crate::services::stripe::StripeService;
use chrono::{DateTime, Duration, Utc};
use pistonprotection_common::error::{Error, Result};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Dunning configuration
#[derive(Debug, Clone)]
pub struct DunningConfig {
    /// Days before first retry
    pub first_retry_days: i64,
    /// Days before second retry
    pub second_retry_days: i64,
    /// Days before third retry
    pub third_retry_days: i64,
    /// Days before final notice
    pub final_notice_days: i64,
    /// Days before account downgrade
    pub downgrade_days: i64,
    /// Maximum retry attempts
    pub max_retry_attempts: i32,
}

impl Default for DunningConfig {
    fn default() -> Self {
        Self {
            first_retry_days: 1,
            second_retry_days: 3,
            third_retry_days: 5,
            final_notice_days: 7,
            downgrade_days: 10,
            max_retry_attempts: 4,
        }
    }
}

/// Dunning state for a subscription
#[derive(Debug, Clone, sqlx::Type, PartialEq, Eq)]
#[sqlx(type_name = "dunning_state", rename_all = "snake_case")]
pub enum DunningState {
    None,
    FirstRetry,
    SecondRetry,
    ThirdRetry,
    FinalNotice,
    Downgraded,
}

impl std::fmt::Display for DunningState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DunningState::None => write!(f, "none"),
            DunningState::FirstRetry => write!(f, "first_retry"),
            DunningState::SecondRetry => write!(f, "second_retry"),
            DunningState::ThirdRetry => write!(f, "third_retry"),
            DunningState::FinalNotice => write!(f, "final_notice"),
            DunningState::Downgraded => write!(f, "downgraded"),
        }
    }
}

/// Dunning record for tracking payment recovery
#[derive(Debug, Clone)]
pub struct DunningRecord {
    pub id: String,
    pub subscription_id: String,
    pub organization_id: String,
    pub invoice_id: String,
    pub state: DunningState,
    pub attempt_count: i32,
    pub first_failed_at: DateTime<Utc>,
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub next_attempt_at: Option<DateTime<Utc>>,
    pub last_email_sent_at: Option<DateTime<Utc>>,
    pub amount_due: i64,
    pub currency: String,
    pub resolved_at: Option<DateTime<Utc>>,
    pub downgraded_at: Option<DateTime<Utc>>,
}

/// Dunning service for payment recovery
pub struct DunningService {
    db: PgPool,
    stripe_service: Arc<StripeService>,
    email_service: Arc<EmailService>,
    config: DunningConfig,
}

impl DunningService {
    /// Create a new dunning service
    pub fn new(
        db: PgPool,
        stripe_service: Arc<StripeService>,
        email_service: Arc<EmailService>,
        config: DunningConfig,
    ) -> Self {
        Self {
            db,
            stripe_service,
            email_service,
            config,
        }
    }

    /// Start dunning process for a failed invoice
    pub async fn start_dunning(
        &self,
        subscription_id: &str,
        organization_id: &str,
        invoice_id: &str,
        amount_due: i64,
        currency: &str,
    ) -> Result<DunningRecord> {
        info!(
            subscription_id = %subscription_id,
            invoice_id = %invoice_id,
            amount_due = amount_due,
            "Starting dunning process"
        );

        let now = Utc::now();
        let next_attempt = now + Duration::days(self.config.first_retry_days);
        let record_id = uuid::Uuid::new_v4().to_string();

        sqlx::query(
            r#"
            INSERT INTO dunning_records (
                id, subscription_id, organization_id, invoice_id, state,
                attempt_count, first_failed_at, next_attempt_at,
                amount_due, currency, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now(), now())
            ON CONFLICT (invoice_id) DO UPDATE SET
                attempt_count = dunning_records.attempt_count + 1,
                updated_at = now()
            "#,
        )
        .bind(&record_id)
        .bind(subscription_id)
        .bind(organization_id)
        .bind(invoice_id)
        .bind("first_retry")
        .bind(1)
        .bind(now)
        .bind(next_attempt)
        .bind(amount_due)
        .bind(currency)
        .execute(&self.db)
        .await?;

        let record = DunningRecord {
            id: record_id,
            subscription_id: subscription_id.to_string(),
            organization_id: organization_id.to_string(),
            invoice_id: invoice_id.to_string(),
            state: DunningState::FirstRetry,
            attempt_count: 1,
            first_failed_at: now,
            last_attempt_at: Some(now),
            next_attempt_at: Some(next_attempt),
            last_email_sent_at: None,
            amount_due,
            currency: currency.to_string(),
            resolved_at: None,
            downgraded_at: None,
        };

        // Send initial payment failed email
        if let Err(e) = self.send_payment_failed_notification(&record, 1).await {
            warn!(error = %e, "Failed to send payment failed notification");
        }

        Ok(record)
    }

    /// Process pending dunning records
    pub async fn process_pending_dunning(&self) -> Result<ProcessingStats> {
        let mut stats = ProcessingStats::default();
        let now = Utc::now();

        // Get all active dunning records that need processing
        let records = sqlx::query(
            r#"
            SELECT
                id, subscription_id, organization_id, invoice_id, state,
                attempt_count, first_failed_at, last_attempt_at, next_attempt_at,
                last_email_sent_at, amount_due, currency
            FROM dunning_records
            WHERE resolved_at IS NULL
              AND downgraded_at IS NULL
              AND (next_attempt_at IS NULL OR next_attempt_at <= $1)
            ORDER BY first_failed_at ASC
            "#,
        )
        .bind(now)
        .fetch_all(&self.db)
        .await?;

        info!(count = records.len(), "Processing pending dunning records");

        for row in records {
            let state_str: String = row.get("state");
            let record = DunningRecord {
                id: row.get("id"),
                subscription_id: row.get("subscription_id"),
                organization_id: row.get("organization_id"),
                invoice_id: row.get("invoice_id"),
                state: parse_dunning_state(&state_str),
                attempt_count: row.get("attempt_count"),
                first_failed_at: row.get("first_failed_at"),
                last_attempt_at: row.get("last_attempt_at"),
                next_attempt_at: row.get("next_attempt_at"),
                last_email_sent_at: row.get("last_email_sent_at"),
                amount_due: row.get("amount_due"),
                currency: row.get("currency"),
                resolved_at: None,
                downgraded_at: None,
            };

            match self.process_record(&record).await {
                Ok(outcome) => match outcome {
                    DunningOutcome::PaymentRecovered => stats.recovered += 1,
                    DunningOutcome::RetryScheduled => stats.retried += 1,
                    DunningOutcome::Downgraded => stats.downgraded += 1,
                    DunningOutcome::NoAction => {}
                },
                Err(e) => {
                    error!(
                        record_id = %record.id,
                        error = %e,
                        "Failed to process dunning record"
                    );
                    stats.errors += 1;
                }
            }
        }

        Ok(stats)
    }

    /// Process a single dunning record
    async fn process_record(&self, record: &DunningRecord) -> Result<DunningOutcome> {
        let now = Utc::now();
        let days_since_first_failure = (now - record.first_failed_at).num_days();

        debug!(
            record_id = %record.id,
            state = %record.state,
            days_since_failure = days_since_first_failure,
            "Processing dunning record"
        );

        // Check if we should downgrade
        if days_since_first_failure >= self.config.downgrade_days {
            return self.downgrade_account(record).await;
        }

        // Attempt payment retry via Stripe
        match self.attempt_payment_retry(record).await {
            Ok(true) => {
                // Payment successful!
                self.resolve_dunning(record).await?;
                return Ok(DunningOutcome::PaymentRecovered);
            }
            Ok(false) => {
                // Payment failed again
            }
            Err(e) => {
                warn!(error = %e, record_id = %record.id, "Payment retry error");
            }
        }

        // Update state based on days elapsed
        let new_state = if days_since_first_failure >= self.config.final_notice_days {
            DunningState::FinalNotice
        } else if days_since_first_failure >= self.config.third_retry_days {
            DunningState::ThirdRetry
        } else if days_since_first_failure >= self.config.second_retry_days {
            DunningState::SecondRetry
        } else {
            DunningState::FirstRetry
        };

        // Send appropriate notification if state changed
        if new_state != record.state {
            let attempt = match new_state {
                DunningState::FirstRetry => 1,
                DunningState::SecondRetry => 2,
                DunningState::ThirdRetry => 3,
                DunningState::FinalNotice => 4,
                _ => record.attempt_count,
            };

            if let Err(e) = self.send_payment_failed_notification(record, attempt).await {
                warn!(error = %e, "Failed to send dunning notification");
            }
        }

        // Calculate next attempt time
        let next_attempt = calculate_next_attempt(days_since_first_failure, &self.config);

        // Update record
        sqlx::query(
            r#"
            UPDATE dunning_records
            SET state = $1,
                attempt_count = attempt_count + 1,
                last_attempt_at = $2,
                next_attempt_at = $3,
                updated_at = now()
            WHERE id = $4
            "#,
        )
        .bind(new_state.to_string())
        .bind(now)
        .bind(next_attempt)
        .bind(&record.id)
        .execute(&self.db)
        .await?;

        Ok(DunningOutcome::RetryScheduled)
    }

    /// Attempt to retry the payment via Stripe
    async fn attempt_payment_retry(&self, record: &DunningRecord) -> Result<bool> {
        // In a real implementation, this would call Stripe's API to retry the invoice
        // For now, we simulate checking if the invoice was paid
        info!(
            invoice_id = %record.invoice_id,
            "Attempting payment retry"
        );

        // TODO: Implement actual Stripe invoice retry
        // let result = self.stripe_service.retry_invoice(&record.invoice_id).await?;
        // return Ok(result.paid);

        Ok(false)
    }

    /// Mark dunning as resolved (payment recovered)
    async fn resolve_dunning(&self, record: &DunningRecord) -> Result<()> {
        info!(
            record_id = %record.id,
            subscription_id = %record.subscription_id,
            "Dunning resolved - payment recovered"
        );

        sqlx::query(
            r#"
            UPDATE dunning_records
            SET resolved_at = now(),
                state = 'none',
                updated_at = now()
            WHERE id = $1
            "#,
        )
        .bind(&record.id)
        .execute(&self.db)
        .await?;

        // Update subscription status back to active
        self.stripe_service
            .update_subscription_status(&record.subscription_id, SubscriptionStatus::Active)
            .await?;

        Ok(())
    }

    /// Downgrade account due to non-payment
    async fn downgrade_account(&self, record: &DunningRecord) -> Result<DunningOutcome> {
        warn!(
            record_id = %record.id,
            organization_id = %record.organization_id,
            "Downgrading account due to non-payment"
        );

        // Update dunning record
        sqlx::query(
            r#"
            UPDATE dunning_records
            SET downgraded_at = now(),
                state = 'downgraded',
                updated_at = now()
            WHERE id = $1
            "#,
        )
        .bind(&record.id)
        .execute(&self.db)
        .await?;

        // Cancel the subscription
        self.stripe_service
            .update_subscription_status(&record.subscription_id, SubscriptionStatus::Unpaid)
            .await?;

        // Downgrade organization to free tier
        sqlx::query(
            r#"
            UPDATE organizations
            SET plan_id = (SELECT id FROM plans WHERE name = 'Free' LIMIT 1),
                updated_at = now()
            WHERE id = $1
            "#,
        )
        .bind(&record.organization_id)
        .execute(&self.db)
        .await?;

        // Send downgrade notification
        if let Err(e) = self.send_downgrade_notification(record).await {
            warn!(error = %e, "Failed to send downgrade notification");
        }

        Ok(DunningOutcome::Downgraded)
    }

    /// Send payment failed notification email
    async fn send_payment_failed_notification(
        &self,
        record: &DunningRecord,
        attempt: i32,
    ) -> Result<()> {
        // Get organization email
        let row = sqlx::query(
            r#"
            SELECT u.email, u.name
            FROM organizations o
            JOIN users u ON u.id = o.owner_id
            WHERE o.id = $1
            "#,
        )
        .bind(&record.organization_id)
        .fetch_optional(&self.db)
        .await?;

        let (email, name): (String, Option<String>) = match row {
            Some(r) => (r.get("email"), r.get("name")),
            None => return Err(Error::not_found("Organization", &record.organization_id)),
        };

        let amount = format_currency(record.amount_due, &record.currency);
        let failure_reason = "Card declined"; // In real impl, get from Stripe

        let recipient = EmailRecipient { email, name };

        self.email_service
            .send_payment_failed_email(recipient, &amount, failure_reason, attempt as u32)
            .await?;

        // Update last email sent time
        sqlx::query(
            r#"
            UPDATE dunning_records
            SET last_email_sent_at = now(), updated_at = now()
            WHERE id = $1
            "#,
        )
        .bind(&record.id)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Send account downgrade notification
    async fn send_downgrade_notification(&self, record: &DunningRecord) -> Result<()> {
        // Get organization email
        let row = sqlx::query(
            r#"
            SELECT u.email, u.name
            FROM organizations o
            JOIN users u ON u.id = o.owner_id
            WHERE o.id = $1
            "#,
        )
        .bind(&record.organization_id)
        .fetch_optional(&self.db)
        .await?;

        let (email, name): (String, Option<String>) = match row {
            Some(r) => (r.get("email"), r.get("name")),
            None => return Err(Error::not_found("Organization", &record.organization_id)),
        };

        let recipient = EmailRecipient { email, name };

        self.email_service
            .send_account_downgraded_email(recipient)
            .await?;

        Ok(())
    }

    /// Get active dunning records for an organization
    pub async fn get_active_dunning(&self, organization_id: &str) -> Result<Vec<DunningRecord>> {
        let rows = sqlx::query(
            r#"
            SELECT
                id, subscription_id, organization_id, invoice_id, state,
                attempt_count, first_failed_at, last_attempt_at, next_attempt_at,
                last_email_sent_at, amount_due, currency, resolved_at, downgraded_at
            FROM dunning_records
            WHERE organization_id = $1
              AND resolved_at IS NULL
              AND downgraded_at IS NULL
            ORDER BY first_failed_at DESC
            "#,
        )
        .bind(organization_id)
        .fetch_all(&self.db)
        .await?;

        let records = rows
            .into_iter()
            .map(|row| {
                let state_str: String = row.get("state");
                DunningRecord {
                    id: row.get("id"),
                    subscription_id: row.get("subscription_id"),
                    organization_id: row.get("organization_id"),
                    invoice_id: row.get("invoice_id"),
                    state: parse_dunning_state(&state_str),
                    attempt_count: row.get("attempt_count"),
                    first_failed_at: row.get("first_failed_at"),
                    last_attempt_at: row.get("last_attempt_at"),
                    next_attempt_at: row.get("next_attempt_at"),
                    last_email_sent_at: row.get("last_email_sent_at"),
                    amount_due: row.get("amount_due"),
                    currency: row.get("currency"),
                    resolved_at: row.get("resolved_at"),
                    downgraded_at: row.get("downgraded_at"),
                }
            })
            .collect();

        Ok(records)
    }
}

/// Processing statistics
#[derive(Debug, Default)]
pub struct ProcessingStats {
    pub recovered: usize,
    pub retried: usize,
    pub downgraded: usize,
    pub errors: usize,
}

/// Dunning processing outcome
#[derive(Debug)]
enum DunningOutcome {
    PaymentRecovered,
    RetryScheduled,
    Downgraded,
    NoAction,
}

/// Parse dunning state from string
fn parse_dunning_state(s: &str) -> DunningState {
    match s {
        "first_retry" => DunningState::FirstRetry,
        "second_retry" => DunningState::SecondRetry,
        "third_retry" => DunningState::ThirdRetry,
        "final_notice" => DunningState::FinalNotice,
        "downgraded" => DunningState::Downgraded,
        _ => DunningState::None,
    }
}

/// Calculate next retry attempt time
fn calculate_next_attempt(days_since_failure: i64, config: &DunningConfig) -> DateTime<Utc> {
    let now = Utc::now();

    if days_since_failure < config.first_retry_days {
        now + Duration::days(config.first_retry_days - days_since_failure)
    } else if days_since_failure < config.second_retry_days {
        now + Duration::days(config.second_retry_days - days_since_failure)
    } else if days_since_failure < config.third_retry_days {
        now + Duration::days(config.third_retry_days - days_since_failure)
    } else if days_since_failure < config.final_notice_days {
        now + Duration::days(config.final_notice_days - days_since_failure)
    } else {
        now + Duration::days(config.downgrade_days - days_since_failure)
    }
}

/// Format currency amount
fn format_currency(amount: i64, currency: &str) -> String {
    let symbol = match currency.to_uppercase().as_str() {
        "USD" => "$",
        "EUR" => "\u{20AC}",
        "GBP" => "\u{00A3}",
        "JPY" => "\u{00A5}",
        _ => "",
    };

    // Stripe amounts are in cents/pence
    let dollars = amount as f64 / 100.0;
    format!("{}{:.2} {}", symbol, dollars, currency.to_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_currency() {
        assert_eq!(format_currency(9900, "usd"), "$99.00 USD");
        assert_eq!(format_currency(5000, "eur"), "\u{20AC}50.00 EUR");
        assert_eq!(format_currency(1234, "gbp"), "\u{00A3}12.34 GBP");
    }

    #[test]
    fn test_dunning_state_display() {
        assert_eq!(DunningState::FirstRetry.to_string(), "first_retry");
        assert_eq!(DunningState::FinalNotice.to_string(), "final_notice");
        assert_eq!(DunningState::Downgraded.to_string(), "downgraded");
    }

    #[test]
    fn test_parse_dunning_state() {
        assert_eq!(parse_dunning_state("first_retry"), DunningState::FirstRetry);
        assert_eq!(parse_dunning_state("downgraded"), DunningState::Downgraded);
        assert_eq!(parse_dunning_state("unknown"), DunningState::None);
    }

    #[test]
    fn test_default_config() {
        let config = DunningConfig::default();
        assert_eq!(config.first_retry_days, 1);
        assert_eq!(config.downgrade_days, 10);
        assert_eq!(config.max_retry_attempts, 4);
    }
}
