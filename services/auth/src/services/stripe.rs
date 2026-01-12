//! Stripe integration service for subscription management and billing

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use stripe_rust::{
    BillingPortalSession, CheckoutSession, CheckoutSessionMode, Client, CreateBillingPortalSession,
    CreateCheckoutSession, CreateCheckoutSessionLineItems, CreateCustomer, CreateSubscription,
    CreateSubscriptionItems, CreateUsageRecord, Currency, Customer, CustomerId,
    Invoice as StripeInvoice, InvoiceId, ListInvoices, PaymentMethod as StripePaymentMethod,
    PaymentMethodId, Price, PriceId, Product, ProductId, Subscription as StripeSubscription,
    SubscriptionId, SubscriptionItem, SubscriptionStatus as StripeSubscriptionStatus,
    UpdateCustomer, UpdateSubscription, UsageRecord as StripeUsageRecord,
};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::config::StripeConfig;
use crate::models::{
    subscription::{
        BillingPeriod, CancelSubscriptionRequest, CreateBillingPortalSessionRequest,
        CreateCheckoutSessionRequest, Invoice, InvoiceStatus, PaymentMethod, Plan, PlanType,
        ProrationBehavior, SubscriptionDetails, UpdateSubscriptionRequest, UsageMetricType,
        UsageRecord, UsageSummary,
    },
    Organization, OrganizationLimits, Subscription, SubscriptionStatus,
};

/// Stripe service for handling all Stripe-related operations
#[derive(Clone)]
pub struct StripeService {
    client: Client,
    config: Arc<StripeConfig>,
    db: PgPool,
}

impl StripeService {
    /// Create a new Stripe service instance
    pub fn new(config: StripeConfig, db: PgPool) -> Self {
        let client = Client::new(&config.secret_key);
        Self {
            client,
            config: Arc::new(config),
            db,
        }
    }

    // ========== Customer Management ==========

    /// Create a new Stripe customer for an organization
    pub async fn create_customer(
        &self,
        organization: &Organization,
        email: &str,
        name: Option<&str>,
    ) -> Result<Customer> {
        let mut create_customer = CreateCustomer::new();
        create_customer.email = Some(email);
        create_customer.name = name;
        create_customer.metadata = Some(HashMap::from([
            ("organization_id".to_string(), organization.id.clone()),
            ("organization_name".to_string(), organization.name.clone()),
            ("organization_slug".to_string(), organization.slug.clone()),
        ]));
        create_customer.description = Some(&format!(
            "PistonProtection customer for organization: {}",
            organization.name
        ));

        let customer = Customer::create(&self.client, create_customer)
            .await
            .context("Failed to create Stripe customer")?;

        info!(
            customer_id = %customer.id,
            organization_id = %organization.id,
            "Created Stripe customer"
        );

        Ok(customer)
    }

    /// Get a Stripe customer by ID
    pub async fn get_customer(&self, customer_id: &str) -> Result<Customer> {
        let customer_id = CustomerId::from(customer_id.to_string());
        Customer::retrieve(&self.client, &customer_id, &[])
            .await
            .context("Failed to retrieve Stripe customer")
    }

    /// Update a Stripe customer
    pub async fn update_customer(
        &self,
        customer_id: &str,
        email: Option<&str>,
        name: Option<&str>,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<Customer> {
        let customer_id = CustomerId::from(customer_id.to_string());
        let mut update = UpdateCustomer::new();
        update.email = email;
        update.name = name;
        update.metadata = metadata.as_ref();

        Customer::update(&self.client, &customer_id, update)
            .await
            .context("Failed to update Stripe customer")
    }

    /// Delete a Stripe customer
    pub async fn delete_customer(&self, customer_id: &str) -> Result<()> {
        let customer_id = CustomerId::from(customer_id.to_string());
        Customer::delete(&self.client, &customer_id)
            .await
            .context("Failed to delete Stripe customer")?;

        info!(customer_id = %customer_id, "Deleted Stripe customer");
        Ok(())
    }

    // ========== Subscription Management ==========

    /// Create a new subscription for an organization
    pub async fn create_subscription(
        &self,
        customer_id: &str,
        price_id: &str,
        trial_days: Option<u32>,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<StripeSubscription> {
        let customer_id = CustomerId::from(customer_id.to_string());
        let price_id = PriceId::from(price_id.to_string());

        let mut create_subscription = CreateSubscription::new(customer_id);
        create_subscription.items = Some(vec![CreateSubscriptionItems {
            price: Some(price_id.to_string()),
            ..Default::default()
        }]);

        if let Some(days) = trial_days {
            create_subscription.trial_period_days = Some(days);
        }

        if let Some(meta) = &metadata {
            create_subscription.metadata = Some(meta.clone());
        }

        // Set payment behavior
        create_subscription.payment_behavior =
            Some(stripe_rust::SubscriptionPaymentBehavior::DefaultIncomplete);

        let subscription = StripeSubscription::create(&self.client, create_subscription)
            .await
            .context("Failed to create Stripe subscription")?;

        info!(
            subscription_id = %subscription.id,
            "Created Stripe subscription"
        );

        Ok(subscription)
    }

    /// Get a subscription by ID
    pub async fn get_subscription(&self, subscription_id: &str) -> Result<StripeSubscription> {
        let subscription_id = SubscriptionId::from(subscription_id.to_string());
        StripeSubscription::retrieve(&self.client, &subscription_id, &[])
            .await
            .context("Failed to retrieve Stripe subscription")
    }

    /// Update a subscription (change plan, billing period, etc.)
    pub async fn update_subscription(
        &self,
        subscription_id: &str,
        new_price_id: Option<&str>,
        proration_behavior: ProrationBehavior,
    ) -> Result<StripeSubscription> {
        let subscription_id_parsed = SubscriptionId::from(subscription_id.to_string());

        // Get current subscription to find the item ID
        let current = self.get_subscription(subscription_id).await?;

        let mut update = UpdateSubscription::new();

        if let Some(price_id) = new_price_id {
            // Get the first subscription item
            if let Some(item) = current.items.data.first() {
                update.items = Some(vec![stripe_rust::UpdateSubscriptionItems {
                    id: Some(item.id.to_string()),
                    price: Some(price_id.to_string()),
                    ..Default::default()
                }]);
            }
        }

        update.proration_behavior = Some(match proration_behavior {
            ProrationBehavior::CreateProrations => {
                stripe_rust::SubscriptionProrationBehavior::CreateProrations
            }
            ProrationBehavior::None => stripe_rust::SubscriptionProrationBehavior::None,
            ProrationBehavior::AlwaysInvoice => {
                stripe_rust::SubscriptionProrationBehavior::AlwaysInvoice
            }
        });

        StripeSubscription::update(&self.client, &subscription_id_parsed, update)
            .await
            .context("Failed to update Stripe subscription")
    }

    /// Cancel a subscription
    pub async fn cancel_subscription(
        &self,
        subscription_id: &str,
        cancel_at_period_end: bool,
    ) -> Result<StripeSubscription> {
        let subscription_id_parsed = SubscriptionId::from(subscription_id.to_string());

        if cancel_at_period_end {
            // Schedule cancellation at period end
            let mut update = UpdateSubscription::new();
            update.cancel_at_period_end = Some(true);

            StripeSubscription::update(&self.client, &subscription_id_parsed, update)
                .await
                .context("Failed to schedule subscription cancellation")
        } else {
            // Cancel immediately
            StripeSubscription::cancel(
                &self.client,
                &subscription_id_parsed,
                stripe_rust::CancelSubscription::default(),
            )
            .await
            .context("Failed to cancel Stripe subscription")
        }
    }

    /// Resume a canceled subscription (if cancel_at_period_end was set)
    pub async fn resume_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<StripeSubscription> {
        let subscription_id_parsed = SubscriptionId::from(subscription_id.to_string());

        let mut update = UpdateSubscription::new();
        update.cancel_at_period_end = Some(false);

        StripeSubscription::update(&self.client, &subscription_id_parsed, update)
            .await
            .context("Failed to resume Stripe subscription")
    }

    // ========== Checkout Session ==========

    /// Create a checkout session for new subscriptions
    pub async fn create_checkout_session(
        &self,
        request: &CreateCheckoutSessionRequest,
    ) -> Result<CheckoutSession> {
        // Get the organization
        let org = self.get_organization_by_id(&request.organization_id).await?;

        // Get the plan
        let plan = self.get_plan_by_id(&request.plan_id).await?;

        // Get the appropriate price ID based on billing period
        let price_id = match request.billing_period {
            BillingPeriod::Monthly => plan
                .stripe_price_id_monthly
                .as_ref()
                .ok_or_else(|| anyhow!("No monthly price configured for plan"))?,
            BillingPeriod::Yearly => plan
                .stripe_price_id_yearly
                .as_ref()
                .ok_or_else(|| anyhow!("No yearly price configured for plan"))?,
        };

        // Check if organization already has a Stripe customer
        let subscription = self.get_subscription_by_org_id(&request.organization_id).await?;

        let mut create_session = CreateCheckoutSession::new();
        create_session.mode = Some(CheckoutSessionMode::Subscription);
        create_session.success_url = Some(&request.success_url);
        create_session.cancel_url = Some(&request.cancel_url);

        // Set customer if exists
        if let Some(ref sub) = subscription {
            if let Some(ref customer_id) = sub.stripe_customer_id {
                create_session.customer = Some(CustomerId::from(customer_id.clone()));
            }
        }

        create_session.line_items = Some(vec![CreateCheckoutSessionLineItems {
            price: Some(price_id.clone()),
            quantity: Some(1),
            ..Default::default()
        }]);

        create_session.allow_promotion_codes = Some(request.allow_promotion_codes);

        create_session.metadata = Some(HashMap::from([
            ("organization_id".to_string(), request.organization_id.clone()),
            ("plan_id".to_string(), request.plan_id.clone()),
            (
                "billing_period".to_string(),
                match request.billing_period {
                    BillingPeriod::Monthly => "monthly".to_string(),
                    BillingPeriod::Yearly => "yearly".to_string(),
                },
            ),
        ]));

        // Create the session
        let session = CheckoutSession::create(&self.client, create_session)
            .await
            .context("Failed to create checkout session")?;

        info!(
            session_id = %session.id,
            organization_id = %request.organization_id,
            plan_id = %request.plan_id,
            "Created checkout session"
        );

        Ok(session)
    }

    /// Retrieve a checkout session
    pub async fn get_checkout_session(&self, session_id: &str) -> Result<CheckoutSession> {
        let session_id = stripe_rust::CheckoutSessionId::from(session_id.to_string());
        CheckoutSession::retrieve(&self.client, &session_id, &[])
            .await
            .context("Failed to retrieve checkout session")
    }

    // ========== Billing Portal ==========

    /// Create a billing portal session
    pub async fn create_billing_portal_session(
        &self,
        request: &CreateBillingPortalSessionRequest,
    ) -> Result<BillingPortalSession> {
        // Get the subscription for this organization
        let subscription = self
            .get_subscription_by_org_id(&request.organization_id)
            .await?
            .ok_or_else(|| anyhow!("No subscription found for organization"))?;

        let customer_id = subscription
            .stripe_customer_id
            .ok_or_else(|| anyhow!("Organization has no Stripe customer ID"))?;

        let mut create_portal = CreateBillingPortalSession::new(CustomerId::from(customer_id));
        create_portal.return_url = Some(&request.return_url);

        let session = BillingPortalSession::create(&self.client, create_portal)
            .await
            .context("Failed to create billing portal session")?;

        info!(
            session_id = %session.id,
            organization_id = %request.organization_id,
            "Created billing portal session"
        );

        Ok(session)
    }

    // ========== Invoice Handling ==========

    /// List invoices for a customer
    pub async fn list_invoices(
        &self,
        customer_id: &str,
        limit: Option<u64>,
    ) -> Result<Vec<StripeInvoice>> {
        let customer_id = CustomerId::from(customer_id.to_string());

        let mut list_params = ListInvoices::new();
        list_params.customer = Some(customer_id);
        list_params.limit = limit;

        let invoices = StripeInvoice::list(&self.client, &list_params)
            .await
            .context("Failed to list invoices")?;

        Ok(invoices.data)
    }

    /// Get a specific invoice
    pub async fn get_invoice(&self, invoice_id: &str) -> Result<StripeInvoice> {
        let invoice_id = InvoiceId::from(invoice_id.to_string());
        StripeInvoice::retrieve(&self.client, &invoice_id, &[])
            .await
            .context("Failed to retrieve invoice")
    }

    /// Pay an invoice manually
    pub async fn pay_invoice(&self, invoice_id: &str) -> Result<StripeInvoice> {
        let invoice_id = InvoiceId::from(invoice_id.to_string());
        StripeInvoice::pay(&self.client, &invoice_id)
            .await
            .context("Failed to pay invoice")
    }

    /// Void an invoice
    pub async fn void_invoice(&self, invoice_id: &str) -> Result<StripeInvoice> {
        let invoice_id = InvoiceId::from(invoice_id.to_string());
        StripeInvoice::void_invoice(&self.client, &invoice_id)
            .await
            .context("Failed to void invoice")
    }

    // ========== Usage-Based Billing ==========

    /// Report usage for a subscription item
    pub async fn report_usage(
        &self,
        subscription_item_id: &str,
        quantity: i64,
        timestamp: Option<i64>,
        action: stripe_rust::UsageRecordAction,
    ) -> Result<StripeUsageRecord> {
        let subscription_item_id =
            stripe_rust::SubscriptionItemId::from(subscription_item_id.to_string());

        let mut create_usage = CreateUsageRecord::new(quantity);
        create_usage.timestamp = timestamp;
        create_usage.action = Some(action);

        StripeUsageRecord::create(&self.client, &subscription_item_id, create_usage)
            .await
            .context("Failed to report usage")
    }

    /// Report bandwidth usage
    pub async fn report_bandwidth_usage(
        &self,
        organization_id: &str,
        bytes: i64,
    ) -> Result<()> {
        let subscription = self
            .get_subscription_by_org_id(organization_id)
            .await?
            .ok_or_else(|| anyhow!("No subscription found for organization"))?;

        let stripe_sub_id = subscription
            .stripe_subscription_id
            .ok_or_else(|| anyhow!("No Stripe subscription ID"))?;

        // Get the subscription to find the metered item
        let stripe_sub = self.get_subscription(&stripe_sub_id).await?;

        // Find the metered subscription item for bandwidth
        for item in stripe_sub.items.data {
            if let Some(price) = &item.price {
                if let Some(ref metadata) = price.metadata {
                    if metadata.get("metric_type") == Some(&"bandwidth".to_string()) {
                        // Report usage in GB
                        let gb = bytes / 1_073_741_824;
                        if gb > 0 {
                            self.report_usage(
                                &item.id.to_string(),
                                gb,
                                Some(Utc::now().timestamp()),
                                stripe_rust::UsageRecordAction::Increment,
                            )
                            .await?;

                            // Store locally
                            self.store_usage_record(
                                organization_id,
                                &subscription.id,
                                UsageMetricType::BandwidthBytes,
                                bytes,
                                Some(&item.id.to_string()),
                            )
                            .await?;
                        }
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Report request usage
    pub async fn report_request_usage(
        &self,
        organization_id: &str,
        request_count: i64,
    ) -> Result<()> {
        let subscription = self
            .get_subscription_by_org_id(organization_id)
            .await?
            .ok_or_else(|| anyhow!("No subscription found for organization"))?;

        let stripe_sub_id = subscription
            .stripe_subscription_id
            .ok_or_else(|| anyhow!("No Stripe subscription ID"))?;

        // Get the subscription to find the metered item
        let stripe_sub = self.get_subscription(&stripe_sub_id).await?;

        // Find the metered subscription item for requests
        for item in stripe_sub.items.data {
            if let Some(price) = &item.price {
                if let Some(ref metadata) = price.metadata {
                    if metadata.get("metric_type") == Some(&"requests".to_string()) {
                        // Report in thousands
                        let thousands = request_count / 1000;
                        if thousands > 0 {
                            self.report_usage(
                                &item.id.to_string(),
                                thousands,
                                Some(Utc::now().timestamp()),
                                stripe_rust::UsageRecordAction::Increment,
                            )
                            .await?;

                            // Store locally
                            self.store_usage_record(
                                organization_id,
                                &subscription.id,
                                UsageMetricType::Requests,
                                request_count,
                                Some(&item.id.to_string()),
                            )
                            .await?;
                        }
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    // ========== Plan Management ==========

    /// Get all available plans
    pub async fn list_plans(&self) -> Result<Vec<Plan>> {
        let plans = sqlx::query_as::<_, Plan>(
            r#"
            SELECT * FROM plans WHERE is_active = true ORDER BY price_monthly_cents ASC
            "#,
        )
        .fetch_all(&self.db)
        .await
        .context("Failed to list plans")?;

        Ok(plans)
    }

    /// Get a plan by ID
    pub async fn get_plan_by_id(&self, plan_id: &str) -> Result<Plan> {
        sqlx::query_as::<_, Plan>(
            r#"
            SELECT * FROM plans WHERE id = $1
            "#,
        )
        .bind(plan_id)
        .fetch_optional(&self.db)
        .await
        .context("Failed to fetch plan")?
        .ok_or_else(|| anyhow!("Plan not found: {}", plan_id))
    }

    /// Get a plan by Stripe price ID
    pub async fn get_plan_by_stripe_price(&self, price_id: &str) -> Result<Plan> {
        sqlx::query_as::<_, Plan>(
            r#"
            SELECT * FROM plans
            WHERE stripe_price_id_monthly = $1 OR stripe_price_id_yearly = $1
            "#,
        )
        .bind(price_id)
        .fetch_optional(&self.db)
        .await
        .context("Failed to fetch plan by price")?
        .ok_or_else(|| anyhow!("Plan not found for price: {}", price_id))
    }

    /// Sync plans from Stripe
    pub async fn sync_plans_from_stripe(&self) -> Result<()> {
        // Get all products from Stripe
        let products = Product::list(&self.client, &stripe_rust::ListProducts::default())
            .await
            .context("Failed to list Stripe products")?;

        for product in products.data {
            if !product.active.unwrap_or(false) {
                continue;
            }

            // Get prices for this product
            let mut list_prices = stripe_rust::ListPrices::default();
            list_prices.product = Some(stripe_rust::IdOrCreate::Id(&product.id));

            let prices = Price::list(&self.client, &list_prices)
                .await
                .context("Failed to list prices")?;

            let mut monthly_price: Option<Price> = None;
            let mut yearly_price: Option<Price> = None;

            for price in prices.data {
                if !price.active.unwrap_or(false) {
                    continue;
                }

                if let Some(ref recurring) = price.recurring {
                    match recurring.interval {
                        stripe_rust::RecurringInterval::Month => {
                            monthly_price = Some(price);
                        }
                        stripe_rust::RecurringInterval::Year => {
                            yearly_price = Some(price);
                        }
                        _ => {}
                    }
                }
            }

            // Determine plan type from product metadata
            let plan_type = product
                .metadata
                .as_ref()
                .and_then(|m| m.get("plan_type"))
                .map(|s| match s.as_str() {
                    "free" => PlanType::Free,
                    "starter" => PlanType::Starter,
                    "pro" => PlanType::Pro,
                    "enterprise" => PlanType::Enterprise,
                    _ => PlanType::Starter,
                })
                .unwrap_or(PlanType::Starter);

            let limits = plan_type.default_limits();

            // Upsert the plan
            sqlx::query(
                r#"
                INSERT INTO plans (
                    id, name, plan_type, description, stripe_product_id,
                    stripe_price_id_monthly, stripe_price_id_yearly,
                    price_monthly_cents, price_yearly_cents,
                    max_backends, max_origins_per_backend, max_domains, max_filter_rules,
                    max_bandwidth_bytes, max_requests, advanced_protection, priority_support,
                    custom_ssl, api_access, data_retention_days, is_active, created_at, updated_at
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                    $18, $19, $20, $21, NOW(), NOW()
                )
                ON CONFLICT (stripe_product_id) DO UPDATE SET
                    name = EXCLUDED.name,
                    description = EXCLUDED.description,
                    stripe_price_id_monthly = EXCLUDED.stripe_price_id_monthly,
                    stripe_price_id_yearly = EXCLUDED.stripe_price_id_yearly,
                    price_monthly_cents = EXCLUDED.price_monthly_cents,
                    price_yearly_cents = EXCLUDED.price_yearly_cents,
                    is_active = EXCLUDED.is_active,
                    updated_at = NOW()
                "#,
            )
            .bind(Uuid::new_v4().to_string())
            .bind(product.name.unwrap_or_default())
            .bind(plan_type)
            .bind(product.description)
            .bind(product.id.to_string())
            .bind(monthly_price.as_ref().map(|p| p.id.to_string()))
            .bind(yearly_price.as_ref().map(|p| p.id.to_string()))
            .bind(monthly_price.as_ref().and_then(|p| p.unit_amount).unwrap_or(0))
            .bind(yearly_price.as_ref().and_then(|p| p.unit_amount).unwrap_or(0))
            .bind(limits.max_backends)
            .bind(limits.max_origins_per_backend)
            .bind(limits.max_domains)
            .bind(limits.max_filter_rules)
            .bind(limits.max_bandwidth_bytes)
            .bind(limits.max_requests)
            .bind(limits.advanced_protection)
            .bind(limits.priority_support)
            .bind(limits.custom_ssl)
            .bind(limits.api_access)
            .bind(limits.data_retention_days)
            .bind(true)
            .execute(&self.db)
            .await
            .context("Failed to upsert plan")?;
        }

        info!("Synced plans from Stripe");
        Ok(())
    }

    // ========== Database Helpers ==========

    /// Get organization by ID
    async fn get_organization_by_id(&self, organization_id: &str) -> Result<Organization> {
        sqlx::query_as::<_, Organization>(
            r#"
            SELECT * FROM organizations WHERE id = $1 AND deleted_at IS NULL
            "#,
        )
        .bind(organization_id)
        .fetch_optional(&self.db)
        .await
        .context("Failed to fetch organization")?
        .ok_or_else(|| anyhow!("Organization not found: {}", organization_id))
    }

    /// Get subscription by organization ID
    pub async fn get_subscription_by_org_id(
        &self,
        organization_id: &str,
    ) -> Result<Option<Subscription>> {
        sqlx::query_as::<_, Subscription>(
            r#"
            SELECT * FROM subscriptions WHERE organization_id = $1
            ORDER BY created_at DESC LIMIT 1
            "#,
        )
        .bind(organization_id)
        .fetch_optional(&self.db)
        .await
        .context("Failed to fetch subscription")
    }

    /// Get subscription by Stripe subscription ID
    pub async fn get_subscription_by_stripe_id(
        &self,
        stripe_subscription_id: &str,
    ) -> Result<Option<Subscription>> {
        sqlx::query_as::<_, Subscription>(
            r#"
            SELECT * FROM subscriptions WHERE stripe_subscription_id = $1
            "#,
        )
        .bind(stripe_subscription_id)
        .fetch_optional(&self.db)
        .await
        .context("Failed to fetch subscription by Stripe ID")
    }

    /// Get subscription by Stripe customer ID
    pub async fn get_subscription_by_customer_id(
        &self,
        stripe_customer_id: &str,
    ) -> Result<Option<Subscription>> {
        sqlx::query_as::<_, Subscription>(
            r#"
            SELECT * FROM subscriptions WHERE stripe_customer_id = $1
            ORDER BY created_at DESC LIMIT 1
            "#,
        )
        .bind(stripe_customer_id)
        .fetch_optional(&self.db)
        .await
        .context("Failed to fetch subscription by customer ID")
    }

    /// Update subscription status in database
    pub async fn update_subscription_status(
        &self,
        subscription_id: &str,
        status: SubscriptionStatus,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE subscriptions
            SET status = $1, updated_at = NOW()
            WHERE id = $1 OR stripe_subscription_id = $2
            "#,
        )
        .bind(status)
        .bind(subscription_id)
        .execute(&self.db)
        .await
        .context("Failed to update subscription status")?;

        Ok(())
    }

    /// Update subscription from Stripe data
    pub async fn sync_subscription_from_stripe(
        &self,
        stripe_sub: &StripeSubscription,
    ) -> Result<()> {
        let status = match stripe_sub.status {
            StripeSubscriptionStatus::Active => SubscriptionStatus::Active,
            StripeSubscriptionStatus::Trialing => SubscriptionStatus::Trialing,
            StripeSubscriptionStatus::PastDue => SubscriptionStatus::PastDue,
            StripeSubscriptionStatus::Canceled => SubscriptionStatus::Canceled,
            StripeSubscriptionStatus::Unpaid => SubscriptionStatus::Unpaid,
            _ => SubscriptionStatus::Active,
        };

        let current_period_start = Utc
            .timestamp_opt(stripe_sub.current_period_start, 0)
            .single()
            .unwrap_or_else(Utc::now);
        let current_period_end = Utc
            .timestamp_opt(stripe_sub.current_period_end, 0)
            .single()
            .unwrap_or_else(Utc::now);

        let trial_end = stripe_sub
            .trial_end
            .and_then(|ts| Utc.timestamp_opt(ts, 0).single());

        let canceled_at = stripe_sub
            .canceled_at
            .and_then(|ts| Utc.timestamp_opt(ts, 0).single());

        // Get customer ID
        let customer_id = match &stripe_sub.customer {
            stripe_rust::Expandable::Id(id) => id.to_string(),
            stripe_rust::Expandable::Object(customer) => customer.id.to_string(),
        };

        // Check if we have this subscription
        let existing = self
            .get_subscription_by_stripe_id(&stripe_sub.id.to_string())
            .await?;

        if let Some(sub) = existing {
            // Update existing
            sqlx::query(
                r#"
                UPDATE subscriptions SET
                    status = $1,
                    current_period_start = $2,
                    current_period_end = $3,
                    in_trial = $4,
                    trial_ends_at = $5,
                    cancel_at_period_end = $6,
                    canceled_at = $7,
                    updated_at = NOW()
                WHERE id = $8
                "#,
            )
            .bind(status)
            .bind(current_period_start)
            .bind(current_period_end)
            .bind(stripe_sub.trial_end.is_some())
            .bind(trial_end)
            .bind(stripe_sub.cancel_at_period_end)
            .bind(canceled_at)
            .bind(&sub.id)
            .execute(&self.db)
            .await
            .context("Failed to update subscription")?;
        } else {
            // Find organization by customer ID
            let org_sub = self.get_subscription_by_customer_id(&customer_id).await?;

            if let Some(sub) = org_sub {
                // Update with Stripe subscription ID
                sqlx::query(
                    r#"
                    UPDATE subscriptions SET
                        stripe_subscription_id = $1,
                        status = $2,
                        current_period_start = $3,
                        current_period_end = $4,
                        in_trial = $5,
                        trial_ends_at = $6,
                        cancel_at_period_end = $7,
                        canceled_at = $8,
                        updated_at = NOW()
                    WHERE id = $9
                    "#,
                )
                .bind(stripe_sub.id.to_string())
                .bind(status)
                .bind(current_period_start)
                .bind(current_period_end)
                .bind(stripe_sub.trial_end.is_some())
                .bind(trial_end)
                .bind(stripe_sub.cancel_at_period_end)
                .bind(canceled_at)
                .bind(&sub.id)
                .execute(&self.db)
                .await
                .context("Failed to update subscription with Stripe ID")?;
            } else {
                warn!(
                    stripe_subscription_id = %stripe_sub.id,
                    customer_id = %customer_id,
                    "Could not find organization for Stripe subscription"
                );
            }
        }

        // Update organization limits based on plan
        if let Some(item) = stripe_sub.items.data.first() {
            if let Some(price) = &item.price {
                if let Ok(plan) = self.get_plan_by_stripe_price(&price.id.to_string()).await {
                    self.update_organization_limits_from_plan(&stripe_sub.id.to_string(), &plan)
                        .await?;
                }
            }
        }

        Ok(())
    }

    /// Update organization limits based on plan
    async fn update_organization_limits_from_plan(
        &self,
        stripe_subscription_id: &str,
        plan: &Plan,
    ) -> Result<()> {
        // Get the subscription to find organization
        let sub = self
            .get_subscription_by_stripe_id(stripe_subscription_id)
            .await?
            .ok_or_else(|| anyhow!("Subscription not found"))?;

        sqlx::query(
            r#"
            INSERT INTO organization_limits (
                id, organization_id, max_backends, max_origins_per_backend,
                max_domains, max_filter_rules, max_bandwidth_bytes, max_requests,
                advanced_protection, priority_support, custom_ssl, api_access,
                data_retention_days, created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW()
            )
            ON CONFLICT (organization_id) DO UPDATE SET
                max_backends = EXCLUDED.max_backends,
                max_origins_per_backend = EXCLUDED.max_origins_per_backend,
                max_domains = EXCLUDED.max_domains,
                max_filter_rules = EXCLUDED.max_filter_rules,
                max_bandwidth_bytes = EXCLUDED.max_bandwidth_bytes,
                max_requests = EXCLUDED.max_requests,
                advanced_protection = EXCLUDED.advanced_protection,
                priority_support = EXCLUDED.priority_support,
                custom_ssl = EXCLUDED.custom_ssl,
                api_access = EXCLUDED.api_access,
                data_retention_days = EXCLUDED.data_retention_days,
                updated_at = NOW()
            "#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&sub.organization_id)
        .bind(plan.max_backends)
        .bind(plan.max_origins_per_backend)
        .bind(plan.max_domains)
        .bind(plan.max_filter_rules)
        .bind(plan.max_bandwidth_bytes)
        .bind(plan.max_requests)
        .bind(plan.advanced_protection)
        .bind(plan.priority_support)
        .bind(plan.custom_ssl)
        .bind(plan.api_access)
        .bind(plan.data_retention_days)
        .execute(&self.db)
        .await
        .context("Failed to update organization limits")?;

        info!(
            organization_id = %sub.organization_id,
            plan_id = %plan.id,
            "Updated organization limits from plan"
        );

        Ok(())
    }

    /// Store a local invoice record from Stripe
    pub async fn sync_invoice_from_stripe(&self, stripe_invoice: &StripeInvoice) -> Result<()> {
        let customer_id = match &stripe_invoice.customer {
            Some(stripe_rust::Expandable::Id(id)) => id.to_string(),
            Some(stripe_rust::Expandable::Object(customer)) => customer.id.to_string(),
            None => return Ok(()), // No customer, skip
        };

        let subscription = self.get_subscription_by_customer_id(&customer_id).await?;
        let sub = match subscription {
            Some(s) => s,
            None => {
                warn!(
                    invoice_id = %stripe_invoice.id,
                    customer_id = %customer_id,
                    "Could not find subscription for invoice"
                );
                return Ok(());
            }
        };

        let status = stripe_invoice
            .status
            .as_ref()
            .map(|s| InvoiceStatus::from_stripe_status(&s.to_string()))
            .unwrap_or(InvoiceStatus::Draft);

        let period_start = stripe_invoice
            .period_start
            .and_then(|ts| Utc.timestamp_opt(ts, 0).single())
            .unwrap_or_else(Utc::now);

        let period_end = stripe_invoice
            .period_end
            .and_then(|ts| Utc.timestamp_opt(ts, 0).single())
            .unwrap_or_else(Utc::now);

        let due_date = stripe_invoice
            .due_date
            .and_then(|ts| Utc.timestamp_opt(ts, 0).single());

        let paid_at = if stripe_invoice.paid.unwrap_or(false) {
            Some(Utc::now())
        } else {
            None
        };

        let payment_intent_id = stripe_invoice.payment_intent.as_ref().map(|pi| match pi {
            stripe_rust::Expandable::Id(id) => id.to_string(),
            stripe_rust::Expandable::Object(pi) => pi.id.to_string(),
        });

        sqlx::query(
            r#"
            INSERT INTO invoices (
                id, organization_id, subscription_id, stripe_invoice_id,
                stripe_payment_intent_id, number, status, currency,
                subtotal_cents, tax_cents, total_cents, amount_paid_cents,
                amount_due_cents, description, invoice_pdf_url, hosted_invoice_url,
                period_start, period_end, due_date, paid_at, created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
                $16, $17, $18, $19, $20, NOW(), NOW()
            )
            ON CONFLICT (stripe_invoice_id) DO UPDATE SET
                status = EXCLUDED.status,
                amount_paid_cents = EXCLUDED.amount_paid_cents,
                amount_due_cents = EXCLUDED.amount_due_cents,
                invoice_pdf_url = EXCLUDED.invoice_pdf_url,
                hosted_invoice_url = EXCLUDED.hosted_invoice_url,
                paid_at = EXCLUDED.paid_at,
                updated_at = NOW()
            "#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&sub.organization_id)
        .bind(&sub.id)
        .bind(stripe_invoice.id.to_string())
        .bind(payment_intent_id)
        .bind(&stripe_invoice.number)
        .bind(status)
        .bind(stripe_invoice.currency.map(|c| c.to_string()).unwrap_or_else(|| "usd".to_string()))
        .bind(stripe_invoice.subtotal.unwrap_or(0))
        .bind(stripe_invoice.tax.unwrap_or(0))
        .bind(stripe_invoice.total.unwrap_or(0))
        .bind(stripe_invoice.amount_paid.unwrap_or(0))
        .bind(stripe_invoice.amount_due.unwrap_or(0))
        .bind(&stripe_invoice.description)
        .bind(&stripe_invoice.invoice_pdf)
        .bind(&stripe_invoice.hosted_invoice_url)
        .bind(period_start)
        .bind(period_end)
        .bind(due_date)
        .bind(paid_at)
        .execute(&self.db)
        .await
        .context("Failed to sync invoice")?;

        Ok(())
    }

    /// Store usage record locally
    async fn store_usage_record(
        &self,
        organization_id: &str,
        subscription_id: &str,
        metric_type: UsageMetricType,
        quantity: i64,
        stripe_usage_record_id: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO usage_records (
                id, organization_id, subscription_id, metric_type, quantity,
                timestamp, stripe_usage_record_id, created_at
            ) VALUES ($1, $2, $3, $4, $5, NOW(), $6, NOW())
            "#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(organization_id)
        .bind(subscription_id)
        .bind(metric_type)
        .bind(quantity)
        .bind(stripe_usage_record_id)
        .execute(&self.db)
        .await
        .context("Failed to store usage record")?;

        Ok(())
    }

    /// Get invoices for an organization
    pub async fn get_organization_invoices(
        &self,
        organization_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Invoice>> {
        sqlx::query_as::<_, Invoice>(
            r#"
            SELECT * FROM invoices
            WHERE organization_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(organization_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .context("Failed to fetch invoices")
    }

    /// Get usage summary for an organization
    pub async fn get_usage_summary(
        &self,
        organization_id: &str,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> Result<Option<UsageSummary>> {
        sqlx::query_as::<_, UsageSummary>(
            r#"
            SELECT * FROM usage_summaries
            WHERE organization_id = $1 AND period_start = $2 AND period_end = $3
            "#,
        )
        .bind(organization_id)
        .bind(period_start)
        .bind(period_end)
        .fetch_optional(&self.db)
        .await
        .context("Failed to fetch usage summary")
    }

    /// Create or update subscription for organization after checkout
    pub async fn create_subscription_from_checkout(
        &self,
        session: &CheckoutSession,
    ) -> Result<Subscription> {
        let organization_id = session
            .metadata
            .as_ref()
            .and_then(|m| m.get("organization_id"))
            .ok_or_else(|| anyhow!("Missing organization_id in session metadata"))?;

        let plan_id = session
            .metadata
            .as_ref()
            .and_then(|m| m.get("plan_id"))
            .ok_or_else(|| anyhow!("Missing plan_id in session metadata"))?;

        let billing_period = session
            .metadata
            .as_ref()
            .and_then(|m| m.get("billing_period"))
            .map(|s| match s.as_str() {
                "yearly" => BillingPeriod::Yearly,
                _ => BillingPeriod::Monthly,
            })
            .unwrap_or(BillingPeriod::Monthly);

        let customer_id = session.customer.as_ref().map(|c| match c {
            stripe_rust::Expandable::Id(id) => id.to_string(),
            stripe_rust::Expandable::Object(customer) => customer.id.to_string(),
        });

        let stripe_subscription_id = session.subscription.as_ref().map(|s| match s {
            stripe_rust::Expandable::Id(id) => id.to_string(),
            stripe_rust::Expandable::Object(sub) => sub.id.to_string(),
        });

        // Get the plan details
        let plan = self.get_plan_by_id(plan_id).await?;

        let now = Utc::now();
        let subscription_id = Uuid::new_v4().to_string();

        // Calculate period end based on billing period
        let period_end = match billing_period {
            BillingPeriod::Monthly => now + chrono::Duration::days(30),
            BillingPeriod::Yearly => now + chrono::Duration::days(365),
        };

        // Check if subscription already exists
        let existing = self.get_subscription_by_org_id(organization_id).await?;

        if let Some(existing_sub) = existing {
            // Update existing subscription
            sqlx::query(
                r#"
                UPDATE subscriptions SET
                    plan_id = $1,
                    plan_name = $2,
                    status = $3,
                    stripe_customer_id = $4,
                    stripe_subscription_id = $5,
                    current_period_start = $6,
                    current_period_end = $7,
                    in_trial = false,
                    updated_at = NOW()
                WHERE id = $8
                "#,
            )
            .bind(plan_id)
            .bind(&plan.name)
            .bind(SubscriptionStatus::Active)
            .bind(&customer_id)
            .bind(&stripe_subscription_id)
            .bind(now)
            .bind(period_end)
            .bind(&existing_sub.id)
            .execute(&self.db)
            .await
            .context("Failed to update subscription")?;

            // Update organization limits
            self.update_organization_limits_for_org(organization_id, &plan)
                .await?;

            return self
                .get_subscription_by_org_id(organization_id)
                .await?
                .ok_or_else(|| anyhow!("Subscription not found after update"));
        }

        // Create new subscription
        sqlx::query(
            r#"
            INSERT INTO subscriptions (
                id, organization_id, plan_id, plan_name, status,
                stripe_customer_id, stripe_subscription_id,
                current_period_start, current_period_end,
                in_trial, cancel_at_period_end, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, false, false, NOW(), NOW())
            "#,
        )
        .bind(&subscription_id)
        .bind(organization_id)
        .bind(plan_id)
        .bind(&plan.name)
        .bind(SubscriptionStatus::Active)
        .bind(&customer_id)
        .bind(&stripe_subscription_id)
        .bind(now)
        .bind(period_end)
        .execute(&self.db)
        .await
        .context("Failed to create subscription")?;

        // Update organization limits
        self.update_organization_limits_for_org(organization_id, &plan)
            .await?;

        info!(
            subscription_id = %subscription_id,
            organization_id = %organization_id,
            plan_id = %plan_id,
            "Created subscription from checkout"
        );

        self.get_subscription_by_org_id(organization_id)
            .await?
            .ok_or_else(|| anyhow!("Subscription not found after creation"))
    }

    /// Update organization limits directly for an organization
    async fn update_organization_limits_for_org(
        &self,
        organization_id: &str,
        plan: &Plan,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO organization_limits (
                id, organization_id, max_backends, max_origins_per_backend,
                max_domains, max_filter_rules, max_bandwidth_bytes, max_requests,
                advanced_protection, priority_support, custom_ssl, api_access,
                data_retention_days, created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW()
            )
            ON CONFLICT (organization_id) DO UPDATE SET
                max_backends = EXCLUDED.max_backends,
                max_origins_per_backend = EXCLUDED.max_origins_per_backend,
                max_domains = EXCLUDED.max_domains,
                max_filter_rules = EXCLUDED.max_filter_rules,
                max_bandwidth_bytes = EXCLUDED.max_bandwidth_bytes,
                max_requests = EXCLUDED.max_requests,
                advanced_protection = EXCLUDED.advanced_protection,
                priority_support = EXCLUDED.priority_support,
                custom_ssl = EXCLUDED.custom_ssl,
                api_access = EXCLUDED.api_access,
                data_retention_days = EXCLUDED.data_retention_days,
                updated_at = NOW()
            "#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(organization_id)
        .bind(plan.max_backends)
        .bind(plan.max_origins_per_backend)
        .bind(plan.max_domains)
        .bind(plan.max_filter_rules)
        .bind(plan.max_bandwidth_bytes)
        .bind(plan.max_requests)
        .bind(plan.advanced_protection)
        .bind(plan.priority_support)
        .bind(plan.custom_ssl)
        .bind(plan.api_access)
        .bind(plan.data_retention_days)
        .execute(&self.db)
        .await
        .context("Failed to update organization limits")?;

        Ok(())
    }

    /// Get the Stripe config
    pub fn config(&self) -> &StripeConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proration_behavior_str() {
        assert_eq!(
            ProrationBehavior::CreateProrations.as_stripe_str(),
            "create_prorations"
        );
        assert_eq!(ProrationBehavior::None.as_stripe_str(), "none");
        assert_eq!(
            ProrationBehavior::AlwaysInvoice.as_stripe_str(),
            "always_invoice"
        );
    }
}
