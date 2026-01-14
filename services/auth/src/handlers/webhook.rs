//! Stripe webhook handler for processing billing events

use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use std::sync::Arc;
use stripe_rust::{
    CheckoutSession, Customer, Event, EventObject, EventType, Invoice as StripeInvoice,
    PaymentIntent, Subscription as StripeSubscription,
};
use tracing::{error, info, warn};

use crate::models::SubscriptionStatus;
use crate::services::email::{EmailRecipient, EmailService};
use crate::services::stripe::StripeService;

/// Webhook handler state
#[derive(Clone)]
pub struct WebhookState {
    pub stripe_service: Arc<StripeService>,
    pub email_service: Arc<EmailService>,
}

/// Create the webhook router
pub fn create_webhook_router(state: WebhookState) -> Router {
    Router::new()
        .route("/stripe", post(handle_stripe_webhook))
        .with_state(state)
}

/// Stripe webhook signature header
const STRIPE_SIGNATURE_HEADER: &str = "Stripe-Signature";

/// Signature tolerance in seconds (5 minutes)
const SIGNATURE_TOLERANCE_SECS: i64 = 300;

/// Handle incoming Stripe webhook
async fn handle_stripe_webhook(
    State(state): State<WebhookState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // Get the signature header
    let signature = match headers.get(STRIPE_SIGNATURE_HEADER) {
        Some(sig) => match sig.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                error!("Invalid Stripe signature header encoding");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(WebhookResponse::error("Invalid signature header")),
                );
            }
        },
        None => {
            error!("Missing Stripe signature header");
            return (
                StatusCode::BAD_REQUEST,
                Json(WebhookResponse::error("Missing signature header")),
            );
        }
    };

    // Verify the webhook signature
    let webhook_secret = &state.stripe_service.config().webhook_secret;
    if let Err(e) = verify_webhook_signature(&body, &signature, webhook_secret) {
        error!(error = %e, "Webhook signature verification failed");
        return (
            StatusCode::UNAUTHORIZED,
            Json(WebhookResponse::error("Invalid signature")),
        );
    }

    // Parse the event
    let event: Event = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(e) => {
            error!(error = %e, "Failed to parse webhook event");
            return (
                StatusCode::BAD_REQUEST,
                Json(WebhookResponse::error("Invalid event payload")),
            );
        }
    };

    info!(
        event_type = %event.type_,
        event_id = %event.id,
        "Received Stripe webhook"
    );

    // Process the event
    if let Err(e) = process_webhook_event(&state, &event).await {
        error!(
            event_type = %event.type_,
            event_id = %event.id,
            error = %e,
            "Failed to process webhook event"
        );
        // Still return 200 to prevent Stripe from retrying (we've logged the error)
        return (
            StatusCode::OK,
            Json(WebhookResponse::error(&format!("Processing error: {}", e))),
        );
    }

    (StatusCode::OK, Json(WebhookResponse::success()))
}

/// Webhook response
#[derive(Debug, Serialize)]
struct WebhookResponse {
    received: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl WebhookResponse {
    fn success() -> Self {
        Self {
            received: true,
            error: None,
        }
    }

    fn error(message: &str) -> Self {
        Self {
            received: false,
            error: Some(message.to_string()),
        }
    }
}

/// Verify Stripe webhook signature
fn verify_webhook_signature(payload: &[u8], signature: &str, secret: &str) -> Result<(), String> {
    // Parse the signature header
    // Format: t=1492774577,v1=signature1,v1=signature2,...
    let mut timestamp: Option<i64> = None;
    let mut signatures: Vec<String> = Vec::new();

    for part in signature.split(',') {
        let kv: Vec<&str> = part.splitn(2, '=').collect();
        if kv.len() != 2 {
            continue;
        }

        match kv[0] {
            "t" => {
                timestamp = kv[1].parse().ok();
            }
            "v1" => {
                signatures.push(kv[1].to_string());
            }
            _ => {}
        }
    }

    let timestamp = timestamp.ok_or_else(|| "Missing timestamp in signature".to_string())?;

    if signatures.is_empty() {
        return Err("No v1 signatures found".to_string());
    }

    // Check timestamp tolerance
    let now = chrono::Utc::now().timestamp();
    if (now - timestamp).abs() > SIGNATURE_TOLERANCE_SECS {
        return Err("Webhook timestamp outside tolerance window".to_string());
    }

    // Compute expected signature
    let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(payload));

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| "Failed to create HMAC".to_string())?;
    mac.update(signed_payload.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    // Check if any signature matches
    if signatures
        .iter()
        .any(|sig| constant_time_compare(sig, &expected))
    {
        Ok(())
    } else {
        Err("Signature verification failed".to_string())
    }
}

/// Constant time string comparison to prevent timing attacks
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();

    let mut result = 0u8;
    for (x, y) in a_bytes.iter().zip(b_bytes.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Process a webhook event
async fn process_webhook_event(state: &WebhookState, event: &Event) -> Result<(), anyhow::Error> {
    match event.type_ {
        // Customer events
        EventType::CustomerCreated => {
            if let EventObject::Customer(customer) = &event.data.object {
                handle_customer_created(state, customer).await?;
            }
        }
        EventType::CustomerUpdated => {
            if let EventObject::Customer(customer) = &event.data.object {
                handle_customer_updated(state, customer).await?;
            }
        }
        EventType::CustomerDeleted => {
            if let EventObject::Customer(customer) = &event.data.object {
                handle_customer_deleted(state, customer).await?;
            }
        }

        // Subscription events
        EventType::CustomerSubscriptionCreated => {
            if let EventObject::Subscription(subscription) = &event.data.object {
                handle_subscription_created(state, subscription).await?;
            }
        }
        EventType::CustomerSubscriptionUpdated => {
            if let EventObject::Subscription(subscription) = &event.data.object {
                handle_subscription_updated(state, subscription).await?;
            }
        }
        EventType::CustomerSubscriptionDeleted => {
            if let EventObject::Subscription(subscription) = &event.data.object {
                handle_subscription_deleted(state, subscription).await?;
            }
        }
        EventType::CustomerSubscriptionTrialWillEnd => {
            if let EventObject::Subscription(subscription) = &event.data.object {
                handle_subscription_trial_ending(state, subscription).await?;
            }
        }
        EventType::CustomerSubscriptionPaused => {
            if let EventObject::Subscription(subscription) = &event.data.object {
                handle_subscription_paused(state, subscription).await?;
            }
        }
        EventType::CustomerSubscriptionResumed => {
            if let EventObject::Subscription(subscription) = &event.data.object {
                handle_subscription_resumed(state, subscription).await?;
            }
        }

        // Invoice events
        EventType::InvoiceCreated => {
            if let EventObject::Invoice(invoice) = &event.data.object {
                handle_invoice_created(state, invoice).await?;
            }
        }
        EventType::InvoiceFinalized => {
            if let EventObject::Invoice(invoice) = &event.data.object {
                handle_invoice_finalized(state, invoice).await?;
            }
        }
        EventType::InvoicePaid => {
            if let EventObject::Invoice(invoice) = &event.data.object {
                handle_invoice_paid(state, invoice).await?;
            }
        }
        EventType::InvoicePaymentFailed => {
            if let EventObject::Invoice(invoice) = &event.data.object {
                handle_invoice_payment_failed(state, invoice).await?;
            }
        }
        EventType::InvoicePaymentActionRequired => {
            if let EventObject::Invoice(invoice) = &event.data.object {
                handle_invoice_payment_action_required(state, invoice).await?;
            }
        }
        EventType::InvoiceUpcoming => {
            if let EventObject::Invoice(invoice) = &event.data.object {
                handle_invoice_upcoming(state, invoice).await?;
            }
        }
        EventType::InvoiceMarkedUncollectible => {
            if let EventObject::Invoice(invoice) = &event.data.object {
                handle_invoice_uncollectible(state, invoice).await?;
            }
        }
        EventType::InvoiceVoided => {
            if let EventObject::Invoice(invoice) = &event.data.object {
                handle_invoice_voided(state, invoice).await?;
            }
        }

        // Payment intent events
        EventType::PaymentIntentCreated => {
            if let EventObject::PaymentIntent(payment_intent) = &event.data.object {
                handle_payment_intent_created(state, payment_intent).await?;
            }
        }
        EventType::PaymentIntentSucceeded => {
            if let EventObject::PaymentIntent(payment_intent) = &event.data.object {
                handle_payment_intent_succeeded(state, payment_intent).await?;
            }
        }
        EventType::PaymentIntentPaymentFailed => {
            if let EventObject::PaymentIntent(payment_intent) = &event.data.object {
                handle_payment_intent_failed(state, payment_intent).await?;
            }
        }
        EventType::PaymentIntentCanceled => {
            if let EventObject::PaymentIntent(payment_intent) = &event.data.object {
                handle_payment_intent_canceled(state, payment_intent).await?;
            }
        }
        EventType::PaymentIntentRequiresAction => {
            if let EventObject::PaymentIntent(payment_intent) = &event.data.object {
                handle_payment_intent_requires_action(state, payment_intent).await?;
            }
        }

        // Checkout session events
        EventType::CheckoutSessionCompleted => {
            if let EventObject::CheckoutSession(session) = &event.data.object {
                handle_checkout_session_completed(state, session).await?;
            }
        }
        EventType::CheckoutSessionExpired => {
            if let EventObject::CheckoutSession(session) = &event.data.object {
                handle_checkout_session_expired(state, session).await?;
            }
        }

        // Unhandled events
        _ => {
            info!(event_type = %event.type_, "Received unhandled webhook event type");
        }
    }

    Ok(())
}

// ========== Customer Event Handlers ==========

async fn handle_customer_created(
    _state: &WebhookState,
    customer: &Customer,
) -> Result<(), anyhow::Error> {
    info!(
        customer_id = %customer.id,
        email = ?customer.email,
        "Customer created in Stripe"
    );
    // Customer creation is typically initiated by us, so we just log it
    Ok(())
}

async fn handle_customer_updated(
    _state: &WebhookState,
    customer: &Customer,
) -> Result<(), anyhow::Error> {
    info!(
        customer_id = %customer.id,
        "Customer updated in Stripe"
    );
    // Could update local customer data if needed
    Ok(())
}

async fn handle_customer_deleted(
    _state: &WebhookState,
    customer: &Customer,
) -> Result<(), anyhow::Error> {
    warn!(
        customer_id = %customer.id,
        "Customer deleted in Stripe"
    );
    // Handle customer deletion - might need to cancel subscriptions
    Ok(())
}

// ========== Email Notification Helpers ==========

/// Get email recipient from subscription's customer
async fn get_subscription_email(
    _state: &WebhookState,
    subscription: &StripeSubscription,
) -> Option<EmailRecipient> {
    // Try to get customer email from the subscription
    match &subscription.customer {
        stripe_rust::Expandable::Id(_id) => {
            // We don't have the customer object expanded, can't get email
            None
        }
        stripe_rust::Expandable::Object(customer) => {
            // If we have the full customer object, use its email directly
            customer.email.as_ref().map(|email| EmailRecipient {
                email: email.clone(),
                name: customer.name.clone(),
            })
        }
    }
}

/// Get email recipient from invoice's customer
async fn get_invoice_email(
    _state: &WebhookState,
    invoice: &StripeInvoice,
) -> Option<EmailRecipient> {
    // Check if invoice has customer_email directly
    if let Some(email) = &invoice.customer_email {
        return Some(EmailRecipient {
            email: email.clone(),
            name: invoice.customer_name.clone(),
        });
    }

    // Try to get from customer object
    if let Some(customer) = &invoice.customer {
        match customer {
            stripe_rust::Expandable::Id(_id) => {}
            stripe_rust::Expandable::Object(cust) => {
                if let Some(email) = &cust.email {
                    return Some(EmailRecipient {
                        email: email.clone(),
                        name: cust.name.clone(),
                    });
                }
            }
        };
    }

    None
}

/// Get email recipient from checkout session
async fn get_checkout_email(
    _state: &WebhookState,
    session: &CheckoutSession,
) -> Option<EmailRecipient> {
    if let Some(email) = &session.customer_email {
        return Some(EmailRecipient {
            email: email.clone(),
            name: session
                .customer_details
                .as_ref()
                .and_then(|d| d.name.clone()),
        });
    }

    // Try from customer_details
    if let Some(details) = &session.customer_details {
        if let Some(email) = &details.email {
            return Some(EmailRecipient {
                email: email.clone(),
                name: details.name.clone(),
            });
        }
    }

    None
}

/// Format currency amount for display
fn format_amount(amount: Option<i64>, currency: &Option<stripe_rust::Currency>) -> String {
    let cents = amount.unwrap_or(0);
    let dollars = cents as f64 / 100.0;

    // Get currency symbol from the currency code string
    let currency_symbol = match currency
        .as_ref()
        .map(|c| c.to_string().to_lowercase())
        .as_deref()
    {
        Some("usd") => "$",
        Some("eur") => "€",
        Some("gbp") => "£",
        Some("cad") => "CA$",
        Some("aud") => "A$",
        _ => "$", // Default to USD
    };

    format!("{}{:.2}", currency_symbol, dollars)
}

/// Extract plan name from invoice
fn get_invoice_plan_name(invoice: &StripeInvoice) -> String {
    // Try to get from invoice lines
    if let Some(lines) = &invoice.lines {
        if let Some(first_line) = lines.data.first() {
            if let Some(description) = &first_line.description {
                return description.clone();
            }
        }
    }

    "PistonProtection Plan".to_string()
}

// ========== Subscription Event Handlers ==========

async fn handle_subscription_created(
    state: &WebhookState,
    subscription: &StripeSubscription,
) -> Result<(), anyhow::Error> {
    info!(
        subscription_id = %subscription.id,
        status = ?subscription.status,
        "Subscription created"
    );

    state
        .stripe_service
        .sync_subscription_from_stripe(subscription)
        .await?;

    Ok(())
}

async fn handle_subscription_updated(
    state: &WebhookState,
    subscription: &StripeSubscription,
) -> Result<(), anyhow::Error> {
    info!(
        subscription_id = %subscription.id,
        status = ?subscription.status,
        cancel_at_period_end = subscription.cancel_at_period_end,
        "Subscription updated"
    );

    state
        .stripe_service
        .sync_subscription_from_stripe(subscription)
        .await?;

    Ok(())
}

async fn handle_subscription_deleted(
    state: &WebhookState,
    subscription: &StripeSubscription,
) -> Result<(), anyhow::Error> {
    info!(
        subscription_id = %subscription.id,
        "Subscription deleted/canceled"
    );

    // Update subscription status to canceled
    state
        .stripe_service
        .update_subscription_status(subscription.id.as_ref(), SubscriptionStatus::Canceled)
        .await?;

    // Send cancellation email
    if let Some(email) = get_subscription_email(state, subscription).await {
        let end_date = subscription
            .ended_at
            .or(Some(subscription.current_period_end))
            .and_then(|ts| {
                chrono::DateTime::from_timestamp(ts, 0).map(|dt| dt.format("%B %d, %Y").to_string())
            })
            .unwrap_or_else(|| "soon".to_string());

        if let Err(e) = state
            .email_service
            .send_cancellation_email(email, &end_date)
            .await
        {
            warn!(error = %e, "Failed to send cancellation email");
        }
    }

    Ok(())
}

async fn handle_subscription_trial_ending(
    state: &WebhookState,
    subscription: &StripeSubscription,
) -> Result<(), anyhow::Error> {
    info!(
        subscription_id = %subscription.id,
        trial_end = ?subscription.trial_end,
        "Subscription trial ending soon"
    );

    // Send trial ending notification email
    if let Some(email) = get_subscription_email(state, subscription).await {
        // Calculate days remaining
        let days_remaining = subscription
            .trial_end
            .map(|ts| {
                let end = chrono::DateTime::from_timestamp(ts, 0).unwrap_or_default();
                let now = chrono::Utc::now();
                (end - now).num_days().max(0) as u32
            })
            .unwrap_or(3); // Default to 3 days if unknown

        let trial_end_date = subscription
            .trial_end
            .and_then(|ts| {
                chrono::DateTime::from_timestamp(ts, 0).map(|dt| dt.format("%B %d, %Y").to_string())
            })
            .unwrap_or_else(|| "soon".to_string());

        if let Err(e) = state
            .email_service
            .send_trial_ending_email(email, days_remaining, &trial_end_date)
            .await
        {
            warn!(error = %e, "Failed to send trial ending email");
        }
    }

    Ok(())
}

async fn handle_subscription_paused(
    state: &WebhookState,
    subscription: &StripeSubscription,
) -> Result<(), anyhow::Error> {
    info!(
        subscription_id = %subscription.id,
        "Subscription paused"
    );

    state
        .stripe_service
        .sync_subscription_from_stripe(subscription)
        .await?;

    Ok(())
}

async fn handle_subscription_resumed(
    state: &WebhookState,
    subscription: &StripeSubscription,
) -> Result<(), anyhow::Error> {
    info!(
        subscription_id = %subscription.id,
        "Subscription resumed"
    );

    state
        .stripe_service
        .sync_subscription_from_stripe(subscription)
        .await?;

    Ok(())
}

// ========== Invoice Event Handlers ==========

async fn handle_invoice_created(
    state: &WebhookState,
    invoice: &StripeInvoice,
) -> Result<(), anyhow::Error> {
    info!(
        invoice_id = %invoice.id,
        "Invoice created"
    );

    state
        .stripe_service
        .sync_invoice_from_stripe(invoice)
        .await?;

    Ok(())
}

async fn handle_invoice_finalized(
    state: &WebhookState,
    invoice: &StripeInvoice,
) -> Result<(), anyhow::Error> {
    info!(
        invoice_id = %invoice.id,
        total = ?invoice.total,
        "Invoice finalized"
    );

    state
        .stripe_service
        .sync_invoice_from_stripe(invoice)
        .await?;

    Ok(())
}

async fn handle_invoice_paid(
    state: &WebhookState,
    invoice: &StripeInvoice,
) -> Result<(), anyhow::Error> {
    info!(
        invoice_id = %invoice.id,
        amount_paid = ?invoice.amount_paid,
        "Invoice paid"
    );

    state
        .stripe_service
        .sync_invoice_from_stripe(invoice)
        .await?;

    // Update subscription status to active if it was past_due
    if let Some(subscription) = &invoice.subscription {
        let sub_id = match subscription {
            stripe_rust::Expandable::Id(id) => id.to_string(),
            stripe_rust::Expandable::Object(sub) => sub.id.to_string(),
        };

        if let Ok(Some(local_sub)) = state
            .stripe_service
            .get_subscription_by_stripe_id(&sub_id)
            .await
        {
            if local_sub.status == SubscriptionStatus::PastDue {
                state
                    .stripe_service
                    .update_subscription_status(&sub_id, SubscriptionStatus::Active)
                    .await?;
            }
        }
    }

    // Send payment receipt email
    if let Some(email) = get_invoice_email(state, invoice).await {
        let amount = format_amount(invoice.amount_paid, &invoice.currency);
        let invoice_id = invoice
            .number
            .clone()
            .unwrap_or_else(|| invoice.id.to_string());
        let plan_name = get_invoice_plan_name(invoice);

        if let Err(e) = state
            .email_service
            .send_payment_received_email(email, &amount, &invoice_id, &plan_name)
            .await
        {
            warn!(error = %e, "Failed to send payment receipt email");
        }
    }

    Ok(())
}

async fn handle_invoice_payment_failed(
    state: &WebhookState,
    invoice: &StripeInvoice,
) -> Result<(), anyhow::Error> {
    warn!(
        invoice_id = %invoice.id,
        attempt_count = ?invoice.attempt_count,
        "Invoice payment failed"
    );

    state
        .stripe_service
        .sync_invoice_from_stripe(invoice)
        .await?;

    // Update subscription status to past_due
    if let Some(subscription) = &invoice.subscription {
        let sub_id = match subscription {
            stripe_rust::Expandable::Id(id) => id.to_string(),
            stripe_rust::Expandable::Object(sub) => sub.id.to_string(),
        };

        state
            .stripe_service
            .update_subscription_status(&sub_id, SubscriptionStatus::PastDue)
            .await?;
    }

    // Send payment failed email
    if let Some(email) = get_invoice_email(state, invoice).await {
        let amount = format_amount(invoice.amount_due, &invoice.currency);
        let failure_reason = "Your payment method was declined".to_string();
        let attempt_count = invoice.attempt_count.unwrap_or(1) as u32;

        if let Err(e) = state
            .email_service
            .send_payment_failed_email(email, &amount, &failure_reason, attempt_count)
            .await
        {
            warn!(error = %e, "Failed to send payment failed email");
        }
    }

    Ok(())
}

async fn handle_invoice_payment_action_required(
    state: &WebhookState,
    invoice: &StripeInvoice,
) -> Result<(), anyhow::Error> {
    warn!(
        invoice_id = %invoice.id,
        "Invoice payment requires action (3D Secure, etc.)"
    );

    state
        .stripe_service
        .sync_invoice_from_stripe(invoice)
        .await?;

    // Send payment action required email
    if let Some(email) = get_invoice_email(state, invoice).await {
        let amount = format_amount(invoice.amount_due, &invoice.currency);
        // Use the payment failed email with a custom reason for action required
        if let Err(e) = state
            .email_service
            .send_payment_failed_email(
                email,
                &amount,
                "Additional verification is required to complete your payment (3D Secure)",
                1,
            )
            .await
        {
            warn!(error = %e, "Failed to send payment action required email");
        }
    }

    Ok(())
}

async fn handle_invoice_upcoming(
    _state: &WebhookState,
    invoice: &StripeInvoice,
) -> Result<(), anyhow::Error> {
    info!(
        invoice_id = %invoice.id,
        amount_due = ?invoice.amount_due,
        "Upcoming invoice"
    );

    // TODO: Send upcoming invoice notification
    // This is a good time to remind users about their upcoming charge

    Ok(())
}

async fn handle_invoice_uncollectible(
    state: &WebhookState,
    invoice: &StripeInvoice,
) -> Result<(), anyhow::Error> {
    error!(
        invoice_id = %invoice.id,
        "Invoice marked as uncollectible"
    );

    state
        .stripe_service
        .sync_invoice_from_stripe(invoice)
        .await?;

    // Update subscription status
    if let Some(subscription) = &invoice.subscription {
        let sub_id = match subscription {
            stripe_rust::Expandable::Id(id) => id.to_string(),
            stripe_rust::Expandable::Object(sub) => sub.id.to_string(),
        };

        state
            .stripe_service
            .update_subscription_status(&sub_id, SubscriptionStatus::Unpaid)
            .await?;
    }

    // TODO: Consider downgrading or suspending the account

    Ok(())
}

async fn handle_invoice_voided(
    state: &WebhookState,
    invoice: &StripeInvoice,
) -> Result<(), anyhow::Error> {
    info!(
        invoice_id = %invoice.id,
        "Invoice voided"
    );

    state
        .stripe_service
        .sync_invoice_from_stripe(invoice)
        .await?;

    Ok(())
}

// ========== Payment Intent Event Handlers ==========

async fn handle_payment_intent_created(
    _state: &WebhookState,
    payment_intent: &PaymentIntent,
) -> Result<(), anyhow::Error> {
    info!(
        payment_intent_id = %payment_intent.id,
        amount = payment_intent.amount,
        "Payment intent created"
    );
    Ok(())
}

async fn handle_payment_intent_succeeded(
    _state: &WebhookState,
    payment_intent: &PaymentIntent,
) -> Result<(), anyhow::Error> {
    info!(
        payment_intent_id = %payment_intent.id,
        amount = payment_intent.amount,
        "Payment intent succeeded"
    );

    // Payment success is usually handled via invoice.paid
    // This is mainly for one-off payments

    Ok(())
}

async fn handle_payment_intent_failed(
    _state: &WebhookState,
    payment_intent: &PaymentIntent,
) -> Result<(), anyhow::Error> {
    warn!(
        payment_intent_id = %payment_intent.id,
        last_payment_error = ?payment_intent.last_payment_error,
        "Payment intent failed"
    );

    // TODO: Log payment failure details for debugging
    // TODO: Notify customer of payment failure

    Ok(())
}

async fn handle_payment_intent_canceled(
    _state: &WebhookState,
    payment_intent: &PaymentIntent,
) -> Result<(), anyhow::Error> {
    info!(
        payment_intent_id = %payment_intent.id,
        "Payment intent canceled"
    );
    Ok(())
}

async fn handle_payment_intent_requires_action(
    _state: &WebhookState,
    payment_intent: &PaymentIntent,
) -> Result<(), anyhow::Error> {
    info!(
        payment_intent_id = %payment_intent.id,
        "Payment intent requires action"
    );

    // TODO: Send notification to complete 3D Secure or other verification

    Ok(())
}

// ========== Checkout Session Event Handlers ==========

async fn handle_checkout_session_completed(
    state: &WebhookState,
    session: &CheckoutSession,
) -> Result<(), anyhow::Error> {
    info!(
        session_id = %session.id,
        mode = ?session.mode,
        "Checkout session completed"
    );

    // Create/update subscription from the completed checkout
    state
        .stripe_service
        .create_subscription_from_checkout(session)
        .await?;

    // Send welcome email for new subscription
    if let Some(email) = get_checkout_email(state, session).await {
        // Extract plan name from session metadata or line items
        let plan_name = session
            .metadata
            .as_ref()
            .and_then(|m| m.get("plan_name").cloned())
            .unwrap_or_else(|| "PistonProtection".to_string());

        if let Err(e) = state
            .email_service
            .send_welcome_email(email, &plan_name)
            .await
        {
            warn!(error = %e, "Failed to send welcome email");
        }
    }

    Ok(())
}

async fn handle_checkout_session_expired(
    _state: &WebhookState,
    session: &CheckoutSession,
) -> Result<(), anyhow::Error> {
    info!(
        session_id = %session.id,
        "Checkout session expired"
    );

    // TODO: Optionally send abandoned checkout email

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_webhook_signature() {
        // Test signature format parsing
        let payload = b"test payload";
        let secret = "whsec_test_secret";
        let timestamp = chrono::Utc::now().timestamp();

        // Create a valid signature
        let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(payload));
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(signed_payload.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        let signature_header = format!("t={},v1={}", timestamp, signature);

        assert!(verify_webhook_signature(payload, &signature_header, secret).is_ok());
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("hello", "hello"));
        assert!(!constant_time_compare("hello", "world"));
        assert!(!constant_time_compare("hello", "hell"));
        assert!(!constant_time_compare("hell", "hello"));
    }

    #[test]
    fn test_webhook_response() {
        let success = WebhookResponse::success();
        assert!(success.received);
        assert!(success.error.is_none());

        let error = WebhookResponse::error("test error");
        assert!(!error.received);
        assert_eq!(error.error, Some("test error".to_string()));
    }
}
