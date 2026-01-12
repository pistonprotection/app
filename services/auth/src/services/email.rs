//! Email notification service for PistonProtection
//!
//! Provides templated email notifications for billing events, account updates,
//! and other system notifications.

use pistonprotection_common::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, error, info, warn};

/// Email service configuration
#[derive(Debug, Clone)]
pub struct EmailConfig {
    /// SMTP server host
    pub smtp_host: String,
    /// SMTP server port
    pub smtp_port: u16,
    /// SMTP username
    pub smtp_username: String,
    /// SMTP password
    pub smtp_password: String,
    /// Sender email address
    pub sender_email: String,
    /// Sender name
    pub sender_name: String,
    /// Base URL for links in emails
    pub base_url: String,
    /// Whether to actually send emails (false for testing)
    pub enabled: bool,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            smtp_host: std::env::var("SMTP_HOST").unwrap_or_else(|_| "localhost".to_string()),
            smtp_port: std::env::var("SMTP_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(587),
            smtp_username: std::env::var("SMTP_USERNAME").unwrap_or_default(),
            smtp_password: std::env::var("SMTP_PASSWORD").unwrap_or_default(),
            sender_email: std::env::var("SMTP_SENDER_EMAIL")
                .unwrap_or_else(|_| "noreply@pistonprotection.io".to_string()),
            sender_name: std::env::var("SMTP_SENDER_NAME")
                .unwrap_or_else(|_| "PistonProtection".to_string()),
            base_url: std::env::var("APP_BASE_URL")
                .unwrap_or_else(|_| "https://app.pistonprotection.io".to_string()),
            enabled: std::env::var("EMAIL_ENABLED")
                .map(|s| s == "true" || s == "1")
                .unwrap_or(true),
        }
    }
}

/// Email template type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailTemplate {
    // Subscription emails
    WelcomeNewSubscription,
    SubscriptionCanceled,
    SubscriptionPaused,
    SubscriptionResumed,
    TrialEnding,
    TrialExpired,

    // Payment emails
    PaymentReceived,
    PaymentFailed,
    PaymentFailedFinal,
    PaymentActionRequired,
    UpcomingInvoice,
    AccountDowngraded,

    // Security emails
    PasswordReset,
    EmailVerification,
    NewDeviceLogin,
    ApiKeyCreated,
}

impl EmailTemplate {
    /// Get the subject line for this template
    fn subject(&self) -> &'static str {
        match self {
            EmailTemplate::WelcomeNewSubscription => "Welcome to PistonProtection!",
            EmailTemplate::SubscriptionCanceled => "Your subscription has been canceled",
            EmailTemplate::SubscriptionPaused => "Your subscription has been paused",
            EmailTemplate::SubscriptionResumed => "Your subscription has been resumed",
            EmailTemplate::TrialEnding => "Your free trial is ending soon",
            EmailTemplate::TrialExpired => "Your free trial has expired",
            EmailTemplate::PaymentReceived => "Payment received - Thank you!",
            EmailTemplate::PaymentFailed => "Payment failed - Action required",
            EmailTemplate::PaymentFailedFinal => "Final notice: Update payment method",
            EmailTemplate::PaymentActionRequired => "Complete your payment",
            EmailTemplate::UpcomingInvoice => "Your upcoming invoice",
            EmailTemplate::AccountDowngraded => "Your account has been downgraded",
            EmailTemplate::PasswordReset => "Reset your password",
            EmailTemplate::EmailVerification => "Verify your email address",
            EmailTemplate::NewDeviceLogin => "New device login detected",
            EmailTemplate::ApiKeyCreated => "New API key created",
        }
    }
}

/// Email recipient information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailRecipient {
    pub email: String,
    pub name: Option<String>,
}

/// Email message to be sent
#[derive(Debug, Clone)]
pub struct EmailMessage {
    pub to: EmailRecipient,
    pub template: EmailTemplate,
    pub variables: HashMap<String, String>,
    pub metadata: Option<HashMap<String, String>>,
}

impl EmailMessage {
    /// Create a new email message
    pub fn new(to: EmailRecipient, template: EmailTemplate) -> Self {
        Self {
            to,
            template,
            variables: HashMap::new(),
            metadata: None,
        }
    }

    /// Add a template variable
    pub fn with_variable<K: Into<String>, V: Into<String>>(mut self, key: K, value: V) -> Self {
        self.variables.insert(key.into(), value.into());
        self
    }

    /// Add multiple template variables
    pub fn with_variables(mut self, vars: HashMap<String, String>) -> Self {
        self.variables.extend(vars);
        self
    }

    /// Add metadata for tracking
    pub fn with_metadata(mut self, metadata: HashMap<String, String>) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

/// Email delivery result
#[derive(Debug, Clone)]
pub struct EmailResult {
    pub message_id: Option<String>,
    pub success: bool,
    pub error: Option<String>,
}

/// Email service for sending notifications
pub struct EmailService {
    config: EmailConfig,
}

impl EmailService {
    /// Create a new email service
    pub fn new(config: EmailConfig) -> Self {
        Self { config }
    }

    /// Send an email message
    pub async fn send(&self, message: EmailMessage) -> Result<EmailResult> {
        if !self.config.enabled {
            info!(
                email = %message.to.email,
                template = ?message.template,
                "Email sending disabled, skipping"
            );
            return Ok(EmailResult {
                message_id: None,
                success: true,
                error: None,
            });
        }

        debug!(
            email = %message.to.email,
            template = ?message.template,
            "Sending email"
        );

        // Build the email content
        let subject = message.template.subject();
        let body = self.render_template(&message)?;

        // In a production implementation, this would use an SMTP client
        // or email service API (SendGrid, Mailgun, etc.)
        self.send_via_smtp(&message.to.email, subject, &body).await
    }

    /// Render an email template with variables
    fn render_template(&self, message: &EmailMessage) -> Result<String> {
        let mut body = self.get_template_html(message.template);

        // Replace variables
        for (key, value) in &message.variables {
            let placeholder = format!("{{{{{}}}}}", key);
            body = body.replace(&placeholder, value);
        }

        // Replace common variables
        body = body.replace("{{base_url}}", &self.config.base_url);
        body = body.replace("{{sender_name}}", &self.config.sender_name);
        body = body.replace("{{recipient_email}}", &message.to.email);
        if let Some(ref name) = message.to.name {
            body = body.replace("{{recipient_name}}", name);
        } else {
            body = body.replace("{{recipient_name}}", "there");
        }

        Ok(body)
    }

    /// Get the HTML template for a given template type
    fn get_template_html(&self, template: EmailTemplate) -> String {
        // In production, these would be loaded from files or a database
        match template {
            EmailTemplate::WelcomeNewSubscription => {
                r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    <h1 style="color: #2563eb;">Welcome to PistonProtection!</h1>
    <p>Hi {{recipient_name}},</p>
    <p>Thank you for subscribing to PistonProtection. Your {{plan_name}} subscription is now active.</p>
    <p>Here's what you can do next:</p>
    <ul>
        <li>Configure your first backend for DDoS protection</li>
        <li>Set up filter rules to block malicious traffic</li>
        <li>Monitor your traffic in the dashboard</li>
    </ul>
    <p><a href="{{base_url}}/dashboard" style="background: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Go to Dashboard</a></p>
    <p>If you have any questions, don't hesitate to reach out to our support team.</p>
    <p>Best regards,<br>The PistonProtection Team</p>
</div>
</body>
</html>"#.to_string()
            }
            EmailTemplate::SubscriptionCanceled => {
                r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    <h1 style="color: #dc2626;">Subscription Canceled</h1>
    <p>Hi {{recipient_name}},</p>
    <p>Your PistonProtection subscription has been canceled as requested.</p>
    <p>Your access will continue until {{end_date}}.</p>
    <p>We're sorry to see you go. If you change your mind, you can resubscribe at any time.</p>
    <p>If there's anything we could have done better, we'd love to hear your feedback.</p>
    <p><a href="{{base_url}}/pricing" style="background: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Resubscribe</a></p>
    <p>Best regards,<br>The PistonProtection Team</p>
</div>
</body>
</html>"#.to_string()
            }
            EmailTemplate::TrialEnding => {
                r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    <h1 style="color: #f59e0b;">Your Trial Ends in {{days_remaining}} Days</h1>
    <p>Hi {{recipient_name}},</p>
    <p>Your free trial of PistonProtection will end on {{trial_end_date}}.</p>
    <p>To continue protecting your infrastructure from DDoS attacks, please add a payment method to upgrade your account.</p>
    <p><a href="{{base_url}}/billing" style="background: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Upgrade Now</a></p>
    <p>If you have any questions about our plans, feel free to reach out.</p>
    <p>Best regards,<br>The PistonProtection Team</p>
</div>
</body>
</html>"#.to_string()
            }
            EmailTemplate::PaymentReceived => {
                r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    <h1 style="color: #16a34a;">Payment Received</h1>
    <p>Hi {{recipient_name}},</p>
    <p>We've received your payment of {{amount}} for your PistonProtection subscription.</p>
    <p><strong>Invoice ID:</strong> {{invoice_id}}<br>
    <strong>Payment Date:</strong> {{payment_date}}<br>
    <strong>Plan:</strong> {{plan_name}}</p>
    <p>You can view your receipt and billing history in your account settings.</p>
    <p><a href="{{base_url}}/billing" style="background: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">View Billing</a></p>
    <p>Thank you for your continued trust in PistonProtection.</p>
    <p>Best regards,<br>The PistonProtection Team</p>
</div>
</body>
</html>"#.to_string()
            }
            EmailTemplate::PaymentFailed => {
                r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    <h1 style="color: #dc2626;">Payment Failed</h1>
    <p>Hi {{recipient_name}},</p>
    <p>We were unable to process your payment of {{amount}} for your PistonProtection subscription.</p>
    <p><strong>Reason:</strong> {{failure_reason}}</p>
    <p>Please update your payment method to avoid service interruption. We'll automatically retry the payment in a few days.</p>
    <p><a href="{{base_url}}/billing/update-payment" style="background: #dc2626; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Update Payment Method</a></p>
    <p>If you need any assistance, please contact our support team.</p>
    <p>Best regards,<br>The PistonProtection Team</p>
</div>
</body>
</html>"#.to_string()
            }
            EmailTemplate::PaymentFailedFinal => {
                r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    <h1 style="color: #dc2626;">Final Notice: Payment Required</h1>
    <p>Hi {{recipient_name}},</p>
    <p>Despite multiple attempts, we've been unable to collect payment for your PistonProtection subscription.</p>
    <p><strong>Amount Due:</strong> {{amount}}<br>
    <strong>Attempts:</strong> {{attempt_count}}</p>
    <p><strong>Important:</strong> If payment is not received within 3 days, your account will be downgraded to the free tier and your backends will lose DDoS protection.</p>
    <p><a href="{{base_url}}/billing/update-payment" style="background: #dc2626; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Update Payment Method Now</a></p>
    <p>Best regards,<br>The PistonProtection Team</p>
</div>
</body>
</html>"#.to_string()
            }
            EmailTemplate::AccountDowngraded => {
                r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    <h1 style="color: #dc2626;">Account Downgraded</h1>
    <p>Hi {{recipient_name}},</p>
    <p>Due to non-payment, your PistonProtection account has been downgraded to the free tier.</p>
    <p><strong>What this means:</strong></p>
    <ul>
        <li>Your backends beyond the free tier limit have been disabled</li>
        <li>Advanced DDoS protection features are no longer available</li>
        <li>You may experience reduced traffic limits</li>
    </ul>
    <p>To restore your service, please update your payment method and resubscribe.</p>
    <p><a href="{{base_url}}/pricing" style="background: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Resubscribe</a></p>
    <p>Best regards,<br>The PistonProtection Team</p>
</div>
</body>
</html>"#.to_string()
            }
            // Default template for other types
            _ => {
                r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    <h1 style="color: #2563eb;">PistonProtection Notification</h1>
    <p>Hi {{recipient_name}},</p>
    <p>{{message}}</p>
    <p><a href="{{base_url}}/dashboard" style="background: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Go to Dashboard</a></p>
    <p>Best regards,<br>The PistonProtection Team</p>
</div>
</body>
</html>"#.to_string()
            }
        }
    }

    /// Send email via SMTP
    async fn send_via_smtp(
        &self,
        to: &str,
        subject: &str,
        body: &str,
    ) -> Result<EmailResult> {
        // In a real implementation, use lettre or similar SMTP library
        // For now, log the email and return success
        info!(
            to = %to,
            subject = %subject,
            "Would send email (SMTP not configured)"
        );

        // TODO: Implement actual SMTP sending with lettre
        // use lettre::{Message, SmtpTransport, Transport};
        // let email = Message::builder()
        //     .from(format!("{} <{}>", self.config.sender_name, self.config.sender_email).parse().unwrap())
        //     .to(to.parse().unwrap())
        //     .subject(subject)
        //     .header(lettre::message::header::ContentType::TEXT_HTML)
        //     .body(body.to_string())
        //     .unwrap();
        //
        // let transport = SmtpTransport::relay(&self.config.smtp_host)
        //     .unwrap()
        //     .port(self.config.smtp_port)
        //     .credentials(Credentials::new(
        //         self.config.smtp_username.clone(),
        //         self.config.smtp_password.clone(),
        //     ))
        //     .build();
        //
        // transport.send(&email)?;

        Ok(EmailResult {
            message_id: Some(uuid::Uuid::new_v4().to_string()),
            success: true,
            error: None,
        })
    }

    // ========== Convenience methods for common emails ==========

    /// Send welcome email for new subscription
    pub async fn send_welcome_email(
        &self,
        recipient: EmailRecipient,
        plan_name: &str,
    ) -> Result<EmailResult> {
        let message = EmailMessage::new(recipient, EmailTemplate::WelcomeNewSubscription)
            .with_variable("plan_name", plan_name);
        self.send(message).await
    }

    /// Send subscription canceled email
    pub async fn send_cancellation_email(
        &self,
        recipient: EmailRecipient,
        end_date: &str,
    ) -> Result<EmailResult> {
        let message = EmailMessage::new(recipient, EmailTemplate::SubscriptionCanceled)
            .with_variable("end_date", end_date);
        self.send(message).await
    }

    /// Send trial ending notification
    pub async fn send_trial_ending_email(
        &self,
        recipient: EmailRecipient,
        days_remaining: u32,
        trial_end_date: &str,
    ) -> Result<EmailResult> {
        let message = EmailMessage::new(recipient, EmailTemplate::TrialEnding)
            .with_variable("days_remaining", days_remaining.to_string())
            .with_variable("trial_end_date", trial_end_date);
        self.send(message).await
    }

    /// Send payment received email
    pub async fn send_payment_received_email(
        &self,
        recipient: EmailRecipient,
        amount: &str,
        invoice_id: &str,
        plan_name: &str,
    ) -> Result<EmailResult> {
        let message = EmailMessage::new(recipient, EmailTemplate::PaymentReceived)
            .with_variable("amount", amount)
            .with_variable("invoice_id", invoice_id)
            .with_variable("plan_name", plan_name)
            .with_variable("payment_date", chrono::Utc::now().format("%B %d, %Y").to_string());
        self.send(message).await
    }

    /// Send payment failed email
    pub async fn send_payment_failed_email(
        &self,
        recipient: EmailRecipient,
        amount: &str,
        failure_reason: &str,
        attempt_count: u32,
    ) -> Result<EmailResult> {
        // Use final notice template if this is the last attempt
        let template = if attempt_count >= 3 {
            EmailTemplate::PaymentFailedFinal
        } else {
            EmailTemplate::PaymentFailed
        };

        let message = EmailMessage::new(recipient, template)
            .with_variable("amount", amount)
            .with_variable("failure_reason", failure_reason)
            .with_variable("attempt_count", attempt_count.to_string());
        self.send(message).await
    }

    /// Send account downgraded email
    pub async fn send_account_downgraded_email(
        &self,
        recipient: EmailRecipient,
    ) -> Result<EmailResult> {
        let message = EmailMessage::new(recipient, EmailTemplate::AccountDowngraded);
        self.send(message).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_template_subjects() {
        assert_eq!(
            EmailTemplate::WelcomeNewSubscription.subject(),
            "Welcome to PistonProtection!"
        );
        assert_eq!(
            EmailTemplate::PaymentFailed.subject(),
            "Payment failed - Action required"
        );
    }

    #[test]
    fn test_email_message_builder() {
        let recipient = EmailRecipient {
            email: "test@example.com".to_string(),
            name: Some("Test User".to_string()),
        };

        let message = EmailMessage::new(recipient, EmailTemplate::PaymentReceived)
            .with_variable("amount", "$99.00")
            .with_variable("invoice_id", "INV-123");

        assert_eq!(message.variables.get("amount"), Some(&"$99.00".to_string()));
        assert_eq!(message.variables.get("invoice_id"), Some(&"INV-123".to_string()));
    }

    #[tokio::test]
    async fn test_email_service_disabled() {
        let config = EmailConfig {
            enabled: false,
            ..Default::default()
        };

        let service = EmailService::new(config);
        let recipient = EmailRecipient {
            email: "test@example.com".to_string(),
            name: None,
        };

        let result = service
            .send_welcome_email(recipient, "Pro")
            .await
            .unwrap();

        assert!(result.success);
    }
}
