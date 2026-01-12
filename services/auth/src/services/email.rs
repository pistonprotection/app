//! Email notification service for PistonProtection
//!
//! Provides templated email notifications for billing events, account updates,
//! and other system notifications. Supports both SMTP and Resend API.

use pistonprotection_common::error::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, error, info};

/// Email provider type
#[derive(Debug, Clone, Default)]
pub enum EmailProvider {
    /// Resend API (recommended)
    Resend,
    /// SMTP server
    Smtp,
    /// Disabled - just logs emails
    #[default]
    Disabled,
}

/// Email service configuration
#[derive(Debug, Clone)]
pub struct EmailConfig {
    /// Email provider to use
    pub provider: EmailProvider,
    /// Resend API key
    pub resend_api_key: Option<String>,
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
        // Determine provider based on environment
        let resend_api_key = std::env::var("RESEND_API_KEY").ok();
        let provider = if resend_api_key.is_some() {
            EmailProvider::Resend
        } else if std::env::var("SMTP_HOST").is_ok() {
            EmailProvider::Smtp
        } else {
            EmailProvider::Disabled
        };

        Self {
            provider,
            resend_api_key,
            smtp_host: std::env::var("SMTP_HOST").unwrap_or_else(|_| "localhost".to_string()),
            smtp_port: std::env::var("SMTP_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(587),
            smtp_username: std::env::var("SMTP_USERNAME").unwrap_or_default(),
            smtp_password: std::env::var("SMTP_PASSWORD").unwrap_or_default(),
            sender_email: std::env::var("SMTP_SENDER_EMAIL")
                .or_else(|_| std::env::var("RESEND_SENDER_EMAIL"))
                .unwrap_or_else(|_| "noreply@pistonprotection.io".to_string()),
            sender_name: std::env::var("SMTP_SENDER_NAME")
                .or_else(|_| std::env::var("RESEND_SENDER_NAME"))
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
    TwoFactorEnabled,

    // Team emails
    InvitationSent,
    MemberJoined,
    MemberRemoved,

    // Alerts
    AttackDetected,
    AttackMitigated,
    BackendHealthWarning,
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
            EmailTemplate::TwoFactorEnabled => "Two-factor authentication enabled",
            EmailTemplate::InvitationSent => "You've been invited to PistonProtection",
            EmailTemplate::MemberJoined => "New team member joined",
            EmailTemplate::MemberRemoved => "Team member removed",
            EmailTemplate::AttackDetected => "DDoS Attack Detected - Protection Active",
            EmailTemplate::AttackMitigated => "DDoS Attack Mitigated",
            EmailTemplate::BackendHealthWarning => "Backend Health Warning",
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

/// Resend API request body
#[derive(Debug, Serialize)]
struct ResendEmailRequest {
    from: String,
    to: Vec<String>,
    subject: String,
    html: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<ResendTag>>,
}

#[derive(Debug, Serialize)]
struct ResendTag {
    name: String,
    value: String,
}

/// Resend API response
#[derive(Debug, Deserialize)]
struct ResendEmailResponse {
    id: String,
}

/// Resend API error response
#[derive(Debug, Deserialize)]
struct ResendErrorResponse {
    message: String,
}

/// Email service for sending notifications
pub struct EmailService {
    config: EmailConfig,
    http_client: Client,
}

impl EmailService {
    /// Create a new email service
    pub fn new(config: EmailConfig) -> Self {
        Self {
            config,
            http_client: Client::new(),
        }
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

        match self.config.provider {
            EmailProvider::Resend => self.send_via_resend(&message.to, subject, &body, &message).await,
            EmailProvider::Smtp => self.send_via_smtp(&message.to.email, subject, &body).await,
            EmailProvider::Disabled => {
                info!(
                    to = %message.to.email,
                    subject = %subject,
                    "Email provider disabled, logging only"
                );
                Ok(EmailResult {
                    message_id: Some(uuid::Uuid::new_v4().to_string()),
                    success: true,
                    error: None,
                })
            }
        }
    }

    /// Send email via Resend API
    async fn send_via_resend(
        &self,
        to: &EmailRecipient,
        subject: &str,
        body: &str,
        message: &EmailMessage,
    ) -> Result<EmailResult> {
        let api_key = match &self.config.resend_api_key {
            Some(key) => key,
            None => {
                error!("Resend API key not configured");
                return Ok(EmailResult {
                    message_id: None,
                    success: false,
                    error: Some("Resend API key not configured".to_string()),
                });
            }
        };

        let from = format!("{} <{}>", self.config.sender_name, self.config.sender_email);
        let to_email = match &to.name {
            Some(name) => format!("{} <{}>", name, to.email),
            None => to.email.clone(),
        };

        // Build tags for tracking
        let tags = message.metadata.as_ref().map(|meta| {
            meta.iter()
                .map(|(k, v)| ResendTag {
                    name: k.clone(),
                    value: v.clone(),
                })
                .collect()
        });

        let request_body = ResendEmailRequest {
            from,
            to: vec![to_email],
            subject: subject.to_string(),
            html: body.to_string(),
            tags,
        };

        let response = self
            .http_client
            .post("https://api.resend.com/emails")
            .bearer_auth(api_key)
            .json(&request_body)
            .send()
            .await;

        match response {
            Ok(resp) => {
                if resp.status().is_success() {
                    match resp.json::<ResendEmailResponse>().await {
                        Ok(email_resp) => {
                            info!(
                                message_id = %email_resp.id,
                                to = %to.email,
                                subject = %subject,
                                "Email sent successfully via Resend"
                            );
                            Ok(EmailResult {
                                message_id: Some(email_resp.id),
                                success: true,
                                error: None,
                            })
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to parse Resend response");
                            Ok(EmailResult {
                                message_id: None,
                                success: false,
                                error: Some(format!("Failed to parse response: {}", e)),
                            })
                        }
                    }
                } else {
                    let error_msg = match resp.json::<ResendErrorResponse>().await {
                        Ok(err) => err.message,
                        Err(_) => "Unknown error".to_string(),
                    };
                    error!(error = %error_msg, "Resend API error");
                    Ok(EmailResult {
                        message_id: None,
                        success: false,
                        error: Some(error_msg),
                    })
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to send email via Resend");
                Ok(EmailResult {
                    message_id: None,
                    success: false,
                    error: Some(e.to_string()),
                })
            }
        }
    }

    /// Send email via SMTP
    async fn send_via_smtp(&self, to: &str, subject: &str, _body: &str) -> Result<EmailResult> {
        // In a real implementation, use lettre or similar SMTP library
        // For now, log the email and return success
        info!(
            to = %to,
            subject = %subject,
            "Would send email via SMTP (not implemented)"
        );

        // TODO: Implement actual SMTP sending with lettre
        Ok(EmailResult {
            message_id: Some(uuid::Uuid::new_v4().to_string()),
            success: true,
            error: None,
        })
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
        // Base styles for all emails
        let base_style = r#"
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #1f2937;
        "#;
        let btn_style = "background: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: 500;";
        let danger_btn_style = "background: #dc2626; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: 500;";

        match template {
            EmailTemplate::WelcomeNewSubscription => format!(
                r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="{}">
<div style="max-width: 600px; margin: 0 auto; padding: 20px; background: #ffffff;">
    <div style="text-align: center; margin-bottom: 32px;">
        <h1 style="color: #2563eb; margin: 0;">Welcome to PistonProtection!</h1>
    </div>
    <p>Hi {{{{recipient_name}}}},</p>
    <p>Thank you for subscribing to PistonProtection. Your <strong>{{{{plan_name}}}}</strong> subscription is now active.</p>
    <p>Here's what you can do next:</p>
    <ul style="padding-left: 20px;">
        <li>Configure your first backend for DDoS protection</li>
        <li>Set up filter rules to block malicious traffic</li>
        <li>Monitor your traffic in the dashboard</li>
    </ul>
    <p style="text-align: center; margin: 32px 0;">
        <a href="{{{{base_url}}}}/dashboard" style="{}">Go to Dashboard</a>
    </p>
    <p>If you have any questions, don't hesitate to reach out to our support team.</p>
    <p style="color: #6b7280;">Best regards,<br>The PistonProtection Team</p>
</div>
</body>
</html>"#, base_style, btn_style),

            EmailTemplate::SubscriptionCanceled => format!(
                r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="{}">
<div style="max-width: 600px; margin: 0 auto; padding: 20px; background: #ffffff;">
    <h1 style="color: #dc2626;">Subscription Canceled</h1>
    <p>Hi {{{{recipient_name}}}},</p>
    <p>Your PistonProtection subscription has been canceled as requested.</p>
    <p>Your access will continue until <strong>{{{{end_date}}}}</strong>.</p>
    <p>We're sorry to see you go. If you change your mind, you can resubscribe at any time.</p>
    <p style="text-align: center; margin: 32px 0;">
        <a href="{{{{base_url}}}}/pricing" style="{}">Resubscribe</a>
    </p>
    <p style="color: #6b7280;">Best regards,<br>The PistonProtection Team</p>
</div>
</body>
</html>"#, base_style, btn_style),

            EmailTemplate::TrialEnding => format!(
                r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="{}">
<div style="max-width: 600px; margin: 0 auto; padding: 20px; background: #ffffff;">
    <h1 style="color: #f59e0b;">Your Trial Ends in {{{{days_remaining}}}} Days</h1>
    <p>Hi {{{{recipient_name}}}},</p>
    <p>Your free trial of PistonProtection will end on <strong>{{{{trial_end_date}}}}</strong>.</p>
    <p>To continue protecting your infrastructure from DDoS attacks, please add a payment method to upgrade your account.</p>
    <p style="text-align: center; margin: 32px 0;">
        <a href="{{{{base_url}}}}/dashboard/billing" style="{}">Upgrade Now</a>
    </p>
    <p>If you have any questions about our plans, feel free to reach out.</p>
    <p style="color: #6b7280;">Best regards,<br>The PistonProtection Team</p>
</div>
</body>
</html>"#, base_style, btn_style),

            EmailTemplate::PaymentReceived => format!(
                r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="{}">
<div style="max-width: 600px; margin: 0 auto; padding: 20px; background: #ffffff;">
    <h1 style="color: #16a34a;">Payment Received</h1>
    <p>Hi {{{{recipient_name}}}},</p>
    <p>We've received your payment of <strong>{{{{amount}}}}</strong> for your PistonProtection subscription.</p>
    <div style="background: #f3f4f6; padding: 16px; border-radius: 8px; margin: 24px 0;">
        <p style="margin: 4px 0;"><strong>Invoice ID:</strong> {{{{invoice_id}}}}</p>
        <p style="margin: 4px 0;"><strong>Payment Date:</strong> {{{{payment_date}}}}</p>
        <p style="margin: 4px 0;"><strong>Plan:</strong> {{{{plan_name}}}}</p>
    </div>
    <p>You can view your receipt and billing history in your account settings.</p>
    <p style="text-align: center; margin: 32px 0;">
        <a href="{{{{base_url}}}}/dashboard/billing" style="{}">View Billing</a>
    </p>
    <p>Thank you for your continued trust in PistonProtection.</p>
    <p style="color: #6b7280;">Best regards,<br>The PistonProtection Team</p>
</div>
</body>
</html>"#, base_style, btn_style),

            EmailTemplate::PaymentFailed => format!(
                r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="{}">
<div style="max-width: 600px; margin: 0 auto; padding: 20px; background: #ffffff;">
    <h1 style="color: #dc2626;">Payment Failed</h1>
    <p>Hi {{{{recipient_name}}}},</p>
    <p>We were unable to process your payment of <strong>{{{{amount}}}}</strong> for your PistonProtection subscription.</p>
    <div style="background: #fef2f2; padding: 16px; border-radius: 8px; margin: 24px 0; border-left: 4px solid #dc2626;">
        <p style="margin: 0;"><strong>Reason:</strong> {{{{failure_reason}}}}</p>
    </div>
    <p>Please update your payment method to avoid service interruption. We'll automatically retry the payment in a few days.</p>
    <p style="text-align: center; margin: 32px 0;">
        <a href="{{{{base_url}}}}/dashboard/billing" style="{}">Update Payment Method</a>
    </p>
    <p>If you need any assistance, please contact our support team.</p>
    <p style="color: #6b7280;">Best regards,<br>The PistonProtection Team</p>
</div>
</body>
</html>"#, base_style, danger_btn_style),

            EmailTemplate::PaymentFailedFinal => format!(
                r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="{}">
<div style="max-width: 600px; margin: 0 auto; padding: 20px; background: #ffffff;">
    <div style="background: #fef2f2; padding: 24px; border-radius: 8px; text-align: center; margin-bottom: 24px;">
        <h1 style="color: #dc2626; margin: 0;">Final Notice: Payment Required</h1>
    </div>
    <p>Hi {{{{recipient_name}}}},</p>
    <p>Despite multiple attempts, we've been unable to collect payment for your PistonProtection subscription.</p>
    <div style="background: #fef2f2; padding: 16px; border-radius: 8px; margin: 24px 0;">
        <p style="margin: 4px 0;"><strong>Amount Due:</strong> {{{{amount}}}}</p>
        <p style="margin: 4px 0;"><strong>Attempts:</strong> {{{{attempt_count}}}}</p>
    </div>
    <p style="color: #dc2626;"><strong>Important:</strong> If payment is not received within 3 days, your account will be downgraded to the free tier and your backends will lose DDoS protection.</p>
    <p style="text-align: center; margin: 32px 0;">
        <a href="{{{{base_url}}}}/dashboard/billing" style="{}">Update Payment Method Now</a>
    </p>
    <p style="color: #6b7280;">Best regards,<br>The PistonProtection Team</p>
</div>
</body>
</html>"#, base_style, danger_btn_style),

            EmailTemplate::AccountDowngraded => format!(
                r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="{}">
<div style="max-width: 600px; margin: 0 auto; padding: 20px; background: #ffffff;">
    <h1 style="color: #dc2626;">Account Downgraded</h1>
    <p>Hi {{{{recipient_name}}}},</p>
    <p>Due to non-payment, your PistonProtection account has been downgraded to the free tier.</p>
    <p><strong>What this means:</strong></p>
    <ul style="padding-left: 20px;">
        <li>Your backends beyond the free tier limit have been disabled</li>
        <li>Advanced DDoS protection features are no longer available</li>
        <li>You may experience reduced traffic limits</li>
    </ul>
    <p>To restore your service, please update your payment method and resubscribe.</p>
    <p style="text-align: center; margin: 32px 0;">
        <a href="{{{{base_url}}}}/pricing" style="{}">Resubscribe</a>
    </p>
    <p style="color: #6b7280;">Best regards,<br>The PistonProtection Team</p>
</div>
</body>
</html>"#, base_style, btn_style),

            EmailTemplate::PasswordReset => format!(
                r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="{}">
<div style="max-width: 600px; margin: 0 auto; padding: 20px; background: #ffffff;">
    <h1 style="color: #2563eb;">Reset Your Password</h1>
    <p>Hi {{{{recipient_name}}}},</p>
    <p>We received a request to reset your password. Click the button below to create a new password:</p>
    <p style="text-align: center; margin: 32px 0;">
        <a href="{{{{reset_link}}}}" style="{}">Reset Password</a>
    </p>
    <p style="color: #6b7280; font-size: 14px;">This link will expire in {{{{expires_in_minutes}}}} minutes.</p>
    <p>If you didn't request this, you can safely ignore this email. Your password will remain unchanged.</p>
    <p style="color: #6b7280;">Best regards,<br>The PistonProtection Team</p>
</div>
</body>
</html>"#, base_style, btn_style),

            EmailTemplate::EmailVerification => format!(
                r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="{}">
<div style="max-width: 600px; margin: 0 auto; padding: 20px; background: #ffffff;">
    <h1 style="color: #2563eb;">Verify Your Email</h1>
    <p>Hi {{{{recipient_name}}}},</p>
    <p>Thanks for signing up for PistonProtection! Please verify your email address by clicking the button below:</p>
    <p style="text-align: center; margin: 32px 0;">
        <a href="{{{{verification_link}}}}" style="{}">Verify Email</a>
    </p>
    <p>If you didn't create an account with us, please ignore this email.</p>
    <p style="color: #6b7280;">Best regards,<br>The PistonProtection Team</p>
</div>
</body>
</html>"#, base_style, btn_style),

            EmailTemplate::InvitationSent => format!(
                r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="{}">
<div style="max-width: 600px; margin: 0 auto; padding: 20px; background: #ffffff;">
    <h1 style="color: #2563eb;">You're Invited!</h1>
    <p>Hi {{{{recipient_name}}}},</p>
    <p><strong>{{{{inviter_name}}}}</strong> has invited you to join <strong>{{{{organization_name}}}}</strong> on PistonProtection.</p>
    <p>PistonProtection provides enterprise-grade DDoS protection for your infrastructure.</p>
    <p style="text-align: center; margin: 32px 0;">
        <a href="{{{{invitation_link}}}}" style="{}">Accept Invitation</a>
    </p>
    <p style="color: #6b7280; font-size: 14px;">This invitation will expire in 7 days.</p>
    <p style="color: #6b7280;">Best regards,<br>The PistonProtection Team</p>
</div>
</body>
</html>"#, base_style, btn_style),

            EmailTemplate::AttackDetected => format!(
                r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="{}">
<div style="max-width: 600px; margin: 0 auto; padding: 20px; background: #ffffff;">
    <div style="background: #fef2f2; padding: 24px; border-radius: 8px; text-align: center; margin-bottom: 24px;">
        <h1 style="color: #dc2626; margin: 0;">DDoS Attack Detected</h1>
        <p style="margin: 8px 0 0 0; color: #dc2626;">Protection Active</p>
    </div>
    <p>Hi {{{{recipient_name}}}},</p>
    <p>We have detected a DDoS attack targeting your backend:</p>
    <div style="background: #f3f4f6; padding: 16px; border-radius: 8px; margin: 24px 0;">
        <p style="margin: 4px 0;"><strong>Backend:</strong> {{{{backend_name}}}}</p>
        <p style="margin: 4px 0;"><strong>Attack Type:</strong> {{{{attack_type}}}}</p>
        <p style="margin: 4px 0;"><strong>Traffic:</strong> {{{{pps}}}} PPS / {{{{bps}}}}</p>
        <p style="margin: 4px 0;"><strong>Detected:</strong> {{{{timestamp}}}}</p>
    </div>
    <p style="color: #16a34a;"><strong>Your backend is protected.</strong> Malicious traffic is being filtered automatically.</p>
    <p style="text-align: center; margin: 32px 0;">
        <a href="{{{{base_url}}}}/dashboard/analytics" style="{}">View Attack Details</a>
    </p>
    <p style="color: #6b7280;">Best regards,<br>The PistonProtection Team</p>
</div>
</body>
</html>"#, base_style, btn_style),

            EmailTemplate::AttackMitigated => format!(
                r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="{}">
<div style="max-width: 600px; margin: 0 auto; padding: 20px; background: #ffffff;">
    <div style="background: #dcfce7; padding: 24px; border-radius: 8px; text-align: center; margin-bottom: 24px;">
        <h1 style="color: #16a34a; margin: 0;">Attack Mitigated</h1>
    </div>
    <p>Hi {{{{recipient_name}}}},</p>
    <p>The DDoS attack on your backend has been successfully mitigated:</p>
    <div style="background: #f3f4f6; padding: 16px; border-radius: 8px; margin: 24px 0;">
        <p style="margin: 4px 0;"><strong>Backend:</strong> {{{{backend_name}}}}</p>
        <p style="margin: 4px 0;"><strong>Attack Type:</strong> {{{{attack_type}}}}</p>
        <p style="margin: 4px 0;"><strong>Duration:</strong> {{{{duration}}}}</p>
        <p style="margin: 4px 0;"><strong>Requests Blocked:</strong> {{{{blocked_count}}}}</p>
    </div>
    <p>Your backend is now receiving normal traffic. View the full attack report in your dashboard.</p>
    <p style="text-align: center; margin: 32px 0;">
        <a href="{{{{base_url}}}}/dashboard/analytics" style="{}">View Report</a>
    </p>
    <p style="color: #6b7280;">Best regards,<br>The PistonProtection Team</p>
</div>
</body>
</html>"#, base_style, btn_style),

            // Default template for other types
            _ => format!(
                r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="{}">
<div style="max-width: 600px; margin: 0 auto; padding: 20px; background: #ffffff;">
    <h1 style="color: #2563eb;">PistonProtection Notification</h1>
    <p>Hi {{{{recipient_name}}}},</p>
    <p>{{{{message}}}}</p>
    <p style="text-align: center; margin: 32px 0;">
        <a href="{{{{base_url}}}}/dashboard" style="{}">Go to Dashboard</a>
    </p>
    <p style="color: #6b7280;">Best regards,<br>The PistonProtection Team</p>
</div>
</body>
</html>"#, base_style, btn_style),
        }
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
            .with_variable(
                "payment_date",
                chrono::Utc::now().format("%B %d, %Y").to_string(),
            );
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
    pub async fn send_account_downgraded_email(&self, recipient: EmailRecipient) -> Result<EmailResult> {
        let message = EmailMessage::new(recipient, EmailTemplate::AccountDowngraded);
        self.send(message).await
    }

    /// Send password reset email
    pub async fn send_password_reset_email(
        &self,
        recipient: EmailRecipient,
        reset_link: &str,
        expires_in_minutes: u32,
    ) -> Result<EmailResult> {
        let message = EmailMessage::new(recipient, EmailTemplate::PasswordReset)
            .with_variable("reset_link", reset_link)
            .with_variable("expires_in_minutes", expires_in_minutes.to_string());
        self.send(message).await
    }

    /// Send email verification
    pub async fn send_verification_email(
        &self,
        recipient: EmailRecipient,
        verification_link: &str,
    ) -> Result<EmailResult> {
        let message = EmailMessage::new(recipient, EmailTemplate::EmailVerification)
            .with_variable("verification_link", verification_link);
        self.send(message).await
    }

    /// Send team invitation email
    pub async fn send_invitation_email(
        &self,
        recipient: EmailRecipient,
        organization_name: &str,
        inviter_name: &str,
        invitation_link: &str,
    ) -> Result<EmailResult> {
        let message = EmailMessage::new(recipient, EmailTemplate::InvitationSent)
            .with_variable("organization_name", organization_name)
            .with_variable("inviter_name", inviter_name)
            .with_variable("invitation_link", invitation_link);
        self.send(message).await
    }

    /// Send attack detected notification
    pub async fn send_attack_detected_email(
        &self,
        recipient: EmailRecipient,
        backend_name: &str,
        attack_type: &str,
        pps: &str,
        bps: &str,
    ) -> Result<EmailResult> {
        let message = EmailMessage::new(recipient, EmailTemplate::AttackDetected)
            .with_variable("backend_name", backend_name)
            .with_variable("attack_type", attack_type)
            .with_variable("pps", pps)
            .with_variable("bps", bps)
            .with_variable("timestamp", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string());
        self.send(message).await
    }

    /// Send attack mitigated notification
    pub async fn send_attack_mitigated_email(
        &self,
        recipient: EmailRecipient,
        backend_name: &str,
        attack_type: &str,
        duration: &str,
        blocked_count: &str,
    ) -> Result<EmailResult> {
        let message = EmailMessage::new(recipient, EmailTemplate::AttackMitigated)
            .with_variable("backend_name", backend_name)
            .with_variable("attack_type", attack_type)
            .with_variable("duration", duration)
            .with_variable("blocked_count", blocked_count);
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
        assert_eq!(
            message.variables.get("invoice_id"),
            Some(&"INV-123".to_string())
        );
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

        let result = service.send_welcome_email(recipient, "Pro").await.unwrap();

        assert!(result.success);
    }
}
