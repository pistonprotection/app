//! Alert management system
//!
//! This module handles alert creation, evaluation, and notification dispatch
//! for the metrics service.

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use pistonprotection_proto::{
    common::{Pagination, PaginationInfo, Timestamp},
    metrics::*,
};
use reqwest::Client;
use serde::Serialize;
use sqlx::Row;
use sqlx::postgres::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Alert management errors
#[derive(Debug, Error)]
pub enum AlertError {
    #[error("Alert not found: {0}")]
    NotFound(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Notification error: {0}")]
    Notification(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Alert evaluation state
#[derive(Debug, Clone)]
struct AlertEvalState {
    /// Alert ID
    alert_id: String,
    /// Current state
    state: AlertState,
    /// Condition met since (for duration checking)
    condition_met_since: Option<DateTime<Utc>>,
    /// Last evaluation time
    last_evaluated: DateTime<Utc>,
    /// Last triggered time
    last_triggered: Option<DateTime<Utc>>,
    /// Consecutive condition failures
    consecutive_failures: u32,
}

/// Metric value for evaluation
#[derive(Debug, Clone)]
pub struct MetricValue {
    pub name: String,
    pub value: f64,
    pub timestamp: DateTime<Utc>,
}

/// Notification to be sent
#[derive(Debug, Clone, Serialize)]
struct AlertNotificationPayload {
    alert_id: String,
    alert_name: String,
    backend_id: String,
    metric: String,
    current_value: f64,
    threshold: f64,
    operator: String,
    severity: String,
    triggered_at: String,
    message: String,
}

/// Alert manager service
pub struct AlertManager {
    /// Database pool for persistence
    db_pool: Option<PgPool>,

    /// In-memory alert cache
    alerts: DashMap<String, Alert>,

    /// Alert evaluation states
    eval_states: DashMap<String, AlertEvalState>,

    /// Alerts by backend for quick lookup
    alerts_by_backend: DashMap<String, Vec<String>>,

    /// HTTP client for webhook notifications
    http_client: Client,

    /// Channel for triggering evaluations
    eval_trigger: broadcast::Sender<String>,

    /// Channel for notification dispatch
    notification_tx: mpsc::Sender<AlertNotificationPayload>,

    /// Configuration
    config: AlertConfig,
}

/// Alert manager configuration
#[derive(Debug, Clone)]
pub struct AlertConfig {
    /// Evaluation interval
    pub eval_interval: Duration,
    /// Minimum interval between repeated alerts
    pub min_repeat_interval: Duration,
    /// Maximum retries for notifications
    pub notification_retries: u32,
    /// Notification timeout
    pub notification_timeout: Duration,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            eval_interval: Duration::from_secs(10),
            min_repeat_interval: Duration::from_secs(300), // 5 minutes
            notification_retries: 3,
            notification_timeout: Duration::from_secs(10),
        }
    }
}

impl AlertManager {
    /// Create a new alert manager
    pub fn new(db_pool: Option<PgPool>, config: AlertConfig) -> Arc<Self> {
        let (eval_trigger, _) = broadcast::channel(100);
        let (notification_tx, notification_rx) = mpsc::channel(1000);

        let http_client = Client::builder()
            .timeout(config.notification_timeout)
            .build()
            .expect("Failed to create HTTP client");

        let manager = Arc::new(Self {
            db_pool,
            alerts: DashMap::new(),
            eval_states: DashMap::new(),
            alerts_by_backend: DashMap::new(),
            http_client,
            eval_trigger,
            notification_tx,
            config,
        });

        // Start notification dispatcher
        let manager_clone = Arc::clone(&manager);
        tokio::spawn(async move {
            manager_clone.notification_dispatcher(notification_rx).await;
        });

        manager
    }

    /// Load alerts from database
    pub async fn load_alerts(&self) -> Result<(), AlertError> {
        if let Some(ref pool) = self.db_pool {
            let rows = sqlx::query(
                r#"
                SELECT id, backend_id, name, condition_metric, condition_operator,
                       condition_threshold, condition_duration_seconds, enabled,
                       state, last_triggered, created_at, updated_at, notifications
                FROM alerts
                WHERE enabled = true
                "#,
            )
            .fetch_all(pool)
            .await?;

            for row in rows {
                let alert = self.row_to_alert(&row)?;
                let alert_id = alert.id.clone();
                let backend_id = alert.backend_id.clone();

                self.alerts.insert(alert_id.clone(), alert);

                // Initialize evaluation state
                self.eval_states.insert(
                    alert_id.clone(),
                    AlertEvalState {
                        alert_id: alert_id.clone(),
                        state: AlertState::Ok,
                        condition_met_since: None,
                        last_evaluated: Utc::now(),
                        last_triggered: None,
                        consecutive_failures: 0,
                    },
                );

                // Index by backend
                self.alerts_by_backend
                    .entry(backend_id)
                    .or_default()
                    .push(alert_id);
            }

            info!("Loaded {} alerts from database", self.alerts.len());
        }

        Ok(())
    }

    /// Create a new alert
    pub async fn create_alert(
        &self,
        backend_id: &str,
        mut alert: Alert,
    ) -> Result<Alert, AlertError> {
        // Generate ID if not provided
        if alert.id.is_empty() {
            alert.id = Uuid::new_v4().to_string();
        }

        // Set backend_id
        alert.backend_id = backend_id.to_string();

        // Validate
        self.validate_alert(&alert)?;

        // Set timestamps
        let now = Utc::now();
        alert.created_at = Some(Timestamp::from(now));
        alert.updated_at = Some(Timestamp::from(now));
        alert.state = AlertState::Ok as i32;

        // Store in database
        if let Some(ref pool) = self.db_pool {
            let condition = alert
                .condition
                .as_ref()
                .ok_or_else(|| AlertError::Validation("Alert condition is required".to_string()))?;

            let notifications_json = serde_json::to_value(&alert.notifications)
                .map_err(|e| AlertError::Internal(e.to_string()))?;

            sqlx::query(
                r#"
                INSERT INTO alerts (
                    id, backend_id, name, condition_metric, condition_operator,
                    condition_threshold, condition_duration_seconds, enabled,
                    state, created_at, updated_at, notifications
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                "#,
            )
            .bind(&alert.id)
            .bind(&alert.backend_id)
            .bind(&alert.name)
            .bind(&condition.metric)
            .bind(condition.operator)
            .bind(condition.threshold)
            .bind(condition.duration_seconds as i32)
            .bind(alert.enabled)
            .bind(alert.state)
            .bind(now)
            .bind(now)
            .bind(notifications_json)
            .execute(pool)
            .await?;
        }

        // Store in memory
        let alert_id = alert.id.clone();
        self.alerts.insert(alert_id.clone(), alert.clone());

        // Initialize evaluation state
        self.eval_states.insert(
            alert_id.clone(),
            AlertEvalState {
                alert_id: alert_id.clone(),
                state: AlertState::Ok,
                condition_met_since: None,
                last_evaluated: Utc::now(),
                last_triggered: None,
                consecutive_failures: 0,
            },
        );

        // Index by backend
        self.alerts_by_backend
            .entry(backend_id.to_string())
            .or_default()
            .push(alert_id);

        Ok(alert)
    }

    /// Get an alert by ID
    pub async fn get_alert(&self, alert_id: &str) -> Result<Alert, AlertError> {
        // Check in-memory cache first
        if let Some(alert) = self.alerts.get(alert_id) {
            return Ok(alert.clone());
        }

        // Check database
        if let Some(ref pool) = self.db_pool {
            let row = sqlx::query(
                r#"
                SELECT id, backend_id, name, condition_metric, condition_operator,
                       condition_threshold, condition_duration_seconds, enabled,
                       state, last_triggered, created_at, updated_at, notifications
                FROM alerts
                WHERE id = $1
                "#,
            )
            .bind(alert_id)
            .fetch_optional(pool)
            .await?
            .ok_or_else(|| AlertError::NotFound(alert_id.to_string()))?;

            let alert = self.row_to_alert(&row)?;
            return Ok(alert);
        }

        Err(AlertError::NotFound(alert_id.to_string()))
    }

    /// Update an alert
    pub async fn update_alert(&self, alert: Alert) -> Result<Alert, AlertError> {
        // Validate
        self.validate_alert(&alert)?;

        let mut updated_alert = alert.clone();
        updated_alert.updated_at = Some(Timestamp::from(Utc::now()));

        // Update in database
        if let Some(ref pool) = self.db_pool {
            let condition = updated_alert
                .condition
                .as_ref()
                .ok_or_else(|| AlertError::Validation("Alert condition is required".to_string()))?;

            let notifications_json = serde_json::to_value(&updated_alert.notifications)
                .map_err(|e| AlertError::Internal(e.to_string()))?;

            let result = sqlx::query(
                r#"
                UPDATE alerts SET
                    name = $2,
                    condition_metric = $3,
                    condition_operator = $4,
                    condition_threshold = $5,
                    condition_duration_seconds = $6,
                    enabled = $7,
                    updated_at = $8,
                    notifications = $9
                WHERE id = $1
                "#,
            )
            .bind(&updated_alert.id)
            .bind(&updated_alert.name)
            .bind(&condition.metric)
            .bind(condition.operator)
            .bind(condition.threshold)
            .bind(condition.duration_seconds as i32)
            .bind(updated_alert.enabled)
            .bind(Utc::now())
            .bind(notifications_json)
            .execute(pool)
            .await?;

            if result.rows_affected() == 0 {
                return Err(AlertError::NotFound(alert.id));
            }
        }

        // Update in memory
        self.alerts
            .insert(updated_alert.id.clone(), updated_alert.clone());

        Ok(updated_alert)
    }

    /// Delete an alert
    pub async fn delete_alert(&self, alert_id: &str) -> Result<(), AlertError> {
        // Remove from database
        if let Some(ref pool) = self.db_pool {
            sqlx::query("DELETE FROM alerts WHERE id = $1")
                .bind(alert_id)
                .execute(pool)
                .await?;
        }

        // Remove from memory
        if let Some((_, alert)) = self.alerts.remove(alert_id) {
            // Remove from backend index
            if let Some(mut alerts) = self.alerts_by_backend.get_mut(&alert.backend_id) {
                alerts.retain(|id| id != alert_id);
            }
        }

        // Remove evaluation state
        self.eval_states.remove(alert_id);

        Ok(())
    }

    /// List alerts for a backend
    pub async fn list_alerts(
        &self,
        backend_id: &str,
        pagination: Option<Pagination>,
    ) -> Result<(Vec<Alert>, PaginationInfo), AlertError> {
        let page = pagination.as_ref().map(|p| p.page).unwrap_or(1).max(1);
        let page_size = pagination
            .as_ref()
            .map(|p| p.page_size)
            .unwrap_or(20)
            .clamp(1, 100);

        // Try to get from database for complete list
        if let Some(ref pool) = self.db_pool {
            let offset = (page - 1) * page_size;

            // Get total count
            let count_row =
                sqlx::query("SELECT COUNT(*) as count FROM alerts WHERE backend_id = $1")
                    .bind(backend_id)
                    .fetch_one(pool)
                    .await?;
            let total_count: i64 = count_row.get("count");

            // Get alerts
            let rows = sqlx::query(
                r#"
                SELECT id, backend_id, name, condition_metric, condition_operator,
                       condition_threshold, condition_duration_seconds, enabled,
                       state, last_triggered, created_at, updated_at, notifications
                FROM alerts
                WHERE backend_id = $1
                ORDER BY created_at DESC
                LIMIT $2 OFFSET $3
                "#,
            )
            .bind(backend_id)
            .bind(page_size as i32)
            .bind(offset as i32)
            .fetch_all(pool)
            .await?;

            let alerts: Vec<Alert> = rows
                .iter()
                .map(|row| self.row_to_alert(row))
                .collect::<Result<Vec<_>, _>>()?;

            let has_next = (offset + page_size) < total_count as u32;

            return Ok((
                alerts,
                PaginationInfo {
                    total_count: total_count as u32,
                    page,
                    page_size,
                    has_next,
                    next_cursor: String::new(),
                },
            ));
        }

        // Fall back to in-memory
        let alert_ids = self
            .alerts_by_backend
            .get(backend_id)
            .map(|ids| ids.clone())
            .unwrap_or_default();

        let total_count = alert_ids.len() as u32;
        let offset = ((page - 1) * page_size) as usize;

        let alerts: Vec<Alert> = alert_ids
            .into_iter()
            .skip(offset)
            .take(page_size as usize)
            .filter_map(|id| self.alerts.get(&id).map(|a| a.clone()))
            .collect();

        let has_next = offset + alerts.len() < total_count as usize;

        Ok((
            alerts,
            PaginationInfo {
                total_count,
                page,
                page_size,
                has_next,
                next_cursor: String::new(),
            },
        ))
    }

    /// Evaluate alerts for a backend with current metric values
    pub async fn evaluate_alerts(
        &self,
        backend_id: &str,
        metrics: &HashMap<String, f64>,
    ) -> Result<(), AlertError> {
        let alert_ids = self
            .alerts_by_backend
            .get(backend_id)
            .map(|ids| ids.clone())
            .unwrap_or_default();

        for alert_id in alert_ids {
            if let Some(alert) = self.alerts.get(&alert_id) {
                if !alert.enabled {
                    continue;
                }

                if let Some(ref condition) = alert.condition
                    && let Some(&current_value) = metrics.get(&condition.metric) {
                        self.evaluate_single_alert(&alert, current_value).await?;
                    }
            }
        }

        Ok(())
    }

    /// Evaluate a single alert
    async fn evaluate_single_alert(
        &self,
        alert: &Alert,
        current_value: f64,
    ) -> Result<(), AlertError> {
        let condition = match &alert.condition {
            Some(c) => c,
            None => return Ok(()),
        };

        let condition_met = self.check_condition(current_value, condition);
        let now = Utc::now();

        let mut state =
            self.eval_states
                .entry(alert.id.clone())
                .or_insert_with(|| AlertEvalState {
                    alert_id: alert.id.clone(),
                    state: AlertState::Ok,
                    condition_met_since: None,
                    last_evaluated: now,
                    last_triggered: None,
                    consecutive_failures: 0,
                });

        state.last_evaluated = now;

        if condition_met {
            // Condition is met
            if state.condition_met_since.is_none() {
                state.condition_met_since = Some(now);
                state.state = AlertState::Pending;
            }

            // Check if duration threshold has been met
            if let Some(since) = state.condition_met_since {
                let duration = now.signed_duration_since(since);
                if duration.num_seconds() as u32 >= condition.duration_seconds {
                    // Fire the alert
                    if state.state != AlertState::Firing {
                        state.state = AlertState::Firing;
                        self.fire_alert(alert, current_value, condition).await?;
                        state.last_triggered = Some(now);
                    } else {
                        // Check if we should send a repeat notification
                        if let Some(last_triggered) = state.last_triggered {
                            let since_last = now.signed_duration_since(last_triggered);
                            if since_last.to_std().unwrap_or(Duration::ZERO)
                                >= self.config.min_repeat_interval
                            {
                                self.fire_alert(alert, current_value, condition).await?;
                                state.last_triggered = Some(now);
                            }
                        }
                    }
                }
            }
        } else {
            // Condition is not met - reset state
            if state.state == AlertState::Firing {
                info!(alert_id = %alert.id, "Alert resolved");
            }
            state.condition_met_since = None;
            state.state = AlertState::Ok;
        }

        // Update alert state in storage
        self.update_alert_state(&alert.id, state.state, state.last_triggered)
            .await?;

        Ok(())
    }

    /// Check if condition is met
    fn check_condition(&self, current_value: f64, condition: &AlertCondition) -> bool {
        let operator =
            AlertOperator::try_from(condition.operator).unwrap_or(AlertOperator::Unspecified);

        match operator {
            AlertOperator::GreaterThan => current_value > condition.threshold,
            AlertOperator::LessThan => current_value < condition.threshold,
            AlertOperator::Equal => (current_value - condition.threshold).abs() < f64::EPSILON,
            AlertOperator::NotEqual => (current_value - condition.threshold).abs() >= f64::EPSILON,
            AlertOperator::Unspecified => false,
        }
    }

    /// Fire an alert and send notifications
    async fn fire_alert(
        &self,
        alert: &Alert,
        current_value: f64,
        condition: &AlertCondition,
    ) -> Result<(), AlertError> {
        info!(
            alert_id = %alert.id,
            alert_name = %alert.name,
            metric = %condition.metric,
            current_value = %current_value,
            threshold = %condition.threshold,
            "Alert fired"
        );

        let operator_str = match AlertOperator::try_from(condition.operator) {
            Ok(AlertOperator::GreaterThan) => ">",
            Ok(AlertOperator::LessThan) => "<",
            Ok(AlertOperator::Equal) => "==",
            Ok(AlertOperator::NotEqual) => "!=",
            _ => "?",
        };

        let payload = AlertNotificationPayload {
            alert_id: alert.id.clone(),
            alert_name: alert.name.clone(),
            backend_id: alert.backend_id.clone(),
            metric: condition.metric.clone(),
            current_value,
            threshold: condition.threshold,
            operator: operator_str.to_string(),
            severity: "high".to_string(),
            triggered_at: Utc::now().to_rfc3339(),
            message: format!(
                "Alert '{}': {} ({:.2}) {} {:.2}",
                alert.name, condition.metric, current_value, operator_str, condition.threshold
            ),
        };

        // Send notification to dispatcher
        if let Err(e) = self.notification_tx.send(payload).await {
            warn!("Failed to queue notification: {}", e);
        }

        Ok(())
    }

    /// Update alert state in storage
    async fn update_alert_state(
        &self,
        alert_id: &str,
        state: AlertState,
        last_triggered: Option<DateTime<Utc>>,
    ) -> Result<(), AlertError> {
        // Update in memory
        if let Some(mut alert) = self.alerts.get_mut(alert_id) {
            alert.state = state as i32;
            if let Some(triggered) = last_triggered {
                alert.last_triggered = Some(Timestamp::from(triggered));
            }
        }

        // Update in database
        if let Some(ref pool) = self.db_pool {
            sqlx::query("UPDATE alerts SET state = $2, last_triggered = $3 WHERE id = $1")
                .bind(alert_id)
                .bind(state as i32)
                .bind(last_triggered)
                .execute(pool)
                .await?;
        }

        Ok(())
    }

    /// Notification dispatcher task
    async fn notification_dispatcher(&self, mut rx: mpsc::Receiver<AlertNotificationPayload>) {
        info!("Starting notification dispatcher");

        while let Some(payload) = rx.recv().await {
            // Get alert to find notification targets
            if let Some(alert) = self.alerts.get(&payload.alert_id) {
                for notification in &alert.notifications {
                    let result = self.send_notification(notification, &payload).await;

                    if let Err(e) = result {
                        error!(
                            alert_id = %payload.alert_id,
                            notification_type = ?notification.r#type,
                            "Failed to send notification: {}",
                            e
                        );
                    }
                }
            }
        }

        info!("Notification dispatcher stopped");
    }

    /// Send a notification
    async fn send_notification(
        &self,
        notification: &AlertNotification,
        payload: &AlertNotificationPayload,
    ) -> Result<(), AlertError> {
        let notification_type = AlertNotificationType::try_from(notification.r#type)
            .unwrap_or(AlertNotificationType::Unspecified);

        match notification_type {
            AlertNotificationType::Webhook => {
                self.send_webhook_notification(&notification.destination, payload)
                    .await
            }
            AlertNotificationType::Slack => {
                self.send_slack_notification(&notification.destination, payload)
                    .await
            }
            AlertNotificationType::Discord => {
                self.send_discord_notification(&notification.destination, payload)
                    .await
            }
            AlertNotificationType::Email => {
                // Email requires additional configuration
                warn!("Email notifications not implemented");
                Ok(())
            }
            AlertNotificationType::Pagerduty => {
                self.send_pagerduty_notification(&notification.destination, payload)
                    .await
            }
            AlertNotificationType::Unspecified => {
                warn!("Unknown notification type");
                Ok(())
            }
        }
    }

    /// Send webhook notification
    async fn send_webhook_notification(
        &self,
        url: &str,
        payload: &AlertNotificationPayload,
    ) -> Result<(), AlertError> {
        let response = self
            .http_client
            .post(url)
            .json(payload)
            .send()
            .await
            .map_err(|e| AlertError::Notification(e.to_string()))?;

        if !response.status().is_success() {
            return Err(AlertError::Notification(format!(
                "Webhook returned status: {}",
                response.status()
            )));
        }

        debug!(url = %url, "Webhook notification sent");
        Ok(())
    }

    /// Send Slack notification
    async fn send_slack_notification(
        &self,
        webhook_url: &str,
        payload: &AlertNotificationPayload,
    ) -> Result<(), AlertError> {
        let slack_payload = serde_json::json!({
            "text": format!(":warning: *Alert: {}*", payload.alert_name),
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": format!("Alert: {}", payload.alert_name)
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": format!("*Backend:*\n{}", payload.backend_id)
                        },
                        {
                            "type": "mrkdwn",
                            "text": format!("*Metric:*\n{}", payload.metric)
                        },
                        {
                            "type": "mrkdwn",
                            "text": format!("*Current Value:*\n{:.2}", payload.current_value)
                        },
                        {
                            "type": "mrkdwn",
                            "text": format!("*Threshold:*\n{} {:.2}", payload.operator, payload.threshold)
                        }
                    ]
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": format!("Triggered at: {}", payload.triggered_at)
                        }
                    ]
                }
            ]
        });

        let response = self
            .http_client
            .post(webhook_url)
            .json(&slack_payload)
            .send()
            .await
            .map_err(|e| AlertError::Notification(e.to_string()))?;

        if !response.status().is_success() {
            return Err(AlertError::Notification(format!(
                "Slack webhook returned status: {}",
                response.status()
            )));
        }

        debug!("Slack notification sent");
        Ok(())
    }

    /// Send Discord notification
    async fn send_discord_notification(
        &self,
        webhook_url: &str,
        payload: &AlertNotificationPayload,
    ) -> Result<(), AlertError> {
        let discord_payload = serde_json::json!({
            "embeds": [{
                "title": format!("Alert: {}", payload.alert_name),
                "color": 16711680, // Red
                "fields": [
                    {
                        "name": "Backend",
                        "value": payload.backend_id,
                        "inline": true
                    },
                    {
                        "name": "Metric",
                        "value": payload.metric,
                        "inline": true
                    },
                    {
                        "name": "Current Value",
                        "value": format!("{:.2}", payload.current_value),
                        "inline": true
                    },
                    {
                        "name": "Threshold",
                        "value": format!("{} {:.2}", payload.operator, payload.threshold),
                        "inline": true
                    }
                ],
                "footer": {
                    "text": format!("Triggered at {}", payload.triggered_at)
                }
            }]
        });

        let response = self
            .http_client
            .post(webhook_url)
            .json(&discord_payload)
            .send()
            .await
            .map_err(|e| AlertError::Notification(e.to_string()))?;

        if !response.status().is_success() {
            return Err(AlertError::Notification(format!(
                "Discord webhook returned status: {}",
                response.status()
            )));
        }

        debug!("Discord notification sent");
        Ok(())
    }

    /// Send PagerDuty notification
    async fn send_pagerduty_notification(
        &self,
        integration_key: &str,
        payload: &AlertNotificationPayload,
    ) -> Result<(), AlertError> {
        let pagerduty_payload = serde_json::json!({
            "routing_key": integration_key,
            "event_action": "trigger",
            "dedup_key": format!("{}:{}", payload.alert_id, payload.backend_id),
            "payload": {
                "summary": payload.message,
                "source": "pistonprotection-metrics",
                "severity": payload.severity,
                "custom_details": {
                    "backend_id": payload.backend_id,
                    "metric": payload.metric,
                    "current_value": payload.current_value,
                    "threshold": payload.threshold,
                    "operator": payload.operator
                }
            }
        });

        let response = self
            .http_client
            .post("https://events.pagerduty.com/v2/enqueue")
            .json(&pagerduty_payload)
            .send()
            .await
            .map_err(|e| AlertError::Notification(e.to_string()))?;

        if !response.status().is_success() {
            return Err(AlertError::Notification(format!(
                "PagerDuty returned status: {}",
                response.status()
            )));
        }

        debug!("PagerDuty notification sent");
        Ok(())
    }

    /// Validate an alert
    fn validate_alert(&self, alert: &Alert) -> Result<(), AlertError> {
        if alert.name.is_empty() {
            return Err(AlertError::Validation("Alert name is required".to_string()));
        }

        if alert.name.len() > 255 {
            return Err(AlertError::Validation(
                "Alert name must be less than 256 characters".to_string(),
            ));
        }

        let condition = alert
            .condition
            .as_ref()
            .ok_or_else(|| AlertError::Validation("Alert condition is required".to_string()))?;

        if condition.metric.is_empty() {
            return Err(AlertError::Validation(
                "Condition metric is required".to_string(),
            ));
        }

        let operator = AlertOperator::try_from(condition.operator)
            .map_err(|_| AlertError::Validation("Invalid condition operator".to_string()))?;

        if operator == AlertOperator::Unspecified {
            return Err(AlertError::Validation(
                "Condition operator is required".to_string(),
            ));
        }

        Ok(())
    }

    /// Convert database row to Alert
    fn row_to_alert(&self, row: &sqlx::postgres::PgRow) -> Result<Alert, AlertError> {
        let notifications_json: serde_json::Value = row
            .try_get("notifications")
            .unwrap_or(serde_json::json!([]));
        let notifications: Vec<AlertNotification> = serde_json::from_value(notifications_json)
            .map_err(|e| AlertError::Internal(e.to_string()))?;

        let created_at: DateTime<Utc> = row.get("created_at");
        let updated_at: DateTime<Utc> = row.get("updated_at");
        let last_triggered: Option<DateTime<Utc>> = row.get("last_triggered");

        Ok(Alert {
            id: row.get("id"),
            backend_id: row.get("backend_id"),
            name: row.get("name"),
            condition: Some(AlertCondition {
                metric: row.get("condition_metric"),
                operator: row.get("condition_operator"),
                threshold: row.get("condition_threshold"),
                duration_seconds: row.get::<i32, _>("condition_duration_seconds") as u32,
            }),
            notifications,
            enabled: row.get("enabled"),
            state: row.get("state"),
            last_triggered: last_triggered.map(Timestamp::from),
            created_at: Some(Timestamp::from(created_at)),
            updated_at: Some(Timestamp::from(updated_at)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_condition_greater_than() {
        let manager = AlertManager::new(None, AlertConfig::default());
        let condition = AlertCondition {
            metric: "rps".to_string(),
            operator: AlertOperator::GreaterThan as i32,
            threshold: 100.0,
            duration_seconds: 60,
        };

        assert!(manager.check_condition(150.0, &condition));
        assert!(!manager.check_condition(50.0, &condition));
        assert!(!manager.check_condition(100.0, &condition));
    }

    #[test]
    fn test_check_condition_less_than() {
        let manager = AlertManager::new(None, AlertConfig::default());
        let condition = AlertCondition {
            metric: "uptime".to_string(),
            operator: AlertOperator::LessThan as i32,
            threshold: 99.0,
            duration_seconds: 60,
        };

        assert!(manager.check_condition(95.0, &condition));
        assert!(!manager.check_condition(99.5, &condition));
    }

    #[test]
    fn test_validate_alert() {
        let manager = AlertManager::new(None, AlertConfig::default());

        // Valid alert
        let valid_alert = Alert {
            id: "test".to_string(),
            name: "Test Alert".to_string(),
            backend_id: "backend1".to_string(),
            condition: Some(AlertCondition {
                metric: "rps".to_string(),
                operator: AlertOperator::GreaterThan as i32,
                threshold: 100.0,
                duration_seconds: 60,
            }),
            ..Default::default()
        };
        assert!(manager.validate_alert(&valid_alert).is_ok());

        // Missing name
        let invalid_alert = Alert {
            name: "".to_string(),
            ..valid_alert.clone()
        };
        assert!(manager.validate_alert(&invalid_alert).is_err());

        // Missing condition
        let invalid_alert = Alert {
            condition: None,
            ..valid_alert.clone()
        };
        assert!(manager.validate_alert(&invalid_alert).is_err());
    }
}
