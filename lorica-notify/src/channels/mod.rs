// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub mod email;
pub mod slack;
pub mod stdout;
pub mod webhook;

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::events::AlertEvent;
use tracing::{info, warn};

/// Errors from notification delivery.
#[derive(Debug, thiserror::Error)]
pub enum NotifyError {
    #[error("email: {0}")]
    Email(String),
    #[error("webhook: {0}")]
    Webhook(String),
    #[error("config: {0}")]
    Config(String),
}

/// Configuration for an email notification channel.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: Option<u16>,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub from_address: String,
    pub to_address: String,
}

/// Configuration for a webhook notification channel.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct WebhookConfig {
    pub url: String,
    pub auth_header: Option<String>,
}

/// A registered notification channel with its alert type subscriptions.
struct RegisteredChannel {
    id: String,
    channel_type: ChannelType,
    alert_types: Vec<String>,
    enabled: bool,
}

enum ChannelType {
    Email(EmailConfig),
    Webhook(WebhookConfig),
    Slack(WebhookConfig),
}

/// Rate limiter configuration.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum number of notifications per channel within the window.
    pub max_per_window: usize,
    /// Sliding window duration.
    pub window: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_per_window: 10,
            window: Duration::from_secs(60),
        }
    }
}

/// Dispatches alert events to all configured notification channels.
pub struct NotifyDispatcher {
    channels: Vec<RegisteredChannel>,
    history: Arc<Mutex<VecDeque<AlertEvent>>>,
    max_history: usize,
    rate_limit: RateLimitConfig,
    /// Per-channel send timestamps for rate limiting.
    send_times: Mutex<HashMap<String, VecDeque<Instant>>>,
    /// Counter of rate-limited (suppressed) notifications.
    suppressed_count: Mutex<usize>,
}

impl NotifyDispatcher {
    pub fn new() -> Self {
        Self {
            channels: Vec::new(),
            history: Arc::new(Mutex::new(VecDeque::with_capacity(100))),
            max_history: 100,
            rate_limit: RateLimitConfig::default(),
            send_times: Mutex::new(HashMap::new()),
            suppressed_count: Mutex::new(0),
        }
    }

    /// Create a dispatcher with custom rate limiting.
    pub fn with_rate_limit(rate_limit: RateLimitConfig) -> Self {
        Self {
            rate_limit,
            ..Self::new()
        }
    }

    /// Return the number of suppressed notifications.
    pub fn suppressed_count(&self) -> usize {
        *self.suppressed_count.lock().unwrap()
    }

    /// Return a reference to the event history buffer.
    pub fn history(&self) -> Arc<Mutex<VecDeque<AlertEvent>>> {
        Arc::clone(&self.history)
    }

    /// Register an email channel.
    pub fn add_email_channel(
        &mut self,
        id: String,
        config: EmailConfig,
        alert_types: Vec<String>,
        enabled: bool,
    ) {
        self.channels.push(RegisteredChannel {
            id,
            channel_type: ChannelType::Email(config),
            alert_types,
            enabled,
        });
    }

    /// Register a webhook channel.
    pub fn add_webhook_channel(
        &mut self,
        id: String,
        config: WebhookConfig,
        alert_types: Vec<String>,
        enabled: bool,
    ) {
        self.channels.push(RegisteredChannel {
            id,
            channel_type: ChannelType::Webhook(config),
            alert_types,
            enabled,
        });
    }

    /// Register a Slack (or Discord) webhook channel.
    pub fn add_slack_channel(
        &mut self,
        id: String,
        config: WebhookConfig,
        alert_types: Vec<String>,
        enabled: bool,
    ) {
        self.channels.push(RegisteredChannel {
            id,
            channel_type: ChannelType::Slack(config),
            alert_types,
            enabled,
        });
    }

    /// Clear all registered channels (for reconfiguration).
    pub fn clear_channels(&mut self) {
        self.channels.clear();
    }

    /// Dispatch an alert event to all matching channels.
    ///
    /// Stdout is always emitted. Email and webhook channels are only
    /// used if they are enabled and subscribe to the event's alert type.
    pub async fn dispatch(&self, event: &AlertEvent) {
        // Always emit to stdout
        stdout::emit(event);

        // Store in history
        {
            let mut hist = self.history.lock().unwrap();
            if hist.len() >= self.max_history {
                hist.pop_front();
            }
            hist.push_back(event.clone());
        }

        let alert_str = event.alert_type.as_str();

        for ch in &self.channels {
            if !ch.enabled {
                continue;
            }

            // Check if this channel subscribes to this alert type
            if !ch.alert_types.is_empty()
                && !ch.alert_types.iter().any(|t| t == alert_str || t == "*")
            {
                continue;
            }

            // Rate limiting check
            if self.is_rate_limited(&ch.id) {
                warn!(
                    channel_id = %ch.id,
                    alert_type = alert_str,
                    "notification suppressed by rate limiter"
                );
                *self.suppressed_count.lock().unwrap() += 1;
                continue;
            }

            match &ch.channel_type {
                ChannelType::Email(config) => {
                    if let Err(e) = email::send(config, event).await {
                        warn!(
                            channel_id = %ch.id,
                            error = %e,
                            "failed to send email notification"
                        );
                    } else {
                        self.record_send(&ch.id);
                        info!(
                            channel_id = %ch.id,
                            alert_type = alert_str,
                            "email notification sent"
                        );
                    }
                }
                ChannelType::Webhook(config) => {
                    if let Err(e) = webhook::send(config, event).await {
                        warn!(
                            channel_id = %ch.id,
                            error = %e,
                            "failed to send webhook notification"
                        );
                    } else {
                        self.record_send(&ch.id);
                        info!(
                            channel_id = %ch.id,
                            alert_type = alert_str,
                            "webhook notification sent"
                        );
                    }
                }
                ChannelType::Slack(config) => {
                    if let Err(e) = slack::send(config, event).await {
                        warn!(
                            channel_id = %ch.id,
                            error = %e,
                            "failed to send Slack notification"
                        );
                    } else {
                        self.record_send(&ch.id);
                        info!(
                            channel_id = %ch.id,
                            alert_type = alert_str,
                            "Slack notification sent"
                        );
                    }
                }
            }
        }
    }

    /// Return the number of registered channels.
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Return recent notification history.
    pub fn recent_history(&self, limit: usize) -> Vec<AlertEvent> {
        let hist = self.history.lock().unwrap();
        hist.iter().rev().take(limit).cloned().collect()
    }

    /// Return the total number of events in history.
    pub fn history_count(&self) -> usize {
        self.history.lock().unwrap().len()
    }

    /// Check if a channel has exceeded its rate limit.
    fn is_rate_limited(&self, channel_id: &str) -> bool {
        let now = Instant::now();
        let mut times = self.send_times.lock().unwrap();
        let entry = times.entry(channel_id.to_string()).or_default();

        // Evict expired entries
        while entry
            .front()
            .is_some_and(|t| now.duration_since(*t) > self.rate_limit.window)
        {
            entry.pop_front();
        }

        entry.len() >= self.rate_limit.max_per_window
    }

    /// Record a successful send for rate limiting.
    fn record_send(&self, channel_id: &str) {
        let mut times = self.send_times.lock().unwrap();
        let entry = times.entry(channel_id.to_string()).or_default();
        entry.push_back(Instant::now());
    }
}

impl Default for NotifyDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate an email configuration string (JSON).
pub fn validate_email_config(config_json: &str) -> Result<EmailConfig, NotifyError> {
    let config: EmailConfig =
        serde_json::from_str(config_json).map_err(|e| NotifyError::Config(e.to_string()))?;
    if config.smtp_host.is_empty() {
        return Err(NotifyError::Config("smtp_host is required".into()));
    }
    if config.from_address.is_empty() {
        return Err(NotifyError::Config("from_address is required".into()));
    }
    if config.to_address.is_empty() {
        return Err(NotifyError::Config("to_address is required".into()));
    }
    Ok(config)
}

/// Validate a webhook configuration string (JSON).
pub fn validate_webhook_config(config_json: &str) -> Result<WebhookConfig, NotifyError> {
    let config: WebhookConfig =
        serde_json::from_str(config_json).map_err(|e| NotifyError::Config(e.to_string()))?;
    if config.url.is_empty() {
        return Err(NotifyError::Config("url is required".into()));
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::AlertType;

    #[test]
    fn test_validate_email_config_valid() {
        let json = r#"{"smtp_host":"mail.example.com","from_address":"noreply@example.com","to_address":"admin@example.com"}"#;
        let config = validate_email_config(json).unwrap();
        assert_eq!(config.smtp_host, "mail.example.com");
        assert_eq!(config.from_address, "noreply@example.com");
    }

    #[test]
    fn test_validate_email_config_missing_host() {
        let json = r#"{"smtp_host":"","from_address":"a@b.com","to_address":"c@d.com"}"#;
        assert!(validate_email_config(json).is_err());
    }

    #[test]
    fn test_validate_email_config_invalid_json() {
        assert!(validate_email_config("not json").is_err());
    }

    #[test]
    fn test_validate_webhook_config_valid() {
        let json = r#"{"url":"https://hooks.example.com/alert"}"#;
        let config = validate_webhook_config(json).unwrap();
        assert_eq!(config.url, "https://hooks.example.com/alert");
        assert!(config.auth_header.is_none());
    }

    #[test]
    fn test_validate_webhook_config_with_auth() {
        let json =
            r#"{"url":"https://hooks.example.com/alert","auth_header":"Bearer secret-token"}"#;
        let config = validate_webhook_config(json).unwrap();
        assert_eq!(config.auth_header.as_deref(), Some("Bearer secret-token"));
    }

    #[test]
    fn test_validate_webhook_config_empty_url() {
        let json = r#"{"url":""}"#;
        assert!(validate_webhook_config(json).is_err());
    }

    #[test]
    fn test_dispatcher_new() {
        let d = NotifyDispatcher::new();
        assert_eq!(d.channel_count(), 0);
        assert_eq!(d.history_count(), 0);
    }

    #[test]
    fn test_dispatcher_add_channels() {
        let mut d = NotifyDispatcher::new();
        d.add_email_channel(
            "e1".into(),
            EmailConfig {
                smtp_host: "mail.test".into(),
                smtp_port: None,
                smtp_username: None,
                smtp_password: None,
                from_address: "a@b.com".into(),
                to_address: "c@d.com".into(),
            },
            vec!["backend_down".into()],
            true,
        );
        d.add_webhook_channel(
            "w1".into(),
            WebhookConfig {
                url: "https://hook.test".into(),
                auth_header: None,
            },
            vec![],
            true,
        );
        assert_eq!(d.channel_count(), 2);
    }

    #[test]
    fn test_dispatcher_clear_channels() {
        let mut d = NotifyDispatcher::new();
        d.add_webhook_channel(
            "w1".into(),
            WebhookConfig {
                url: "https://hook.test".into(),
                auth_header: None,
            },
            vec![],
            true,
        );
        assert_eq!(d.channel_count(), 1);
        d.clear_channels();
        assert_eq!(d.channel_count(), 0);
    }

    #[tokio::test]
    async fn test_dispatch_stores_in_history() {
        let d = NotifyDispatcher::new();
        let event = AlertEvent::new(AlertType::BackendDown, "test backend down");
        d.dispatch(&event).await;
        assert_eq!(d.history_count(), 1);
        let recent = d.recent_history(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].alert_type, AlertType::BackendDown);
    }

    // ---- Rate limiting ----

    #[test]
    fn test_rate_limit_config_default() {
        let cfg = RateLimitConfig::default();
        assert_eq!(cfg.max_per_window, 10);
        assert_eq!(cfg.window, Duration::from_secs(60));
    }

    #[test]
    fn test_is_rate_limited_under_threshold() {
        let d = NotifyDispatcher::new();
        // Record 5 sends (under default of 10)
        for _ in 0..5 {
            d.record_send("ch1");
        }
        assert!(!d.is_rate_limited("ch1"));
    }

    #[test]
    fn test_is_rate_limited_at_threshold() {
        let d = NotifyDispatcher::new();
        for _ in 0..10 {
            d.record_send("ch1");
        }
        assert!(d.is_rate_limited("ch1"));
    }

    #[test]
    fn test_rate_limit_per_channel_isolation() {
        let d = NotifyDispatcher::new();
        for _ in 0..10 {
            d.record_send("ch1");
        }
        assert!(d.is_rate_limited("ch1"));
        assert!(!d.is_rate_limited("ch2"));
    }

    #[test]
    fn test_rate_limit_custom_config() {
        let d = NotifyDispatcher::with_rate_limit(RateLimitConfig {
            max_per_window: 2,
            window: Duration::from_secs(60),
        });
        d.record_send("ch1");
        assert!(!d.is_rate_limited("ch1"));
        d.record_send("ch1");
        assert!(d.is_rate_limited("ch1"));
    }

    #[test]
    fn test_suppressed_count_starts_at_zero() {
        let d = NotifyDispatcher::new();
        assert_eq!(d.suppressed_count(), 0);
    }

    #[tokio::test]
    async fn test_dispatch_with_disabled_channel_skips() {
        let mut d = NotifyDispatcher::new();
        d.add_webhook_channel(
            "w1".into(),
            WebhookConfig {
                url: "http://192.0.2.1:1/hook".into(),
                auth_header: None,
            },
            vec![],
            false, // disabled
        );
        let event = AlertEvent::new(AlertType::BackendDown, "test");
        d.dispatch(&event).await;
        // Should be in history (stdout always emits) but webhook not called
        assert_eq!(d.history_count(), 1);
    }

    #[tokio::test]
    async fn test_dispatch_with_unmatched_alert_type_skips() {
        let mut d = NotifyDispatcher::new();
        d.add_webhook_channel(
            "w1".into(),
            WebhookConfig {
                url: "http://192.0.2.1:1/hook".into(),
                auth_header: None,
            },
            vec!["cert_expiring".into()], // only cert_expiring
            true,
        );
        let event = AlertEvent::new(AlertType::BackendDown, "test");
        d.dispatch(&event).await;
        // Webhook should be skipped (wrong alert type), but event still in history
        assert_eq!(d.history_count(), 1);
    }

    #[tokio::test]
    async fn test_dispatch_wildcard_matches_all() {
        let mut d = NotifyDispatcher::new();
        d.add_webhook_channel(
            "w1".into(),
            WebhookConfig {
                url: "http://192.0.2.1:1/hook".into(),
                auth_header: None,
            },
            vec!["*".into()], // wildcard
            true,
        );
        let event = AlertEvent::new(AlertType::ConfigChanged, "test");
        d.dispatch(&event).await;
        // Event in history, webhook attempted (will fail but that's ok)
        assert_eq!(d.history_count(), 1);
    }

    #[tokio::test]
    async fn test_dispatch_email_with_invalid_address_logs_error() {
        let mut d = NotifyDispatcher::new();
        d.add_email_channel(
            "e1".into(),
            EmailConfig {
                smtp_host: "192.0.2.1".into(),
                smtp_port: None,
                smtp_username: None,
                smtp_password: None,
                from_address: "not-valid".into(),
                to_address: "admin@example.com".into(),
            },
            vec![],
            true,
        );
        let event = AlertEvent::new(AlertType::BackendDown, "test");
        d.dispatch(&event).await;
        // Email send fails but doesn't panic, event still in history
        assert_eq!(d.history_count(), 1);
    }

    #[tokio::test]
    async fn test_history_ring_buffer_overflow() {
        let mut d = NotifyDispatcher::new();
        // Default max_history is 100
        for i in 0..110 {
            let event = AlertEvent::new(AlertType::BackendDown, format!("event {i}"));
            d.dispatch(&event).await;
        }
        assert_eq!(d.history_count(), 100);
        let recent = d.recent_history(1);
        assert!(recent[0].summary.contains("event 109"));
    }

    #[test]
    fn test_default_dispatcher() {
        let d = NotifyDispatcher::default();
        assert_eq!(d.channel_count(), 0);
        assert_eq!(d.history_count(), 0);
        assert_eq!(d.suppressed_count(), 0);
    }

    #[test]
    fn test_notify_error_display() {
        let e1 = NotifyError::Email("test error".into());
        assert_eq!(e1.to_string(), "email: test error");
        let e2 = NotifyError::Webhook("timeout".into());
        assert_eq!(e2.to_string(), "webhook: timeout");
        let e3 = NotifyError::Config("missing field".into());
        assert_eq!(e3.to_string(), "config: missing field");
    }
}
