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
pub mod stdout;
pub mod webhook;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

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
}

/// Dispatches alert events to all configured notification channels.
pub struct NotifyDispatcher {
    channels: Vec<RegisteredChannel>,
    history: Arc<Mutex<VecDeque<AlertEvent>>>,
    max_history: usize,
}

impl NotifyDispatcher {
    pub fn new() -> Self {
        Self {
            channels: Vec::new(),
            history: Arc::new(Mutex::new(VecDeque::with_capacity(100))),
            max_history: 100,
        }
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

            match &ch.channel_type {
                ChannelType::Email(config) => {
                    if let Err(e) = email::send(config, event).await {
                        warn!(
                            channel_id = %ch.id,
                            error = %e,
                            "failed to send email notification"
                        );
                    } else {
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
                        info!(
                            channel_id = %ch.id,
                            alert_type = alert_str,
                            "webhook notification sent"
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
}
