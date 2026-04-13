// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Slack notification channel via incoming webhook.
//!
//! Sends alerts as Slack messages using the Incoming Webhooks API.
//! Also supports Discord webhooks with Slack-compatible format.

use super::{NotifyError, WebhookConfig};
use crate::events::AlertEvent;

/// Slack message payload.
#[derive(serde::Serialize)]
struct SlackMessage {
    text: String,
    username: String,
    icon_emoji: String,
}

/// Send an alert event to a Slack (or Discord) incoming webhook.
pub async fn send(config: &WebhookConfig, event: &AlertEvent) -> Result<(), NotifyError> {
    let emoji = match event.alert_type {
        crate::events::AlertType::CertExpiring => ":lock:",
        crate::events::AlertType::BackendDown => ":red_circle:",
        crate::events::AlertType::WafAlert => ":shield:",
        crate::events::AlertType::ConfigChanged => ":gear:",
        crate::events::AlertType::SlaBreached => ":chart_with_downwards_trend:",
        crate::events::AlertType::SlaRecovered => ":white_check_mark:",
        crate::events::AlertType::IpBanned => ":no_entry:",
    };

    let mut text = format!(
        "{} *[{}]* {}\n",
        emoji,
        event.alert_type.as_str().to_uppercase().replace('_', " "),
        event.summary,
    );

    if !event.details.is_empty() {
        for (key, value) in &event.details {
            text.push_str(&format!("  - _{key}_: `{value}`\n"));
        }
    }

    text.push_str(&format!("_{}_ | Lorica Reverse Proxy", event.timestamp));

    let message = SlackMessage {
        text,
        username: "Lorica".to_string(),
        icon_emoji: ":shield:".to_string(),
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| NotifyError::Webhook(format!("failed to create HTTP client: {e}")))?;

    let mut request = client.post(&config.url).json(&message);

    if let Some(ref auth) = config.auth_header {
        request = request.header("Authorization", auth);
    }

    let response = request
        .send()
        .await
        .map_err(|e| NotifyError::Webhook(format!("Slack webhook failed: {e}")))?;

    let status = response.status();
    if !status.is_success() {
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<no body>".to_string());
        return Err(NotifyError::Webhook(format!(
            "Slack webhook returned {status}: {body}"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::AlertType;

    #[test]
    fn test_slack_message_format() {
        let event = AlertEvent::new(AlertType::BackendDown, "Backend 10.0.0.1:8080 is down")
            .with_detail("route", "web-frontend");
        let msg = SlackMessage {
            text: format!(":red_circle: *[BACKEND DOWN]* {}", event.summary),
            username: "Lorica".into(),
            icon_emoji: ":shield:".into(),
        };
        let json = serde_json::to_string(&msg).expect("SlackMessage fixture serializes cleanly");
        assert!(json.contains("BACKEND DOWN"));
        assert!(json.contains("Lorica"));
    }

    #[tokio::test]
    async fn test_send_to_invalid_url_fails() {
        let config = WebhookConfig {
            url: "http://192.0.2.1:1/slack".into(),
            auth_header: None,
        };
        let event = AlertEvent::new(AlertType::WafAlert, "test");
        let result = send(&config, &event).await;
        assert!(result.is_err());
    }
}
