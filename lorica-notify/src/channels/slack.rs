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

/// Post an alert event to a Slack-compatible incoming webhook.
///
/// Formats the event as a single Slack message (with an emoji chosen from
/// the alert type) and POSTs the Slack payload as JSON. Also accepts
/// Discord webhooks in Slack-compatibility mode. Uses the channels' shared
/// client (a 10-second total timeout, no redirect following) and returns
/// [`NotifyError::Webhook`] on transport failures or non-2xx responses,
/// a redirect included.
pub async fn send(config: &WebhookConfig, event: &AlertEvent) -> Result<(), NotifyError> {
    let text = slack_text(event);

    let message = SlackMessage {
        text,
        username: "Lorica".to_string(),
        icon_emoji: ":shield:".to_string(),
    };

    let mut request = super::http_client()?.post(&config.url).json(&message);

    if let Some(ref auth) = config.auth_header {
        request = request.header("Authorization", auth);
    }

    let response = match request.send().await {
        Ok(response) => response,
        Err(e) => {
            crate::metrics::record_notification_dispatch(
                "slack",
                crate::metrics::classify_reqwest_error(&e),
            );
            return Err(NotifyError::Webhook(format!("Slack webhook failed: {e}")));
        }
    };

    let status = response.status();
    if !status.is_success() {
        crate::metrics::record_notification_dispatch(
            "slack",
            crate::metrics::classify_response_status(status),
        );
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<no body>".to_string());
        return Err(NotifyError::Webhook(format!(
            "Slack webhook returned {status}: {body}"
        )));
    }

    crate::metrics::record_notification_dispatch("slack", "ok");
    Ok(())
}

/// The Slack message for `event`: an emoji and the alert type's label,
/// the summary, then one line per detail.
fn slack_text(event: &AlertEvent) -> String {
    let emoji = match event.alert_type {
        crate::events::AlertType::CertExpiring => ":lock:",
        crate::events::AlertType::BackendDown => ":red_circle:",
        crate::events::AlertType::WafAlert => ":shield:",
        crate::events::AlertType::ConfigChanged => ":gear:",
        crate::events::AlertType::SlaBreached => ":chart_with_downwards_trend:",
        crate::events::AlertType::SlaRecovered => ":white_check_mark:",
        crate::events::AlertType::IpBanned => ":no_entry:",
        crate::events::AlertType::ClusterNodeLeft => ":wave:",
        crate::events::AlertType::ClusterConfigRefused => ":no_entry_sign:",
        crate::events::AlertType::ClusterDrift => ":arrows_counterclockwise:",
        crate::events::AlertType::LogStoreUnavailable => ":rotating_light:",
        crate::events::AlertType::LogStoreRecovered => ":floppy_disk:",
        crate::events::AlertType::AdcsAuthorityFailed => ":key:",
        crate::events::AlertType::CertIssuanceFailed => ":warning:",
    };

    let mut text = format!(
        "{} *[{}]* {}\n",
        emoji,
        event.alert_type.label().to_uppercase(),
        escape_slack_text(&event.summary),
    );

    for (key, value) in &event.details {
        let value = escape_slack_text(value).replace('`', "'");
        text.push_str(&format!("  - _{key}_: `{value}`\n"));
    }

    text.push_str(&format!("_{}_ | Lorica Reverse Proxy", event.timestamp));
    text
}

/// `text` safe to place in a Slack message: an alert summary or detail
/// can carry a hostname or a path a client chose, and must not be able to
/// ping a channel (`<!channel>`, `<@U...>`) or, on Discord's
/// Slack-compatible endpoint, `@everyone`. Slack's own escaping covers
/// `&`, `<` and `>`; a zero-width space after `@` defuses Discord's
/// plain-text mentions.
fn escape_slack_text(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('@', "@\u{200B}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::AlertType;

    #[test]
    fn test_slack_message_format() {
        let event = AlertEvent::new(AlertType::SlaBreached, "SLA breach on app.example.com")
            .with_detail("route", "app.example.com");
        let text = slack_text(&event);
        assert!(
            text.starts_with(
                ":chart_with_downwards_trend: *[SLA BREACHED]* SLA breach on app.example.com\n"
            ),
            "{text}"
        );
        assert!(text.contains("  - _route_: `app.example.com`\n"), "{text}");
    }

    /// A host or path a client chose reaches WAF alerts: it must not be
    /// able to mention a channel, or break out of a detail's code span.
    #[test]
    fn client_text_cannot_mention_or_escape_a_code_span() {
        let event = AlertEvent::new(
            AlertType::WafAlert,
            "WAF blocked xss on <!channel> @everyone",
        )
        .with_detail("host", "a`<@U123>`b & c");
        let text = slack_text(&event);
        assert!(!text.contains("<!channel>"), "{text}");
        assert!(!text.contains("<@U123>"), "{text}");
        assert!(!text.contains("@everyone"), "{text}");
        assert!(
            text.contains("  - _host_: `a'&lt;@\u{200B}U123&gt;'b &amp; c`\n"),
            "{text}"
        );
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
