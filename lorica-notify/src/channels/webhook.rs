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

//! Webhook notification channel via HTTP POST with JSON body.

use super::{NotifyError, WebhookConfig};
use crate::events::AlertEvent;

/// POST an alert event as JSON to the configured webhook URL.
///
/// Uses a 10-second total timeout. If `auth_header` is set it is sent
/// verbatim as the `Authorization` header. Returns [`NotifyError::Webhook`]
/// on transport failures or when the response status is not 2xx.
pub async fn send(config: &WebhookConfig, event: &AlertEvent) -> Result<(), NotifyError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        // Disable redirect following to defend against an attacker
        // who controls the configured webhook URL redirecting to an
        // internal service (`http://10.0.0.5:8500/`,
        // `http://169.254.169.254/`). Webhook bodies are operator-
        // supplied JSON alerts ; leaking them is a soft data-leak.
        // Trust-boundary fix, audit L-7.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| NotifyError::Webhook(format!("failed to create HTTP client: {e}")))?;

    let mut request = client.post(&config.url).json(event);

    if let Some(ref auth) = config.auth_header {
        request = request.header("Authorization", auth);
    }

    let response = request
        .send()
        .await
        .map_err(|e| NotifyError::Webhook(format!("HTTP request failed: {e}")))?;

    let status = response.status();
    if !status.is_success() {
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<no body>".to_string());
        return Err(NotifyError::Webhook(format!(
            "webhook returned {status}: {body}"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::AlertType;

    #[tokio::test]
    async fn test_send_to_invalid_url_returns_error() {
        let config = WebhookConfig {
            url: "http://192.0.2.1:1/nonexistent".into(),
            auth_header: None,
        };
        let event = AlertEvent::new(AlertType::BackendDown, "test");
        let result = send(&config, &event).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_event_serializes_for_webhook() {
        let event = AlertEvent::new(AlertType::ConfigChanged, "config updated")
            .with_detail("changed_by", "admin");
        let json = serde_json::to_value(&event).expect("AlertEvent fixture serializes cleanly");
        assert_eq!(json["alert_type"], "config_changed");
        assert_eq!(json["details"]["changed_by"], "admin");
    }

    #[tokio::test]
    async fn test_send_with_auth_header_fails_gracefully() {
        let config = WebhookConfig {
            url: "http://192.0.2.1:1/hook".into(),
            auth_header: Some("Bearer test-token".into()),
        };
        let event = AlertEvent::new(AlertType::WafAlert, "test");
        let result = send(&config, &event).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_send_with_empty_url_fails() {
        let config = WebhookConfig {
            url: "".into(),
            auth_header: None,
        };
        let event = AlertEvent::new(AlertType::BackendDown, "test");
        let result = send(&config, &event).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_webhook_config_serialization() {
        let config = WebhookConfig {
            url: "https://hooks.example.com/alert".into(),
            auth_header: Some("Bearer secret".into()),
        };
        let json =
            serde_json::to_string(&config).expect("WebhookConfig fixture serializes cleanly");
        let parsed: WebhookConfig =
            serde_json::from_str(&json).expect("just-serialized JSON round-trips");
        assert_eq!(parsed.url, config.url);
        assert_eq!(parsed.auth_header, config.auth_header);
    }
}
