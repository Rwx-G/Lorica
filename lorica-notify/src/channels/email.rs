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

//! Email notification channel using SMTP via lettre.

use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use super::{EmailConfig, NotifyError};
use crate::events::AlertEvent;

/// Send an alert event via SMTP email.
pub async fn send(config: &EmailConfig, event: &AlertEvent) -> Result<(), NotifyError> {
    let subject = format!(
        "[Lorica Alert] {} - {}",
        event.alert_type.as_str(),
        event.summary
    );

    let body = format_email_body(event);

    let email = Message::builder()
        .from(
            config
                .from_address
                .parse()
                .map_err(|e: lettre::address::AddressError| {
                    NotifyError::Email(format!("invalid from_address: {e}"))
                })?,
        )
        .to(config
            .to_address
            .parse()
            .map_err(|e: lettre::address::AddressError| {
                NotifyError::Email(format!("invalid to_address: {e}"))
            })?)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(body)
        .map_err(|e| NotifyError::Email(format!("failed to build email: {e}")))?;

    let port = config.smtp_port.unwrap_or(587);

    let mut transport_builder =
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host)
            .map_err(|e| NotifyError::Email(format!("SMTP relay error: {e}")))?
            .port(port);

    if let (Some(ref username), Some(ref password)) =
        (&config.smtp_username, &config.smtp_password)
    {
        transport_builder =
            transport_builder.credentials(Credentials::new(username.clone(), password.clone()));
    }

    let transport = transport_builder.build();

    transport
        .send(email)
        .await
        .map_err(|e| NotifyError::Email(format!("SMTP send failed: {e}")))?;

    Ok(())
}

fn format_email_body(event: &AlertEvent) -> String {
    let mut body = format!(
        "Lorica Alert Notification\n\
         ========================\n\n\
         Type:    {}\n\
         Summary: {}\n\
         Time:    {}\n",
        event.alert_type.as_str(),
        event.summary,
        event.timestamp,
    );

    if !event.details.is_empty() {
        body.push_str("\nDetails:\n");
        for (key, value) in &event.details {
            body.push_str(&format!("  {key}: {value}\n"));
        }
    }

    body.push_str("\n--\nSent by Lorica Reverse Proxy\n");
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::AlertType;

    #[test]
    fn test_format_email_body_basic() {
        let event = AlertEvent::new(AlertType::BackendDown, "Backend 10.0.0.1:8080 is down");
        let body = format_email_body(&event);
        assert!(body.contains("backend_down"));
        assert!(body.contains("10.0.0.1:8080"));
        assert!(body.contains("Lorica Alert"));
    }

    #[test]
    fn test_format_email_body_with_details() {
        let event = AlertEvent::new(AlertType::CertExpiring, "Certificate expiring soon")
            .with_detail("domain", "example.com")
            .with_detail("days_remaining", "7");
        let body = format_email_body(&event);
        assert!(body.contains("Details:"));
        assert!(body.contains("example.com"));
        assert!(body.contains("days_remaining"));
    }

    #[test]
    fn test_format_email_body_no_details() {
        let event = AlertEvent::new(AlertType::WafAlert, "SQL injection detected");
        let body = format_email_body(&event);
        assert!(!body.contains("Details:"));
        assert!(body.contains("waf_alert"));
        assert!(body.contains("SQL injection"));
        assert!(body.contains("Sent by Lorica"));
    }

    #[test]
    fn test_format_email_body_all_event_types() {
        for alert_type in [
            AlertType::CertExpiring,
            AlertType::BackendDown,
            AlertType::WafAlert,
            AlertType::ConfigChanged,
        ] {
            let event = AlertEvent::new(alert_type.clone(), "test summary");
            let body = format_email_body(&event);
            assert!(body.contains(alert_type.as_str()));
            assert!(body.contains("test summary"));
        }
    }

    #[tokio::test]
    async fn test_send_invalid_from_address() {
        let config = EmailConfig {
            smtp_host: "mail.example.com".into(),
            smtp_port: None,
            smtp_username: None,
            smtp_password: None,
            from_address: "not-an-email".into(),
            to_address: "admin@example.com".into(),
        };
        let event = AlertEvent::new(AlertType::BackendDown, "test");
        let result = send(&config, &event).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("from_address"));
    }

    #[tokio::test]
    async fn test_send_invalid_to_address() {
        let config = EmailConfig {
            smtp_host: "mail.example.com".into(),
            smtp_port: None,
            smtp_username: None,
            smtp_password: None,
            from_address: "noreply@example.com".into(),
            to_address: "not-an-email".into(),
        };
        let event = AlertEvent::new(AlertType::BackendDown, "test");
        let result = send(&config, &event).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("to_address"));
    }

    #[tokio::test]
    async fn test_send_unreachable_smtp_fails() {
        let config = EmailConfig {
            smtp_host: "192.0.2.1".into(),
            smtp_port: Some(25),
            smtp_username: None,
            smtp_password: None,
            from_address: "noreply@example.com".into(),
            to_address: "admin@example.com".into(),
        };
        let event = AlertEvent::new(AlertType::BackendDown, "test");
        let result = send(&config, &event).await;
        assert!(result.is_err());
    }
}
