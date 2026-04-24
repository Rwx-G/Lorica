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

use super::{EmailConfig, NotifyError, SmtpEncryption};
use crate::events::AlertEvent;

/// Default port when `smtp_port` is unset, per encryption mode.
fn default_port_for(enc: SmtpEncryption) -> u16 {
    match enc {
        SmtpEncryption::Starttls => 587,
        SmtpEncryption::Tls => 465,
        SmtpEncryption::None => 25,
    }
}

/// Send an alert event as a plain-text SMTP email.
///
/// Transport is selected by `smtp_encryption`:
/// - [`SmtpEncryption::Starttls`] (default) - plaintext then STARTTLS
///   upgrade, typical port 587. Public-internet relays.
/// - [`SmtpEncryption::Tls`] - implicit TLS (SMTPS), typical port 465.
/// - [`SmtpEncryption::None`] - plaintext, no TLS at all. Port 25 LAN
///   MTA relays (Postfix, sendmail, mailhog, corporate gateways).
///   Credentials and message bodies travel in clear - operator MUST
///   constrain this to a trusted network.
///
/// When `smtp_port` is unset, falls back to the standard default for
/// the encryption mode (587 / 465 / 25). Authenticates when both
/// `smtp_username` and `smtp_password` are provided. Returns
/// [`NotifyError::Email`] on address parse failures, transport setup
/// errors, or SMTP send failures.
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

    let port = config
        .smtp_port
        .unwrap_or_else(|| default_port_for(config.smtp_encryption));

    let builder = match config.smtp_encryption {
        SmtpEncryption::Starttls => {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host)
                .map_err(|e| NotifyError::Email(format!("SMTP STARTTLS relay error: {e}")))?
        }
        SmtpEncryption::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)
            .map_err(|e| NotifyError::Email(format!("SMTP TLS relay error: {e}")))?,
        SmtpEncryption::None => {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.smtp_host)
        }
    };
    let mut transport_builder = builder.port(port);

    if let (Some(ref username), Some(ref password)) = (&config.smtp_username, &config.smtp_password)
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
            smtp_encryption: SmtpEncryption::Starttls,
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
            smtp_encryption: SmtpEncryption::Starttls,
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
            smtp_encryption: SmtpEncryption::None,
            from_address: "noreply@example.com".into(),
            to_address: "admin@example.com".into(),
        };
        let event = AlertEvent::new(AlertType::BackendDown, "test");
        let result = send(&config, &event).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_default_port_for_starttls_is_587() {
        assert_eq!(default_port_for(SmtpEncryption::Starttls), 587);
    }

    #[test]
    fn test_default_port_for_tls_is_465() {
        assert_eq!(default_port_for(SmtpEncryption::Tls), 465);
    }

    #[test]
    fn test_default_port_for_none_is_25() {
        assert_eq!(default_port_for(SmtpEncryption::None), 25);
    }

    #[tokio::test]
    async fn test_send_with_plaintext_encryption_builds_transport() {
        // Regression for v1.5.2 bug #2 : sendmail-style port 25 relay
        // without STARTTLS must not fail at transport-build time.
        // `192.0.2.1` is TEST-NET-1 (RFC 5737), unroutable so the
        // send step fails - but that is AFTER the builder_dangerous
        // branch runs. Previously `starttls_relay` returned a build
        // error on this shape before the network call was even
        // attempted.
        let config = EmailConfig {
            smtp_host: "192.0.2.1".into(),
            smtp_port: None, // exercises default_port_for(None) = 25
            smtp_username: None,
            smtp_password: None,
            smtp_encryption: SmtpEncryption::None,
            from_address: "noreply@example.com".into(),
            to_address: "admin@example.com".into(),
        };
        let event = AlertEvent::new(AlertType::BackendDown, "test");
        let result = send(&config, &event).await;
        // Must fail with "SMTP send failed" (network), NOT a
        // transport-setup error.
        let err = result.expect_err("unroutable host cannot deliver");
        let msg = err.to_string();
        assert!(
            msg.contains("SMTP send failed"),
            "expected network error, got: {msg}"
        );
        assert!(
            !msg.contains("relay error"),
            "transport setup should not fail for SmtpEncryption::None, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_send_with_implicit_tls_builds_transport() {
        let config = EmailConfig {
            smtp_host: "192.0.2.1".into(),
            smtp_port: None, // exercises default_port_for(Tls) = 465
            smtp_username: None,
            smtp_password: None,
            smtp_encryption: SmtpEncryption::Tls,
            from_address: "noreply@example.com".into(),
            to_address: "admin@example.com".into(),
        };
        let event = AlertEvent::new(AlertType::BackendDown, "test");
        let result = send(&config, &event).await;
        assert!(result.is_err());
    }
}
