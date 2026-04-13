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

use serde::{Deserialize, Serialize};

/// Alert event types that can trigger notifications.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertType {
    CertExpiring,
    BackendDown,
    WafAlert,
    ConfigChanged,
    SlaBreached,
    SlaRecovered,
    IpBanned,
}

impl AlertType {
    /// Return the canonical `snake_case` identifier of this alert type.
    ///
    /// Matches the form used by `Serialize`/`Deserialize` and by
    /// [`std::str::FromStr`], so it is safe to use for routing keys and
    /// channel subscription filters.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CertExpiring => "cert_expiring",
            Self::BackendDown => "backend_down",
            Self::WafAlert => "waf_alert",
            Self::ConfigChanged => "config_changed",
            Self::SlaBreached => "sla_breached",
            Self::SlaRecovered => "sla_recovered",
            Self::IpBanned => "ip_banned",
        }
    }
}

impl std::str::FromStr for AlertType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "cert_expiring" => Ok(Self::CertExpiring),
            "backend_down" => Ok(Self::BackendDown),
            "waf_alert" => Ok(Self::WafAlert),
            "config_changed" => Ok(Self::ConfigChanged),
            "sla_breached" => Ok(Self::SlaBreached),
            "sla_recovered" => Ok(Self::SlaRecovered),
            "ip_banned" => Ok(Self::IpBanned),
            other => Err(format!("unknown alert type: {other}")),
        }
    }
}

/// A concrete alert event with contextual data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEvent {
    /// The type of alert.
    pub alert_type: AlertType,
    /// Human-readable summary.
    pub summary: String,
    /// Additional details as key-value pairs.
    pub details: std::collections::HashMap<String, String>,
    /// When the event occurred.
    pub timestamp: String,
}

impl AlertEvent {
    /// Create a new alert event with the current timestamp.
    pub fn new(alert_type: AlertType, summary: impl Into<String>) -> Self {
        Self {
            alert_type,
            summary: summary.into(),
            details: std::collections::HashMap::new(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Add a detail key-value pair.
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_type_round_trip() {
        for (s, variant) in [
            ("cert_expiring", AlertType::CertExpiring),
            ("backend_down", AlertType::BackendDown),
            ("waf_alert", AlertType::WafAlert),
            ("config_changed", AlertType::ConfigChanged),
            ("sla_breached", AlertType::SlaBreached),
            ("sla_recovered", AlertType::SlaRecovered),
            ("ip_banned", AlertType::IpBanned),
        ] {
            assert_eq!(
                s.parse::<AlertType>().expect("known AlertType variant"),
                variant
            );
            assert_eq!(variant.as_str(), s);
        }
    }

    #[test]
    fn test_alert_type_unknown() {
        assert!("unknown".parse::<AlertType>().is_err());
    }

    #[test]
    fn test_alert_event_new() {
        let event = AlertEvent::new(AlertType::BackendDown, "Backend 10.0.0.1:8080 is down");
        assert_eq!(event.alert_type, AlertType::BackendDown);
        assert!(event.summary.contains("10.0.0.1"));
        assert!(!event.timestamp.is_empty());
    }

    #[test]
    fn test_alert_event_with_details() {
        let event = AlertEvent::new(AlertType::CertExpiring, "Certificate expiring soon")
            .with_detail("domain", "example.com")
            .with_detail("days_remaining", "7");
        assert_eq!(
            event.details.get("domain").expect("domain was set above"),
            "example.com"
        );
        assert_eq!(
            event
                .details
                .get("days_remaining")
                .expect("days_remaining was set above"),
            "7"
        );
    }

    #[test]
    fn test_ip_banned_alert_event() {
        let event = AlertEvent::new(AlertType::IpBanned, "IP 1.2.3.4 auto-banned")
            .with_detail("ip", "1.2.3.4")
            .with_detail("route_id", "route-1")
            .with_detail("duration_s", "3600");
        assert_eq!(event.alert_type, AlertType::IpBanned);
        assert_eq!(event.details.len(), 3);
        assert_eq!(
            event.details.get("ip").expect("ip was set above"),
            "1.2.3.4"
        );
    }

    #[test]
    fn test_alert_event_serde_round_trip() {
        let event = AlertEvent::new(AlertType::IpBanned, "banned").with_detail("ip", "10.0.0.1");
        let json = serde_json::to_string(&event).expect("AlertEvent fixture serializes cleanly");
        let deserialized: AlertEvent =
            serde_json::from_str(&json).expect("just-serialized JSON round-trips");
        assert_eq!(deserialized.alert_type, AlertType::IpBanned);
        assert_eq!(deserialized.summary, "banned");
        assert_eq!(
            deserialized
                .details
                .get("ip")
                .expect("ip was set on the source event"),
            "10.0.0.1"
        );
    }

    #[test]
    fn test_alert_event_serializes_to_json() {
        let event = AlertEvent::new(AlertType::WafAlert, "SQL injection detected")
            .with_detail("rule_id", "942100");
        let json = serde_json::to_string(&event).expect("AlertEvent fixture serializes cleanly");
        assert!(json.contains("waf_alert"));
        assert!(json.contains("942100"));
    }
}
