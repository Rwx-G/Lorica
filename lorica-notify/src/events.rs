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
    /// A cluster node left the fleet or was revoked (Story 9.3
    /// AC #13); raised on the control plane.
    ClusterNodeLeft,
    /// A follower refused a replicated configuration wholesale
    /// (Story 9.4 AC #1: unknown field, version or hash mismatch);
    /// raised on the follower that refused it.
    ClusterConfigRefused,
    /// A node's applied configuration differs from the control
    /// plane's current one (Story 9.4 AC #12); raised on the control
    /// plane, suppressed per node by an exponential backoff.
    ClusterDrift,
    /// The access-log store (`access-log.db`) could not be opened, by
    /// this process or one of its workers: the node keeps serving, but
    /// its audit trail, access logs and WAF events are not persisted.
    /// Raised by the process serving the management API when the
    /// outage starts, sent again until a channel takes it, then as a
    /// periodic reminder for as long as the outage lasts.
    LogStoreUnavailable,
    /// Persistence resumed after a [`Self::LogStoreUnavailable`], without
    /// a restart.
    LogStoreRecovered,
    /// The AD CS authority entered the failed state of Epic 13 PRD D15:
    /// the KDC rejected its credential, so every further Kerberos
    /// exchange is suspended until an operator writes a new password.
    /// Raised once per entry into that state, not on each refused
    /// attempt while it lasts.
    AdcsAuthorityFailed,
    /// An AD CS issuance or renewal did not produce a certificate: the
    /// CA denied it, answered with an error fault, left it pending, or a
    /// step before that failed. The event carries the certificate id
    /// when there is one (a renewal, or an issuance that got that far),
    /// the failing step, and the authority's message.
    CertIssuanceFailed,
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
            Self::ClusterNodeLeft => "cluster_node_left",
            Self::ClusterConfigRefused => "cluster_config_refused",
            Self::ClusterDrift => "cluster_drift",
            Self::LogStoreUnavailable => "log_store_unavailable",
            Self::LogStoreRecovered => "log_store_recovered",
            Self::AdcsAuthorityFailed => "adcs_authority_failed",
            Self::CertIssuanceFailed => "cert_issuance_failed",
        }
    }

    /// Every alert type, in declaration order: the vocabulary a
    /// notification channel can subscribe to.
    pub const ALL: [AlertType; 14] = [
        Self::CertExpiring,
        Self::BackendDown,
        Self::WafAlert,
        Self::ConfigChanged,
        Self::SlaBreached,
        Self::SlaRecovered,
        Self::IpBanned,
        Self::ClusterNodeLeft,
        Self::ClusterConfigRefused,
        Self::ClusterDrift,
        Self::LogStoreUnavailable,
        Self::LogStoreRecovered,
        Self::AdcsAuthorityFailed,
        Self::CertIssuanceFailed,
    ];
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
            "cluster_node_left" => Ok(Self::ClusterNodeLeft),
            "cluster_config_refused" => Ok(Self::ClusterConfigRefused),
            "cluster_drift" => Ok(Self::ClusterDrift),
            "log_store_unavailable" => Ok(Self::LogStoreUnavailable),
            "log_store_recovered" => Ok(Self::LogStoreRecovered),
            "adcs_authority_failed" => Ok(Self::AdcsAuthorityFailed),
            "cert_issuance_failed" => Ok(Self::CertIssuanceFailed),
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

    /// The position of `alert_type` in [`AlertType::ALL`]. The match is
    /// exhaustive, so a new variant does not compile until it is given
    /// a position here, and the test below then fails until `ALL`
    /// holds it there.
    fn declared_position(alert_type: &AlertType) -> usize {
        match alert_type {
            AlertType::CertExpiring => 0,
            AlertType::BackendDown => 1,
            AlertType::WafAlert => 2,
            AlertType::ConfigChanged => 3,
            AlertType::SlaBreached => 4,
            AlertType::SlaRecovered => 5,
            AlertType::IpBanned => 6,
            AlertType::ClusterNodeLeft => 7,
            AlertType::ClusterConfigRefused => 8,
            AlertType::ClusterDrift => 9,
            AlertType::LogStoreUnavailable => 10,
            AlertType::LogStoreRecovered => 11,
            AlertType::AdcsAuthorityFailed => 12,
            AlertType::CertIssuanceFailed => 13,
        }
    }

    #[test]
    fn all_holds_every_variant_once() {
        for (index, alert_type) in AlertType::ALL.iter().enumerate() {
            assert_eq!(declared_position(alert_type), index, "{alert_type:?}");
        }
    }

    #[test]
    fn test_alert_type_round_trip() {
        for variant in AlertType::ALL {
            let s = variant.as_str();
            assert_eq!(
                s.parse::<AlertType>().expect("known AlertType variant"),
                variant
            );
            let json = serde_json::to_string(&variant).expect("an AlertType serializes");
            assert_eq!(json, format!("\"{s}\""), "serde and as_str agree");
        }
    }

    /// The management API reference lists the alert types a channel can
    /// subscribe to; a type missing there is one an operator scripting
    /// the API cannot know to ask for.
    #[test]
    fn the_api_reference_lists_every_alert_type() {
        let reference = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../lorica-api/openapi.yaml"
        ))
        .expect("test setup: the OpenAPI document reads");
        let line = reference
            .lines()
            .find(|line| line.contains("Alert categories this destination subscribes to"))
            .expect("the alert_types description is present");
        for alert_type in AlertType::ALL {
            let quoted = format!("`{}`", alert_type.as_str());
            assert!(line.contains(&quoted), "{quoted} is missing from: {line}");
        }
        let named: Vec<&str> = line.split('`').skip(1).step_by(2).collect();
        for name in &named {
            assert!(
                name.parse::<AlertType>().is_ok(),
                "`{name}` is listed in the API reference but is not an alert type"
            );
        }
        assert_eq!(
            named.len(),
            AlertType::ALL.len(),
            "the API reference names an alert type twice: {line}"
        );
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
