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

//! How the dashboard shows the alert types: a tone, and which alert a
//! recovery closes. The label is [`AlertType::label`], held by
//! `lorica_notify` because the email and Slack channels write it too.
//!
//! The alert vocabulary is `lorica_notify`'s [`AlertType::ALL`]; how an
//! operator reads each entry is held here, beside the API that serves
//! the notification channels, by exhaustive matches, so a new alert type
//! does not compile until it has a tone and a recovery. The dashboard
//! reads them from `adcs.generated.ts`, which
//! `lorica-api/tests/adcs_vocabulary_fixture.rs` renders from these
//! functions and pins byte for byte.

use lorica_notify::events::AlertType;

/// How an alert reads at a glance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertTone {
    /// Something stopped working.
    Problem,
    /// Something that had stopped works again.
    Recovery,
    /// Something will stop working unless acted on.
    Warning,
    /// Something happened.
    Info,
}

impl AlertTone {
    /// Every tone, in declaration order.
    pub const ALL: [AlertTone; 4] = [
        AlertTone::Problem,
        AlertTone::Recovery,
        AlertTone::Warning,
        AlertTone::Info,
    ];

    /// The tone's closed word.
    pub fn as_str(self) -> &'static str {
        match self {
            AlertTone::Problem => "problem",
            AlertTone::Recovery => "recovery",
            AlertTone::Warning => "warning",
            AlertTone::Info => "info",
        }
    }
}

/// How `alert_type` reads at a glance.
pub fn alert_type_tone(alert_type: &AlertType) -> AlertTone {
    match alert_type {
        AlertType::BackendDown
        | AlertType::SlaBreached
        | AlertType::LogStoreUnavailable
        | AlertType::AdcsAuthorityFailed
        | AlertType::CertIssuanceFailed
        | AlertType::ClusterConfigRefused => AlertTone::Problem,
        AlertType::SlaRecovered | AlertType::LogStoreRecovered => AlertTone::Recovery,
        AlertType::CertExpiring | AlertType::ClusterDrift | AlertType::ClusterNodeLeft => {
            AlertTone::Warning
        }
        AlertType::WafAlert | AlertType::ConfigChanged | AlertType::IpBanned => AlertTone::Info,
    }
}

/// The alert `alert_type` closes, for a recovery: a channel that
/// subscribes to one is meant to receive the other, so the dashboard
/// offers them as one choice.
pub fn alert_type_recovers(alert_type: &AlertType) -> Option<AlertType> {
    match alert_type {
        AlertType::SlaRecovered => Some(AlertType::SlaBreached),
        AlertType::LogStoreRecovered => Some(AlertType::LogStoreUnavailable),
        AlertType::CertExpiring
        | AlertType::BackendDown
        | AlertType::WafAlert
        | AlertType::ConfigChanged
        | AlertType::SlaBreached
        | AlertType::IpBanned
        | AlertType::ClusterNodeLeft
        | AlertType::ClusterConfigRefused
        | AlertType::ClusterDrift
        | AlertType::LogStoreUnavailable
        | AlertType::AdcsAuthorityFailed
        | AlertType::CertIssuanceFailed => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recovery_closes_a_problem_and_only_a_recovery_closes_anything() {
        for alert_type in AlertType::ALL {
            match alert_type_recovers(&alert_type) {
                Some(closed) => {
                    assert_eq!(alert_type_tone(&alert_type), AlertTone::Recovery);
                    assert_eq!(alert_type_tone(&closed), AlertTone::Problem);
                }
                None => assert_ne!(
                    alert_type_tone(&alert_type),
                    AlertTone::Recovery,
                    "{alert_type:?} recovers nothing"
                ),
            }
        }
    }
}
