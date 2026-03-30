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

//! Stdout notification channel - always on, structured JSON log events.

use crate::events::AlertEvent;
use tracing::info;

/// Emit an alert event as a structured JSON log entry.
///
/// This channel is always active and cannot be disabled. It provides
/// machine-parseable output for SIEM and log aggregation systems.
pub fn emit(event: &AlertEvent) {
    let json = serde_json::to_string(event).unwrap_or_else(|_| format!("{event:?}"));
    info!(
        alert_type = event.alert_type.as_str(),
        summary = %event.summary,
        event_json = %json,
        "ALERT"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::AlertType;

    #[test]
    fn test_emit_does_not_panic() {
        let event = AlertEvent::new(AlertType::BackendDown, "test");
        // Should not panic
        emit(&event);
    }

    #[test]
    fn test_emit_with_details() {
        let event = AlertEvent::new(AlertType::CertExpiring, "cert expiring")
            .with_detail("domain", "example.com");
        emit(&event);
    }
}
