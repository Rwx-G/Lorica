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

//! The alerts the data plane raises, built in one place.
//!
//! A WAF hit and an auto-ban are raised by the proxy itself in
//! single-process mode and by the supervisor in worker mode. Both go
//! through these constructors, so an alert reads the same, and carries
//! the same details, whichever process raised it.

use std::fmt::Display;

use lorica_notify::events::{AlertEvent, AlertType};
use lorica_waf::WafEvent;

/// Why an address was banned automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanCause {
    /// It went past a route's rate limit too often.
    RateLimitAbuse,
    /// It triggered too many WAF blocks.
    RepeatedWafViolations,
}

impl BanCause {
    fn describe(self) -> &'static str {
        match self {
            BanCause::RateLimitAbuse => "rate limit abuse",
            BanCause::RepeatedWafViolations => "repeated WAF violations",
        }
    }
}

/// The `waf_alert` for `event`. `path` is the request path when the
/// raising process still holds it; a WAF event forwarded by a worker
/// does not carry one.
pub fn waf_alert(event: &WafEvent, path: Option<&str>) -> AlertEvent {
    let action = if event.action.is_empty() {
        "hit"
    } else {
        event.action.as_str()
    };
    let mut alert = AlertEvent::new(
        AlertType::WafAlert,
        format!(
            "WAF {action} {} on {}{}: {} (rule {})",
            event.category.as_str(),
            event.route_hostname,
            path.unwrap_or(""),
            event.description,
            event.rule_id
        ),
    )
    .with_detail("rule_id", event.rule_id.to_string())
    .with_detail("category", event.category.as_str())
    .with_detail("severity", event.severity.to_string())
    .with_detail("host", event.route_hostname.clone())
    .with_detail("client_ip", event.client_ip.clone());
    if let Some(path) = path {
        alert = alert.with_detail("path", path);
    }
    alert
}

/// The `ip_banned` alert for `ip`, banned for `ban_duration_s` seconds
/// after `violations` offences of kind `cause`.
pub fn ip_banned(
    ip: &str,
    cause: BanCause,
    violations: impl Display,
    ban_duration_s: impl Display,
) -> AlertEvent {
    AlertEvent::new(
        AlertType::IpBanned,
        format!("IP {ip} auto-banned for {}", cause.describe()),
    )
    .with_detail("ip", ip)
    .with_detail("violations", violations.to_string())
    .with_detail("ban_duration_s", ban_duration_s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lorica_waf::RuleCategory;

    fn sql_injection_event() -> WafEvent {
        WafEvent {
            rule_id: 942100,
            description: "SQL injection".to_string(),
            category: RuleCategory::SqlInjection,
            severity: 5,
            matched_field: "query".to_string(),
            matched_value: "1 OR 1=1".to_string(),
            timestamp: "2026-11-23T00:00:00Z".to_string(),
            client_ip: "203.0.113.7".to_string(),
            route_hostname: "app.example.com".to_string(),
            action: "blocked".to_string(),
        }
    }

    /// Single-process and worker mode differ only by the path, which a
    /// forwarded event no longer has.
    #[test]
    fn a_waf_alert_names_the_host_rule_and_client() {
        let event = sql_injection_event();
        let forwarded = waf_alert(&event, None);
        assert_eq!(
            forwarded.summary,
            "WAF blocked sql_injection on app.example.com: SQL injection (rule 942100)"
        );
        assert_eq!(forwarded.details.get("path"), None);
        let local = waf_alert(&event, Some("/search"));
        assert_eq!(
            local.summary,
            "WAF blocked sql_injection on app.example.com/search: SQL injection (rule 942100)"
        );
        assert_eq!(
            local.details.get("path").map(String::as_str),
            Some("/search")
        );
        for key in ["rule_id", "category", "severity", "host", "client_ip"] {
            assert_eq!(
                local.details.get(key),
                forwarded.details.get(key),
                "{key} differs between run modes"
            );
        }
        assert_eq!(
            local.details.get("client_ip").map(String::as_str),
            Some("203.0.113.7")
        );
    }

    #[test]
    fn an_ip_banned_alert_says_why() {
        let alert = ip_banned("203.0.113.7", BanCause::RepeatedWafViolations, 5, 3600);
        assert_eq!(alert.alert_type, AlertType::IpBanned);
        assert_eq!(
            alert.summary,
            "IP 203.0.113.7 auto-banned for repeated WAF violations"
        );
        assert_eq!(
            alert.details.get("ban_duration_s").map(String::as_str),
            Some("3600")
        );
        assert_eq!(
            ip_banned("203.0.113.7", BanCause::RateLimitAbuse, 5, 3600).summary,
            "IP 203.0.113.7 auto-banned for rate limit abuse"
        );
    }
}
