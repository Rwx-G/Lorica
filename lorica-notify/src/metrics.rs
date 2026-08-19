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

//! Prometheus counter owned by `lorica-notify` (Story 8.11 AC #2).
//!
//! Notification dispatch runs in the supervisor / management process, so
//! the counter is served directly by the existing `/metrics` handler
//! with no per-worker aggregation. It registers lazily against the
//! shared [`lorica_metrics::REGISTRY`] through the namespace-applying
//! helper, so the scrape name is `lorica_notification_dispatch_total`.

use std::sync::OnceLock;

use lorica_metrics::prometheus::IntCounterVec;

/// `lorica_notification_dispatch_total{channel, outcome}`.
///
/// Incremented exactly once per channel dispatch attempt. `channel` is
/// one of `email | webhook | slack | stdout`. `outcome` is one of
/// `ok | http_4xx | http_5xx | timeout | connect_failed`; see
/// [`record_notification_dispatch`] and the per-channel classifiers.
fn dispatch_counter() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        lorica_metrics::register_int_counter_vec(
            "notification_dispatch_total",
            "Notification dispatch outcomes per channel \
             (outcome=ok|http_4xx|http_5xx|timeout|connect_failed)",
            &["channel", "outcome"],
        )
    })
}

/// Record one notification dispatch outcome. `channel` MUST be one of
/// `email`, `webhook`, `slack`, `stdout`; `outcome` MUST be one of `ok`,
/// `http_4xx`, `http_5xx`, `timeout`, `connect_failed`. The counter does
/// not constrain the strings, so the call sites (the channel `send`
/// functions and the stdout path in `channels::NotifyDispatcher::dispatch`)
/// enforce the value sets.
pub fn record_notification_dispatch(channel: &str, outcome: &str) {
    dispatch_counter()
        .with_label_values(&[channel, outcome])
        .inc();
}

/// Classify a `reqwest` request error (webhook / slack transport) into a
/// dispatch outcome label.
///
/// A request that exceeded its timeout -> `timeout`. Every other
/// transport failure (connection refused, DNS failure, TLS handshake,
/// body / decode error) has no HTTP status and is bucketed as
/// `connect_failed`.
pub(crate) fn classify_reqwest_error(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else {
        "connect_failed"
    }
}

/// Classify a non-success HTTP response status (webhook / slack) into a
/// dispatch outcome label.
///
/// 4xx -> `http_4xx`, 5xx -> `http_5xx`. A non-2xx, non-4xx, non-5xx
/// status (a 1xx/3xx reaching this path only with redirects disabled,
/// which the webhook client enforces) carries no clean bucket and is
/// reported as `connect_failed`.
pub(crate) fn classify_response_status(status: reqwest::StatusCode) -> &'static str {
    if status.is_client_error() {
        "http_4xx"
    } else if status.is_server_error() {
        "http_5xx"
    } else {
        "connect_failed"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::StatusCode;

    #[test]
    fn record_notification_dispatch_increments_counter() {
        record_notification_dispatch("metrics-test-channel", "ok");
        record_notification_dispatch("metrics-test-channel", "ok");
        let value = dispatch_counter()
            .with_label_values(&["metrics-test-channel", "ok"])
            .get();
        assert_eq!(value, 2);

        // The counter must surface under the namespaced scrape name.
        let families = lorica_metrics::gather();
        assert!(families
            .iter()
            .any(|mf| mf.name() == "lorica_notification_dispatch_total"));
    }

    #[test]
    fn classify_response_status_buckets() {
        assert_eq!(classify_response_status(StatusCode::NOT_FOUND), "http_4xx");
        assert_eq!(
            classify_response_status(StatusCode::SERVICE_UNAVAILABLE),
            "http_5xx"
        );
        // 3xx with redirects disabled has no 4xx/5xx bucket.
        assert_eq!(classify_response_status(StatusCode::FOUND), "connect_failed");
    }
}
