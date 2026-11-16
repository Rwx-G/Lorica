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

//! Prometheus counters owned by `lorica-bench` (Story 8.11 AC #2).
//!
//! These counters live in the supervisor / management process (the SLA
//! flush task and the active-probe scheduler both run there), so they
//! are served directly by the existing `/metrics` handler with no
//! per-worker aggregation. They register lazily against the shared
//! [`lorica_metrics::REGISTRY`] through the namespace-applying helpers,
//! so the scrape names carry the `lorica_` prefix.

use std::sync::OnceLock;

use lorica_metrics::prometheus::IntCounterVec;

/// `lorica_sla_breach_total{route_id, threshold_kind}`.
///
/// Incremented once per passive-SLA breach transition (OK -> breached),
/// not per sample. `route_id` is an operator-defined route id (bounded
/// by the number of configured routes). `threshold_kind` is a fixed
/// small set; see [`record_sla_breach`] for the value set and its
/// derivation.
fn sla_breach_counter() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        lorica_metrics::register_int_counter_vec(
            "sla_breach_total",
            "Passive-SLA breach transitions per route and threshold kind",
            &["route_id", "threshold_kind"],
        )
    })
}

/// `threshold_kind` label value for a passive-SLA target breach.
///
/// The passive-SLA evaluation in `passive_sla::persistence::check_thresholds`
/// reduces every per-route decision to the single composite
/// `SlaSummary::meets_target` boolean (`sla_pct >= target_pct`, where
/// `sla_pct = success_count / request_count`). The per-bucket
/// `max_latency_ms` and `success_status_min/max` thresholds are folded
/// into `success_count` at bucket-recording time, so the breach
/// transition exposes exactly one threshold kind here: the SLA target
/// percentage. Kept as a named constant so the call site and the metric
/// share one stable, lowercase snake_case label value.
pub const SLA_THRESHOLD_TARGET_PCT: &str = "target_pct";

/// Record a passive-SLA breach transition for `route_id` against
/// `threshold_kind`. Call exactly once per OK -> breached transition.
/// Pass [`SLA_THRESHOLD_TARGET_PCT`] for the current single threshold
/// kind; a future per-kind breakdown would call this once per kind
/// breached.
pub fn record_sla_breach(route_id: &str, threshold_kind: &str) {
    sla_breach_counter()
        .with_label_values(&[route_id, threshold_kind])
        .inc();
}

/// `lorica_stream_sla_breach_total{stream_id, threshold_kind}`, the
/// stream sibling of `lorica_sla_breach_total` (Story 12.9). A sibling
/// rather than a `stream_id` label on the route family, so that no
/// route series carries an empty `stream_id` and every stream family
/// keeps the `stream_` prefix.
fn stream_sla_breach_counter() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        lorica_metrics::register_int_counter_vec(
            "stream_sla_breach_total",
            "Passive-SLA breach transitions per stream and threshold kind",
            &["stream_id", "threshold_kind"],
        )
    })
}

/// Record a passive-SLA breach transition for `stream_id`, under the
/// same contract as [`record_sla_breach`]: once per OK -> breached
/// transition.
pub fn record_stream_sla_breach(stream_id: &str, threshold_kind: &str) {
    stream_sla_breach_counter()
        .with_label_values(&[stream_id, threshold_kind])
        .inc();
}

/// Remove the breach series of a stream that no longer exists, so a
/// churn of streams does not grow `/metrics` (Story 12.9 D-e). Call on
/// the table change that removes the stream.
pub fn forget_stream_sla_breaches(stream_id: &str) {
    // A stream that never breached has no series: nothing to remove.
    let _ = stream_sla_breach_counter().remove_label_values(&[stream_id, SLA_THRESHOLD_TARGET_PCT]);
}

/// `lorica_active_probe_outcome_total{probe_id, outcome}`.
///
/// Incremented once per active-probe execution. `probe_id` is an
/// operator-defined probe id (bounded by `max_active_probes`).
/// `outcome` is one of `ok | fail | timeout`; see [`record_probe_outcome`].
fn probe_outcome_counter() -> &'static IntCounterVec {
    static COUNTER: OnceLock<IntCounterVec> = OnceLock::new();
    COUNTER.get_or_init(|| {
        lorica_metrics::register_int_counter_vec(
            "active_probe_outcome_total",
            "Active-probe execution outcomes per probe (outcome=ok|fail|timeout)",
            &["probe_id", "outcome"],
        )
    })
}

/// Record an active-probe outcome. `outcome` MUST be one of `ok`,
/// `fail`, or `timeout`; the counter does not constrain the string, so
/// the call site enforces it (see `active_probes::probe_outcome`).
pub fn record_probe_outcome(probe_id: &str, outcome: &str) {
    probe_outcome_counter()
        .with_label_values(&[probe_id, outcome])
        .inc();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_sla_breach_increments_counter() {
        // Unique label values keep this isolated from other tests that
        // read the shared REGISTRY.
        record_sla_breach("metrics-test-sla-route", SLA_THRESHOLD_TARGET_PCT);
        record_sla_breach("metrics-test-sla-route", SLA_THRESHOLD_TARGET_PCT);
        let value = sla_breach_counter()
            .with_label_values(&["metrics-test-sla-route", SLA_THRESHOLD_TARGET_PCT])
            .get();
        assert_eq!(value, 2);

        // The counter must surface under the namespaced scrape name.
        let families = lorica_metrics::gather();
        assert!(families
            .iter()
            .any(|mf| mf.name() == "lorica_sla_breach_total"));
    }

    #[test]
    fn record_probe_outcome_increments_counter() {
        record_probe_outcome("metrics-test-probe", "timeout");
        let value = probe_outcome_counter()
            .with_label_values(&["metrics-test-probe", "timeout"])
            .get();
        assert_eq!(value, 1);
    }

    #[test]
    fn a_stream_breach_counts_under_its_own_family_until_forgotten() {
        let stream_id = "metrics-test-sla-stream";
        let labels = [stream_id, SLA_THRESHOLD_TARGET_PCT];
        record_stream_sla_breach(stream_id, SLA_THRESHOLD_TARGET_PCT);
        assert_eq!(
            stream_sla_breach_counter().with_label_values(&labels).get(),
            1
        );
        let family = |name: &str| {
            lorica_metrics::gather()
                .into_iter()
                .find(|mf| mf.name() == name)
        };
        let streams = family("lorica_stream_sla_breach_total").expect("registered");
        assert!(streams
            .get_metric()
            .iter()
            .any(|m| m.get_label().iter().any(|l| l.value() == stream_id)));

        forget_stream_sla_breaches(stream_id);
        let streams = family("lorica_stream_sla_breach_total");
        assert!(streams.is_none_or(|mf| !mf
            .get_metric()
            .iter()
            .any(|m| m.get_label().iter().any(|l| l.value() == stream_id))));
        forget_stream_sla_breaches(stream_id);
    }
}
