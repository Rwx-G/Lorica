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

#![deny(unsafe_code)]
#![warn(clippy::all)]

//! Shared Prometheus infrastructure for Lorica.
//!
//! This crate owns the process-global metrics [`REGISTRY`], the
//! type-safe registration helpers every Lorica crate uses to create
//! counters, and the cross-worker counter aggregation machinery that
//! ships per-worker counter deltas to the supervisor's registry.
//!
//! It was extracted from `lorica-api::metrics` in v1.6.0 to break the
//! `lorica-api -> lorica-bench` / `lorica-api -> lorica-notify`
//! dependency cycle: those crates need to register Prometheus counters
//! but cannot depend on `lorica-api` (which already depends on them).
//!
//! Consumers register and increment counters through this crate and
//! through the re-exported [`prometheus`] module; they must NOT add a
//! direct `prometheus` dependency, so the whole workspace shares one
//! `prometheus` version and the metric types stay compatible.
//!
//! ```
//! let counter = lorica_metrics::register_int_counter_vec(
//!     "doc_example_total",
//!     "Doc-test counter",
//!     &["label"],
//! );
//! counter.with_label_values(&["a"]).inc();
//! // Registered under the `lorica` namespace, so the scrape name is
//! // `lorica_doc_example_total`.
//! assert!(lorica_metrics::gather()
//!     .iter()
//!     .any(|mf| mf.name() == "lorica_doc_example_total"));
//! ```

/// Re-exported `prometheus`. Consumers depend on
/// `lorica_metrics::prometheus` rather than pulling in `prometheus`
/// directly, which keeps a single version of the metric types across
/// the workspace and avoids the type-incompatibility that two
/// independently-pinned `prometheus` crates would cause.
pub use prometheus;

use once_cell::sync::Lazy;
use prometheus::{
    Gauge, GaugeVec, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Registry,
};

/// Namespace prepended to every metric registered through the helpers
/// below. Matches the historical `lorica-api` convention so existing
/// scrape names (e.g. `lorica_http_requests_total`) are unchanged. A
/// custom [`prometheus::core::Collector`] that builds its own families
/// prefixes their names with it too.
pub const NAMESPACE: &str = "lorica";

/// Process-global metrics registry.
///
/// Supervisor and worker run as separate processes, so each has its
/// own instance of this static; that per-process separation is the
/// reason the cross-worker aggregation helpers below exist.
pub static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

/// Borrow the process-global [`REGISTRY`].
pub fn registry() -> &'static Registry {
    &REGISTRY
}

/// Gather the current metric families from the process-global
/// [`REGISTRY`]. The `/metrics` handler encodes the result with a
/// `prometheus::TextEncoder`.
pub fn gather() -> Vec<prometheus::proto::MetricFamily> {
    REGISTRY.gather()
}

/// A hardcoded metric definition failed to build. This only happens
/// for a malformed compile-time constant name or label set, i.e. a
/// programmer error in a registration call site, so it is treated as
/// an unreachable invariant rather than a recoverable error.
fn unreachable_metric_definition(name: &str, err: &prometheus::Error) -> ! {
    panic!("lorica-metrics: invalid metric definition for '{name}': {err}");
}

/// Build a label-less [`IntCounter`] under the `lorica` namespace and
/// register it against the shared [`REGISTRY`]. Double registration
/// (e.g. a counter re-created in a test process) is tolerated: the
/// duplicate `register` is ignored and the returned handle still
/// increments the live counter.
pub fn register_int_counter(name: &str, help: &str) -> IntCounter {
    let opts: prometheus::Opts = prometheus::Opts::new(name, help).namespace(NAMESPACE);
    match IntCounter::with_opts(opts) {
        Ok(counter) => {
            REGISTRY.register(Box::new(counter.clone())).ok();
            counter
        }
        Err(err) => unreachable_metric_definition(name, &err),
    }
}

/// Build an [`IntCounterVec`] under the `lorica` namespace with the
/// given label names and register it against the shared [`REGISTRY`].
pub fn register_int_counter_vec(name: &str, help: &str, label_names: &[&str]) -> IntCounterVec {
    let opts: prometheus::Opts = prometheus::Opts::new(name, help).namespace(NAMESPACE);
    match IntCounterVec::new(opts, label_names) {
        Ok(counter) => {
            REGISTRY.register(Box::new(counter.clone())).ok();
            counter
        }
        Err(err) => unreachable_metric_definition(name, &err),
    }
}

/// Build an [`IntGauge`] under the `lorica` namespace and register it
/// against the shared [`REGISTRY`].
pub fn register_int_gauge(name: &str, help: &str) -> IntGauge {
    let opts: prometheus::Opts = prometheus::Opts::new(name, help).namespace(NAMESPACE);
    match IntGauge::with_opts(opts) {
        Ok(gauge) => {
            REGISTRY.register(Box::new(gauge.clone())).ok();
            gauge
        }
        Err(err) => unreachable_metric_definition(name, &err),
    }
}

/// Build an [`IntGaugeVec`] under the `lorica` namespace with the
/// given label names and register it against the shared [`REGISTRY`].
pub fn register_int_gauge_vec(name: &str, help: &str, label_names: &[&str]) -> IntGaugeVec {
    let opts: prometheus::Opts = prometheus::Opts::new(name, help).namespace(NAMESPACE);
    match IntGaugeVec::new(opts, label_names) {
        Ok(gauge) => {
            REGISTRY.register(Box::new(gauge.clone())).ok();
            gauge
        }
        Err(err) => unreachable_metric_definition(name, &err),
    }
}

/// Build a [`HistogramVec`] under the `lorica` namespace with the
/// given label names and bucket boundaries, and register it against
/// the shared [`REGISTRY`].
pub fn register_histogram_vec(
    name: &str,
    help: &str,
    label_names: &[&str],
    buckets: Vec<f64>,
) -> HistogramVec {
    let opts: HistogramOpts = HistogramOpts::new(name, help)
        .namespace(NAMESPACE)
        .buckets(buckets);
    match HistogramVec::new(opts, label_names) {
        Ok(histogram) => {
            REGISTRY.register(Box::new(histogram.clone())).ok();
            histogram
        }
        Err(err) => unreachable_metric_definition(name, &err),
    }
}

/// Build a floating-point [`Gauge`] under the `lorica` namespace and
/// register it against the shared [`REGISTRY`]. Use this for a scalar
/// gauge whose value is fractional (e.g. a CPU-usage percentage);
/// [`register_int_gauge`] is the integer-valued counterpart.
pub fn register_gauge(name: &str, help: &str) -> Gauge {
    let opts: prometheus::Opts = prometheus::Opts::new(name, help).namespace(NAMESPACE);
    match Gauge::with_opts(opts) {
        Ok(gauge) => {
            REGISTRY.register(Box::new(gauge.clone())).ok();
            gauge
        }
        Err(err) => unreachable_metric_definition(name, &err),
    }
}

/// Build a floating-point [`GaugeVec`] under the `lorica` namespace
/// with the given label names and register it against the shared
/// [`REGISTRY`]. Use this for a labelled gauge whose value is
/// fractional (e.g. backend health `1.0 | 0.5 | 0.0`);
/// [`register_int_gauge_vec`] is the integer-valued counterpart.
pub fn register_gauge_vec(name: &str, help: &str, label_names: &[&str]) -> GaugeVec {
    let opts: prometheus::Opts = prometheus::Opts::new(name, help).namespace(NAMESPACE);
    match GaugeVec::new(opts, label_names) {
        Ok(gauge) => {
            REGISTRY.register(Box::new(gauge.clone())).ok();
            gauge
        }
        Err(err) => unreachable_metric_definition(name, &err),
    }
}

/// Build a label-less [`Histogram`] under the `lorica` namespace with
/// the given bucket boundaries and register it against the shared
/// [`REGISTRY`]. [`register_histogram_vec`] is the labelled
/// counterpart.
pub fn register_histogram(name: &str, help: &str, buckets: Vec<f64>) -> Histogram {
    let opts: HistogramOpts = HistogramOpts::new(name, help)
        .namespace(NAMESPACE)
        .buckets(buckets);
    match Histogram::with_opts(opts) {
        Ok(histogram) => {
            REGISTRY.register(Box::new(histogram.clone())).ok();
            histogram
        }
        Err(err) => unreachable_metric_definition(name, &err),
    }
}

// ---------------------------------------------------------------------------
// Cross-worker counter aggregation.
//
// In worker mode, the `IntCounterVec` / `IntCounter` statics that own
// the data-plane counters live in the worker process that incremented
// them. The supervisor's `/metrics` handler scrapes the supervisor's
// own registry, which never sees worker-side increments for those
// counters. The helpers below let a worker serialise a snapshot of the
// named counters and let the supervisor apply that snapshot to its own
// registry, keyed per-worker so successive scrapes replace instead of
// double-count.
//
// The apply path does not blindly `inc_by` the reported value (that
// would double-count on the next scrape). It tracks per-worker
// snapshots (worker_id -> metric_name -> label_key -> value) and on
// every apply computes the delta to reach the new value; if a worker
// resets or drops out the delta goes negative and the counter stays
// put (Prometheus counters cannot decrement).
//
// The list of counter NAMES and the mapping from name to the live
// supervisor-side counter handle stay in the owning crate
// (`lorica-api`): this crate operates purely on names + a caller-
// supplied resolver, so it carries no data-plane domain knowledge.
// ---------------------------------------------------------------------------

/// One generic counter entry on the worker -> supervisor wire:
/// `(metric_name, label_name_value_pairs, value)`.
///
/// Labels are carried as name=value pairs (not positional values)
/// because `prometheus::Metric::get_label()` returns them in
/// ALPHABETICAL order, not registration order. At apply time the
/// supervisor reorders them into the target counter's registered
/// label order via the resolver's label-name list.
pub type GenericCounterTuple = (String, Vec<(String, String)>, u64);

/// Where a resolved wire entry applies on the supervisor side: a
/// labelled [`IntCounterVec`] or a label-less scalar [`IntCounter`].
/// References are `'static` (they point at the owning crate's
/// `Lazy`-initialised counter statics) and `Copy`.
#[derive(Clone, Copy)]
pub enum CounterTarget {
    /// A labelled counter vec; the wire entry's labels are reordered
    /// into the registered label order before `with_label_values`.
    Vec(&'static IntCounterVec),
    /// A label-less scalar counter (no label-arity guard needed).
    Scalar(&'static IntCounter),
}

/// Snapshot every counter named in `names` from the process-global
/// [`REGISTRY`]. Called on every metrics-report tick by a worker.
///
/// Returns one entry per non-zero label combination of each named
/// counter; counters that have never incremented contribute nothing,
/// keeping the steady-state RPC payload small. A label-less counter
/// (e.g. an [`IntCounter`]) yields an entry with an empty label vec.
///
/// `names` are the FULL registered names including the namespace
/// prefix (e.g. `"lorica_geoip_block_total"`), matching what the
/// scrape exposes.
pub fn snapshot_per_worker_counters(names: &[&str]) -> Vec<GenericCounterTuple> {
    let mut out: Vec<GenericCounterTuple> = Vec::new();
    for mf in REGISTRY.gather() {
        let name: &str = mf.name();
        if !names.contains(&name) {
            continue;
        }
        for m in mf.get_metric() {
            // `get_label` returns pairs in alphabetical order, which
            // is NOT the registration order; the supervisor rebuilds
            // positional ordering from the resolver's label list.
            let labels: Vec<(String, String)> = m
                .get_label()
                .iter()
                .map(|l| (l.name().to_string(), l.value().to_string()))
                .collect();
            let value: u64 = m.get_counter().value() as u64;
            if value > 0 {
                out.push((name.to_string(), labels, value));
            }
        }
    }
    out
}

/// Supervisor-side snapshot: metric_name -> label_key -> last-known
/// value, per worker.
type PerWorkerCounterSnapshot =
    std::collections::HashMap<String, std::collections::HashMap<String, u64>>;

static SUPERVISOR_GENERIC_SNAPSHOT: Lazy<
    parking_lot::RwLock<std::collections::HashMap<u32, PerWorkerCounterSnapshot>>,
> = Lazy::new(|| parking_lot::RwLock::new(std::collections::HashMap::new()));

/// Apply a worker's generic-counter snapshot to the process-global
/// [`REGISTRY`] via the supervisor-side counter statics.
///
/// `resolve` maps a metric name to its registered label order and the
/// live supervisor-side [`CounterTarget`]; unknown names are skipped.
/// Keeping the resolver in the caller lets this crate stay free of any
/// data-plane counter knowledge.
///
/// A worker's reported value only ever produces a POSITIVE delta: a
/// dropped or restarted worker's state stays at the last scrape until
/// another report arrives or [`forget_worker_generic_counters`]
/// removes it.
pub fn apply_worker_generic_counters(
    worker_id: u32,
    entries: &[GenericCounterTuple],
    resolve: impl Fn(&str) -> Option<(&'static [&'static str], CounterTarget)>,
) {
    fn key_from_positional(values: &[String]) -> String {
        values.join("\0")
    }

    /// One wire entry fully resolved before the snapshot lock is
    /// taken: owned key strings plus the target supervisor-side
    /// counter.
    struct PreparedEntry {
        metric_name: String,
        label_key: String,
        positional: Vec<String>,
        value: u64,
        target: CounterTarget,
    }

    // Phase 1 - no lock held. Resolve label order, build the
    // positional values and the snapshot key, and bind the target for
    // every wire entry. All string allocation happens here so the
    // write lock below covers hashmap delta math only.
    let mut prepared: Vec<PreparedEntry> = Vec::with_capacity(entries.len());
    for (name, label_pairs, value) in entries {
        let Some((order, target)) = resolve(name) else {
            continue;
        };
        // Reorder name=value pairs into positional values matching the
        // registered order. A missing name becomes an empty string,
        // which the registered vec rejects, so it is skipped by the
        // phase-3 `get_metric_with_label_values` guard (safe default).
        let mut positional: Vec<String> = Vec::with_capacity(order.len());
        for expected in order {
            let v: String = label_pairs
                .iter()
                .find(|(n, _)| n.as_str() == *expected)
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            positional.push(v);
        }
        let label_key: String = key_from_positional(&positional);
        prepared.push(PreparedEntry {
            metric_name: name.clone(),
            label_key,
            positional,
            value: *value,
            target,
        });
    }

    // Phase 2 - tight critical section. Compute per-label deltas
    // against the worker's last-known snapshot and record the new
    // values: HashMap moves and u64 math only, no string building and
    // no prometheus calls under the lock. This MERGES into the
    // existing worker state rather than swapping it wholesale: a label
    // combo absent from this report keeps its previous value, so a
    // later report carrying it again does not re-apply the full count
    // as a fresh delta.
    let mut to_apply: Vec<(CounterTarget, Vec<String>, u64)> = Vec::with_capacity(prepared.len());
    {
        let mut map = SUPERVISOR_GENERIC_SNAPSHOT.write();
        let worker_state = map.entry(worker_id).or_default();
        for entry in prepared {
            let metric_state = worker_state.entry(entry.metric_name).or_default();
            let prev: u64 = metric_state.get(&entry.label_key).copied().unwrap_or(0);
            if entry.value <= prev {
                continue;
            }
            let delta: u64 = entry.value - prev;
            metric_state.insert(entry.label_key, entry.value);
            to_apply.push((entry.target, entry.positional, delta));
        }
    }

    // Phase 3 - no lock held. Counter increments are atomic and the
    // deltas were computed atomically in phase 2, so interleaving with
    // a concurrent apply still converges to the same sums.
    for (target, positional, delta) in to_apply {
        match target {
            CounterTarget::Vec(vec) => {
                let label_refs: Vec<&str> = positional.iter().map(|s| s.as_str()).collect();
                if vec.get_metric_with_label_values(&label_refs).is_ok() {
                    vec.with_label_values(&label_refs).inc_by(delta);
                }
            }
            CounterTarget::Scalar(counter) => counter.inc_by(delta),
        }
    }
}

/// Drop a worker's supervisor-side snapshot. Called when the
/// supervisor detects a dead worker (RPC channel gone, crash
/// signalled). Without this the supervisor would keep the worker's
/// last-known counter values forever, skewing the aggregate.
pub fn forget_worker_generic_counters(worker_id: u32) {
    SUPERVISOR_GENERIC_SNAPSHOT.write().remove(&worker_id);
}

/// Test helper that wipes the supervisor's generic-counter snapshot so
/// a fresh test starts from zero. Exposed (not `#[cfg(test)]`) so the
/// owning crate's tests, which drive `apply_worker_generic_counters`
/// through their own wrappers, can reset shared state too.
pub fn reset_generic_counter_snapshot_for_test() {
    SUPERVISOR_GENERIC_SNAPSHOT.write().clear();
}

// ---------------------------------------------------------------------------
// Cross-worker gauge aggregation (Story 12.9 D-f).
//
// A gauge is a state, not a running total, so the counter delta
// machinery above cannot carry it: a value that goes down is the news,
// not a reset to swallow. Each process sets its own value; a worker
// ships it in the same generic list the counters ride (so no wire
// change), and the supervisor renders, per label set, the aggregate of
// its own value and every worker's last report.
// ---------------------------------------------------------------------------

/// How the supervisor combines the per-process values of one gauge into
/// the node's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GaugeAggregation {
    /// The lowest value: a state where one process down means the node
    /// is down for that process's share of the work.
    Min,
    /// The highest value.
    Max,
    /// The sum: each process holds its own share of the quantity.
    Sum,
}

impl GaugeAggregation {
    /// Combine `values`; `None` when there is none.
    pub fn combine(self, values: impl IntoIterator<Item = i64>) -> Option<i64> {
        let mut values = values.into_iter();
        let first: i64 = values.next()?;
        Some(values.fold(first, |acc, v| match self {
            Self::Min => acc.min(v),
            Self::Max => acc.max(v),
            Self::Sum => acc.saturating_add(v),
        }))
    }

    /// Whether a dead worker's last values keep counting until its
    /// replacement, which takes the same id, reports. A state (`Min`,
    /// `Max`) does: dropping it would read "every process is fine" for
    /// the length of a respawn. A share (`Sum`) does not: what a dead
    /// process held died with it.
    pub fn outlives_its_worker(self) -> bool {
        !matches!(self, Self::Sum)
    }
}

/// Positional label values of one series.
type GaugeLabelValues = Vec<String>;

#[derive(Debug, Default)]
struct AggregatedGaugeState {
    /// This process's own values.
    local: std::collections::BTreeMap<GaugeLabelValues, i64>,
    /// Each worker's last report, by worker id.
    workers: std::collections::BTreeMap<u32, std::collections::BTreeMap<GaugeLabelValues, i64>>,
    /// The label sets the registry renders now, so one that no process
    /// holds any more is removed.
    rendered: std::collections::BTreeSet<GaugeLabelValues>,
}

/// An [`IntGaugeVec`] whose rendered value, per label set, is the
/// [`GaugeAggregation`] of this process's value and every worker's.
///
/// In a worker, and in a single process, nothing reports to it, so it
/// renders the process's own value. A worker ships that value with
/// [`AggregatedGauge::snapshot_local`]; the supervisor applies each
/// report with [`AggregatedGauge::apply_worker`].
#[derive(Debug)]
pub struct AggregatedGauge {
    name: String,
    label_names: &'static [&'static str],
    aggregation: GaugeAggregation,
    gauge: IntGaugeVec,
    state: parking_lot::Mutex<AggregatedGaugeState>,
}

impl AggregatedGauge {
    /// Build the gauge under the `lorica` namespace and register it
    /// against the shared [`REGISTRY`].
    pub fn register(
        name: &str,
        help: &str,
        label_names: &'static [&'static str],
        aggregation: GaugeAggregation,
    ) -> AggregatedGauge {
        Self::with_gauge(
            name,
            register_int_gauge_vec(name, help, label_names),
            label_names,
            aggregation,
        )
    }

    fn with_gauge(
        name: &str,
        gauge: IntGaugeVec,
        label_names: &'static [&'static str],
        aggregation: GaugeAggregation,
    ) -> AggregatedGauge {
        AggregatedGauge {
            name: format!("{NAMESPACE}_{name}"),
            label_names,
            aggregation,
            gauge,
            state: parking_lot::Mutex::new(AggregatedGaugeState::default()),
        }
    }

    /// The registered name, namespace included, as a scrape and the wire
    /// spell it.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set this process's value for `label_values`, given in the
    /// registered label order.
    pub fn set_local(&self, label_values: &[&str], value: i64) {
        let mut state = self.state.lock();
        state.local.insert(owned(label_values), value);
        self.render(&mut state);
    }

    /// This process no longer holds a value for `label_values`.
    pub fn clear_local(&self, label_values: &[&str]) {
        let mut state = self.state.lock();
        state.local.remove(&owned(label_values));
        self.render(&mut state);
    }

    /// This process's own values as wire entries, zeros included: for a
    /// state, 0 is the news. Negative values are sent as 0, the wire
    /// being unsigned; no aggregated gauge holds a negative value.
    pub fn snapshot_local(&self) -> Vec<GenericCounterTuple> {
        let state = self.state.lock();
        state
            .local
            .iter()
            .map(|(values, value)| {
                let pairs: Vec<(String, String)> = self
                    .label_names
                    .iter()
                    .zip(values)
                    .map(|(name, value)| ((*name).to_string(), value.clone()))
                    .collect();
                (self.name.clone(), pairs, u64::try_from(*value).unwrap_or(0))
            })
            .collect()
    }

    /// Record a worker's report. The report is the worker's whole state
    /// for this gauge: a label set it no longer carries is dropped from
    /// that worker. Entries of other names are ignored, so the whole
    /// generic list can be passed; an entry missing one of the gauge's
    /// labels is skipped.
    pub fn apply_worker(&self, worker_id: u32, entries: &[GenericCounterTuple]) {
        let reported: std::collections::BTreeMap<GaugeLabelValues, i64> = entries
            .iter()
            .filter(|(name, _, _)| *name == self.name)
            .filter_map(|(_, pairs, value)| {
                let values: Option<GaugeLabelValues> = self
                    .label_names
                    .iter()
                    .map(|expected| {
                        pairs
                            .iter()
                            .find(|(name, _)| name == expected)
                            .map(|(_, value)| value.clone())
                    })
                    .collect();
                values.map(|v| (v, i64::try_from(*value).unwrap_or(i64::MAX)))
            })
            .collect();
        let mut state = self.state.lock();
        state.workers.insert(worker_id, reported);
        self.render(&mut state);
    }

    /// A worker died. Its values leave the aggregate at once for a
    /// [`GaugeAggregation::Sum`], and stand until its replacement
    /// reports otherwise ([`GaugeAggregation::outlives_its_worker`]).
    pub fn forget_worker(&self, worker_id: u32) {
        if self.aggregation.outlives_its_worker() {
            return;
        }
        let mut state = self.state.lock();
        state.workers.remove(&worker_id);
        self.render(&mut state);
    }

    fn render(&self, state: &mut AggregatedGaugeState) {
        let mut keys: std::collections::BTreeSet<GaugeLabelValues> =
            state.local.keys().cloned().collect();
        for values in state.workers.values() {
            keys.extend(values.keys().cloned());
        }
        for stale in state.rendered.difference(&keys) {
            let refs: Vec<&str> = stale.iter().map(String::as_str).collect();
            // Absent already is the state this asks for.
            let _ = self.gauge.remove_label_values(&refs);
        }
        for key in &keys {
            let values = state
                .local
                .get(key)
                .into_iter()
                .chain(state.workers.values().filter_map(|w| w.get(key)))
                .copied();
            if let Some(value) = self.aggregation.combine(values) {
                let refs: Vec<&str> = key.iter().map(String::as_str).collect();
                self.gauge.with_label_values(&refs).set(value);
            }
        }
        state.rendered = keys;
    }
}

fn owned(values: &[&str]) -> GaugeLabelValues {
    values.iter().map(|v| (*v).to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::core::Collector;

    // The two aggregation tests below each reset the process-global
    // SUPERVISOR_GENERIC_SNAPSHOT. Rust runs tests in parallel, so without
    // serialization one test's reset wipes the other's mid-accumulation and
    // the delta math breaks (order-dependent flake). This guard serializes
    // them; a poisoned lock (a prior test panicked) is recovered so the
    // surviving test still runs.
    static SNAPSHOT_TEST_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn register_helpers_apply_namespace_and_register() {
        // The helper must prepend the `lorica` namespace and register
        // the counter so it shows up in `gather()` under the prefixed
        // name - the byte-for-byte scrape-name guarantee consumers
        // rely on.
        let counter = register_int_counter_vec(
            "metrics_unit_helper_total",
            "registration helper unit test",
            &["label"],
        );
        counter.with_label_values(&["v"]).inc();

        let families = gather();
        let found = families
            .iter()
            .any(|mf| mf.name() == "lorica_metrics_unit_helper_total");
        assert!(
            found,
            "registered counter must appear with lorica namespace"
        );
    }

    #[test]
    fn snapshot_then_apply_aggregates_and_is_delta_based() {
        let _guard = SNAPSHOT_TEST_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        reset_generic_counter_snapshot_for_test();

        // A labelled counter owned "by the caller" - here a local
        // static stands in for an owning-crate counter static.
        static TEST_VEC: Lazy<IntCounterVec> = Lazy::new(|| {
            register_int_counter_vec(
                "metrics_unit_agg_total",
                "aggregation unit test",
                &["route_id"],
            )
        });

        fn resolve(name: &str) -> Option<(&'static [&'static str], CounterTarget)> {
            match name {
                "lorica_metrics_unit_agg_total" => {
                    Some((&["route_id"], CounterTarget::Vec(&TEST_VEC)))
                }
                _ => None,
            }
        }

        let entry = |value: u64| {
            vec![(
                "lorica_metrics_unit_agg_total".to_string(),
                vec![("route_id".to_string(), "agg".to_string())],
                value,
            )]
        };

        apply_worker_generic_counters(1, &entry(3), resolve);
        apply_worker_generic_counters(2, &entry(5), resolve);
        assert_eq!(TEST_VEC.with_label_values(&["agg"]).get(), 8);

        // Second report from worker 1 with a bigger value applies only
        // the delta (4 - 3 = 1), not the full 4.
        apply_worker_generic_counters(1, &entry(4), resolve);
        assert_eq!(TEST_VEC.with_label_values(&["agg"]).get(), 9);

        // A regressed worker snapshot must not decrement.
        apply_worker_generic_counters(1, &entry(0), resolve);
        assert_eq!(TEST_VEC.with_label_values(&["agg"]).get(), 9);

        // Snapshot must surface the live value and skip zero entries.
        let snap = snapshot_per_worker_counters(&["lorica_metrics_unit_agg_total"]);
        assert!(snap
            .iter()
            .any(|(n, _, v)| n == "lorica_metrics_unit_agg_total" && *v == 9));
        assert!(snap.iter().all(|(_, _, v)| *v > 0));
    }

    #[test]
    fn apply_handles_label_less_scalar() {
        let _guard = SNAPSHOT_TEST_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        reset_generic_counter_snapshot_for_test();

        static TEST_SCALAR: Lazy<IntCounter> =
            Lazy::new(|| register_int_counter("metrics_unit_scalar_total", "scalar unit test"));

        fn resolve(name: &str) -> Option<(&'static [&'static str], CounterTarget)> {
            match name {
                "lorica_metrics_unit_scalar_total" => {
                    Some((&[], CounterTarget::Scalar(&TEST_SCALAR)))
                }
                _ => None,
            }
        }

        let before = TEST_SCALAR.get();
        apply_worker_generic_counters(
            7,
            &[(
                "lorica_metrics_unit_scalar_total".to_string(),
                Vec::new(),
                4,
            )],
            resolve,
        );
        apply_worker_generic_counters(
            8,
            &[(
                "lorica_metrics_unit_scalar_total".to_string(),
                Vec::new(),
                6,
            )],
            resolve,
        );
        assert_eq!(TEST_SCALAR.get(), before + 10);
    }

    #[test]
    fn forget_worker_resets_its_delta_baseline() {
        let _guard = SNAPSHOT_TEST_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        reset_generic_counter_snapshot_for_test();

        static TEST_VEC: Lazy<IntCounterVec> = Lazy::new(|| {
            register_int_counter_vec(
                "metrics_unit_forget_total",
                "forget unit test",
                &["route_id"],
            )
        });

        fn resolve(name: &str) -> Option<(&'static [&'static str], CounterTarget)> {
            match name {
                "lorica_metrics_unit_forget_total" => {
                    Some((&["route_id"], CounterTarget::Vec(&TEST_VEC)))
                }
                _ => None,
            }
        }

        let entry = |value: u64| {
            vec![(
                "lorica_metrics_unit_forget_total".to_string(),
                vec![("route_id".to_string(), "fgt".to_string())],
                value,
            )]
        };

        let base = TEST_VEC.with_label_values(&["fgt"]).get();

        // Worker 1 reports 5 -> +5 against the base.
        apply_worker_generic_counters(1, &entry(5), resolve);
        assert_eq!(TEST_VEC.with_label_values(&["fgt"]).get(), base + 5);

        // A smaller follow-up (3 < 5) from the same worker is swallowed as a
        // regression, proving the retained baseline is still 5.
        apply_worker_generic_counters(1, &entry(3), resolve);
        assert_eq!(TEST_VEC.with_label_values(&["fgt"]).get(), base + 5);

        // Forgetting the (dead) worker drops its snapshot, so the same worker
        // id reporting 3 again now applies as a fresh delta from zero.
        forget_worker_generic_counters(1);
        apply_worker_generic_counters(1, &entry(3), resolve);
        assert_eq!(TEST_VEC.with_label_values(&["fgt"]).get(), base + 8);
    }

    /// A gauge over a vec of its own, outside the shared registry, so
    /// each test owns its state.
    fn aggregated(aggregation: GaugeAggregation) -> AggregatedGauge {
        const NAME: &str = "metrics_unit_aggregated";
        let opts = prometheus::Opts::new(NAME, "aggregated gauge unit test").namespace(NAMESPACE);
        let vec = IntGaugeVec::new(opts, &["sink"]).expect("a valid definition");
        AggregatedGauge::with_gauge(NAME, vec, &["sink"], aggregation)
    }

    /// The rendered value of `gauge` for `sink`, `None` without a series.
    fn rendered(gauge: &AggregatedGauge, sink: &str) -> Option<i64> {
        gauge
            .gauge
            .collect()
            .iter()
            .flat_map(|family| family.get_metric())
            .find(|m| m.get_label().iter().any(|l| l.value() == sink))
            .map(|m| m.get_gauge().value() as i64)
    }

    /// What worker `value` would ship for `sink`, through the snapshot a
    /// real worker builds, so the wire shape is the one under test.
    fn report(sink: &str, value: i64) -> Vec<GenericCounterTuple> {
        let worker = aggregated(GaugeAggregation::Min);
        worker.set_local(&[sink], value);
        worker.snapshot_local()
    }

    #[test]
    fn combine_follows_each_aggregation_and_is_none_without_a_value() {
        assert_eq!(GaugeAggregation::Min.combine([1, 0, 1]), Some(0));
        assert_eq!(GaugeAggregation::Max.combine([1, 0, 1]), Some(1));
        assert_eq!(GaugeAggregation::Sum.combine([1, 0, 1]), Some(2));
        assert_eq!(GaugeAggregation::Min.combine(std::iter::empty()), None);
    }

    #[test]
    fn min_reads_down_as_soon_as_one_process_is_down() {
        let gauge = aggregated(GaugeAggregation::Min);
        gauge.set_local(&["syslog"], 1);
        gauge.apply_worker(1, &report("syslog", 1));
        assert_eq!(rendered(&gauge, "syslog"), Some(1));
        gauge.apply_worker(2, &report("syslog", 0));
        assert_eq!(rendered(&gauge, "syslog"), Some(0));
        gauge.apply_worker(2, &report("syslog", 1));
        assert_eq!(rendered(&gauge, "syslog"), Some(1));
        gauge.set_local(&["syslog"], 0);
        assert_eq!(
            rendered(&gauge, "syslog"),
            Some(0),
            "the local value counts"
        );
    }

    #[test]
    fn a_dead_worker_value_stands_for_a_state_and_leaves_for_a_share() {
        let state = aggregated(GaugeAggregation::Min);
        state.set_local(&["syslog"], 1);
        state.apply_worker(3, &report("syslog", 0));
        state.forget_worker(3);
        assert_eq!(rendered(&state, "syslog"), Some(0), "stands until replaced");
        state.apply_worker(3, &report("syslog", 1));
        assert_eq!(
            rendered(&state, "syslog"),
            Some(1),
            "the replacement reports"
        );

        let share = aggregated(GaugeAggregation::Sum);
        share.apply_worker(1, &report("syslog", 4));
        share.apply_worker(2, &report("syslog", 3));
        assert_eq!(rendered(&share, "syslog"), Some(7));
        share.forget_worker(2);
        assert_eq!(rendered(&share, "syslog"), Some(4));
    }

    #[test]
    fn a_label_set_no_process_holds_is_removed() {
        let gauge = aggregated(GaugeAggregation::Min);
        gauge.set_local(&["otlp"], 1);
        gauge.apply_worker(1, &report("syslog", 1));
        assert_eq!(rendered(&gauge, "syslog"), Some(1));
        gauge.apply_worker(1, &[]);
        assert_eq!(
            rendered(&gauge, "syslog"),
            None,
            "the worker no longer has it"
        );
        gauge.clear_local(&["otlp"]);
        assert_eq!(rendered(&gauge, "otlp"), None);
    }

    #[test]
    fn a_report_carries_zeros_and_ignores_other_names_and_partial_labels() {
        assert_eq!(
            report("syslog", 0),
            vec![(
                "lorica_metrics_unit_aggregated".to_string(),
                vec![("sink".to_string(), "syslog".to_string())],
                0
            )]
        );
        let gauge = aggregated(GaugeAggregation::Max);
        let mut entries = report("syslog", 1);
        entries.push(("lorica_other".to_string(), Vec::new(), 9));
        entries.push(("lorica_metrics_unit_aggregated".to_string(), Vec::new(), 9));
        gauge.apply_worker(1, &entries);
        assert_eq!(rendered(&gauge, "syslog"), Some(1));
        assert_eq!(gauge.gauge.collect()[0].get_metric().len(), 1);
    }
}
