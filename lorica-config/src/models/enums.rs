use serde::{Deserialize, Serialize};
use strum::{EnumString, IntoStaticStr};

// --- Enums ---
//
// Each enum below derives `strum::EnumString` (provides `FromStr`) and
// `strum::IntoStaticStr` (provides `impl From<&Self> for &'static str`),
// with `#[strum(serialize_all = "snake_case")]` matching the existing
// on-the-wire and on-disk representation. Callers use the
// `as_str(&self) -> &'static str` accessor defined on each enum, which
// simply delegates to the strum derive.
//
// Strum's `FromStr::Err` is `strum::ParseError`; callers that feed this
// into `ConfigError::Validation` need `.map_err(|e| ConfigError::
// Validation(e.to_string()))`, which is already the pattern.

/// Backend selection strategy for a route's pool of upstream backends.
///
/// Used by [`Route::load_balancing`] and consumed by the proxy's load balancer.
/// Parsed from snake_case strings via `FromStr`; an unknown variant produces
/// a `strum::ParseError` that callers wrap into `ConfigError::Validation`.
///
/// [`Route::load_balancing`]: super::route::Route::load_balancing
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, EnumString, IntoStaticStr)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum LoadBalancing {
    /// Rotate through backends in declaration order.
    RoundRobin,
    /// Hash the client IP (or a configured key) to a backend for
    /// session stickiness.
    ConsistentHash,
    /// Pick uniformly at random on each request.
    Random,
    /// Peak EWMA: pick the backend with the lowest exponentially-weighted
    /// moving average of recent response latencies.
    PeakEwma,
    /// Least active in-flight connections at selection time.
    LeastConn,
}

impl LoadBalancing {
    /// Snake_case wire representation of the variant (matches the
    /// `serde` and `FromStr` form).
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// WAF enforcement mode for a route. `Detection` logs hits but lets the
/// request through; `Blocking` denies the request with a 403.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, EnumString, IntoStaticStr)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum WafMode {
    /// Log rule hits without rejecting the request.
    Detection,
    /// Reject matching requests with 403.
    Blocking,
}

impl WafMode {
    /// Snake_case wire representation of the variant (matches the
    /// `serde` and `FromStr` form).
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// Last observed health probe outcome for a backend. `Unknown` is the
/// pre-probe / probing-disabled default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, EnumString, IntoStaticStr)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum HealthStatus {
    /// Probe succeeded on the last cycle.
    Healthy,
    /// Last cycle intermittent (soft fail, not yet fully down).
    Degraded,
    /// Probe failed on the last cycle past the fail threshold.
    Down,
    /// No probe has run yet (startup) or probing is disabled.
    Unknown,
}

impl HealthStatus {
    /// Snake_case wire representation of the variant (matches the
    /// `serde` and `FromStr` form).
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// Backend rotation state used for graceful drains.
///
/// - `Normal`: receives new connections.
/// - `Closing`: drained by the load balancer; existing connections finish
///   but no new traffic is sent.
/// - `Closed`: fully out of rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, EnumString, IntoStaticStr)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum LifecycleState {
    /// Accepts new connections normally.
    Normal,
    /// Draining : existing connections finish, new ones go elsewhere.
    Closing,
    /// Fully out of rotation.
    Closed,
}

impl LifecycleState {
    /// Snake_case wire representation of the variant (matches the
    /// `serde` and `FromStr` form).
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// Transport for an alert sent by a [`NotificationConfig`].
///
/// [`NotificationConfig`]: super::notification::NotificationConfig
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, EnumString, IntoStaticStr)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum NotificationChannel {
    /// SMTP email (settings carry the host + from / to addresses).
    Email,
    /// Generic HTTP POST to an operator-configured URL.
    Webhook,
    /// Slack-flavoured webhook (incoming webhook URL + payload shape).
    Slack,
}

impl NotificationChannel {
    /// Snake_case wire representation of the variant (matches the
    /// `serde` and `FromStr` form).
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// Tri-state value persisted in [`UserPreference`] for "always / never /
/// once" UI dialogs (e.g. "show this tip again?").
///
/// [`UserPreference`]: super::preferences::UserPreference
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, EnumString, IntoStaticStr)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum PreferenceValue {
    /// User opted out permanently.
    Never,
    /// User opted in permanently.
    Always,
    /// Remember the decision for the current session only.
    Once,
}

impl PreferenceValue {
    /// Snake_case wire representation of the variant (matches the
    /// `serde` and `FromStr` form).
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// Match semantics for a [`PathRule`]. `Prefix` matches when the request
/// path starts with the rule's `path`; `Exact` requires equality.
///
/// [`PathRule`]: super::route::PathRule
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, EnumString, IntoStaticStr,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum PathMatchType {
    /// Request path starts with the rule's `path` value.
    #[default]
    Prefix,
    /// Request path equals the rule's `path` value.
    Exact,
}

impl PathMatchType {
    /// Snake_case wire representation of the variant (matches the
    /// `serde` and `FromStr` form).
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// Match semantics for a [`HeaderRule`].
///
/// `Regex` is compiled at route-load time; a malformed regex produces a
/// warning and disables the rule rather than failing the whole reload.
///
/// [`HeaderRule`]: super::route::HeaderRule
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, EnumString, IntoStaticStr,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum HeaderMatchType {
    /// Header value equals the rule's `value`.
    #[default]
    Exact,
    /// Header value starts with the rule's `value`.
    Prefix,
    /// Rule's `value` is compiled as a regex and matched.
    Regex,
}

impl HeaderMatchType {
    /// Snake_case wire representation of the variant (matches the
    /// `serde` and `FromStr` form).
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}
