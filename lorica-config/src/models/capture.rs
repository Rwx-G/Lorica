//! Traffic-capture rules (Story 10.1): the operator-facing description
//! of which requests a node records, how much of them it keeps, and for
//! how long.
//!
//! The model lives here and nowhere else. It is written by the
//! management API, stored in `capture_rules`, projected into the
//! canonical blob as [`CanonicalCaptureRule`], and read by the proxy in
//! a later slice. Every limit in it is an operator-facing dial with a
//! hard cap this module owns: a capture rule is the one configuration
//! object that deliberately records request and response bodies, so an
//! unbounded one is a disk-fill and a disclosure at the same time.
//!
//! [`CanonicalCaptureRule`]: crate::canonical::CanonicalCaptureRule

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::enums::HeaderMatchType;

/// Hard cap on [`CaptureScope::request_body_max_bytes`] and
/// [`CaptureScope::response_body_max_bytes`]. A capture holds the
/// buffered body in memory before it reaches disk, so the ceiling is
/// what bounds one in-flight capture's footprint.
pub const CAPTURE_BODY_MAX_BYTES_CAP: u32 = 4 * 1024 * 1024;

/// Hard cap on [`CaptureLimits::max_captures`]. Past this a rule is a
/// standing recorder rather than a diagnostic, which is a different
/// feature with different retention obligations.
pub const CAPTURE_MAX_CAPTURES_CAP: u32 = 10_000;

/// Hard cap on [`CaptureLimits::rate_per_minute`], the same number as
/// [`CAPTURE_MAX_CAPTURES_CAP`] because a rule cannot emit more than its
/// total anyway; a separate number would only be a second thing to
/// reason about. Zero is refused rather than read as unlimited: a rule
/// that can never emit is what `enabled = false` is for, and accepting
/// it here produces a rule that looks armed and is not.
pub const CAPTURE_RATE_PER_MINUTE_CAP: u32 = 10_000;

/// Hard cap on [`CaptureLimits::ttl_seconds`]: seven days. Captured
/// bodies carry whatever the client sent, credentials included, so the
/// retention ceiling is a policy limit and not a tuning knob.
pub const CAPTURE_TTL_SECONDS_CAP: u32 = 7 * 24 * 60 * 60;

/// Byte ceiling on any pattern an operator submits in a capture rule
/// ([`CaptureMatch::path_regex`] and the `value` of a
/// [`HeaderMatchType::Regex`] header match).
///
/// It is the same 4 KiB budget `lorica-waf` applies to a custom WAF
/// pattern (`WafEngine::MAX_CUSTOM_PATTERN_LEN`), restated rather than
/// imported: `lorica-config` depends on neither `lorica-waf` nor the
/// `regex` crate, deliberately (see [`super::HeaderRule::matches`]), so
/// it can cap the SOURCE length but cannot compile the pattern to check
/// its compiled size. The compile-time budget
/// (`RegexBuilder::size_limit`) still applies wherever the pattern is
/// actually built, in the crate that owns the matcher.
pub const CAPTURE_PATTERN_MAX_LEN: usize = 4 * 1024;

/// Byte ceiling on [`CaptureRule::name`]. The name is a label a
/// dashboard column and an audit line both render verbatim, so it is
/// bounded for the same reason any other operator-supplied string is.
pub const CAPTURE_NAME_MAX_LEN: usize = 200;

/// Byte ceiling on [`CaptureMatch::path_prefix`]. It is compared
/// against a request target, and a prefix longer than the longest target
/// the proxy will ever accept cannot match anything.
pub const CAPTURE_PATH_PREFIX_MAX_LEN: usize = 2048;

/// Hard cap on [`CaptureOutput::max_dir_bytes`]: 10 GiB. The field is
/// the only thing that makes the writer prune, so an uncapped value is
/// "never prune" on a node whose main job is serving traffic.
pub const CAPTURE_MAX_DIR_BYTES_CAP: u64 = 10 * 1024 * 1024 * 1024;

/// Cap on how many names one [`CaptureRedaction`] list may carry. The
/// writer walks both lists per captured header and per captured query
/// parameter, so the list length is a per-capture cost.
pub const CAPTURE_REDACT_MAX_ENTRIES: usize = 64;

/// Byte ceiling on one [`CaptureRedaction`] entry. Both lists hold
/// names, and a name longer than this is not one.
pub const CAPTURE_REDACT_ENTRY_MAX_LEN: usize = 128;

/// Default body ceiling for both directions: 64 KiB, enough for an API
/// request or an error page without holding a file upload.
pub const CAPTURE_DEFAULT_BODY_MAX_BYTES: u32 = 64 * 1024;

/// Default cap on how many captures one rule produces before it stops.
pub const CAPTURE_DEFAULT_MAX_CAPTURES: u32 = 100;

/// Default per-minute capture rate, so a rule on a busy route degrades
/// into a sample instead of a firehose.
pub const CAPTURE_DEFAULT_RATE_PER_MINUTE: u32 = 10;

/// Default capture retention: one hour.
pub const CAPTURE_DEFAULT_TTL_SECONDS: u32 = 3600;

fn default_body_max_bytes() -> u32 {
    CAPTURE_DEFAULT_BODY_MAX_BYTES
}

fn default_true() -> bool {
    true
}

fn default_max_captures() -> u32 {
    CAPTURE_DEFAULT_MAX_CAPTURES
}

fn default_rate_per_minute() -> u32 {
    CAPTURE_DEFAULT_RATE_PER_MINUTE
}

fn default_ttl_seconds() -> u32 {
    CAPTURE_DEFAULT_TTL_SECONDS
}

/// One header predicate in a [`CaptureMatch`].
///
/// Carries the same [`HeaderMatchType`] semantics a [`super::HeaderRule`]
/// uses, so an operator who knows how a route matches a header knows how
/// a capture rule does. It is a separate struct only because
/// `HeaderRule` also carries `backend_ids`, which has no meaning here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct HeaderMatch {
    /// HTTP header name to test (matched case-insensitively).
    pub name: String,
    /// Exact / prefix / regex semantics for `value`.
    #[serde(default)]
    pub match_type: HeaderMatchType,
    /// Literal string, or regex source when `match_type = Regex`.
    pub value: String,
}

/// Which HTTP statuses make a response worth emitting.
///
/// `ClientAborted` is 499 specifically and not part of `ClientError`:
/// it is not a status any upstream returns, it is the marker for a
/// client that hung up mid-response, and an operator hunting a timeout
/// wants it without every 404 on the route coming along.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusMatch {
    /// One exact status code.
    Exact(u16),
    /// Any 4xx except the 499 client-abort marker.
    ClientError,
    /// Any 5xx.
    ServerError,
    /// The 499 client-abort marker.
    ClientAborted,
}

impl StatusMatch {
    /// Whether `status` satisfies this predicate.
    ///
    /// ```
    /// use lorica_config::models::StatusMatch;
    /// assert!(StatusMatch::ServerError.matches(503));
    /// assert!(StatusMatch::ClientError.matches(404));
    /// assert!(!StatusMatch::ClientError.matches(499));
    /// assert!(StatusMatch::ClientAborted.matches(499));
    /// ```
    pub fn matches(&self, status: u16) -> bool {
        match self {
            StatusMatch::Exact(code) => *code == status,
            StatusMatch::ClientError => (400..500).contains(&status) && status != 499,
            StatusMatch::ServerError => (500..600).contains(&status),
            StatusMatch::ClientAborted => status == 499,
        }
    }
}

/// Which requests a rule considers at all. Every populated field
/// narrows; an empty [`CaptureMatch`] considers every request on the
/// rule's route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CaptureMatch {
    /// Client source addresses, as CIDRs or bare IPs. Empty = any.
    #[serde(default)]
    pub source_cidrs: Vec<String>,
    /// Uppercase HTTP methods. Empty = any.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Request path prefix. `None` = any.
    #[serde(default)]
    pub path_prefix: Option<String>,
    /// Regex over the request path. `None` = any.
    #[serde(default)]
    pub path_regex: Option<String>,
    /// Header predicates, all of which must hold. Empty = any.
    #[serde(default)]
    pub headers: Vec<HeaderMatch>,
}

/// Which of the considered requests are actually written out. A rule
/// matches far more traffic than it should record, so this is the
/// second gate and the one that keeps a capture rule cheap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CaptureEmit {
    /// Emit every matched request, unconditionally.
    #[serde(default)]
    pub always: bool,
    /// Emit when the response status satisfies any of these.
    #[serde(default)]
    pub status: Vec<StatusMatch>,
    /// Emit when the response took at least this many milliseconds.
    #[serde(default)]
    pub min_latency_ms: Option<u64>,
    /// Emit when the upstream failed to produce a response at all
    /// (connect, read or TLS failure).
    #[serde(default)]
    pub upstream_error: bool,
}

/// How much of a captured exchange is kept. Headers and the request
/// line are always kept; the bodies are the expensive, sensitive part
/// and each direction is independently bounded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureScope {
    /// Whether the request body is kept.
    #[serde(default = "default_true")]
    pub request_body: bool,
    /// Whether the response body is kept.
    #[serde(default = "default_true")]
    pub response_body: bool,
    /// Ceiling on the kept request body, in bytes. Capped by
    /// [`CAPTURE_BODY_MAX_BYTES_CAP`].
    #[serde(default = "default_body_max_bytes")]
    pub request_body_max_bytes: u32,
    /// Ceiling on the kept response body, in bytes. Capped by
    /// [`CAPTURE_BODY_MAX_BYTES_CAP`].
    #[serde(default = "default_body_max_bytes")]
    pub response_body_max_bytes: u32,
}

impl Default for CaptureScope {
    fn default() -> Self {
        Self {
            request_body: true,
            response_body: true,
            request_body_max_bytes: CAPTURE_DEFAULT_BODY_MAX_BYTES,
            response_body_max_bytes: CAPTURE_DEFAULT_BODY_MAX_BYTES,
        }
    }
}

/// What stops a rule: a total, a rate, and a clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureLimits {
    /// Captures this rule may emit before it stops. Capped by
    /// [`CAPTURE_MAX_CAPTURES_CAP`].
    #[serde(default = "default_max_captures")]
    pub max_captures: u32,
    /// Captures this rule may emit per minute. Non-zero, and capped
    /// by [`CAPTURE_RATE_PER_MINUTE_CAP`].
    #[serde(default = "default_rate_per_minute")]
    pub rate_per_minute: u32,
    /// How long a written capture is retained, in seconds. Capped by
    /// [`CAPTURE_TTL_SECONDS_CAP`].
    #[serde(default = "default_ttl_seconds")]
    pub ttl_seconds: u32,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        Self {
            max_captures: CAPTURE_DEFAULT_MAX_CAPTURES,
            rate_per_minute: CAPTURE_DEFAULT_RATE_PER_MINUTE,
            ttl_seconds: CAPTURE_DEFAULT_TTL_SECONDS,
        }
    }
}

/// Where captures land. Both fields are `None` by default, meaning the
/// node's own capture directory and its own size budget, which are
/// node-local facts and deliberately not part of this model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CaptureOutput {
    /// Override directory for this rule's captures. Absolute, with no
    /// `..` component.
    #[serde(default)]
    pub dir: Option<String>,
    /// Override size budget for that directory, in bytes. Capped by
    /// [`CAPTURE_MAX_DIR_BYTES_CAP`].
    #[serde(default)]
    pub max_dir_bytes: Option<u64>,
}

/// Additional names to redact in a capture.
///
/// This EXTENDS the always-redacted set the capture writer applies
/// (`Authorization`, `Cookie`, `Set-Cookie` and the rest); it never
/// replaces it. An empty redaction block therefore still produces a
/// redacted capture, which is the only safe default for a feature whose
/// output is a verbatim copy of production traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CaptureRedaction {
    /// Extra header names to redact, case-insensitive.
    #[serde(default)]
    pub headers: Vec<String>,
    /// Extra query-parameter names to redact, case-insensitive.
    #[serde(default)]
    pub query: Vec<String>,
}

/// One traffic-capture rule, always bound to exactly one route.
///
/// `route_id` is mandatory and is a foreign key with `ON DELETE
/// CASCADE`: a capture rule describes what to record on one route, so a
/// rule outliving its route would be a recorder pointed at nothing.
///
/// `expires_at` is an absolute UTC instant rather than a duration from
/// creation, so every node in the fleet stops the same rule at the same
/// moment regardless of when its own copy of the configuration landed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureRule {
    /// Stable UUID; primary key of the `capture_rules` table.
    pub id: String,
    /// Operator-facing label.
    pub name: String,
    /// `Route.id` this rule records. Mandatory.
    pub route_id: String,
    /// Whether the rule is currently recording.
    pub enabled: bool,
    /// Which requests the rule considers.
    #[serde(rename = "match")]
    pub match_: CaptureMatch,
    /// Which of those are written out.
    pub emit: CaptureEmit,
    /// How much of each exchange is kept.
    pub capture: CaptureScope,
    /// What stops the rule.
    pub limits: CaptureLimits,
    /// Where captures land.
    pub output: CaptureOutput,
    /// Names redacted on top of the always-redacted set.
    pub redact: CaptureRedaction,
    /// Username of the operator who created the rule.
    pub created_by: String,
    /// Insert timestamp.
    pub created_at: DateTime<Utc>,
    /// Absolute UTC instant after which the rule records nothing.
    pub expires_at: DateTime<Utc>,
    /// Captures this node's process has emitted for this rule.
    pub captures_emitted: i64,
    /// Captures this node's process has dropped (rate, total, or size).
    pub captures_dropped: i64,
}

impl CaptureRule {
    /// Validate every operator-supplied field against the caps and the
    /// consistency rules this module owns.
    ///
    /// Returns a human-readable message describing the first violated
    /// rule, suitable for a `400 Bad Request` body, the same shape as
    /// [`super::Route::validate_node_selector`].
    ///
    /// # Errors
    ///
    /// Returns `Err` when `route_id` is empty, when `name` is blank or
    /// over [`CAPTURE_NAME_MAX_LEN`], when `emit` constrains nothing,
    /// when `emit.always` is combined with another predicate, when any
    /// capped limit is zero or over its cap, when a pattern exceeds
    /// [`CAPTURE_PATTERN_MAX_LEN`], when a source CIDR does not parse,
    /// when a method is not an uppercase HTTP token, when a header
    /// predicate names something that is not a legal header token, when
    /// `match.path_prefix` does not start with `/` or exceeds
    /// [`CAPTURE_PATH_PREFIX_MAX_LEN`], when `output.dir` is relative or
    /// carries a `..` component, when `output.max_dir_bytes` is zero or
    /// over [`CAPTURE_MAX_DIR_BYTES_CAP`], or when a redaction list is
    /// longer than [`CAPTURE_REDACT_MAX_ENTRIES`] or holds an entry that
    /// is empty, over [`CAPTURE_REDACT_ENTRY_MAX_LEN`], or (for headers)
    /// not a legal header token.
    ///
    /// ```
    /// use lorica_config::models::CaptureRule;
    /// # fn demo(mut rule: CaptureRule) {
    /// rule.emit.always = true;
    /// rule.emit.upstream_error = true;
    /// // Silently ignoring `upstream_error` under an unconditional
    /// // `always` would hide the operator's real intent.
    /// assert!(rule.validate().is_err());
    /// # }
    /// ```
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("capture rule must carry a name".to_string());
        }
        if self.name.len() > CAPTURE_NAME_MAX_LEN {
            return Err(format!("name exceeds {CAPTURE_NAME_MAX_LEN} bytes"));
        }
        if self.route_id.is_empty() {
            return Err("capture rule must name the route it records (route_id)".to_string());
        }
        self.validate_emit()?;
        self.validate_limits()?;
        self.validate_match()?;
        self.validate_output()?;
        self.validate_redaction()?;
        Ok(())
    }

    /// The emit block must both constrain something and not contradict
    /// itself.
    fn validate_emit(&self) -> Result<(), String> {
        let has_predicate = !self.emit.status.is_empty()
            || self.emit.min_latency_ms.is_some()
            || self.emit.upstream_error;
        if !self.emit.always && !has_predicate {
            return Err(
                "a rule with no emit condition must set `emit.always` explicitly".to_string(),
            );
        }
        if self.emit.always && has_predicate {
            return Err(
                "`emit.always` records every matched request, so it cannot be combined with \
                 `emit.status`, `emit.min_latency_ms` or `emit.upstream_error`"
                    .to_string(),
            );
        }
        Ok(())
    }

    /// Every capped dial: non-zero, and at or under its hard cap.
    fn validate_limits(&self) -> Result<(), String> {
        check_cap(
            self.capture.request_body_max_bytes,
            CAPTURE_BODY_MAX_BYTES_CAP,
            "capture.request_body_max_bytes",
        )?;
        check_cap(
            self.capture.response_body_max_bytes,
            CAPTURE_BODY_MAX_BYTES_CAP,
            "capture.response_body_max_bytes",
        )?;
        check_cap(
            self.limits.max_captures,
            CAPTURE_MAX_CAPTURES_CAP,
            "limits.max_captures",
        )?;
        check_cap(
            self.limits.rate_per_minute,
            CAPTURE_RATE_PER_MINUTE_CAP,
            "limits.rate_per_minute",
        )?;
        check_cap(
            self.limits.ttl_seconds,
            CAPTURE_TTL_SECONDS_CAP,
            "limits.ttl_seconds",
        )?;
        Ok(())
    }

    /// Source CIDRs, methods, header names and pattern sizes.
    fn validate_match(&self) -> Result<(), String> {
        for cidr in &self.match_.source_cidrs {
            validate_cidr(cidr, "match.source_cidrs")?;
        }
        for method in &self.match_.methods {
            if !is_uppercase_http_method(method) {
                return Err(format!(
                    "`{method}` is not a valid uppercase HTTP method in match.methods"
                ));
            }
        }
        if let Some(prefix) = &self.match_.path_prefix {
            // A prefix is compared against a request target, which always
            // begins at the root. One that does not is a predicate no
            // request can satisfy, and a rule that records nothing while
            // the dashboard shows it armed is the worst outcome here.
            if !prefix.starts_with('/') {
                return Err(format!(
                    "`{prefix}` cannot match a request target in match.path_prefix: a path \
                     prefix starts with `/`"
                ));
            }
            if prefix.len() > CAPTURE_PATH_PREFIX_MAX_LEN {
                return Err(format!(
                    "match.path_prefix exceeds {CAPTURE_PATH_PREFIX_MAX_LEN} bytes"
                ));
            }
        }
        if let Some(pattern) = &self.match_.path_regex {
            check_pattern_len(pattern, "match.path_regex")?;
        }
        for header in &self.match_.headers {
            check_header_name(&header.name, "match.headers[].name")?;
            if header.match_type == HeaderMatchType::Regex {
                check_pattern_len(&header.value, "match.headers[].value")?;
            }
        }
        Ok(())
    }

    /// The output override: an absolute directory with no traversal, and
    /// a bounded size budget.
    ///
    /// Whether that directory EXISTS and is writable is the capture
    /// writer's business at capture time (Story 10.2), not this
    /// validator's. A rule is replicated to every node the route lives
    /// on, and a node that has not created the directory yet does not
    /// make the rule invalid; a validator that touched the filesystem
    /// would refuse it there and accept it here.
    fn validate_output(&self) -> Result<(), String> {
        if let Some(dir) = &self.output.dir {
            // The runtime target is Linux, so an absolute path is a
            // leading `/`. `Path::is_absolute` would answer differently
            // for the same operator input when the crate is compiled on
            // a Windows development host.
            if !dir.starts_with('/') {
                return Err(format!(
                    "`{dir}` is not absolute in output.dir: a relative directory resolves \
                     against whatever working directory the node process happens to have"
                ));
            }
            if dir.split('/').any(|component| component == "..") {
                return Err(format!(
                    "`{dir}` contains a `..` component in output.dir, which makes the \
                     configured directory a different one from the directory written to"
                ));
            }
        }
        if let Some(budget) = self.output.max_dir_bytes {
            if budget == 0 {
                return Err("output.max_dir_bytes must be greater than zero".to_string());
            }
            if budget > CAPTURE_MAX_DIR_BYTES_CAP {
                return Err(format!(
                    "output.max_dir_bytes may not exceed {CAPTURE_MAX_DIR_BYTES_CAP}"
                ));
            }
        }
        Ok(())
    }

    /// Both redaction lists: bounded, non-empty entries, and header
    /// names that a request can actually carry.
    fn validate_redaction(&self) -> Result<(), String> {
        check_redaction_list(&self.redact.headers, "redact.headers")?;
        for name in &self.redact.headers {
            // A malformed name redacts nothing while reading, in the
            // dashboard and in the rule itself, as though it does. An
            // operator who believes a header is redacted and is wrong is
            // worse off than one who knows it is not.
            check_header_name(name, "redact.headers[]")?;
        }
        check_redaction_list(&self.redact.query, "redact.query")?;
        Ok(())
    }
}

/// One capped dial: non-zero and at or under `cap`.
fn check_cap(value: u32, cap: u32, field: &str) -> Result<(), String> {
    if value == 0 {
        return Err(format!("{field} must be greater than zero"));
    }
    if value > cap {
        return Err(format!("{field} may not exceed {cap}"));
    }
    Ok(())
}

/// Source-length budget for an operator-supplied pattern.
fn check_pattern_len(pattern: &str, field: &str) -> Result<(), String> {
    if pattern.len() > CAPTURE_PATTERN_MAX_LEN {
        return Err(format!("{field} exceeds {CAPTURE_PATTERN_MAX_LEN} bytes"));
    }
    Ok(())
}

/// One redaction list: how many names it may hold, and how long each
/// one may be. `field` names the list in the error message.
fn check_redaction_list(entries: &[String], field: &str) -> Result<(), String> {
    if entries.len() > CAPTURE_REDACT_MAX_ENTRIES {
        return Err(format!(
            "{field} may not list more than {CAPTURE_REDACT_MAX_ENTRIES} names"
        ));
    }
    for entry in entries {
        if entry.trim().is_empty() {
            return Err(format!("{field} may not contain an empty name"));
        }
        if entry.len() > CAPTURE_REDACT_ENTRY_MAX_LEN {
            return Err(format!(
                "`{entry}` exceeds {CAPTURE_REDACT_ENTRY_MAX_LEN} bytes in {field}"
            ));
        }
    }
    Ok(())
}

/// An operator-supplied header name, wherever one appears in a capture
/// rule. Anything outside the token grammar is a name no request carries,
/// so both the predicate reading and the redaction reading of such a
/// name are silent no-ops.
fn check_header_name(name: &str, field: &str) -> Result<(), String> {
    if !is_http_token(name) {
        return Err(format!(
            "`{name}` is not a valid HTTP header name in {field}"
        ));
    }
    Ok(())
}

/// Accept a CIDR (`10.0.0.0/8`, `2001:db8::/32`) or a bare address,
/// which is what the connection filter accepts for the same kind of
/// list. `field` names the list in the error message.
///
/// `lorica-config` has no `ipnet` dependency and gains none for this,
/// so the check is built on `std::net::IpAddr` plus an explicit prefix
/// bound: it accepts exactly the same shapes `ipnet` does for these two
/// families, and rejects strictly more (an `ipnet` parse tolerates host
/// bits set, which is fine to keep, but nothing looser).
///
/// Visible to the whole `models` module: every operator-supplied
/// address list in the crate answers to this one definition, so an
/// operator who learns what Lorica accepts learns it once.
pub(super) fn validate_cidr(entry: &str, field: &str) -> Result<(), String> {
    let trimmed = entry.trim();
    let invalid = || format!("`{entry}` is not a valid IP or CIDR in {field}");
    let (addr, prefix) = match trimmed.split_once('/') {
        Some((addr, prefix)) => (addr, Some(prefix)),
        None => (trimmed, None),
    };
    let ip: IpAddr = addr.parse().map_err(|_| invalid())?;
    let Some(prefix) = prefix else {
        return Ok(());
    };
    let bits: u8 = prefix.parse().map_err(|_| invalid())?;
    let max_bits = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if bits > max_bits {
        return Err(invalid());
    }
    Ok(())
}

/// A non-empty RFC 9110 section 5.6.2 `token`: ASCII letters, digits,
/// and the fifteen `tchar` punctuation marks. Method names and header
/// names are both this grammar, so they answer to one definition here.
fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '!' | '#'
                        | '$'
                        | '%'
                        | '&'
                        | '\''
                        | '*'
                        | '+'
                        | '-'
                        | '.'
                        | '^'
                        | '_'
                        | '`'
                        | '|'
                        | '~'
                )
        })
}

/// An RFC 9110 method token with no lowercase letters. The uppercase
/// requirement is ours: the proxy compares methods verbatim, so a rule
/// written `get` would match nothing and look like a broken feature.
fn is_uppercase_http_method(method: &str) -> bool {
    is_http_token(method) && !method.chars().any(|c| c.is_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rule that validates, so each test below changes exactly one
    /// thing and the failure it asserts is the thing it changed.
    fn valid_rule() -> CaptureRule {
        CaptureRule {
            id: "cap-1".to_string(),
            name: "checkout 5xx".to_string(),
            route_id: "route-1".to_string(),
            enabled: true,
            match_: CaptureMatch::default(),
            emit: CaptureEmit {
                always: false,
                status: vec![StatusMatch::ServerError],
                min_latency_ms: None,
                upstream_error: false,
            },
            capture: CaptureScope::default(),
            limits: CaptureLimits::default(),
            output: CaptureOutput::default(),
            redact: CaptureRedaction::default(),
            created_by: "admin".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now(),
            captures_emitted: 0,
            captures_dropped: 0,
        }
    }

    #[test]
    fn a_rule_with_a_status_predicate_validates() {
        assert!(valid_rule().validate().is_ok());
    }

    #[test]
    fn a_rule_without_a_route_is_refused() {
        let mut rule = valid_rule();
        rule.route_id = String::new();
        let err = rule.validate().expect_err("empty route_id must be refused");
        assert!(err.contains("route_id"), "{err}");
    }

    #[test]
    fn a_rule_with_no_emit_condition_is_refused_and_told_to_set_always() {
        let mut rule = valid_rule();
        rule.emit = CaptureEmit::default();
        let err = rule
            .validate()
            .expect_err("an unconstrained emit is refused");
        assert!(err.contains("emit.always"), "{err}");
    }

    #[test]
    fn always_combined_with_a_status_predicate_is_refused() {
        let mut rule = valid_rule();
        rule.emit.always = true;
        let err = rule.validate().expect_err("always plus status is refused");
        assert!(err.contains("emit.always"), "{err}");
    }

    #[test]
    fn always_combined_with_a_latency_predicate_is_refused() {
        let mut rule = valid_rule();
        rule.emit.always = true;
        rule.emit.status.clear();
        rule.emit.min_latency_ms = Some(250);
        assert!(rule.validate().is_err());
    }

    #[test]
    fn always_combined_with_upstream_error_is_refused() {
        let mut rule = valid_rule();
        rule.emit.always = true;
        rule.emit.status.clear();
        rule.emit.upstream_error = true;
        assert!(rule.validate().is_err());
    }

    #[test]
    fn a_request_body_ceiling_over_the_hard_cap_is_refused() {
        let mut rule = valid_rule();
        rule.capture.request_body_max_bytes = CAPTURE_BODY_MAX_BYTES_CAP + 1;
        let err = rule.validate().expect_err("over the cap");
        assert!(err.contains("request_body_max_bytes"), "{err}");
    }

    #[test]
    fn a_response_body_ceiling_over_the_hard_cap_is_refused() {
        let mut rule = valid_rule();
        rule.capture.response_body_max_bytes = CAPTURE_BODY_MAX_BYTES_CAP + 1;
        assert!(rule.validate().is_err());
    }

    #[test]
    fn a_zero_body_ceiling_is_refused() {
        let mut rule = valid_rule();
        rule.capture.request_body_max_bytes = 0;
        assert!(rule.validate().is_err());
    }

    #[test]
    fn a_max_captures_over_the_hard_cap_is_refused() {
        let mut rule = valid_rule();
        rule.limits.max_captures = CAPTURE_MAX_CAPTURES_CAP + 1;
        assert!(rule.validate().is_err());
    }

    #[test]
    fn a_rate_per_minute_over_the_hard_cap_is_refused() {
        let mut rule = valid_rule();
        rule.limits.rate_per_minute = CAPTURE_RATE_PER_MINUTE_CAP + 1;
        assert!(rule.validate().is_err());
    }

    #[test]
    fn a_rate_of_zero_is_refused_rather_than_read_as_unlimited() {
        // A rule that can never emit is what `enabled = false` says.
        // Accepting it here would leave an operator with a rule the
        // dashboard shows as armed and that never produces anything.
        let mut rule = valid_rule();
        rule.limits.rate_per_minute = 0;
        let err = rule.validate().expect_err("a zero rate must be refused");
        assert!(err.contains("limits.rate_per_minute"), "{err}");
    }

    #[test]
    fn a_zero_max_captures_is_refused() {
        let mut rule = valid_rule();
        rule.limits.max_captures = 0;
        assert!(rule.validate().is_err());
    }

    #[test]
    fn a_ttl_over_seven_days_is_refused() {
        let mut rule = valid_rule();
        rule.limits.ttl_seconds = CAPTURE_TTL_SECONDS_CAP + 1;
        assert!(rule.validate().is_err());
    }

    #[test]
    fn a_zero_ttl_is_refused() {
        let mut rule = valid_rule();
        rule.limits.ttl_seconds = 0;
        assert!(rule.validate().is_err());
    }

    #[test]
    fn a_path_regex_over_the_pattern_budget_is_refused() {
        let mut rule = valid_rule();
        rule.match_.path_regex = Some("a".repeat(CAPTURE_PATTERN_MAX_LEN + 1));
        let err = rule.validate().expect_err("over the pattern budget");
        assert!(err.contains("path_regex"), "{err}");
    }

    #[test]
    fn a_header_regex_over_the_pattern_budget_is_refused() {
        let mut rule = valid_rule();
        rule.match_.headers = vec![HeaderMatch {
            name: "X-Trace".to_string(),
            match_type: HeaderMatchType::Regex,
            value: "a".repeat(CAPTURE_PATTERN_MAX_LEN + 1),
        }];
        assert!(rule.validate().is_err());
    }

    #[test]
    fn a_long_exact_header_value_is_not_a_pattern_and_is_accepted() {
        // The budget exists to bound regex compilation, not to cap a
        // literal an operator legitimately wants to match.
        let mut rule = valid_rule();
        rule.match_.headers = vec![HeaderMatch {
            name: "X-Trace".to_string(),
            match_type: HeaderMatchType::Exact,
            value: "a".repeat(CAPTURE_PATTERN_MAX_LEN + 1),
        }];
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn a_source_cidr_that_does_not_parse_is_refused() {
        let mut rule = valid_rule();
        rule.match_.source_cidrs = vec!["10.0.0.0/33".to_string()];
        let err = rule.validate().expect_err("a /33 is not a v4 prefix");
        assert!(err.contains("source_cidrs"), "{err}");
    }

    #[test]
    fn every_shape_the_connection_filter_accepts_is_accepted() {
        let mut rule = valid_rule();
        rule.match_.source_cidrs = vec![
            "10.0.0.0/8".to_string(),
            "192.0.2.10".to_string(),
            "2001:db8::/32".to_string(),
            "::1".to_string(),
        ];
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn a_lowercase_method_is_refused() {
        let mut rule = valid_rule();
        rule.match_.methods = vec!["get".to_string()];
        let err = rule.validate().expect_err("lowercase is refused");
        assert!(err.contains("methods"), "{err}");
    }

    #[test]
    fn a_method_with_a_separator_is_refused() {
        let mut rule = valid_rule();
        rule.match_.methods = vec!["GET POST".to_string()];
        assert!(rule.validate().is_err());
    }

    #[test]
    fn uppercase_methods_are_accepted() {
        let mut rule = valid_rule();
        rule.match_.methods = vec!["GET".to_string(), "POST".to_string(), "PATCH".to_string()];
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn a_rule_without_a_name_is_refused() {
        let mut rule = valid_rule();
        rule.name = "   ".to_string();
        let err = rule.validate().expect_err("a blank name must be refused");
        assert!(err.contains("name"), "{err}");
    }

    #[test]
    fn a_name_over_the_length_cap_is_refused() {
        let mut rule = valid_rule();
        rule.name = "a".repeat(CAPTURE_NAME_MAX_LEN + 1);
        assert!(rule.validate().is_err());
    }

    #[test]
    fn a_header_predicate_with_a_malformed_name_is_refused() {
        let mut rule = valid_rule();
        rule.match_.headers = vec![HeaderMatch {
            name: "X Trace".to_string(),
            match_type: HeaderMatchType::Exact,
            value: "abc".to_string(),
        }];
        let err = rule
            .validate()
            .expect_err("a space is not a header token character");
        assert!(err.contains("match.headers[].name"), "{err}");
    }

    #[test]
    fn a_header_predicate_with_an_empty_name_is_refused() {
        let mut rule = valid_rule();
        rule.match_.headers = vec![HeaderMatch::default()];
        assert!(rule.validate().is_err());
    }

    #[test]
    fn a_legal_header_token_is_accepted_as_a_predicate_name() {
        let mut rule = valid_rule();
        rule.match_.headers = vec![HeaderMatch {
            name: "X-Trace_id.v2".to_string(),
            match_type: HeaderMatchType::Exact,
            value: "abc".to_string(),
        }];
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn a_path_prefix_without_a_leading_slash_is_refused() {
        let mut rule = valid_rule();
        rule.match_.path_prefix = Some("checkout".to_string());
        let err = rule
            .validate()
            .expect_err("a prefix that cannot match is refused");
        assert!(err.contains("match.path_prefix"), "{err}");
    }

    #[test]
    fn a_path_prefix_over_the_length_cap_is_refused() {
        let mut rule = valid_rule();
        rule.match_.path_prefix = Some(format!("/{}", "a".repeat(CAPTURE_PATH_PREFIX_MAX_LEN)));
        assert!(rule.validate().is_err());
    }

    #[test]
    fn a_rooted_path_prefix_is_accepted() {
        let mut rule = valid_rule();
        rule.match_.path_prefix = Some("/checkout".to_string());
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn a_relative_output_dir_is_refused() {
        let mut rule = valid_rule();
        rule.output.dir = Some("captures".to_string());
        let err = rule.validate().expect_err("a relative dir is refused");
        assert!(err.contains("output.dir"), "{err}");
    }

    #[test]
    fn an_output_dir_with_a_traversal_component_is_refused() {
        let mut rule = valid_rule();
        rule.output.dir = Some("/var/lib/lorica/../../etc".to_string());
        let err = rule.validate().expect_err("a traversal is refused");
        assert!(err.contains("output.dir"), "{err}");
    }

    #[test]
    fn an_absolute_output_dir_without_traversal_is_accepted() {
        // Existence and writability belong to the writer at capture
        // time, so a directory this node has not created yet still
        // validates.
        let mut rule = valid_rule();
        rule.output.dir = Some("/var/lib/lorica/captures".to_string());
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn a_dir_budget_over_the_hard_cap_is_refused() {
        let mut rule = valid_rule();
        rule.output.max_dir_bytes = Some(CAPTURE_MAX_DIR_BYTES_CAP + 1);
        let err = rule.validate().expect_err("over the dir budget cap");
        assert!(err.contains("output.max_dir_bytes"), "{err}");
    }

    #[test]
    fn a_zero_dir_budget_is_refused() {
        let mut rule = valid_rule();
        rule.output.max_dir_bytes = Some(0);
        assert!(rule.validate().is_err());
    }

    #[test]
    fn a_malformed_redaction_entry_is_refused_rather_than_silently_redacting_nothing() {
        let mut rule = valid_rule();
        rule.redact.headers = vec!["X-Api Key".to_string()];
        let err = rule
            .validate()
            .expect_err("a name no header carries redacts nothing");
        assert!(err.contains("redact.headers"), "{err}");
    }

    #[test]
    fn an_empty_redaction_entry_is_refused() {
        let mut rule = valid_rule();
        rule.redact.query = vec![String::new()];
        let err = rule.validate().expect_err("an empty name is refused");
        assert!(err.contains("redact.query"), "{err}");
    }

    #[test]
    fn a_redaction_list_over_the_entry_count_cap_is_refused() {
        let mut rule = valid_rule();
        rule.redact.query = (0..=CAPTURE_REDACT_MAX_ENTRIES)
            .map(|n| format!("token{n}"))
            .collect();
        assert!(rule.validate().is_err());
    }

    #[test]
    fn a_redaction_entry_over_the_length_cap_is_refused() {
        let mut rule = valid_rule();
        rule.redact.headers = vec!["a".repeat(CAPTURE_REDACT_ENTRY_MAX_LEN + 1)];
        assert!(rule.validate().is_err());
    }

    #[test]
    fn well_formed_redaction_lists_are_accepted() {
        let mut rule = valid_rule();
        rule.redact.headers = vec!["X-Api-Key".to_string(), "X-Session".to_string()];
        rule.redact.query = vec!["access_token".to_string()];
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn the_match_block_serialises_under_its_reserved_name() {
        let rule = valid_rule();
        let json = serde_json::to_value(&rule).expect("test setup: rule serialises");
        assert!(json.get("match").is_some(), "the wire name is `match`");
        assert!(json.get("match_").is_none());
    }
}
