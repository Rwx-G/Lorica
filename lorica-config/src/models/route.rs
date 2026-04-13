use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::enums::{HeaderMatchType, LoadBalancing, PathMatchType, WafMode};

/// Per-path override that layers on top of a [`Route`]. A matching rule
/// can re-target backends, swap caching/rate-limit settings, force a
/// redirect, or short-circuit with `return_status` for the requests
/// whose path matches `path` under [`PathMatchType`] semantics.
///
/// Rules are evaluated in declaration order; the first match wins.
/// `None` fields leave the underlying route value unchanged - see
/// [`Route::with_path_rule_overrides`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathRule {
    pub path: String,
    #[serde(default)]
    pub match_type: PathMatchType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_ids: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_ttl_s: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_headers: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_headers_remove: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_rps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_burst: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_status: Option<u16>,
}

impl PathRule {
    /// Test the rule's `path` against an incoming request path under the
    /// configured [`PathMatchType`].
    pub fn matches(&self, request_path: &str) -> bool {
        match self.match_type {
            PathMatchType::Prefix => request_path.starts_with(&self.path),
            PathMatchType::Exact => request_path == self.path,
        }
    }
}

/// Route a request to a specific backend group based on one of its HTTP
/// request headers. Enables A/B testing (`X-Version: beta`), tenant
/// isolation (`X-Tenant: acme`), and similar content-negotiation-adjacent
/// patterns without changing upstream URLs.
///
/// Rules are evaluated in declaration order; first match wins. Header
/// names are matched case-insensitively as required by RFC 7230. An
/// empty `backend_ids` is allowed and means "match this rule but keep
/// the route's default backends" - useful when future fields (canary
/// split, headers override) extend this struct without requiring an
/// explicit backend set.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeaderRule {
    pub header_name: String,
    #[serde(default)]
    pub match_type: HeaderMatchType,
    pub value: String,
    #[serde(default)]
    pub backend_ids: Vec<String>,
}

impl HeaderRule {
    /// Test this rule against a single header value. The `regex_match`
    /// closure is invoked only for `HeaderMatchType::Regex` rules; the
    /// proxy engine passes a closure wrapping a precompiled `regex::Regex`,
    /// and tests that don't care about regex semantics can pass
    /// `|_| false`. `lorica-config` deliberately does not depend on the
    /// `regex` crate so the schema stays light.
    pub fn matches<F: FnOnce(&str) -> bool>(&self, value: &str, regex_match: F) -> bool {
        match self.match_type {
            HeaderMatchType::Exact => value == self.value,
            HeaderMatchType::Prefix => value.starts_with(&self.value),
            HeaderMatchType::Regex => regex_match(value),
        }
    }
}

/// Single response-body rewrite rule (Nginx `sub_filter` equivalent).
///
/// `pattern` is treated as a literal string by default; setting
/// `is_regex = true` compiles it with the `regex` crate and runs it
/// against the response body as bytes (so non-UTF-8 content like
/// tightly encoded binary JSON still works predictably).
///
/// `max_replacements` caps how many matches are substituted per
/// response. Useful defence against pathological rules like
/// `pattern: "a" replacement: "aa"` which would otherwise double the
/// body length on every pass. `None` = unlimited.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseRewriteRule {
    pub pattern: String,
    pub replacement: String,
    #[serde(default)]
    pub is_regex: bool,
    #[serde(default)]
    pub max_replacements: Option<u32>,
}

/// Per-route response-body rewriting. Buffers the response body up to
/// `max_body_bytes`, then applies each rule in declaration order to
/// the full buffered body before streaming it to the client. Responses
/// with compressed encodings (`Content-Encoding: gzip` etc.) are NOT
/// rewritten - doing so would need to decode/re-encode, which is out
/// of v1 scope. Operators who want rewriting on compressed upstreams
/// should disable compression on the route or upstream.
///
/// Content-type filtering: rewrite only applies when the response
/// `Content-Type` starts with one of `content_type_prefixes` (e.g.
/// `text/`, `application/json`). Empty list defaults to `["text/"]`.
///
/// Responses whose body exceeds `max_body_bytes` stream through
/// verbatim (no partial rewrite) - a half-rewritten body would be
/// worse than none. Matches the mirror-body-overflow stance.
/// # Mutual exclusion with caching
///
/// Response rewriting and cache (`cache_enabled = true`) are mutually
/// exclusive on the same route in v1. When both are configured, the
/// rewrite step is skipped and a warn log is emitted at response-
/// filter time (origin body passes through verbatim). The constraint
/// is a scope decision for v1, not a bug:
/// - Caching rewritten bytes risks serving stale rewrites after a
///   rule edit without an explicit purge.
/// - Stripping `Content-Length` on rewrite breaks the cache writer's
///   framing expectations.
///
/// Pick one per route; rewriting wins over caching with a warning
/// because rewriting is typically the stricter correctness / security
/// requirement (e.g. stripping internal hostnames from the origin
/// body). To serve cached rewritten content, put Lorica behind a
/// cache (or in front of a cache) - don't try to do both on the same
/// route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseRewriteConfig {
    /// Ordered list of rewrite rules. Each rule runs against the body
    /// after the previous one, so composition is possible (rule A
    /// renames an internal host, rule B strips a trailing marker).
    pub rules: Vec<ResponseRewriteRule>,
    /// Maximum buffered body size, in bytes. Responses larger than
    /// this stream through unchanged. Default 1 MiB.
    #[serde(default = "default_rewrite_max_body_bytes")]
    pub max_body_bytes: u32,
    /// Response Content-Type prefixes that enable rewriting. Empty
    /// list falls back to `["text/"]`. Matches are prefix-insensitive.
    #[serde(default)]
    pub content_type_prefixes: Vec<String>,
}

fn default_rewrite_max_body_bytes() -> u32 {
    1_048_576 // 1 MiB
}

/// Request mirroring: duplicate incoming requests to one or more
/// secondary backends for shadow testing. Fire-and-forget - the mirror
/// responses are discarded, and any mirror failure must never affect
/// the primary request.
///
/// # Trust model
///
/// The shadow backend receives a byte-for-byte clone of the primary
/// request INCLUDING Cookie, Authorization, and any custom session
/// headers. This is industry-standard behaviour (Nginx `mirror`,
/// Traefik `Mirroring`, Envoy `request_mirror_policies`) because
/// shadow testing only produces meaningful results when the shadow
/// sees the same authentication context as the primary. The
/// consequence: **shadow backends must be part of the same trust
/// boundary as the primary**. Do not mirror traffic to a backend
/// you would not trust with a production session cookie. The
/// `X-Lorica-Mirror: 1` marker is for log/metric filtering, not a
/// security boundary - an attacker on the shadow can still replay
/// the session against the primary.
///
/// # Behaviour
///
/// Typical use case: validate a new service version against real
/// production traffic before promoting it. The shadow backend receives
/// a clone of the request with an identifying `X-Lorica-Mirror: 1`
/// header so its logs and metrics can be distinguished from primary
/// traffic.
///
/// Sampling is deterministic per-request (hash of `X-Request-Id`) so a
/// given request is mirrored to every configured shadow backend or to
/// none - never split between them.
///
/// Request bodies on POST/PUT/PATCH are forwarded in full up to
/// `max_body_bytes`. Requests whose body exceeds that cap are NOT
/// mirrored - the shadow would see truncated data and report
/// misleading behaviour, so it's safer to skip. The cap is also what
/// prevents a single large upload from pinning memory for the length
/// of the mirror timeout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorConfig {
    /// One or more backend IDs that receive shadow copies of the
    /// request. Each eligible request spawns one sub-request per
    /// backend in this list. Must be non-empty.
    pub backend_ids: Vec<String>,
    /// Percentage of eligible requests to mirror. 0..=100. 0 disables
    /// the mirror without removing the config (useful for staged
    /// rollouts); 100 mirrors every request.
    #[serde(default = "default_mirror_sample_percent")]
    pub sample_percent: u8,
    /// Per-mirror-request timeout in milliseconds. Mirrors slower than
    /// this are dropped silently. Default 5000.
    #[serde(default = "default_mirror_timeout_ms")]
    pub timeout_ms: u32,
    /// Maximum request body size to buffer for mirroring, in bytes.
    /// Requests with bodies larger than this are sent to the primary
    /// normally but NOT mirrored (a truncated body would produce
    /// misleading shadow behaviour). Default 1 MiB. Set to 0 to
    /// explicitly skip body mirroring (headers-only mode).
    #[serde(default = "default_mirror_max_body_bytes")]
    pub max_body_bytes: u32,
}

fn default_mirror_sample_percent() -> u8 {
    100
}

fn default_mirror_timeout_ms() -> u32 {
    5_000
}

fn default_mirror_max_body_bytes() -> u32 {
    1_048_576 // 1 MiB
}

/// Forward-authentication config: before proxying to upstream, issue a
/// sub-request to an external authentication service (Authelia,
/// Authentik, Keycloak, oauth2-proxy, ...) and honour its verdict.
///
/// Semantics (matches Traefik / Nginx `auth_request` / Caddy
/// `forward_auth` conventions):
///
/// - A `GET` request is sent to [`address`] with a standard header set
///   (Host as `X-Forwarded-Host`, client IP as `X-Forwarded-For`, the
///   original method and path as `X-Forwarded-Method`/`-Uri`, plus
///   cookies, `Authorization`, and `User-Agent` verbatim). These are
///   the five bits Authelia/Authentik need to identify the session and
///   make a decision.
/// - 2xx: the request is allowed to continue to the upstream. Any
///   header named in [`response_headers`] is copied from the auth
///   response into the upstream request (common: `Remote-User`,
///   `Remote-Groups`, `Remote-Email`).
/// - 401 / 403: denial is surfaced verbatim to the client, body and
///   headers included. Critical for Authelia's login-redirect flow.
/// - Timeout / connection error / unexpected status: fail closed with
///   503.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardAuthConfig {
    /// Absolute URL of the auth service endpoint (scheme + host +
    /// optional port + path). Example: `http://authelia.internal:9091/api/verify`.
    pub address: String,
    /// Per-sub-request timeout in milliseconds. Applies to the total
    /// round-trip (connect + response). Default 5000.
    #[serde(default = "default_forward_auth_timeout_ms")]
    pub timeout_ms: u32,
    /// Header names to copy from the auth service's 2xx response into
    /// the upstream request. Empty = do not copy any (default).
    #[serde(default)]
    pub response_headers: Vec<String>,
    /// Cache successful (`Allow`) verdicts for this many milliseconds,
    /// keyed on the downstream session cookie. `0` (default) disables
    /// caching so every request is verified by the auth service - the
    /// correct behavior for strict zero-trust deployments.
    ///
    /// Only 2xx (`Allow`) verdicts are cached. `Deny` / `FailClosed`
    /// are always re-evaluated so a newly revoked session starts
    /// being denied immediately.
    ///
    /// Hard-capped at 60000 ms (60 s). Longer TTLs are rejected at
    /// the API validator because "revoked-session still allowed"
    /// grows more dangerous with TTL. Most Authelia / Authentik
    /// deployments use session lifetimes in the minutes-to-hours
    /// range; caching for up to 60 s is a good balance between
    /// removing the auth-service round-trip on hot paths and
    /// keeping revocation latency bounded.
    #[serde(default)]
    pub verdict_cache_ttl_ms: u32,
}

fn default_forward_auth_timeout_ms() -> u32 {
    5_000
}

/// Mutual-TLS client verification.
///
/// # HTTP-only listeners
///
/// mTLS enforcement is keyed on the downstream TLS digest
/// (`session.as_downstream().digest().ssl_digest`). Plaintext HTTP
/// connections have no TLS digest, so a route with `mtls.required =
/// true` served over an HTTP listener returns 496 unconditionally -
/// the request never carries a client cert to verify. This is
/// intentional (fail-closed), but confusing if the operator forgot
/// to also set `force_https = true` / `redirect_to`. Pair mTLS with
/// either an HTTPS-only listener or `force_https` so plaintext
/// clients are redirected to the TLS-terminating port.
///
/// # Requirements and constraints
///
/// Require connecting clients to present an X.509 certificate signed
/// by the configured CA bundle and, optionally, constrain which
/// certificate subjects are allowed.
///
/// The CA bundle is used by the TLS listener to validate the chain;
/// whether a missing cert counts as a failure is driven by `required`.
/// rustls is configured with `allow_unauthenticated` so the handshake
/// always succeeds - final allow/deny lives in the proxy layer, which
/// lets different routes on the same listener have different policies.
///
/// Two enforcement levels:
/// - `required = true`: the request is denied with 496
///   (RFC-reserved "SSL certificate required" status) if the client
///   did not present a cert. This is the zero-trust mode.
/// - `required = false`: requests without a cert pass through; requests
///   WITH a cert still get their organization checked against the
///   allowlist if one is configured. Useful for routes that want to
///   prefer-but-not-require client certs (mixed public + B2B).
///
/// `allowed_organizations` is an optional allowlist matched against the
/// cert subject's `O=` field. An empty list accepts any cert that
/// chains to the bundle. When non-empty, the organization is a
/// case-sensitive exact match.
///
/// Changes to `ca_cert_pem` require a proxy restart because rustls
/// server configs are immutable after build. Toggling `required` and
/// editing `allowed_organizations` are both hot-reloadable since those
/// are enforced in the request path.
/// Per-route token-bucket rate limit. Cross-worker under `--workers N`
/// via the lorica-limits `LocalBucket` + supervisor-synced
/// `AuthoritativeBucket` pair. See
/// `docs/architecture/worker-shared-state.md` § 6.
///
/// `capacity` is the burst allowance (tokens in the bucket); every
/// request consumes one token. `refill_per_sec` is the steady-state
/// admission rate. A request whose worker finds the local cache empty
/// is rejected with 429 `Too Many Requests`. Inter-worker drift is
/// bounded at `100 ms * N_workers` worth of tokens (sync interval).
///
/// When `scope = PerIp`, each client IP gets its own bucket. When
/// `scope = PerRoute`, a single shared bucket caps aggregate route
/// traffic regardless of client — useful to protect an origin that
/// cannot handle more than X rps total.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    /// Burst / token-bucket capacity. Must be `> 0`; the API rejects 0.
    pub capacity: u32,
    /// Refill rate in tokens/second. `0` disables refill (one-shot).
    pub refill_per_sec: u32,
    /// Keying strategy for per-client isolation.
    #[serde(default)]
    pub scope: RateLimitScope,
}

/// How a `RateLimit` partitions traffic across clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitScope {
    /// One bucket per `(route_id, client_ip)`. Default — protects
    /// against a single abusive client without penalising the rest.
    #[default]
    PerIp,
    /// Single bucket for the whole route. All clients compete for the
    /// same tokens. Use to cap aggregate traffic to a fragile origin.
    PerRoute,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtlsConfig {
    /// Concatenated PEM-encoded CA certificates that are allowed to
    /// issue client certs. Must contain at least one valid CERTIFICATE
    /// block. Empty / garbage PEM is rejected by the API validator.
    pub ca_cert_pem: String,
    /// When true, requests without a validated client certificate are
    /// rejected with 496. When false, unauthenticated requests pass
    /// through but any presented cert must still match the allowlist.
    #[serde(default)]
    pub required: bool,
    /// Optional subject-organization allowlist. Empty = accept any
    /// cert that chains to `ca_cert_pem`. Case-sensitive exact match.
    #[serde(default)]
    pub allowed_organizations: Vec<String>,
}

/// Canary traffic split: send `weight_percent` of a route's requests to
/// a specific backend group, the rest fall through to the next split or
/// (if cumulative weights < 100) to the route's default backends.
///
/// Splits are evaluated in cumulative order with buckets assigned by
/// hashing the client IP together with the route ID:
///
/// ```text
///   splits = [A: 5%, B: 10%]
///   buckets = 0..=4 -> A, 5..=14 -> B, 15..=99 -> default
/// ```
///
/// Using the client IP (not a per-request random) makes the assignment
/// *sticky*: the same user stays on the same version across multiple
/// requests on the same route. Mixing the route ID prevents an unlucky
/// client from being in every service's canary bucket simultaneously
/// (which would happen if we hashed the IP alone).
///
/// Requests with no client IP - e.g. Unix-socket listeners used in
/// tests - skip the canary entirely and serve from the route defaults.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrafficSplit {
    /// Human-readable label; surfaced in dashboards and access logs.
    /// Optional but recommended so on-call can answer "which bucket?"
    /// at a glance.
    #[serde(default)]
    pub name: String,
    /// Percentage of eligible traffic that should hit this split.
    /// Valid range 0..=100. 0 is allowed (rule kept but inactive -
    /// useful while preparing a rollout).
    pub weight_percent: u8,
    /// Backends that serve this split. Must be non-empty for the split
    /// to actually divert traffic; an empty list means "match but do
    /// nothing" and is rejected by the API.
    #[serde(default)]
    pub backend_ids: Vec<String>,
}

/// A virtual host served by the proxy: hostname (+ optional aliases),
/// associated TLS certificate, the pool of backends behind it, and the
/// per-route policy knobs (timeouts, headers, WAF, cache, mTLS, ...).
///
/// `hostname` (and any entry in `hostname_aliases`) must be unique across
/// the whole route table - `ConfigStore::create_route` /
/// `update_route` reject inserts that would create a conflict.
/// `certificate_id` is a soft reference: if it points to a missing
/// [`Certificate`] the route will simply fail to terminate TLS at runtime
/// rather than at insert time.
///
/// Backends are linked separately through `route_backends`; see
/// `ConfigStore::link_route_backend`.
///
/// [`Certificate`]: super::certificate::Certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub id: String,
    pub hostname: String,
    pub path_prefix: String,
    pub certificate_id: Option<String>,
    pub load_balancing: LoadBalancing,
    pub waf_enabled: bool,
    pub waf_mode: WafMode,
    pub enabled: bool,
    #[serde(default)]
    pub force_https: bool,
    #[serde(default)]
    pub redirect_hostname: Option<String>,
    #[serde(default)]
    pub redirect_to: Option<String>,
    #[serde(default)]
    pub hostname_aliases: Vec<String>,
    #[serde(default)]
    pub proxy_headers: HashMap<String, String>,
    #[serde(default)]
    pub response_headers: HashMap<String, String>,
    #[serde(default = "default_security_headers")]
    pub security_headers: String,
    #[serde(default = "default_connect_timeout_s")]
    pub connect_timeout_s: i32,
    #[serde(default = "default_read_timeout_s")]
    pub read_timeout_s: i32,
    #[serde(default = "default_send_timeout_s")]
    pub send_timeout_s: i32,
    #[serde(default)]
    pub strip_path_prefix: Option<String>,
    #[serde(default)]
    pub add_path_prefix: Option<String>,
    /// Regex pattern for path rewriting (e.g. `^/api/v1/(.*)`).
    /// Applied after strip/add prefix. Rust regex crate (linear time, ReDoS-safe).
    #[serde(default)]
    pub path_rewrite_pattern: Option<String>,
    /// Replacement string for regex rewrite (e.g. `/v2/$1`).
    #[serde(default)]
    pub path_rewrite_replacement: Option<String>,
    #[serde(default = "default_access_log_enabled")]
    pub access_log_enabled: bool,
    #[serde(default)]
    pub proxy_headers_remove: Vec<String>,
    #[serde(default)]
    pub response_headers_remove: Vec<String>,
    #[serde(default)]
    pub max_request_body_bytes: Option<u64>,
    #[serde(default = "default_websocket_enabled")]
    pub websocket_enabled: bool,
    #[serde(default)]
    pub rate_limit_rps: Option<u32>,
    #[serde(default)]
    pub rate_limit_burst: Option<u32>,
    #[serde(default)]
    pub ip_allowlist: Vec<String>,
    #[serde(default)]
    pub ip_denylist: Vec<String>,
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
    #[serde(default)]
    pub cors_allowed_methods: Vec<String>,
    #[serde(default)]
    pub cors_max_age_s: Option<i32>,
    #[serde(default = "default_compression_enabled")]
    pub compression_enabled: bool,
    #[serde(default)]
    pub retry_attempts: Option<u32>,
    #[serde(default)]
    pub cache_enabled: bool,
    #[serde(default = "default_cache_ttl_s")]
    pub cache_ttl_s: i32,
    #[serde(default = "default_cache_max_bytes")]
    pub cache_max_bytes: i64,
    #[serde(default)]
    pub max_connections: Option<u32>,
    #[serde(default = "default_slowloris_threshold_ms")]
    pub slowloris_threshold_ms: i32,
    #[serde(default)]
    pub auto_ban_threshold: Option<u32>,
    #[serde(default = "default_auto_ban_duration_s")]
    pub auto_ban_duration_s: i32,
    #[serde(default)]
    pub path_rules: Vec<PathRule>,
    #[serde(default)]
    pub return_status: Option<u16>,
    /// Enable cookie-based sticky sessions (session affinity).
    /// When enabled, a `LORICA_SRV` cookie is set with the backend ID.
    #[serde(default)]
    pub sticky_session: bool,
    #[serde(default)]
    pub basic_auth_username: Option<String>,
    #[serde(default)]
    pub basic_auth_password_hash: Option<String>,
    #[serde(default = "default_stale_while_revalidate_s")]
    pub stale_while_revalidate_s: i32,
    #[serde(default = "default_stale_if_error_s")]
    pub stale_if_error_s: i32,
    #[serde(default)]
    pub retry_on_methods: Vec<String>,
    #[serde(default)]
    pub maintenance_mode: bool,
    #[serde(default)]
    pub error_page_html: Option<String>,
    /// Request header names that partition the cache for this route.
    /// Each listed header contributes its value to a variance key so
    /// different values get separate cache entries (e.g.
    /// `["Accept-Encoding"]` keeps gzip and identity responses separate).
    /// Merged with any `Vary` header the origin returns.
    #[serde(default)]
    pub cache_vary_headers: Vec<String>,
    /// Header-based routing rules. Evaluated before path rules; first match
    /// selects `matched_backends`. A later path rule with its own
    /// `backend_ids` overrides the header rule's selection.
    #[serde(default)]
    pub header_rules: Vec<HeaderRule>,
    /// Canary traffic splits. Evaluated AFTER header rules (header rules
    /// are explicit opt-in and should win) and BEFORE path rules (path
    /// rules are URL-specific and should win).
    #[serde(default)]
    pub traffic_splits: Vec<TrafficSplit>,
    /// Forward-auth config. When set, every request on this route is
    /// gated by a sub-request to the configured auth service. Evaluated
    /// after route match but before any backend selection, so a denied
    /// request never touches the upstream.
    #[serde(default)]
    pub forward_auth: Option<ForwardAuthConfig>,
    /// Request mirroring: fire-and-forget shadow copies to alternate
    /// backends. Evaluated after the primary upstream is committed;
    /// mirror failures never affect the primary response.
    #[serde(default)]
    pub mirror: Option<MirrorConfig>,
    /// Response-body rewriting: buffer and apply search-and-replace
    /// rules to the upstream response body before it reaches the
    /// client (Nginx `sub_filter` equivalent). `None` = disabled.
    #[serde(default)]
    pub response_rewrite: Option<ResponseRewriteConfig>,
    /// mTLS client verification. When set, the TLS listener requires
    /// or accepts client certs signed by `ca_cert_pem`; the proxy then
    /// gates the request per route based on `required` and
    /// `allowed_organizations`. `None` = disabled (current default).
    #[serde(default)]
    pub mtls: Option<MtlsConfig>,
    /// Token-bucket rate limit. When set, every request on this route
    /// passes through a `LocalBucket::try_consume`. In worker mode the
    /// bucket is synced cross-worker via the supervisor (see
    /// `lorica_limits::AuthoritativeBucket`). `None` = unlimited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimit>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Route {
    /// Return a clone of this route with any `Some(_)` field of `rule`
    /// merged on top (cache, rate-limit, headers, redirect, return
    /// status). `None` fields on the rule leave the route unchanged.
    /// Used by the proxy to resolve the effective config for a request
    /// once a [`PathRule`] has matched.
    pub fn with_path_rule_overrides(&self, rule: &PathRule) -> Route {
        let mut r = self.clone();
        if let Some(ref h) = rule.response_headers {
            r.response_headers = h.clone();
        }
        if let Some(ref h) = rule.response_headers_remove {
            r.response_headers_remove = h.clone();
        }
        if let Some(v) = rule.cache_enabled {
            r.cache_enabled = v;
        }
        if let Some(v) = rule.cache_ttl_s {
            r.cache_ttl_s = v;
        }
        if let Some(v) = rule.rate_limit_rps {
            r.rate_limit_rps = Some(v);
        }
        if let Some(v) = rule.rate_limit_burst {
            r.rate_limit_burst = Some(v);
        }
        if rule.redirect_to.is_some() {
            r.redirect_to = rule.redirect_to.clone();
        }
        if rule.return_status.is_some() {
            r.return_status = rule.return_status;
        }
        r
    }
}

fn default_security_headers() -> String {
    "moderate".to_string()
}

fn default_stale_while_revalidate_s() -> i32 {
    10
}

fn default_stale_if_error_s() -> i32 {
    60
}

fn default_connect_timeout_s() -> i32 {
    5
}

fn default_read_timeout_s() -> i32 {
    60
}

fn default_send_timeout_s() -> i32 {
    60
}

fn default_access_log_enabled() -> bool {
    true
}

fn default_websocket_enabled() -> bool {
    true
}

fn default_compression_enabled() -> bool {
    false
}

fn default_cache_ttl_s() -> i32 {
    300
}

fn default_cache_max_bytes() -> i64 {
    52428800
}

fn default_slowloris_threshold_ms() -> i32 {
    5000
}

fn default_auto_ban_duration_s() -> i32 {
    3600
}
