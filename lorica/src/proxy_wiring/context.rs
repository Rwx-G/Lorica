// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Per-request context carried through every Pingora hook.
//!
//! [`RequestCtx`] is the `ProxyHttp::CTX` associated type for
//! `LoricaProxy` ; one instance is allocated by `new_ctx` for every
//! incoming request and threaded through `request_filter`,
//! `request_body_filter`, `upstream_peer`, `upstream_request_filter`,
//! `response_filter`, `response_body_filter`, `logging`, and
//! `fail_to_proxy`. Most fields are populated lazily as the pipeline
//! progresses ; the `Default` impl in `new_ctx` materialises the empty
//! state at request entry.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Instant;

use lorica_config::models::{Backend, Route};

use super::mirror_rewrite::{
    CompiledRewriteRule, MirrorBodyState, MirrorPending, ResponseRewriteState,
};
use super::RouteEntry;

/// Per-request context carried through the proxy pipeline.
pub struct RequestCtx {
    /// When the request started processing.
    pub start_time: Instant,
    /// The selected backend address (for logging).
    pub backend_addr: Option<String>,
    /// The matched route hostname (for logging).
    pub matched_host: Option<String>,
    /// The matched route path prefix (for logging).
    pub matched_path: Option<String>,
    /// The matched route ID (for metrics - bounded cardinality).
    pub route_id: Option<String>,
    /// Whether WAF blocked this request.
    pub waf_blocked: bool,
    /// Whether WAF detected (but allowed) a threat on this request.
    pub waf_detected: bool,
    /// Snapshot of the matched route for use in later pipeline stages.
    /// Arc-wrapped to avoid deep-cloning the Route struct on every request.
    pub route_snapshot: Option<Arc<Route>>,
    /// Full matched `RouteEntry` captured in `request_filter` so
    /// `upstream_peer` does not need to re-run `config.find_route`.
    /// Cheap (pointer clone) since the entry is already `Arc`'d in
    /// `ProxyConfig`. `None` when no route matched (request_filter
    /// returned `Ok(false)` and upstream_peer will 404).
    pub matched_route_entry: Option<Arc<RouteEntry>>,
    /// Unique request identifier for tracing (propagated to backend via X-Request-Id).
    pub request_id: String,
    /// Whether access logging is enabled for this route.
    pub access_log_enabled: bool,
    /// Client IP address (from socket or X-Forwarded-For).
    pub client_ip: Option<String>,
    /// Whether the client IP was extracted from X-Forwarded-For header.
    pub is_xff: bool,
    /// The direct TCP peer IP when XFF is used (the forwarding proxy's IP).
    pub xff_proxy_ip: Option<String>,
    /// Request source (from X-Lorica-Source header, e.g., "loadtest").
    pub source: String,
    /// Per-route connection counter for max_connections enforcement.
    /// Stored here so the counter is decremented in `logging()` when the request ends.
    pub route_conn_counter: Option<Arc<AtomicU64>>,
    /// Precompiled regex for path rewriting (from RouteEntry, avoids recompiling per request).
    pub path_rewrite_regex: Option<Arc<regex::Regex>>,
    /// Rate limit info for response headers: (limit_rps, current_rate).
    pub rate_limit_info: Option<(u32, f64)>,
    /// Retry counter for upstream connection failures.
    pub retry_count: u32,
    /// Backends overridden by a matched path rule (None = use route backends).
    pub matched_backends: Option<Vec<Backend>>,
    /// True when the active `redirect_to` originates from a path rule
    /// override. In that case the target URL is used verbatim (no
    /// path/query appended), because the operator explicitly set the
    /// destination for this specific path. Route-level `redirect_to`
    /// still appends the request path + query for migration use cases.
    pub path_rule_literal_redirect: bool,
    /// Human-readable reason when the proxy short-circuits with an error status
    /// (e.g. "WAF blocked", "rate limited", "return_status rule", "IP banned").
    pub block_reason: Option<String>,
    /// Accumulated request body bytes for chunked transfer size enforcement.
    pub body_bytes_received: u64,
    /// Buffered request body for WAF body scanning (only when WAF is enabled).
    pub waf_body_buffer: Option<Vec<u8>>,
    /// Set to true the first time the request body crosses
    /// `WAF_BODY_SCAN_MAX` in Detection mode, so the corresponding
    /// `WafEvent` (`BodyTruncated`) is emitted once per request
    /// rather than on every subsequent chunk. Has no effect in
    /// Blocking mode (the request is rejected with 413 instead).
    pub waf_body_truncated: bool,
    /// Backend ID for sticky session cookie injection (set in upstream_peer).
    pub sticky_backend_id: Option<String>,
    /// Headers harvested from a successful forward-auth response, to be
    /// injected into the upstream request (e.g. Remote-User).
    pub forward_auth_inject: Vec<(String, String)>,
    /// Response-body rewrite state. `Some(Active(buf))` while we're
    /// buffering the upstream response to rewrite it at end-of-stream;
    /// `Some(Overflowed)` if the body exceeded `max_body_bytes` (we
    /// then flush the buffer and stream the rest verbatim - better
    /// than a half-rewritten body). `None` means the feature is off
    /// for this response (Content-Type/Encoding didn't qualify).
    pub response_rewrite_state: Option<ResponseRewriteState>,
    /// Precompiled rewrite rules for this response, resolved once in
    /// `response_filter` from the current ProxyConfig and stored here
    /// so `response_body_filter` does not re-scan the routes map on
    /// every chunk (which was O(routes) per chunk under load). `Arc`
    /// so clones stay cheap.
    pub response_rewrite_rules: Option<Arc<Vec<Option<CompiledRewriteRule>>>>,

    /// Pending mirror sub-request awaiting the downstream request body.
    /// Populated in `request_filter` when the route has mirroring
    /// enabled and the request carries a body; fired in
    /// `request_body_filter` on `end_of_stream`. `None` for requests
    /// that don't mirror, or that have already fired (no-body methods
    /// fire immediately from `request_filter`).
    pub mirror_pending: Option<MirrorPending>,
    /// Accumulating body state for a pending mirror. Separate from
    /// `mirror_pending` so the buffer can be taken without disturbing
    /// the pending metadata.
    pub mirror_body_state: Option<MirrorBodyState>,
    /// Address of the backend admitted via a HalfOpen probe slot on
    /// this request, when any. Drives `was_probe=true` on the
    /// subsequent `BreakerEngine::record(...)` call for that exact
    /// backend so the supervisor can close the breaker on success (or
    /// bounce back to Open on failure). `None` for requests that went
    /// out on a Closed breaker.
    pub breaker_probe_backend: Option<String>,
    /// W3C `traceparent` to emit toward the upstream. `Some` once the
    /// request_filter pipeline has either preserved the client's
    /// header (with a new parent-span id rolled for Lorica) or
    /// synthesised a fresh trace from the request_id. `None` only
    /// during early startup between `new_ctx` and the first line of
    /// `request_filter`. See `lorica::otel`.
    pub outgoing_traceparent: Option<crate::otel::TraceParent>,
    /// Parsed incoming `traceparent` from the client, retained so the
    /// OTel span created in `request_filter` can link to the client's
    /// span as its parent. `None` when the client did not send a
    /// header or sent a malformed one.
    pub incoming_traceparent: Option<crate::otel::TraceParent>,
    /// Whether the outgoing traceparent was preserved from the
    /// client (true) or synthesised by Lorica (false). Used by later
    /// stories (span attributes, metrics) to distinguish trace origin.
    pub traceparent_from_client: bool,
    /// Root `tracing::Span` for this request. Created by the
    /// `#[instrument(name = "http_request")]` on `request_filter` and
    /// captured via `Span::current()` at the top of that hook so the
    /// downstream hooks (`upstream_request_filter`, `response_filter`,
    /// `logging`, `fail_to_proxy`) can parent their own `#[instrument]`
    /// spans under it — producing a clean nested tree in Jaeger /
    /// Tempo when the `otel` feature is on (the
    /// `tracing_opentelemetry` bridge installed in `init_logging`
    /// mirrors every tracing span to an OTel span, inheriting the
    /// parent link). Without the feature, the tracing span still
    /// exists but only feeds the fmt layer for log correlation. The
    /// field starts as `tracing::Span::none()` in `new_ctx` and is
    /// replaced at the top of `request_filter`.
    pub root_tracing_span: tracing::Span,
}
