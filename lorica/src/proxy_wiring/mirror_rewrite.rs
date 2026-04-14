// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Request mirroring + response body rewriting (audit M-8 step 4).
//!
//! Two closely related response-pipeline features grouped in one
//! submodule because they share the `request_has_body` helper and
//! both hook into the same `request_filter` -> `response_filter`
//! points on `LoricaProxy`. Moved verbatim from `proxy_wiring.rs`;
//! no logic change.
//!
//! Mirror:
//!   - `MIRROR_CLIENT` / `MIRROR_SEMAPHORE` statics (shared reqwest
//!     client and global 256-slot concurrency cap).
//!   - `mirror_sample_hit` / `build_mirror_url` /
//!     `build_mirror_forward_headers` / `request_has_body`.
//!   - `MirrorPending` + `MirrorBodyState` ctx state.
//!   - `spawn_mirrors` entry point.
//!
//! Rewrite:
//!   - `CompiledRewriteRule` + `compile_rewrite_rule`.
//!   - `apply_response_rewrites` / `should_rewrite_response`.
//!   - `ResponseRewriteState` ctx state.

use std::sync::Arc;
use std::time::Duration;

use once_cell::sync::Lazy;

use super::Backend;

static MIRROR_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(16)
        .connect_timeout(Duration::from_secs(3))
        .build()
        .expect("build mirror reqwest client")
});

/// Global cap on in-flight mirror sub-requests. Prevents a misconfigured
/// shadow backend (slow or dead) from leaking unbounded tokio tasks and
/// file descriptors. When the permit can't be acquired immediately, the
/// mirror is dropped - shadow testing is best-effort by design.
///
/// 256 is generous for a single-node deployment and still bounded
/// enough that a hung shadow can't take the process down.
static MIRROR_SEMAPHORE: Lazy<Arc<tokio::sync::Semaphore>> =
    Lazy::new(|| Arc::new(tokio::sync::Semaphore::new(256)));

pub(crate) fn mirror_sample_hit(request_id: &str, sample_percent: u8) -> bool {
    let pct = sample_percent.min(100);
    if pct == 0 {
        return false;
    }
    if pct == 100 {
        return true;
    }
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    request_id.hash(&mut h);
    (h.finish() % 100) < (pct as u64)
}

/// Build the mirror request URL by combining the shadow backend address
/// with the downstream request's path+query. The backend address can be
/// bare `host:port` (then we prepend `http://`) or a full URL. Returns
/// `None` if the resulting URL is unparseable (mirror is skipped, never
/// fatal).
pub(crate) fn build_mirror_url(backend_addr: &str, path_and_query: &str) -> Option<String> {
    let trimmed = backend_addr.trim();
    if trimmed.is_empty() {
        return None;
    }
    let base = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };
    // Ensure exactly one '/' between base and path.
    let base = base.trim_end_matches('/');
    let path = if path_and_query.starts_with('/') {
        path_and_query.to_string()
    } else {
        format!("/{path_and_query}")
    };
    let full = format!("{base}{path}");
    // Validate at the http::Uri level - reqwest will re-parse but this
    // rejects obvious typos at spawn time.
    full.parse::<http::Uri>().ok().map(|_| full)
}

/// Compiled form of a single response-rewrite rule. Pre-compiling the
/// `regex::bytes::Regex` at route-load time avoids re-parsing the
/// pattern for every response, and lets us report malformed regex
/// patterns once (at reload) rather than once per request.
#[derive(Debug, Clone)]
pub struct CompiledRewriteRule {
    pub regex: regex::bytes::Regex,
    pub replacement: Vec<u8>,
    pub max_replacements: Option<u32>,
}

/// Compile a raw `ResponseRewriteRule` to its engine form. Literal
/// patterns are regex-escaped so the same code path handles both. An
/// invalid regex is logged and returns `None` so the rule is silently
/// skipped at runtime - callers aggregate these into a
/// `Vec<Option<_>>` parallel to the declared rules.
pub(crate) fn compile_rewrite_rule(
    rule: &lorica_config::models::ResponseRewriteRule,
    route_id: &str,
    index: usize,
) -> Option<CompiledRewriteRule> {
    let pattern = if rule.is_regex {
        rule.pattern.clone()
    } else {
        regex::escape(&rule.pattern)
    };
    match regex::bytes::Regex::new(&pattern) {
        Ok(re) => Some(CompiledRewriteRule {
            regex: re,
            replacement: rule.replacement.as_bytes().to_vec(),
            max_replacements: rule.max_replacements,
        }),
        Err(e) => {
            tracing::warn!(
                route_id = %route_id,
                rule_index = index,
                pattern = %rule.pattern,
                is_regex = rule.is_regex,
                error = %e,
                "invalid response_rewrite pattern, skipping rule"
            );
            None
        }
    }
}

/// Apply all rewrite rules to a response body in declaration order.
/// Each rule operates on the output of the previous one, so rules
/// compose. `max_replacements` caps substitutions per rule; `None`
/// means unlimited.
///
/// Pure function over bytes, so the composition rules, cross-chunk
/// correctness (since we run on the full buffered body), and
/// per-rule replacement limits are all unit-testable.
pub(crate) fn apply_response_rewrites(
    body: &[u8],
    rules: &[Option<CompiledRewriteRule>],
) -> Vec<u8> {
    let mut out: std::borrow::Cow<[u8]> = std::borrow::Cow::Borrowed(body);
    for rule in rules.iter().flatten() {
        let rewritten = match rule.max_replacements {
            Some(n) => rule
                .regex
                .replacen(&out, n as usize, rule.replacement.as_slice()),
            None => rule.regex.replace_all(&out, rule.replacement.as_slice()),
        };
        // `replace_all` returns a Cow - promote to owned if it modified.
        out = std::borrow::Cow::Owned(rewritten.into_owned());
    }
    out.into_owned()
}

/// Decide whether a given response should be rewritten. Returns true
/// when:
///   - the route has a rewrite config
///   - the response is not compressed (Content-Encoding is absent,
///     empty, or explicitly "identity")
///   - the Content-Type matches one of the configured prefixes
///     (case-insensitive), or defaults to "text/" when the list is empty
pub(crate) fn should_rewrite_response(
    cfg: &lorica_config::models::ResponseRewriteConfig,
    content_type: &str,
    content_encoding: &str,
) -> bool {
    // Skip compressed bodies: rewriting raw gzip/br would corrupt them.
    let enc = content_encoding.trim();
    if !enc.is_empty() && !enc.eq_ignore_ascii_case("identity") {
        return false;
    }
    // Default to text/* when the operator list is empty. A typo-proof
    // defensive default: operators who enable rewriting almost always
    // mean "for HTML/text responses".
    let lower_ct = content_type.to_ascii_lowercase();
    let allowed_list: Vec<String> = if cfg.content_type_prefixes.is_empty() {
        vec!["text/".into()]
    } else {
        cfg.content_type_prefixes
            .iter()
            .map(|p| p.to_ascii_lowercase())
            .collect()
    };
    allowed_list.iter().any(|p| lower_ct.starts_with(p))
}

/// Build the fixed forward-header set for a mirror sub-request: the
/// whole request header bag minus hop-by-hop headers, plus the mirror
/// tag and the propagated request id. Pure function so the filtering
/// contract is unit-testable without a proxy setup.
pub(crate) fn build_mirror_forward_headers(
    req: &lorica_http::RequestHeader,
    request_id: &str,
) -> Vec<(String, String)> {
    let mut forward_headers: Vec<(String, String)> = Vec::with_capacity(req.headers.len() + 2);
    forward_headers.push(("X-Lorica-Mirror".into(), "1".into()));
    forward_headers.push(("X-Request-Id".into(), request_id.to_string()));
    for (name, value) in req.headers.iter() {
        let n = name.as_str().to_ascii_lowercase();
        if matches!(
            n.as_str(),
            "host"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "keep-alive"
                | "proxy-connection"
                | "te"
                | "trailer"
                | "upgrade"
                // Don't double-set the header we just injected.
                | "x-lorica-mirror"
                | "x-request-id"
        ) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            forward_headers.push((name.as_str().to_string(), v.to_string()));
        }
    }
    forward_headers
}

/// Classify whether a request carries (or will carry) a body based on
/// RFC-mandated framing headers. Returns true for `Content-Length > 0`
/// or `Transfer-Encoding: chunked`. Used to decide whether mirroring
/// must wait for `request_body_filter` or can fire immediately.
pub(crate) fn request_has_body(req: &lorica_http::RequestHeader) -> bool {
    if let Some(te) = req.headers.get("transfer-encoding") {
        if let Ok(v) = te.to_str() {
            if v.to_ascii_lowercase().contains("chunked") {
                return true;
            }
        }
    }
    if let Some(cl) = req.headers.get("content-length") {
        if let Ok(v) = cl.to_str() {
            if let Ok(n) = v.parse::<u64>() {
                return n > 0;
            }
        }
    }
    false
}

/// Captured state of a pending mirror. Sits in `RequestCtx` while we
/// wait for `request_body_filter` to collect the body.
#[derive(Debug, Clone)]
pub struct MirrorPending {
    pub cfg: lorica_config::models::MirrorConfig,
    pub backends: Vec<Backend>,
    pub method: http::Method,
    pub path_and_query: String,
    pub headers: Vec<(String, String)>,
    pub request_id: String,
    pub max_body_bytes: usize,
    pub route_id: String,
}

/// Body-accumulation state for a mirror sub-request. `Overflowed`
/// means the request body exceeded `max_body_bytes` and we have to
/// drop the mirror (a truncated body would produce misleading shadow
/// behaviour).
#[derive(Debug)]
pub enum MirrorBodyState {
    Active(Vec<u8>),
    Overflowed,
}

/// Response-body buffering state for rewriting. Active while below
/// `max_body_bytes`; flipped to Overflowed once the buffer would
/// exceed the cap. Overflowed means "flush what we have and stream
/// the rest unchanged" - a partial rewrite would corrupt the output
/// worse than no rewrite.
#[derive(Debug)]
pub enum ResponseRewriteState {
    Active(Vec<u8>),
    Overflowed,
}

/// Spawn fire-and-forget shadow copies of the current request to each
/// configured mirror backend. Runs under a global semaphore so a slow
/// shadow cannot leak unbounded tasks. Never returns an error - mirror
/// failures are logged at debug and forgotten.
///
/// The `body` parameter is the captured request body (already bounded
/// by `max_body_bytes` at buffer time); `None` means "do not send a
/// body" (GETs, HEADs, DELETE+no-body, or operator-configured
/// headers-only mode via `max_body_bytes = 0`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_mirrors(
    cfg: &lorica_config::models::MirrorConfig,
    resolved_backends: &[Backend],
    method: http::Method,
    path_and_query: String,
    forward_headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    request_id: String,
    route_id: String,
) {
    if !mirror_sample_hit(&request_id, cfg.sample_percent) {
        return;
    }
    if resolved_backends.is_empty() {
        return;
    }

    let timeout = Duration::from_millis(cfg.timeout_ms as u64);
    let sem = Arc::clone(&MIRROR_SEMAPHORE);

    for backend in resolved_backends {
        let url = match build_mirror_url(&backend.address, &path_and_query) {
            Some(u) => u,
            None => {
                tracing::debug!(backend = %backend.address, "mirror: invalid URL, skipping");
                continue;
            }
        };
        let method_c = method.clone();
        let headers_c = forward_headers.clone();
        let body_c = body.clone();
        let sem_c = Arc::clone(&sem);
        let route_id_c = route_id.clone();
        tokio::spawn(async move {
            // try_acquire_owned is the right primitive here: if all 256
            // slots are in-flight, drop the mirror silently instead of
            // queuing (queuing would build a backlog behind a slow
            // shadow that never drains).
            let _permit = match sem_c.try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    tracing::debug!(url = %url, "mirror: semaphore saturated, dropping");
                    lorica_api::metrics::inc_mirror_outcome(&route_id_c, "dropped_saturated");
                    return;
                }
            };
            lorica_api::metrics::inc_mirror_outcome(&route_id_c, "spawned");
            let method_r = match reqwest::Method::from_bytes(method_c.as_str().as_bytes()) {
                Ok(m) => m,
                Err(_) => {
                    lorica_api::metrics::inc_mirror_outcome(&route_id_c, "errored");
                    return;
                }
            };
            let mut builder = MIRROR_CLIENT.request(method_r, &url).timeout(timeout);
            for (name, value) in headers_c {
                builder = builder.header(name, value);
            }
            if let Some(body_bytes) = body_c {
                builder = builder.body(body_bytes);
            }
            match builder.send().await {
                Ok(_) => {
                    // Discard the response body to release the
                    // connection back to the pool.
                }
                Err(e) => {
                    tracing::debug!(url = %url, error = %e, "mirror request failed");
                    lorica_api::metrics::inc_mirror_outcome(&route_id_c, "errored");
                }
            }
        });
    }
}
