//! API-contract drift gate (backlog #42c).
//!
//! CI runs `cargo test`, so this failing test IS the gate: whenever a
//! handler route in `server.rs` and the published `openapi.yaml` drift
//! apart, the build goes red with an explicit list of the offending
//! `(METHOD, path)` pairs.
//!
//! It is a diff-style check, not a codegen step: nothing is generated,
//! nothing is auto-written. Two `(METHOD, path)` sets are extracted -
//! one from the axum route table, one from the OpenAPI document - and
//! compared for exact equality.
//!
//! Path parameters are normalised to `{}` on both sides so the gate
//! reasons about the routing contract (path shape + method), not the
//! spelling of a parameter identifier, which is not part of the wire
//! contract.
//!
//! The automation plane (Story 10.3) is a second socket with a second
//! credential, so it has a second document, `openapi-automation.yaml`,
//! and a second gate below. It reuses every extractor here: the router
//! is an axum router and the document is an OpenAPI document, so the
//! two sides are the same shape as the management pair. What it adds
//! is a scope check, because on that plane the scope a path requires
//! is part of the contract an automation reads, and a scope that
//! drifts from [`lorica_api::automation::required_scope`] is a 403
//! nobody predicted.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// Route/method pairs that live in the router but are intentionally
/// absent from the REST OpenAPI document. Each entry MUST be a genuine
/// "not a documented REST operation", never a way to hide real drift.
///
/// Currently empty: the dashboard SPA / static-asset / fallback routes
/// live in `lorica_dashboard::router()` (a separate crate), so they are
/// never scanned out of `server.rs` in the first place, and the two
/// WebSocket upgrade endpoints (`/api/v1/logs/ws`,
/// `/api/v1/loadtest/ws`) are documented in the spec with a `101`
/// response. There is nothing legitimately non-REST left to exclude.
const ROUTE_ALLOWLIST: &[(&str, &str)] = &[];

/// Acknowledged, unreconciled pre-existing drift. Pairs listed here are
/// excluded from BOTH diff directions so the gate passes while keeping
/// the debt explicit and greppable. Each entry carries a
/// `// TODO(#42c): ...` line naming the reconciliation owed.
///
/// Currently empty: the only drift found when this gate was introduced
/// was the two Story 8.9 audit-log endpoints missing from the spec;
/// those were mechanically documented rather than parked here.
const KNOWN_DRIFT: &[(&str, &str)] = &[];

const HTTP_METHODS: [&str; 7] = ["get", "post", "put", "delete", "patch", "options", "head"];

#[test]
fn openapi_spec_matches_routes() {
    let server_src: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/server.rs"));
    let openapi_src: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.yaml"));

    let routes: BTreeSet<(String, String)> = extract_routes(server_src);
    let spec: BTreeSet<(String, String)> = extract_spec_paths(openapi_src);

    // Extraction sanity: a parser that silently under-collects (a
    // format change breaking the scan) must fail loudly, not pass by
    // comparing two empty sets.
    assert!(
        routes.len() >= 115,
        "route extraction looks broken: only {} (method, path) pairs found in server.rs (expected ~120+)",
        routes.len()
    );
    assert!(
        spec.len() >= 80,
        "spec extraction looks broken: only {} (method, path) pairs found in openapi.yaml (expected ~90)",
        spec.len()
    );

    let allowlist: BTreeSet<(String, String)> = to_set(ROUTE_ALLOWLIST);
    let known_drift: BTreeSet<(String, String)> = to_set(KNOWN_DRIFT);

    // Non-REST routes are dropped from the router side before comparing.
    let routes_effective: BTreeSet<(String, String)> =
        routes.difference(&allowlist).cloned().collect();

    let mut missing_from_spec: Vec<(String, String)> = routes_effective
        .difference(&spec)
        .filter(|pair| !known_drift.contains(*pair))
        .cloned()
        .collect();
    let mut spec_without_route: Vec<(String, String)> = spec
        .difference(&routes_effective)
        .filter(|pair| !known_drift.contains(*pair))
        .cloned()
        .collect();
    missing_from_spec.sort();
    spec_without_route.sort();

    if !missing_from_spec.is_empty() || !spec_without_route.is_empty() {
        let mut msg = String::from("\nAPI contract drift detected (backlog #42c).\n");
        msg.push_str(&format!(
            "\nRoutes missing from openapi.yaml ({}):\n",
            missing_from_spec.len()
        ));
        for (method, path) in &missing_from_spec {
            msg.push_str(&format!("  {method:<7} {path}\n"));
        }
        msg.push_str(&format!(
            "\nOpenapi paths with no route ({}):\n",
            spec_without_route.len()
        ));
        for (method, path) in &spec_without_route {
            msg.push_str(&format!("  {method:<7} {path}\n"));
        }
        msg.push_str(
            "\nEither document the route in openapi.yaml, remove the stale spec entry, \
             or - if the route is genuinely not a REST operation - add it to \
             ROUTE_ALLOWLIST with justification.\n",
        );
        panic!("{msg}");
    }
}

#[test]
fn automation_openapi_matches_automation_routes() {
    let router_src: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/automation/router.rs"
    ));
    let spec_src: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/openapi-automation.yaml"
    ));

    let routes: BTreeSet<(String, String)> = extract_routes(router_src);
    let spec: BTreeSet<(String, String)> = extract_spec_paths(spec_src);

    // Same extraction sanity as the management gate: two empty sets
    // compare equal, and a silently broken parser must not read as a
    // clean contract.
    assert!(
        !routes.is_empty(),
        "route extraction looks broken: no (method, path) pair found in src/automation/router.rs"
    );
    assert!(
        !spec.is_empty(),
        "spec extraction looks broken: no (method, path) pair found in openapi-automation.yaml"
    );

    // No allowlist and no known-drift list here. The automation plane
    // serves REST operations only, and it is new enough to carry no
    // pre-existing debt; either list would be a place to hide drift
    // that has no reason to exist yet.
    let mut missing_from_spec: Vec<(String, String)> = routes.difference(&spec).cloned().collect();
    let mut spec_without_route: Vec<(String, String)> = spec.difference(&routes).cloned().collect();
    missing_from_spec.sort();
    spec_without_route.sort();

    if !missing_from_spec.is_empty() || !spec_without_route.is_empty() {
        let mut msg = String::from("\nAutomation API contract drift detected.\n");
        msg.push_str(&format!(
            "\nRoutes missing from openapi-automation.yaml ({}):\n",
            missing_from_spec.len()
        ));
        for (method, path) in &missing_from_spec {
            msg.push_str(&format!("  {method:<7} {path}\n"));
        }
        msg.push_str(&format!(
            "\nOpenapi paths with no route ({}):\n",
            spec_without_route.len()
        ));
        for (method, path) in &spec_without_route {
            msg.push_str(&format!("  {method:<7} {path}\n"));
        }
        msg.push_str(
            "\nEither document the route in openapi-automation.yaml or remove the \
             stale spec entry. Automation paths never belong in openapi.yaml: that \
             document describes the management plane, a different socket with a \
             different credential.\n",
        );
        panic!("{msg}");
    }
}

#[test]
fn automation_openapi_declares_the_scope_the_gate_enforces() {
    let spec_src: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/openapi-automation.yaml"
    ));

    let declared: BTreeMap<(String, String), String> = extract_declared_scopes(spec_src);
    assert!(
        !declared.is_empty(),
        "no x-required-scope found in openapi-automation.yaml: every documented \
         operation must name the scope it requires"
    );

    let documented: BTreeSet<(String, String)> = extract_spec_paths(spec_src);
    let without_scope: Vec<&(String, String)> = documented
        .iter()
        .filter(|pair| !declared.contains_key(*pair))
        .collect();
    assert!(
        without_scope.is_empty(),
        "documented operations with no x-required-scope: {without_scope:?}. \
         A path with no declared scope is reachable by no token, so leaving it \
         undocumented promises a caller something the scope gate refuses."
    );

    for ((method, path), spelled) in &declared {
        let method: http::Method = method.parse().expect("documented method parses");
        let enforced: Option<String> =
            documented_spelling(lorica_api::automation::required_scope(&method, path));
        assert_eq!(
            enforced.as_deref(),
            Some(spelled.as_str()),
            "openapi-automation.yaml says {method} {path} needs {spelled:?}, \
             but the scope gate enforces {enforced:?}"
        );
    }
}

/// The automation reads whose query vocabulary is the management
/// plane's, and the struct each one takes it from.
///
/// `(path, source file, struct name)`. The read surface reuses these
/// filter structs verbatim so it never owns a filter vocabulary of its
/// own, which means the published document is a TRANSCRIPTION of Rust
/// field names: a filter added to the dashboard's log query becomes an
/// undocumented parameter of a network-facing API, and a renamed one
/// makes the document false, with nothing red in between. The test
/// below is what turns red.
const AUTOMATION_REUSED_QUERIES: &[(&str, &str, &str)] = &[
    ("/automation/v1/logs", "/src/logs.rs", "LogsQuery"),
    ("/automation/v1/waf/events", "/src/waf.rs", "WafEventsQuery"),
    (
        "/automation/v1/routes",
        "/src/routes/crud.rs",
        "ListRoutesQuery",
    ),
];

/// The page parameters every automation collection adds to whatever
/// filters it reuses.
///
/// `limit` is named by both sides: the filter structs carry one and
/// this surface overrides it with its own window, so the documented
/// parameter is the page's whatever the struct says.
const PAGE_PARAMETERS: &[&str] = &["limit", "offset"];

#[test]
fn automation_openapi_documents_the_query_vocabulary_the_handlers_reuse() {
    let spec_src: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/openapi-automation.yaml"
    ));
    let sources: BTreeMap<&str, &str> = BTreeMap::from([
        (
            "/src/logs.rs",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/logs.rs")),
        ),
        (
            "/src/waf.rs",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/waf.rs")),
        ),
        (
            "/src/routes/crud.rs",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/routes/crud.rs")),
        ),
    ]);

    let components = extract_parameter_components(spec_src);
    assert!(
        !components.is_empty(),
        "parameter-component extraction looks broken: no entry found under \
         components.parameters in openapi-automation.yaml"
    );
    let documented = extract_operation_query_parameters(spec_src, &components);
    assert!(
        !documented.is_empty(),
        "query-parameter extraction looks broken: no documented query parameter \
         found in openapi-automation.yaml"
    );

    for (path, file, struct_name) in AUTOMATION_REUSED_QUERIES {
        let src = sources.get(file).expect("the source is included above");
        let mut expected: BTreeSet<String> = serde_field_names(src, struct_name);
        assert!(
            !expected.is_empty(),
            "field extraction looks broken: no field found in `pub struct {struct_name}` \
             in {file}. The scan expects `pub struct {struct_name} {{` and `pub <name>:` \
             lines until the closing brace."
        );
        expected.extend(PAGE_PARAMETERS.iter().map(|p| (*p).to_string()));

        let key = ("GET".to_string(), (*path).to_string());
        let actual: &BTreeSet<String> = documented
            .get(&key)
            .unwrap_or_else(|| panic!("{path} documents no query parameters at all"));

        let missing: Vec<&String> = expected.difference(actual).collect();
        let extra: Vec<&String> = actual.difference(&expected).collect();
        if !missing.is_empty() || !extra.is_empty() {
            let mut msg = format!("\nAutomation query-parameter drift on GET {path}.\n");
            msg.push_str(&format!(
                "\nAccepted by {struct_name} ({file}) and undocumented ({}):\n",
                missing.len()
            ));
            for name in &missing {
                msg.push_str(&format!("  {name}\n"));
            }
            msg.push_str(&format!(
                "\nDocumented and not a field of {struct_name} ({}):\n",
                extra.len()
            ));
            for name in &extra {
                msg.push_str(&format!("  {name}\n"));
            }
            msg.push_str(
                "\nThe automation read takes this filter struct verbatim, so the struct \
                 is the contract and the document restates it. Add the parameter to \
                 openapi-automation.yaml, or remove the stale entry. A filter the \
                 handler accepts and the document omits is an undocumented parameter of \
                 a network-facing API; one the document names and the handler ignores \
                 is a promise nothing keeps.\n",
            );
            panic!("{msg}");
        }
    }
}

/// What a caller may send to each automation write, pinned per
/// `(METHOD, path)` as the wire field names of the request struct the
/// handler deserialises (Story 11.2).
///
/// The read side pins what each answer carries
/// (`AUTOMATION_READ_FIELD_NAMES` in `src/tests.rs`); this is the
/// request side of the same contract. Every write on this plane takes
/// the management model's own body, so a field added to
/// `CreateRouteRequest` for the dashboard becomes, with no other
/// change, a field a network-reachable token may set. That is not
/// wrong, it is a decision, and this list is what turns it into one:
/// the test below diffs it both ways against the struct and names what
/// to do. Sorted, and nothing writes it.
///
/// Top-level names only. A nested body (`path_rules[]`, `backends[]`)
/// is the management model's inner shape, documented against the
/// management path.
const AUTOMATION_WRITE_FIELD_NAMES: &[(&str, &str, &[&str])] = &[
    (
        "POST",
        "/automation/v1/backends",
        &[
            "address",
            "group_name",
            "h2_upstream",
            "health_check_enabled",
            "health_check_interval_s",
            "health_check_path",
            "managed_by",
            "name",
            "tls_skip_verify",
            "tls_sni",
            "tls_upstream",
            "weight",
        ],
    ),
    (
        "PUT",
        "/automation/v1/backends/{}",
        &[
            "address",
            "group_name",
            "h2_upstream",
            "health_check_enabled",
            "health_check_interval_s",
            "health_check_path",
            "managed_by",
            "name",
            "tls_skip_verify",
            "tls_sni",
            "tls_upstream",
            "weight",
        ],
    ),
    (
        "PUT",
        "/automation/v1/environments/{}",
        &[
            "backends",
            "certificate",
            "force_https",
            "hostname",
            "labels",
            "path_prefix",
            "ttl_seconds",
            "waf_enabled",
        ],
    ),
    (
        "POST",
        "/automation/v1/routes",
        &[
            "access_log_enabled",
            "add_path_prefix",
            "ai_bot_policy",
            "ai_bot_spoofed_fallback",
            "auto_ban_duration_s",
            "auto_ban_threshold",
            "backend_ids",
            "basic_auth_password",
            "basic_auth_username",
            "bot_protection",
            "cache_enabled",
            "cache_max_bytes",
            "cache_ttl_s",
            "cache_vary_headers",
            "certificate_id",
            "compression_enabled",
            "connect_timeout_s",
            "cors_allowed_methods",
            "cors_allowed_origins",
            "cors_max_age_s",
            "error_page_html",
            "force_https",
            "forward_auth",
            "geoip",
            "group_name",
            "header_rules",
            "hostname",
            "hostname_aliases",
            "ip_allowlist",
            "ip_denylist",
            "load_balancing",
            "maintenance_mode",
            "managed_by",
            "max_connections",
            "max_request_body_bytes",
            "mirror",
            "mtls",
            "node_selector",
            "path_prefix",
            "path_rewrite_pattern",
            "path_rewrite_replacement",
            "path_rules",
            "proxy_headers",
            "proxy_headers_remove",
            "rate_limit",
            "rate_limit_burst",
            "rate_limit_rps",
            "read_timeout_s",
            "redirect_hostname",
            "redirect_to",
            "response_headers",
            "response_headers_remove",
            "response_rewrite",
            "retry_attempts",
            "retry_on_methods",
            "return_status",
            "security_headers",
            "send_timeout_s",
            "serve_robots_txt",
            "slowloris_threshold_ms",
            "stale_if_error_s",
            "stale_while_revalidate_s",
            "sticky_session",
            "strip_path_prefix",
            "traffic_splits",
            "waf_body_scan_max_bytes",
            "waf_enabled",
            "waf_mode",
            "websocket_enabled",
        ],
    ),
    (
        "PUT",
        "/automation/v1/routes/{}",
        &[
            "access_log_enabled",
            "add_path_prefix",
            "ai_bot_policy",
            "ai_bot_spoofed_fallback",
            "ai_bot_spoofed_fallback_inherit",
            "auto_ban_duration_s",
            "auto_ban_threshold",
            "backend_ids",
            "basic_auth_password",
            "basic_auth_username",
            "bot_protection",
            "bot_protection_disable",
            "cache_enabled",
            "cache_max_bytes",
            "cache_ttl_s",
            "cache_vary_headers",
            "certificate_id",
            "compression_enabled",
            "connect_timeout_s",
            "cors_allowed_methods",
            "cors_allowed_origins",
            "cors_max_age_s",
            "enabled",
            "error_page_html",
            "force_https",
            "forward_auth",
            "geoip",
            "group_name",
            "header_rules",
            "hostname",
            "hostname_aliases",
            "ip_allowlist",
            "ip_denylist",
            "load_balancing",
            "maintenance_mode",
            "managed_by",
            "max_connections",
            "max_request_body_bytes",
            "mirror",
            "mtls",
            "node_selector",
            "path_prefix",
            "path_rewrite_pattern",
            "path_rewrite_replacement",
            "path_rules",
            "proxy_headers",
            "proxy_headers_remove",
            "rate_limit",
            "rate_limit_burst",
            "rate_limit_rps",
            "read_timeout_s",
            "redirect_hostname",
            "redirect_to",
            "response_headers",
            "response_headers_remove",
            "response_rewrite",
            "retry_attempts",
            "retry_on_methods",
            "return_status",
            "security_headers",
            "send_timeout_s",
            "serve_robots_txt",
            "slowloris_threshold_ms",
            "stale_if_error_s",
            "stale_while_revalidate_s",
            "sticky_session",
            "strip_path_prefix",
            "traffic_splits",
            "waf_body_scan_max_bytes",
            "waf_enabled",
            "waf_mode",
            "websocket_enabled",
        ],
    ),
    (
        "PUT",
        "/automation/v1/routes/{}/certificate",
        &["certificate_id"],
    ),
];

/// The one path on the automation plane whose body is not a resource:
/// a JSON-RPC message, documented as such and pinned by the MCP core's
/// own tests rather than as a field set.
const AUTOMATION_MCP_PATH: &str = "/automation/v1/mcp";

/// A field name no automation write may accept, matched as a substring
/// of the top-level name (Story 11.2 AC #6).
const KEY_MATERIAL_MARKERS: &[&str] = &["pem", "private_key", "csr"];

/// The automation module declaring `pub async fn <handler>(`, among
/// the two that mount a write: the router names some handlers through
/// `super::<module>::` and imports others by name, so the module is
/// found from the handler rather than read off the route.
fn automation_handler_source(handler: &str) -> Option<(&'static str, &'static str)> {
    let opening = format!("pub async fn {handler}(");
    [
        (
            "/src/automation/write.rs",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/automation/write.rs"
            )),
        ),
        (
            "/src/automation/environments.rs",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/automation/environments.rs"
            )),
        ),
    ]
    .into_iter()
    .find(|(_, src)| src.contains(&opening))
}

/// Every source a request struct an automation write takes is declared
/// in: the automation modules and the management modules whose body
/// the writes reuse verbatim.
fn request_struct_sources() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "/src/automation/write.rs",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/automation/write.rs"
            )),
        ),
        (
            "/src/automation/environments.rs",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/automation/environments.rs"
            )),
        ),
        (
            "/src/routes/crud.rs",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/routes/crud.rs")),
        ),
        (
            "/src/backends.rs",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/backends.rs")),
        ),
    ]
}

/// Every non-`GET` `(METHOD, normalised path, handler)` the automation
/// router mounts, read off the `.route(` calls the way
/// [`extract_routes`] reads the paths: the handler is the last segment
/// of the token after each method combinator.
fn extract_write_routes(src: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let marker = ".route(";
    let mut from = 0usize;
    while let Some(rel) = src[from..].find(marker) {
        let open_paren = from + rel + marker.len() - 1;
        let (span, after) = balanced_span(src, open_paren);
        from = after;
        let Some(path) = first_string_literal(&span) else {
            continue;
        };
        let normalized = normalize_path(&path);
        for method in ["post", "put", "delete", "patch"] {
            for handler in handlers_after_combinator(&span, method) {
                let name = handler.rsplit("::").next().unwrap_or_default().to_string();
                out.push((method.to_uppercase(), normalized.clone(), name));
            }
        }
    }
    out
}

/// The handler tokens a route span applies `method(` to, on a word
/// boundary, the way [`method_combinators`] finds the method itself.
fn handlers_after_combinator(span: &str, method: &str) -> Vec<String> {
    let bytes = span.as_bytes();
    let mut found = Vec::new();
    let mut search = 0usize;
    while let Some(rel) = span[search..].find(method) {
        let idx = search + rel;
        let after = idx + method.len();
        search = after;
        let boundary_before = idx == 0 || !is_ident_byte(bytes[idx - 1]);
        let boundary_after = after >= bytes.len() || !is_ident_byte(bytes[after]);
        if !boundary_before || !boundary_after {
            continue;
        }
        let mut j = after;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j < bytes.len() && bytes[j] == b'(' {
            let (inner, _) = balanced_span(span, j);
            found.push(inner.trim().to_string());
        }
    }
    found
}

/// The type a handler's `Json<...>` extractor deserialises, or `None`
/// when the handler takes no JSON body.
fn handler_body_struct(module_src: &str, handler: &str) -> Option<String> {
    let opening = format!("pub async fn {handler}(");
    let at = module_src.find(&opening)?;
    let (parameters, _) = balanced_span(module_src, at + opening.len() - 1);
    let (_, after) = parameters.split_once("Json<")?;
    let (name, _) = after.split_once('>')?;
    Some(name.trim().to_string())
}

/// The source declaring `pub struct <name> {`, among
/// [`request_struct_sources`].
fn source_declaring(name: &str) -> Option<(&'static str, &'static str)> {
    let opening = format!("pub struct {name} {{");
    request_struct_sources()
        .into_iter()
        .find(|(_, src)| src.contains(&opening))
}

#[test]
fn every_automation_write_accepts_exactly_the_field_names_this_surface_committed_to() {
    let router_src: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/automation/router.rs"
    ));
    let writes = extract_write_routes(router_src);
    assert!(
        writes.len() >= 8,
        "write-route extraction looks broken: only {} non-GET routes found in \
         src/automation/router.rs",
        writes.len()
    );

    let mut pinned_and_seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut drift = String::new();
    for (method, path, handler) in &writes {
        if path == AUTOMATION_MCP_PATH {
            continue;
        }
        let (_, module_src) = automation_handler_source(handler).unwrap_or_else(|| {
            panic!("{method} {path} is handled by `{handler}`, which no automation module this test reads declares")
        });
        let body = handler_body_struct(module_src, handler);
        if method == "DELETE" {
            assert_eq!(
                body, None,
                "{method} {path}: a delete names its resource in the path and takes no body"
            );
            continue;
        }
        let Some(struct_name) = body else {
            if method == "POST" && path.ends_with("/renew") {
                // The one bodiless POST: an action on a named resource.
                continue;
            }
            panic!("{method} {path}: `{handler}` takes no `Json<...>` body, so its field set cannot be pinned");
        };
        let (file, src) = source_declaring(&struct_name).unwrap_or_else(|| {
            panic!("`pub struct {struct_name}` is declared in no source this test reads")
        });
        let accepted: BTreeSet<String> = serde_field_names(src, &struct_name);
        assert!(
            !accepted.is_empty(),
            "field extraction looks broken: no field found in `pub struct {struct_name}` in {file}"
        );

        let key = (method.clone(), path.clone());
        let Some((_, _, committed)) = AUTOMATION_WRITE_FIELD_NAMES
            .iter()
            .find(|(m, p, _)| *m == method.as_str() && *p == path.as_str())
        else {
            drift.push_str(&format!(
                "\n{method} {path} takes `{struct_name}` ({file}) and is not pinned in \
                 AUTOMATION_WRITE_FIELD_NAMES at all. It accepts: {}\n",
                accepted.iter().cloned().collect::<Vec<_>>().join(", ")
            ));
            continue;
        };
        pinned_and_seen.insert(key);
        let committed: BTreeSet<String> = committed.iter().map(|n| (*n).to_string()).collect();
        let newly_accepted: Vec<&String> = accepted.difference(&committed).collect();
        let no_longer_accepted: Vec<&String> = committed.difference(&accepted).collect();
        if !newly_accepted.is_empty() || !no_longer_accepted.is_empty() {
            drift.push_str(&format!("\n{method} {path} (`{struct_name}` in {file}):\n"));
            drift.push_str(&format!(
                "  accepted by the handler and not pinned ({}):\n",
                newly_accepted.len()
            ));
            for name in &newly_accepted {
                drift.push_str(&format!("    {name}\n"));
            }
            drift.push_str(&format!(
                "  pinned and no longer accepted ({}):\n",
                no_longer_accepted.len()
            ));
            for name in &no_longer_accepted {
                drift.push_str(&format!("    {name}\n"));
            }
        }
    }

    let stale: Vec<String> = AUTOMATION_WRITE_FIELD_NAMES
        .iter()
        .filter(|(m, p, _)| !pinned_and_seen.contains(&((*m).to_string(), (*p).to_string())))
        .map(|(m, p, _)| format!("{m} {p}"))
        .collect();
    if !stale.is_empty() {
        drift.push_str(&format!(
            "\nPinned in AUTOMATION_WRITE_FIELD_NAMES and mounted by no handler with a body: {}\n",
            stale.join(", ")
        ));
    }

    assert!(
        drift.is_empty(),
        "\nAutomation write surface: what a caller may send moved.\n{drift}\n\
         A name on an \"accepted and not pinned\" list arrived here because a management \
         request model grew a field, not because anyone decided a network-reachable token \
         may set it. Decide: either it belongs on this plane, and you add it to \
         AUTOMATION_WRITE_FIELD_NAMES in tests/openapi_contract.rs, sorted; or it does not, \
         and the automation write takes a narrower body. The mirror list is a field the \
         handler stopped accepting, which is a contract change for whoever sends it.\n"
    );
}

/// The `$ref` a documented operation's request body points at, keyed
/// by `(METHOD, path)`; an operation with no body or an inline schema
/// is absent.
fn extract_request_body_refs(yaml: &str) -> BTreeMap<(String, String), String> {
    let mut out = BTreeMap::new();
    let mut in_paths = false;
    let mut current_path: Option<String> = None;
    let mut current_method: Option<String> = None;
    let mut in_body = false;

    for line in yaml.lines() {
        let first = line.as_bytes().first().copied();
        if let Some(c) = first {
            if c != b' ' && c != b'#' {
                in_paths = line.starts_with("paths:");
                current_path = None;
                current_method = None;
                in_body = false;
                continue;
            }
        } else {
            continue;
        }
        if !in_paths {
            continue;
        }
        if let Some(rest) = strip_exact_indent(line, 2) {
            if let Some(key) = rest.trim_end().strip_suffix(':') {
                if key.starts_with('/') {
                    current_path = Some(normalize_path(key));
                    current_method = None;
                }
            }
            in_body = false;
            continue;
        }
        if let Some(rest) = strip_exact_indent(line, 4) {
            let key = rest.trim_end().strip_suffix(':').unwrap_or("");
            current_method = HTTP_METHODS.contains(&key).then(|| key.to_uppercase());
            in_body = false;
            continue;
        }
        if let Some(rest) = strip_exact_indent(line, 6) {
            in_body = rest.trim_end() == "requestBody:";
            continue;
        }
        if !in_body {
            continue;
        }
        if let Some((_, reference)) = line.split_once("$ref:") {
            if let (Some(path), Some(method)) = (&current_path, &current_method) {
                let name = reference
                    .trim()
                    .trim_matches('"')
                    .rsplit('/')
                    .next()
                    .unwrap_or_default()
                    .to_string();
                out.insert((method.clone(), path.clone()), name);
            }
        }
    }
    out
}

/// The property names of `components.schemas.<name>`, or an empty set
/// for a schema that declares none.
fn extract_schema_properties(yaml: &str, name: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut in_components = false;
    let mut in_schemas = false;
    let mut in_named = false;
    let mut in_properties = false;

    for line in yaml.lines() {
        let first = line.as_bytes().first().copied();
        if let Some(c) = first {
            if c != b' ' && c != b'#' {
                in_components = line.starts_with("components:");
                in_schemas = false;
                in_named = false;
                in_properties = false;
                continue;
            }
        } else {
            continue;
        }
        if !in_components {
            continue;
        }
        if let Some(rest) = strip_exact_indent(line, 2) {
            in_schemas = rest.trim_end() == "schemas:";
            in_named = false;
            in_properties = false;
            continue;
        }
        if !in_schemas {
            continue;
        }
        if let Some(rest) = strip_exact_indent(line, 4) {
            in_named = rest.trim_end() == format!("{name}:");
            in_properties = false;
            continue;
        }
        if !in_named {
            continue;
        }
        if let Some(rest) = strip_exact_indent(line, 6) {
            in_properties = rest.trim_end() == "properties:";
            continue;
        }
        if in_properties {
            if let Some(rest) = strip_exact_indent(line, 8) {
                if let Some(property) = rest.trim_end().strip_suffix(':') {
                    out.insert(property.to_string());
                }
            }
        }
    }
    out
}

#[test]
fn no_automation_write_accepts_key_material() {
    // Story 11.2 AC #6, asserted three ways rather than promised.
    let router_src: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/automation/router.rs"
    ));
    let spec_src: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/openapi-automation.yaml"
    ));

    // 1. The management paths that take a PEM body are mounted on this
    //    listener under no verb, and the matrix declares nothing for
    //    them, so two things refuse them.
    let mounted = extract_routes(router_src);
    for (method, path) in [
        ("POST", "/automation/v1/certificates"),
        ("PUT", "/automation/v1/certificates/{}"),
        ("POST", "/automation/v1/certificates/self-signed"),
    ] {
        assert!(
            !mounted.contains(&(method.to_string(), path.to_string())),
            "{method} {path} is mounted on the automation listener"
        );
        let verb: http::Method = method.parse().expect("a method");
        assert_eq!(
            lorica_api::automation::required_scope(&verb, path),
            None,
            "{method} {path} is declared in the scope matrix"
        );
    }

    // 2. No request struct an automation write deserialises has a
    //    top-level field that could carry key material.
    let writes = extract_write_routes(router_src);
    let mut structs_checked = 0usize;
    for (method, path, handler) in &writes {
        if path == AUTOMATION_MCP_PATH {
            continue;
        }
        let Some((_, module_src)) = automation_handler_source(handler) else {
            continue;
        };
        let Some(struct_name) = handler_body_struct(module_src, handler) else {
            continue;
        };
        let (file, src) = source_declaring(&struct_name).unwrap_or_else(|| {
            panic!("`pub struct {struct_name}` is declared nowhere this test reads")
        });
        let accepted = serde_field_names(src, &struct_name);
        assert!(!accepted.is_empty(), "{struct_name} in {file} has no field");
        structs_checked += 1;
        for name in &accepted {
            for marker in KEY_MATERIAL_MARKERS {
                assert!(
                    !name.contains(marker),
                    "{method} {path} accepts `{name}` (`{struct_name}` in {file}), which \
                     matches the key-material marker `{marker}`. Key material enters the \
                     node through the management API, by a human, never through a token."
                );
            }
        }
    }
    assert!(
        structs_checked >= 5,
        "only {structs_checked} write bodies were checked; the scan is reading a shape the \
         router no longer has"
    );

    // 3. The document says the same: no documented write body names a
    //    key-material property, and the certificate binding's body is
    //    the one field it is.
    let bodies = extract_request_body_refs(spec_src);
    assert!(
        bodies.len() >= 6,
        "request-body extraction looks broken: only {} documented bodies found",
        bodies.len()
    );
    let mut documented_properties = 0usize;
    for ((method, path), schema) in &bodies {
        if path == AUTOMATION_MCP_PATH {
            continue;
        }
        let properties = extract_schema_properties(spec_src, schema);
        documented_properties += properties.len();
        for property in &properties {
            for marker in KEY_MATERIAL_MARKERS {
                assert!(
                    !property.contains(marker),
                    "openapi-automation.yaml documents `{property}` on {method} {path} \
                     (schema {schema}), which matches `{marker}`"
                );
            }
        }
    }
    assert!(
        documented_properties > 0,
        "no documented write body declares a property; the schema scan went blind"
    );
    assert_eq!(
        extract_schema_properties(spec_src, "BindCertificateRequest"),
        BTreeSet::from(["certificate_id".to_string()]),
        "the certificate binding takes the id and nothing else"
    );
}

/// Each `components.parameters` entry as `component name -> (name, in)`.
fn extract_parameter_components(yaml: &str) -> BTreeMap<String, (String, String)> {
    let mut out: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut in_components = false;
    let mut in_parameters = false;
    let mut current: Option<String> = None;

    for line in yaml.lines() {
        let first = line.as_bytes().first().copied();
        if let Some(c) = first {
            if c != b' ' && c != b'#' {
                in_components = line.starts_with("components:");
                in_parameters = false;
                current = None;
                continue;
            }
        } else {
            continue;
        }
        if !in_components {
            continue;
        }

        if let Some(rest) = strip_exact_indent(line, 2) {
            in_parameters = rest.trim_end() == "parameters:";
            current = None;
            continue;
        }
        if !in_parameters {
            continue;
        }

        if let Some(rest) = strip_exact_indent(line, 4) {
            current = rest.trim_end().strip_suffix(':').map(str::to_string);
            continue;
        }
        if let (Some(rest), Some(component)) = (strip_exact_indent(line, 6), current.as_ref()) {
            let entry = out
                .entry(component.clone())
                .or_insert_with(|| (String::new(), String::new()));
            if let Some(value) = rest.trim_end().strip_prefix("name:") {
                entry.0 = value.trim().to_string();
            } else if let Some(value) = rest.trim_end().strip_prefix("in:") {
                entry.1 = value.trim().to_string();
            }
        }
    }
    out
}

/// The `in: query` parameter names each operation documents, `$ref`s to
/// `components.parameters` resolved.
fn extract_operation_query_parameters(
    yaml: &str,
    components: &BTreeMap<String, (String, String)>,
) -> BTreeMap<(String, String), BTreeSet<String>> {
    let mut out: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    let mut in_paths = false;
    let mut current_path: Option<String> = None;
    let mut current_method: Option<String> = None;
    let mut in_parameters = false;
    let mut pending: Option<String> = None;

    for line in yaml.lines() {
        let first = line.as_bytes().first().copied();
        if let Some(c) = first {
            if c != b' ' && c != b'#' {
                in_paths = line.starts_with("paths:");
                current_path = None;
                current_method = None;
                in_parameters = false;
                pending = None;
                continue;
            }
        } else {
            continue;
        }
        if !in_paths {
            continue;
        }

        if let Some(rest) = strip_exact_indent(line, 2) {
            if let Some(key) = rest.trim_end().strip_suffix(':') {
                if key.starts_with('/') {
                    current_path = Some(normalize_path(key));
                    current_method = None;
                }
            }
            in_parameters = false;
            pending = None;
            continue;
        }

        if let Some(rest) = strip_exact_indent(line, 4) {
            let key = rest.trim_end().strip_suffix(':').unwrap_or("");
            current_method = HTTP_METHODS.contains(&key).then(|| key.to_uppercase());
            in_parameters = false;
            pending = None;
            continue;
        }

        if let Some(rest) = strip_exact_indent(line, 6) {
            in_parameters = rest.trim_end() == "parameters:";
            pending = None;
            continue;
        }
        if !in_parameters {
            continue;
        }

        let (Some(path), Some(method)) = (&current_path, &current_method) else {
            continue;
        };
        let key = (method.clone(), path.clone());

        if let Some(rest) = strip_exact_indent(line, 8) {
            pending = None;
            let item = rest.trim_end();
            if let Some(reference) = item.strip_prefix("- $ref:") {
                let component = reference
                    .trim()
                    .trim_matches('"')
                    .rsplit('/')
                    .next()
                    .unwrap_or_default();
                if let Some((name, location)) = components.get(component) {
                    if location == "query" {
                        out.entry(key).or_default().insert(name.clone());
                    }
                }
            } else if let Some(name) = item.strip_prefix("- name:") {
                pending = Some(name.trim().to_string());
            }
            continue;
        }

        if let (Some(rest), Some(name)) = (strip_exact_indent(line, 10), pending.as_ref()) {
            if let Some(location) = rest.trim_end().strip_prefix("in:") {
                if location.trim() == "query" {
                    out.entry(key).or_default().insert(name.clone());
                }
                pending = None;
            }
        }
    }
    out
}

/// The wire names of every field of `pub struct <name>` in `src`.
///
/// A `#[serde(rename = "...")]` on a field wins, the way it does on the
/// wire; everything else is the identifier.
fn serde_field_names(src: &str, struct_name: &str) -> BTreeSet<String> {
    let opening = format!("pub struct {struct_name} {{");
    let Some((_, body)) = src.split_once(&opening) else {
        return BTreeSet::new();
    };
    let Some((body, _)) = body.split_once("\n}") else {
        return BTreeSet::new();
    };

    let mut out = BTreeSet::new();
    let mut renamed: Option<String> = None;
    for line in body.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("#[serde(rename = \"") {
            renamed = rest.split('"').next().map(str::to_string);
            continue;
        }
        let Some(rest) = line.strip_prefix("pub ") else {
            continue;
        };
        let Some((name, _)) = rest.split_once(':') else {
            continue;
        };
        out.insert(renamed.take().unwrap_or_else(|| name.trim().to_string()));
    }
    out
}

/// The `x-required-scope` value that documents a path any authenticated
/// caller reaches.
///
/// A sentinel and not a scope: the gate's third state has no scope to
/// name, and leaving the extension off instead would be indistinguishable
/// from forgetting it, which the assertion above refuses. The spelling
/// carries no colon, so it cannot collide with a scope, every one of
/// which has one.
const ANY_LIVE_TOKEN: &str = "any-live-token";

/// How the document spells what the gate enforces, or `None` for a path
/// the gate declares nothing for and therefore refuses to everyone.
fn documented_spelling(
    enforced: Option<lorica_api::automation::ScopeRequirement>,
) -> Option<String> {
    match enforced? {
        lorica_api::automation::ScopeRequirement::AnyLiveToken => Some(ANY_LIVE_TOKEN.to_string()),
        lorica_api::automation::ScopeRequirement::Scope(scope) => Some(
            serde_json::to_value(scope)
                .expect("scope serialises")
                .as_str()
                .expect("scope serialises to a string")
                .to_string(),
        ),
    }
}

/// Collect the `x-required-scope` an operation declares, keyed by the
/// `(METHOD, path)` pair that owns it.
///
/// Same strict-indent hand-parse as [`extract_spec_paths`], one level
/// deeper: the extension is a 6-space-indented child of the operation.
fn extract_declared_scopes(yaml: &str) -> BTreeMap<(String, String), String> {
    const MARKER: &str = "x-required-scope:";

    let mut out = BTreeMap::new();
    let mut in_paths = false;
    let mut current_path: Option<String> = None;
    let mut current_method: Option<String> = None;

    for line in yaml.lines() {
        let first = line.as_bytes().first().copied();
        if let Some(c) = first {
            if c != b' ' && c != b'#' {
                in_paths = line.starts_with("paths:");
                current_path = None;
                current_method = None;
                continue;
            }
        } else {
            continue; // blank line
        }
        if !in_paths {
            continue;
        }

        if let Some(rest) = strip_exact_indent(line, 2) {
            if let Some(key) = rest.trim_end().strip_suffix(':') {
                if key.starts_with('/') {
                    current_path = Some(normalize_path(key));
                    current_method = None;
                }
            }
            continue;
        }

        if let Some(rest) = strip_exact_indent(line, 4) {
            if let Some(key) = rest.trim_end().strip_suffix(':') {
                if HTTP_METHODS.contains(&key) {
                    current_method = Some(key.to_uppercase());
                } else {
                    current_method = None;
                }
            }
            continue;
        }

        if let Some(rest) = strip_exact_indent(line, 6) {
            if let Some(value) = rest.trim_end().strip_prefix(MARKER) {
                if let (Some(path), Some(method)) = (&current_path, &current_method) {
                    out.insert(
                        (method.clone(), path.clone()),
                        value.trim().trim_matches('"').to_string(),
                    );
                }
            }
        }
    }
    out
}

/// Collapse an allow/known-drift slice into an owned set.
fn to_set(pairs: &[(&str, &str)]) -> BTreeSet<(String, String)> {
    pairs
        .iter()
        .map(|(m, p)| (m.to_string(), p.to_string()))
        .collect()
}

/// Replace every `{param}` segment with the bare placeholder `{}` so
/// parameter-name spelling does not count as contract drift.
fn normalize_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut in_brace = false;
    for c in path.chars() {
        match c {
            '{' => {
                in_brace = true;
                out.push('{');
            }
            '}' => {
                in_brace = false;
                out.push('}');
            }
            _ if !in_brace => out.push(c),
            _ => {}
        }
    }
    out
}

/// Extract every `(METHOD, path)` pair from the axum router source.
///
/// Each `.route(` call is delimited by balancing parentheses (with
/// string-literal awareness so parens inside path/bucket strings do not
/// throw off the count). The first string literal inside the call is
/// the path; the method combinators (`get(`, `post(`, ...) applied
/// directly to a handler inside that call are the methods.
fn extract_routes(src: &str) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    let marker = ".route(";
    let mut from = 0usize;
    while let Some(rel) = src[from..].find(marker) {
        // Index of the '(' that opens this `.route(` call.
        let open_paren = from + rel + marker.len() - 1;
        let (span, after) = balanced_span(src, open_paren);
        from = after;

        let Some(path) = first_string_literal(&span) else {
            continue;
        };
        let normalized = normalize_path(&path);
        for method in method_combinators(&span) {
            out.insert((method.to_uppercase(), normalized.clone()));
        }
    }
    out
}

/// Given the byte index of an opening `(`, return the substring between
/// it and its matching `)` (exclusive) plus the index just past the
/// close paren. Double-quoted string literals are skipped so their
/// contents never affect the paren depth.
fn balanced_span(src: &str, open_paren: usize) -> (String, usize) {
    let bytes = src.as_bytes();
    let start_inner = open_paren + 1;
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    let mut i = open_paren;
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_string = false;
            }
        } else {
            match c {
                b'"' => in_string = true,
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return (src[start_inner..i].to_string(), i + 1);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    (src[start_inner..].to_string(), bytes.len())
}

/// Return the content of the first double-quoted string literal in the
/// span, or `None` if there is none.
fn first_string_literal(span: &str) -> Option<String> {
    let bytes = span.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let mut j = i + 1;
            let mut literal = String::new();
            let mut escaped = false;
            while j < bytes.len() {
                let c = bytes[j];
                if escaped {
                    literal.push(c as char);
                    escaped = false;
                } else if c == b'\\' {
                    escaped = true;
                } else if c == b'"' {
                    return Some(literal);
                } else {
                    literal.push(c as char);
                }
                j += 1;
            }
            return None;
        }
        i += 1;
    }
    None
}

/// Collect the HTTP-method combinators (`get(`, `post(`, ...) applied
/// directly to a handler inside a route span.
///
/// A method counts only when the keyword sits on a word boundary and is
/// immediately followed (modulo whitespace) by `(`. That rejects
/// handler names that merely start with a method word (`get_metrics`,
/// `delete_backend`), which are always followed by `_`, never `(`.
fn method_combinators(span: &str) -> Vec<&'static str> {
    let bytes = span.as_bytes();
    let mut found = Vec::new();
    for &method in &HTTP_METHODS {
        let mut search = 0usize;
        while let Some(rel) = span[search..].find(method) {
            let idx = search + rel;
            let after = idx + method.len();
            search = after;

            let boundary_before = idx == 0 || !is_ident_byte(bytes[idx - 1]);
            let boundary_after = after >= bytes.len() || !is_ident_byte(bytes[after]);
            if !boundary_before || !boundary_after {
                continue;
            }
            let mut j = after;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'(' {
                found.push(method);
                break;
            }
        }
    }
    found
}

fn is_ident_byte(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphanumeric()
}

/// Extract every `(METHOD, path)` pair from the OpenAPI document.
///
/// Dependency-free hand-parse of the strictly-indented `paths:` block:
/// path items are 2-space-indented keys starting with `/`, operations
/// are their 4-space-indented HTTP-method children. Anything at another
/// indent (operation bodies, descriptions, schemas) cannot be mistaken
/// for either. Only the `paths:` top-level section is scanned.
fn extract_spec_paths(yaml: &str) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    let mut in_paths = false;
    let mut current_path: Option<String> = None;

    for line in yaml.lines() {
        // Top-level key (column 0, not a comment, not blank) switches
        // sections. Only the `paths:` section is of interest.
        let first = line.as_bytes().first().copied();
        if let Some(c) = first {
            if c != b' ' && c != b'#' {
                in_paths = line.starts_with("paths:");
                current_path = None;
                continue;
            }
        } else {
            continue; // blank line
        }
        if !in_paths {
            continue;
        }

        // Path item: exactly two spaces of indent, key starts with '/'.
        if let Some(rest) = strip_exact_indent(line, 2) {
            let trimmed = rest.trim_end();
            if let Some(key) = trimmed.strip_suffix(':') {
                if key.starts_with('/') {
                    current_path = Some(normalize_path(key));
                }
            }
            continue;
        }

        // Operation: exactly four spaces of indent, key is an HTTP method.
        if let Some(rest) = strip_exact_indent(line, 4) {
            let trimmed = rest.trim_end();
            if let Some(key) = trimmed.strip_suffix(':') {
                if HTTP_METHODS.contains(&key) {
                    if let Some(path) = &current_path {
                        out.insert((key.to_uppercase(), path.clone()));
                    }
                }
            }
        }
    }
    out
}

/// Return the line content after exactly `n` leading spaces, or `None`
/// if the indent is not exactly `n` (fewer spaces, or a deeper nesting
/// whose `n+1`-th character is also a space).
fn strip_exact_indent(line: &str, n: usize) -> Option<&str> {
    let bytes = line.as_bytes();
    if bytes.len() <= n {
        return None;
    }
    if bytes[..n].iter().any(|&b| b != b' ') {
        return None;
    }
    if bytes[n] == b' ' {
        return None; // deeper indent
    }
    Some(&line[n..])
}
