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
//! and a second gate below. Its router side is not scanned: it reads
//! [`lorica_api::automation::route_table`], the declared table both
//! automation routers are built from, so the gate does not depend on
//! how `src/automation/router.rs` is formatted. Its document side reuses
//! the extractors here. What it adds is a scope check, because on that plane the scope a path requires
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
    let spec_src: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/openapi-automation.yaml"
    ));

    let routes: BTreeSet<(String, String)> = automation_routes();
    let spec: BTreeSet<(String, String)> = extract_spec_paths(spec_src);

    // Same extraction sanity as the management gate: two empty sets
    // compare equal, and a silently broken parser must not read as a
    // clean contract.
    assert!(!routes.is_empty(), "the automation route table is empty");
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

/// The values `components.schemas.AutomationScope.enum` lists in an
/// OpenAPI document, in their order.
///
/// Read by indentation: the schema is the four-space key, its body the
/// lines indented deeper, and the enum the `- ` items after its `enum:`
/// key up to the first line that is not one.
fn documented_scope_enum(document: &str) -> Vec<String> {
    let schema: Vec<&str> = document
        .lines()
        .skip_while(|line| line.trim_end() != "    AutomationScope:")
        .skip(1)
        .take_while(|line| line.trim().is_empty() || line.starts_with("     "))
        .collect();
    schema
        .iter()
        .skip_while(|line| line.trim() != "enum:")
        .skip(1)
        .map_while(|line| line.trim().strip_prefix("- "))
        .map(str::to_string)
        .collect()
}

#[test]
fn both_documents_enumerate_every_automation_scope_and_nothing_else() {
    // The scope a token may carry is a published contract on both
    // planes: the management document describes the mint body and the
    // automation document the grants a caller holds. Each restates the
    // enum, so each is held to `AutomationScope::ALL`, both ways and in
    // its order, and a scope added there alone turns this red.
    let expected: Vec<String> = lorica_automation_policy::AutomationScope::ALL
        .iter()
        .map(|scope| scope.as_str().to_string())
        .collect();
    for (name, document) in [
        (
            "openapi.yaml",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.yaml")),
        ),
        (
            "openapi-automation.yaml",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/openapi-automation.yaml"
            )),
        ),
    ] {
        let documented = documented_scope_enum(document);
        assert!(
            !documented.is_empty(),
            "{name}: no AutomationScope enum was read; the parse went blind"
        );
        assert_eq!(
            documented, expected,
            "{name}'s AutomationScope enum and AutomationScope::ALL disagree"
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
/// (`AUTOMATION_READ_FIELD_NAMES` in `src/automation/read/plane_tests.rs`); this is the
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
/// the two that mount a write. The route table carries each handler's
/// path as `std::any::type_name` spells it, which is best-effort and
/// not a file path, so the module is found by the declaration it
/// holds rather than mapped from that spelling.
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
/// in: the automation modules, the management modules whose body the
/// writes reuse verbatim, and the modules declaring the structs those
/// bodies nest, down to the `lorica-config` models a route body embeds
/// as they are.
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
        (
            "/src/settings.rs",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/settings.rs")),
        ),
        (
            "/src/routes/path_rules.rs",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/routes/path_rules.rs"
            )),
        ),
        (
            "/src/routes/header_rules.rs",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/routes/header_rules.rs"
            )),
        ),
        (
            "/src/routes/traffic_splits.rs",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/routes/traffic_splits.rs"
            )),
        ),
        (
            "/src/routes/response_rewrite.rs",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/routes/response_rewrite.rs"
            )),
        ),
        (
            "/src/routes/forward_auth.rs",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/routes/forward_auth.rs"
            )),
        ),
        (
            "/src/routes/mirror.rs",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/routes/mirror.rs")),
        ),
        (
            "/src/routes/mtls.rs",
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/routes/mtls.rs")),
        ),
        (
            "/../lorica-config/src/models/route.rs",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../lorica-config/src/models/route.rs"
            )),
        ),
    ]
}

/// The struct a field's type names once `Option<` and `Vec<` are
/// peeled, and whether a `Vec<` was among them, or `None` for a type
/// that is not one struct: a primitive, a map, a tuple, a generic
/// container this scan does not know.
fn nested_struct_of(field_type: &str) -> Option<(String, bool)> {
    let mut inner = field_type.trim();
    let mut list = false;
    loop {
        if let Some(rest) = inner.strip_prefix("Option<") {
            inner = rest.strip_suffix('>').unwrap_or(rest).trim();
        } else if let Some(rest) = inner.strip_prefix("Vec<") {
            list = true;
            inner = rest.strip_suffix('>').unwrap_or(rest).trim();
        } else {
            break;
        }
    }
    if inner.contains('<') || inner.contains('(') || inner.contains('[') {
        return None;
    }
    let name = inner.rsplit("::").next().unwrap_or(inner).trim();
    if name.is_empty() || !name.starts_with(|c: char| c.is_ascii_uppercase()) {
        return None;
    }
    Some((name.to_string(), list))
}

/// Every field name under `struct_name` at any depth, as
/// `(path, name)` with the path the dotted field chain above it:
/// the fields of every field whose type is a struct one of the
/// sources declares, recursively. `only` narrows the walk at the top
/// level to the fields a tool offers; below that every field of a
/// reached struct is walked, since a tool offers a nested object whole.
fn nested_field_names(
    struct_name: &str,
    only: Option<&BTreeSet<String>>,
    path: &str,
    into: &mut Vec<(String, String)>,
) {
    let Some((_, src)) = source_declaring(struct_name) else {
        return;
    };
    for (name, field_type) in serde_fields_with_types(src, struct_name) {
        if only.is_some_and(|offered| !offered.contains(&name)) {
            continue;
        }
        let here = if path.is_empty() {
            name.clone()
        } else {
            format!("{path}.{name}")
        };
        into.push((path.to_string(), name.clone()));
        if let Some((child, _)) = nested_struct_of(&field_type) {
            if child != struct_name {
                nested_field_names(&child, None, &here, into);
            }
        }
    }
}

/// Every `(METHOD, normalised path)` the automation router mounts,
/// read off the route table both automation routers are built from.
fn automation_routes() -> BTreeSet<(String, String)> {
    lorica_api::automation::route_table()
        .iter()
        .map(|route| (route.method.to_string(), normalize_path(route.path)))
        .collect()
}

/// Every non-`GET` `(METHOD, normalised path, handler)` the automation
/// router mounts, read off the same table: the handler is the last
/// segment of the Rust path the table records for the function mounted.
fn automation_write_routes() -> Vec<(String, String, String)> {
    lorica_api::automation::route_table()
        .iter()
        .filter(|route| route.method != http::Method::GET)
        .map(|route| {
            let name = route.handler.rsplit("::").next().unwrap_or_default();
            (
                route.method.to_string(),
                normalize_path(route.path),
                name.to_string(),
            )
        })
        .collect()
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

/// The one automation write whose body is bounded by an allowlist and
/// not by a struct (Story 11.3): the body type its handler extracts,
/// and the management struct the allowlisted keys are then read into.
///
/// The handler takes the body as a JSON object so it can refuse a key
/// outside `SETTINGS_ALLOWLIST` by name before any value is typed, so
/// there is no struct whose fields are the contract; the allowlist is.
const ALLOWLISTED_BODY: (&str, &str) = ("SettingsPatch", "UpdateSettingsRequest");

/// The keys the admin tier accepts, read from the constant the plane
/// enforces rather than typed again here.
fn settings_allowlist() -> BTreeSet<String> {
    lorica_api::automation::write::SETTINGS_ALLOWLIST
        .iter()
        .map(|setting| setting.name.to_string())
        .collect()
}

/// The field names a write body accepts, and where they were read
/// from: the serde fields of its request struct, or for the settings
/// patch the plane's allowlist, which is what bounds it.
fn accepted_fields(body_type: &str) -> Option<(&'static str, BTreeSet<String>)> {
    if body_type == ALLOWLISTED_BODY.0 {
        return Some(("SETTINGS_ALLOWLIST", settings_allowlist()));
    }
    let (file, src) = source_declaring(body_type)?;
    Some((file, serde_field_names(src, body_type)))
}

/// The struct a body's fields are declared on, for the walks that go
/// below the top level: the body type itself, or for the settings patch
/// the management struct its keys are read into.
fn declaring_struct(body_type: &str) -> &str {
    if body_type == ALLOWLISTED_BODY.0 {
        ALLOWLISTED_BODY.1
    } else {
        body_type
    }
}

#[test]
fn every_automation_write_accepts_exactly_the_field_names_this_surface_committed_to() {
    let writes = automation_write_routes();
    assert!(
        writes.len() >= 8,
        "only {} non-GET routes in the automation route table",
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
        if struct_name == ALLOWLISTED_BODY.0 {
            // The settings patch is committed to by the allowlist the
            // plane enforces, which is its own decision list with a
            // reason per entry; a copy of it here would be a third
            // statement of one list. What is left to pin is that every
            // allowlisted key is one the management struct reads.
            let (_, src) = source_declaring(ALLOWLISTED_BODY.1).unwrap_or_else(|| {
                panic!("`pub struct {}` is declared nowhere", ALLOWLISTED_BODY.1)
            });
            let readable = serde_field_names(src, ALLOWLISTED_BODY.1);
            assert!(!readable.is_empty(), "{} has no field", ALLOWLISTED_BODY.1);
            let unread: Vec<String> = settings_allowlist()
                .difference(&readable)
                .cloned()
                .collect();
            assert!(
                unread.is_empty(),
                "{method} {path}: SETTINGS_ALLOWLIST names keys {} does not read: {unread:?}",
                ALLOWLISTED_BODY.1
            );
            continue;
        }
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
    let spec_src: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/openapi-automation.yaml"
    ));

    // 1. The management paths that take a PEM body are mounted on this
    //    listener under no verb, and the matrix declares nothing for
    //    them, so two things refuse them.
    let mounted = automation_routes();
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
    let writes = automation_write_routes();
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
        let (file, accepted) = accepted_fields(&struct_name).unwrap_or_else(|| {
            panic!("`pub struct {struct_name}` is declared nowhere this test reads")
        });
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

/// The fields of a management request struct the MCP config tier does
/// not offer a model, with the reason for each (Story 11.2).
///
/// `lorica-mcp` declares the field vocabulary of each write tool's
/// body; the test below pins each declaration against the struct the
/// automation handler deserialises, both ways, and this list is the
/// only difference it tolerates. An entry here is a decision, and a
/// field the struct grows lands on the "accepted and not offered" side
/// until somebody makes one.
const NOT_OFFERED_TO_A_MODEL: &[(&str, &str)] = &[
    (
        "managed_by",
        "refused by the plane on input (422): offering it would be a field that always fails",
    ),
    (
        "basic_auth_password",
        "refused by the plane from an automation token (403): a credential a model would be \
         choosing or relaying, crossing the model's host in the clear, and clearing it \
         switches Basic auth off; set in the dashboard by a human",
    ),
    (
        "basic_auth_username",
        "the Basic-auth credential in force may not change from an automation token (403), \
         and a username alone, without the password a token never sends, protects nothing; \
         set in the dashboard by a human",
    ),
    (
        "forward_auth",
        "refused by the plane from an automation token (403): its address is a URL the CIDR \
         grant cannot weigh, and the proxy forwards every downstream Cookie and Authorization \
         header to it; set in the dashboard by a human",
    ),
    (
        "mirror",
        "refused by the plane from an automation token (403): it ships a copy of every request \
         to a second set of backends the preview does not show; set in the dashboard by a human",
    ),
    (
        "mtls",
        "refused by the plane from an automation token (403): a client-authentication trust \
         anchor, the CA bundle whose client certificates the route accepts, which a model \
         reading attacker text must not be able to replace; set in the dashboard by a human",
    ),
    (
        "proxy_headers",
        "refused by the plane from an automation token (403): a static header map to the \
         upstream is where a credential would go; set in the dashboard by a human",
    ),
];

#[test]
fn every_withheld_route_field_is_one_the_tools_do_not_offer() {
    // The plane's refusal list and the tools' absence list are two
    // statements of one decision: a field the plane refuses from every
    // token and a tool still offered would be an argument that always
    // fails.
    let not_offered: BTreeSet<&str> = NOT_OFFERED_TO_A_MODEL
        .iter()
        .map(|(name, _)| *name)
        .collect();
    for (field, _) in lorica_api::automation::write::WITHHELD_ROUTE_FIELDS {
        assert!(
            not_offered.contains(field),
            "{field} is withheld by the plane and not on NOT_OFFERED_TO_A_MODEL"
        );
    }
}

#[test]
fn every_protection_the_plane_holds_is_named_by_the_tool_that_reaches_it() {
    // The direction rule is the plane's (`ROUTE_PROTECTIONS`,
    // `BACKEND_PROTECTIONS`); the update tool's summary is how a model
    // learns it before the 403 does. A control added to either list
    // and offered by the tool without a word in its summary fails here.
    let not_offered: BTreeSet<&str> = NOT_OFFERED_TO_A_MODEL
        .iter()
        .map(|(name, _)| *name)
        .collect();
    let summary = |tool: &str| {
        lorica_mcp::tools::find(tool)
            .unwrap_or_else(|| panic!("{tool} is in the catalogue"))
            .summary
    };
    let routes = summary("lorica_route_update");
    for protection in lorica_api::automation::write::ROUTE_PROTECTIONS {
        for field in protection.fields {
            if not_offered.contains(field) {
                continue;
            }
            assert!(
                routes.contains(&format!("`{field}`")),
                "lorica_route_update does not name `{field}` ({})",
                protection.rule
            );
        }
    }
    let backends = summary("lorica_backend_update");
    for protection in lorica_api::automation::write::BACKEND_PROTECTIONS {
        for field in protection.fields {
            assert!(
                backends.contains(&format!("`{field}`")),
                "lorica_backend_update does not name `{field}` ({})",
                protection.rule
            );
        }
    }
    assert!(
        summary("lorica_backend_create").contains("`tls_skip_verify`"),
        "the create refuses an unverified upstream and does not say so"
    );
}

#[test]
fn the_operator_reference_states_every_protection_rule_as_the_plane_holds_it() {
    // `docs/mcp.md` tabulates the one-way rules an operator reads before
    // handing a model a config-tier token. Each row is rendered from the
    // constant, and the table holds nothing else, so a rule reworded or
    // added on one side alone fails here.
    let reference: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/mcp.md"));
    let section = reference
        .split("### Protections move one way")
        .nth(1)
        .and_then(|rest| rest.split("\n#").next())
        .expect("docs/mcp.md carries the protections section");
    let documented: BTreeSet<String> = section
        .lines()
        .filter(|line| line.starts_with("| `"))
        .map(str::to_string)
        .collect();
    let route_rows = lorica_api::automation::write::ROUTE_PROTECTIONS
        .iter()
        .map(|protection| (protection.fields, protection.rule));
    let backend_rows = lorica_api::automation::write::BACKEND_PROTECTIONS
        .iter()
        .map(|protection| (protection.fields, protection.rule));
    let expected: BTreeSet<String> = route_rows
        .chain(backend_rows)
        .map(|(fields, rule)| {
            let named: Vec<String> = fields.iter().map(|field| format!("`{field}`")).collect();
            format!("| {} | {rule} |", named.join(", "))
        })
        .collect();
    assert!(
        !documented.is_empty(),
        "the protections table in docs/mcp.md was found and read as empty; the parse went blind"
    );
    assert_eq!(
        documented, expected,
        "docs/mcp.md's protections table and ROUTE_PROTECTIONS / BACKEND_PROTECTIONS disagree"
    );
}

/// The handler each MCP write tool's call reaches, as `(METHOD, path)`
/// with the id normalised, taken from the tool's own call.
fn mcp_write_targets() -> Vec<(&'static lorica_mcp::tools::ToolSpec, (String, String))> {
    lorica_mcp::tools::catalogue()
        .iter()
        .filter(|spec| spec.write().is_some_and(|write| !write.previews))
        .map(|spec| {
            let mut arguments = serde_json::Map::new();
            if let Some(param) = spec.resource {
                arguments.insert(param.name.to_string(), serde_json::json!("{}"));
            }
            if let Some(body) = spec.body() {
                arguments.insert(body.argument.to_string(), serde_json::json!({}));
            }
            let call = spec
                .call_for(&serde_json::Value::Object(arguments))
                .unwrap_or_else(|refused| panic!("{}: {}", spec.name, refused.message));
            // The id was given as `{}` and travels percent-encoded;
            // decoded it is the normalised parameter the router scan
            // spells.
            let path = call.path.replace("%7B%7D", "{}");
            (spec, (call.verb.as_str().to_string(), path))
        })
        .collect()
}

#[test]
fn every_mcp_write_tool_declares_exactly_the_fields_its_handler_accepts_less_the_ones_not_offered()
{
    // Story 11.2 AC #5 and AC #6 on the tool's schema. The tool
    // declares the body's top-level field names so a client reads them
    // and so a key outside them is refused before the call leaves; the
    // plane's handler deserialises a struct. The two are one vocabulary
    // less the entries above, and this is what turns red when either
    // side moves: a field added to `CreateRouteRequest` for the
    // dashboard is offered to a model by a decision, and a field the
    // tool declares that the handler dropped is a promise nothing keeps.
    let writes = automation_write_routes();
    let targets = mcp_write_targets();
    assert!(
        targets.len() >= 8,
        "only {} MCP write tools; the catalogue is a shape this guard does not know",
        targets.len()
    );

    let mut drift = String::new();
    let mut bodies_pinned = 0usize;
    for (spec, (method, path)) in &targets {
        let handler = writes
            .iter()
            .find(|(m, p, _)| m == method && p == path)
            .map(|(_, _, handler)| handler.clone())
            .unwrap_or_else(|| {
                panic!(
                    "{} calls {method} {path}, which the automation router does not mount",
                    spec.name
                )
            });
        let (_, module_src) = automation_handler_source(&handler)
            .unwrap_or_else(|| panic!("`{handler}` is declared in no automation module"));
        let struct_name = handler_body_struct(module_src, &handler);
        let Some(body) = spec.body() else {
            assert_eq!(
                struct_name, None,
                "{} carries no body and its handler `{handler}` takes one",
                spec.name
            );
            continue;
        };
        bodies_pinned += 1;
        let struct_name = struct_name.unwrap_or_else(|| {
            panic!(
                "{} carries a body and its handler `{handler}` takes none",
                spec.name
            )
        });
        assert_eq!(
            body.schema, struct_name,
            "{} names its body `{}` and the handler deserialises `{struct_name}`",
            spec.name, body.schema
        );
        let (file, accepted) = accepted_fields(&struct_name).unwrap_or_else(|| {
            panic!("`pub struct {struct_name}` is declared nowhere this test reads")
        });
        assert!(!accepted.is_empty(), "{struct_name} in {file} has no field");
        let not_offered: BTreeSet<String> = NOT_OFFERED_TO_A_MODEL
            .iter()
            .map(|(name, _)| (*name).to_string())
            .collect();
        let expected: BTreeSet<String> = accepted.difference(&not_offered).cloned().collect();
        let declared: BTreeSet<String> = body.fields.iter().map(|f| (*f).to_string()).collect();

        let accepted_and_not_offered: Vec<&String> = expected.difference(&declared).collect();
        let declared_and_not_accepted: Vec<&String> = declared.difference(&expected).collect();
        if !accepted_and_not_offered.is_empty() || !declared_and_not_accepted.is_empty() {
            drift.push_str(&format!(
                "\n{} (`{struct_name}` in {file}, argument `{}`):\n",
                spec.name, body.argument
            ));
            drift.push_str(&format!(
                "  accepted by the handler and not offered by the tool ({}):\n",
                accepted_and_not_offered.len()
            ));
            for name in &accepted_and_not_offered {
                drift.push_str(&format!("    {name}\n"));
            }
            drift.push_str(&format!(
                "  offered by the tool and not accepted by the handler ({}):\n",
                declared_and_not_accepted.len()
            ));
            for name in &declared_and_not_accepted {
                drift.push_str(&format!("    {name}\n"));
            }
        }
        // And the entries this test tolerates are real: each one is a
        // field the struct has, or the exemption has rotted.
        for (name, why) in NOT_OFFERED_TO_A_MODEL {
            if accepted.contains(*name) {
                assert!(
                    !declared.contains(*name),
                    "{} offers `{name}`, which is not offered because: {why}",
                    spec.name
                );
            }
        }
    }
    assert!(
        bodies_pinned >= 5,
        "only {bodies_pinned} bodies were pinned"
    );
    assert!(
        drift.is_empty(),
        "\nThe MCP config tier's body vocabulary and the automation handlers disagree.\n{drift}\n\
         A name on an \"accepted and not offered\" list arrived because a management request \
         model grew a field, not because anyone decided a model may set it through the config \
         tier. Decide: either it belongs in the tier, and you add it to the tool's field list \
         in lorica-mcp/src/tools.rs, sorted; or it does not, and you name it with its reason in \
         NOT_OFFERED_TO_A_MODEL in tests/openapi_contract.rs. The mirror list is a field the \
         handler stopped accepting, which the tool must stop offering.\n"
    );
}

/// Every property name at any depth under `schema`, through the
/// `items` of an array as well as the `properties` of an object.
fn schema_property_names(schema: &serde_json::Value, into: &mut Vec<String>) {
    if let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
        for (name, nested) in properties {
            into.push(name.clone());
            schema_property_names(nested, into);
        }
    }
    if let Some(items) = schema.get("items") {
        schema_property_names(items, into);
    }
}

#[test]
fn no_mcp_tool_argument_takes_key_material() {
    // Story 11.2 AC #6 on what a client is SHOWN: no property at any
    // depth of any tool's inputSchema matches a key-material marker,
    // and the one credential-shaped field a management body has is not
    // offered. What the schema does not spell out, the test below
    // reaches through the request structs.
    let mut swept = 0usize;
    for spec in lorica_mcp::tools::catalogue() {
        let mut names = Vec::new();
        schema_property_names(&spec.input_schema(), &mut names);
        swept += names.len();
        for name in &names {
            for marker in KEY_MATERIAL_MARKERS {
                assert!(
                    !name.contains(marker),
                    "{} takes `{name}`, which matches the key-material marker `{marker}`. Key \
                     material enters the node through the management API, by a human, never \
                     through a token and never through a model.",
                    spec.name
                );
            }
            assert_ne!(name, "basic_auth_password", "{}", spec.name);
        }
    }
    assert!(swept > 100, "the sweep walked only {swept} property names");
}

#[test]
fn no_mcp_tool_body_field_takes_key_material_at_any_depth_of_its_request_struct() {
    // Story 11.2 AC #6 on what a client can SEND. The schema sweep
    // above walks what the tool publishes, and a body field whose
    // schema is `{}` publishes nothing below itself: `mtls` was offered
    // and `mtls.ca_cert_pem`, a client-authentication trust anchor,
    // travelled under it with the sweep green. This walks the Rust
    // request struct the handler deserialises instead, from each field
    // the tool offers into every struct it nests, so the next nested
    // credential-shaped field turns red whatever its schema says.
    let writes = automation_write_routes();
    let mut nested_reached = 0usize;
    let mut withheld_material: Vec<String> = Vec::new();
    for (spec, (method, path)) in mcp_write_targets() {
        let Some(body) = spec.body() else {
            continue;
        };
        let handler = writes
            .iter()
            .find(|(m, p, _)| *m == method && *p == path)
            .map(|(_, _, handler)| handler.clone())
            .unwrap_or_else(|| panic!("{} calls {method} {path}, which is not mounted", spec.name));
        let (_, module_src) = automation_handler_source(&handler)
            .unwrap_or_else(|| panic!("`{handler}` is declared in no automation module"));
        let struct_name = handler_body_struct(module_src, &handler)
            .unwrap_or_else(|| panic!("`{handler}` takes no body"));
        let struct_name = declaring_struct(&struct_name).to_string();
        let offered: BTreeSet<String> = body.fields.iter().map(|f| (*f).to_string()).collect();

        let mut reachable = Vec::new();
        nested_field_names(&struct_name, Some(&offered), "", &mut reachable);
        assert_eq!(
            reachable.iter().filter(|(path, _)| path.is_empty()).count(),
            offered.len(),
            "{}: the walk into `{struct_name}` did not reach every offered field; the scan is \
             reading a shape the struct no longer has",
            spec.name
        );
        for (path, name) in &reachable {
            if path.is_empty() {
                continue;
            }
            nested_reached += 1;
            let lowered = name.to_ascii_lowercase();
            for marker in KEY_MATERIAL_MARKERS {
                assert!(
                    !lowered.contains(marker),
                    "{} offers `{path}`, under which `{name}` matches the key-material marker \
                     `{marker}`. A trust anchor or a key entering through a nested field is \
                     still a trust anchor or a key: withhold the field in \
                     NOT_OFFERED_TO_A_MODEL with its reason.",
                    spec.name
                );
            }
        }

        // The positive control, so a green run means the walk saw what
        // it is for: over the WHOLE struct, offered or not, at least one
        // nested name matches a marker, and every such name sits under
        // a top-level field NOT_OFFERED_TO_A_MODEL withholds.
        let mut every = Vec::new();
        nested_field_names(&struct_name, None, "", &mut every);
        for (path, name) in &every {
            let lowered = name.to_ascii_lowercase();
            if path.is_empty() || !KEY_MATERIAL_MARKERS.iter().any(|m| lowered.contains(m)) {
                continue;
            }
            let top = path.split('.').next().unwrap_or(path);
            assert!(
                NOT_OFFERED_TO_A_MODEL
                    .iter()
                    .any(|(field, _)| *field == top),
                "{}: `{path}.{name}` is key material under `{top}`, which is offered",
                spec.name
            );
            withheld_material.push(format!("{}: {path}.{name}", spec.name));
        }
    }
    assert!(
        nested_reached >= 20,
        "only {nested_reached} nested fields were walked; the scan went blind"
    );
    assert!(
        !withheld_material.is_empty(),
        "no nested field of any request struct matches a key-material marker, so this test \
         cannot tell a walk that sees nested fields from one that does not; pick a new \
         positive control before trusting it"
    );
}

#[test]
fn every_mcp_write_tool_declares_its_nested_vocabularies_against_the_nested_structs() {
    // The tool refuses an undeclared key at the top level of a body and,
    // since this, inside every object the body nests, because the
    // plane's structs ignore an unknown key at every depth and a caller
    // would otherwise believe it set `path_rules[].backend_idz`. The
    // nested lists are typed in `lorica-mcp`; this pins each against
    // the struct behind the field, both ways, checks that a list is
    // declared as one exactly when the field is a `Vec`, and refuses a
    // field that is a struct with no vocabulary declared for it.
    let writes = automation_write_routes();
    let mut drift = String::new();
    let mut nested_pinned = 0usize;
    for (spec, (method, path)) in mcp_write_targets() {
        let Some(body) = spec.body() else {
            continue;
        };
        let handler = writes
            .iter()
            .find(|(m, p, _)| *m == method && *p == path)
            .map(|(_, _, handler)| handler.clone())
            .unwrap_or_else(|| panic!("{} calls {method} {path}, which is not mounted", spec.name));
        let (_, module_src) = automation_handler_source(&handler)
            .unwrap_or_else(|| panic!("`{handler}` is declared in no automation module"));
        let struct_name = handler_body_struct(module_src, &handler)
            .unwrap_or_else(|| panic!("`{handler}` takes no body"));
        let offered: Vec<&str> = body.fields.to_vec();
        pin_nested(
            spec.name,
            declaring_struct(&struct_name),
            &offered,
            body.nested,
            &mut nested_pinned,
            &mut drift,
        );
    }
    assert!(
        nested_pinned >= 5,
        "only {nested_pinned} nested vocabularies were pinned"
    );
    assert!(
        drift.is_empty(),
        "\nThe MCP config tier's nested vocabularies and the nested request structs disagree.\n\
         {drift}\nA nested struct grew or lost a field, or a body field became an object with \
         no vocabulary declared for it. Edit the nested field lists in lorica-mcp/src/tools.rs, \
         sorted, or withhold the top-level field in NOT_OFFERED_TO_A_MODEL with its reason.\n"
    );
}

/// The nested half of the pin: for `struct_name` and the fields of it
/// `offered`, every declared [`lorica_mcp::tools::Nested`] names an
/// offered field whose type is a struct, is a list exactly when that
/// type is a `Vec`, and lists that struct's fields exactly; and every
/// offered field whose type is a struct has a vocabulary declared.
fn pin_nested(
    tool: &str,
    struct_name: &str,
    offered: &[&str],
    nested: &[lorica_mcp::tools::Nested],
    pinned: &mut usize,
    drift: &mut String,
) {
    let (file, src) = source_declaring(struct_name).unwrap_or_else(|| {
        panic!("`pub struct {struct_name}` is declared nowhere this test reads")
    });
    let fields = serde_fields_with_types(src, struct_name);
    assert!(!fields.is_empty(), "{struct_name} in {file} has no field");

    for declared in nested {
        let Some((_, field_type)) = fields.iter().find(|(name, _)| name == declared.field) else {
            drift.push_str(&format!(
                "\n{tool}: a nested vocabulary is declared for `{}`, which `{struct_name}` \
                 ({file}) has no field of\n",
                declared.field
            ));
            continue;
        };
        if !offered.contains(&declared.field) {
            drift.push_str(&format!(
                "\n{tool}: a nested vocabulary is declared for `{}`, which the tool does not \
                 offer\n",
                declared.field
            ));
            continue;
        }
        let Some((child, list)) = nested_struct_of(field_type) else {
            drift.push_str(&format!(
                "\n{tool}: `{}` is declared nested but its type `{field_type}` is not one \
                 struct\n",
                declared.field
            ));
            continue;
        };
        if source_declaring(&child).is_none() {
            drift.push_str(&format!(
                "\n{tool}: `{}` is declared nested but `{child}` is declared in no source this \
                 test reads (an enum, or a struct in a file to add to request_struct_sources)\n",
                declared.field
            ));
            continue;
        }
        if list != declared.list {
            drift.push_str(&format!(
                "\n{tool}: `{}` is `{field_type}` and is declared with list = {}\n",
                declared.field, declared.list
            ));
        }
        let (child_file, child_src) = source_declaring(&child).expect("checked above");
        let accepted: BTreeSet<String> = serde_field_names(child_src, &child);
        let listed: BTreeSet<String> = declared.fields.iter().map(|f| (*f).to_string()).collect();
        let accepted_not_listed: Vec<&String> = accepted.difference(&listed).collect();
        let listed_not_accepted: Vec<&String> = listed.difference(&accepted).collect();
        if !accepted_not_listed.is_empty() || !listed_not_accepted.is_empty() {
            drift.push_str(&format!(
                "\n{tool}: `{}` (`{child}` in {child_file}):\n  accepted by the struct and not \
                 declared: {accepted_not_listed:?}\n  declared and not accepted: \
                 {listed_not_accepted:?}\n",
                declared.field
            ));
        }
        *pinned += 1;
        pin_nested(
            tool,
            &child,
            declared.fields,
            declared.nested,
            pinned,
            drift,
        );
    }

    for (name, field_type) in &fields {
        if !offered.contains(&name.as_str()) || nested.iter().any(|n| n.field == name) {
            continue;
        }
        if let Some((child, _)) = nested_struct_of(field_type) {
            if source_declaring(&child).is_some() {
                drift.push_str(&format!(
                    "\n{tool}: `{name}` is `{field_type}`, an object the tool offers with no \
                     nested vocabulary, so a mistyped key inside it would be dropped by the \
                     plane and refused by nothing\n"
                ));
            }
        }
    }
}

/// The `minimum` and `maximum` each property of the schema `name`
/// publishes in `components.schemas`, by property.
fn extract_schema_property_bounds(
    yaml: &str,
    name: &str,
) -> BTreeMap<String, (Option<i64>, Option<i64>)> {
    let opening = format!("\n    {name}:\n");
    let start = yaml
        .find(&opening)
        .unwrap_or_else(|| panic!("components.schemas.{name} is not in the document"))
        + opening.len();
    let mut bounds = BTreeMap::new();
    let mut in_properties = false;
    let mut current: Option<String> = None;
    for line in yaml[start..].lines() {
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent <= 4 {
            break;
        }
        let text = line.trim();
        if indent == 6 {
            in_properties = text == "properties:";
            continue;
        }
        if !in_properties {
            continue;
        }
        if indent == 8 {
            let property = text.trim_end_matches(':').to_string();
            bounds.insert(property.clone(), (None, None));
            current = Some(property);
            continue;
        }
        let Some(property) = &current else {
            continue;
        };
        let entry = bounds.get_mut(property).expect("inserted above");
        if let Some(value) = text.strip_prefix("minimum:") {
            entry.0 = Some(value.trim().parse().expect("an integer minimum"));
        } else if let Some(value) = text.strip_prefix("maximum:") {
            entry.1 = Some(value.trim().parse().expect("an integer maximum"));
        }
    }
    bounds
}

#[test]
fn the_settings_patch_publishes_each_allowlisted_bound() {
    // Story 11.3, decision A of 2026-09-28: the plane refuses a value
    // outside its entry's bound, and the schema a caller reads before
    // calling publishes the same bound, pinned here against the entry.
    let spec_src: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/openapi-automation.yaml"
    ));
    let published = extract_schema_property_bounds(spec_src, ALLOWLISTED_BODY.0);
    assert!(!published.is_empty(), "no property read off SettingsPatch");
    for setting in lorica_api::automation::write::SETTINGS_ALLOWLIST {
        assert_eq!(
            published.get(setting.name),
            Some(&(Some(setting.min), Some(setting.max))),
            "SettingsPatch.{} publishes a bound other than {}",
            setting.name,
            setting.bound_text()
        );
    }
}

#[test]
fn the_settings_patch_is_documented_and_offered_as_exactly_the_allowlist() {
    // Story 11.3: the allowlist binds at the plane, and one surface
    // restates it, the documented schema a caller reads. It is diffed
    // against the constant here, both ways, so a key added to one side
    // alone is a red gate rather than a key the document offers and the
    // plane refuses, or one the plane accepts and nothing documents. The
    // MCP tool's body vocabulary is the constant's own names
    // (`SETTINGS_ALLOWLIST_NAMES`), so it is not a second surface.
    let spec_src: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/openapi-automation.yaml"
    ));
    let allowlist = settings_allowlist();
    assert!(!allowlist.is_empty(), "SETTINGS_ALLOWLIST is empty");

    let bodies = extract_request_body_refs(spec_src);
    let documented_ref = bodies
        .get(&("PUT".to_string(), "/automation/v1/settings".to_string()))
        .expect("PUT /automation/v1/settings documents a request body by $ref");
    assert_eq!(documented_ref, ALLOWLISTED_BODY.0);
    let documented = extract_schema_properties(spec_src, ALLOWLISTED_BODY.0);

    let mut drift = String::new();
    let mut compare = |surface: &str, offered: &BTreeSet<String>| {
        let missing: Vec<&String> = allowlist.difference(offered).collect();
        let extra: Vec<&String> = offered.difference(&allowlist).collect();
        if !missing.is_empty() || !extra.is_empty() {
            drift.push_str(&format!(
                "\n{surface}:\n  in SETTINGS_ALLOWLIST and missing here: {missing:?}\n  here and \
                 not in SETTINGS_ALLOWLIST: {extra:?}\n"
            ));
        }
    };
    compare(
        &format!(
            "openapi-automation.yaml, components.schemas.{}",
            ALLOWLISTED_BODY.0
        ),
        &documented,
    );
    assert!(
        drift.is_empty(),
        "\nThe admin tier's settings allowlist and the document restating it disagree.\n{drift}\n\
         SETTINGS_ALLOWLIST in lorica-automation-policy/src/settings.rs is the control, each entry with \
         its reason. Change it there first, by a decision, then the SettingsPatch schema in \
         openapi-automation.yaml; the MCP tool is built from the constant.\n"
    );
}

#[test]
fn every_automation_write_documents_dry_run_and_no_read_does() {
    // The preview is `?dry_run=true` on the write itself (Story 11.2
    // AC #3), so every documented write names the parameter, the same
    // component each time, and no read does: a read has nothing to
    // preview and a documented `dry_run` on one would promise a
    // behaviour the handler does not have.
    let spec_src: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/openapi-automation.yaml"
    ));
    let components = extract_parameter_components(spec_src);
    assert_eq!(
        components
            .get("DryRun")
            .map(|(name, location)| (name.as_str(), location.as_str())),
        Some(("dry_run", "query")),
        "components.parameters.DryRun is not the query parameter `dry_run`"
    );
    let documented = extract_operation_query_parameters(spec_src, &components);
    let mut writes = 0usize;
    for (method, path) in extract_spec_paths(spec_src) {
        if path == AUTOMATION_MCP_PATH || path.starts_with("/automation/v1/environments") {
            // The environment resource is Story 10.4's and previews
            // nothing; the MCP endpoint is not a resource.
            continue;
        }
        let names = documented.get(&(method.clone(), path.clone()));
        let has_dry_run = names.is_some_and(|names| names.contains("dry_run"));
        if method == "GET" {
            assert!(!has_dry_run, "{method} {path} documents dry_run on a read");
        } else {
            writes += 1;
            assert!(has_dry_run, "{method} {path} documents no dry_run");
        }
    }
    assert!(writes >= 8, "only {writes} documented writes were checked");
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

/// The wire names of every field of `pub struct <name>` in `src` that
/// a caller may send.
///
/// A `#[serde(rename = "...")]` on a field wins, the way it does on the
/// wire; everything else is the identifier. A `skip_deserializing`
/// field is left out: a value sent for it is dropped, so it is not a
/// field a caller may set and a tool must not offer it as one.
fn serde_field_names(src: &str, struct_name: &str) -> BTreeSet<String> {
    serde_fields_with_types(src, struct_name)
        .into_iter()
        .map(|(name, _)| name)
        .collect()
}

/// [`serde_field_names`] with each field's declared type beside it,
/// in declaration order, as the source spells it.
fn serde_fields_with_types(src: &str, struct_name: &str) -> Vec<(String, String)> {
    let opening = format!("pub struct {struct_name} {{");
    let Some((_, body)) = src.split_once(&opening) else {
        return Vec::new();
    };
    let Some((body, _)) = body.split_once("\n}") else {
        return Vec::new();
    };

    let mut out = Vec::new();
    let mut renamed: Option<String> = None;
    let mut skipped = false;
    for line in body.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("#[serde(rename = \"") {
            renamed = rest.split('"').next().map(str::to_string);
            continue;
        }
        if line.starts_with("#[serde(") && line.contains("skip_deserializing") {
            skipped = true;
            continue;
        }
        let Some(rest) = line.strip_prefix("pub ") else {
            continue;
        };
        let Some((name, field_type)) = rest.split_once(':') else {
            continue;
        };
        let name = renamed.take().unwrap_or_else(|| name.trim().to_string());
        if std::mem::take(&mut skipped) {
            continue;
        }
        let field_type = field_type.trim().trim_end_matches(',').trim().to_string();
        out.push((name, field_type));
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
