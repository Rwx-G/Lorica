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
    let server_src: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/server.rs"));
    let openapi_src: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.yaml"));

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
