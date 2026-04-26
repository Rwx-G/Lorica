//! Route CRUD HTTP handlers: list/get/create/update/delete.
//!
//! Request/response wrapper types and the `route_to_response` view
//! builder live here too; per-feature validation helpers are delegated
//! to sibling modules (`header_rules`, `traffic_splits`,
//! `forward_auth`, `mirror`, `response_rewrite`, `mtls`, `path_rules`).

use std::collections::HashMap;

use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::{json_data, json_data_with_status, ApiError};
use crate::server::AppState;

use super::forward_auth::{build_forward_auth, ForwardAuthConfigRequest};
use super::header_rules::{build_header_rule, HeaderRuleRequest};
use super::mirror::{build_mirror_config, MirrorConfigRequest};
use super::mtls::{build_mtls_config, MtlsConfigRequest};
use super::path_rules::{build_path_rules, PathRuleRequest, PathRuleResponse};
use super::response_rewrite::{
    build_response_rewrite, ResponseRewriteConfigRequest, ResponseRewriteRuleRequest,
};
use super::traffic_splits::{build_traffic_split, validate_traffic_splits, TrafficSplitRequest};

/// Upper bound for `capacity` and `refill_per_sec`. Chosen to be large
/// enough for any realistic proxy workload while still rejecting
/// accidental values (e.g. u32::MAX) that would overflow downstream
/// arithmetic in the token-bucket refill path.
///
/// `pub` so the OpenAPI generator + future SDK builders can read the
/// same upper bound the validator enforces (audit L-23) - operators
/// who hit the limit see "rate_limit.capacity must be <= 1000000"
/// from the API today, but the documented contract should match.
pub const RATE_LIMIT_MAX: u32 = 1_000_000;

/// Maximum bot-protection cookie TTL (7 days) accepted by the API.
pub const BOT_COOKIE_TTL_MAX: u32 = 604_800;

/// Minimum bot-protection PoW difficulty (bits of leading-zero
/// constraint on the SHA-256 challenge digest). Below this the
/// challenge is trivially solvable on a phone CPU.
pub const BOT_POW_DIFFICULTY_MIN: u8 = 14;

/// Maximum PoW difficulty. Above this, even a desktop browser may
/// take seconds to solve the challenge - bad UX.
pub const BOT_POW_DIFFICULTY_MAX: u8 = 22;

/// Captcha alphabet length bounds. Below 10, the answer space is
/// too small to be useful ; above 128, the rendered image gets
/// unreadable.
pub const BOT_CAPTCHA_ALPHABET_MIN: usize = 10;
pub const BOT_CAPTCHA_ALPHABET_MAX: usize = 128;

/// Maximum entries per bot-protection bypass category (paths /
/// hostnames / countries / IPs / user-agent regexes). Above this,
/// the per-request bypass-matrix evaluation cost crosses into
/// "single broad config can DoS the proxy" territory.
pub const BOT_MAX_BYPASS_ENTRIES_PER_CATEGORY: usize = 500;

/// Validate a per-route `GeoIpConfig` for API acceptance. Country
/// codes must be ISO 3166-1 alpha-2 (two ASCII letters, normalised to
/// upper). Duplicates are collapsed. Allowlist mode rejects empty
/// lists so an operator cannot accidentally block everything by
/// leaving the country list blank after switching modes.
fn validate_geoip(
    cfg: &lorica_config::models::GeoIpConfig,
) -> Result<lorica_config::models::GeoIpConfig, ApiError> {
    use lorica_config::models::GeoIpMode;

    let mut normalised: Vec<String> = Vec::with_capacity(cfg.countries.len());
    for raw in &cfg.countries {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.len() != 2 || !trimmed.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(ApiError::BadRequest(format!(
                "geoip.countries: '{trimmed}' is not a valid ISO 3166-1 alpha-2 code"
            )));
        }
        let upper = trimmed.to_ascii_uppercase();
        if !normalised.contains(&upper) {
            normalised.push(upper);
        }
    }

    if cfg.mode == GeoIpMode::Allowlist && normalised.is_empty() {
        return Err(ApiError::BadRequest(
            "geoip.countries: allowlist mode with empty country list would block every request. \
             Use denylist mode or add at least one country"
                .into(),
        ));
    }

    // Upper bound on the country list so an operator cannot paste a
    // huge blob. 300 covers every ISO code twice over.
    const MAX_COUNTRIES: usize = 300;
    if normalised.len() > MAX_COUNTRIES {
        return Err(ApiError::BadRequest(format!(
            "geoip.countries: at most {MAX_COUNTRIES} entries allowed"
        )));
    }

    Ok(lorica_config::models::GeoIpConfig {
        mode: cfg.mode,
        countries: normalised,
    })
}

/// Validate a `BotProtectionConfig` for API acceptance (v1.4.0 Epic
/// 3 story 3.3). Normalises country codes to uppercase, compiles
/// user-agent regexes to surface parse errors at write time rather
/// than on the first request, and bounds every numeric knob so a
/// hand-crafted JSON blob cannot stash an out-of-spec config that
/// the request-filter would then have to defend against.
///
/// Error messages are plain-English and include the offending
/// value so the dashboard can surface them directly to the operator.
fn validate_bot_protection(
    cfg: &lorica_config::models::BotProtectionConfig,
) -> Result<lorica_config::models::BotProtectionConfig, ApiError> {
    use lorica_config::models::{BotBypassRules, BotProtectionConfig};

    // Hard caps matching `lorica_challenge::pow` constants (the
    // crate constants are not re-exported here to avoid forcing
    // lorica-api to depend on lorica-challenge at compile time —
    // the values are tiny and duplicated as named constants below).
    // Audit L-23 : the `BOT_*` and `BYPASS_*` constants are public
    // so OpenAPI / SDK generators can read the same upper bounds
    // the validators enforce.

    if cfg.cookie_ttl_s == 0 {
        return Err(ApiError::BadRequest(
            "bot_protection.cookie_ttl_s must be > 0".into(),
        ));
    }
    if cfg.cookie_ttl_s > BOT_COOKIE_TTL_MAX {
        return Err(ApiError::BadRequest(format!(
            "bot_protection.cookie_ttl_s must be <= {BOT_COOKIE_TTL_MAX} (7 days)"
        )));
    }

    if !(BOT_POW_DIFFICULTY_MIN..=BOT_POW_DIFFICULTY_MAX).contains(&cfg.pow_difficulty) {
        return Err(ApiError::BadRequest(format!(
            "bot_protection.pow_difficulty must be in {BOT_POW_DIFFICULTY_MIN}..={BOT_POW_DIFFICULTY_MAX}"
        )));
    }

    // Captcha alphabet: length bounds, ASCII-printable only, no
    // duplicates. Same rules as `lorica_challenge::captcha::validate_alphabet`
    // so the API + crate agree on the contract.
    let alpha_chars: Vec<char> = cfg.captcha_alphabet.chars().collect();
    if alpha_chars.len() < BOT_CAPTCHA_ALPHABET_MIN {
        return Err(ApiError::BadRequest(format!(
            "bot_protection.captcha_alphabet shorter than minimum of \
             {BOT_CAPTCHA_ALPHABET_MIN} characters"
        )));
    }
    if alpha_chars.len() > BOT_CAPTCHA_ALPHABET_MAX {
        return Err(ApiError::BadRequest(format!(
            "bot_protection.captcha_alphabet longer than maximum of \
             {BOT_CAPTCHA_ALPHABET_MAX} characters"
        )));
    }
    {
        let mut seen = Vec::<char>::with_capacity(alpha_chars.len());
        for c in &alpha_chars {
            if !c.is_ascii_graphic() {
                return Err(ApiError::BadRequest(
                    "bot_protection.captcha_alphabet contains non-ASCII-printable \
                     character (must be ASCII 0x21..=0x7e)"
                        .into(),
                ));
            }
            if seen.contains(c) {
                return Err(ApiError::BadRequest(format!(
                    "bot_protection.captcha_alphabet contains duplicate '{c}'"
                )));
            }
            seen.push(*c);
        }
    }

    // Bypass matrix: validate each category independently. All of
    // these are upper-bounded by a per-category cap so an operator
    // cannot paste a multi-megabyte blob. Validation is inlined per
    // category (rather than a shared generic) because each field
    // carries a different element type (String / u32) and
    // trimming / normalisation rules.
    fn check_cap(label: &str, len: usize) -> Result<(), ApiError> {
        if len > BOT_MAX_BYPASS_ENTRIES_PER_CATEGORY {
            return Err(ApiError::BadRequest(format!(
                "bot_protection.bypass.{label}: at most \
                 {BOT_MAX_BYPASS_ENTRIES_PER_CATEGORY} entries allowed"
            )));
        }
        Ok(())
    }

    check_cap("ip_cidrs", cfg.bypass.ip_cidrs.len())?;
    let mut ip_cidrs: Vec<String> = Vec::with_capacity(cfg.bypass.ip_cidrs.len());
    for raw in &cfg.bypass.ip_cidrs {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ApiError::BadRequest(
                "bot_protection.bypass.ip_cidrs: empty entry".into(),
            ));
        }
        if trimmed.parse::<ipnet::IpNet>().is_err() && trimmed.parse::<std::net::IpAddr>().is_err()
        {
            return Err(ApiError::BadRequest(format!(
                "bot_protection.bypass.ip_cidrs: '{trimmed}' is not a valid IP or CIDR"
            )));
        }
        ip_cidrs.push(trimmed.to_string());
    }

    // ASN-based bypass (v1.4.0 Epic 3). Resolver is
    // `lorica_geoip::AsnResolver` loaded from
    // `GlobalSettings.asn_db_path`. When the DB is missing at
    // request time, `asn_handle().lookup_asn()` returns `None` and
    // the request falls through to the remaining bypass categories
    // — the config is accepted, it just does not fire until the
    // operator points `asn_db_path` at an ASN `.mmdb`.
    check_cap("asns", cfg.bypass.asns.len())?;
    for n in &cfg.bypass.asns {
        if *n == 0 {
            return Err(ApiError::BadRequest(
                "bot_protection.bypass.asns: 0 is not a valid ASN (IANA reserves 0)".into(),
            ));
        }
    }
    let asns = cfg.bypass.asns.clone();

    check_cap("countries", cfg.bypass.countries.len())?;
    let mut countries: Vec<String> = Vec::with_capacity(cfg.bypass.countries.len());
    for raw in &cfg.bypass.countries {
        let trimmed = raw.trim();
        if trimmed.len() != 2 || !trimmed.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(ApiError::BadRequest(format!(
                "bot_protection.bypass.countries: '{trimmed}' is not a valid ISO 3166-1 alpha-2 code"
            )));
        }
        countries.push(trimmed.to_ascii_uppercase());
    }

    check_cap("user_agents", cfg.bypass.user_agents.len())?;
    let mut user_agents: Vec<String> = Vec::with_capacity(cfg.bypass.user_agents.len());
    for raw in &cfg.bypass.user_agents {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ApiError::BadRequest(
                "bot_protection.bypass.user_agents: empty pattern".into(),
            ));
        }
        regex::Regex::new(trimmed).map_err(|e| {
            ApiError::BadRequest(format!(
                "bot_protection.bypass.user_agents: '{trimmed}' is not a valid regex: {e}"
            ))
        })?;
        user_agents.push(trimmed.to_string());
    }

    // rDNS-based bypass (v1.4.0 Epic 3). Forward-
    // confirmation is enforced in-process by
    // `lorica::bot_rdns::RdnsResolver` (resolve PTR then confirm
    // one of the resulting names forward-resolves back to the
    // client IP — without this a hostile resolver could trivially
    // spoof any PTR and bypass).
    //
    // Shape rules: printable ASCII, no leading dot, contains at
    // least one dot (a bare TLD like `com` would match every
    // `.com` host and is almost always an operator mistake).
    // Lowercase the suffix for case-insensitive matching against
    // the resolved host.
    check_cap("rdns", cfg.bypass.rdns.len())?;
    let mut rdns: Vec<String> = Vec::with_capacity(cfg.bypass.rdns.len());
    for raw in &cfg.bypass.rdns {
        let trimmed = raw.trim().to_ascii_lowercase();
        if trimmed.is_empty() {
            return Err(ApiError::BadRequest(
                "bot_protection.bypass.rdns: empty entry".into(),
            ));
        }
        if !trimmed.chars().all(|c| c.is_ascii_graphic()) {
            return Err(ApiError::BadRequest(format!(
                "bot_protection.bypass.rdns: '{trimmed}' contains non-ASCII-printable character"
            )));
        }
        if trimmed.starts_with('.') {
            return Err(ApiError::BadRequest(format!(
                "bot_protection.bypass.rdns: '{trimmed}' must not start with a dot"
            )));
        }
        // Allow a trailing dot (canonical DNS form) but require at
        // least two labels. `com` = 0 internal dots → reject.
        // `com.` = trailing dot only → reject.
        let no_trail = trimmed.trim_end_matches('.');
        if !no_trail.contains('.') {
            return Err(ApiError::BadRequest(format!(
                "bot_protection.bypass.rdns: '{trimmed}' must contain at least one \
                 dot (a bare TLD like 'com' would match every `.com` host and \
                 is almost always a mistake)"
            )));
        }
        rdns.push(trimmed);
    }

    // only_country: same shape rules as bypass.countries.
    let only_country = match cfg.only_country.as_ref() {
        Some(list) => {
            if list.is_empty() {
                return Err(ApiError::BadRequest(
                    "bot_protection.only_country: empty list; use null instead to \
                     signal 'challenge applies to all traffic'"
                        .into(),
                ));
            }
            check_cap("only_country", list.len())?;
            let mut normalised: Vec<String> = Vec::with_capacity(list.len());
            for raw in list {
                let trimmed = raw.trim();
                if trimmed.len() != 2 || !trimmed.chars().all(|c| c.is_ascii_alphabetic()) {
                    return Err(ApiError::BadRequest(format!(
                        "bot_protection.only_country: '{trimmed}' is not a valid ISO \
                         3166-1 alpha-2 code"
                    )));
                }
                normalised.push(trimmed.to_ascii_uppercase());
            }
            Some(normalised)
        }
        None => None,
    };

    Ok(BotProtectionConfig {
        mode: cfg.mode,
        cookie_ttl_s: cfg.cookie_ttl_s,
        pow_difficulty: cfg.pow_difficulty,
        captcha_alphabet: cfg.captcha_alphabet.clone(),
        bypass: BotBypassRules {
            ip_cidrs,
            asns,
            countries,
            user_agents,
            rdns,
        },
        only_country,
    })
}

/// Validate a `RateLimit` config for API acceptance. Returns the
/// config unchanged on success, `ApiError::BadRequest` with a clear
/// message on validation failure.
fn validate_rate_limit(
    rl: &lorica_config::models::RateLimit,
) -> Result<lorica_config::models::RateLimit, ApiError> {
    if rl.capacity == 0 {
        return Err(ApiError::BadRequest(
            "rate_limit.capacity must be > 0 (use `rate_limit: null` or omit to disable)".into(),
        ));
    }
    if rl.capacity > RATE_LIMIT_MAX {
        return Err(ApiError::BadRequest(format!(
            "rate_limit.capacity must be <= {RATE_LIMIT_MAX}"
        )));
    }
    if rl.refill_per_sec > RATE_LIMIT_MAX {
        return Err(ApiError::BadRequest(format!(
            "rate_limit.refill_per_sec must be <= {RATE_LIMIT_MAX}"
        )));
    }
    Ok(rl.clone())
}

/// Validate a `redirect_hostname` input for API acceptance.
///
/// The proxy emits redirects as `{scheme}://{redirect_hostname}{path}{?query}`;
/// the field is a bare DNS hostname, NOT a full URL. Operators who
/// paste `https://example.com/foo` end up with a malformed Location
/// header (`https://https://example.com/foo/...`). We reject those at
/// the API boundary with a clear error so the mistake surfaces on save
/// instead of silently on the next client request.
///
/// Accepts: RFC 1123-style hostnames (letters, digits, `-`, `.`), with
/// labels 1..=63 chars and total length <= 253. The input is returned
/// trimmed of surrounding whitespace. An empty string (after trim) is
/// caller-policy: the two callers below treat it as "clear the field".
/// Validate a `group_name` input for a Route or a Backend. Empty
/// string (after trim) is accepted as "ungrouped". Non-empty must
/// match the RFC-1035-inspired identifier alphabet
/// `^[a-z0-9_-]{1,64}$`: lowercase ASCII letters, digits, dash and
/// underscore. The `Backend.group_name` column has been in production
/// since v1.2 without validation; this helper applies the new rule
/// to both routes and backends going forward. Returns the trimmed
/// value.
fn validate_group_name(raw: &str) -> Result<String, ApiError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.len() > 64 {
        return Err(ApiError::BadRequest(
            "group_name must be <= 64 characters".into(),
        ));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(ApiError::BadRequest(
            "group_name may only contain ASCII lowercase letters, digits, `-` and `_`".into(),
        ));
    }
    Ok(trimmed.to_string())
}

/// Validate a canonical-host redirect target.
///
/// `redirect_hostname` is specifically for the "redirect every request
/// on this route to the same path on a different hostname" pattern
/// (aka canonical-host redirect). It intentionally accepts ONLY a
/// bare DNS hostname (no scheme, path, query, port, userinfo) because
/// the proxy emits `{scheme}://{redirect_hostname}{path}{?query}` at
/// runtime and anything else produces malformed Location headers.
///
/// Ports are **deliberately** rejected here. Operators that need a
/// redirect to a non-standard port (e.g. migrating from port 443 to
/// 8443 on a new host) should use `redirect_to` with a full URL
/// (`https://new.example.com:8443`) instead ; `redirect_to` supports
/// ports, userinfo, and explicit schemes. Splitting the two fields
/// keeps the common case (canonical-host) typo-proof without forcing
/// a full URL parser on every write path.
fn validate_redirect_hostname(raw: &str) -> Result<String, ApiError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.contains("://") {
        return Err(ApiError::BadRequest(
            "redirect_hostname must be a bare hostname (e.g. `example.com`) \
             without a scheme - drop the `http://` / `https://` prefix"
                .into(),
        ));
    }
    if trimmed.contains('/') {
        return Err(ApiError::BadRequest(
            "redirect_hostname must be a bare hostname without a path or \
             trailing slash - drop everything after the hostname"
                .into(),
        ));
    }
    // `:` rejection = no port in this field. See the module comment
    // above: redirects to a non-standard port go through `redirect_to`
    // with a full URL, which takes the whole authority shape.
    if trimmed.contains(|c: char| c.is_whitespace() || matches!(c, '?' | '#' | ':' | '@')) {
        return Err(ApiError::BadRequest(
            "redirect_hostname contains a character that is not valid in a \
             hostname (whitespace, `?`, `#`, `:`, `@`). If you need to \
             redirect to a non-standard port, use `redirect_to` with a \
             full URL like `https://target.example.com:8443` instead."
                .into(),
        ));
    }
    if trimmed.len() > 253 {
        return Err(ApiError::BadRequest(
            "redirect_hostname is longer than 253 characters (DNS limit)".into(),
        ));
    }
    if trimmed.starts_with('.') || trimmed.ends_with('.') {
        return Err(ApiError::BadRequest(
            "redirect_hostname must not start or end with a dot".into(),
        ));
    }
    for label in trimmed.split('.') {
        if label.is_empty() {
            return Err(ApiError::BadRequest(
                "redirect_hostname contains an empty DNS label (consecutive dots)".into(),
            ));
        }
        if label.len() > 63 {
            return Err(ApiError::BadRequest(
                "redirect_hostname contains a DNS label longer than 63 characters".into(),
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ApiError::BadRequest(
                "redirect_hostname contains a DNS label that starts or ends with `-`".into(),
            ));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(ApiError::BadRequest(
                "redirect_hostname may only contain ASCII letters, digits, `-` and `.`".into(),
            ));
        }
    }
    Ok(trimmed.to_string())
}

/// Validate a `redirect_to` input. Accepts a full HTTP(S) URL and
/// returns it trimmed. Empty/whitespace => returns empty (caller
/// interprets as "clear the field"). Non-empty values must have a
/// `http://` or `https://` scheme and a non-empty host (fails closed:
/// operators typing just `example.com` get a clear error instead of
/// Lorica emitting a 301 with a relative Location header at runtime).
/// Total length capped at 2048 which is comfortably above every
/// browser URL limit and low enough to reject accidental paste-entire-
/// document mistakes.
pub(super) fn validate_redirect_to(raw: &str, field_label: &str) -> Result<String, ApiError> {
    const MAX_URL_LEN: usize = 2048;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.len() > MAX_URL_LEN {
        return Err(ApiError::BadRequest(format!(
            "{field_label} is longer than {MAX_URL_LEN} characters"
        )));
    }
    if trimmed.chars().any(|c| c.is_whitespace()) {
        return Err(ApiError::BadRequest(format!(
            "{field_label} must not contain whitespace"
        )));
    }
    let rest = if let Some(r) = trimmed.strip_prefix("http://") {
        r
    } else if let Some(r) = trimmed.strip_prefix("https://") {
        r
    } else {
        return Err(ApiError::BadRequest(format!(
            "{field_label} must start with `http://` or `https://`"
        )));
    };
    // Host ends at the first `/`, `?`, or `#`; must be non-empty.
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    if host_end == 0 {
        return Err(ApiError::BadRequest(format!(
            "{field_label} must include a host after the scheme"
        )));
    }
    Ok(trimmed.to_string())
}

/// Validate a `path_rewrite_pattern` regex. Shared between `create_route`
/// and `update_route` so the rule is enforced on both endpoints (the
/// previous setup only validated on `update`, letting `POST /routes`
/// silently accept a pattern that the proxy rejects at reload).
fn validate_path_rewrite_pattern(pattern: &str) -> Result<String, ApiError> {
    const MAX_PATTERN_LEN: usize = 1024;
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.len() > MAX_PATTERN_LEN {
        return Err(ApiError::BadRequest(format!(
            "path_rewrite_pattern must be <= {MAX_PATTERN_LEN} characters"
        )));
    }
    if regex::Regex::new(trimmed).is_err() {
        return Err(ApiError::BadRequest(format!(
            "path_rewrite_pattern is not a valid regex: {trimmed}"
        )));
    }
    Ok(trimmed.to_string())
}

/// Validate an HTTP field-name per RFC 7230 §3.2.6 (`token`). Returns
/// the name verbatim on success; caller is expected to pass the
/// already-trimmed string. Rejects empty names so the UI does not
/// silently ignore blank entries and rejects any character outside
/// the RFC 7230 token alphabet (letters, digits, and
/// `!#$%&'*+-.^_`|~`). Length capped at 256 which is well above any
/// real-world field name.
fn validate_http_header_name(name: &str, field_label: &str) -> Result<(), ApiError> {
    if name.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "{field_label}: header name must not be empty"
        )));
    }
    if name.len() > 256 {
        return Err(ApiError::BadRequest(format!(
            "{field_label}: header name must be <= 256 characters"
        )));
    }
    for c in name.chars() {
        let is_token = c.is_ascii_alphanumeric()
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
            );
        if !is_token {
            return Err(ApiError::BadRequest(format!(
                "{field_label}: header name {name:?} contains `{c}` which is not a \
                 valid HTTP field-name character (RFC 7230 token)"
            )));
        }
    }
    Ok(())
}

/// Validate an HTTP field-value. The proxy forwards the bytes mostly
/// verbatim so a rogue CR / LF in a header value would enable
/// response-splitting attacks. NUL is rejected alongside for the same
/// reason. Printable ASCII, horizontal tab, and any byte >= 0x80 (for
/// UTF-8 header values like Content-Disposition filenames) are
/// accepted. Length capped at 4096.
fn validate_http_header_value(value: &str, field_label: &str) -> Result<(), ApiError> {
    if value.len() > 4096 {
        return Err(ApiError::BadRequest(format!(
            "{field_label}: header value must be <= 4096 characters"
        )));
    }
    for b in value.bytes() {
        if b == b'\r' || b == b'\n' || b == 0 {
            return Err(ApiError::BadRequest(format!(
                "{field_label}: header value contains CR, LF, or NUL (response splitting)"
            )));
        }
    }
    Ok(())
}

/// Validate a `HashMap<String, String>` of HTTP headers - names and
/// values both. Used for route-level `proxy_headers` and
/// `response_headers` as well as per-path-rule overrides.
pub(super) fn validate_http_headers_map(
    map: &std::collections::HashMap<String, String>,
    field_label: &str,
) -> Result<(), ApiError> {
    for (name, value) in map {
        let trimmed = name.trim();
        validate_http_header_name(trimmed, field_label)?;
        validate_http_header_value(value, &format!("{field_label}[{trimmed}]"))?;
    }
    Ok(())
}

/// Validate a list of header names (e.g. `proxy_headers_remove`,
/// `response_headers_remove`, `cache_vary_headers`).
pub(super) fn validate_http_header_name_list(
    names: &[String],
    field_label: &str,
) -> Result<(), ApiError> {
    for name in names {
        let trimmed = name.trim();
        validate_http_header_name(trimmed, field_label)?;
    }
    Ok(())
}

/// Validate an HTTP method token. Accepts the canonical set
/// (`GET`, `POST`, ...) plus any all-uppercase-letter token (to allow
/// `PATCH`, `MKCOL`, custom verbs). Rejects lowercase, digits, and
/// anything that is not a valid RFC 7230 token.
fn validate_http_method(method: &str, field_label: &str) -> Result<(), ApiError> {
    if method.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "{field_label}: method must not be empty"
        )));
    }
    if method.len() > 32 {
        return Err(ApiError::BadRequest(format!(
            "{field_label}: method {method:?} is longer than 32 characters"
        )));
    }
    if !method.chars().all(|c| c.is_ascii_uppercase()) {
        return Err(ApiError::BadRequest(format!(
            "{field_label}: method {method:?} must be ASCII uppercase letters only \
             (e.g. `GET`, `POST`, `PATCH`)"
        )));
    }
    Ok(())
}

/// Validate a single hostname alias. Same RFC 1123 shape check as
/// `validate_redirect_hostname` but with its own field label so the
/// UI can point at the right input. Returns the trimmed value on
/// success.
fn validate_hostname_alias(raw: &str, field_label: &str) -> Result<String, ApiError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "{field_label} must not be empty"
        )));
    }
    if trimmed.len() > 253 {
        return Err(ApiError::BadRequest(format!(
            "{field_label} is longer than 253 characters"
        )));
    }
    if trimmed.contains("://") || trimmed.contains('/') {
        return Err(ApiError::BadRequest(format!(
            "{field_label} must be a bare hostname (no scheme, no path)"
        )));
    }
    if trimmed.chars().any(|c| c.is_whitespace()) {
        return Err(ApiError::BadRequest(format!(
            "{field_label} must not contain whitespace"
        )));
    }
    if trimmed.starts_with('.') || trimmed.ends_with('.') {
        return Err(ApiError::BadRequest(format!(
            "{field_label} must not start or end with a dot"
        )));
    }
    // Wildcards on the first label are legal for SNI match in Lorica
    // (same rule the primary hostname field accepts). Let `*.example.com`
    // through and validate the remaining labels normally.
    let check_body = if let Some(rest) = trimmed.strip_prefix("*.") {
        rest
    } else {
        trimmed
    };
    for label in check_body.split('.') {
        if label.is_empty() {
            return Err(ApiError::BadRequest(format!(
                "{field_label} contains an empty DNS label"
            )));
        }
        if label.len() > 63 {
            return Err(ApiError::BadRequest(format!(
                "{field_label} contains a DNS label longer than 63 characters"
            )));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ApiError::BadRequest(format!(
                "{field_label} contains a DNS label that starts or ends with `-`"
            )));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(ApiError::BadRequest(format!(
                "{field_label} may only contain ASCII letters, digits, `-` and `.`"
            )));
        }
    }
    Ok(trimmed.to_string())
}

/// Validate an `error_page_html` body. Size cap 128 KiB - more than
/// enough for a branded error page including inline CSS and an SVG
/// or two, far short of something that would pressure the response
/// buffer. Runtime sanitisation still runs on every render; this is
/// the boundary check.
fn validate_error_page_html(raw: &str) -> Result<(), ApiError> {
    const ERROR_PAGE_MAX_BYTES: usize = 128 * 1024;
    if raw.len() > ERROR_PAGE_MAX_BYTES {
        return Err(ApiError::BadRequest(format!(
            "error_page_html must be <= {ERROR_PAGE_MAX_BYTES} bytes (128 KiB)"
        )));
    }
    Ok(())
}

/// Validate a path-prefix-style field (route-level `path_prefix`,
/// `strip_path_prefix`, `add_path_prefix`). Must start with `/`, no
/// whitespace, length cap 1024. Empty => returns empty (caller
/// interprets as "clear").
fn validate_route_path(raw: &str, field_label: &str) -> Result<String, ApiError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if !trimmed.starts_with('/') {
        return Err(ApiError::BadRequest(format!(
            "{field_label} must start with '/'"
        )));
    }
    if trimmed.len() > 1024 {
        return Err(ApiError::BadRequest(format!(
            "{field_label} must be <= 1024 characters"
        )));
    }
    if trimmed.chars().any(|c| c.is_whitespace()) {
        return Err(ApiError::BadRequest(format!(
            "{field_label} must not contain whitespace"
        )));
    }
    if trimmed.chars().any(|c| (c as u32) < 0x20 || c == '\u{7f}') {
        return Err(ApiError::BadRequest(format!(
            "{field_label} contains a control character"
        )));
    }
    Ok(trimmed.to_string())
}

/// Tiny helper for inline integer-range checks. Lets each call site
/// spell its own range + field label without a macro.
fn check_range<T: PartialOrd + std::fmt::Display>(
    value: T,
    min: T,
    max: T,
    field_label: &str,
) -> Result<(), ApiError> {
    if value < min || value > max {
        return Err(ApiError::BadRequest(format!(
            "{field_label} must be in {min}..={max}"
        )));
    }
    Ok(())
}

/// Route-level numeric bounds, shared between `create_route` and
/// `update_route`. Each caller passes `Option<T>` for every field so
/// missing ones are skipped (update semantics: don't touch what the
/// operator did not send). Centralising avoids the bug where `POST`
/// and `PUT` drift apart on validity rules.
#[allow(clippy::too_many_arguments)] // intentional single-site fan-in of route numeric fields
fn validate_route_numeric_bounds(
    connect_timeout_s: Option<i32>,
    read_timeout_s: Option<i32>,
    send_timeout_s: Option<i32>,
    cache_ttl_s: Option<i32>,
    cache_max_bytes: Option<i64>,
    max_connections: Option<u32>,
    slowloris_threshold_ms: Option<i32>,
    auto_ban_threshold: Option<u32>,
    auto_ban_duration_s: Option<i32>,
    return_status: Option<u16>,
    retry_attempts: Option<u32>,
    stale_while_revalidate_s: Option<i32>,
    stale_if_error_s: Option<i32>,
    cors_max_age_s: Option<i32>,
    max_request_body_bytes: Option<u64>,
) -> Result<(), ApiError> {
    if let Some(v) = connect_timeout_s {
        check_range(v, 1, 3600, "connect_timeout_s")?;
    }
    if let Some(v) = read_timeout_s {
        check_range(v, 1, 3600, "read_timeout_s")?;
    }
    if let Some(v) = send_timeout_s {
        check_range(v, 1, 3600, "send_timeout_s")?;
    }
    // `cache_ttl_s == 0` is a valid HTTP cache configuration :
    // `response_cache_filter` computes `fresh_until = now + ttl_s`
    // so a zero TTL stores the entry but marks it already expired,
    // forcing revalidation on every hit (equivalent to the origin
    // sending `Cache-Control: max-age=0`, useful paired with
    // stale-while-revalidate). `cache_max_bytes == 0` is the
    // "no per-entry size cap" sentinel in `request_cache_filter`
    // (the `cache_max_bytes > 0` guard skips
    // `set_max_file_size_bytes`). Both legitimate values were
    // rejected by the v1.5.0 lower-bound-1 validator.
    if let Some(v) = cache_ttl_s {
        check_range(v, 0, 31_536_000, "cache_ttl_s")?;
    }
    if let Some(v) = cache_max_bytes {
        check_range(v, 0, 137_438_953_472, "cache_max_bytes")?; // 128 GiB
    }
    // `max_connections` and `auto_ban_threshold` treat `0` as the
    // "clear / disabled / no limit" sentinel on `update_route` (the
    // handler normalises `Some(0) => None` before writing to the
    // DB ; the dashboard relies on this via `empty(0)` in
    // `route-form.ts` to re-clear an optional field). Extend the
    // lower bound to 0 here so the clear path is not mistaken for
    // a bad value ; any non-zero value still has to land inside
    // the documented bounds.
    if let Some(v) = max_connections {
        check_range(v, 0, 1_000_000, "max_connections")?;
    }
    if let Some(v) = slowloris_threshold_ms {
        check_range(v, 100, 600_000, "slowloris_threshold_ms")?;
    }
    if let Some(v) = auto_ban_threshold {
        check_range(v, 0, 10_000, "auto_ban_threshold")?;
    }
    if let Some(v) = auto_ban_duration_s {
        check_range(v, 1, 31_536_000, "auto_ban_duration_s")?;
    }
    // `return_status` uses the same "0 = clear" convention, but
    // unlike the two fields above, non-zero values MUST be a valid
    // HTTP status code (100..=599). Extending the range to
    // `0..=599` would let `return_status: 42` through and emit a
    // malformed response line on the wire. Bypass the range check
    // for 0 explicitly so the clear path works while the HTTP
    // range stays strict for every other value.
    if let Some(v) = return_status {
        if v != 0 {
            check_range(v, 100, 599, "return_status")?;
        }
    }
    if let Some(v) = retry_attempts {
        check_range(v, 0, 10, "retry_attempts")?;
    }
    if let Some(v) = stale_while_revalidate_s {
        check_range(v, 0, 86_400, "stale_while_revalidate_s")?;
    }
    if let Some(v) = stale_if_error_s {
        check_range(v, 0, 86_400, "stale_if_error_s")?;
    }
    if let Some(v) = cors_max_age_s {
        check_range(v, 0, 86_400, "cors_max_age_s")?;
    }
    if let Some(v) = max_request_body_bytes {
        // Upper bound = 128 GiB. Zero is legal (means "unlimited",
        // translated to None by `update_route` and `create_route`).
        check_range(v, 0, 137_438_953_472, "max_request_body_bytes")?;
    }
    Ok(())
}

/// Rate-limit bounds kept in a dedicated helper so the main
/// numeric-bounds validator does not grow past `#[allow(clippy::
/// too_many_arguments)]`. `rate_limit_rps` and `rate_limit_burst`
/// use the same "0 = clear" convention as `max_connections` (the
/// handler normalises `Some(0) => None` before persisting), so the
/// lower bound is 0. The 1_000_000 ceiling mirrors `max_connections`
/// and keeps `rps + burst` well inside u32 at the proxy level
/// (`proxy_wiring::rate_limit` adds them as a `u32` to derive
/// `effective_limit`).
fn validate_rate_limit_bounds(
    rate_limit_rps: Option<u32>,
    rate_limit_burst: Option<u32>,
) -> Result<(), ApiError> {
    if let Some(v) = rate_limit_rps {
        check_range(v, 0, 1_000_000, "rate_limit_rps")?;
    }
    if let Some(v) = rate_limit_burst {
        check_range(v, 0, 1_000_000, "rate_limit_burst")?;
    }
    Ok(())
}

/// Validate a CORS origin entry. Accepts `*`, `null`, or a full
/// `scheme://host[:port]` URL without path / query / fragment. The
/// CORS spec only attaches meaning to origin-equality, so an origin
/// with a path is always a mistake.
fn validate_cors_origin(origin: &str, field_label: &str) -> Result<(), ApiError> {
    if origin == "*" || origin == "null" {
        return Ok(());
    }
    if origin.len() > 2048 {
        return Err(ApiError::BadRequest(format!(
            "{field_label}: origin {origin:?} is longer than 2048 characters"
        )));
    }
    if origin.chars().any(|c| c.is_whitespace()) {
        return Err(ApiError::BadRequest(format!(
            "{field_label}: origin {origin:?} contains whitespace"
        )));
    }
    let rest = if let Some(r) = origin.strip_prefix("http://") {
        r
    } else if let Some(r) = origin.strip_prefix("https://") {
        r
    } else {
        return Err(ApiError::BadRequest(format!(
            "{field_label}: origin {origin:?} must be `*`, `null`, or a full \
             `http(s)://host[:port]` URL"
        )));
    };
    if rest.contains('/') || rest.contains('?') || rest.contains('#') {
        return Err(ApiError::BadRequest(format!(
            "{field_label}: origin {origin:?} must not contain a path, query, or fragment"
        )));
    }
    if rest.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "{field_label}: origin {origin:?} must include a host after the scheme"
        )));
    }
    Ok(())
}

/// Validate a `path_rewrite_replacement` string. Bounded-length guard
/// (2048 chars, same ceiling as URLs). Rejects regex replacements that
/// reference capture groups not present in the pattern (`$1` when the
/// pattern has no groups) because those would silently emit the literal
/// `$1` to the backend at runtime - a correctness footgun the operator
/// can't diagnose from the proxy log.
fn validate_path_rewrite_replacement(
    replacement: &str,
    pattern: Option<&str>,
) -> Result<String, ApiError> {
    const MAX_REPLACEMENT_LEN: usize = 2048;
    if replacement.len() > MAX_REPLACEMENT_LEN {
        return Err(ApiError::BadRequest(format!(
            "path_rewrite_replacement must be <= {MAX_REPLACEMENT_LEN} characters"
        )));
    }
    if let Some(p) = pattern.filter(|p| !p.is_empty()) {
        let captures = regex::Regex::new(p).map(|r| r.captures_len()).unwrap_or(1);
        // captures_len() counts the implicit group-0 (the whole match)
        // plus each `(...)`. A pattern with N explicit groups allows
        // references `$0..$N`.
        let max_ref = captures.saturating_sub(1);
        // `$$` in a regex replacement is a literal `$`. Strip those
        // pairs first so a legitimate `$$5` (meant as literal `$5`)
        // does not get flagged as an invalid `$5` reference.
        let scan = replacement.replace("$$", "");
        let ref_re = regex::Regex::new(r"\$(\d+)").expect("static regex");
        for cap in ref_re.captures_iter(&scan) {
            let n: usize = cap[1].parse().unwrap_or(0);
            if n > max_ref {
                return Err(ApiError::BadRequest(format!(
                    "path_rewrite_replacement references `${n}` but the pattern has \
                     only {max_ref} capture group{s}",
                    s = if max_ref == 1 { "" } else { "s" }
                )));
            }
        }
    }
    Ok(replacement.to_string())
}

#[cfg(test)]
mod rate_limit_tests {
    use super::*;
    use lorica_config::models::{RateLimit, RateLimitScope};

    fn rl(capacity: u32, refill_per_sec: u32) -> RateLimit {
        RateLimit {
            capacity,
            refill_per_sec,
            scope: RateLimitScope::PerIp,
        }
    }

    #[test]
    fn accepts_minimal_valid_config() {
        let out = validate_rate_limit(&rl(1, 0)).expect("capacity=1 refill=0 should pass");
        assert_eq!(out.capacity, 1);
        assert_eq!(out.refill_per_sec, 0);
    }

    #[test]
    fn accepts_at_cap() {
        assert!(validate_rate_limit(&rl(RATE_LIMIT_MAX, RATE_LIMIT_MAX)).is_ok());
    }

    #[test]
    fn rejects_zero_capacity() {
        match validate_rate_limit(&rl(0, 10)) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("capacity"), "msg={msg}");
                assert!(msg.contains("> 0"), "msg should mention > 0: {msg}");
            }
            other => panic!("expected BadRequest on capacity=0, got {other:?}"),
        }
    }

    #[test]
    fn rejects_capacity_above_cap() {
        match validate_rate_limit(&rl(RATE_LIMIT_MAX + 1, 0)) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("capacity"));
                assert!(msg.contains(&RATE_LIMIT_MAX.to_string()));
            }
            other => panic!("expected BadRequest on capacity overflow, got {other:?}"),
        }
    }

    #[test]
    fn rejects_refill_above_cap() {
        match validate_rate_limit(&rl(1, RATE_LIMIT_MAX + 1)) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("refill_per_sec"));
                assert!(msg.contains(&RATE_LIMIT_MAX.to_string()));
            }
            other => panic!("expected BadRequest on refill overflow, got {other:?}"),
        }
    }

    #[test]
    fn preserves_scope_across_validation() {
        let input = RateLimit {
            capacity: 42,
            refill_per_sec: 7,
            scope: RateLimitScope::PerRoute,
        };
        let out = validate_rate_limit(&input).unwrap();
        assert_eq!(out.scope, RateLimitScope::PerRoute);
    }

    #[test]
    fn does_not_mutate_input_on_success() {
        let input = rl(50, 5);
        let out = validate_rate_limit(&input).unwrap();
        // out is a clone, input untouched (the function takes &RateLimit).
        assert_eq!(input.capacity, 50);
        assert_eq!(out.capacity, 50);
    }
}

#[cfg(test)]
mod group_name_validation_tests {
    use super::*;

    fn expect_err(input: &str) -> String {
        match validate_group_name(input) {
            Ok(v) => panic!("expected validation error for {input:?}, got Ok({v:?})"),
            Err(ApiError::BadRequest(m)) => m,
            Err(e) => panic!("expected BadRequest, got {e:?}"),
        }
    }

    #[test]
    fn accepts_empty() {
        assert_eq!(validate_group_name("").unwrap(), "");
        assert_eq!(validate_group_name("   ").unwrap(), "");
    }

    #[test]
    fn accepts_valid_identifiers() {
        assert_eq!(validate_group_name("prod").unwrap(), "prod");
        assert_eq!(
            validate_group_name("homelab-staging").unwrap(),
            "homelab-staging"
        );
        assert_eq!(validate_group_name("my_group_42").unwrap(), "my_group_42");
        assert_eq!(validate_group_name("a").unwrap(), "a");
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(validate_group_name("  prod  ").unwrap(), "prod");
    }

    #[test]
    fn rejects_uppercase() {
        assert!(expect_err("PROD").contains("lowercase"));
        assert!(expect_err("Prod").contains("lowercase"));
    }

    #[test]
    fn rejects_whitespace_and_special_chars() {
        assert!(expect_err("my group").contains("lowercase"));
        assert!(expect_err("my.group").contains("lowercase"));
        assert!(expect_err("my/group").contains("lowercase"));
        assert!(expect_err("accent-é").contains("lowercase"));
    }

    #[test]
    fn rejects_too_long() {
        let long = "a".repeat(100);
        assert!(expect_err(&long).contains("64"));
    }
}

#[cfg(test)]
mod redirect_hostname_validation_tests {
    use super::*;

    fn expect_err(input: &str) -> String {
        match validate_redirect_hostname(input) {
            Ok(v) => panic!("expected validation error for {input:?}, got Ok({v:?})"),
            Err(ApiError::BadRequest(m)) => m,
            Err(e) => panic!("expected BadRequest, got {e:?}"),
        }
    }

    #[test]
    fn empty_or_whitespace_clears_the_field() {
        assert_eq!(validate_redirect_hostname("").unwrap(), "");
        assert_eq!(validate_redirect_hostname("   ").unwrap(), "");
        assert_eq!(validate_redirect_hostname("\t\n").unwrap(), "");
    }

    #[test]
    fn accepts_bare_hostname() {
        assert_eq!(
            validate_redirect_hostname("example.com").unwrap(),
            "example.com"
        );
        assert_eq!(
            validate_redirect_hostname("  www.example.com  ").unwrap(),
            "www.example.com"
        );
        assert_eq!(
            validate_redirect_hostname("a-b.c-d.example.co.uk").unwrap(),
            "a-b.c-d.example.co.uk"
        );
    }

    #[test]
    fn accepts_single_label_hostname() {
        // "localhost" and similar single-label internal names are common
        // in home-lab Lorica setups; we must not reject them.
        assert_eq!(
            validate_redirect_hostname("localhost").unwrap(),
            "localhost"
        );
        assert_eq!(validate_redirect_hostname("plex").unwrap(), "plex");
    }

    #[test]
    fn rejects_scheme() {
        assert!(expect_err("https://example.com").contains("scheme"));
        assert!(expect_err("http://example.com").contains("scheme"));
        assert!(expect_err("HTTP://example.com").contains("scheme"));
    }

    #[test]
    fn rejects_path_or_trailing_slash() {
        assert!(expect_err("example.com/").contains("path"));
        assert!(expect_err("example.com/foo").contains("path"));
        assert!(expect_err("/example.com").contains("path"));
    }

    #[test]
    fn rejects_port_query_fragment() {
        // Port (`:8080`), query (`?x=1`) and fragment (`#frag`) are
        // URL syntax, not hostname syntax. Reject with the shared
        // "not valid in a hostname" message so the UI fails fast.
        assert!(expect_err("example.com:8080").contains("not valid"));
        assert!(expect_err("example.com?x=1").contains("not valid"));
        assert!(expect_err("example.com#foo").contains("not valid"));
        assert!(expect_err("user@example.com").contains("not valid"));
    }

    #[test]
    fn rejects_whitespace() {
        // Surrounding whitespace is trimmed and accepted (tested
        // separately above); whitespace *inside* the hostname is a
        // syntax error.
        assert!(expect_err("exa mple.com").contains("not valid"));
        assert!(expect_err("example.\tcom").contains("not valid"));
    }

    #[test]
    fn rejects_leading_or_trailing_dot() {
        assert!(expect_err(".example.com").contains("dot"));
        assert!(expect_err("example.com.").contains("dot"));
    }

    #[test]
    fn rejects_consecutive_dots() {
        assert!(expect_err("example..com").contains("empty DNS label"));
    }

    #[test]
    fn rejects_label_too_long() {
        let long_label = "a".repeat(64);
        let input = format!("{long_label}.com");
        assert!(expect_err(&input).contains("63"));
    }

    #[test]
    fn rejects_total_too_long() {
        // 64 labels of 3 chars + 63 dots = 255 chars, exceeds the 253 cap.
        let input = (0..64).map(|_| "abc").collect::<Vec<_>>().join(".");
        assert!(expect_err(&input).contains("253"));
    }

    #[test]
    fn rejects_label_leading_or_trailing_dash() {
        assert!(expect_err("-example.com").contains("`-`"));
        assert!(expect_err("example-.com").contains("`-`"));
        assert!(expect_err("example.-com").contains("`-`"));
        assert!(expect_err("example.com-").contains("`-`"));
    }

    #[test]
    fn rejects_non_ascii_or_punctuation() {
        assert!(expect_err("exämple.com").contains("ASCII"));
        assert!(expect_err("example_underscore.com").contains("ASCII"));
    }
}

#[cfg(test)]
mod hostname_alias_tests {
    use super::*;

    #[test]
    fn accepts_bare_hostnames_and_wildcards() {
        assert!(validate_hostname_alias("example.com", "f").is_ok());
        assert!(validate_hostname_alias("api.example.com", "f").is_ok());
        assert!(validate_hostname_alias("*.example.com", "f").is_ok());
    }

    #[test]
    fn rejects_scheme_path_whitespace_empty() {
        assert!(validate_hostname_alias("https://example.com", "f").is_err());
        assert!(validate_hostname_alias("example.com/foo", "f").is_err());
        assert!(validate_hostname_alias("exa mple.com", "f").is_err());
        assert!(validate_hostname_alias("", "f").is_err());
    }

    #[test]
    fn rejects_leading_trailing_dot_and_dash() {
        assert!(validate_hostname_alias(".example.com", "f").is_err());
        assert!(validate_hostname_alias("example.com.", "f").is_err());
        assert!(validate_hostname_alias("-example.com", "f").is_err());
        assert!(validate_hostname_alias("example-.com", "f").is_err());
    }

    #[test]
    fn rejects_too_long_label_or_hostname() {
        let long_label = format!("{}.example.com", "a".repeat(64));
        assert!(validate_hostname_alias(&long_label, "f").is_err());
        let long_total = (0..64).map(|_| "abc").collect::<Vec<_>>().join(".");
        assert!(validate_hostname_alias(&long_total, "f").is_err());
    }
}

#[cfg(test)]
mod error_page_html_tests {
    use super::*;

    #[test]
    fn accepts_small_page() {
        assert!(validate_error_page_html("<h1>oops</h1>").is_ok());
        assert!(validate_error_page_html("").is_ok());
    }

    #[test]
    fn rejects_over_128_kib() {
        let big = "a".repeat(128 * 1024 + 1);
        let err = validate_error_page_html(&big).expect_err("test");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("128 KiB")));
    }
}

#[cfg(test)]
mod route_path_validation_tests {
    use super::*;

    #[test]
    fn empty_clears_the_field() {
        assert_eq!(validate_route_path("", "path_prefix").unwrap(), "");
        assert_eq!(validate_route_path("   ", "path_prefix").unwrap(), "");
    }

    #[test]
    fn accepts_paths_with_leading_slash() {
        assert_eq!(validate_route_path("/", "f").unwrap(), "/");
        assert_eq!(validate_route_path("/api", "f").unwrap(), "/api");
        assert_eq!(
            validate_route_path("/api/v1/users", "f").unwrap(),
            "/api/v1/users"
        );
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(validate_route_path("  /api  ", "f").unwrap(), "/api");
    }

    #[test]
    fn rejects_missing_leading_slash() {
        let err = validate_route_path("api", "f").expect_err("test");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("'/'")));
    }

    #[test]
    fn rejects_whitespace_inside() {
        assert!(validate_route_path("/foo bar", "f").is_err());
        assert!(validate_route_path("/foo\tbar", "f").is_err());
    }

    #[test]
    fn rejects_too_long() {
        let long = format!("/{}", "a".repeat(1100));
        let err = validate_route_path(&long, "f").expect_err("test");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("1024")));
    }

    #[test]
    fn rejects_control_char() {
        let err = validate_route_path("/foo\x01bar", "f").expect_err("test");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("control character")));
    }
}

#[cfg(test)]
mod route_numeric_bounds_tests {
    use super::*;

    fn ok(f: impl FnOnce() -> Result<(), ApiError>) {
        f().expect("expected Ok");
    }

    fn err_matches(f: impl FnOnce() -> Result<(), ApiError>, needle: &str) {
        let e = f().expect_err("expected Err");
        match e {
            ApiError::BadRequest(m) => assert!(m.contains(needle), "got {m:?}, wanted {needle:?}"),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn accepts_all_defaults() {
        ok(|| {
            validate_route_numeric_bounds(
                Some(5),
                Some(60),
                Some(60),
                Some(300),
                Some(52_428_800),
                None,
                Some(5000),
                None,
                Some(3600),
                None,
                None,
                Some(10),
                Some(60),
                None,
                None,
            )
        });
    }

    #[test]
    fn timeouts_bounds() {
        err_matches(
            || {
                validate_route_numeric_bounds(
                    Some(0),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            },
            "connect_timeout_s",
        );
        err_matches(
            || {
                validate_route_numeric_bounds(
                    None,
                    Some(3601),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            },
            "read_timeout_s",
        );
        err_matches(
            || {
                validate_route_numeric_bounds(
                    None,
                    None,
                    Some(-1),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            },
            "send_timeout_s",
        );
    }

    #[test]
    fn return_status_must_be_in_http_range() {
        err_matches(
            || {
                validate_route_numeric_bounds(
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(42),
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            },
            "return_status",
        );
        err_matches(
            || {
                validate_route_numeric_bounds(
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(600),
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            },
            "return_status",
        );
        ok(|| {
            validate_route_numeric_bounds(
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(418),
                None,
                None,
                None,
                None,
                None,
            )
        });
    }

    #[test]
    fn cors_max_age_rejects_negative_and_huge() {
        err_matches(
            || {
                validate_route_numeric_bounds(
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(-1),
                    None,
                )
            },
            "cors_max_age_s",
        );
        err_matches(
            || {
                validate_route_numeric_bounds(
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(100_000),
                    None,
                )
            },
            "cors_max_age_s",
        );
    }

    #[test]
    fn retry_attempts_cap() {
        err_matches(
            || {
                validate_route_numeric_bounds(
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(11),
                    None,
                    None,
                    None,
                    None,
                )
            },
            "retry_attempts",
        );
        ok(|| {
            validate_route_numeric_bounds(
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(3),
                None,
                None,
                None,
                None,
            )
        });
    }

    #[test]
    fn zero_is_accepted_as_clear_on_the_three_optional_fields() {
        // v1.5.1 fix : `max_connections`, `auto_ban_threshold` and
        // `return_status` all follow the "0 = clear / disabled /
        // no limit" convention the frontend sends on every UPDATE
        // via `route-form.ts::empty(0)`. The old validator
        // rejected 0 for all three, producing "must be in 1..=X"
        // 400s on every route save for routes that were never
        // configured with a max / auto-ban / short-circuit.
        assert!(validate_route_numeric_bounds(
            None,
            None,
            None,
            None,
            None,
            Some(0), // max_connections
            None,
            Some(0), // auto_ban_threshold
            None,
            Some(0), // return_status
            None,
            None,
            None,
            None,
            None,
        )
        .is_ok());
    }

    #[test]
    fn max_connections_still_rejects_values_past_the_cap() {
        // Zero means "clear" (see above), but any non-zero value
        // must still land inside the documented bounds.
        err_matches(
            || {
                validate_route_numeric_bounds(
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(2_000_000), // past the 1_000_000 cap
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            },
            "max_connections",
        );
    }

    #[test]
    fn auto_ban_threshold_still_rejects_values_past_the_cap() {
        err_matches(
            || {
                validate_route_numeric_bounds(
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(50_000), // past the 10_000 cap
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            },
            "auto_ban_threshold",
        );
    }

    #[test]
    fn return_status_accepts_zero_but_rejects_invalid_http_status() {
        // The 0 = clear sentinel is accepted, but unlike
        // max_connections / auto_ban_threshold the non-zero range
        // is restricted to valid HTTP status codes (100..=599) so
        // a typo like `return_status: 42` doesn't emit a
        // malformed response line on the wire.
        err_matches(
            || {
                validate_route_numeric_bounds(
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(42), // below HTTP range
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            },
            "return_status",
        );
        err_matches(
            || {
                validate_route_numeric_bounds(
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(650), // above HTTP range
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            },
            "return_status",
        );
    }

    #[test]
    fn cache_ttl_and_max_bytes_accept_zero() {
        // v1.5.1 follow-up : `cache_ttl_s == 0` is a valid HTTP
        // cache configuration (always revalidate, paired with SWR)
        // and `cache_max_bytes == 0` is the runtime sentinel for
        // "no per-entry size cap" (see the `cache_max_bytes > 0`
        // guard in `request_cache_filter`). Both were rejected by
        // the v1.5.0 lower-bound-1 validator.
        ok(|| {
            validate_route_numeric_bounds(
                None,
                None,
                None,
                Some(0), // cache_ttl_s
                Some(0), // cache_max_bytes
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
        });
    }

    #[test]
    fn cache_ttl_still_rejects_values_past_the_cap() {
        err_matches(
            || {
                validate_route_numeric_bounds(
                    None,
                    None,
                    None,
                    Some(40_000_000), // past the 1-year cap
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            },
            "cache_ttl_s",
        );
    }
}

#[cfg(test)]
mod rate_limit_bounds_tests {
    use super::*;

    fn err_matches<F: FnOnce() -> Result<(), ApiError>>(f: F, needle: &str) {
        let err = f().expect_err("test setup");
        match err {
            ApiError::BadRequest(m) => {
                assert!(
                    m.contains(needle),
                    "expected error message to contain {needle:?} : {m}"
                );
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    /// `rate_limit_rps == 0` and `rate_limit_burst == 0` are
    /// valid clear sentinels : `create_route` and `update_route`
    /// both normalise `Some(0) => None` before writing, so the
    /// validator has to let 0 through.
    #[test]
    fn zero_is_accepted_as_clear() {
        validate_rate_limit_bounds(Some(0), Some(0)).expect("zero must be accepted");
    }

    #[test]
    fn none_is_accepted() {
        validate_rate_limit_bounds(None, None).expect("None must be accepted");
    }

    #[test]
    fn in_range_values_are_accepted() {
        validate_rate_limit_bounds(Some(1_000), Some(500)).expect("typical values must pass");
    }

    #[test]
    fn rps_past_the_cap_is_rejected() {
        err_matches(
            || validate_rate_limit_bounds(Some(10_000_000), None),
            "rate_limit_rps",
        );
    }

    #[test]
    fn burst_past_the_cap_is_rejected() {
        err_matches(
            || validate_rate_limit_bounds(None, Some(10_000_000)),
            "rate_limit_burst",
        );
    }

    /// The documented ceiling is 1_000_000 on both fields, which
    /// mirrors `max_connections` and keeps `rps + burst` well
    /// inside u32 on the proxy hot path.
    #[test]
    fn exactly_one_million_is_accepted() {
        validate_rate_limit_bounds(Some(1_000_000), Some(1_000_000))
            .expect("the 1M ceiling itself must pass");
    }
}

#[cfg(test)]
mod http_header_validation_tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn header_name_accepts_rfc_token_chars() {
        for name in &[
            "X-Forwarded-For",
            "Content-Type",
            "X_My_Header",
            "X-99-Proxy",
            "!#$%&'*+-.^_`|~",
        ] {
            validate_http_header_name(name, "h")
                .unwrap_or_else(|e| panic!("expected {name:?} to pass: {e:?}"));
        }
    }

    #[test]
    fn header_name_rejects_empty() {
        let err = validate_http_header_name("", "h").expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("must not be empty")));
    }

    #[test]
    fn header_name_rejects_whitespace_and_special_chars() {
        for name in &["X Forwarded", "Content Type", "X:Bad", "X\tBad", "X@bad"] {
            assert!(
                validate_http_header_name(name, "h").is_err(),
                "name {name:?}"
            );
        }
    }

    #[test]
    fn header_name_rejects_too_long() {
        let long = "a".repeat(300);
        let err = validate_http_header_name(&long, "h").expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("256")));
    }

    #[test]
    fn header_value_accepts_printable_ascii_and_utf8() {
        for value in &["foo", "no-cache, no-store", "café", ""] {
            validate_http_header_value(value, "h")
                .unwrap_or_else(|e| panic!("expected {value:?} to pass: {e:?}"));
        }
    }

    #[test]
    fn header_value_rejects_cr_lf_nul() {
        assert!(validate_http_header_value("foo\r", "h").is_err());
        assert!(validate_http_header_value("foo\n", "h").is_err());
        assert!(validate_http_header_value("foo\0", "h").is_err());
        assert!(validate_http_header_value("foo\r\nX-Admin: yes", "h").is_err());
    }

    #[test]
    fn header_value_rejects_too_long() {
        let long = "a".repeat(5000);
        assert!(validate_http_header_value(&long, "h").is_err());
    }

    #[test]
    fn headers_map_catches_bad_name() {
        let mut map = HashMap::new();
        map.insert("X Bad".into(), "ok".into());
        assert!(validate_http_headers_map(&map, "proxy_headers").is_err());
    }

    #[test]
    fn headers_map_catches_bad_value() {
        let mut map = HashMap::new();
        map.insert("X-Good".into(), "bad\r\nX-Admin: yes".into());
        assert!(validate_http_headers_map(&map, "proxy_headers").is_err());
    }

    #[test]
    fn method_accepts_standard_verbs() {
        for m in &[
            "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "MKCOL",
        ] {
            validate_http_method(m, "methods")
                .unwrap_or_else(|e| panic!("expected {m:?} to pass: {e:?}"));
        }
    }

    #[test]
    fn method_rejects_lowercase_and_garbage() {
        assert!(validate_http_method("get", "m").is_err());
        assert!(validate_http_method("GET,POST", "m").is_err());
        assert!(validate_http_method("GET ", "m").is_err());
        assert!(validate_http_method("", "m").is_err());
        assert!(validate_http_method("GET1", "m").is_err());
    }

    #[test]
    fn cors_origin_accepts_wildcard_and_null() {
        validate_cors_origin("*", "o").unwrap();
        validate_cors_origin("null", "o").unwrap();
    }

    #[test]
    fn cors_origin_accepts_scheme_host_port() {
        validate_cors_origin("https://example.com", "o").unwrap();
        validate_cors_origin("http://example.com:8080", "o").unwrap();
    }

    #[test]
    fn cors_origin_rejects_path_query_fragment() {
        assert!(validate_cors_origin("https://example.com/", "o").is_err());
        assert!(validate_cors_origin("https://example.com/foo", "o").is_err());
        assert!(validate_cors_origin("https://example.com?x=1", "o").is_err());
        assert!(validate_cors_origin("https://example.com#frag", "o").is_err());
    }

    #[test]
    fn cors_origin_rejects_bare_host_and_bad_scheme() {
        assert!(validate_cors_origin("example.com", "o").is_err());
        assert!(validate_cors_origin("ftp://example.com", "o").is_err());
        assert!(validate_cors_origin("https://", "o").is_err());
    }

    #[test]
    fn cors_origin_rejects_whitespace() {
        assert!(validate_cors_origin("https://exam ple.com", "o").is_err());
    }
}

#[cfg(test)]
mod redirect_to_validation_tests {
    use super::*;

    fn expect_err(input: &str) -> String {
        match validate_redirect_to(input, "redirect_to") {
            Ok(v) => panic!("expected validation error for {input:?}, got Ok({v:?})"),
            Err(ApiError::BadRequest(m)) => m,
            Err(e) => panic!("expected BadRequest, got {e:?}"),
        }
    }

    #[test]
    fn empty_or_whitespace_clears_the_field() {
        assert_eq!(validate_redirect_to("", "redirect_to").unwrap(), "");
        assert_eq!(validate_redirect_to("   ", "redirect_to").unwrap(), "");
    }

    #[test]
    fn accepts_http_and_https_urls() {
        assert_eq!(
            validate_redirect_to("https://example.com", "redirect_to").unwrap(),
            "https://example.com"
        );
        assert_eq!(
            validate_redirect_to("http://example.com/legacy", "redirect_to").unwrap(),
            "http://example.com/legacy"
        );
        assert_eq!(
            validate_redirect_to(
                "https://www.youtube.com/redirect?q=https://plex.rwx-g.fr/",
                "redirect_to"
            )
            .unwrap(),
            "https://www.youtube.com/redirect?q=https://plex.rwx-g.fr/"
        );
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(
            validate_redirect_to("  https://example.com  ", "redirect_to").unwrap(),
            "https://example.com"
        );
    }

    #[test]
    fn rejects_missing_scheme() {
        assert!(expect_err("example.com").contains("http"));
        assert!(expect_err("//example.com").contains("http"));
        assert!(expect_err("ftp://example.com").contains("http"));
    }

    #[test]
    fn rejects_scheme_without_host() {
        assert!(expect_err("https://").contains("host"));
        assert!(expect_err("https:///path").contains("host"));
    }

    #[test]
    fn rejects_whitespace_inside_url() {
        assert!(expect_err("https://example .com").contains("whitespace"));
        assert!(expect_err("https://example.com/foo bar").contains("whitespace"));
    }

    #[test]
    fn rejects_too_long_url() {
        let long = format!("https://example.com/{}", "a".repeat(2048));
        assert!(expect_err(&long).contains("2048"));
    }

    #[test]
    fn uses_the_provided_field_label_in_errors() {
        // Path-rule callers pass `path_rules[3].redirect_to` as the
        // label so the UI can show the operator which specific rule is
        // the offender.
        match validate_redirect_to("nope", "path_rules[3].redirect_to") {
            Err(ApiError::BadRequest(m)) => {
                assert!(m.contains("path_rules[3].redirect_to"))
            }
            _ => panic!("expected BadRequest"),
        }
    }
}

#[cfg(test)]
mod path_rewrite_validation_tests {
    use super::*;

    #[test]
    fn pattern_empty_returns_empty_string() {
        assert_eq!(validate_path_rewrite_pattern("").unwrap(), "");
        assert_eq!(validate_path_rewrite_pattern("   ").unwrap(), "");
    }

    #[test]
    fn pattern_accepts_valid_regex() {
        assert_eq!(
            validate_path_rewrite_pattern(r"^/api/v1/(.*)$").unwrap(),
            r"^/api/v1/(.*)$"
        );
    }

    #[test]
    fn pattern_rejects_invalid_regex() {
        match validate_path_rewrite_pattern("(unclosed") {
            Err(ApiError::BadRequest(m)) => assert!(m.contains("not a valid regex")),
            _ => panic!("expected BadRequest"),
        }
    }

    #[test]
    fn pattern_rejects_too_long() {
        let long = "a".repeat(2048);
        match validate_path_rewrite_pattern(&long) {
            Err(ApiError::BadRequest(m)) => assert!(m.contains("1024")),
            _ => panic!("expected BadRequest"),
        }
    }

    #[test]
    fn replacement_length_cap() {
        let long = "a".repeat(3000);
        match validate_path_rewrite_replacement(&long, None) {
            Err(ApiError::BadRequest(m)) => assert!(m.contains("2048")),
            _ => panic!("expected BadRequest"),
        }
    }

    #[test]
    fn replacement_accepts_no_group_reference_when_pattern_has_none() {
        assert_eq!(
            validate_path_rewrite_replacement("/static/$0", Some(r"^/api/")).unwrap(),
            "/static/$0"
        );
    }

    #[test]
    fn replacement_accepts_in_range_group_references() {
        assert_eq!(
            validate_path_rewrite_replacement("/v2/$1", Some(r"^/api/v1/(.*)$")).unwrap(),
            "/v2/$1"
        );
        assert_eq!(
            validate_path_rewrite_replacement("/$1/$2/$3", Some(r"^/(a)/(b)/(c)$")).unwrap(),
            "/$1/$2/$3"
        );
    }

    #[test]
    fn replacement_rejects_out_of_range_group_references() {
        match validate_path_rewrite_replacement("/v2/$3", Some(r"^/api/v1/(.*)$")) {
            Err(ApiError::BadRequest(m)) => {
                assert!(m.contains("$3"));
                assert!(m.contains("only 1"));
            }
            _ => panic!("expected BadRequest"),
        }
    }

    #[test]
    fn replacement_respects_dollar_escape() {
        // `$$` is a literal `$` in the regex crate's replacement syntax.
        // `$$5` means "$5" as a literal string; the validator must not
        // flag it as a group reference.
        assert_eq!(
            validate_path_rewrite_replacement("price: $$5", Some(r"^/x$")).unwrap(),
            "price: $$5"
        );
    }

    #[test]
    fn replacement_no_check_when_pattern_is_none() {
        // Without a pattern the field is meaningless but the validator
        // should not choke on capture-group refs - it just bounces at
        // the pattern level.
        assert_eq!(
            validate_path_rewrite_replacement("/v2/$99", None).unwrap(),
            "/v2/$99"
        );
    }
}

#[cfg(test)]
mod geoip_validation_tests {
    use super::*;
    use lorica_config::models::{GeoIpConfig, GeoIpMode};

    fn cfg(mode: GeoIpMode, countries: &[&str]) -> GeoIpConfig {
        GeoIpConfig {
            mode,
            countries: countries.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn normalises_country_case() {
        let out = validate_geoip(&cfg(GeoIpMode::Denylist, &["us", "Fr", "DE"])).unwrap();
        assert_eq!(out.countries, vec!["US", "FR", "DE"]);
    }

    #[test]
    fn trims_and_dedupes() {
        // Whitespace padding + duplicate after case-folding.
        let out = validate_geoip(&cfg(GeoIpMode::Denylist, &[" us ", "US", "fr"])).unwrap();
        assert_eq!(out.countries, vec!["US", "FR"]);
    }

    #[test]
    fn skips_empty_entries() {
        let out = validate_geoip(&cfg(GeoIpMode::Denylist, &["", "US", "   "])).unwrap();
        assert_eq!(out.countries, vec!["US"]);
    }

    #[test]
    fn rejects_non_alpha2() {
        match validate_geoip(&cfg(GeoIpMode::Denylist, &["USA"])) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("USA"), "msg={msg}");
                assert!(msg.contains("alpha-2"), "msg={msg}");
            }
            other => panic!("expected BadRequest on 3-letter code, got {other:?}"),
        }
    }

    #[test]
    fn rejects_digits() {
        assert!(matches!(
            validate_geoip(&cfg(GeoIpMode::Denylist, &["U1"])),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn rejects_allowlist_with_empty_list() {
        // Allowlist with no countries = block everyone; must be rejected
        // so the operator sees the mistake at API time instead of at
        // traffic time.
        match validate_geoip(&cfg(GeoIpMode::Allowlist, &[])) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("allowlist"), "msg={msg}");
                assert!(msg.contains("empty"), "msg={msg}");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn accepts_denylist_with_empty_list() {
        // Denylist + empty = "block nobody", legal no-op (equivalent
        // to `geoip: null`, useful when keeping the row around for
        // quick re-enable).
        let out = validate_geoip(&cfg(GeoIpMode::Denylist, &[])).unwrap();
        assert_eq!(out.mode, GeoIpMode::Denylist);
        assert!(out.countries.is_empty());
    }

    #[test]
    fn rejects_oversize_list() {
        // 301 distinct ASCII alpha-2 combos would exceed MAX_COUNTRIES.
        // We cheat by generating synthetic duplicates - dedup kicks
        // first though, so pad with distinct codes.
        let mut long: Vec<String> = Vec::with_capacity(301);
        for a in b'A'..=b'Z' {
            for b in b'A'..=b'Z' {
                if long.len() >= 301 {
                    break;
                }
                long.push(format!("{}{}", a as char, b as char));
            }
        }
        assert!(long.len() > 300);
        let cfg = GeoIpConfig {
            mode: GeoIpMode::Denylist,
            countries: long,
        };
        match validate_geoip(&cfg) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("at most 300"), "msg={msg}");
            }
            other => panic!("expected BadRequest on oversize list, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod bot_protection_validation_tests {
    use super::*;
    use lorica_config::models::{BotBypassRules, BotProtectionConfig, BotProtectionMode};

    fn baseline() -> BotProtectionConfig {
        BotProtectionConfig {
            mode: BotProtectionMode::Javascript,
            cookie_ttl_s: 86_400,
            pow_difficulty: 18,
            captcha_alphabet: "23456789abcdefghijkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ".to_string(),
            bypass: BotBypassRules::default(),
            only_country: None,
        }
    }

    #[test]
    fn accepts_baseline() {
        validate_bot_protection(&baseline()).expect("defaults must validate");
    }

    #[test]
    fn rejects_cookie_ttl_zero() {
        let mut c = baseline();
        c.cookie_ttl_s = 0;
        assert!(matches!(
            validate_bot_protection(&c),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn rejects_cookie_ttl_above_cap() {
        let mut c = baseline();
        c.cookie_ttl_s = 604_801;
        match validate_bot_protection(&c) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("604800"), "msg={msg}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rejects_difficulty_below_floor() {
        let mut c = baseline();
        c.pow_difficulty = 13;
        match validate_bot_protection(&c) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("14..=22"), "msg={msg}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rejects_difficulty_above_ceiling() {
        let mut c = baseline();
        c.pow_difficulty = 23;
        assert!(matches!(
            validate_bot_protection(&c),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn rejects_short_alphabet() {
        let mut c = baseline();
        c.captcha_alphabet = "abc".to_string();
        match validate_bot_protection(&c) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("shorter than minimum"), "msg={msg}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rejects_alphabet_with_duplicates() {
        let mut c = baseline();
        c.captcha_alphabet = "aabcdefghij".to_string();
        match validate_bot_protection(&c) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("duplicate"), "msg={msg}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rejects_alphabet_with_non_printable() {
        let mut c = baseline();
        c.captcha_alphabet = "abcdefghij\t".to_string();
        assert!(matches!(
            validate_bot_protection(&c),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn accepts_valid_ip_cidr_bypass() {
        let mut c = baseline();
        c.bypass.ip_cidrs = vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()];
        validate_bot_protection(&c).unwrap();
    }

    #[test]
    fn accepts_bare_ip_in_bypass() {
        // Matches the existing trusted_proxies convention: a bare IP
        // is a /32 or /128 CIDR.
        let mut c = baseline();
        c.bypass.ip_cidrs = vec!["203.0.113.42".to_string()];
        validate_bot_protection(&c).unwrap();
    }

    #[test]
    fn rejects_malformed_cidr() {
        let mut c = baseline();
        c.bypass.ip_cidrs = vec!["not-a-cidr".to_string()];
        match validate_bot_protection(&c) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("not a valid IP or CIDR"), "msg={msg}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rejects_bad_country_code() {
        let mut c = baseline();
        c.bypass.countries = vec!["USA".to_string()];
        assert!(matches!(
            validate_bot_protection(&c),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn normalises_country_code_to_upper() {
        let mut c = baseline();
        c.bypass.countries = vec!["us".to_string(), "Fr".to_string()];
        let out = validate_bot_protection(&c).unwrap();
        assert_eq!(out.bypass.countries, vec!["US", "FR"]);
    }

    #[test]
    fn rejects_uncompilable_regex() {
        let mut c = baseline();
        c.bypass.user_agents = vec!["[unterminated".to_string()];
        match validate_bot_protection(&c) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("not a valid regex"), "msg={msg}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn accepts_non_empty_rdns_list() {
        let mut c = baseline();
        c.bypass.rdns = vec!["GoogleBot.com".to_string(), "search.msn.com".to_string()];
        let out = validate_bot_protection(&c).expect("non-empty rdns must pass");
        assert_eq!(out.bypass.rdns, vec!["googlebot.com", "search.msn.com"]);
    }

    #[test]
    fn rejects_bare_tld_in_rdns() {
        let mut c = baseline();
        c.bypass.rdns = vec!["com".to_string()];
        match validate_bot_protection(&c) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("bare TLD"), "msg={msg}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rejects_leading_dot_in_rdns() {
        let mut c = baseline();
        c.bypass.rdns = vec![".googlebot.com".to_string()];
        match validate_bot_protection(&c) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("must not start with a dot"), "msg={msg}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rejects_bare_trailing_dot_tld_in_rdns() {
        // `com.` is a TLD with canonical trailing dot — still a
        // bare TLD that would match every .com host.
        let mut c = baseline();
        c.bypass.rdns = vec!["com.".to_string()];
        assert!(matches!(
            validate_bot_protection(&c),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn accepts_empty_rdns_list() {
        let mut c = baseline();
        c.bypass.rdns = vec![];
        validate_bot_protection(&c).expect("empty rdns must pass");
    }

    #[test]
    fn rejects_empty_only_country_list() {
        // Empty Some(vec![]) is a nonsensical shape. None = disabled,
        // non-empty = scope. The API enforces one of the two to avoid
        // silent UI states.
        let mut c = baseline();
        c.only_country = Some(vec![]);
        match validate_bot_protection(&c) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("empty list"), "msg={msg}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn normalises_only_country_codes() {
        let mut c = baseline();
        c.only_country = Some(vec!["fr".to_string(), "DE".to_string()]);
        let out = validate_bot_protection(&c).unwrap();
        assert_eq!(
            out.only_country,
            Some(vec!["FR".to_string(), "DE".to_string()])
        );
    }

    #[test]
    fn caps_bypass_categories_at_500_entries() {
        let mut c = baseline();
        c.bypass.ip_cidrs = (0..501).map(|i| format!("10.0.{i}.0/24")).collect();
        match validate_bot_protection(&c) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("at most 500"), "msg={msg}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn accepts_non_empty_asn_list() {
        // Now that the ASN resolver shipped, non-empty lists are
        // a legal config. The resolver runs lookups at request time;
        // an absent ASN DB makes the bypass a silent no-op.
        let mut c = baseline();
        c.bypass.asns = vec![15169, 8075];
        let out = validate_bot_protection(&c).expect("non-empty asns must pass");
        assert_eq!(out.bypass.asns, vec![15169, 8075]);
    }

    #[test]
    fn rejects_zero_asn() {
        // ASN 0 is IANA-reserved; allowing it in a bypass list would
        // be a misconfiguration that silently never matches (the DB
        // never returns 0 for a real IP).
        let mut c = baseline();
        c.bypass.asns = vec![0];
        match validate_bot_protection(&c) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("IANA reserves 0"), "msg={msg}");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn accepts_empty_asn_list() {
        let mut c = baseline();
        c.bypass.asns = vec![];
        validate_bot_protection(&c).expect("empty asns must pass");
    }
}

/// Full JSON view of a route returned by list / get / create / update
/// endpoints. Fields mirror `lorica_config::models::Route` one-for-one
/// unless noted otherwise ; see that type for the full semantics.
#[derive(Serialize)]
pub struct RouteResponse {
    /// Mirror of `Route.id`.
    pub id: String,
    /// Mirror of `Route.hostname`.
    pub hostname: String,
    /// Mirror of `Route.path_prefix`.
    pub path_prefix: String,
    /// IDs of the backends linked via `route_backends`.
    pub backends: Vec<String>,
    /// Mirror of `Route.certificate_id`.
    pub certificate_id: Option<String>,
    /// Load-balancing policy (rendered as the lowercase string form).
    pub load_balancing: String,
    /// Mirror of `Route.waf_enabled`.
    pub waf_enabled: bool,
    /// WAF mode (rendered as the lowercase string form).
    pub waf_mode: String,
    /// Mirror of `Route.enabled`.
    pub enabled: bool,
    /// Mirror of `Route.force_https`.
    pub force_https: bool,
    /// Mirror of `Route.redirect_hostname`.
    pub redirect_hostname: Option<String>,
    /// Mirror of `Route.redirect_to`.
    pub redirect_to: Option<String>,
    /// Mirror of `Route.hostname_aliases`.
    pub hostname_aliases: Vec<String>,
    /// Mirror of `Route.proxy_headers`.
    pub proxy_headers: HashMap<String, String>,
    /// Mirror of `Route.response_headers`.
    pub response_headers: HashMap<String, String>,
    /// Mirror of `Route.security_headers`.
    pub security_headers: String,
    /// Mirror of `Route.connect_timeout_s`.
    pub connect_timeout_s: i32,
    /// Mirror of `Route.read_timeout_s`.
    pub read_timeout_s: i32,
    /// Mirror of `Route.send_timeout_s`.
    pub send_timeout_s: i32,
    /// Mirror of `Route.strip_path_prefix`.
    pub strip_path_prefix: Option<String>,
    /// Mirror of `Route.add_path_prefix`.
    pub add_path_prefix: Option<String>,
    /// Mirror of `Route.path_rewrite_pattern`.
    pub path_rewrite_pattern: Option<String>,
    /// Mirror of `Route.path_rewrite_replacement`.
    pub path_rewrite_replacement: Option<String>,
    /// Mirror of `Route.access_log_enabled`.
    pub access_log_enabled: bool,
    /// Mirror of `Route.proxy_headers_remove`.
    pub proxy_headers_remove: Vec<String>,
    /// Mirror of `Route.response_headers_remove`.
    pub response_headers_remove: Vec<String>,
    /// Mirror of `Route.max_request_body_bytes`.
    pub max_request_body_bytes: Option<u64>,
    /// Mirror of `Route.websocket_enabled`.
    pub websocket_enabled: bool,
    /// Mirror of `Route.rate_limit_rps`.
    pub rate_limit_rps: Option<u32>,
    /// Mirror of `Route.rate_limit_burst`.
    pub rate_limit_burst: Option<u32>,
    /// Mirror of `Route.ip_allowlist`.
    pub ip_allowlist: Vec<String>,
    /// Mirror of `Route.ip_denylist`.
    pub ip_denylist: Vec<String>,
    /// Mirror of `Route.cors_allowed_origins`.
    pub cors_allowed_origins: Vec<String>,
    /// Mirror of `Route.cors_allowed_methods`.
    pub cors_allowed_methods: Vec<String>,
    /// Mirror of `Route.cors_max_age_s`.
    pub cors_max_age_s: Option<i32>,
    /// Mirror of `Route.compression_enabled`.
    pub compression_enabled: bool,
    /// Mirror of `Route.retry_attempts`.
    pub retry_attempts: Option<u32>,
    /// Mirror of `Route.cache_enabled`.
    pub cache_enabled: bool,
    /// Mirror of `Route.cache_ttl_s`.
    pub cache_ttl_s: i32,
    /// Mirror of `Route.cache_max_bytes`.
    pub cache_max_bytes: i64,
    /// Mirror of `Route.max_connections`.
    pub max_connections: Option<u32>,
    /// Mirror of `Route.slowloris_threshold_ms`.
    pub slowloris_threshold_ms: i32,
    /// Mirror of `Route.auto_ban_threshold`.
    pub auto_ban_threshold: Option<u32>,
    /// Mirror of `Route.auto_ban_duration_s`.
    pub auto_ban_duration_s: i32,
    /// Per-path overrides evaluated in declaration order.
    pub path_rules: Vec<PathRuleResponse>,
    /// Mirror of `Route.return_status`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_status: Option<u16>,
    /// Mirror of `Route.sticky_session`.
    pub sticky_session: bool,
    /// Basic-auth username (hash stays server-side, never in the
    /// response).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic_auth_username: Option<String>,
    /// Mirror of `Route.stale_while_revalidate_s`.
    pub stale_while_revalidate_s: i32,
    /// Mirror of `Route.stale_if_error_s`.
    pub stale_if_error_s: i32,
    /// Mirror of `Route.retry_on_methods`.
    pub retry_on_methods: Vec<String>,
    /// Mirror of `Route.maintenance_mode`.
    pub maintenance_mode: bool,
    /// Mirror of `Route.error_page_html`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_page_html: Option<String>,
    /// Mirror of `Route.cache_vary_headers`.
    pub cache_vary_headers: Vec<String>,
    /// Header-based routing rules.
    pub header_rules: Vec<HeaderRuleRequest>,
    /// Canary traffic splits.
    pub traffic_splits: Vec<TrafficSplitRequest>,
    /// Forward-auth config ; `None` = disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forward_auth: Option<ForwardAuthConfigRequest>,
    /// Request-mirror config ; `None` = disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mirror: Option<MirrorConfigRequest>,
    /// Response-body rewrite config ; `None` = disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_rewrite: Option<ResponseRewriteConfigRequest>,
    /// mTLS client-cert gate ; `None` = disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtls: Option<MtlsConfigRequest>,
    /// Token-bucket rate limit ; `None` = unlimited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<lorica_config::models::RateLimit>,
    /// Per-route GeoIP filter ; `None` = disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip: Option<lorica_config::models::GeoIpConfig>,
    /// Per-route bot-protection filter ; `None` = disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bot_protection: Option<lorica_config::models::BotProtectionConfig>,
    /// Free-form classification label (prod / staging / homelab / ...).
    /// Empty string = ungrouped. Mirrors `Backend.group_name`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub group_name: String,
    /// RFC 3339 insert timestamp.
    pub created_at: String,
    /// RFC 3339 last-write timestamp.
    pub updated_at: String,
}

/// JSON body for `POST /api/v1/routes`. Most fields are optional and
/// fall back to defaults ; semantics mirror
/// [`lorica_config::models::Route`] field-for-field.
#[derive(Deserialize)]
pub struct CreateRouteRequest {
    /// Hostname served by the new route. Required.
    pub hostname: String,
    /// URL path prefix ; defaults to `"/"`.
    pub path_prefix: Option<String>,
    /// IDs of backends to link via `route_backends`. Order matters
    /// for consistent-hash LB.
    pub backend_ids: Option<Vec<String>>,
    /// TLS certificate ID ; omit for plaintext-only routes.
    pub certificate_id: Option<String>,
    /// Load-balancing policy (snake_case name).
    pub load_balancing: Option<String>,
    /// Enable the WAF filter chain on this route.
    pub waf_enabled: Option<bool>,
    /// WAF mode : `"detection"` or `"blocking"`.
    pub waf_mode: Option<String>,
    /// Force redirect to HTTPS on plaintext listeners.
    pub force_https: Option<bool>,
    /// Canonical host for route-level redirects.
    pub redirect_hostname: Option<String>,
    /// Full URL to redirect every request to.
    pub redirect_to: Option<String>,
    /// Extra hostnames the route answers on.
    pub hostname_aliases: Option<Vec<String>>,
    /// Request headers injected on the way to the upstream.
    pub proxy_headers: Option<HashMap<String, String>>,
    /// Response headers appended on the way back.
    pub response_headers: Option<HashMap<String, String>>,
    /// Named security-header preset.
    pub security_headers: Option<String>,
    /// Upstream connect timeout (s).
    pub connect_timeout_s: Option<i32>,
    /// Upstream read timeout (s).
    pub read_timeout_s: Option<i32>,
    /// Upstream send timeout (s).
    pub send_timeout_s: Option<i32>,
    /// Strip this prefix before forwarding.
    pub strip_path_prefix: Option<String>,
    /// Prepend this prefix before forwarding.
    pub add_path_prefix: Option<String>,
    /// Regex pattern for path rewriting.
    pub path_rewrite_pattern: Option<String>,
    /// Replacement string for regex rewrite.
    pub path_rewrite_replacement: Option<String>,
    /// Emit an access-log line per request.
    pub access_log_enabled: Option<bool>,
    /// Request-header names removed before forwarding.
    pub proxy_headers_remove: Option<Vec<String>>,
    /// Response-header names removed before returning.
    pub response_headers_remove: Option<Vec<String>>,
    /// Hard cap on request body (bytes).
    pub max_request_body_bytes: Option<u64>,
    /// Allow `Upgrade: websocket` requests.
    pub websocket_enabled: Option<bool>,
    /// Per-client RPS rate limit.
    pub rate_limit_rps: Option<u32>,
    /// Token-bucket burst capacity.
    pub rate_limit_burst: Option<u32>,
    /// IP allow-list (CIDRs).
    pub ip_allowlist: Option<Vec<String>>,
    /// IP deny-list (CIDRs).
    pub ip_denylist: Option<Vec<String>>,
    /// CORS `Access-Control-Allow-Origin` values.
    pub cors_allowed_origins: Option<Vec<String>>,
    /// CORS `Access-Control-Allow-Methods` values.
    pub cors_allowed_methods: Option<Vec<String>>,
    /// CORS `Access-Control-Max-Age` (s).
    pub cors_max_age_s: Option<i32>,
    /// Enable gzip / deflate response compression.
    pub compression_enabled: Option<bool>,
    /// Idempotent-method retry count.
    pub retry_attempts: Option<u32>,
    /// Enable in-proxy response cache.
    pub cache_enabled: Option<bool>,
    /// Default cache TTL (s).
    pub cache_ttl_s: Option<i32>,
    /// Per-entry cache size cap (bytes).
    pub cache_max_bytes: Option<i64>,
    /// Hard cap on concurrent connections.
    pub max_connections: Option<u32>,
    /// Slowloris request-header timeout (ms).
    pub slowloris_threshold_ms: Option<i32>,
    /// Auto-ban request-count threshold.
    pub auto_ban_threshold: Option<u32>,
    /// Auto-ban duration (s).
    pub auto_ban_duration_s: Option<i32>,
    /// Per-path overrides evaluated in declaration order.
    pub path_rules: Option<Vec<PathRuleRequest>>,
    /// Route-level short-circuit status.
    pub return_status: Option<u16>,
    /// Enable cookie-based session affinity.
    pub sticky_session: Option<bool>,
    /// Basic-auth username.
    pub basic_auth_username: Option<String>,
    /// Plaintext password - hashed with Argon2id before storage. Never stored
    /// or logged in cleartext. The management API binds to localhost only;
    /// ensure TLS or SSH tunnel if accessing remotely.
    pub basic_auth_password: Option<String>,
    /// Cache-Control `stale-while-revalidate` (s).
    pub stale_while_revalidate_s: Option<i32>,
    /// Cache-Control `stale-if-error` (s).
    pub stale_if_error_s: Option<i32>,
    /// HTTP methods retryable by the retry logic.
    pub retry_on_methods: Option<Vec<String>>,
    /// Return 503 on every request (maintenance).
    pub maintenance_mode: Option<bool>,
    /// Operator-supplied HTML for terminal status codes.
    pub error_page_html: Option<String>,
    /// Request headers that partition the cache.
    pub cache_vary_headers: Option<Vec<String>>,
    /// Header-based routing rules.
    pub header_rules: Option<Vec<HeaderRuleRequest>>,
    /// Canary traffic splits.
    pub traffic_splits: Option<Vec<TrafficSplitRequest>>,
    /// Forward-auth config (optional).
    pub forward_auth: Option<ForwardAuthConfigRequest>,
    /// Request-mirror config (optional).
    pub mirror: Option<MirrorConfigRequest>,
    /// Response-body rewrite config (optional).
    pub response_rewrite: Option<ResponseRewriteConfigRequest>,
    /// mTLS client-cert gate (optional).
    pub mtls: Option<MtlsConfigRequest>,
    /// Token-bucket rate-limit struct (optional).
    pub rate_limit: Option<lorica_config::models::RateLimit>,
    /// Per-route GeoIP filter (optional).
    pub geoip: Option<lorica_config::models::GeoIpConfig>,
    /// Per-route bot-protection filter (optional).
    pub bot_protection: Option<lorica_config::models::BotProtectionConfig>,
    /// Free-form operator classification (prod / staging / homelab / ...).
    /// Omit or send empty string for ungrouped. Validated against a
    /// lowercase ASCII + digits + `-` + `_` alphabet, 1..=64 chars.
    pub group_name: Option<String>,
}

/// JSON body for `PUT /api/v1/routes/:id`. Only supplied fields are
/// mutated ; every field is optional. Semantics mirror the matching
/// [`lorica_config::models::Route`] field.
#[derive(Deserialize)]
pub struct UpdateRouteRequest {
    /// New hostname (must stay unique across the route table).
    pub hostname: Option<String>,
    /// New URL path prefix.
    pub path_prefix: Option<String>,
    /// New backend ID list ; full replace when present.
    pub backend_ids: Option<Vec<String>>,
    /// New TLS certificate ID.
    pub certificate_id: Option<String>,
    /// Load-balancing policy name.
    pub load_balancing: Option<String>,
    /// Enable / disable the WAF filter chain.
    pub waf_enabled: Option<bool>,
    /// WAF mode (`"detection"` / `"blocking"`).
    pub waf_mode: Option<String>,
    /// Admin toggle : disable to 404 all traffic.
    pub enabled: Option<bool>,
    /// Force HTTPS redirect on plaintext listeners.
    pub force_https: Option<bool>,
    /// Canonical redirect host.
    pub redirect_hostname: Option<String>,
    /// Route-level redirect target URL.
    pub redirect_to: Option<String>,
    /// Alias hostnames.
    pub hostname_aliases: Option<Vec<String>>,
    /// Request headers to inject.
    pub proxy_headers: Option<HashMap<String, String>>,
    /// Response headers to append.
    pub response_headers: Option<HashMap<String, String>>,
    /// Named security-header preset.
    pub security_headers: Option<String>,
    /// Upstream connect timeout (s).
    pub connect_timeout_s: Option<i32>,
    /// Upstream read timeout (s).
    pub read_timeout_s: Option<i32>,
    /// Upstream send timeout (s).
    pub send_timeout_s: Option<i32>,
    /// Strip this prefix before forwarding.
    pub strip_path_prefix: Option<String>,
    /// Prepend this prefix before forwarding.
    pub add_path_prefix: Option<String>,
    /// Regex pattern for path rewriting.
    pub path_rewrite_pattern: Option<String>,
    /// Replacement string for regex rewrite.
    pub path_rewrite_replacement: Option<String>,
    /// Emit access-log lines.
    pub access_log_enabled: Option<bool>,
    /// Request-header names to strip.
    pub proxy_headers_remove: Option<Vec<String>>,
    /// Response-header names to strip.
    pub response_headers_remove: Option<Vec<String>>,
    /// Hard cap on request body (bytes).
    pub max_request_body_bytes: Option<u64>,
    /// Allow WebSocket upgrades.
    pub websocket_enabled: Option<bool>,
    /// Per-client RPS rate limit.
    pub rate_limit_rps: Option<u32>,
    /// Token-bucket burst capacity.
    pub rate_limit_burst: Option<u32>,
    /// IP allow-list (CIDRs).
    pub ip_allowlist: Option<Vec<String>>,
    /// IP deny-list (CIDRs).
    pub ip_denylist: Option<Vec<String>>,
    /// CORS `Access-Control-Allow-Origin` values.
    pub cors_allowed_origins: Option<Vec<String>>,
    /// CORS `Access-Control-Allow-Methods` values.
    pub cors_allowed_methods: Option<Vec<String>>,
    /// CORS `Access-Control-Max-Age` (s).
    pub cors_max_age_s: Option<i32>,
    /// Enable gzip / deflate response compression.
    pub compression_enabled: Option<bool>,
    /// Idempotent-method retry count.
    pub retry_attempts: Option<u32>,
    /// Enable in-proxy response cache.
    pub cache_enabled: Option<bool>,
    /// Default cache TTL (s).
    pub cache_ttl_s: Option<i32>,
    /// Per-entry cache size cap (bytes).
    pub cache_max_bytes: Option<i64>,
    /// Hard cap on concurrent connections.
    pub max_connections: Option<u32>,
    /// Slowloris request-header timeout (ms).
    pub slowloris_threshold_ms: Option<i32>,
    /// Auto-ban request-count threshold.
    pub auto_ban_threshold: Option<u32>,
    /// Auto-ban duration (s).
    pub auto_ban_duration_s: Option<i32>,
    /// Per-path overrides (full replace).
    pub path_rules: Option<Vec<PathRuleRequest>>,
    /// Route-level short-circuit status.
    pub return_status: Option<u16>,
    /// Enable cookie-based session affinity.
    pub sticky_session: Option<bool>,
    /// Basic-auth username.
    pub basic_auth_username: Option<String>,
    /// Plaintext password - hashed with Argon2id before storage.
    pub basic_auth_password: Option<String>,
    /// Cache-Control `stale-while-revalidate` (s).
    pub stale_while_revalidate_s: Option<i32>,
    /// Cache-Control `stale-if-error` (s).
    pub stale_if_error_s: Option<i32>,
    /// HTTP methods retryable by the retry logic.
    pub retry_on_methods: Option<Vec<String>>,
    /// Return 503 on every request (maintenance).
    pub maintenance_mode: Option<bool>,
    /// Operator-supplied HTML for terminal status codes.
    pub error_page_html: Option<String>,
    /// Cache-variance request-header names.
    pub cache_vary_headers: Option<Vec<String>>,
    /// Header-based routing rules (full replace).
    pub header_rules: Option<Vec<HeaderRuleRequest>>,
    /// Canary traffic splits (full replace).
    pub traffic_splits: Option<Vec<TrafficSplitRequest>>,
    /// Update semantics: missing field = leave current value alone;
    /// present with empty `address` = clear; present with non-empty
    /// address = validate + install/replace.
    pub forward_auth: Option<ForwardAuthConfigRequest>,
    /// Update semantics: missing field = leave alone; present with
    /// empty `backend_ids` = clear; present with non-empty = validate
    /// + install/replace.
    pub mirror: Option<MirrorConfigRequest>,
    /// Update semantics: missing = leave alone; present with empty
    /// `rules` = clear; non-empty = validate + install/replace.
    pub response_rewrite: Option<ResponseRewriteConfigRequest>,
    /// Update semantics: missing = leave alone; present with empty
    /// `ca_cert_pem` = clear; non-empty = validate + install/replace.
    pub mtls: Option<MtlsConfigRequest>,
    /// Update semantics: missing = leave alone; present with
    /// `capacity = 0` = clear; present with `capacity > 0` =
    /// validate + install/replace.
    pub rate_limit: Option<lorica_config::models::RateLimit>,
    /// Update semantics: missing = leave alone; present with empty
    /// `countries` list = clear; present with non-empty = validate
    /// (ISO 3166-1 alpha-2 codes only) + install / replace. When
    /// `mode = Allowlist` an empty list is rejected at validation
    /// time so the operator cannot accidentally block everything.
    pub geoip: Option<lorica_config::models::GeoIpConfig>,
    /// Update semantics: missing = leave alone; present = validate +
    /// install/replace. See story 3.3 for the validation rules.
    /// To CLEAR an existing config (toggle bot-protection off on
    /// a route that already had it configured), set
    /// `bot_protection_disable: true`. Without this boolean the
    /// axum JSON layer cannot distinguish "absent field" from
    /// "field explicitly set to null", so a clear-by-null scheme
    /// would be brittle. The boolean + config-struct pair keeps
    /// the three cases orthogonal: neither sent = no-op, config
    /// sent = install, disable=true = clear.
    pub bot_protection: Option<lorica_config::models::BotProtectionConfig>,
    /// Explicit clear flag for `bot_protection`. Setting this to
    /// `true` removes the existing config ; `false` / absent is a
    /// no-op (use the `bot_protection` field itself to replace).
    #[serde(default)]
    pub bot_protection_disable: Option<bool>,
    /// Free-form operator classification (prod / staging / homelab / ...).
    /// Empty string clears the grouping. `None` leaves the field unchanged.
    pub group_name: Option<String>,
}

fn route_to_response(
    route: &lorica_config::models::Route,
    backend_ids: Vec<String>,
) -> RouteResponse {
    RouteResponse {
        id: route.id.clone(),
        hostname: route.hostname.clone(),
        path_prefix: route.path_prefix.clone(),
        backends: backend_ids,
        certificate_id: route.certificate_id.clone(),
        load_balancing: route.load_balancing.as_str().to_string(),
        waf_enabled: route.waf_enabled,
        waf_mode: route.waf_mode.as_str().to_string(),
        enabled: route.enabled,
        force_https: route.force_https,
        redirect_hostname: route.redirect_hostname.clone(),
        redirect_to: route.redirect_to.clone(),
        hostname_aliases: route.hostname_aliases.clone(),
        proxy_headers: route.proxy_headers.clone(),
        response_headers: route.response_headers.clone(),
        security_headers: route.security_headers.clone(),
        connect_timeout_s: route.connect_timeout_s,
        read_timeout_s: route.read_timeout_s,
        send_timeout_s: route.send_timeout_s,
        strip_path_prefix: route.strip_path_prefix.clone(),
        add_path_prefix: route.add_path_prefix.clone(),
        path_rewrite_pattern: route.path_rewrite_pattern.clone(),
        path_rewrite_replacement: route.path_rewrite_replacement.clone(),
        access_log_enabled: route.access_log_enabled,
        proxy_headers_remove: route.proxy_headers_remove.clone(),
        response_headers_remove: route.response_headers_remove.clone(),
        max_request_body_bytes: route.max_request_body_bytes,
        websocket_enabled: route.websocket_enabled,
        rate_limit_rps: route.rate_limit_rps,
        rate_limit_burst: route.rate_limit_burst,
        ip_allowlist: route.ip_allowlist.clone(),
        ip_denylist: route.ip_denylist.clone(),
        cors_allowed_origins: route.cors_allowed_origins.clone(),
        cors_allowed_methods: route.cors_allowed_methods.clone(),
        cors_max_age_s: route.cors_max_age_s,
        compression_enabled: route.compression_enabled,
        retry_attempts: route.retry_attempts,
        cache_enabled: route.cache_enabled,
        cache_ttl_s: route.cache_ttl_s,
        cache_max_bytes: route.cache_max_bytes,
        max_connections: route.max_connections,
        slowloris_threshold_ms: route.slowloris_threshold_ms,
        auto_ban_threshold: route.auto_ban_threshold,
        auto_ban_duration_s: route.auto_ban_duration_s,
        path_rules: route
            .path_rules
            .iter()
            .map(|pr| PathRuleResponse {
                path: pr.path.clone(),
                match_type: pr.match_type.as_str().to_string(),
                backend_ids: pr.backend_ids.clone(),
                cache_enabled: pr.cache_enabled,
                cache_ttl_s: pr.cache_ttl_s,
                response_headers: pr.response_headers.clone(),
                response_headers_remove: pr.response_headers_remove.clone(),
                rate_limit_rps: pr.rate_limit_rps,
                rate_limit_burst: pr.rate_limit_burst,
                redirect_to: pr.redirect_to.clone(),
                return_status: pr.return_status,
            })
            .collect(),
        return_status: route.return_status,
        sticky_session: route.sticky_session,
        basic_auth_username: route.basic_auth_username.clone(),
        stale_while_revalidate_s: route.stale_while_revalidate_s,
        stale_if_error_s: route.stale_if_error_s,
        retry_on_methods: route.retry_on_methods.clone(),
        maintenance_mode: route.maintenance_mode,
        error_page_html: route.error_page_html.clone(),
        cache_vary_headers: route.cache_vary_headers.clone(),
        header_rules: route
            .header_rules
            .iter()
            .map(|hr| {
                // Recompute disabled state at read time by attempting
                // to compile the regex. The write-path validator
                // already rejects bad regex, so in normal operation
                // this is always `false`. The flag exists for out-of-
                // band edits (raw DB writes, TOML import of a stale
                // export, regex-crate version drift on upgrade) so
                // the dashboard can show a red badge and the operator
                // can republish the rule.
                let disabled =
                    matches!(hr.match_type, lorica_config::models::HeaderMatchType::Regex)
                        && regex::Regex::new(&hr.value).is_err();
                HeaderRuleRequest {
                    header_name: hr.header_name.clone(),
                    match_type: Some(hr.match_type.as_str().to_string()),
                    value: hr.value.clone(),
                    backend_ids: hr.backend_ids.clone(),
                    disabled,
                }
            })
            .collect(),
        traffic_splits: route
            .traffic_splits
            .iter()
            .map(|ts| TrafficSplitRequest {
                name: ts.name.clone(),
                weight_percent: ts.weight_percent,
                backend_ids: ts.backend_ids.clone(),
            })
            .collect(),
        forward_auth: route
            .forward_auth
            .as_ref()
            .map(|fa| ForwardAuthConfigRequest {
                address: fa.address.clone(),
                timeout_ms: fa.timeout_ms,
                response_headers: fa.response_headers.clone(),
                verdict_cache_ttl_ms: fa.verdict_cache_ttl_ms,
            }),
        mirror: route.mirror.as_ref().map(|m| MirrorConfigRequest {
            backend_ids: m.backend_ids.clone(),
            sample_percent: m.sample_percent,
            timeout_ms: m.timeout_ms,
            max_body_bytes: m.max_body_bytes,
        }),
        response_rewrite: route
            .response_rewrite
            .as_ref()
            .map(|rr| ResponseRewriteConfigRequest {
                rules: rr
                    .rules
                    .iter()
                    .map(|r| ResponseRewriteRuleRequest {
                        pattern: r.pattern.clone(),
                        replacement: r.replacement.clone(),
                        is_regex: r.is_regex,
                        max_replacements: r.max_replacements,
                    })
                    .collect(),
                max_body_bytes: rr.max_body_bytes,
                content_type_prefixes: rr.content_type_prefixes.clone(),
            }),
        mtls: route.mtls.as_ref().map(|m| MtlsConfigRequest {
            ca_cert_pem: m.ca_cert_pem.clone(),
            required: m.required,
            allowed_organizations: m.allowed_organizations.clone(),
        }),
        rate_limit: route.rate_limit.clone(),
        geoip: route.geoip.clone(),
        bot_protection: route.bot_protection.clone(),
        group_name: route.group_name.clone(),
        created_at: route.created_at.to_rfc3339(),
        updated_at: route.updated_at.to_rfc3339(),
    }
}

/// Query string for `GET /api/v1/routes`. Optional `group` filter lets
/// the dashboard narrow the list to a single operator classification
/// (prod / staging / etc.) without fetching everything first.
#[derive(Deserialize, Default)]
pub struct ListRoutesQuery {
    /// Filter : when set, only routes whose `group_name` equals this
    /// value are returned.
    pub group: Option<String>,
}

/// GET /api/v1/routes - list every configured route with its linked backend ids.
pub async fn list_routes(
    Extension(state): Extension<AppState>,
    axum::extract::Query(query): axum::extract::Query<ListRoutesQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let routes = store.list_routes()?;
    // Optional `?group=...` filter: trimmed, exact match on
    // `Route.group_name`. Invalid shapes (non-alphabet chars) return
    // 400 early rather than silently matching nothing.
    let group_filter = match query.group.as_deref() {
        Some(raw) => {
            let v = validate_group_name(raw)?;
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        }
        None => None,
    };
    let mut responses = Vec::with_capacity(routes.len());
    for route in &routes {
        if let Some(ref g) = group_filter {
            if &route.group_name != g {
                continue;
            }
        }
        let backend_ids = store.list_backends_for_route(&route.id)?;
        responses.push(route_to_response(route, backend_ids));
    }
    Ok(json_data(serde_json::json!({ "routes": responses })))
}

/// POST /api/v1/routes - create a new route.
///
/// Validates type-shape (enum parsing, regex compilability); business
/// rules (hostname uniqueness) are enforced by the store layer.
pub async fn create_route(
    Extension(state): Extension<AppState>,
    Json(body): Json<CreateRouteRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    if body.hostname.is_empty() {
        return Err(ApiError::BadRequest("hostname is required".into()));
    }

    let redirect_hostname = match body.redirect_hostname.as_deref() {
        Some(h) => {
            let v = validate_redirect_hostname(h)?;
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        }
        None => None,
    };

    let redirect_to = match body.redirect_to.as_deref() {
        Some(r) => {
            let v = validate_redirect_to(r, "redirect_to")?;
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        }
        None => None,
    };

    let path_prefix = {
        let raw = body.path_prefix.clone().unwrap_or_else(|| "/".to_string());
        let v = validate_route_path(&raw, "path_prefix")?;
        if v.is_empty() {
            "/".to_string()
        } else {
            v
        }
    };

    let strip_path_prefix = match body.strip_path_prefix.as_deref() {
        Some(p) => {
            let v = validate_route_path(p, "strip_path_prefix")?;
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        }
        None => None,
    };

    let add_path_prefix = match body.add_path_prefix.as_deref() {
        Some(p) => {
            let v = validate_route_path(p, "add_path_prefix")?;
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        }
        None => None,
    };

    let path_rewrite_pattern = match body.path_rewrite_pattern.as_deref() {
        Some(p) => {
            let v = validate_path_rewrite_pattern(p)?;
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        }
        None => None,
    };

    let path_rewrite_replacement = match body.path_rewrite_replacement.as_deref() {
        Some(r) => Some(validate_path_rewrite_replacement(
            r,
            path_rewrite_pattern.as_deref(),
        )?),
        None => None,
    };

    let lb = body
        .load_balancing
        .as_deref()
        .unwrap_or("round_robin")
        .parse::<lorica_config::models::LoadBalancing>()
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    let waf_mode = body
        .waf_mode
        .as_deref()
        .unwrap_or("detection")
        .parse::<lorica_config::models::WafMode>()
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    if let Some(ref h) = body.proxy_headers {
        validate_http_headers_map(h, "proxy_headers")?;
    }
    if let Some(ref h) = body.response_headers {
        validate_http_headers_map(h, "response_headers")?;
    }
    if let Some(ref h) = body.proxy_headers_remove {
        validate_http_header_name_list(h, "proxy_headers_remove")?;
    }
    if let Some(ref h) = body.response_headers_remove {
        validate_http_header_name_list(h, "response_headers_remove")?;
    }
    if let Some(ref h) = body.cache_vary_headers {
        validate_http_header_name_list(h, "cache_vary_headers")?;
    }
    if let Some(ref origins) = body.cors_allowed_origins {
        for o in origins {
            validate_cors_origin(o.trim(), "cors_allowed_origins")?;
        }
    }
    if let Some(ref methods) = body.cors_allowed_methods {
        for m in methods {
            validate_http_method(m.trim(), "cors_allowed_methods")?;
        }
    }
    validate_route_numeric_bounds(
        body.connect_timeout_s,
        body.read_timeout_s,
        body.send_timeout_s,
        Some(body.cache_ttl_s.unwrap_or(300)),
        Some(body.cache_max_bytes.unwrap_or(52_428_800)),
        body.max_connections,
        Some(body.slowloris_threshold_ms.unwrap_or(5000)),
        body.auto_ban_threshold,
        Some(body.auto_ban_duration_s.unwrap_or(3600)),
        body.return_status,
        body.retry_attempts,
        Some(body.stale_while_revalidate_s.unwrap_or(10)),
        Some(body.stale_if_error_s.unwrap_or(60)),
        body.cors_max_age_s,
        body.max_request_body_bytes,
    )?;
    validate_rate_limit_bounds(body.rate_limit_rps, body.rate_limit_burst)?;

    let path_rules = if let Some(ref prs) = body.path_rules {
        build_path_rules(prs)?
    } else {
        Vec::new()
    };

    let now = Utc::now();
    let route = lorica_config::models::Route {
        id: uuid::Uuid::new_v4().to_string(),
        hostname: body.hostname,
        path_prefix,
        certificate_id: body.certificate_id,
        load_balancing: lb,
        waf_enabled: body.waf_enabled.unwrap_or(false),
        waf_mode,
        enabled: true,
        force_https: body.force_https.unwrap_or(false),
        redirect_hostname,
        redirect_to,
        hostname_aliases: {
            let raw = body.hostname_aliases.clone().unwrap_or_default();
            let mut out = Vec::with_capacity(raw.len());
            for (i, a) in raw.iter().enumerate() {
                out.push(validate_hostname_alias(
                    a,
                    &format!("hostname_aliases[{i}]"),
                )?);
            }
            out
        },
        proxy_headers: body.proxy_headers.unwrap_or_default(),
        response_headers: body.response_headers.unwrap_or_default(),
        security_headers: body
            .security_headers
            .unwrap_or_else(|| "moderate".to_string()),
        connect_timeout_s: body.connect_timeout_s.unwrap_or(5),
        read_timeout_s: body.read_timeout_s.unwrap_or(60),
        send_timeout_s: body.send_timeout_s.unwrap_or(60),
        strip_path_prefix,
        add_path_prefix,
        path_rewrite_pattern,
        path_rewrite_replacement,
        access_log_enabled: body.access_log_enabled.unwrap_or(true),
        proxy_headers_remove: body.proxy_headers_remove.unwrap_or_default(),
        response_headers_remove: body.response_headers_remove.unwrap_or_default(),
        // Six fields below honour the "0 = clear" convention that
        // `update_route` already implements : `Some(0)` in the DB
        // either has no meaningful semantic (e.g. `rate_limit_rps=0`
        // = reject every request, which nobody configures that way)
        // or is equivalent to `None` (e.g. `max_request_body_bytes=0`
        // is documented as "unlimited"). Normalise here too so a
        // direct `curl POST` does not land a stray `Some(0)` in the
        // DB ; CREATE and UPDATE stay symmetric.
        // `retry_attempts` and `cors_max_age_s` deliberately keep
        // `Some(0)` because 0 is a valid configuration there
        // (no retries / preflight-uncached).
        max_request_body_bytes: body.max_request_body_bytes.filter(|&v| v != 0),
        websocket_enabled: body.websocket_enabled.unwrap_or(true),
        rate_limit_rps: body.rate_limit_rps.filter(|&v| v != 0),
        rate_limit_burst: body.rate_limit_burst.filter(|&v| v != 0),
        ip_allowlist: body.ip_allowlist.unwrap_or_default(),
        ip_denylist: body.ip_denylist.unwrap_or_default(),
        cors_allowed_origins: body.cors_allowed_origins.unwrap_or_default(),
        cors_allowed_methods: body.cors_allowed_methods.unwrap_or_default(),
        cors_max_age_s: body.cors_max_age_s,
        compression_enabled: body.compression_enabled.unwrap_or(false),
        retry_attempts: body.retry_attempts,
        cache_enabled: body.cache_enabled.unwrap_or(false),
        cache_ttl_s: body.cache_ttl_s.unwrap_or(300),
        cache_max_bytes: body.cache_max_bytes.unwrap_or(52428800),
        max_connections: body.max_connections.filter(|&v| v != 0),
        slowloris_threshold_ms: body.slowloris_threshold_ms.unwrap_or(5000),
        auto_ban_threshold: body.auto_ban_threshold.filter(|&v| v != 0),
        auto_ban_duration_s: body.auto_ban_duration_s.unwrap_or(3600),
        path_rules,
        return_status: body.return_status.filter(|&v| v != 0),
        sticky_session: body.sticky_session.unwrap_or(false),
        basic_auth_username: body.basic_auth_username.clone(),
        basic_auth_password_hash: if let Some(ref pw) = body.basic_auth_password {
            Some(crate::auth::hash_password(pw)?)
        } else {
            None
        },
        stale_while_revalidate_s: body.stale_while_revalidate_s.unwrap_or(10),
        stale_if_error_s: body.stale_if_error_s.unwrap_or(60),
        retry_on_methods: {
            let raw = body.retry_on_methods.clone().unwrap_or_default();
            for m in &raw {
                validate_http_method(m.trim(), "retry_on_methods")?;
            }
            raw
        },
        maintenance_mode: body.maintenance_mode.unwrap_or(false),
        error_page_html: {
            if let Some(ref h) = body.error_page_html {
                validate_error_page_html(h)?;
            }
            body.error_page_html.clone()
        },
        cache_vary_headers: body.cache_vary_headers.clone().unwrap_or_default(),
        header_rules: body
            .header_rules
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(build_header_rule)
            .collect::<Result<Vec<_>, _>>()?,
        traffic_splits: {
            let splits = body
                .traffic_splits
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(build_traffic_split)
                .collect::<Result<Vec<_>, _>>()?;
            validate_traffic_splits(&splits)?;
            splits
        },
        forward_auth: match body.forward_auth.as_ref() {
            Some(fa) if !fa.address.trim().is_empty() => Some(build_forward_auth(fa)?),
            _ => None,
        },
        mirror: match body.mirror.as_ref() {
            Some(m) if !m.backend_ids.is_empty() => Some(build_mirror_config(m)?),
            _ => None,
        },
        response_rewrite: match body.response_rewrite.as_ref() {
            Some(rr) if !rr.rules.is_empty() => Some(build_response_rewrite(rr)?),
            _ => None,
        },
        mtls: match body.mtls.as_ref() {
            Some(m) if !m.ca_cert_pem.trim().is_empty() => Some(build_mtls_config(m)?),
            _ => None,
        },
        rate_limit: match body.rate_limit.as_ref() {
            Some(rl) => Some(validate_rate_limit(rl)?),
            None => None,
        },
        geoip: match body.geoip.as_ref() {
            // Empty country list in denylist mode is legal (means "no
            // countries blocked"), but allowlist with empty list is
            // rejected by `validate_geoip`.
            Some(g) => Some(validate_geoip(g)?),
            None => None,
        },
        bot_protection: match body.bot_protection.as_ref() {
            Some(b) => Some(validate_bot_protection(b)?),
            None => None,
        },
        group_name: match body.group_name.as_deref() {
            Some(g) => validate_group_name(g)?,
            None => String::new(),
        },
        created_at: now,
        updated_at: now,
    };

    let store = state.store.lock().await;
    store.create_route(&route)?;

    let backend_ids = body.backend_ids.unwrap_or_default();
    for bid in &backend_ids {
        store.link_route_backend(&route.id, bid)?;
    }

    let response = route_to_response(&route, backend_ids);
    state.notify_config_changed();
    Ok(json_data_with_status(StatusCode::CREATED, response))
}

/// GET /api/v1/routes/:id - fetch a single route by id.
pub async fn get_route(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let route = store
        .get_route(&id)?
        .ok_or_else(|| ApiError::NotFound(format!("route {id}")))?;
    let backend_ids = store.list_backends_for_route(&route.id)?;
    Ok(json_data(route_to_response(&route, backend_ids)))
}

/// PUT /api/v1/routes/:id - patch route fields and trigger a proxy reload.
pub async fn update_route(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Json(body): Json<UpdateRouteRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let mut route = store
        .get_route(&id)?
        .ok_or_else(|| ApiError::NotFound(format!("route {id}")))?;

    validate_route_numeric_bounds(
        body.connect_timeout_s,
        body.read_timeout_s,
        body.send_timeout_s,
        body.cache_ttl_s,
        body.cache_max_bytes,
        body.max_connections,
        body.slowloris_threshold_ms,
        body.auto_ban_threshold,
        body.auto_ban_duration_s,
        body.return_status,
        body.retry_attempts,
        body.stale_while_revalidate_s,
        body.stale_if_error_s,
        body.cors_max_age_s,
        body.max_request_body_bytes,
    )?;
    validate_rate_limit_bounds(body.rate_limit_rps, body.rate_limit_burst)?;

    if let Some(hostname) = body.hostname {
        route.hostname = hostname;
    }
    if let Some(path_prefix) = body.path_prefix {
        let v = validate_route_path(&path_prefix, "path_prefix")?;
        route.path_prefix = if v.is_empty() { "/".to_string() } else { v };
    }
    if let Some(certificate_id) = body.certificate_id {
        if certificate_id.is_empty() {
            route.certificate_id = None;
            route.force_https = false;
        } else {
            route.certificate_id = Some(certificate_id);
        }
    }
    if let Some(lb) = body.load_balancing {
        route.load_balancing = lb
            .parse::<lorica_config::models::LoadBalancing>()
            .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    }
    if let Some(waf_enabled) = body.waf_enabled {
        route.waf_enabled = waf_enabled;
    }
    if let Some(waf_mode) = body.waf_mode {
        route.waf_mode = waf_mode
            .parse::<lorica_config::models::WafMode>()
            .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    }
    if let Some(enabled) = body.enabled {
        route.enabled = enabled;
    }
    if let Some(force_https) = body.force_https {
        route.force_https = force_https;
    }
    if let Some(redirect_hostname) = body.redirect_hostname {
        let v = validate_redirect_hostname(&redirect_hostname)?;
        route.redirect_hostname = if v.is_empty() { None } else { Some(v) };
    }
    if let Some(redirect_to) = body.redirect_to {
        let v = validate_redirect_to(&redirect_to, "redirect_to")?;
        route.redirect_to = if v.is_empty() { None } else { Some(v) };
    }
    if let Some(hostname_aliases) = body.hostname_aliases {
        let mut out = Vec::with_capacity(hostname_aliases.len());
        for (i, a) in hostname_aliases.iter().enumerate() {
            out.push(validate_hostname_alias(
                a,
                &format!("hostname_aliases[{i}]"),
            )?);
        }
        route.hostname_aliases = out;
    }
    if let Some(proxy_headers) = body.proxy_headers {
        validate_http_headers_map(&proxy_headers, "proxy_headers")?;
        route.proxy_headers = proxy_headers;
    }
    if let Some(response_headers) = body.response_headers {
        validate_http_headers_map(&response_headers, "response_headers")?;
        route.response_headers = response_headers;
    }
    if let Some(security_headers) = body.security_headers {
        route.security_headers = security_headers;
    }
    if let Some(connect_timeout_s) = body.connect_timeout_s {
        route.connect_timeout_s = connect_timeout_s;
    }
    if let Some(read_timeout_s) = body.read_timeout_s {
        route.read_timeout_s = read_timeout_s;
    }
    if let Some(send_timeout_s) = body.send_timeout_s {
        route.send_timeout_s = send_timeout_s;
    }
    if let Some(strip_path_prefix) = body.strip_path_prefix {
        let v = validate_route_path(&strip_path_prefix, "strip_path_prefix")?;
        route.strip_path_prefix = if v.is_empty() { None } else { Some(v) };
    }
    if let Some(add_path_prefix) = body.add_path_prefix {
        let v = validate_route_path(&add_path_prefix, "add_path_prefix")?;
        route.add_path_prefix = if v.is_empty() { None } else { Some(v) };
    }
    if let Some(ref pattern) = body.path_rewrite_pattern {
        let v = validate_path_rewrite_pattern(pattern)?;
        if v.is_empty() {
            route.path_rewrite_pattern = None;
            route.path_rewrite_replacement = None;
        } else {
            route.path_rewrite_pattern = Some(v);
        }
    }
    if let Some(replacement) = body.path_rewrite_replacement {
        let v =
            validate_path_rewrite_replacement(&replacement, route.path_rewrite_pattern.as_deref())?;
        route.path_rewrite_replacement = if v.is_empty() && route.path_rewrite_pattern.is_none() {
            None
        } else {
            Some(v)
        };
    }
    if let Some(access_log_enabled) = body.access_log_enabled {
        route.access_log_enabled = access_log_enabled;
    }
    if let Some(proxy_headers_remove) = body.proxy_headers_remove {
        validate_http_header_name_list(&proxy_headers_remove, "proxy_headers_remove")?;
        route.proxy_headers_remove = proxy_headers_remove;
    }
    if let Some(response_headers_remove) = body.response_headers_remove {
        validate_http_header_name_list(&response_headers_remove, "response_headers_remove")?;
        route.response_headers_remove = response_headers_remove;
    }
    if let Some(max_request_body_bytes) = body.max_request_body_bytes {
        route.max_request_body_bytes = if max_request_body_bytes == 0 {
            None
        } else {
            Some(max_request_body_bytes)
        };
    }
    if let Some(websocket_enabled) = body.websocket_enabled {
        route.websocket_enabled = websocket_enabled;
    }
    if let Some(rate_limit_rps) = body.rate_limit_rps {
        route.rate_limit_rps = if rate_limit_rps == 0 {
            None
        } else {
            Some(rate_limit_rps)
        };
    }
    if let Some(rate_limit_burst) = body.rate_limit_burst {
        route.rate_limit_burst = if rate_limit_burst == 0 {
            None
        } else {
            Some(rate_limit_burst)
        };
    }
    if let Some(ip_allowlist) = body.ip_allowlist {
        route.ip_allowlist = ip_allowlist;
    }
    if let Some(ip_denylist) = body.ip_denylist {
        route.ip_denylist = ip_denylist;
    }
    if let Some(cors_allowed_origins) = body.cors_allowed_origins {
        for o in &cors_allowed_origins {
            validate_cors_origin(o.trim(), "cors_allowed_origins")?;
        }
        route.cors_allowed_origins = cors_allowed_origins;
    }
    if let Some(cors_allowed_methods) = body.cors_allowed_methods {
        for m in &cors_allowed_methods {
            validate_http_method(m.trim(), "cors_allowed_methods")?;
        }
        route.cors_allowed_methods = cors_allowed_methods;
    }
    if let Some(cors_max_age_s) = body.cors_max_age_s {
        route.cors_max_age_s = if cors_max_age_s == 0 {
            None
        } else {
            Some(cors_max_age_s)
        };
    }
    if let Some(compression_enabled) = body.compression_enabled {
        route.compression_enabled = compression_enabled;
    }
    if let Some(retry_attempts) = body.retry_attempts {
        route.retry_attempts = if retry_attempts == 0 {
            None
        } else {
            Some(retry_attempts)
        };
    }
    if let Some(cache_enabled) = body.cache_enabled {
        route.cache_enabled = cache_enabled;
    }
    if let Some(cache_ttl_s) = body.cache_ttl_s {
        route.cache_ttl_s = cache_ttl_s;
    }
    if let Some(cache_max_bytes) = body.cache_max_bytes {
        route.cache_max_bytes = cache_max_bytes;
    }
    if let Some(max_connections) = body.max_connections {
        route.max_connections = if max_connections == 0 {
            None
        } else {
            Some(max_connections)
        };
    }
    if let Some(slowloris_threshold_ms) = body.slowloris_threshold_ms {
        route.slowloris_threshold_ms = slowloris_threshold_ms;
    }
    if let Some(auto_ban_threshold) = body.auto_ban_threshold {
        route.auto_ban_threshold = if auto_ban_threshold == 0 {
            None
        } else {
            Some(auto_ban_threshold)
        };
    }
    if let Some(auto_ban_duration_s) = body.auto_ban_duration_s {
        route.auto_ban_duration_s = auto_ban_duration_s;
    }
    if let Some(ref prs) = body.path_rules {
        route.path_rules = build_path_rules(prs)?;
    }
    if let Some(return_status) = body.return_status {
        route.return_status = if return_status == 0 {
            None
        } else {
            Some(return_status)
        };
    }
    if let Some(sticky) = body.sticky_session {
        route.sticky_session = sticky;
    }
    if let Some(ref username) = body.basic_auth_username {
        route.basic_auth_username = if username.is_empty() {
            None
        } else {
            Some(username.clone())
        };
    }
    if let Some(ref password) = body.basic_auth_password {
        route.basic_auth_password_hash = if password.is_empty() {
            None
        } else {
            Some(crate::auth::hash_password(password)?)
        };
    }
    if let Some(swr) = body.stale_while_revalidate_s {
        route.stale_while_revalidate_s = swr;
    }
    if let Some(sie) = body.stale_if_error_s {
        route.stale_if_error_s = sie;
    }
    if let Some(ref methods) = body.retry_on_methods {
        for m in methods {
            validate_http_method(m.trim(), "retry_on_methods")?;
        }
        route.retry_on_methods = methods.clone();
    }
    if let Some(maintenance) = body.maintenance_mode {
        route.maintenance_mode = maintenance;
    }
    if let Some(ref html) = body.error_page_html {
        validate_error_page_html(html)?;
        route.error_page_html = if html.is_empty() {
            None
        } else {
            Some(html.clone())
        };
    }
    if let Some(ref headers) = body.cache_vary_headers {
        // Normalise on write: trim whitespace, drop empties. Downstream
        // variance logic lowercases on the hot path so no need to do it
        // here - keeps the dashboard showing exactly what the operator typed.
        let normalised: Vec<String> = headers
            .iter()
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty())
            .collect();
        validate_http_header_name_list(&normalised, "cache_vary_headers")?;
        route.cache_vary_headers = normalised;
    }
    if let Some(ref rules) = body.header_rules {
        route.header_rules = rules
            .iter()
            .map(build_header_rule)
            .collect::<Result<Vec<_>, _>>()?;
    }
    if let Some(ref splits) = body.traffic_splits {
        let built = splits
            .iter()
            .map(build_traffic_split)
            .collect::<Result<Vec<_>, _>>()?;
        validate_traffic_splits(&built)?;
        route.traffic_splits = built;
    }
    if let Some(ref fa) = body.forward_auth {
        // Empty address = explicit "disable" signal from the dashboard.
        // Non-empty address = validate + install/replace.
        if fa.address.trim().is_empty() {
            route.forward_auth = None;
        } else {
            route.forward_auth = Some(build_forward_auth(fa)?);
        }
    }
    if let Some(ref m) = body.mirror {
        if m.backend_ids.is_empty() {
            route.mirror = None;
        } else {
            route.mirror = Some(build_mirror_config(m)?);
        }
    }
    if let Some(ref rr) = body.response_rewrite {
        if rr.rules.is_empty() {
            route.response_rewrite = None;
        } else {
            route.response_rewrite = Some(build_response_rewrite(rr)?);
        }
    }
    if let Some(ref m) = body.mtls {
        // Empty ca_cert_pem = explicit "disable" signal from dashboard.
        // Non-empty = validate + install/replace. Changes to the PEM
        // take effect on next restart (rustls ServerConfig is immutable
        // after build); required/allowed_organizations hot-reload.
        if m.ca_cert_pem.trim().is_empty() {
            route.mtls = None;
        } else {
            route.mtls = Some(build_mtls_config(m)?);
        }
    }
    if let Some(ref rl) = body.rate_limit {
        // capacity == 0 = explicit "disable" signal; any positive value
        // goes through validate_rate_limit and replaces the existing
        // config.
        if rl.capacity == 0 {
            route.rate_limit = None;
        } else {
            route.rate_limit = Some(validate_rate_limit(rl)?);
        }
    }
    if let Some(ref g) = body.geoip {
        // Empty country list in allowlist mode is rejected by
        // `validate_geoip`; empty list in denylist mode is legal and
        // means "filter disabled for this route". Empty list in
        // denylist mode also clears the `geoip` column on disk.
        use lorica_config::models::GeoIpMode;
        if g.mode == GeoIpMode::Denylist && g.countries.is_empty() {
            route.geoip = None;
        } else {
            route.geoip = Some(validate_geoip(g)?);
        }
    }
    if body.bot_protection_disable == Some(true) {
        // Explicit clear signal from the dashboard when the
        // operator toggles bot-protection OFF on a route that
        // previously had a config. Mutually exclusive with
        // sending a new `bot_protection` body (would be a
        // contradiction — `disable` wins so the API contract
        // stays predictable).
        route.bot_protection = None;
    } else if let Some(ref b) = body.bot_protection {
        route.bot_protection = Some(validate_bot_protection(b)?);
    }
    if let Some(ref raw) = body.group_name {
        route.group_name = validate_group_name(raw)?;
    }
    route.updated_at = Utc::now();

    store.update_route(&route)?;

    // Update backend associations if provided
    if let Some(backend_ids) = &body.backend_ids {
        let current = store.list_backends_for_route(&id)?;
        for bid in &current {
            store.unlink_route_backend(&id, bid)?;
        }
        for bid in backend_ids {
            store.link_route_backend(&id, bid)?;
        }
    }

    let backend_ids = store.list_backends_for_route(&id)?;
    state.notify_config_changed();
    Ok(json_data(route_to_response(&route, backend_ids)))
}

/// DELETE /api/v1/routes/:id - delete a route and notify the proxy.
pub async fn delete_route(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    store.delete_route(&id)?;
    drop(store);
    state.notify_config_changed();
    Ok(json_data(serde_json::json!({"message": "route deleted"})))
}
