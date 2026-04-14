//! Forward-auth subrequest configuration types, validator, and
//! the `POST /api/v1/validate/forward-auth` dashboard endpoint.

use axum::extract::Extension;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::{json_data, ApiError};
use crate::server::AppState;

/// Forward-auth subrequest configuration (address, timeout, propagated headers, verdict cache TTL).
#[derive(Serialize, Deserialize, Clone)]
pub struct ForwardAuthConfigRequest {
    pub address: String,
    #[serde(default = "default_forward_auth_timeout_ms")]
    pub timeout_ms: u32,
    #[serde(default)]
    pub response_headers: Vec<String>,
    #[serde(default)]
    pub verdict_cache_ttl_ms: u32,
}

pub(super) fn default_forward_auth_timeout_ms() -> u32 {
    5_000
}

/// Validate and convert a `ForwardAuthConfigRequest` to the stored
/// model. Rejects obvious operator mistakes at write time rather than at
/// the first request: empty address, non-absolute URL, zero or absurd
/// timeout, malformed response-header names.
pub(super) fn build_forward_auth(
    body: &ForwardAuthConfigRequest,
) -> Result<lorica_config::models::ForwardAuthConfig, ApiError> {
    let address = body.address.trim();
    if address.is_empty() {
        return Err(ApiError::BadRequest(
            "forward_auth.address must not be empty (use null/missing to disable)".into(),
        ));
    }
    let parsed: http::Uri = address.parse().map_err(|e| {
        ApiError::BadRequest(format!("forward_auth.address must be an absolute URL: {e}"))
    })?;
    match parsed.scheme_str() {
        Some("https") => {}
        Some("http") => {
            // Accepted for loopback / sidecar deployments (auth
            // service on the same host, localhost) where the cost of
            // TLS termination is not justified. Warn because the
            // full downstream Cookie + Authorization is forwarded to
            // the auth service verbatim; on anything other than
            // loopback that leaks credentials in cleartext.
            let host = parsed
                .authority()
                .map(|a| a.host().to_string())
                .unwrap_or_default();
            let is_loopback = host == "localhost"
                || host == "127.0.0.1"
                || host == "[::1]"
                || host.starts_with("127.")
                || host.ends_with(".localhost");
            if !is_loopback {
                tracing::warn!(
                    address = %address,
                    host = %host,
                    "forward_auth.address uses http:// to a non-loopback host; downstream Cookie and Authorization headers will be forwarded in cleartext. Use https:// in production."
                );
            }
        }
        Some(s) => {
            return Err(ApiError::BadRequest(format!(
                "forward_auth.address must use http or https scheme, got {s}"
            )));
        }
        None => {
            return Err(ApiError::BadRequest(
                "forward_auth.address must be an absolute URL (scheme://host/path)".into(),
            ));
        }
    }
    if parsed.authority().is_none() {
        return Err(ApiError::BadRequest(
            "forward_auth.address must include a host (scheme://host/path)".into(),
        ));
    }
    if body.timeout_ms == 0 {
        return Err(ApiError::BadRequest(
            "forward_auth.timeout_ms must be > 0".into(),
        ));
    }
    if body.timeout_ms > 60_000 {
        return Err(ApiError::BadRequest(
            "forward_auth.timeout_ms must be <= 60000 (60 seconds); longer timeouts stall the request pipeline".into(),
        ));
    }
    for name in &body.response_headers {
        if name.trim().is_empty() {
            return Err(ApiError::BadRequest(
                "forward_auth.response_headers entries must be non-empty".into(),
            ));
        }
    }
    // Verdict cache TTL cap. 60s is a hard ceiling because cached
    // "Allow" verdicts survive session revocation for up to TTL;
    // anything beyond 60s would turn the feature into an unbounded
    // authentication bypass on session logout. 0 disables the cache
    // entirely (strict zero-trust default).
    const VERDICT_CACHE_TTL_CEILING_MS: u32 = 60_000;
    if body.verdict_cache_ttl_ms > VERDICT_CACHE_TTL_CEILING_MS {
        return Err(ApiError::BadRequest(format!(
            "forward_auth.verdict_cache_ttl_ms must be <= {VERDICT_CACHE_TTL_CEILING_MS} (60s); longer TTLs delay session-revocation too much. Use 0 to disable caching."
        )));
    }
    Ok(lorica_config::models::ForwardAuthConfig {
        address: address.to_string(),
        timeout_ms: body.timeout_ms,
        response_headers: body
            .response_headers
            .iter()
            .map(|h| h.trim().to_string())
            .collect(),
        verdict_cache_ttl_ms: body.verdict_cache_ttl_ms,
    })
}

/// JSON body for `POST /api/v1/validate/forward-auth`.
#[derive(Deserialize)]
pub struct ValidateForwardAuthRequest {
    pub address: String,
    #[serde(default = "default_forward_auth_timeout_ms")]
    pub timeout_ms: u32,
}

/// Response describing a validated forward-auth probe (status, latency, whitelisted headers).
#[derive(Serialize)]
pub struct ValidateForwardAuthResponse {
    /// Status returned by the auth service.
    pub status: u16,
    /// Round-trip time in milliseconds (connect + response).
    pub elapsed_ms: u64,
    /// Small whitelist of response headers likely useful for
    /// diagnostics (Location, Remote-User, Content-Type). We do not
    /// echo arbitrary headers to avoid leaking internal service info
    /// if an operator accidentally pointed this at a sensitive URL.
    pub headers: std::collections::HashMap<String, String>,
}

/// POST /api/v1/validate/forward-auth - shape-validate the address
/// and make ONE GET to confirm the auth service is reachable. No
/// body is sent; the caller is expected to be a dashboard admin
/// confirming their config, not automating anything.
///
/// Note: this allows an admin to trigger a single outbound GET to
/// any URL. That is the same capability the forward_auth route
/// feature already provides on every request, so this endpoint does
/// not widen the attack surface - it just shortens the feedback loop.
pub async fn validate_forward_auth(
    Extension(_state): Extension<AppState>,
    Json(body): Json<ValidateForwardAuthRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Shape check first so we fail the same way the route save would.
    let fa_req = ForwardAuthConfigRequest {
        address: body.address.clone(),
        timeout_ms: body.timeout_ms,
        response_headers: Vec::new(),
        verdict_cache_ttl_ms: 0,
    };
    let cfg = build_forward_auth(&fa_req)?;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_millis(
            cfg.timeout_ms.min(5_000) as u64
        ))
        .build()
        .map_err(|e| ApiError::Internal(format!("reqwest build: {e}")))?;
    let start = std::time::Instant::now();
    let resp = client
        .get(&cfg.address)
        .timeout(std::time::Duration::from_millis(cfg.timeout_ms as u64))
        .send()
        .await
        .map_err(|e| ApiError::BadRequest(format!("request to auth service failed: {e}")))?;
    let elapsed_ms = start.elapsed().as_millis() as u64;
    let status = resp.status().as_u16();
    let mut headers = std::collections::HashMap::new();
    for name in [
        "location",
        "remote-user",
        "remote-groups",
        "remote-email",
        "content-type",
    ] {
        if let Some(v) = resp.headers().get(name) {
            if let Ok(s) = v.to_str() {
                headers.insert(name.to_string(), s.to_string());
            }
        }
    }

    Ok(json_data(ValidateForwardAuthResponse {
        status,
        elapsed_ms,
        headers,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fa_req(
        address: &str,
        timeout_ms: u32,
        response_headers: Vec<&str>,
    ) -> ForwardAuthConfigRequest {
        ForwardAuthConfigRequest {
            address: address.into(),
            timeout_ms,
            response_headers: response_headers.into_iter().map(String::from).collect(),
            verdict_cache_ttl_ms: 0,
        }
    }

    fn fa_req_with_cache(
        address: &str,
        timeout_ms: u32,
        response_headers: Vec<&str>,
        verdict_cache_ttl_ms: u32,
    ) -> ForwardAuthConfigRequest {
        ForwardAuthConfigRequest {
            address: address.into(),
            timeout_ms,
            response_headers: response_headers.into_iter().map(String::from).collect(),
            verdict_cache_ttl_ms,
        }
    }

    #[test]
    fn build_forward_auth_accepts_http_url() {
        let built = build_forward_auth(&fa_req(
            "http://authelia.internal/api/verify",
            2_000,
            vec!["Remote-User"],
        ))
        .expect("test setup");
        assert_eq!(built.address, "http://authelia.internal/api/verify");
        assert_eq!(built.timeout_ms, 2_000);
        assert_eq!(built.response_headers, vec!["Remote-User".to_string()]);
    }

    #[test]
    fn build_forward_auth_accepts_https_url() {
        assert!(
            build_forward_auth(&fa_req("https://auth.example.com/v1/verify", 500, vec![],)).is_ok()
        );
    }

    #[test]
    fn build_forward_auth_rejects_empty_address() {
        let err = build_forward_auth(&fa_req("", 1000, vec![])).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("must not be empty")));
    }

    #[test]
    fn build_forward_auth_rejects_non_absolute_url() {
        let err = build_forward_auth(&fa_req("/verify", 1000, vec![])).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn build_forward_auth_rejects_non_http_scheme() {
        let err = build_forward_auth(&fa_req("ftp://x.example.com/", 1000, vec![]))
            .expect_err("test setup");
        assert!(
            matches!(err, ApiError::BadRequest(ref m) if m.contains("http") || m.contains("https"))
        );
    }

    #[test]
    fn build_forward_auth_rejects_zero_timeout() {
        let err = build_forward_auth(&fa_req("http://a/", 0, vec![])).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("> 0")));
    }

    #[test]
    fn build_forward_auth_rejects_over_one_minute_timeout() {
        let err = build_forward_auth(&fa_req("http://a/", 60_001, vec![])).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("60000")));
    }

    #[test]
    fn build_forward_auth_rejects_blank_response_header_entry() {
        let err = build_forward_auth(&fa_req("http://a/", 1000, vec!["Remote-User", "   "]))
            .expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("non-empty")));
    }

    #[test]
    fn build_forward_auth_trims_response_header_names() {
        let built = build_forward_auth(&fa_req(
            "http://a/",
            1000,
            vec![" Remote-User ", "Remote-Groups"],
        ))
        .expect("test setup");
        assert_eq!(
            built.response_headers,
            vec!["Remote-User".to_string(), "Remote-Groups".to_string()]
        );
    }

    #[test]
    fn build_forward_auth_trims_address() {
        let built =
            build_forward_auth(&fa_req("  http://a/verify  ", 1000, vec![])).expect("test setup");
        assert_eq!(built.address, "http://a/verify");
    }

    #[test]
    fn build_forward_auth_accepts_verdict_cache_within_cap() {
        let built = build_forward_auth(&fa_req_with_cache("https://a/v", 1000, vec![], 30_000))
            .expect("test setup");
        assert_eq!(built.verdict_cache_ttl_ms, 30_000);
    }

    #[test]
    fn build_forward_auth_rejects_verdict_cache_over_cap() {
        let err = build_forward_auth(&fa_req_with_cache("https://a/v", 1000, vec![], 60_001))
            .expect_err("test setup");
        assert!(
            matches!(err, ApiError::BadRequest(ref m) if m.contains("60s") || m.contains("60000")),
            "expected 60s cap message, got: {err:?}"
        );
    }

    #[test]
    fn build_forward_auth_default_verdict_cache_is_zero() {
        // Zero-trust default: caching must be opt-in.
        let built = build_forward_auth(&fa_req("https://a/v", 1000, vec![])).expect("test setup");
        assert_eq!(built.verdict_cache_ttl_ms, 0);
    }

    #[test]
    fn build_forward_auth_accepts_http_loopback_without_warn_surface() {
        // Loopback http:// is accepted silently (sidecar deployments).
        // We can't observe the warn log from a unit test without a
        // tracing subscriber, so this test documents the acceptance
        // path; the warn-on-non-loopback path is covered in e2e.
        let built = build_forward_auth(&fa_req("http://127.0.0.1:9091/verify", 1000, vec![]))
            .expect("test setup");
        assert_eq!(built.address, "http://127.0.0.1:9091/verify");
    }
}
