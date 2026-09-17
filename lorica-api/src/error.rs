//! Unified error type for API handlers and the JSON error envelope they emit.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use thiserror::Error;

/// Error type returned by every handler. Maps to an HTTP status and a
/// `{"error": {"code", "message"}}` JSON envelope via [`IntoResponse`].
#[derive(Debug, Error)]
pub enum ApiError {
    /// 404 Not Found: the requested resource (route, certificate, backend, ...) does not exist.
    #[error("not found: {0}")]
    NotFound(String),

    /// 400 Bad Request: the request itself could not be understood.
    ///
    /// A malformed path parameter, an unparseable value, a body the
    /// server could not make sense of. See [`ApiError::Unprocessable`]
    /// for the other half of the split and the rule that decides
    /// between them.
    ///
    /// Most of this crate predates that split and answers 400 for
    /// semantic refusals too. Those call sites are not being swept:
    /// reclassifying them one by one is a behaviour change on a public
    /// API for no gain to the caller, both being 4xx and every client
    /// in this repository reading the body rather than branching on the
    /// code. New handlers follow the rule below; old ones are corrected
    /// when they are touched for another reason.
    #[error("bad request: {0}")]
    BadRequest(String),

    /// 401 Unauthorized: missing or invalid session cookie / credentials.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// 403 Forbidden: authenticated but not allowed (e.g. CSRF check failed).
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// 409 Conflict: uniqueness violation or state conflict (duplicate hostname, etc.).
    #[error("conflict: {0}")]
    Conflict(String),

    /// 422 Unprocessable Entity: the body parsed, and its content is
    /// refused by a model rule.
    ///
    /// # The rule
    ///
    /// Ask whether the server understood the request. If it did not,
    /// that is 400. If it understood it perfectly and refuses it on its
    /// merits, a cap over its limit, a predicate that constrains
    /// nothing, an identifier naming no row, that is 422.
    ///
    /// The split is not a preference. Axum already answers 422 when a
    /// `deny_unknown_fields` body carries a field the server owns, such
    /// as a client-supplied `expires_at` or a runtime counter. A
    /// handler that then answered 400 for a cap over its limit would
    /// split one class of refusal across two statuses on the same
    /// endpoint, and a caller could not tell from the code which kind
    /// of mistake they made.
    #[error("unprocessable: {0}")]
    Unprocessable(String),

    /// 429 Too Many Requests: client exceeded a per-bucket rate
    /// limiter. The inner `u64` is the Retry-After value in
    /// seconds (0 if unknown; the response still emits the
    /// header for client tooling consistency).
    #[error("rate limited (retry after {0}s)")]
    RateLimited(u64),

    /// 500 Internal Server Error: unexpected failure (DB, IO, serialization).
    #[error("internal error: {0}")]
    Internal(String),

    /// 503 Service Unavailable: the resource exists in the product but
    /// not in this process, and the message names where to read it
    /// instead. The recent-captures ring under `--workers` is the one
    /// case today: the ring is per worker and the API runs in the
    /// supervisor, which holds an empty one.
    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),
}

impl From<lorica_config::ConfigError> for ApiError {
    fn from(err: lorica_config::ConfigError) -> Self {
        match &err {
            lorica_config::ConfigError::NotFound(_) => ApiError::NotFound(err.to_string()),
            // The store's two input refusals land on the two halves of
            // the rule documented on `Unprocessable` above. A rule the
            // store enforces (uniqueness, a cap, a reference naming no
            // row) is a request the server understood and refuses on
            // its merits: 422. A payload the store could not read is a
            // request the server did not understand: 400. Mapping both
            // to 400, as this did, split one class of refusal across
            // two statuses on the same endpoint depending on whether
            // the handler or the store caught it.
            lorica_config::ConfigError::Validation(_) => ApiError::Unprocessable(err.to_string()),
            lorica_config::ConfigError::Malformed(_) => ApiError::BadRequest(err.to_string()),
            // A stored column this process itself wrote back that no
            // longer decodes is not the caller's doing: no payload they
            // could send would make it succeed. 500, with the same
            // wording the store used, so the operator reads "the
            // database is damaged" rather than "your request is bad".
            lorica_config::ConfigError::Corrupt(_) => ApiError::Internal(err.to_string()),
            _ => ApiError::Internal(err.to_string()),
        }
    }
}

/// ACME protocol failures are internal server errors: they surface a
/// generic "internal error" to the client (audit M-12) while the full
/// `AcmeError` detail is logged. Input validation for ACME requests
/// (`DnsChallengeConfig::validate`, `build_dns_challenger`) stays a
/// `BadRequest` at the individual call sites; only the driver's protocol
/// errors flow through here.
impl From<lorica_acme::AcmeError> for ApiError {
    fn from(err: lorica_acme::AcmeError) -> Self {
        ApiError::Internal(err.to_string())
    }
}

#[derive(Serialize)]
struct ErrorBody {
    code: String,
    message: String,
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

impl ApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            ApiError::NotFound(_) => "not_found",
            ApiError::BadRequest(_) => "bad_request",
            ApiError::Unauthorized(_) => "unauthorized",
            ApiError::Forbidden(_) => "forbidden",
            ApiError::Conflict(_) => "conflict",
            ApiError::Unprocessable(_) => "unprocessable_entity",
            ApiError::RateLimited(_) => "rate_limited",
            ApiError::Internal(_) => "internal_error",
            ApiError::ServiceUnavailable(_) => "service_unavailable",
        }
    }
}

/// Generic placeholder emitted in the JSON body for every
/// `ApiError::Internal`. The full inner detail (which may
/// contain `rusqlite::Error` strings, file paths under
/// `/var/lib/lorica/...`, library version banners, etc.) is
/// logged at `tracing::error!` for operator forensics but
/// never crosses the API boundary. v1.5.1 audit M-12.
const INTERNAL_USER_MESSAGE: &str = "internal error";

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        // 429 responses carry a Retry-After header (RFC 6585) so
        // polite clients know when to retry. The inner u64 is the
        // seconds until the current window rolls over.
        let retry_after = match &self {
            ApiError::RateLimited(secs) => Some(*secs),
            _ => None,
        };
        // v1.5.1 audit M-12 : sanitise `Internal` errors at the
        // response boundary. The inner detail (built by ~84
        // `format!("...: {e}")` call sites across `lorica-api`)
        // commonly carries `rusqlite::Error` text with SQL
        // fragments, file paths, library version banners. Log
        // the full detail at `error!` level so the operator
        // keeps a forensics trail, then emit a generic
        // placeholder in the JSON body so an authenticated
        // dashboard toast - or a future federated multi-tenant
        // deployment, or a screen-captured triage session -
        // never surfaces internal bytes. Other variants
        // (`NotFound`, `BadRequest`, `Unauthorized`, etc.)
        // carry operator-supplied or user-supplied content
        // and stay verbatim - their messages are part of the
        // documented contract.
        let user_message = match &self {
            ApiError::Internal(detail) => {
                tracing::error!(detail = %detail, "API internal error");
                INTERNAL_USER_MESSAGE.to_string()
            }
            _ => self.to_string(),
        };
        let body = ErrorEnvelope {
            error: ErrorBody {
                code: self.code().to_string(),
                message: user_message,
            },
        };
        let mut response = (status, axum::Json(body)).into_response();
        if let Some(secs) = retry_after {
            if let Ok(value) = http::HeaderValue::from_str(&secs.to_string()) {
                response.headers_mut().insert("Retry-After", value);
            }
        }
        response
    }
}

/// Wrap a successful response in {"data": ...} envelope.
pub fn json_data<T: Serialize>(data: T) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "data": data }))
}

/// Wrap a successful response in {"data": ...} envelope with a specific status code.
pub fn json_data_with_status<T: Serialize>(
    status: StatusCode,
    data: T,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    (status, axum::Json(serde_json::json!({ "data": data })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    #[test]
    fn test_status_codes() {
        assert_eq!(
            ApiError::NotFound("x".into()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            ApiError::BadRequest("x".into()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ApiError::Unauthorized("x".into()).status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ApiError::Forbidden("x".into()).status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            ApiError::Conflict("x".into()).status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            ApiError::Unprocessable("x".into()).status_code(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            ApiError::RateLimited(30).status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            ApiError::Internal("x".into()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            ApiError::ServiceUnavailable("x".into()).status_code(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(ApiError::NotFound("x".into()).code(), "not_found");
        assert_eq!(ApiError::BadRequest("x".into()).code(), "bad_request");
        assert_eq!(ApiError::Unauthorized("x".into()).code(), "unauthorized");
        assert_eq!(ApiError::Forbidden("x".into()).code(), "forbidden");
        assert_eq!(ApiError::Conflict("x".into()).code(), "conflict");
        assert_eq!(
            ApiError::Unprocessable("x".into()).code(),
            "unprocessable_entity"
        );
        assert_eq!(ApiError::RateLimited(30).code(), "rate_limited");
        assert_eq!(ApiError::Internal("x".into()).code(), "internal_error");
        assert_eq!(
            ApiError::ServiceUnavailable("x".into()).code(),
            "service_unavailable"
        );
    }

    #[test]
    fn test_display_messages() {
        assert_eq!(
            ApiError::NotFound("item".into()).to_string(),
            "not found: item"
        );
        assert_eq!(
            ApiError::BadRequest("bad".into()).to_string(),
            "bad request: bad"
        );
        assert_eq!(
            ApiError::RateLimited(30).to_string(),
            "rate limited (retry after 30s)"
        );
    }

    #[tokio::test]
    async fn test_into_response_status_and_body() {
        let err = ApiError::NotFound("route 42".into());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should fit in memory");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("response body is JSON");
        assert_eq!(json["error"]["code"], "not_found");
        assert_eq!(json["error"]["message"], "not found: route 42");
    }

    /// v1.5.1 audit M-12 : `ApiError::Internal` must NEVER
    /// surface its inner detail to the API consumer. Whatever
    /// the call site put in the inner String (rusqlite error
    /// text, file paths, library version banners) stays in the
    /// `tracing::error!` log only ; the JSON body returns the
    /// generic placeholder.
    #[tokio::test]
    async fn test_into_response_internal_does_not_leak_inner_detail() {
        // Worst-case-shape inner detail : SQL fragment + file
        // path + library banner.
        let leaky_detail =
            "rusqlite error: UNIQUE constraint failed: routes.hostname (file: /var/lib/lorica/lorica.db, sqlite 3.42.0)";
        let err = ApiError::Internal(leaky_detail.to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should fit in memory");
        let body_str = std::str::from_utf8(&body).expect("response body is UTF-8");
        let json: serde_json::Value =
            serde_json::from_str(body_str).expect("response body is JSON");

        assert_eq!(json["error"]["code"], "internal_error");
        assert_eq!(
            json["error"]["message"], "internal error",
            "internal errors must surface the generic placeholder, not the inner detail"
        );
        // Defense-in-depth byte scan on the whole body :
        // none of the leaky tokens may appear anywhere.
        assert!(
            !body_str.contains("rusqlite"),
            "`rusqlite` token must not leak to the response body"
        );
        assert!(
            !body_str.contains("/var/lib/lorica"),
            "filesystem paths must not leak to the response body"
        );
        assert!(
            !body_str.contains("UNIQUE constraint"),
            "SQL fragments must not leak to the response body"
        );
        assert!(
            !body_str.contains("3.42.0"),
            "library version banners must not leak to the response body"
        );
    }

    /// v1.5.1 audit M-12 : non-Internal variants keep their
    /// documented message format - the sanitisation only
    /// applies to `Internal`. NotFound / BadRequest / etc.
    /// carry operator- or user-supplied content that is part
    /// of the API contract and must round-trip verbatim.
    #[tokio::test]
    async fn test_into_response_non_internal_variants_keep_message() {
        for (err, expected) in [
            (ApiError::NotFound("x".into()), "not found: x"),
            (ApiError::BadRequest("y".into()), "bad request: y"),
            (ApiError::Unauthorized("z".into()), "unauthorized: z"),
            (ApiError::Forbidden("a".into()), "forbidden: a"),
            (ApiError::Conflict("b".into()), "conflict: b"),
        ] {
            let response = err.into_response();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body");
            let json: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
            assert_eq!(
                json["error"]["message"], expected,
                "non-Internal variant message must round-trip verbatim"
            );
        }
    }

    #[test]
    fn test_config_error_not_found_converts() {
        let err: ApiError = lorica_config::ConfigError::NotFound("cert 1".into()).into();
        assert_eq!(err.status_code(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_config_error_validation_converts_to_unprocessable() {
        // A store-level rule refusal is a request the server
        // understood: the same 422 a handler-level refusal answers.
        let err: ApiError = lorica_config::ConfigError::Validation("bad ref".into()).into();
        assert_eq!(err.status_code(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn test_config_error_malformed_converts_to_bad_request() {
        let err: ApiError = lorica_config::ConfigError::Malformed("not JSON".into()).into();
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_config_error_corrupt_converts_to_internal() {
        // A JSON column this process wrote back and can no longer read
        // is a damaged or downgraded database, not a bad request: the
        // caller has nothing to fix, so it is a 500 and never a 4xx.
        let err: ApiError =
            lorica_config::ConfigError::Corrupt("invalid path_rules JSON: eof".into()).into();
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_ne!(err.status_code(), StatusCode::BAD_REQUEST);
        assert_ne!(err.status_code(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn test_config_error_other_converts_to_internal() {
        let err: ApiError = lorica_config::ConfigError::Serialization("toml fail".into()).into();
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_rate_limited_sets_retry_after_header() {
        let err = ApiError::RateLimited(42);
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry = response
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok());
        assert_eq!(retry, Some("42"));
    }

    #[test]
    fn test_json_data_envelope() {
        let result = json_data("hello");
        let val = result.0;
        assert_eq!(val["data"], "hello");
    }

    #[test]
    fn test_json_data_with_status_envelope() {
        let (status, json) = json_data_with_status(StatusCode::CREATED, "item");
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(json.0["data"], "item");
    }
}
