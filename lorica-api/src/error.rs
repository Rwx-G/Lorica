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

    /// 400 Bad Request: payload failed validation (bad enum, malformed regex, etc.).
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

    /// 429 Too Many Requests: client exceeded a per-bucket rate
    /// limiter. The inner `u64` is the Retry-After value in
    /// seconds (0 if unknown; the response still emits the
    /// header for client tooling consistency).
    #[error("rate limited (retry after {0}s)")]
    RateLimited(u64),

    /// 500 Internal Server Error: unexpected failure (DB, IO, serialization).
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<lorica_config::ConfigError> for ApiError {
    fn from(err: lorica_config::ConfigError) -> Self {
        match &err {
            lorica_config::ConfigError::NotFound(_) => ApiError::NotFound(err.to_string()),
            lorica_config::ConfigError::Validation(_) => ApiError::BadRequest(err.to_string()),
            _ => ApiError::Internal(err.to_string()),
        }
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
            ApiError::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            ApiError::NotFound(_) => "not_found",
            ApiError::BadRequest(_) => "bad_request",
            ApiError::Unauthorized(_) => "unauthorized",
            ApiError::Forbidden(_) => "forbidden",
            ApiError::Conflict(_) => "conflict",
            ApiError::RateLimited(_) => "rate_limited",
            ApiError::Internal(_) => "internal_error",
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
            ApiError::RateLimited(30).status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            ApiError::Internal("x".into()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(ApiError::NotFound("x".into()).code(), "not_found");
        assert_eq!(ApiError::BadRequest("x".into()).code(), "bad_request");
        assert_eq!(ApiError::Unauthorized("x".into()).code(), "unauthorized");
        assert_eq!(ApiError::Forbidden("x".into()).code(), "forbidden");
        assert_eq!(ApiError::Conflict("x".into()).code(), "conflict");
        assert_eq!(ApiError::RateLimited(30).code(), "rate_limited");
        assert_eq!(ApiError::Internal("x".into()).code(), "internal_error");
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
    fn test_config_error_validation_converts() {
        let err: ApiError = lorica_config::ConfigError::Validation("bad ref".into()).into();
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
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
