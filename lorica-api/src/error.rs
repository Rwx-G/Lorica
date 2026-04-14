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

    /// 429 Too Many Requests: client exceeded the per-IP login rate limiter.
    #[error("rate limited")]
    RateLimited,

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
            ApiError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
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
            ApiError::RateLimited => "rate_limited",
            ApiError::Internal(_) => "internal_error",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = ErrorEnvelope {
            error: ErrorBody {
                code: self.code().to_string(),
                message: self.to_string(),
            },
        };
        (status, axum::Json(body)).into_response()
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
            ApiError::RateLimited.status_code(),
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
        assert_eq!(ApiError::RateLimited.code(), "rate_limited");
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
        assert_eq!(ApiError::RateLimited.to_string(), "rate limited");
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
