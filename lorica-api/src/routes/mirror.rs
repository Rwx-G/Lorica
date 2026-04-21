//! Request mirroring configuration types and validator.

use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// Request mirroring configuration (shadow backends, sample percent, body cap, timeout).
#[derive(Serialize, Deserialize, Clone)]
pub struct MirrorConfigRequest {
    /// Backend IDs that receive shadow copies.
    #[serde(default)]
    pub backend_ids: Vec<String>,
    /// Percentage of eligible requests to mirror (0..=100).
    #[serde(default = "default_mirror_sample_percent")]
    pub sample_percent: u8,
    /// Per-mirror-request timeout (ms).
    #[serde(default = "default_mirror_timeout_ms")]
    pub timeout_ms: u32,
    /// Maximum request body to buffer for mirroring (bytes).
    #[serde(default = "default_mirror_max_body_bytes")]
    pub max_body_bytes: u32,
}

fn default_mirror_sample_percent() -> u8 {
    100
}
fn default_mirror_timeout_ms() -> u32 {
    5_000
}
fn default_mirror_max_body_bytes() -> u32 {
    1_048_576
}

/// Validate a MirrorConfigRequest and convert to stored model. Rejects
/// the two operator mistakes that make the feature silently broken:
/// non-existent backend IDs (caught at reload via a warning too, but
/// better to fail the write) and out-of-range weights.
pub(super) fn build_mirror_config(
    body: &MirrorConfigRequest,
) -> Result<lorica_config::models::MirrorConfig, ApiError> {
    if body.backend_ids.is_empty() {
        return Err(ApiError::BadRequest(
            "mirror.backend_ids must not be empty (use null/missing to disable)".into(),
        ));
    }
    if body.sample_percent > 100 {
        return Err(ApiError::BadRequest(format!(
            "mirror.sample_percent must be 0..=100, got {}",
            body.sample_percent
        )));
    }
    if body.timeout_ms == 0 {
        return Err(ApiError::BadRequest("mirror.timeout_ms must be > 0".into()));
    }
    if body.timeout_ms > 60_000 {
        return Err(ApiError::BadRequest(
            "mirror.timeout_ms must be <= 60000 (60 seconds)".into(),
        ));
    }
    // Cap max_body_bytes at 128 MiB to prevent an operator from
    // unknowingly configuring memory amplification under the
    // 256-concurrent-mirrors cap.
    const MIRROR_MAX_BODY_CEILING: u32 = 128 * 1_048_576;
    if body.max_body_bytes > MIRROR_MAX_BODY_CEILING {
        return Err(ApiError::BadRequest(format!(
            "mirror.max_body_bytes must be <= {MIRROR_MAX_BODY_CEILING} ({} MiB); larger bodies should be mirrored via a dedicated replay tool",
            MIRROR_MAX_BODY_CEILING / 1_048_576
        )));
    }
    // Dedup and trim backend IDs so the engine doesn't spawn duplicate
    // sub-requests to the same shadow.
    let mut seen = std::collections::HashSet::new();
    let mut cleaned = Vec::with_capacity(body.backend_ids.len());
    for id in &body.backend_ids {
        let t = id.trim();
        if t.is_empty() {
            return Err(ApiError::BadRequest(
                "mirror.backend_ids entries must be non-empty".into(),
            ));
        }
        if seen.insert(t.to_string()) {
            cleaned.push(t.to_string());
        }
    }
    Ok(lorica_config::models::MirrorConfig {
        backend_ids: cleaned,
        sample_percent: body.sample_percent,
        timeout_ms: body.timeout_ms,
        max_body_bytes: body.max_body_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mirror_req(backends: Vec<&str>, pct: u8, timeout: u32) -> MirrorConfigRequest {
        MirrorConfigRequest {
            backend_ids: backends.into_iter().map(String::from).collect(),
            sample_percent: pct,
            timeout_ms: timeout,
            max_body_bytes: 1_048_576,
        }
    }

    #[test]
    fn build_mirror_accepts_valid() {
        let built =
            build_mirror_config(&mirror_req(vec!["b1", "b2"], 25, 3000)).expect("test setup");
        assert_eq!(built.backend_ids, vec!["b1".to_string(), "b2".to_string()]);
        assert_eq!(built.sample_percent, 25);
        assert_eq!(built.timeout_ms, 3000);
    }

    #[test]
    fn build_mirror_rejects_empty_backend_list() {
        let err = build_mirror_config(&mirror_req(vec![], 100, 5000)).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("must not be empty")));
    }

    #[test]
    fn build_mirror_rejects_sample_over_100() {
        let err = build_mirror_config(&mirror_req(vec!["b"], 101, 5000)).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("0..=100")));
    }

    #[test]
    fn build_mirror_rejects_zero_timeout() {
        let err = build_mirror_config(&mirror_req(vec!["b"], 50, 0)).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("> 0")));
    }

    #[test]
    fn build_mirror_rejects_over_60s_timeout() {
        let err = build_mirror_config(&mirror_req(vec!["b"], 50, 60_001)).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("60000")));
    }

    #[test]
    fn build_mirror_rejects_blank_backend_id() {
        let err = build_mirror_config(&mirror_req(vec!["   "], 50, 5000)).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("non-empty")));
    }

    #[test]
    fn build_mirror_dedups_backend_ids() {
        // Duplicate backend IDs would spawn two sub-requests to the same
        // shadow per primary request, which is wasteful and skews any
        // load/error metrics the operator is watching on the shadow.
        let built =
            build_mirror_config(&mirror_req(vec!["b1", "b2", "b1"], 50, 5000)).expect("test setup");
        assert_eq!(built.backend_ids, vec!["b1".to_string(), "b2".to_string()]);
    }

    #[test]
    fn build_mirror_trims_backend_ids() {
        let built = build_mirror_config(&mirror_req(vec!["  b1  "], 50, 5000)).expect("test setup");
        assert_eq!(built.backend_ids, vec!["b1".to_string()]);
    }

    #[test]
    fn build_mirror_rejects_excessive_max_body_bytes() {
        // Cap is 128 MiB. Operator writing 512 MB would blow memory
        // under the 256 concurrent-mirror cap.
        let mut req = mirror_req(vec!["b"], 50, 5000);
        req.max_body_bytes = 256 * 1_048_576;
        let err = build_mirror_config(&req).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("128 MiB")));
    }

    #[test]
    fn build_mirror_accepts_zero_max_body_bytes_as_headers_only() {
        // 0 = opt into headers-only mirroring (the old v1 behaviour).
        // Explicitly allowed, not an error.
        let mut req = mirror_req(vec!["b"], 50, 5000);
        req.max_body_bytes = 0;
        let built = build_mirror_config(&req).expect("test setup");
        assert_eq!(built.max_body_bytes, 0);
    }
}
