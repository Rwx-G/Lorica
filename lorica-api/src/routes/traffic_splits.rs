//! Canary traffic split types and validators.

use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// Canary traffic split assigning a percent of traffic to a backend pool.
#[derive(Serialize, Deserialize)]
pub struct TrafficSplitRequest {
    #[serde(default)]
    pub name: String,
    pub weight_percent: u8,
    #[serde(default)]
    pub backend_ids: Vec<String>,
}

/// Validate a traffic split request and convert it to the stored model.
/// Rejects the two operator mistakes that would silently break the feature:
/// weights outside 0..=100 (serde already caps at u8 max, but 101-255 still
/// slips through), and non-zero weight with an empty backend list (would
/// consume its weight band without diverting any traffic).
pub(super) fn build_traffic_split(
    body: &TrafficSplitRequest,
) -> Result<lorica_config::models::TrafficSplit, ApiError> {
    if body.weight_percent > 100 {
        return Err(ApiError::BadRequest(format!(
            "traffic_splits: weight_percent must be 0..=100, got {}",
            body.weight_percent
        )));
    }
    if body.weight_percent > 0 && body.backend_ids.is_empty() {
        return Err(ApiError::BadRequest(
            "traffic_splits: a split with weight > 0 must list at least one backend".into(),
        ));
    }
    let name = body.name.trim();
    if name.len() > 128 {
        return Err(ApiError::BadRequest(
            "traffic_splits: name must be <= 128 characters".into(),
        ));
    }
    if name.chars().any(|c| (c as u32) < 0x20 || c == '\u{7f}') {
        return Err(ApiError::BadRequest(
            "traffic_splits: name contains a control character".into(),
        ));
    }
    Ok(lorica_config::models::TrafficSplit {
        name: name.to_string(),
        weight_percent: body.weight_percent,
        backend_ids: body.backend_ids.clone(),
    })
}

/// Per-route global check: cumulative weights must not exceed 100%. The
/// engine clamps silently but the operator experience is better if the
/// API rejects the typo before it hits the DB.
pub(super) fn validate_traffic_splits(
    splits: &[lorica_config::models::TrafficSplit],
) -> Result<(), ApiError> {
    let total: u32 = splits.iter().map(|s| s.weight_percent as u32).sum();
    if total > 100 {
        return Err(ApiError::BadRequest(format!(
            "traffic_splits: cumulative weight_percent must be <= 100, got {total}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(name: &str, w: u8, ids: &[&str]) -> TrafficSplitRequest {
        TrafficSplitRequest {
            name: name.into(),
            weight_percent: w,
            backend_ids: ids.iter().map(|s| (*s).into()).collect(),
        }
    }

    #[test]
    fn build_traffic_split_rejects_weight_over_100() {
        let req = split("bad", 150, &["b"]);
        let err = build_traffic_split(&req).expect_err("should reject");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("must be 0..=100")));
    }

    #[test]
    fn build_traffic_split_rejects_non_zero_weight_without_backends() {
        // Split that would consume a weight band but divert to nothing -
        // operator typo; surface as 400 instead of silently swallowing
        // traffic on reload.
        let req = split("typo", 5, &[]);
        let err = build_traffic_split(&req).expect_err("should reject");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("at least one backend")));
    }

    #[test]
    fn build_traffic_split_accepts_zero_weight_with_no_backends() {
        // Zero-weight entry is a valid "prepared but disabled" state,
        // used while staging a rollout.
        let req = split("", 0, &[]);
        assert!(build_traffic_split(&req).is_ok());
    }

    #[test]
    fn build_traffic_split_trims_name() {
        let req = split("  v2  ", 5, &["b"]);
        let built = build_traffic_split(&req).expect("test setup");
        assert_eq!(built.name, "v2");
    }

    #[test]
    fn validate_traffic_splits_rejects_cumulative_over_100() {
        let splits = vec![
            build_traffic_split(&split("a", 60, &["x"])).expect("test setup"),
            build_traffic_split(&split("b", 50, &["y"])).expect("test setup"),
        ];
        let err = validate_traffic_splits(&splits).expect_err("should reject");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("<= 100")));
    }

    #[test]
    fn validate_traffic_splits_accepts_cumulative_exactly_100() {
        let splits = vec![
            build_traffic_split(&split("a", 40, &["x"])).expect("test setup"),
            build_traffic_split(&split("b", 60, &["y"])).expect("test setup"),
        ];
        assert!(validate_traffic_splits(&splits).is_ok());
    }

    #[test]
    fn validate_traffic_splits_empty_is_ok() {
        assert!(validate_traffic_splits(&[]).is_ok());
    }

    #[test]
    fn build_traffic_split_rejects_name_too_long() {
        let name: String = "a".repeat(200);
        let req = split(&name, 5, &["b"]);
        let err = build_traffic_split(&req).expect_err("should reject");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("128")));
    }

    #[test]
    fn build_traffic_split_rejects_control_char_in_name() {
        let req = split("bad\nname", 5, &["b"]);
        let err = build_traffic_split(&req).expect_err("should reject");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("control character")));
    }
}
