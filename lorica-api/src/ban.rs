//! Ban reason classification carried on every IP ban.
//!
//! A ban entry in the data-plane ban map is a [`BanRecord`]. The reason
//! is surfaced in `GET /api/v1/bans` and propagated over the
//! supervisor -> worker `BanIp` RPC as an i32 ([`BanReason::as_i32`] /
//! [`BanReason::from_i32`]).

use std::time::Instant;

use dashmap::DashMap;

/// One ban entry in the data-plane ban map.
///
/// Replaces the former bare `(Instant, u64, BanReason)` tuple. The two
/// adjacent `u64`-shaped quantities (`duration_s` here plus the
/// `remaining_seconds` carried by neighbouring report code) made the
/// positional form a transposition magnet; named fields make every
/// read and write site self-documenting. The per-request expiry check
/// gates on `banned_at` + `duration_s`; `reason` is cosmetic (surfaced
/// in the API response and logs).
#[derive(Debug, Clone)]
pub struct BanRecord {
    /// When the ban was issued (monotonic clock).
    pub banned_at: Instant,
    /// Ban duration in seconds.
    pub duration_s: u64,
    /// Why the IP was banned.
    pub reason: BanReason,
}

/// Data-plane ban map shared between the proxy hot path and the
/// management API: client IP -> [`BanRecord`].
pub type BanMap = DashMap<String, BanRecord>;

/// Why an IP was added to the ban list.
///
/// The discriminants returned by [`BanReason::as_i32`] are part of the
/// supervisor/worker wire contract: never reuse one for a different
/// reason. The snake_case strings from [`BanReason::as_str`] are part of
/// the public `/api/v1/bans` JSON contract and the dashboard.
///
/// ```
/// use lorica_api::ban::BanReason;
/// assert_eq!(BanReason::WafFlood.as_str(), "waf_flood");
/// assert_eq!(BanReason::from_i32(BanReason::Manual.as_i32()), Some(BanReason::Manual));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanReason {
    /// Per-route rate-limit violation threshold crossed
    /// (`auto_ban_threshold`).
    RateLimit,
    /// Volumetric WAF flood threshold crossed.
    WafFlood,
    /// Repeated WAF critical-rule blocks crossed `waf_ban_threshold`.
    WafCriticalRule,
    /// Operator-issued ban via the management API.
    Manual,
}

impl BanReason {
    /// Stable snake_case identifier used in the API response and logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            BanReason::RateLimit => "rate_limit",
            BanReason::WafFlood => "waf_flood",
            BanReason::WafCriticalRule => "waf_critical_rule",
            BanReason::Manual => "manual",
        }
    }

    /// Wire encoding for the `BanIp` RPC and `BanReportEntry`. Stable;
    /// never reassign a value to a different reason.
    pub fn as_i32(&self) -> i32 {
        match self {
            BanReason::RateLimit => 1,
            BanReason::WafFlood => 2,
            BanReason::WafCriticalRule => 3,
            BanReason::Manual => 4,
        }
    }

    /// Decode a wire value. Returns `None` for an unrecognized i32 (e.g.
    /// 0 from a legacy encoder) so the caller picks an explicit
    /// forward-compat fallback rather than silently mislabeling.
    pub fn from_i32(value: i32) -> Option<BanReason> {
        match value {
            1 => Some(BanReason::RateLimit),
            2 => Some(BanReason::WafFlood),
            3 => Some(BanReason::WafCriticalRule),
            4 => Some(BanReason::Manual),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BanReason;

    #[test]
    fn as_str_is_snake_case() {
        assert_eq!(BanReason::RateLimit.as_str(), "rate_limit");
        assert_eq!(BanReason::WafFlood.as_str(), "waf_flood");
        assert_eq!(BanReason::WafCriticalRule.as_str(), "waf_critical_rule");
        assert_eq!(BanReason::Manual.as_str(), "manual");
    }

    #[test]
    fn i32_round_trip() {
        for reason in [
            BanReason::RateLimit,
            BanReason::WafFlood,
            BanReason::WafCriticalRule,
            BanReason::Manual,
        ] {
            assert_eq!(BanReason::from_i32(reason.as_i32()), Some(reason));
        }
    }

    #[test]
    fn unknown_i32_is_none() {
        assert_eq!(BanReason::from_i32(0), None);
        assert_eq!(BanReason::from_i32(99), None);
    }

    #[test]
    fn unknown_i32_falls_back_to_waf_critical_rule() {
        // Documents the wire-decode contract the supervisor/worker
        // ban-report decoders rely on: an unrecognized i32 (legacy `0`
        // or a future reason from a newer peer) decodes via
        // `from_i32(..).unwrap_or(WafCriticalRule)` to WafCriticalRule
        // rather than dropping the row or mislabeling it. Pairs with
        // `decode_ban_report_entry` in the lorica supervisor module.
        for unknown in [0, 99] {
            assert_eq!(
                BanReason::from_i32(unknown).unwrap_or(BanReason::WafCriticalRule),
                BanReason::WafCriticalRule,
            );
        }
        // A known value still round-trips, never hitting the fallback.
        assert_eq!(
            BanReason::from_i32(BanReason::Manual.as_i32()).unwrap_or(BanReason::WafCriticalRule),
            BanReason::Manual,
        );
    }
}
