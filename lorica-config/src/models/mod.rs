//! Domain models shared across the `lorica-config` crate and its
//! consumers. Grouped into per-entity submodules and re-exported here
//! so that `lorica_config::models::<Type>` paths keep working.

mod ai_crawler;
mod backend;
mod capture;
mod cert_export_acl;
mod certificate;
mod cluster;
mod enums;
mod loadtest;
mod notification;
mod preferences;
mod probes;
mod route;
mod settings;
mod sla;

#[cfg(test)]
mod tests;

pub use ai_crawler::{
    CustomCrawler, CustomVerification, CUSTOM_CRAWLER_MAX_CIDRS, CUSTOM_CRAWLER_MAX_COUNT,
};
pub use backend::{Backend, RouteBackend};
pub use capture::{
    CaptureEmit, CaptureLimits, CaptureMatch, CaptureOutput, CaptureRedaction, CaptureRule,
    CaptureScope, HeaderMatch, StatusMatch, CAPTURE_BODY_MAX_BYTES_CAP,
    CAPTURE_DEFAULT_BODY_MAX_BYTES, CAPTURE_DEFAULT_MAX_CAPTURES, CAPTURE_DEFAULT_RATE_PER_MINUTE,
    CAPTURE_DEFAULT_TTL_SECONDS, CAPTURE_MAX_CAPTURES_CAP, CAPTURE_PATTERN_MAX_LEN,
    CAPTURE_TTL_SECONDS_CAP,
};
pub use cert_export_acl::{
    pattern_matches, resolve as resolve_cert_export_acl, specificity, CertExportAcl,
};
pub use certificate::{Certificate, DnsProvider};
pub use cluster::{ClusterIdentity, ClusterNode, JoinToken, NodeStatus, RevokedSerial, TokenState};
pub use enums::{
    HeaderMatchType, HealthStatus, LifecycleState, LoadBalancing, NotificationChannel,
    PathMatchType, PreferenceValue, Role, WafMode,
};
pub use loadtest::{
    LoadTestComparison, LoadTestConfig, LoadTestResult, SAFE_LIMIT_CONCURRENCY,
    SAFE_LIMIT_DURATION_S, SAFE_LIMIT_RPS,
};
pub use notification::NotificationConfig;
pub use preferences::{User, UserPreference};
pub use probes::{ProbeConfig, ProbeResultRow};
pub use route::{
    validate_node_selector_names, AiBotPolicy, BotBypassRules, BotProtectionConfig,
    BotProtectionMode, ForwardAuthConfig, GeoIpConfig, GeoIpMode, HeaderRule, MirrorConfig,
    MtlsConfig, PathRule, RateLimit, RateLimitScope, ResponseRewriteConfig, ResponseRewriteRule,
    Route, SpoofedFallback, TrafficSplit, NODE_SELECTOR_MAX_ENTRIES,
};
pub use settings::{
    builtin_security_presets, resolve_security_preset, GlobalSettings, SecurityHeaderPreset,
};
pub use sla::{SlaBucket, SlaConfig, SlaSummary};
