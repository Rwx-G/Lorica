//! Domain models shared across the `lorica-config` crate and its
//! consumers. Grouped into per-entity submodules and re-exported here
//! so that `lorica_config::models::<Type>` paths keep working.

mod ai_crawler;
mod backend;
mod cert_export_acl;
mod certificate;
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
pub use cert_export_acl::{
    pattern_matches, resolve as resolve_cert_export_acl, specificity, CertExportAcl,
};
pub use certificate::{Certificate, DnsProvider};
pub use enums::{
    HeaderMatchType, HealthStatus, LifecycleState, LoadBalancing, NotificationChannel,
    PathMatchType, PreferenceValue, WafMode,
};
pub use loadtest::{
    LoadTestComparison, LoadTestConfig, LoadTestResult, SAFE_LIMIT_CONCURRENCY,
    SAFE_LIMIT_DURATION_S, SAFE_LIMIT_RPS,
};
pub use notification::NotificationConfig;
pub use preferences::{AdminUser, UserPreference};
pub use probes::{ProbeConfig, ProbeResultRow};
pub use route::{
    AiBotPolicy, BotBypassRules, BotProtectionConfig, BotProtectionMode, ForwardAuthConfig,
    GeoIpConfig, GeoIpMode, HeaderRule, MirrorConfig, MtlsConfig, PathRule, RateLimit,
    RateLimitScope, ResponseRewriteConfig, ResponseRewriteRule, Route, SpoofedFallback,
    TrafficSplit,
};
pub use settings::{
    builtin_security_presets, resolve_security_preset, GlobalSettings, SecurityHeaderPreset,
};
pub use sla::{SlaBucket, SlaConfig, SlaSummary};
