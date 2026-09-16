//! Domain models shared across the `lorica-config` crate and its
//! consumers. Grouped into per-entity submodules and re-exported here
//! so that `lorica_config::models::<Type>` paths keep working.

mod ai_crawler;
mod automation_token;
mod backend;
mod capture;
mod cert_export_acl;
mod certificate;
mod cluster;
mod enums;
mod hostname_pattern;
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
pub use automation_token::{
    automation_public_id_is_valid, automation_secret_hmac_hex, dummy_automation_secret_hmac_hex,
    mint_automation_token, parse_automation_token, verify_automation_secret, AutomationMintError,
    AutomationScope, AutomationToken, AutomationTokenFormatError, MintedAutomationToken,
    ParsedAutomationToken, AUTOMATION_TOKEN_DEFAULT_LIFETIME_DAYS,
    AUTOMATION_TOKEN_DEFAULT_MAX_TTL_SECONDS, AUTOMATION_TOKEN_HMAC_KEY_LEN,
    AUTOMATION_TOKEN_MAX_TTL_SECONDS_CAP, AUTOMATION_TOKEN_PUBLIC_ID_LEN,
    AUTOMATION_TOKEN_SECRET_LEN,
};
pub use backend::{Backend, RouteBackend};
pub use capture::{
    CaptureEmit, CaptureLimits, CaptureMatch, CaptureOutput, CaptureRedaction, CaptureRule,
    CaptureScope, HeaderMatch, StatusMatch, CAPTURE_BODY_MAX_BYTES_CAP,
    CAPTURE_DEFAULT_BODY_MAX_BYTES, CAPTURE_DEFAULT_MAX_CAPTURES, CAPTURE_DEFAULT_RATE_PER_MINUTE,
    CAPTURE_DEFAULT_TTL_SECONDS, CAPTURE_MAX_CAPTURES_CAP, CAPTURE_PATTERN_MAX_LEN,
    CAPTURE_TTL_SECONDS_CAP,
};
pub use cert_export_acl::{resolve as resolve_cert_export_acl, CertExportAcl};
pub use certificate::{Certificate, DnsProvider};
pub use cluster::{ClusterIdentity, ClusterNode, JoinToken, NodeStatus, RevokedSerial, TokenState};
pub use enums::{
    HeaderMatchType, HealthStatus, LifecycleState, LoadBalancing, NotificationChannel,
    PathMatchType, PreferenceValue, Role, WafMode,
};
pub use hostname_pattern::{matches_any_depth, matches_one_label, specificity};
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
