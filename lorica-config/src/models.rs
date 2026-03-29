use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// --- Enums ---

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancing {
    RoundRobin,
    ConsistentHash,
    Random,
    PeakEwma,
}

impl LoadBalancing {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RoundRobin => "round_robin",
            Self::ConsistentHash => "consistent_hash",
            Self::Random => "random",
            Self::PeakEwma => "peak_ewma",
        }
    }
}

impl FromStr for LoadBalancing {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "round_robin" => Ok(Self::RoundRobin),
            "consistent_hash" => Ok(Self::ConsistentHash),
            "random" => Ok(Self::Random),
            "peak_ewma" => Ok(Self::PeakEwma),
            other => Err(format!("unknown load balancing algorithm: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafMode {
    Detection,
    Blocking,
}

impl WafMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Detection => "detection",
            Self::Blocking => "blocking",
        }
    }
}

impl FromStr for WafMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "detection" => Ok(Self::Detection),
            "blocking" => Ok(Self::Blocking),
            other => Err(format!("unknown WAF mode: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyType {
    SingleVm,
    Ha,
    DockerSwarm,
    Kubernetes,
    Custom,
}

impl TopologyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SingleVm => "single_vm",
            Self::Ha => "ha",
            Self::DockerSwarm => "docker_swarm",
            Self::Kubernetes => "kubernetes",
            Self::Custom => "custom",
        }
    }
}

impl FromStr for TopologyType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "single_vm" => Ok(Self::SingleVm),
            "ha" => Ok(Self::Ha),
            "docker_swarm" => Ok(Self::DockerSwarm),
            "kubernetes" => Ok(Self::Kubernetes),
            "custom" => Ok(Self::Custom),
            other => Err(format!("unknown topology type: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Down,
}

impl HealthStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Down => "down",
        }
    }
}

impl FromStr for HealthStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "healthy" => Ok(Self::Healthy),
            "degraded" => Ok(Self::Degraded),
            "down" => Ok(Self::Down),
            other => Err(format!("unknown health status: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    Normal,
    Closing,
    Closed,
}

impl LifecycleState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Closing => "closing",
            Self::Closed => "closed",
        }
    }
}

impl FromStr for LifecycleState {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "normal" => Ok(Self::Normal),
            "closing" => Ok(Self::Closing),
            "closed" => Ok(Self::Closed),
            other => Err(format!("unknown lifecycle state: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationChannel {
    Email,
    Webhook,
}

impl NotificationChannel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Webhook => "webhook",
        }
    }
}

impl FromStr for NotificationChannel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "email" => Ok(Self::Email),
            "webhook" => Ok(Self::Webhook),
            other => Err(format!("unknown notification channel: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreferenceValue {
    Never,
    Always,
    Once,
}

impl PreferenceValue {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::Always => "always",
            Self::Once => "once",
        }
    }
}

impl FromStr for PreferenceValue {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "never" => Ok(Self::Never),
            "always" => Ok(Self::Always),
            "once" => Ok(Self::Once),
            other => Err(format!("unknown preference value: {other}")),
        }
    }
}

// --- Data Models ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub id: String,
    pub hostname: String,
    pub path_prefix: String,
    pub certificate_id: Option<String>,
    pub load_balancing: LoadBalancing,
    pub waf_enabled: bool,
    pub waf_mode: WafMode,
    pub topology_type: TopologyType,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backend {
    pub id: String,
    pub address: String,
    pub weight: i32,
    pub health_status: HealthStatus,
    pub health_check_enabled: bool,
    pub health_check_interval_s: i32,
    pub lifecycle_state: LifecycleState,
    pub active_connections: i32,
    pub tls_upstream: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteBackend {
    pub route_id: String,
    pub backend_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub id: String,
    pub domain: String,
    pub san_domains: Vec<String>,
    pub fingerprint: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub issuer: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub is_acme: bool,
    pub acme_auto_renew: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub id: String,
    pub channel: NotificationChannel,
    pub enabled: bool,
    pub config: String,
    pub alert_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPreference {
    pub id: String,
    pub preference_key: String,
    pub value: PreferenceValue,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminUser {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub must_change_password: bool,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalSettings {
    pub management_port: u16,
    pub log_level: String,
    pub default_health_check_interval_s: i32,
}

impl Default for GlobalSettings {
    fn default() -> Self {
        Self {
            management_port: 9443,
            log_level: "info".to_string(),
            default_health_check_interval_s: 10,
        }
    }
}
