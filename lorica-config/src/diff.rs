use std::collections::HashSet;

use serde::Serialize;

use crate::error::Result;
use crate::import::ImportData;
use crate::models::*;
use crate::store::ConfigStore;

/// Summary of changes that an import would produce.
#[derive(Debug, Serialize)]
pub struct ConfigDiff {
    pub routes: EntityDiff,
    pub backends: EntityDiff,
    pub certificates: EntityDiff,
    pub route_backends: EntityDiff,
    pub notification_configs: EntityDiff,
    pub user_preferences: EntityDiff,
    pub admin_users: EntityDiff,
    pub global_settings: SettingsDiff,
}

/// Per-entity type summary of adds, modifications, and removals.
#[derive(Debug, Serialize)]
pub struct EntityDiff {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub removed: Vec<String>,
}

/// Diff for global settings key-value pairs.
#[derive(Debug, Serialize)]
pub struct SettingsDiff {
    pub changes: Vec<SettingChange>,
}

#[derive(Debug, Serialize)]
pub struct SettingChange {
    pub key: String,
    pub old_value: String,
    pub new_value: String,
}

impl ConfigDiff {
    /// Returns true if there are no changes at all.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
            && self.backends.is_empty()
            && self.certificates.is_empty()
            && self.route_backends.is_empty()
            && self.notification_configs.is_empty()
            && self.user_preferences.is_empty()
            && self.admin_users.is_empty()
            && self.global_settings.changes.is_empty()
    }
}

impl EntityDiff {
    fn is_empty(&self) -> bool {
        self.added.is_empty() && self.modified.is_empty() && self.removed.is_empty()
    }
}

/// Compare import data against the current database state and produce a diff.
pub fn compute_diff(store: &ConfigStore, incoming: &ImportData) -> Result<ConfigDiff> {
    let routes = diff_by_id(
        &store.list_routes()?,
        &incoming.routes,
        |r| r.id.clone(),
        route_eq,
        |r| format!("{} ({})", r.hostname, r.id),
    );

    let backends = diff_by_id(
        &store.list_backends()?,
        &incoming.backends,
        |b| b.id.clone(),
        backend_eq,
        |b| format!("{} ({})", b.address, b.id),
    );

    let certificates = diff_by_id(
        &store.list_certificates()?,
        &incoming.certificates,
        |c| c.id.clone(),
        cert_eq,
        |c| format!("{} ({})", c.domain, c.id),
    );

    let route_backends =
        diff_route_backends(&store.list_route_backends()?, &incoming.route_backends);

    let notification_configs = diff_by_id(
        &store.list_notification_configs()?,
        &incoming.notification_configs,
        |n| n.id.clone(),
        notif_eq,
        |n| format!("{} ({})", n.channel.as_str(), n.id),
    );

    let user_preferences = diff_by_id(
        &store.list_user_preferences()?,
        &incoming.user_preferences,
        |p| p.id.clone(),
        pref_eq,
        |p| format!("{} ({})", p.preference_key, p.id),
    );

    let admin_users = diff_by_id(
        &store.list_admin_users()?,
        &incoming.admin_users,
        |u| u.id.clone(),
        admin_eq,
        |u| format!("{} ({})", u.username, u.id),
    );

    let global_settings = diff_settings(&store.get_global_settings()?, &incoming.global_settings);

    Ok(ConfigDiff {
        routes,
        backends,
        certificates,
        route_backends,
        notification_configs,
        user_preferences,
        admin_users,
        global_settings,
    })
}

fn diff_by_id<T>(
    current: &[T],
    incoming: &[T],
    id_fn: impl Fn(&T) -> String,
    eq_fn: impl Fn(&T, &T) -> bool,
    label_fn: impl Fn(&T) -> String,
) -> EntityDiff {
    let current_ids: HashSet<String> = current.iter().map(&id_fn).collect();
    let incoming_ids: HashSet<String> = incoming.iter().map(&id_fn).collect();

    let added: Vec<String> = incoming
        .iter()
        .filter(|item| !current_ids.contains(&id_fn(item)))
        .map(&label_fn)
        .collect();

    let removed: Vec<String> = current
        .iter()
        .filter(|item| !incoming_ids.contains(&id_fn(item)))
        .map(&label_fn)
        .collect();

    let modified: Vec<String> = incoming
        .iter()
        .filter(|item| {
            let id = id_fn(item);
            if let Some(existing) = current.iter().find(|c| id_fn(c) == id) {
                !eq_fn(existing, item)
            } else {
                false
            }
        })
        .map(&label_fn)
        .collect();

    EntityDiff {
        added,
        modified,
        removed,
    }
}

fn diff_route_backends(current: &[RouteBackend], incoming: &[RouteBackend]) -> EntityDiff {
    let current_set: HashSet<(String, String)> = current
        .iter()
        .map(|rb| (rb.route_id.clone(), rb.backend_id.clone()))
        .collect();
    let incoming_set: HashSet<(String, String)> = incoming
        .iter()
        .map(|rb| (rb.route_id.clone(), rb.backend_id.clone()))
        .collect();

    let added: Vec<String> = incoming_set
        .difference(&current_set)
        .map(|(r, b)| format!("{r} -> {b}"))
        .collect();
    let removed: Vec<String> = current_set
        .difference(&incoming_set)
        .map(|(r, b)| format!("{r} -> {b}"))
        .collect();

    EntityDiff {
        added,
        modified: Vec::new(),
        removed,
    }
}

fn diff_settings(current: &GlobalSettings, incoming: &GlobalSettings) -> SettingsDiff {
    let mut changes = Vec::new();
    if current.management_port != incoming.management_port {
        changes.push(SettingChange {
            key: "management_port".to_string(),
            old_value: current.management_port.to_string(),
            new_value: incoming.management_port.to_string(),
        });
    }
    if current.log_level != incoming.log_level {
        changes.push(SettingChange {
            key: "log_level".to_string(),
            old_value: current.log_level.clone(),
            new_value: incoming.log_level.clone(),
        });
    }
    if current.default_health_check_interval_s != incoming.default_health_check_interval_s {
        changes.push(SettingChange {
            key: "default_health_check_interval_s".to_string(),
            old_value: current.default_health_check_interval_s.to_string(),
            new_value: incoming.default_health_check_interval_s.to_string(),
        });
    }
    if current.cert_warning_days != incoming.cert_warning_days {
        changes.push(SettingChange {
            key: "cert_warning_days".to_string(),
            old_value: current.cert_warning_days.to_string(),
            new_value: incoming.cert_warning_days.to_string(),
        });
    }
    if current.cert_critical_days != incoming.cert_critical_days {
        changes.push(SettingChange {
            key: "cert_critical_days".to_string(),
            old_value: current.cert_critical_days.to_string(),
            new_value: incoming.cert_critical_days.to_string(),
        });
    }
    if current.default_topology_type != incoming.default_topology_type {
        changes.push(SettingChange {
            key: "default_topology_type".to_string(),
            old_value: current.default_topology_type.as_str().to_string(),
            new_value: incoming.default_topology_type.as_str().to_string(),
        });
    }
    if current.max_global_connections != incoming.max_global_connections {
        changes.push(SettingChange {
            key: "max_global_connections".to_string(),
            old_value: current.max_global_connections.to_string(),
            new_value: incoming.max_global_connections.to_string(),
        });
    }
    if current.flood_threshold_rps != incoming.flood_threshold_rps {
        changes.push(SettingChange {
            key: "flood_threshold_rps".to_string(),
            old_value: current.flood_threshold_rps.to_string(),
            new_value: incoming.flood_threshold_rps.to_string(),
        });
    }
    SettingsDiff { changes }
}

fn route_eq(a: &Route, b: &Route) -> bool {
    a.hostname == b.hostname
        && a.path_prefix == b.path_prefix
        && a.certificate_id == b.certificate_id
        && a.load_balancing == b.load_balancing
        && a.waf_enabled == b.waf_enabled
        && a.waf_mode == b.waf_mode
        && a.topology_type == b.topology_type
        && a.enabled == b.enabled
}

fn backend_eq(a: &Backend, b: &Backend) -> bool {
    a.address == b.address
        && a.name == b.name
        && a.group_name == b.group_name
        && a.weight == b.weight
        && a.health_check_enabled == b.health_check_enabled
        && a.health_check_interval_s == b.health_check_interval_s
        && a.tls_upstream == b.tls_upstream
        && a.h2_upstream == b.h2_upstream
}

fn cert_eq(a: &Certificate, b: &Certificate) -> bool {
    a.domain == b.domain
        && a.san_domains == b.san_domains
        && a.cert_pem == b.cert_pem
        && a.issuer == b.issuer
}

fn notif_eq(a: &NotificationConfig, b: &NotificationConfig) -> bool {
    a.channel == b.channel
        && a.enabled == b.enabled
        && a.config == b.config
        && a.alert_types == b.alert_types
}

fn pref_eq(a: &UserPreference, b: &UserPreference) -> bool {
    a.preference_key == b.preference_key && a.value == b.value
}

fn admin_eq(a: &AdminUser, b: &AdminUser) -> bool {
    a.username == b.username && a.password_hash == b.password_hash
}
