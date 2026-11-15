use std::collections::HashSet;

use serde::Serialize;

use crate::error::Result;
use crate::import::ImportData;
use crate::models::*;
use crate::store::ConfigStore;

/// Summary of changes that an import would produce.
#[derive(Debug, Serialize)]
pub struct ConfigDiff {
    /// Per-entity diff for the `routes` table.
    pub routes: EntityDiff,
    /// Per-entity diff for the `backends` table.
    pub backends: EntityDiff,
    /// Per-entity diff for the `certificates` table.
    pub certificates: EntityDiff,
    /// Per-entity diff for the `route_backends` join table.
    pub route_backends: EntityDiff,
    /// Per-entity diff for the `streams` table (Story 12.1).
    pub streams: EntityDiff,
    /// Per-entity diff for the `stream_backends` join table.
    pub stream_backends: EntityDiff,
    /// Per-entity diff for `notification_configs`.
    pub notification_configs: EntityDiff,
    /// Per-entity diff for `user_preferences`.
    pub user_preferences: EntityDiff,
    /// Per-entity diff for `users`.
    pub users: EntityDiff,
    /// Key-level diff for `global_settings`.
    pub global_settings: SettingsDiff,
}

/// Per-entity type summary of adds, modifications, and removals.
#[derive(Debug, Serialize)]
pub struct EntityDiff {
    /// IDs present in the import but absent from the current store.
    pub added: Vec<String>,
    /// IDs present on both sides whose values differ.
    pub modified: Vec<String>,
    /// IDs present in the store but absent from the import.
    pub removed: Vec<String>,
}

/// Diff for global settings key-value pairs.
#[derive(Debug, Serialize)]
pub struct SettingsDiff {
    /// One entry per changed key.
    pub changes: Vec<SettingChange>,
}

/// One entry of a [`SettingsDiff`]: the key whose value would change,
/// rendered both before and after as strings for display purposes.
#[derive(Debug, Serialize)]
pub struct SettingChange {
    /// Name of the changed setting.
    pub key: String,
    /// Previous value (rendered as string).
    pub old_value: String,
    /// New value from the import (rendered as string).
    pub new_value: String,
}

impl ConfigDiff {
    /// Returns true if there are no changes at all.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
            && self.backends.is_empty()
            && self.certificates.is_empty()
            && self.route_backends.is_empty()
            && self.streams.is_empty()
            && self.stream_backends.is_empty()
            && self.notification_configs.is_empty()
            && self.user_preferences.is_empty()
            && self.users.is_empty()
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

    let route_backends = diff_links(
        &store.list_route_backends()?,
        &incoming.route_backends,
        |rb| (rb.route_id.clone(), rb.backend_id.clone()),
    );

    let streams = diff_by_id(
        &store.list_streams()?,
        &incoming.streams,
        |s| s.id.clone(),
        stream_eq,
        |s| format!("{} ({})", s.name, s.id),
    );

    let stream_backends =
        diff_stream_links(&store.list_stream_backends()?, &incoming.stream_backends);

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

    let users = diff_by_id(
        &store.list_users()?,
        &incoming.users,
        |u| u.id.clone(),
        user_eq,
        |u| format!("{} ({})", u.username, u.id),
    );

    let global_settings = diff_settings(&store.get_global_settings()?, &incoming.global_settings);

    Ok(ConfigDiff {
        routes,
        backends,
        certificates,
        route_backends,
        streams,
        stream_backends,
        notification_configs,
        user_preferences,
        users,
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

/// Diff two sets of join rows, each read as its `(owner, backend)` pair.
fn diff_links<T>(
    current: &[T],
    incoming: &[T],
    pair: impl Fn(&T) -> (String, String),
) -> EntityDiff {
    let current_set: HashSet<(String, String)> = current.iter().map(&pair).collect();
    let incoming_set: HashSet<(String, String)> = incoming.iter().map(&pair).collect();

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

/// [`diff_links`] for stream links, which also carry the backup flag
/// (Story 12.3, D-f) and the rule they serve (Story 12.4, D-d): a pair
/// present on both sides whose flag or rule differs is modified.
fn diff_stream_links(current: &[StreamBackend], incoming: &[StreamBackend]) -> EntityDiff {
    let pair = |sb: &StreamBackend| (sb.stream_id.clone(), sb.backend_id.clone());
    let mut diff = diff_links(current, incoming, pair);
    let current_links: std::collections::HashMap<(String, String), &StreamBackend> =
        current.iter().map(|sb| (pair(sb), sb)).collect();
    diff.modified = incoming
        .iter()
        .filter(|sb| {
            current_links
                .get(&pair(sb))
                .is_some_and(|stored| stored.backup != sb.backup || stored.rule != sb.rule)
        })
        .map(|sb| format!("{} -> {}", sb.stream_id, sb.backend_id))
        .collect();
    diff
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
    // Story 8.8 AC #4. The bool toggle is safe to surface in the reload
    // diff; the paired `prometheus_scrape_token` is a secret and is
    // deliberately never diffed (same policy as `bot_hmac_secret_hex`).
    if current.metrics_require_auth != incoming.metrics_require_auth {
        changes.push(SettingChange {
            key: "metrics_require_auth".to_string(),
            old_value: current.metrics_require_auth.to_string(),
            new_value: incoming.metrics_require_auth.to_string(),
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
    if current.ip_blocklist_enabled != incoming.ip_blocklist_enabled {
        changes.push(SettingChange {
            key: "ip_blocklist_enabled".to_string(),
            old_value: current.ip_blocklist_enabled.to_string(),
            new_value: incoming.ip_blocklist_enabled.to_string(),
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
    if current.flood_strict_rps != incoming.flood_strict_rps {
        changes.push(SettingChange {
            key: "flood_strict_rps".to_string(),
            old_value: current.flood_strict_rps.to_string(),
            new_value: incoming.flood_strict_rps.to_string(),
        });
    }
    if current.header_timeout_s != incoming.header_timeout_s {
        changes.push(SettingChange {
            key: "header_timeout_s".to_string(),
            old_value: current.header_timeout_s.to_string(),
            new_value: incoming.header_timeout_s.to_string(),
        });
    }
    if current.downstream_idle_timeout_s != incoming.downstream_idle_timeout_s {
        changes.push(SettingChange {
            key: "downstream_idle_timeout_s".to_string(),
            old_value: current.downstream_idle_timeout_s.to_string(),
            new_value: incoming.downstream_idle_timeout_s.to_string(),
        });
    }
    if current.worker_drain_timeout_s != incoming.worker_drain_timeout_s {
        changes.push(SettingChange {
            key: "worker_drain_timeout_s".to_string(),
            old_value: current.worker_drain_timeout_s.to_string(),
            new_value: incoming.worker_drain_timeout_s.to_string(),
        });
    }
    if current.stream_listen_socket_cap != incoming.stream_listen_socket_cap {
        changes.push(SettingChange {
            key: "stream_listen_socket_cap".to_string(),
            old_value: current.stream_listen_socket_cap.to_string(),
            new_value: incoming.stream_listen_socket_cap.to_string(),
        });
    }
    SettingsDiff { changes }
}

/// Whether an import would leave `a` as `b`; names as the store keeps
/// them, so a spelling it would store canonical is no change.
fn route_eq(a: &Route, b: &Route) -> bool {
    crate::route_selection::same_name(&a.hostname, &b.hostname)
        && a.path_prefix == b.path_prefix
        && a.certificate_id == b.certificate_id
        && a.load_balancing == b.load_balancing
        && a.waf_enabled == b.waf_enabled
        && a.waf_mode == b.waf_mode
        && a.enabled == b.enabled
        && a.redirect_to == b.redirect_to
        && a.path_rewrite_pattern == b.path_rewrite_pattern
        && a.path_rewrite_replacement == b.path_rewrite_replacement
        && a.path_rules.len() == b.path_rules.len()
        && a.return_status == b.return_status
        && a.group_name == b.group_name
        && a.node_selector == b.node_selector
        && a.managed_by == b.managed_by
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
        && a.managed_by == b.managed_by
}

/// Whether an import would leave `a` as `b`: every field but the
/// timestamps, which an export round trip carries and an edit moves.
fn stream_eq(a: &Stream, b: &Stream) -> bool {
    Stream {
        created_at: b.created_at,
        updated_at: b.updated_at,
        ..a.clone()
    } == *b
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

fn user_eq(a: &User, b: &User) -> bool {
    a.username == b.username
        && a.password_hash == b.password_hash
        && a.role == b.role
        && a.disabled_at.is_some() == b.disabled_at.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::export_to_toml;
    use crate::import::parse_toml_for_preview;
    use crate::models::{sample_stream, sample_stream_backend, sample_stream_id as sid};

    #[test]
    fn compute_diff_reports_a_changed_udp_setting() {
        let store = ConfigStore::open_in_memory().expect("test setup: store");
        store
            .create_stream(&sample_stream("s-dns", "dns", StreamProtocol::Udp, 53))
            .expect("test setup: stream");
        let toml_text = export_to_toml(&store).expect("export");
        let unchanged = parse_toml_for_preview(&toml_text).expect("preview");
        assert!(compute_diff(&store, &unchanged)
            .expect("diff")
            .streams
            .is_empty());
        let mut incoming = parse_toml_for_preview(&toml_text).expect("preview");
        incoming.streams[0]
            .udp
            .as_mut()
            .expect("test setup: udp")
            .response_bytes_ratio = 4;
        let diff = compute_diff(&store, &incoming).expect("diff");
        assert_eq!(
            diff.streams.modified,
            vec![format!("dns ({})", sid("s-dns"))]
        );
    }

    #[test]
    fn compute_diff_reports_an_added_a_changed_and_a_removed_stream() {
        let store = ConfigStore::open_in_memory().expect("test setup: store");
        store
            .create_backend(&sample_stream_backend("b-1", "192.0.2.10:25"))
            .expect("test setup: backend");
        for (id, name, port) in [("s-kept", "smtp", 25), ("s-gone", "submission", 587)] {
            store
                .create_stream(&sample_stream(id, name, StreamProtocol::Tcp, port))
                .expect("test setup: stream");
        }
        store
            .set_stream_backends(&sid("s-kept"), &["b-1".to_string()])
            .expect("test setup: link");
        let unchanged = parse_toml_for_preview(&export_to_toml(&store).expect("export"))
            .expect("the export parses");
        assert!(
            compute_diff(&store, &unchanged).expect("diff").is_empty(),
            "an export diffs as no change against its own store"
        );

        let mut incoming = unchanged;
        incoming.streams.retain(|s| s.id != sid("s-gone"));
        let kept = incoming
            .streams
            .iter_mut()
            .find(|s| s.id == sid("s-kept"))
            .expect("test setup: the kept stream");
        kept.enabled = false;
        kept.updated_at = chrono::Utc::now();
        incoming
            .streams
            .push(sample_stream("s-new", "imap", StreamProtocol::Tcp, 143));
        incoming.stream_backends.clear();

        let diff = compute_diff(&store, &incoming).expect("diff");
        assert_eq!(diff.streams.added, vec![format!("imap ({})", sid("s-new"))]);
        assert_eq!(
            diff.streams.modified,
            vec![format!("smtp ({})", sid("s-kept"))]
        );
        assert_eq!(
            diff.streams.removed,
            vec![format!("submission ({})", sid("s-gone"))]
        );
        assert_eq!(
            diff.stream_backends.removed,
            vec![format!("{} -> b-1", sid("s-kept"))]
        );
        assert!(!diff.is_empty());
    }

    #[test]
    fn compute_diff_reports_the_stream_plane_settings() {
        let store = ConfigStore::open_in_memory().expect("test setup: store");
        let mut incoming = parse_toml_for_preview(&export_to_toml(&store).expect("export"))
            .expect("the export parses");
        assert!(compute_diff(&store, &incoming).expect("diff").is_empty());

        incoming.global_settings.worker_drain_timeout_s = 120;
        incoming.global_settings.stream_listen_socket_cap = 64;
        let diff = compute_diff(&store, &incoming).expect("diff");
        let changed: Vec<(&str, &str, &str)> = diff
            .global_settings
            .changes
            .iter()
            .map(|c| (c.key.as_str(), c.old_value.as_str(), c.new_value.as_str()))
            .collect();
        let drain_default = GlobalSettings::DEFAULT_WORKER_DRAIN_TIMEOUT_S.to_string();
        let cap_default = GlobalSettings::DEFAULT_STREAM_LISTEN_SOCKET_CAP.to_string();
        assert_eq!(
            changed,
            vec![
                ("worker_drain_timeout_s", drain_default.as_str(), "120"),
                ("stream_listen_socket_cap", cap_default.as_str(), "64"),
            ]
        );
    }

    #[test]
    fn compute_diff_reports_an_engine_setting_and_a_backup_flag() {
        let store = ConfigStore::open_in_memory().expect("test setup: store");
        for (id, address) in [("b-1", "192.0.2.10:25"), ("b-2", "192.0.2.20:25")] {
            store
                .create_backend(&sample_stream_backend(id, address))
                .expect("test setup: backend");
        }
        store
            .create_stream(&sample_stream("s-1", "smtp", StreamProtocol::Tcp, 25))
            .expect("test setup: stream");
        store
            .set_stream_backends(&sid("s-1"), &["b-1".to_string(), "b-2".to_string()])
            .expect("test setup: links");
        let mut incoming = parse_toml_for_preview(&export_to_toml(&store).expect("export"))
            .expect("the export parses");
        assert!(compute_diff(&store, &incoming).expect("diff").is_empty());

        incoming.streams[0].max_connections = 64;
        let b2 = incoming
            .stream_backends
            .iter_mut()
            .find(|sb| sb.backend_id == "b-2")
            .expect("test setup: the b-2 link");
        b2.backup = true;
        let diff = compute_diff(&store, &incoming).expect("diff");
        assert_eq!(
            diff.streams.modified,
            vec![format!("smtp ({})", sid("s-1"))]
        );
        assert_eq!(
            diff.stream_backends.modified,
            vec![format!("{} -> b-2", sid("s-1"))]
        );
        assert!(diff.stream_backends.added.is_empty());
        assert!(diff.stream_backends.removed.is_empty());
    }

    #[test]
    fn compute_diff_reports_a_link_whose_rule_changed() {
        let store = ConfigStore::open_in_memory().expect("test setup: store");
        for (id, address) in [("b-1", "192.0.2.10:443"), ("b-2", "192.0.2.20:443")] {
            store
                .create_backend(&sample_stream_backend(id, address))
                .expect("test setup: backend");
        }
        store
            .create_stream(&crate::models::sample_tls_stream("s-1", "tls", 443))
            .expect("test setup: stream");
        let rule_link = |backend: &str, rule: &str| StreamBackend {
            rule: Some(rule.to_string()),
            ..StreamBackend::primary(&sid("s-1"), backend)
        };
        store
            .set_stream_links(
                &sid("s-1"),
                &[rule_link("b-1", "web"), rule_link("b-2", "bare")],
            )
            .expect("test setup: links");
        let mut incoming = parse_toml_for_preview(&export_to_toml(&store).expect("export"))
            .expect("the export parses");
        assert!(compute_diff(&store, &incoming).expect("diff").is_empty());

        let b2 = incoming
            .stream_backends
            .iter_mut()
            .find(|sb| sb.backend_id == "b-2")
            .expect("test setup: the b-2 link");
        b2.rule = Some("web".to_string());
        let diff = compute_diff(&store, &incoming).expect("diff");
        assert!(diff.streams.is_empty());
        assert_eq!(
            diff.stream_backends.modified,
            vec![format!("{} -> b-2", sid("s-1"))]
        );
    }

    #[test]
    fn a_stream_differing_only_by_its_timestamps_is_unchanged() {
        let a = sample_stream("s-1", "smtp", StreamProtocol::Tcp, 25);
        let mut b = a.clone();
        b.updated_at = chrono::Utc::now();
        assert!(stream_eq(&a, &b));
        b.port_last = 26;
        assert!(!stream_eq(&a, &b));
    }
}
