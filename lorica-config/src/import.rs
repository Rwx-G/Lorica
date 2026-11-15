use std::collections::HashSet;
use std::path::Path;

use serde::Deserialize;

use crate::error::{ConfigError, Result};
use crate::models::*;
use crate::route_selection::{
    canonical_hostname, validate_hostname_syntax, ROUTE_ALIAS_SHAPE, ROUTE_HOSTNAME_SHAPE,
    ROUTE_REDIRECT_HOSTNAME_SHAPE,
};
use crate::store::ConfigStore;

/// Deserialized counterpart of [`crate::export::ExportData`]. Each
/// collection defaults to empty on missing keys so partial imports
/// remain valid.
#[derive(Debug, Deserialize)]
pub struct ImportData {
    /// Export schema version (must be >= 1 ; 0 is rejected).
    pub version: u32,
    /// Snapshot of `GlobalSettings`.
    pub global_settings: GlobalSettings,
    /// All rows of the `routes` table.
    #[serde(default)]
    pub routes: Vec<Route>,
    /// All rows of the `backends` table.
    #[serde(default)]
    pub backends: Vec<Backend>,
    /// All rows of the `route_backends` join table.
    #[serde(default)]
    pub route_backends: Vec<RouteBackend>,
    /// All rows of the `streams` table (Story 12.1). Absent from every
    /// export older than 1.11.0, which therefore still imports.
    #[serde(default)]
    pub streams: Vec<Stream>,
    /// All rows of the `stream_backends` join table.
    #[serde(default)]
    pub stream_backends: Vec<StreamBackend>,
    /// All rows of the `certificates` table.
    #[serde(default)]
    pub certificates: Vec<Certificate>,
    /// All rows of the `notification_configs` table.
    #[serde(default)]
    pub notification_configs: Vec<NotificationConfig>,
    /// All rows of the `user_preferences` table.
    #[serde(default)]
    pub user_preferences: Vec<UserPreference>,
    /// All rows of the `users` table (password hashes are redacted
    /// to `**REDACTED**` on export ; import rejects those). The
    /// `admin_users` alias accepts pre-1.6.0 exports; those rows
    /// deserialize with `role = super_admin` via the model defaults.
    #[serde(default, alias = "admin_users")]
    pub users: Vec<User>,
}

/// Parse a TOML string into import data.
pub fn parse_toml(content: &str) -> Result<ImportData> {
    let data = decode(content)?;
    validate(&data)?;
    Ok(data)
}

/// Parse TOML for preview/diff only - skips redaction validation.
pub fn parse_toml_for_preview(content: &str) -> Result<ImportData> {
    let data = decode(content)?;
    validate_structure(&data)?;
    Ok(data)
}

/// Decode a TOML export, giving every UDP stream the protocol-dependent
/// defaults a serde default cannot know (Story 12.5 Interface edit E1):
/// the UDP `idle_timeout_s` when the key is absent, which only the
/// document still shows, and the UDP settings when absent.
fn decode(content: &str) -> Result<ImportData> {
    let parse_failed =
        |e: toml::de::Error| ConfigError::Serialization(format!("TOML parse failed: {e}"));
    let mut document: toml::Value = toml::from_str(content).map_err(parse_failed)?;
    let udp = StreamProtocol::Udp;
    if let Some(streams) = document
        .get_mut("streams")
        .and_then(toml::Value::as_array_mut)
    {
        for stream in streams.iter_mut().filter_map(toml::Value::as_table_mut) {
            let is_udp = stream.get("protocol").and_then(toml::Value::as_str) == Some(udp.as_str());
            if is_udp && !stream.contains_key("idle_timeout_s") {
                stream.insert(
                    "idle_timeout_s".to_string(),
                    toml::Value::Integer(i64::from(Stream::default_idle_timeout_s(udp))),
                );
            }
        }
    }
    let mut data: ImportData = document.try_into().map_err(parse_failed)?;
    for stream in &mut data.streams {
        stream.fill_protocol_defaults();
    }
    Ok(data)
}

/// Validate structural consistency (used by both import and preview).
fn validate_structure(data: &ImportData) -> Result<()> {
    if data.version == 0 {
        return Err(ConfigError::Validation(
            "export version must be >= 1".into(),
        ));
    }

    // Validate route-backend references
    for rb in &data.route_backends {
        if !data.routes.iter().any(|r| r.id == rb.route_id) {
            return Err(ConfigError::Validation(format!(
                "route_backend references unknown route_id: {}",
                rb.route_id
            )));
        }
        if !data.backends.iter().any(|b| b.id == rb.backend_id) {
            return Err(ConfigError::Validation(format!(
                "route_backend references unknown backend_id: {}",
                rb.backend_id
            )));
        }
    }

    // Every primary hostname, alias and redirect host as a route write
    // sets it; the store makes the names canonical on the way in.
    for route in &data.routes {
        let refused =
            |reason: String| ConfigError::Validation(format!("route '{}': {reason}", route.id));
        validate_hostname_syntax(
            &canonical_hostname(route.hostname.trim()),
            ROUTE_HOSTNAME_SHAPE,
        )
        .map_err(refused)?;
        for alias in &route.hostname_aliases {
            validate_hostname_syntax(&canonical_hostname(alias.trim()), ROUTE_ALIAS_SHAPE)
                .map_err(refused)?;
        }
        if let Some(target) = &route.redirect_hostname {
            validate_hostname_syntax(target, ROUTE_REDIRECT_HOSTNAME_SHAPE).map_err(refused)?;
        }
    }

    validate_streams(data)
}

/// The stream half of [`validate_structure`] (Story 12.1, D-6 and D-9):
/// each stream's own rules, unique names, links naming an imported
/// stream and backend, and the attachment rule once on the whole file.
///
/// Checked here, before `clear_all`, because [`import_to_store`] writes
/// through the store's unchecked writers: a consistent file written row
/// by row can pass through a transient violation the checked writers
/// would refuse, and a refusal half way through an import would leave
/// the store cleared.
fn validate_streams(data: &ImportData) -> Result<()> {
    let mut names: HashSet<&str> = HashSet::new();
    for stream in &data.streams {
        stream.validate().map_err(|reason| {
            ConfigError::Validation(format!("stream '{}': {reason}", stream.id))
        })?;
        if !names.insert(stream.name.as_str()) {
            return Err(ConfigError::Validation(format!(
                "stream '{}': the name `{}` is used by another stream of the file",
                stream.id, stream.name
            )));
        }
    }
    let mut pairs: HashSet<(&str, &str)> = HashSet::new();
    for link in &data.stream_backends {
        // The store keeps the first row of a pair, so a pair listed
        // twice, once as a backup, would be checked as one thing and
        // stored as the other.
        if !pairs.insert((link.stream_id.as_str(), link.backend_id.as_str())) {
            return Err(ConfigError::Validation(format!(
                "stream_backend {} -> {} is listed twice",
                link.stream_id, link.backend_id
            )));
        }
        if !data.streams.iter().any(|s| s.id == link.stream_id) {
            return Err(ConfigError::Validation(format!(
                "stream_backend references unknown stream_id: {}",
                link.stream_id
            )));
        }
        if !data.backends.iter().any(|b| b.id == link.backend_id) {
            return Err(ConfigError::Validation(format!(
                "stream_backend references unknown backend_id: {}",
                link.backend_id
            )));
        }
    }
    check_backend_attachments(&AttachmentSnapshot {
        backends: &data.backends,
        streams: &data.streams,
        stream_backends: &data.stream_backends,
        route_backends: &data.route_backends,
    })
    .map_err(|conflict| ConfigError::Validation(conflict.to_string()))
}

/// Validate import data for consistency (rejects redacted data).
fn validate(data: &ImportData) -> Result<()> {
    validate_structure(data)?;

    // Reject redacted password hashes (from exports)
    for user in &data.users {
        if user.password_hash == "**REDACTED**" {
            return Err(ConfigError::Validation(format!(
                "user '{}' has a redacted password hash (from export); \
                 set a real password hash or remove the user from the import file",
                user.username
            )));
        }
    }

    // Reject redacted secrets in notification configs (v1.5.1
    // audit L-5 widened the check from Email-only to every
    // channel : Webhook + Slack now scrub `url` + `auth_header`
    // on export, and a round-tripped import must fail loudly so
    // an old TOML cannot silently swap a live webhook URL for the
    // placeholder, breaking alert delivery without trace).
    for nc in &data.notification_configs {
        if nc.config.contains("**REDACTED**") {
            let kind = match nc.channel {
                NotificationChannel::Email => "SMTP password",
                NotificationChannel::Webhook => "webhook URL or auth header",
                NotificationChannel::Slack => "Slack webhook URL or auth header",
            };
            return Err(ConfigError::Validation(format!(
                "notification config '{}' has a redacted {kind} (from export); \
                 set the real value or remove the config from the import file",
                nc.id
            )));
        }
    }

    // Reject redacted certificate private keys
    for cert in &data.certificates {
        if cert.key_pem == "**REDACTED**" {
            return Err(ConfigError::Validation(format!(
                "certificate '{}' has a redacted private key (from export); \
                 provide the real key or remove the certificate from the import file",
                cert.id
            )));
        }
    }

    // Reject redacted bot-protection HMAC secret (v1.5.1 audit H-1).
    // Forces the operator to either provide the real hex secret or
    // clear the field (which triggers regeneration on next reload),
    // so an old export cannot silently rotate a live secret on
    // re-import.
    if data.global_settings.bot_hmac_secret_hex == "**REDACTED**" {
        return Err(ConfigError::Validation(
            "global_settings.bot_hmac_secret_hex is redacted (from export); \
             set the real hex secret or clear the field (it regenerates on next reload)"
                .into(),
        ));
    }

    // Reject redacted log-sink secrets (Story 9.8 AC #8): same
    // rationale as the bot HMAC secret above.
    if data.global_settings.syslog_tls_client_key_pem.as_deref() == Some("**REDACTED**") {
        return Err(ConfigError::Validation(
            "global_settings.syslog_tls_client_key_pem is redacted (from export); \
             set the real PEM key or clear the field"
                .into(),
        ));
    }
    if data.global_settings.otlp_logs_auth_header.as_deref() == Some("**REDACTED**") {
        return Err(ConfigError::Validation(
            "global_settings.otlp_logs_auth_header is redacted (from export); \
             set the real header value or clear the field"
                .into(),
        ));
    }
    if data.global_settings.prometheus_scrape_token.as_deref() == Some("**REDACTED**") {
        return Err(ConfigError::Validation(
            "global_settings.prometheus_scrape_token is redacted (from export); \
             set the real token or clear the field"
                .into(),
        ));
    }

    // Refuse a malformed address entry before it reaches the store.
    // The management API has always refused one; an import wrote
    // `global_settings` verbatim, so a typo in `connection_allow_cidrs`
    // parsed to an EMPTY allow list at reload, which the connection
    // filter reads as default-allow: the TCP allowlist silently stopped
    // filtering, with one WARN as the only trace (backlog #88).
    data.global_settings
        .validate_cidr_lists()
        .map_err(|reason| ConfigError::Validation(format!("global_settings: {reason}")))?;
    // Story 12.8: the PROXY protocol trust list and the listener modes
    // are refused here on the same terms as at the management API.
    data.global_settings
        .validate_proxy_protocol()
        .map_err(|reason| ConfigError::Validation(format!("global_settings: {reason}")))?;

    // Validate certificate references in routes
    for route in &data.routes {
        if let Some(cert_id) = &route.certificate_id {
            if !data.certificates.iter().any(|c| c.id == *cert_id) {
                return Err(ConfigError::Validation(format!(
                    "route '{}' references unknown certificate_id: {}",
                    route.id, cert_id
                )));
            }
        }
    }

    Ok(())
}

/// Import data into the store, replacing all existing data.
///
/// Returns the warnings the operator should see: the import succeeded,
/// but something in it was not taken as written.
///
/// The AD CS authority is not part of the export (Epic 13 PRD D14) and
/// survives the import. A certificate naming an authority this node
/// does not hold is imported as a manual certificate, with its
/// `adcs_authority_id` cleared and a warning: kept as written, it would
/// be an AD CS certificate whose renewals no authority can serve.
///
/// Backends, links and streams are written through the store's
/// unchecked writers (Story 12.1, D-6): the attachment rule is checked
/// once on the whole file. [`parse_toml`] already checked it; it is
/// checked again here, before `clear_all`, so a caller holding an
/// [`ImportData`] built any other way cannot skip it.
pub fn import_to_store(store: &ConfigStore, data: &ImportData) -> Result<Vec<String>> {
    validate_streams(data)?;
    let local_authority_id = store.get_adcs_authority()?.map(|authority| authority.id);
    let mut warnings = Vec::new();

    store.clear_all()?;

    store.update_global_settings(&data.global_settings)?;

    for cert in &data.certificates {
        match cert.adcs_authority_id.as_deref() {
            Some(authority_id) if Some(authority_id) != local_authority_id.as_deref() => {
                let warning = format!(
                    "certificate {} ({}) references AD CS authority {authority_id}, which this \
                     node does not hold; imported as a manual certificate",
                    cert.id, cert.domain
                );
                tracing::warn!("{warning}");
                warnings.push(warning);
                let mut manual = cert.clone();
                manual.adcs_authority_id = None;
                store.create_certificate(&manual)?;
            }
            _ => store.create_certificate(cert)?,
        }
    }
    for backend in &data.backends {
        store.create_backend_unchecked(backend)?;
    }
    for route in &data.routes {
        store.create_route(route)?;
    }
    for rb in &data.route_backends {
        store.link_route_backend_unchecked(&rb.route_id, &rb.backend_id)?;
    }
    for stream in &data.streams {
        store.create_stream_unchecked(stream)?;
    }
    for link in &data.stream_backends {
        store.link_stream_backend_unchecked(link)?;
    }
    for nc in &data.notification_configs {
        store.create_notification_config(nc)?;
    }
    for pref in &data.user_preferences {
        store.create_user_preference(pref)?;
    }
    for user in &data.users {
        store.create_user(user)?;
    }

    Ok(warnings)
}

/// Import from a TOML file into the store. Returns the warnings of
/// [`import_to_store`].
pub fn import_from_file(store: &ConfigStore, path: &Path) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path)?;
    let data = parse_toml(&content)?;
    import_to_store(store, &data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::export_to_toml;
    use crate::models::{sample_stream, sample_stream_backend, sample_stream_id as sid};

    /// A store holding a TCP single-port stream and a disabled UDP range
    /// stream pinned to `edge-1`, each with its own backend.
    fn store_with_streams() -> ConfigStore {
        let store = ConfigStore::open_in_memory().expect("test setup: store");
        store
            .create_backend(&sample_stream_backend("b-smtp", "192.0.2.10:25"))
            .expect("test setup: backend");
        store
            .create_backend(&sample_stream_backend("b-game", "game.example.com"))
            .expect("test setup: portless backend");
        store
            .create_stream(&sample_stream("s-smtp", "smtp", StreamProtocol::Tcp, 25))
            .expect("test setup: stream");
        let mut game = sample_stream("s-game", "game", StreamProtocol::Udp, 27000);
        game.port_last = 27015;
        game.enabled = false;
        game.listen_address = "2001:db8::10".parse().expect("test setup: address");
        game.node_selector = vec!["edge-1".to_string()];
        store.create_stream(&game).expect("test setup: stream");
        store
            .set_stream_backends(&sid("s-smtp"), &["b-smtp".to_string()])
            .expect("test setup: link");
        store
            .set_stream_backends(&sid("s-game"), &["b-game".to_string()])
            .expect("test setup: link");
        store
    }

    /// The store's export, decoded as a TOML value to edit.
    fn exported(store: &ConfigStore) -> toml::Value {
        toml::from_str(&export_to_toml(store).expect("export")).expect("the export is TOML")
    }

    #[test]
    fn streams_round_trip_through_export_and_import() {
        let source = store_with_streams();
        let toml_text = export_to_toml(&source).expect("export");
        assert!(toml_text.contains("[[streams]]"), "{toml_text}");
        assert!(toml_text.contains("[[stream_backends]]"), "{toml_text}");

        let target = ConfigStore::open_in_memory().expect("target");
        let data = parse_toml(&toml_text).expect("the export parses");
        import_to_store(&target, &data).expect("the export imports");

        assert_eq!(
            target.list_streams().expect("streams"),
            source.list_streams().expect("streams")
        );
        assert_eq!(
            target.list_stream_backends().expect("links"),
            source.list_stream_backends().expect("links")
        );
    }

    #[test]
    fn an_export_without_streams_still_imports() {
        let mut value = exported(&store_with_streams());
        let table = value.as_table_mut().expect("the export is a table");
        assert!(table.remove("streams").is_some(), "test setup: on the file");
        assert!(table.remove("stream_backends").is_some());
        let older = toml::to_string(&value).expect("re-encode");

        let target = ConfigStore::open_in_memory().expect("target");
        let data = parse_toml(&older).expect("a pre-1.11.0 export parses");
        assert!(data.streams.is_empty());
        import_to_store(&target, &data).expect("and imports");
        assert!(target.list_streams().expect("streams").is_empty());
        assert_eq!(target.list_backends().expect("backends").len(), 2);
    }

    #[test]
    fn a_stream_export_from_before_the_engine_settings_imports_with_defaults() {
        let source = store_with_streams();
        let mut value = exported(&source);
        for stream in value
            .get_mut("streams")
            .and_then(toml::Value::as_array_mut)
            .expect("test setup: streams")
        {
            let table = stream.as_table_mut().expect("test setup: a stream table");
            for field in crate::models::TCP_ENGINE_FIELDS {
                // `None` settings are absent from TOML already.
                table.remove(field.name);
            }
        }
        for link in value
            .get_mut("stream_backends")
            .and_then(toml::Value::as_array_mut)
            .expect("test setup: links")
        {
            let table = link.as_table_mut().expect("test setup: a link table");
            assert!(table.remove("backup").is_some(), "backup in the export");
        }
        let older = toml::to_string(&value).expect("re-encode");

        let target = ConfigStore::open_in_memory().expect("target");
        let data = parse_toml(&older).expect("a 12.1-shaped export parses");
        import_to_store(&target, &data).expect("and imports");
        assert_eq!(
            target.list_streams().expect("streams"),
            source.list_streams().expect("streams")
        );
        assert_eq!(
            target.list_stream_backends().expect("links"),
            source.list_stream_backends().expect("links")
        );
    }

    /// A UDP stream on a private address with its settings at their
    /// defaults, exported, then stripped of `udp` and `idle_timeout_s`
    /// as a file written before Story 12.5 would be: it imports with the
    /// UDP defaults, the UDP idle timeout included.
    #[test]
    fn a_udp_stream_without_its_udp_keys_imports_with_the_udp_defaults() {
        let source = ConfigStore::open_in_memory().expect("test setup: store");
        let mut dns = sample_stream("s-dns", "dns", StreamProtocol::Udp, 53);
        dns.listen_address = "10.0.0.53".parse().expect("test setup: address");
        dns.udp = Stream::default_udp_settings(StreamProtocol::Udp);
        source.create_stream(&dns).expect("test setup: stream");
        let mut value = exported(&source);
        let table = value
            .get_mut("streams")
            .and_then(toml::Value::as_array_mut)
            .and_then(|streams| streams[0].as_table_mut())
            .expect("test setup: the stream table");
        assert!(table.remove("udp").is_some(), "udp in the export");
        assert!(
            table.remove("idle_timeout_s").is_some(),
            "idle in the export"
        );
        let older = toml::to_string(&value).expect("re-encode");

        let data = parse_toml(&older).expect("parses");
        assert_eq!(data.streams, vec![dns.clone()]);
        assert_eq!(data.streams[0].idle_timeout_s, 10);
        let target = ConfigStore::open_in_memory().expect("target");
        import_to_store(&target, &data).expect("imports");
        assert_eq!(target.list_streams().expect("streams"), vec![dns]);
    }

    #[test]
    fn udp_settings_round_trip_through_export_and_import() {
        let source = store_with_streams();
        let mut game = source
            .get_stream(&sid("s-game"))
            .expect("test setup: read")
            .expect("test setup: stream");
        let udp = game.udp.as_mut().expect("test setup: udp");
        udp.max_sessions = 100;
        udp.source_session_cap = Some(8);
        udp.requests_per_session = None;
        udp.responses_per_request = 0;
        udp.unbounded_responses = true;
        game.idle_timeout_s = 120;
        source.update_stream(&game).expect("test setup: settings");
        let target = ConfigStore::open_in_memory().expect("target");
        let data = parse_toml(&export_to_toml(&source).expect("export")).expect("parses");
        import_to_store(&target, &data).expect("imports");
        assert_eq!(target.get_stream(&sid("s-game")).expect("read"), Some(game));
    }

    #[test]
    fn engine_settings_and_backups_round_trip_through_export_and_import() {
        let source = store_with_streams();
        source
            .create_backend(&sample_stream_backend("b-smtp-2", "192.0.2.11:25"))
            .expect("test setup: backend");
        let mut smtp = source
            .get_stream(&sid("s-smtp"))
            .expect("test setup: read")
            .expect("test setup: stream");
        smtp = crate::models::sample_stream_off_default(smtp);
        source.update_stream(&smtp).expect("test setup: settings");
        source
            .set_stream_backend_links(
                &sid("s-smtp"),
                &["b-smtp".to_string()],
                &["b-smtp-2".to_string()],
            )
            .expect("test setup: a backup");

        let target = ConfigStore::open_in_memory().expect("target");
        let data = parse_toml(&export_to_toml(&source).expect("export")).expect("parses");
        import_to_store(&target, &data).expect("imports");
        assert_eq!(target.get_stream(&sid("s-smtp")).expect("read"), Some(smtp));
        assert_eq!(
            target.list_stream_backends().expect("links"),
            source.list_stream_backends().expect("links")
        );
    }

    #[test]
    fn a_stream_link_listed_twice_is_refused() {
        let edited = with_link(&store_with_streams(), &sid("s-smtp"), "b-smtp");
        let err = parse_toml(&edited).expect_err("a duplicate pair");
        assert!(err.to_string().contains("twice"), "{err}");
    }

    /// The export with one more stream link, from `stream_id` to
    /// `backend_id`.
    fn with_link(store: &ConfigStore, stream_id: &str, backend_id: &str) -> String {
        let mut value = exported(store);
        let links = value
            .get_mut("stream_backends")
            .and_then(toml::Value::as_array_mut)
            .expect("test setup: links");
        let mut link = toml::map::Map::new();
        link.insert("stream_id".into(), toml::Value::String(stream_id.into()));
        link.insert("backend_id".into(), toml::Value::String(backend_id.into()));
        links.push(toml::Value::Table(link));
        toml::to_string(&value).expect("re-encode")
    }

    #[test]
    fn a_file_sharing_a_udp_backend_is_refused_before_the_store_is_cleared() {
        // The UDP stream's backend, also on the TCP stream of the file.
        let edited = with_link(&store_with_streams(), &sid("s-smtp"), "b-game");

        let err = parse_toml(&edited).expect_err("refused at parse");
        assert!(err.to_string().contains("`game`"), "{err}");

        // A caller that skips the parser is refused the same way, and
        // nothing was cleared.
        let target = store_with_streams();
        let data: ImportData = toml::from_str(&edited).expect("test setup: raw decode");
        let err = import_to_store(&target, &data).expect_err("refused before clear_all");
        assert!(err.to_string().contains("`game`"), "{err}");
        assert_eq!(target.list_streams().expect("streams").len(), 2);
    }

    #[test]
    fn a_stream_link_naming_nothing_in_the_file_is_refused() {
        let store = store_with_streams();
        let err = parse_toml(&with_link(&store, "s-ghost", "b-smtp")).expect_err("unknown stream");
        assert!(err.to_string().contains("s-ghost"), "{err}");
        let err =
            parse_toml(&with_link(&store, &sid("s-smtp"), "b-ghost")).expect_err("unknown backend");
        assert!(err.to_string().contains("b-ghost"), "{err}");
    }

    #[test]
    fn a_file_breaking_a_streams_own_rules_is_refused() {
        let toml_text = export_to_toml(&store_with_streams()).expect("export");
        let renamed = toml_text.replace("name = \"game\"", "name = \"smtp\"");
        assert_ne!(renamed, toml_text, "test setup: the name is on the file");
        let err = parse_toml(&renamed).expect_err("two streams named smtp");
        assert!(err.to_string().contains("`smtp`"), "{err}");

        let widened = toml_text.replace("port_last = 27015", "port_last = 29000");
        assert_ne!(widened, toml_text, "test setup: the range is on the file");
        let err = parse_toml(&widened).expect_err("a range above the cap");
        assert!(err.to_string().contains(&sid("s-game")), "{err}");
    }

    #[test]
    fn a_file_carrying_a_non_canonical_stream_id_is_refused() {
        let toml_text = export_to_toml(&store_with_streams()).expect("export");
        let upper = sid("s-game").to_uppercase();
        let respelled = toml_text.replace(&sid("s-game"), &upper);
        assert_ne!(respelled, toml_text, "test setup: the id is on the file");
        let err = parse_toml(&respelled).expect_err("not the minted form");
        assert!(err.to_string().contains("stream id"), "{err}");
    }
}
