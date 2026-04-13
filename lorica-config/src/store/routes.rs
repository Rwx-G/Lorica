//! Route CRUD methods on `ConfigStore`.

use rusqlite::{params, OptionalExtension};

use super::row_helpers::row_to_route;
use super::{serialize_field, serialize_optional_field, ConfigStore};
use crate::error::{ConfigError, Result};
use crate::models::*;

impl ConfigStore {
    /// Check that no other route uses any of the given hostnames (primary or alias).
    /// Returns an error naming the conflicting hostname and route if found.
    fn validate_hostname_uniqueness(
        &self,
        route_id: &str,
        hostname: &str,
        aliases: &[String],
    ) -> Result<()> {
        // Collect all hostnames to check
        let mut check: Vec<&str> = vec![hostname];
        for a in aliases {
            check.push(a.as_str());
        }

        // Check against all existing routes
        let mut stmt = self
            .conn
            .prepare("SELECT id, hostname, hostname_aliases FROM routes WHERE id != ?1")?;
        let rows = stmt.query_map(params![route_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;

        for row in rows {
            let (other_id, other_host, aliases_json) = row?;
            let other_aliases: Vec<String> =
                serde_json::from_str(&aliases_json).unwrap_or_default();

            for h in &check {
                if *h == other_host {
                    return Err(ConfigError::Validation(format!(
                        "hostname '{h}' already used by route {other_id}"
                    )));
                }
                if other_aliases.iter().any(|a| a == *h) {
                    return Err(ConfigError::Validation(format!(
                        "hostname '{h}' already used as alias on route {other_id}"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Insert a new route into the database.
    pub fn create_route(&self, route: &Route) -> Result<()> {
        self.validate_hostname_uniqueness(&route.id, &route.hostname, &route.hostname_aliases)?;

        let hostname_aliases_json = serialize_field("hostname_aliases", &route.hostname_aliases)?;
        let proxy_headers_json = serialize_field("proxy_headers", &route.proxy_headers)?;
        let response_headers_json = serialize_field("response_headers", &route.response_headers)?;
        let proxy_headers_remove_json =
            serialize_field("proxy_headers_remove", &route.proxy_headers_remove)?;
        let response_headers_remove_json =
            serialize_field("response_headers_remove", &route.response_headers_remove)?;
        let ip_allowlist_json = serialize_field("ip_allowlist", &route.ip_allowlist)?;
        let ip_denylist_json = serialize_field("ip_denylist", &route.ip_denylist)?;
        let cors_allowed_origins_json =
            serialize_field("cors_allowed_origins", &route.cors_allowed_origins)?;
        let cors_allowed_methods_json =
            serialize_field("cors_allowed_methods", &route.cors_allowed_methods)?;
        let path_rules_json = serialize_field("path_rules", &route.path_rules)?;
        let retry_on_methods_json = serialize_field("retry_on_methods", &route.retry_on_methods)?;
        let cache_vary_headers_json =
            serialize_field("cache_vary_headers", &route.cache_vary_headers)?;
        let header_rules_json = serialize_field("header_rules", &route.header_rules)?;
        let traffic_splits_json = serialize_field("traffic_splits", &route.traffic_splits)?;
        let forward_auth_json =
            serialize_optional_field("forward_auth", route.forward_auth.as_ref())?;
        let mirror_json = serialize_optional_field("mirror", route.mirror.as_ref())?;
        let response_rewrite_json =
            serialize_optional_field("response_rewrite", route.response_rewrite.as_ref())?;
        let mtls_json = serialize_optional_field("mtls", route.mtls.as_ref())?;
        let rate_limit_json = serialize_optional_field("rate_limit", route.rate_limit.as_ref())?;

        self.conn.execute(
            "INSERT INTO routes (id, hostname, path_prefix, certificate_id, load_balancing,
             waf_enabled, waf_mode, enabled,
             force_https, redirect_hostname, redirect_to, hostname_aliases,
             proxy_headers, response_headers, security_headers,
             connect_timeout_s, read_timeout_s, send_timeout_s,
             strip_path_prefix, add_path_prefix,
             path_rewrite_pattern, path_rewrite_replacement,
             access_log_enabled,
             proxy_headers_remove, response_headers_remove,
             max_request_body_bytes, websocket_enabled,
             rate_limit_rps, rate_limit_burst,
             ip_allowlist, ip_denylist,
             cors_allowed_origins, cors_allowed_methods, cors_max_age_s,
             compression_enabled, retry_attempts,
             cache_enabled, cache_ttl_s, cache_max_bytes,
             max_connections, slowloris_threshold_ms,
             auto_ban_threshold, auto_ban_duration_s,
             created_at, updated_at,
             path_rules, return_status, sticky_session,
             basic_auth_username, basic_auth_password_hash,
             stale_while_revalidate_s, stale_if_error_s,
             retry_on_methods,
             maintenance_mode, error_page_html,
             cache_vary_headers,
             header_rules,
             traffic_splits,
             forward_auth,
             mirror,
             response_rewrite,
             mtls,
             rate_limit)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                     ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21,
                     ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32,
                     ?33, ?34, ?35, ?36, ?37, ?38, ?39, ?40, ?41, ?42, ?43, ?44, ?45,
                     ?46, ?47, ?48, ?49, ?50, ?51, ?52, ?53, ?54, ?55, ?56, ?57, ?58, ?59, ?60, ?61, ?62, ?63)",
            params![
                route.id,
                route.hostname,
                route.path_prefix,
                route.certificate_id,
                route.load_balancing.as_str(),
                route.waf_enabled,
                route.waf_mode.as_str(),
                route.enabled,
                route.force_https,
                route.redirect_hostname,
                route.redirect_to,
                hostname_aliases_json,
                proxy_headers_json,
                response_headers_json,
                route.security_headers,
                route.connect_timeout_s,
                route.read_timeout_s,
                route.send_timeout_s,
                route.strip_path_prefix,
                route.add_path_prefix,
                route.path_rewrite_pattern,
                route.path_rewrite_replacement,
                route.access_log_enabled,
                proxy_headers_remove_json,
                response_headers_remove_json,
                route.max_request_body_bytes.map(|v| v as i64),
                route.websocket_enabled,
                route.rate_limit_rps.map(|v| v as i32),
                route.rate_limit_burst.map(|v| v as i32),
                ip_allowlist_json,
                ip_denylist_json,
                cors_allowed_origins_json,
                cors_allowed_methods_json,
                route.cors_max_age_s,
                route.compression_enabled,
                route.retry_attempts.map(|v| v as i32),
                route.cache_enabled,
                route.cache_ttl_s,
                route.cache_max_bytes,
                route.max_connections.map(|v| v as i32),
                route.slowloris_threshold_ms,
                route.auto_ban_threshold.map(|v| v as i32),
                route.auto_ban_duration_s,
                route.created_at.to_rfc3339(),
                route.updated_at.to_rfc3339(),
                path_rules_json,
                route.return_status.map(|v| v as i32),
                route.sticky_session,
                route.basic_auth_username,
                route.basic_auth_password_hash,
                route.stale_while_revalidate_s,
                route.stale_if_error_s,
                retry_on_methods_json,
                route.maintenance_mode,
                route.error_page_html,
                cache_vary_headers_json,
                header_rules_json,
                traffic_splits_json,
                forward_auth_json,
                mirror_json,
                response_rewrite_json,
                mtls_json,
                rate_limit_json,
            ],
        )?;
        Ok(())
    }

    /// Fetch a route by ID, or `None` if not found.
    pub fn get_route(&self, id: &str) -> Result<Option<Route>> {
        self.conn
            .query_row(
                "SELECT id, hostname, path_prefix, certificate_id, load_balancing,
                 waf_enabled, waf_mode, enabled,
                 force_https, redirect_hostname, redirect_to, hostname_aliases,
                 proxy_headers, response_headers, security_headers,
                 connect_timeout_s, read_timeout_s, send_timeout_s,
                 strip_path_prefix, add_path_prefix,
                 path_rewrite_pattern, path_rewrite_replacement,
                 access_log_enabled,
                 proxy_headers_remove, response_headers_remove,
                 max_request_body_bytes, websocket_enabled,
                 rate_limit_rps, rate_limit_burst,
                 ip_allowlist, ip_denylist,
                 cors_allowed_origins, cors_allowed_methods, cors_max_age_s,
                 compression_enabled, retry_attempts,
                 cache_enabled, cache_ttl_s, cache_max_bytes,
                 max_connections, slowloris_threshold_ms,
                 auto_ban_threshold, auto_ban_duration_s,
                 created_at, updated_at,
                 path_rules, return_status, sticky_session,
                 basic_auth_username, basic_auth_password_hash,
                 stale_while_revalidate_s, stale_if_error_s,
                 retry_on_methods,
                 maintenance_mode, error_page_html,
                 cache_vary_headers,
                 header_rules,
                 traffic_splits,
                 forward_auth,
                 mirror,
                 response_rewrite,
                 mtls
                 FROM routes WHERE id = ?1",
                params![id],
                |row| Ok(row_to_route(row)),
            )
            .optional()?
            .transpose()
    }

    /// List all routes, ordered by hostname and path prefix.
    pub fn list_routes(&self) -> Result<Vec<Route>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, hostname, path_prefix, certificate_id, load_balancing,
             waf_enabled, waf_mode, enabled,
             force_https, redirect_hostname, redirect_to, hostname_aliases,
             proxy_headers, response_headers, security_headers,
             connect_timeout_s, read_timeout_s, send_timeout_s,
             strip_path_prefix, add_path_prefix,
             path_rewrite_pattern, path_rewrite_replacement,
             access_log_enabled,
             proxy_headers_remove, response_headers_remove,
             max_request_body_bytes, websocket_enabled,
             rate_limit_rps, rate_limit_burst,
             ip_allowlist, ip_denylist,
             cors_allowed_origins, cors_allowed_methods, cors_max_age_s,
             compression_enabled, retry_attempts,
             cache_enabled, cache_ttl_s, cache_max_bytes,
             max_connections, slowloris_threshold_ms,
             auto_ban_threshold, auto_ban_duration_s,
             created_at, updated_at,
             path_rules, return_status, sticky_session,
             basic_auth_username, basic_auth_password_hash,
             stale_while_revalidate_s, stale_if_error_s,
             retry_on_methods,
             maintenance_mode, error_page_html,
             cache_vary_headers,
             header_rules,
             traffic_splits,
             forward_auth,
             mirror,
             response_rewrite,
             mtls,
             rate_limit
             FROM routes ORDER BY hostname, path_prefix",
        )?;
        let rows = stmt.query_map([], |row| Ok(row_to_route(row)))?;
        let mut routes = Vec::new();
        for r in rows {
            routes.push(r??);
        }
        Ok(routes)
    }

    /// Update an existing route. Returns `NotFound` if the ID does not exist.
    pub fn update_route(&self, route: &Route) -> Result<()> {
        self.validate_hostname_uniqueness(&route.id, &route.hostname, &route.hostname_aliases)?;

        let hostname_aliases_json = serialize_field("hostname_aliases", &route.hostname_aliases)?;
        let proxy_headers_json = serialize_field("proxy_headers", &route.proxy_headers)?;
        let response_headers_json = serialize_field("response_headers", &route.response_headers)?;
        let proxy_headers_remove_json =
            serialize_field("proxy_headers_remove", &route.proxy_headers_remove)?;
        let response_headers_remove_json =
            serialize_field("response_headers_remove", &route.response_headers_remove)?;
        let ip_allowlist_json = serialize_field("ip_allowlist", &route.ip_allowlist)?;
        let ip_denylist_json = serialize_field("ip_denylist", &route.ip_denylist)?;
        let cors_allowed_origins_json =
            serialize_field("cors_allowed_origins", &route.cors_allowed_origins)?;
        let cors_allowed_methods_json =
            serialize_field("cors_allowed_methods", &route.cors_allowed_methods)?;
        let path_rules_json = serialize_field("path_rules", &route.path_rules)?;
        let retry_on_methods_json = serialize_field("retry_on_methods", &route.retry_on_methods)?;
        let cache_vary_headers_json =
            serialize_field("cache_vary_headers", &route.cache_vary_headers)?;
        let header_rules_json = serialize_field("header_rules", &route.header_rules)?;
        let traffic_splits_json = serialize_field("traffic_splits", &route.traffic_splits)?;
        let forward_auth_json =
            serialize_optional_field("forward_auth", route.forward_auth.as_ref())?;
        let mirror_json = serialize_optional_field("mirror", route.mirror.as_ref())?;
        let response_rewrite_json =
            serialize_optional_field("response_rewrite", route.response_rewrite.as_ref())?;
        let mtls_json = serialize_optional_field("mtls", route.mtls.as_ref())?;
        let rate_limit_json = serialize_optional_field("rate_limit", route.rate_limit.as_ref())?;

        let changed = self.conn.execute(
            "UPDATE routes SET hostname=?2, path_prefix=?3, certificate_id=?4,
             load_balancing=?5, waf_enabled=?6, waf_mode=?7,
             enabled=?8, force_https=?9, redirect_hostname=?10, redirect_to=?11,
             hostname_aliases=?12, proxy_headers=?13, response_headers=?14,
             security_headers=?15, connect_timeout_s=?16, read_timeout_s=?17,
             send_timeout_s=?18, strip_path_prefix=?19, add_path_prefix=?20,
             path_rewrite_pattern=?21, path_rewrite_replacement=?22,
             access_log_enabled=?23, proxy_headers_remove=?24,
             response_headers_remove=?25, max_request_body_bytes=?26,
             websocket_enabled=?27, rate_limit_rps=?28, rate_limit_burst=?29,
             ip_allowlist=?30, ip_denylist=?31,
             cors_allowed_origins=?32, cors_allowed_methods=?33, cors_max_age_s=?34,
             compression_enabled=?35, retry_attempts=?36,
             cache_enabled=?37, cache_ttl_s=?38, cache_max_bytes=?39,
             max_connections=?40, slowloris_threshold_ms=?41,
             auto_ban_threshold=?42, auto_ban_duration_s=?43,
             updated_at=?44,
             path_rules=?45, return_status=?46, sticky_session=?47,
             basic_auth_username=?48, basic_auth_password_hash=?49,
             stale_while_revalidate_s=?50, stale_if_error_s=?51,
             retry_on_methods=?52,
             maintenance_mode=?53, error_page_html=?54,
             cache_vary_headers=?55,
             header_rules=?56,
             traffic_splits=?57,
             forward_auth=?58,
             mirror=?59,
             response_rewrite=?60,
             mtls=?61,
             rate_limit=?62 WHERE id=?1",
            params![
                route.id,
                route.hostname,
                route.path_prefix,
                route.certificate_id,
                route.load_balancing.as_str(),
                route.waf_enabled,
                route.waf_mode.as_str(),
                route.enabled,
                route.force_https,
                route.redirect_hostname,
                route.redirect_to,
                hostname_aliases_json,
                proxy_headers_json,
                response_headers_json,
                route.security_headers,
                route.connect_timeout_s,
                route.read_timeout_s,
                route.send_timeout_s,
                route.strip_path_prefix,
                route.add_path_prefix,
                route.path_rewrite_pattern,
                route.path_rewrite_replacement,
                route.access_log_enabled,
                proxy_headers_remove_json,
                response_headers_remove_json,
                route.max_request_body_bytes.map(|v| v as i64),
                route.websocket_enabled,
                route.rate_limit_rps.map(|v| v as i32),
                route.rate_limit_burst.map(|v| v as i32),
                ip_allowlist_json,
                ip_denylist_json,
                cors_allowed_origins_json,
                cors_allowed_methods_json,
                route.cors_max_age_s,
                route.compression_enabled,
                route.retry_attempts.map(|v| v as i32),
                route.cache_enabled,
                route.cache_ttl_s,
                route.cache_max_bytes,
                route.max_connections.map(|v| v as i32),
                route.slowloris_threshold_ms,
                route.auto_ban_threshold.map(|v| v as i32),
                route.auto_ban_duration_s,
                route.updated_at.to_rfc3339(),
                path_rules_json,
                route.return_status.map(|v| v as i32),
                route.sticky_session,
                route.basic_auth_username,
                route.basic_auth_password_hash,
                route.stale_while_revalidate_s,
                route.stale_if_error_s,
                retry_on_methods_json,
                route.maintenance_mode,
                route.error_page_html,
                cache_vary_headers_json,
                header_rules_json,
                traffic_splits_json,
                forward_auth_json,
                mirror_json,
                response_rewrite_json,
                mtls_json,
                rate_limit_json,
            ],
        )?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("route {}", route.id)));
        }
        Ok(())
    }

    /// Delete a route by ID. Returns `NotFound` if the ID does not exist.
    pub fn delete_route(&self, id: &str) -> Result<()> {
        let changed = self
            .conn
            .execute("DELETE FROM routes WHERE id=?1", params![id])?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("route {id}")));
        }
        Ok(())
    }
}
