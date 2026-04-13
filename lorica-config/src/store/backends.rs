//! Backend CRUD and route-backend link operations on `ConfigStore`.

use rusqlite::{params, OptionalExtension};

use super::row_helpers::row_to_backend;
use super::ConfigStore;
use crate::error::{ConfigError, Result};
use crate::models::*;

impl ConfigStore {
    /// Validate that a backend address contains a port (ip:port format).
    fn validate_backend_address(address: &str) -> Result<()> {
        if !address.contains(':') || address.ends_with(':') {
            return Err(ConfigError::Validation(format!(
                "backend address must be in ip:port format (got '{address}')"
            )));
        }
        let port_str = address.rsplit(':').next().unwrap_or("");
        if port_str.parse::<u16>().is_err() {
            return Err(ConfigError::Validation(format!(
                "backend address has invalid port (got '{address}')"
            )));
        }
        Ok(())
    }

    /// Insert a new backend into the database.
    pub fn create_backend(&self, backend: &Backend) -> Result<()> {
        Self::validate_backend_address(&backend.address)?;
        self.conn.execute(
            "INSERT INTO backends (id, address, name, group_name, weight, health_status,
             health_check_enabled, health_check_interval_s, health_check_path,
             lifecycle_state, active_connections, tls_upstream, h2_upstream, created_at, updated_at, tls_sni, tls_skip_verify)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            params![
                backend.id,
                backend.address,
                backend.name,
                backend.group_name,
                backend.weight,
                backend.health_status.as_str(),
                backend.health_check_enabled,
                backend.health_check_interval_s,
                backend.health_check_path,
                backend.lifecycle_state.as_str(),
                backend.active_connections,
                backend.tls_upstream,
                backend.h2_upstream,
                backend.created_at.to_rfc3339(),
                backend.updated_at.to_rfc3339(),
                backend.tls_sni.as_deref().unwrap_or(""),
                backend.tls_skip_verify,
            ],
        )?;
        Ok(())
    }

    /// Fetch a backend by ID, or `None` if not found.
    pub fn get_backend(&self, id: &str) -> Result<Option<Backend>> {
        self.conn
            .query_row(
                "SELECT id, address, name, group_name, weight, health_status,
                 health_check_enabled, health_check_interval_s, health_check_path,
                 lifecycle_state, active_connections, tls_upstream, created_at, updated_at, h2_upstream, tls_sni, tls_skip_verify
                 FROM backends WHERE id = ?1",
                params![id],
                |row| Ok(row_to_backend(row)),
            )
            .optional()?
            .transpose()
    }

    /// List all backends, ordered by address.
    pub fn list_backends(&self) -> Result<Vec<Backend>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, address, name, group_name, weight, health_status,
             health_check_enabled, health_check_interval_s, health_check_path,
             lifecycle_state, active_connections, tls_upstream, created_at, updated_at, h2_upstream, tls_sni, tls_skip_verify
             FROM backends ORDER BY address",
        )?;
        let rows = stmt.query_map([], |row| Ok(row_to_backend(row)))?;
        let mut backends = Vec::new();
        for r in rows {
            backends.push(r??);
        }
        Ok(backends)
    }

    /// Update an existing backend. Returns `NotFound` if the ID does not exist.
    pub fn update_backend(&self, backend: &Backend) -> Result<()> {
        Self::validate_backend_address(&backend.address)?;
        let changed = self.conn.execute(
            "UPDATE backends SET address=?2, name=?3, group_name=?4, weight=?5,
             health_status=?6, health_check_enabled=?7, health_check_interval_s=?8,
             health_check_path=?9, lifecycle_state=?10, active_connections=?11,
             tls_upstream=?12, h2_upstream=?13, updated_at=?14, tls_sni=?15, tls_skip_verify=?16 WHERE id=?1",
            params![
                backend.id,
                backend.address,
                backend.name,
                backend.group_name,
                backend.weight,
                backend.health_status.as_str(),
                backend.health_check_enabled,
                backend.health_check_interval_s,
                backend.health_check_path,
                backend.lifecycle_state.as_str(),
                backend.active_connections,
                backend.tls_upstream,
                backend.h2_upstream,
                backend.updated_at.to_rfc3339(),
                backend.tls_sni.as_deref().unwrap_or(""),
                backend.tls_skip_verify,
            ],
        )?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("backend {}", backend.id)));
        }
        Ok(())
    }

    /// Delete a backend by ID. Returns `NotFound` if the ID does not exist.
    pub fn delete_backend(&self, id: &str) -> Result<()> {
        let changed = self
            .conn
            .execute("DELETE FROM backends WHERE id=?1", params![id])?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("backend {id}")));
        }
        Ok(())
    }

    // ---- Route-Backend associations ----

    /// Associate a backend with a route. Idempotent (ignores duplicates).
    pub fn link_route_backend(&self, route_id: &str, backend_id: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO route_backends (route_id, backend_id) VALUES (?1, ?2)",
            params![route_id, backend_id],
        )?;
        Ok(())
    }

    /// Remove an association between a route and a backend.
    pub fn unlink_route_backend(&self, route_id: &str, backend_id: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM route_backends WHERE route_id=?1 AND backend_id=?2",
            params![route_id, backend_id],
        )?;
        Ok(())
    }

    /// List backend IDs associated with a given route.
    pub fn list_backends_for_route(&self, route_id: &str) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT backend_id FROM route_backends WHERE route_id=?1 ORDER BY backend_id",
        )?;
        let rows = stmt.query_map(params![route_id], |row| row.get::<_, String>(0))?;
        let mut ids = Vec::new();
        for r in rows {
            ids.push(r?);
        }
        Ok(ids)
    }

    /// List route IDs associated with a given backend.
    pub fn list_routes_for_backend(&self, backend_id: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT route_id FROM route_backends WHERE backend_id=?1 ORDER BY route_id")?;
        let rows = stmt.query_map(params![backend_id], |row| row.get::<_, String>(0))?;
        let mut ids = Vec::new();
        for r in rows {
            ids.push(r?);
        }
        Ok(ids)
    }

    /// List all route-backend associations, ordered by route then backend ID.
    pub fn list_route_backends(&self) -> Result<Vec<RouteBackend>> {
        let mut stmt = self.conn.prepare(
            "SELECT route_id, backend_id FROM route_backends ORDER BY route_id, backend_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(RouteBackend {
                route_id: row.get(0)?,
                backend_id: row.get(1)?,
            })
        })?;
        let mut links = Vec::new();
        for r in rows {
            links.push(r?);
        }
        Ok(links)
    }
}
