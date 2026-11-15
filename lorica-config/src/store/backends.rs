//! Backend CRUD and route-backend link operations on `ConfigStore`.

use rusqlite::{params, OptionalExtension};

use super::row_helpers::row_to_backend;
use super::{serialize_field, serialize_optional_field, ConfigStore};
use crate::error::{ConfigError, Result};
use crate::models::*;

/// The column list every backend read binds, in the order
/// `row_to_backend` expects. Explicit, never `SELECT *`: a 1.10.6
/// binary reading a 1.11.0 database relies on its own copy of this list
/// never naming a column it does not know.
const BACKEND_COLUMNS: &str = "id, address, name, group_name, weight, health_status, \
     health_check_enabled, health_check_interval_s, health_check_path, \
     lifecycle_state, active_connections, tls_upstream, created_at, updated_at, h2_upstream, \
     tls_sni, tls_skip_verify, managed_by, health_check_json";

/// The typed health check a write persists, and the legacy path it
/// projects onto: the reconciled definition (`HealthCheck::reconcile`)
/// of what the caller holds, so the two columns never disagree after a
/// 1.11.0 write.
fn health_check_columns(backend: &Backend) -> Result<(String, Option<String>)> {
    let check = HealthCheck::reconcile(
        Some(backend.health_check.clone()),
        backend.health_check_path.as_deref(),
    );
    let path = check.legacy_path().map(str::to_string);
    Ok((serialize_field("health_check", &check)?, path))
}

impl ConfigStore {
    /// Validate a backend address: `host:port`, or a host without a port
    /// for a port-range stream (`backend_address_port`).
    fn validate_backend_address(address: &str) -> Result<()> {
        backend_address_port(address)
            .map(|_| ())
            .map_err(ConfigError::Validation)
    }

    /// Insert a new backend into the database.
    ///
    /// Refused when the backend breaks the stream attachment rule
    /// (`check_backend_attachments`): a portless backend with active
    /// checks on, for one.
    pub fn create_backend(&self, backend: &Backend) -> Result<()> {
        self.within_savepoint(|| {
            self.create_backend_unchecked(backend)?;
            self.check_attachments_of(&[backend.id.as_str()])
        })
    }

    /// [`ConfigStore::create_backend`] without the attachment rule, for
    /// a writer that checked a whole consistent snapshot first (replica
    /// apply, import).
    pub(crate) fn create_backend_unchecked(&self, backend: &Backend) -> Result<()> {
        Self::validate_backend_address(&backend.address)?;
        let managed_by_json = serialize_optional_field("managed_by", backend.managed_by.as_ref())?;
        let (health_check_json, health_check_path) = health_check_columns(backend)?;
        self.conn.execute(
            "INSERT INTO backends (id, address, name, group_name, weight, health_status,
             health_check_enabled, health_check_interval_s, health_check_path,
             lifecycle_state, active_connections, tls_upstream, h2_upstream, created_at, updated_at, tls_sni, tls_skip_verify,
             managed_by, health_check_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
            params![
                backend.id,
                backend.address,
                backend.name,
                backend.group_name,
                backend.weight,
                backend.health_status.as_str(),
                backend.health_check_enabled,
                backend.health_check_interval_s,
                health_check_path,
                backend.lifecycle_state.as_str(),
                backend.active_connections,
                backend.tls_upstream,
                backend.h2_upstream,
                backend.created_at.to_rfc3339(),
                backend.updated_at.to_rfc3339(),
                backend.tls_sni.as_deref().unwrap_or(""),
                backend.tls_skip_verify,
                managed_by_json,
                health_check_json,
            ],
        )?;
        Ok(())
    }

    /// Fetch a backend by ID, or `None` if not found.
    pub fn get_backend(&self, id: &str) -> Result<Option<Backend>> {
        let sql = format!("SELECT {BACKEND_COLUMNS} FROM backends WHERE id = ?1");
        self.conn
            .query_row(&sql, params![id], |row| Ok(row_to_backend(row)))
            .optional()?
            .transpose()
    }

    /// List all backends, ordered by address.
    pub fn list_backends(&self) -> Result<Vec<Backend>> {
        let sql = format!("SELECT {BACKEND_COLUMNS} FROM backends ORDER BY address");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| Ok(row_to_backend(row)))?;
        let mut backends = Vec::new();
        for r in rows {
            backends.push(r??);
        }
        Ok(backends)
    }

    /// Update an existing backend. Returns `NotFound` if the ID does not
    /// exist, and refuses an update that breaks the stream attachment
    /// rule (`check_backend_attachments`), such as turning active checks
    /// on for a backend of a UDP stream; the error names the stream.
    pub fn update_backend(&self, backend: &Backend) -> Result<()> {
        self.within_savepoint(|| {
            self.update_backend_unchecked(backend)?;
            self.check_attachments_of(&[backend.id.as_str()])
        })
    }

    /// [`ConfigStore::update_backend`] without the attachment rule, for
    /// a writer that checked a whole consistent snapshot first.
    pub(crate) fn update_backend_unchecked(&self, backend: &Backend) -> Result<()> {
        Self::validate_backend_address(&backend.address)?;
        let managed_by_json = serialize_optional_field("managed_by", backend.managed_by.as_ref())?;
        let (health_check_json, health_check_path) = health_check_columns(backend)?;
        let changed = self.conn.execute(
            "UPDATE backends SET address=?2, name=?3, group_name=?4, weight=?5,
             health_status=?6, health_check_enabled=?7, health_check_interval_s=?8,
             health_check_path=?9, lifecycle_state=?10, active_connections=?11,
             tls_upstream=?12, h2_upstream=?13, updated_at=?14, tls_sni=?15, tls_skip_verify=?16,
             managed_by=?17, health_check_json=?18 WHERE id=?1",
            params![
                backend.id,
                backend.address,
                backend.name,
                backend.group_name,
                backend.weight,
                backend.health_status.as_str(),
                backend.health_check_enabled,
                backend.health_check_interval_s,
                health_check_path,
                backend.lifecycle_state.as_str(),
                backend.active_connections,
                backend.tls_upstream,
                backend.h2_upstream,
                backend.updated_at.to_rfc3339(),
                backend.tls_sni.as_deref().unwrap_or(""),
                backend.tls_skip_verify,
                managed_by_json,
                health_check_json,
            ],
        )?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("backend {}", backend.id)));
        }
        Ok(())
    }

    /// Store a probed health status, and nothing else, for the backend
    /// `id`. Returns `NotFound` if the ID does not exist.
    ///
    /// The health loop's writer: a whole-row write from the copy it
    /// listed at the start of a cycle would revert an operator edit
    /// committed while the cycle probed. `updated_at` is not touched (a
    /// probe is not an edit), and the stream attachment rule does not
    /// run, since it reads nothing this changes.
    pub fn set_backend_health_status(&self, id: &str, status: &HealthStatus) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE backends SET health_status=?2 WHERE id=?1",
            params![id, status.as_str()],
        )?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("backend {id}")));
        }
        Ok(())
    }

    /// Store a lifecycle state and its `updated_at`, and nothing else,
    /// for the backend `id`. Returns `NotFound` if the ID does not exist.
    ///
    /// The health loop's drain writer, for the reason given on
    /// [`ConfigStore::set_backend_health_status`]; the attachment rule
    /// reads no lifecycle state, so it does not run.
    pub fn set_backend_lifecycle_state(
        &self,
        id: &str,
        state: &LifecycleState,
        updated_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE backends SET lifecycle_state=?2, updated_at=?3 WHERE id=?1",
            params![id, state.as_str(), updated_at.to_rfc3339()],
        )?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("backend {id}")));
        }
        Ok(())
    }

    /// Delete a backend by ID. Returns `NotFound` if the ID does not exist.
    /// Its route and stream links go with it (both foreign keys cascade).
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
    ///
    /// Refused when the backend serves a UDP stream or carries no port
    /// (`check_backend_attachments`); the error names the stream.
    pub fn link_route_backend(&self, route_id: &str, backend_id: &str) -> Result<()> {
        self.within_savepoint(|| {
            self.link_route_backend_unchecked(route_id, backend_id)?;
            self.check_attachments_of(&[backend_id])
        })
    }

    /// [`ConfigStore::link_route_backend`] without the attachment rule,
    /// for a writer that checked a whole consistent snapshot first.
    pub(crate) fn link_route_backend_unchecked(
        &self,
        route_id: &str,
        backend_id: &str,
    ) -> Result<()> {
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

    /// Apply the stream attachment rule (`check_backend_attachments`) to
    /// the stored backends among `backend_ids`, against every stored
    /// stream and link. Only the backends a write touched are checked,
    /// so a write is never refused for a row it did not change.
    ///
    /// # Errors
    ///
    /// `ConfigError::Validation` naming the stream, as the API maps it.
    pub(crate) fn check_attachments_of(&self, backend_ids: &[&str]) -> Result<()> {
        let mut backends = Vec::with_capacity(backend_ids.len());
        for id in backend_ids {
            if let Some(backend) = self.get_backend(id)? {
                backends.push(backend);
            }
        }
        if backends.is_empty() {
            return Ok(());
        }
        let streams = self.list_streams()?;
        let stream_backends = self.list_stream_backends()?;
        let route_backends = self.list_route_backends()?;
        check_backend_attachments(&AttachmentSnapshot {
            backends: &backends,
            streams: &streams,
            stream_backends: &stream_backends,
            route_backends: &route_backends,
        })
        .map_err(|conflict| ConfigError::Validation(conflict.to_string()))
    }
}
