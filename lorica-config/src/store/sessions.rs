//! Session persistence on `ConfigStore`.
//!
//! Covers the dashboard auth session table created in migration 019
//! plus the indexes added later on `expires_at` and `user_id` to keep
//! the GC tick and per-user cleanup queries off a full-table scan.

use std::str::FromStr;

use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension};

use super::row_helpers::parse_datetime;
use super::ConfigStore;
use crate::error::{ConfigError, Result};
use crate::models::Role;

impl ConfigStore {
    /// Save a session to the database (insert or replace).
    pub fn save_session(
        &self,
        id: &str,
        user_id: &str,
        username: &str,
        role: Role,
        created_at: &DateTime<Utc>,
        expires_at: &DateTime<Utc>,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO sessions (id, user_id, username, role, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                id,
                user_id,
                username,
                role.as_str(),
                created_at.to_rfc3339(),
                expires_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Get a session by ID. Returns None if not found. An
    /// unparseable `role` value is an error, not a default: the
    /// caller treats it as "no session" and the user re-logs in.
    #[allow(clippy::type_complexity)]
    pub fn get_session(
        &self,
        id: &str,
    ) -> Result<Option<(String, String, Role, DateTime<Utc>, DateTime<Utc>)>> {
        let result = self
            .conn
            .query_row(
                "SELECT user_id, username, role, created_at, expires_at FROM sessions WHERE id = ?1",
                params![id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?;

        match result {
            Some((user_id, username, role_str, created_str, expires_str)) => {
                let role = Role::from_str(&role_str)
                    .map_err(|e| ConfigError::Validation(format!("invalid session role: {e}")))?;
                let created_at = parse_datetime(&created_str)?;
                let expires_at = parse_datetime(&expires_str)?;
                Ok(Some((user_id, username, role, created_at, expires_at)))
            }
            None => Ok(None),
        }
    }

    /// Update the expires_at timestamp of a session.
    pub fn update_session_expiry(&self, id: &str, expires_at: &DateTime<Utc>) -> Result<()> {
        self.conn.execute(
            "UPDATE sessions SET expires_at = ?1 WHERE id = ?2",
            params![expires_at.to_rfc3339(), id],
        )?;
        Ok(())
    }

    /// Delete a session by ID.
    pub fn delete_session(&self, id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM sessions WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Delete all sessions for a user except the given session ID.
    pub fn delete_sessions_for_user_except(
        &self,
        user_id: &str,
        except_session_id: &str,
    ) -> Result<()> {
        self.conn.execute(
            "DELETE FROM sessions WHERE user_id = ?1 AND id != ?2",
            params![user_id, except_session_id],
        )?;
        Ok(())
    }

    /// Delete every session belonging to a user. Used by the
    /// password-change flow to invalidate all currently-active
    /// cookies (including the one that triggered the change) so a
    /// stolen cookie cannot survive the rotation. Caller is
    /// expected to mint a fresh session + `Set-Cookie` immediately
    /// after so the legitimate user stays logged in.
    pub fn delete_all_sessions_for_user(&self, user_id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM sessions WHERE user_id = ?1", params![user_id])?;
        Ok(())
    }

    /// Delete sessions that have expired (expires_at < now).
    pub fn cleanup_expired_sessions(&self) -> Result<usize> {
        let now = Utc::now().to_rfc3339();
        let count = self
            .conn
            .execute("DELETE FROM sessions WHERE expires_at < ?1", params![now])?;
        Ok(count)
    }

    /// Load all non-expired sessions from the database. Rows with an
    /// unparseable `role` are skipped (the user re-logs in) rather
    /// than failing the whole startup rehydration.
    #[allow(clippy::type_complexity)]
    pub fn load_all_sessions(
        &self,
    ) -> Result<Vec<(String, String, String, Role, DateTime<Utc>, DateTime<Utc>)>> {
        let now = Utc::now().to_rfc3339();
        let mut stmt = self.conn.prepare(
            "SELECT id, user_id, username, role, created_at, expires_at FROM sessions WHERE expires_at >= ?1",
        )?;
        let rows = stmt.query_map(params![now], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?;

        let mut sessions = Vec::new();
        for row in rows {
            let (id, user_id, username, role_str, created_str, expires_str) = row?;
            let Ok(role) = Role::from_str(&role_str) else {
                tracing::warn!(session_id = %id, role = %role_str, "skipping session with invalid role");
                continue;
            };
            let created_at = parse_datetime(&created_str)?;
            let expires_at = parse_datetime(&expires_str)?;
            sessions.push((id, user_id, username, role, created_at, expires_at));
        }
        Ok(sessions)
    }
}
