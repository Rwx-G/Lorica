//! Admin user CRUD methods on `ConfigStore`.

use rusqlite::{params, OptionalExtension};

use super::row_helpers::row_to_admin_user;
use super::ConfigStore;
use crate::error::{ConfigError, Result};
use crate::models::*;

impl ConfigStore {
    /// Insert a new admin user.
    pub fn create_admin_user(&self, user: &AdminUser) -> Result<()> {
        self.conn.execute(
            "INSERT INTO admin_users (id, username, password_hash, must_change_password,
             created_at, last_login) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                user.id,
                user.username,
                user.password_hash,
                user.must_change_password,
                user.created_at.to_rfc3339(),
                user.last_login.map(|t| t.to_rfc3339()),
            ],
        )?;
        Ok(())
    }

    /// Fetch an admin user by ID, or `None` if not found.
    pub fn get_admin_user(&self, id: &str) -> Result<Option<AdminUser>> {
        self.conn
            .query_row(
                "SELECT id, username, password_hash, must_change_password, created_at, last_login
                 FROM admin_users WHERE id = ?1",
                params![id],
                |row| Ok(row_to_admin_user(row)),
            )
            .optional()?
            .transpose()
    }

    /// Fetch an admin user by username, or `None` if not found.
    pub fn get_admin_user_by_username(&self, username: &str) -> Result<Option<AdminUser>> {
        self.conn
            .query_row(
                "SELECT id, username, password_hash, must_change_password, created_at, last_login
                 FROM admin_users WHERE username = ?1",
                params![username],
                |row| Ok(row_to_admin_user(row)),
            )
            .optional()?
            .transpose()
    }

    /// List all admin users, ordered by username.
    pub fn list_admin_users(&self) -> Result<Vec<AdminUser>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, username, password_hash, must_change_password, created_at, last_login
             FROM admin_users ORDER BY username",
        )?;
        let rows = stmt.query_map([], |row| Ok(row_to_admin_user(row)))?;
        let mut users = Vec::new();
        for r in rows {
            users.push(r??);
        }
        Ok(users)
    }

    /// Update an existing admin user. Returns `NotFound` if the ID does not exist.
    pub fn update_admin_user(&self, user: &AdminUser) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE admin_users SET username=?2, password_hash=?3, must_change_password=?4,
             last_login=?5 WHERE id=?1",
            params![
                user.id,
                user.username,
                user.password_hash,
                user.must_change_password,
                user.last_login.map(|t| t.to_rfc3339()),
            ],
        )?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("admin_user {}", user.id)));
        }
        Ok(())
    }

    /// Delete an admin user by ID. Returns `NotFound` if the ID does not exist.
    pub fn delete_admin_user(&self, id: &str) -> Result<()> {
        let changed = self
            .conn
            .execute("DELETE FROM admin_users WHERE id=?1", params![id])?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("admin_user {id}")));
        }
        Ok(())
    }
}
