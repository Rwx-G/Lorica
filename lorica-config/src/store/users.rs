//! User account CRUD methods on `ConfigStore` (Story 8.3 RBAC).
//!
//! The `users` table replaced `admin_users` in schema version 22; the
//! single pre-RBAC admin row was backfilled as `role = 'super_admin'`.

use rusqlite::{params, OptionalExtension};

use super::row_helpers::row_to_user;
use super::ConfigStore;
use crate::error::{ConfigError, Result};
use crate::models::*;

const USER_COLUMNS: &str = "id, username, password_hash, role, must_change_password, \
     created_at, last_login_at, disabled_at, created_by";

impl ConfigStore {
    /// Insert a new user account.
    pub fn create_user(&self, user: &User) -> Result<()> {
        self.conn.execute(
            "INSERT INTO users (id, username, password_hash, role, must_change_password,
             created_at, last_login_at, disabled_at, created_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                user.id,
                user.username,
                user.password_hash,
                user.role.as_str(),
                user.must_change_password,
                user.created_at.to_rfc3339(),
                user.last_login_at.map(|t| t.to_rfc3339()),
                user.disabled_at.map(|t| t.to_rfc3339()),
                user.created_by,
            ],
        )?;
        Ok(())
    }

    /// Fetch a user by ID, or `None` if not found.
    pub fn get_user(&self, id: &str) -> Result<Option<User>> {
        self.conn
            .query_row(
                &format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?1"),
                params![id],
                |row| Ok(row_to_user(row)),
            )
            .optional()?
            .transpose()
    }

    /// Fetch a user by username, or `None` if not found.
    pub fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        self.conn
            .query_row(
                &format!("SELECT {USER_COLUMNS} FROM users WHERE username = ?1"),
                params![username],
                |row| Ok(row_to_user(row)),
            )
            .optional()?
            .transpose()
    }

    /// List all users, ordered by username.
    pub fn list_users(&self) -> Result<Vec<User>> {
        let mut stmt = self
            .conn
            .prepare(&format!("SELECT {USER_COLUMNS} FROM users ORDER BY username"))?;
        let rows = stmt.query_map([], |row| Ok(row_to_user(row)))?;
        let mut users = Vec::new();
        for r in rows {
            users.push(r??);
        }
        Ok(users)
    }

    /// Update an existing user. Returns `NotFound` if the ID does not exist.
    pub fn update_user(&self, user: &User) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE users SET username=?2, password_hash=?3, role=?4,
             must_change_password=?5, last_login_at=?6, disabled_at=?7 WHERE id=?1",
            params![
                user.id,
                user.username,
                user.password_hash,
                user.role.as_str(),
                user.must_change_password,
                user.last_login_at.map(|t| t.to_rfc3339()),
                user.disabled_at.map(|t| t.to_rfc3339()),
            ],
        )?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("user {}", user.id)));
        }
        Ok(())
    }

    /// Delete a user by ID. Returns `NotFound` if the ID does not exist.
    pub fn delete_user(&self, id: &str) -> Result<()> {
        let changed = self
            .conn
            .execute("DELETE FROM users WHERE id=?1", params![id])?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("user {id}")));
        }
        Ok(())
    }

    /// Count enabled `SuperAdmin` accounts. Backs the "cannot delete,
    /// demote, or disable the last super admin" guard in the users
    /// CRUD handlers.
    pub fn count_active_super_admins(&self) -> Result<i64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM users WHERE role = 'super_admin' AND disabled_at IS NULL",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }
}
