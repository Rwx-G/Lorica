//! The AD CS authority on `ConfigStore` (Story 13.2, Epic 13 PRD D3,
//! D10, D13, D15).
//!
//! # One row, and it does not replicate
//!
//! v1.10.0 supports one authority (D10). The schema does not encode
//! that, so a later release can lift it without a migration; the rule
//! lives in [`ConfigStore::upsert_adcs_authority`], which refuses a
//! second id.
//!
//! `adcs_authority` is absent from the canonical blob, from every
//! follower payload, from `store/replica.rs` and from the configuration
//! export (D13, D14). DNS providers ride the blob with their secret as
//! an unsalted digest, which is acceptable for a high-entropy API token
//! and not for a password a person chose; and a follower never applies
//! the authority, so nothing on it would use the row. The tests at the
//! bottom of this file and in `store/replica.rs` assert the absence.
//!
//! # The password
//!
//! Its own nullable column, base64 ciphertext registered in
//! `ENCRYPTED_COLUMNS` so key rotation covers it. It is not a field of
//! [`AdcsAuthority`], so no serialisation of the model can carry it;
//! only [`ConfigStore::get_adcs_password`] returns it. Writing one is
//! refused on a store with no encryption key (D3): the `encrypt_*`
//! helpers would otherwise store it in clear.

use std::str::FromStr;

use chrono::Utc;
use rusqlite::{params, OptionalExtension};

use super::row_helpers::{json_column, parse_datetime, parse_optional_datetime};
use super::{serialize_field, ConfigStore};
use crate::error::{ConfigError, Result};
use crate::models::{AdcsAuthority, AdcsKeyType, AdcsSubjectDefaults};

/// The column list every authority read binds, in the order
/// [`row_to_adcs_authority`] expects. `password_enc` is deliberately
/// not in it.
const ADCS_AUTHORITY_COLUMNS: &str = "id, endpoint, realm, kdcs_json, principal, \
     endpoint_ca_pem, issuing_ca_pem, default_template, default_key_type, subject_country, \
     subject_state, subject_locality, subject_organization, subject_organizational_unit, \
     subject_email, allowed_suffixes_json, auto_renew_default, failed_since, failed_step, \
     failed_kdc_code, created_at, updated_at, allowed_templates_json";

/// Decode one `adcs_authority` row.
fn row_to_adcs_authority(row: &rusqlite::Row<'_>) -> Result<AdcsAuthority> {
    let key_type: String = row.get(8)?;
    let created_at: String = row.get(20)?;
    let updated_at: String = row.get(21)?;
    Ok(AdcsAuthority {
        id: row.get(0)?,
        endpoint: row.get(1)?,
        realm: row.get(2)?,
        kdcs: json_column(row, 3, "adcs authority", "kdcs")?,
        principal: row.get(4)?,
        endpoint_ca_pem: row.get(5)?,
        issuing_ca_pem: row.get(6)?,
        default_template: row.get(7)?,
        allowed_templates: json_column(row, 22, "adcs authority", "allowed_templates")?,
        default_key_type: AdcsKeyType::from_str(&key_type).map_err(|e| {
            ConfigError::Corrupt(format!("stored adcs authority key type is invalid: {e}"))
        })?,
        subject: AdcsSubjectDefaults {
            country: row.get(9)?,
            state: row.get(10)?,
            locality: row.get(11)?,
            organization: row.get(12)?,
            organizational_unit: row.get(13)?,
            email: row.get(14)?,
        },
        // A suffix that no longer validates fails the read: degrading
        // the list would change which names Lorica may request.
        allowed_suffixes: json_column(row, 15, "adcs authority", "allowed_suffixes")?,
        auto_renew_default: row.get(16)?,
        failed_since: parse_optional_datetime(row.get(17)?)?,
        failed_step: row.get(18)?,
        failed_kdc_code: row.get(19)?,
        created_at: parse_datetime(&created_at)?,
        updated_at: parse_datetime(&updated_at)?,
    })
}

impl ConfigStore {
    /// The authority, or `None` when none is configured.
    pub fn get_adcs_authority(&self) -> Result<Option<AdcsAuthority>> {
        let sql = format!(
            "SELECT {ADCS_AUTHORITY_COLUMNS} FROM adcs_authority ORDER BY created_at, id LIMIT 1"
        );
        self.conn
            .query_row(&sql, [], |row| Ok(row_to_adcs_authority(row)))
            .optional()?
            .transpose()
    }

    /// Create the authority, or update it when `authority.id` is the
    /// one already stored.
    ///
    /// Writes the configuration fields only. The password, the failed
    /// state and `created_at` are left as stored on an update, and a
    /// new row starts with no password and not failed: each has its own
    /// writer ([`ConfigStore::set_adcs_password`],
    /// [`ConfigStore::set_adcs_failed`],
    /// [`ConfigStore::clear_adcs_failed`]), so an edit of the subject
    /// cannot reset the breaker by carrying a stale copy of it.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Validation`] when [`AdcsAuthority::validate`]
    /// fails, or when another authority already exists (at most one,
    /// PRD D10).
    pub fn upsert_adcs_authority(&self, authority: &AdcsAuthority) -> Result<()> {
        authority.validate()?;
        let other: Option<String> = self
            .conn
            .query_row(
                "SELECT id FROM adcs_authority WHERE id != ?1 LIMIT 1",
                params![authority.id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(other) = other {
            return Err(ConfigError::Validation(format!(
                "an AD CS authority is already configured ({other}); only one is supported"
            )));
        }
        let subject = &authority.subject;
        self.conn.execute(
            "INSERT INTO adcs_authority (id, endpoint, realm, kdcs_json, principal,
             endpoint_ca_pem, issuing_ca_pem, default_template, default_key_type,
             subject_country, subject_state, subject_locality, subject_organization,
             subject_organizational_unit, subject_email, allowed_suffixes_json,
             auto_renew_default, created_at, updated_at, allowed_templates_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
             ?17, ?18, ?19, ?20)
             ON CONFLICT(id) DO UPDATE SET endpoint = excluded.endpoint,
             realm = excluded.realm, kdcs_json = excluded.kdcs_json,
             principal = excluded.principal, endpoint_ca_pem = excluded.endpoint_ca_pem,
             issuing_ca_pem = excluded.issuing_ca_pem,
             default_template = excluded.default_template,
             default_key_type = excluded.default_key_type,
             subject_country = excluded.subject_country,
             subject_state = excluded.subject_state,
             subject_locality = excluded.subject_locality,
             subject_organization = excluded.subject_organization,
             subject_organizational_unit = excluded.subject_organizational_unit,
             subject_email = excluded.subject_email,
             allowed_suffixes_json = excluded.allowed_suffixes_json,
             auto_renew_default = excluded.auto_renew_default,
             updated_at = excluded.updated_at,
             allowed_templates_json = excluded.allowed_templates_json",
            params![
                authority.id,
                authority.endpoint,
                authority.realm,
                serialize_field("adcs authority kdcs", &authority.kdcs)?,
                authority.principal,
                authority.endpoint_ca_pem,
                authority.issuing_ca_pem,
                authority.default_template,
                authority.default_key_type.as_str(),
                subject.country,
                subject.state,
                subject.locality,
                subject.organization,
                subject.organizational_unit,
                subject.email,
                serialize_field(
                    "adcs authority allowed_suffixes",
                    &authority.allowed_suffixes
                )?,
                authority.auto_renew_default,
                authority.created_at.to_rfc3339(),
                authority.updated_at.to_rfc3339(),
                serialize_field(
                    "adcs authority allowed_templates",
                    &authority.allowed_templates
                )?,
            ],
        )?;
        Ok(())
    }

    /// The decrypted service account password, or `None` when the
    /// authority has none set (or does not exist).
    ///
    /// # Errors
    ///
    /// [`ConfigError::Corrupt`] when a password is stored but this
    /// store has no key to decrypt it, or when decryption fails.
    pub fn get_adcs_password(&self) -> Result<Option<String>> {
        let stored: Option<Option<String>> = self
            .conn
            .query_row(
                "SELECT password_enc FROM adcs_authority ORDER BY created_at, id LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let Some(ciphertext) = stored.flatten() else {
            return Ok(None);
        };
        // Without a key `decrypt_config` would hand back the base64
        // ciphertext as if it were the password.
        if !self.has_encryption_key() {
            return Err(ConfigError::Corrupt(
                "an AD CS password is stored but no encryption key is loaded".to_string(),
            ));
        }
        self.decrypt_config(&ciphertext).map(Some)
    }

    /// Whether a service account password is stored, read without
    /// decrypting it: a presence check has no reason to put the
    /// cleartext in memory.
    pub fn has_adcs_password(&self) -> Result<bool> {
        let stored: Option<bool> = self
            .conn
            .query_row(
                "SELECT password_enc IS NOT NULL FROM adcs_authority \
                 ORDER BY created_at, id LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        Ok(stored.unwrap_or(false))
    }

    /// Delete every authority row, password included, whatever
    /// certificates reference it. Returns whether a row existed.
    ///
    /// For a node that becomes a follower (Epic 13 D13): a follower holds
    /// AD CS certificates without the authority by design, so the
    /// reference guard of [`ConfigStore::delete_adcs_authority`] does not
    /// apply, and the row and its encrypted password must not stay on a
    /// node that will never use them.
    pub fn purge_adcs_authority(&self) -> Result<bool> {
        let deleted = self.conn.execute("DELETE FROM adcs_authority", [])?;
        Ok(deleted > 0)
    }

    /// Set (`Some`) or clear (`None`) the service account password.
    ///
    /// This does not touch the D15 failed state: the caller pairs a new
    /// password with [`ConfigStore::clear_adcs_failed`] so it can audit
    /// the exit from that state.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Validation`] for an empty password, or for any
    /// password on a store with no encryption key (PRD D3: it would be
    /// written in clear). [`ConfigError::NotFound`] when no authority
    /// exists.
    pub fn set_adcs_password(&self, password: Option<&str>) -> Result<()> {
        let encrypted = match password {
            Some("") => {
                return Err(ConfigError::Validation(
                    "the AD CS password cannot be empty".to_string(),
                ))
            }
            Some(_) if !self.has_encryption_key() => {
                return Err(ConfigError::Validation(
                    "refusing to store the AD CS password: no encryption key is loaded".to_string(),
                ))
            }
            Some(plaintext) => Some(self.encrypt_config(plaintext)?),
            None => None,
        };
        let changed = self.conn.execute(
            "UPDATE adcs_authority SET password_enc = ?1, updated_at = ?2",
            params![encrypted, Utc::now().to_rfc3339()],
        )?;
        if changed == 0 {
            return Err(ConfigError::NotFound("adcs authority".to_string()));
        }
        Ok(())
    }

    /// Ids of the certificates whose `adcs_authority_id` is `id`,
    /// ascending.
    pub fn adcs_authority_certificate_ids(&self, id: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM certificates WHERE adcs_authority_id = ?1 ORDER BY id")?;
        let ids = stmt
            .query_map(params![id], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        Ok(ids)
    }

    /// Delete the authority.
    ///
    /// Refused while any certificate references it: with no foreign
    /// key (followers hold those certificates without the row), this
    /// guard is what keeps the reference honest on the control plane.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Validation`] naming every referencing certificate
    /// id; [`ConfigError::NotFound`] when no authority has this id.
    pub fn delete_adcs_authority(&self, id: &str) -> Result<()> {
        let referencing = self.adcs_authority_certificate_ids(id)?;
        if !referencing.is_empty() {
            return Err(ConfigError::Validation(format!(
                "AD CS authority {id} is still used by certificates: {}",
                referencing.join(", ")
            )));
        }
        let changed = self
            .conn
            .execute("DELETE FROM adcs_authority WHERE id = ?1", params![id])?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("adcs authority {id}")));
        }
        Ok(())
    }

    /// Put the authority in the D15 failed state.
    ///
    /// Returns `true` when this call is the entry into the state, the
    /// moment exactly one `adcs_authority_failed` notification is owed.
    /// An authority already failed keeps its original since, step and
    /// code, and the call returns `false`.
    ///
    /// # Errors
    ///
    /// [`ConfigError::NotFound`] when no authority exists.
    pub fn set_adcs_failed(&self, step: &str, kdc_code: Option<i32>) -> Result<bool> {
        let changed = self.conn.execute(
            "UPDATE adcs_authority SET failed_since = ?1, failed_step = ?2, failed_kdc_code = ?3
             WHERE failed_since IS NULL",
            params![Utc::now().to_rfc3339(), step, kdc_code],
        )?;
        if changed == 0 {
            self.require_adcs_authority()?;
        }
        Ok(changed > 0)
    }

    /// Leave the D15 failed state. Returns `true` when the authority
    /// was failed.
    ///
    /// # Errors
    ///
    /// [`ConfigError::NotFound`] when no authority exists.
    pub fn clear_adcs_failed(&self) -> Result<bool> {
        let changed = self.conn.execute(
            "UPDATE adcs_authority SET failed_since = NULL, failed_step = NULL,
             failed_kdc_code = NULL
             WHERE failed_since IS NOT NULL",
            [],
        )?;
        if changed == 0 {
            self.require_adcs_authority()?;
        }
        Ok(changed > 0)
    }

    /// `NotFound` unless an authority row exists.
    fn require_adcs_authority(&self) -> Result<()> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM adcs_authority", [], |row| row.get(0))?;
        if count == 0 {
            return Err(ConfigError::NotFound("adcs authority".to_string()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use crate::crypto::EncryptionKey;
    use crate::error::ConfigError;
    use crate::models::{
        sample_adcs_authority, AllowedSuffix, Certificate, CertificateSource, GlobalSettings,
        ADCS_FIXTURE_SENTINEL,
    };
    use crate::store::ConfigStore;

    const PASSWORD: &str = "correct horse battery staple";

    fn keyed_store() -> ConfigStore {
        let key = EncryptionKey::generate().expect("test setup: key generates");
        ConfigStore::open_in_memory_with_key(key).expect("test setup: store opens")
    }

    fn at(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339)
            .expect("test setup: valid timestamp")
            .with_timezone(&Utc)
    }

    fn certificate(id: &str, authority_id: Option<&str>) -> Certificate {
        Certificate {
            id: id.to_string(),
            domain: format!("{id}.corp.example.org"),
            san_domains: vec![format!("{id}.corp.example.org")],
            fingerprint: format!("sha256:{id}"),
            cert_pem: "-----BEGIN CERTIFICATE-----\nadcs\n-----END CERTIFICATE-----".into(),
            key_pem: "-----BEGIN PRIVATE KEY-----\nadcs\n-----END PRIVATE KEY-----".into(),
            issuer: "CN=Issuing CA".into(),
            not_before: at("2026-10-01T00:00:00Z"),
            not_after: at("2027-10-01T00:00:00Z"),
            is_acme: false,
            acme_auto_renew: true,
            created_at: at("2026-10-01T00:00:00Z"),
            acme_method: None,
            acme_dns_provider_id: None,
            adcs_authority_id: authority_id.map(str::to_string),
            adcs_template: authority_id.map(|_| "LoricaWebServer".to_string()),
            adcs_template_oid: authority_id.map(|_| "1.3.6.1.4.1.311.21.8.1.2".to_string()),
            adcs_request_id: authority_id.map(|_| "4242".to_string()),
        }
    }

    /// Whether `value` holds an object key equal to `key` at any depth.
    fn has_key(value: &serde_json::Value, key: &str) -> bool {
        match value {
            serde_json::Value::Object(map) => map.iter().any(|(k, v)| k == key || has_key(v, key)),
            serde_json::Value::Array(items) => items.iter().any(|v| has_key(v, key)),
            _ => false,
        }
    }

    fn mentions_the_authority(text: &str) -> bool {
        text.to_ascii_lowercase().contains(ADCS_FIXTURE_SENTINEL)
    }

    #[test]
    fn has_encryption_key_reports_how_the_store_was_opened() {
        let plain = ConfigStore::open_in_memory().expect("test setup: store opens");
        assert!(!plain.has_encryption_key());
        assert!(keyed_store().has_encryption_key());
    }

    #[test]
    fn migration_64_adds_the_table_and_the_certificate_columns() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        let columns = |table: &str| -> Vec<String> {
            let mut stmt = store
                .conn
                .prepare("SELECT name FROM pragma_table_info(?1)")
                .expect("test setup: pragma prepares");
            stmt.query_map([table], |row| row.get(0))
                .expect("test setup: pragma runs")
                .collect::<rusqlite::Result<Vec<String>>>()
                .expect("test setup: pragma rows")
        };
        let certificates = columns("certificates");
        for column in [
            "adcs_authority_id",
            "adcs_template",
            "adcs_template_oid",
            "adcs_request_id",
        ] {
            assert!(certificates.iter().any(|c| c == column), "{column}");
        }
        let authority = columns("adcs_authority");
        for column in ["password_enc", "failed_since", "allowed_suffixes_json"] {
            assert!(authority.iter().any(|c| c == column), "{column}");
        }
        let foreign_keys: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_foreign_key_list('certificates') \
                 WHERE \"from\" = 'adcs_authority_id'",
                [],
                |row| row.get(0),
            )
            .expect("test setup: pragma runs");
        assert_eq!(
            foreign_keys, 0,
            "a foreign key would fail every replica apply on a follower"
        );
    }

    #[test]
    fn an_absent_authority_reads_as_none() {
        let store = keyed_store();
        assert!(store.get_adcs_authority().expect("read").is_none());
        assert!(store.get_adcs_password().expect("read").is_none());
    }

    #[test]
    fn the_authority_round_trips_through_the_store() {
        let store = keyed_store();
        let written = sample_adcs_authority("adcs-1");
        store.upsert_adcs_authority(&written).expect("upsert");
        let read = store
            .get_adcs_authority()
            .expect("read")
            .expect("the row exists");
        assert_eq!(read, written);
    }

    #[test]
    fn a_second_authority_is_refused_and_the_same_id_updates_in_place() {
        let store = keyed_store();
        store
            .upsert_adcs_authority(&sample_adcs_authority("adcs-1"))
            .expect("first upsert");

        let err = store
            .upsert_adcs_authority(&sample_adcs_authority("adcs-2"))
            .expect_err("a second authority must be refused");
        assert!(matches!(err, ConfigError::Validation(_)), "{err:?}");

        let mut edited = sample_adcs_authority("adcs-1");
        edited.default_template = "OtherTemplate".to_string();
        edited.allowed_suffixes =
            vec![AllowedSuffix::new("lab.example.net").expect("test setup: suffix")];
        store.upsert_adcs_authority(&edited).expect("update");
        let read = store.get_adcs_authority().expect("read").expect("row");
        assert_eq!(read.id, "adcs-1");
        assert_eq!(read.default_template, "OtherTemplate");
        assert_eq!(read.allowed_suffixes, edited.allowed_suffixes);
        let rows: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM adcs_authority", [], |row| row.get(0))
            .expect("test setup: count");
        assert_eq!(rows, 1);
    }

    #[test]
    fn an_invalid_authority_is_not_persisted() {
        let store = keyed_store();
        let mut no_suffix = sample_adcs_authority("adcs-1");
        no_suffix.allowed_suffixes.clear();
        assert!(store.upsert_adcs_authority(&no_suffix).is_err());
        assert!(store.get_adcs_authority().expect("read").is_none());
    }

    #[test]
    fn an_update_keeps_the_password_the_failed_state_and_created_at() {
        let store = keyed_store();
        let original = sample_adcs_authority("adcs-1");
        store.upsert_adcs_authority(&original).expect("upsert");
        store.set_adcs_password(Some(PASSWORD)).expect("password");
        assert!(store
            .set_adcs_failed("ticket_acquisition", Some(24))
            .expect("fail"));

        let mut edited = original.clone();
        edited.created_at = at("2030-01-01T00:00:00Z");
        edited.failed_since = None;
        edited.subject.organization = Some("Renamed".to_string());
        store.upsert_adcs_authority(&edited).expect("update");

        let read = store.get_adcs_authority().expect("read").expect("row");
        assert_eq!(read.created_at, original.created_at);
        assert!(read.is_failed(), "an edit must not reset the breaker");
        assert_eq!(read.subject.organization.as_deref(), Some("Renamed"));
        assert_eq!(
            store.get_adcs_password().expect("read").as_deref(),
            Some(PASSWORD)
        );
    }

    #[test]
    fn the_password_is_stored_encrypted_and_read_back_decrypted() {
        let store = keyed_store();
        store
            .upsert_adcs_authority(&sample_adcs_authority("adcs-1"))
            .expect("upsert");
        store.set_adcs_password(Some(PASSWORD)).expect("password");

        let stored: String = store
            .conn
            .query_row("SELECT password_enc FROM adcs_authority", [], |row| {
                row.get(0)
            })
            .expect("test setup: raw read");
        assert!(!stored.contains("horse"), "the column must hold ciphertext");
        assert_eq!(
            store.get_adcs_password().expect("read").as_deref(),
            Some(PASSWORD)
        );

        store.set_adcs_password(None).expect("clear");
        assert!(store.get_adcs_password().expect("read").is_none());
        assert!(
            store.set_adcs_password(Some("")).is_err(),
            "an empty password is not a password"
        );
    }

    #[test]
    fn a_password_write_is_refused_without_an_encryption_key() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        store
            .upsert_adcs_authority(&sample_adcs_authority("adcs-1"))
            .expect("upsert");
        let err = store
            .set_adcs_password(Some(PASSWORD))
            .expect_err("a keyless store must not hold the password");
        assert!(matches!(err, ConfigError::Validation(_)), "{err:?}");
        let stored: Option<String> = store
            .conn
            .query_row("SELECT password_enc FROM adcs_authority", [], |row| {
                row.get(0)
            })
            .expect("test setup: raw read");
        assert!(stored.is_none(), "nothing was written");
        store
            .set_adcs_password(None)
            .expect("clearing stores no secret, so it needs no key");
    }

    #[test]
    fn a_stored_password_is_not_returned_as_ciphertext_by_a_keyless_store() {
        let dir = tempfile::tempdir().expect("test setup: tempdir");
        let path = dir.path().join("adcs.db");
        {
            let key = EncryptionKey::generate().expect("test setup: key generates");
            let store = ConfigStore::open(&path, Some(key)).expect("test setup: open");
            store
                .upsert_adcs_authority(&sample_adcs_authority("adcs-1"))
                .expect("upsert");
            store.set_adcs_password(Some(PASSWORD)).expect("password");
        }
        let keyless = ConfigStore::open(&path, None).expect("test setup: reopen");
        let err = keyless
            .get_adcs_password()
            .expect_err("base64 ciphertext is not the password");
        assert!(matches!(err, ConfigError::Corrupt(_)), "{err:?}");
    }

    #[test]
    fn a_password_write_without_an_authority_is_not_found() {
        let store = keyed_store();
        assert!(matches!(
            store.set_adcs_password(Some(PASSWORD)),
            Err(ConfigError::NotFound(_))
        ));
    }

    #[test]
    fn password_presence_is_read_without_decrypting() {
        let store = keyed_store();
        assert!(!store.has_adcs_password().expect("no authority"));
        store
            .upsert_adcs_authority(&sample_adcs_authority("adcs-1"))
            .expect("upsert");
        assert!(!store.has_adcs_password().expect("no password"));
        store.set_adcs_password(Some(PASSWORD)).expect("password");
        assert!(store.has_adcs_password().expect("a password"));

        // A store that could not decrypt it still answers.
        let dir = tempfile::tempdir().expect("test setup: tempdir");
        let path = dir.path().join("adcs.db");
        {
            let key = EncryptionKey::generate().expect("test setup: key generates");
            let keyed = ConfigStore::open(&path, Some(key)).expect("test setup: open");
            keyed
                .upsert_adcs_authority(&sample_adcs_authority("adcs-1"))
                .expect("upsert");
            keyed.set_adcs_password(Some(PASSWORD)).expect("password");
        }
        let keyless = ConfigStore::open(&path, None).expect("test setup: reopen");
        assert!(keyless.has_adcs_password().expect("presence"));
    }

    #[test]
    fn a_purge_removes_the_authority_and_its_password_whatever_references_it() {
        let store = keyed_store();
        assert!(!store.purge_adcs_authority().expect("nothing to purge"));
        store
            .upsert_adcs_authority(&sample_adcs_authority("adcs-1"))
            .expect("upsert");
        store.set_adcs_password(Some(PASSWORD)).expect("password");
        store
            .create_certificate(&certificate("web", Some("adcs-1")))
            .expect("test setup: cert");

        assert!(store.purge_adcs_authority().expect("purge"));
        assert!(store.get_adcs_authority().expect("read").is_none());
        assert!(!store.has_adcs_password().expect("presence"));
        let rows: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM adcs_authority", [], |row| row.get(0))
            .expect("test setup: count");
        assert_eq!(rows, 0, "no ciphertext left behind");
        let web = store.get_certificate("web").expect("read").expect("row");
        assert_eq!(
            web.adcs_authority_id.as_deref(),
            Some("adcs-1"),
            "a follower keeps the certificates the control plane issued"
        );
    }

    #[test]
    fn migration_66_lists_the_default_template_of_an_existing_authority() {
        let store = keyed_store();
        let mut authority = sample_adcs_authority("adcs-1");
        authority.allowed_templates = Vec::new();
        store.upsert_adcs_authority(&authority).expect("upsert");
        // As a row written before the list existed reads after the column
        // was added with its default.
        store
            .conn
            .execute(
                "UPDATE adcs_authority SET allowed_templates_json = '[]'",
                [],
            )
            .expect("test setup: reset the list");

        super::super::migrate_adcs_allowed_templates(&store.conn).expect("migration 66");
        super::super::migrate_adcs_allowed_templates(&store.conn)
            .expect("migration 66 is idempotent");

        let read = store.get_adcs_authority().expect("read").expect("row");
        assert_eq!(read.allowed_templates, vec![read.default_template.clone()]);
    }

    #[test]
    fn the_allowed_templates_round_trip_and_are_validated() {
        let store = keyed_store();
        let mut authority = sample_adcs_authority("adcs-1");
        authority.allowed_templates = vec!["LoricaWebServer".into(), "LoricaEcdsa".into()];
        store.upsert_adcs_authority(&authority).expect("upsert");
        let read = store.get_adcs_authority().expect("read").expect("row");
        assert_eq!(read.allowed_templates, authority.allowed_templates);

        authority.allowed_templates.push("Bad\ttemplate".into());
        assert!(matches!(
            store.upsert_adcs_authority(&authority),
            Err(ConfigError::Validation(_))
        ));
    }

    #[test]
    fn key_rotation_re_encrypts_the_password() {
        let key2 = EncryptionKey::generate().expect("test setup: key generates");
        let store = keyed_store();
        store
            .upsert_adcs_authority(&sample_adcs_authority("adcs-1"))
            .expect("upsert");
        store.set_adcs_password(Some(PASSWORD)).expect("password");

        let count = store.rotate_encryption_key(&key2).expect("rotation");
        assert_eq!(count, 1, "the AD CS password must rotate");
        assert!(
            store.get_adcs_password().is_err(),
            "post-rotation read under the old key must fail to decrypt"
        );
    }

    #[test]
    fn key_rotation_skips_an_authority_with_no_password() {
        let key2 = EncryptionKey::generate().expect("test setup: key generates");
        let store = keyed_store();
        store
            .upsert_adcs_authority(&sample_adcs_authority("adcs-1"))
            .expect("upsert");
        let count = store
            .rotate_encryption_key(&key2)
            .expect("a NULL password must not fail the rotation");
        assert_eq!(count, 0);
    }

    #[test]
    fn delete_is_refused_while_a_certificate_references_the_authority() {
        let store = keyed_store();
        store
            .upsert_adcs_authority(&sample_adcs_authority("adcs-1"))
            .expect("upsert");
        for cert in [
            certificate("web-b", Some("adcs-1")),
            certificate("web-a", Some("adcs-1")),
            certificate("manual", None),
        ] {
            store.create_certificate(&cert).expect("test setup: cert");
        }

        let err = store
            .delete_adcs_authority("adcs-1")
            .expect_err("referenced authority must not be deleted");
        match err {
            ConfigError::Validation(message) => {
                assert!(message.contains("web-a, web-b"), "{message}");
                assert!(!message.contains("manual"), "{message}");
            }
            other => panic!("unexpected error {other:?}"),
        }
        assert!(store.get_adcs_authority().expect("read").is_some());

        for id in ["web-a", "web-b"] {
            let mut cert = store
                .get_certificate(id)
                .expect("read")
                .expect("test setup: cert exists");
            cert.adcs_authority_id = None;
            store.update_certificate(&cert).expect("revert to manual");
        }
        store.delete_adcs_authority("adcs-1").expect("delete");
        assert!(store.get_adcs_authority().expect("read").is_none());
        assert!(matches!(
            store.delete_adcs_authority("adcs-1"),
            Err(ConfigError::NotFound(_))
        ));
    }

    #[test]
    fn the_adcs_certificate_columns_round_trip() {
        let store = keyed_store();
        let written = certificate("web", Some("adcs-1"));
        store.create_certificate(&written).expect("insert");
        let read = store.get_certificate("web").expect("read").expect("row");
        assert_eq!(read.adcs_authority_id.as_deref(), Some("adcs-1"));
        assert_eq!(read.adcs_template, written.adcs_template);
        assert_eq!(read.adcs_template_oid, written.adcs_template_oid);
        assert_eq!(read.adcs_request_id, written.adcs_request_id);
        assert_eq!(read.source(), CertificateSource::Adcs);

        let listed = store
            .list_certificates_without_private_keys()
            .expect("listing");
        assert_eq!(listed[0].adcs_request_id, written.adcs_request_id);
        assert_eq!(listed[0].adcs_authority_id, written.adcs_authority_id);
    }

    #[test]
    fn the_failed_state_is_entered_once_and_cleared_once() {
        let store = keyed_store();
        assert!(matches!(
            store.set_adcs_failed("ticket_acquisition", Some(24)),
            Err(ConfigError::NotFound(_))
        ));
        assert!(matches!(
            store.clear_adcs_failed(),
            Err(ConfigError::NotFound(_))
        ));
        store
            .upsert_adcs_authority(&sample_adcs_authority("adcs-1"))
            .expect("upsert");

        assert!(store
            .set_adcs_failed("ticket_acquisition", Some(24))
            .expect("entry"));
        assert!(
            !store.set_adcs_failed("spnego", None).expect("repeat"),
            "a second failure is not a second entry"
        );
        let failed = store.get_adcs_authority().expect("read").expect("row");
        assert!(failed.is_failed());
        assert_eq!(failed.failed_step.as_deref(), Some("ticket_acquisition"));
        assert_eq!(failed.failed_kdc_code, Some(24));

        assert!(store.clear_adcs_failed().expect("exit"));
        assert!(!store.clear_adcs_failed().expect("repeat"));
        let cleared = store.get_adcs_authority().expect("read").expect("row");
        assert!(!cleared.is_failed());
        assert!(cleared.failed_step.is_none());
        assert!(cleared.failed_kdc_code.is_none());
    }

    #[test]
    fn the_failed_state_survives_a_reopen() {
        let dir = tempfile::tempdir().expect("test setup: tempdir");
        let path = dir.path().join("adcs.db");
        {
            let store = ConfigStore::open(&path, None).expect("test setup: open");
            store
                .upsert_adcs_authority(&sample_adcs_authority("adcs-1"))
                .expect("upsert");
            store
                .set_adcs_failed("ticket_acquisition", Some(18))
                .expect("entry");
        }
        let reopened = ConfigStore::open(&path, None).expect("test setup: reopen");
        let read = reopened.get_adcs_authority().expect("read").expect("row");
        assert!(read.is_failed());
        assert_eq!(read.failed_kdc_code, Some(18));
    }

    #[test]
    fn the_authority_is_absent_from_the_canonical_blob() {
        let store = keyed_store();
        store
            .upsert_adcs_authority(&sample_adcs_authority("adcs-1"))
            .expect("upsert");
        store.set_adcs_password(Some(PASSWORD)).expect("password");
        store.set_adcs_failed("spnego", Some(7)).expect("fail");
        store
            .create_certificate(&certificate("web", Some("adcs-1")))
            .expect("test setup: cert");

        let bytes = crate::canonical::canonical_bytes(&store).expect("encode");
        let text = String::from_utf8(bytes).expect("the blob is UTF-8");
        assert!(!mentions_the_authority(&text), "{text}");
        assert!(!text.contains("horse"), "{text}");
        let value: serde_json::Value = serde_json::from_str(&text).expect("the blob is JSON");
        assert!(!has_key(&value, "adcs_authority"), "{text}");
        // The certificate it issued does travel, with its reference
        // (PRD D13): followers serve it without the authority row.
        assert_eq!(value["certificates"][0]["adcs_authority_id"], "adcs-1");
    }

    #[test]
    fn the_authority_is_absent_from_the_export() {
        let store = keyed_store();
        store
            .upsert_adcs_authority(&sample_adcs_authority("adcs-1"))
            .expect("upsert");
        store.set_adcs_password(Some(PASSWORD)).expect("password");
        store
            .create_certificate(&certificate("web", Some("adcs-1")))
            .expect("test setup: cert");

        let toml_text = crate::export::export_to_toml(&store).expect("export");
        assert!(!mentions_the_authority(&toml_text), "{toml_text}");
        assert!(!toml_text.contains("horse"), "{toml_text}");
        let parsed: toml::Value = toml::from_str(&toml_text).expect("the export is TOML");
        let value = serde_json::to_value(parsed).expect("test setup: TOML to JSON");
        assert!(!has_key(&value, "adcs_authority"), "{toml_text}");
    }

    fn import_data(certificates: Vec<Certificate>) -> crate::import::ImportData {
        crate::import::ImportData {
            version: 1,
            global_settings: GlobalSettings::default(),
            routes: Vec::new(),
            backends: Vec::new(),
            route_backends: Vec::new(),
            certificates,
            notification_configs: Vec::new(),
            user_preferences: Vec::new(),
            users: Vec::new(),
        }
    }

    #[test]
    fn importing_a_certificate_of_a_missing_authority_makes_it_manual_with_a_warning() {
        let store = keyed_store();
        let warnings = crate::import::import_to_store(
            &store,
            &import_data(vec![
                certificate("orphan", Some("adcs-elsewhere")),
                certificate("manual", None),
            ]),
        )
        .expect("import");

        let orphan = store.get_certificate("orphan").expect("read").expect("row");
        assert_eq!(orphan.source(), CertificateSource::Manual);
        assert!(orphan.adcs_authority_id.is_none());
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("orphan"), "{warnings:?}");
        assert!(warnings[0].contains("adcs-elsewhere"), "{warnings:?}");
    }

    #[test]
    fn importing_a_certificate_of_this_nodes_authority_keeps_it_adcs() {
        let store = keyed_store();
        store
            .upsert_adcs_authority(&sample_adcs_authority("adcs-1"))
            .expect("upsert");
        let warnings = crate::import::import_to_store(
            &store,
            &import_data(vec![certificate("web", Some("adcs-1"))]),
        )
        .expect("import");

        assert!(warnings.is_empty(), "{warnings:?}");
        let web = store.get_certificate("web").expect("read").expect("row");
        assert_eq!(web.source(), CertificateSource::Adcs);
        assert!(
            store.get_adcs_authority().expect("read").is_some(),
            "an import replaces the exported tables, and the authority is not one of them"
        );
    }
}
