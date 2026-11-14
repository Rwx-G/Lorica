//! The typed backend health check (Story 12.1, D-2).
//!
//! Until 1.11.0 a backend's active check was described by one column,
//! `health_check_path`: a path meant an HTTP GET, no path a TCP connect.
//! [`HealthCheck`] names the kind instead, so a kind that is neither
//! (a send/expect exchange, a UDP probe) is a variant here rather than a
//! new column. `health_check_path` stays, written beside the typed
//! definition, because a 1.10.6 binary opening a 1.11.0 database after a
//! hot-upgrade rollback reads and writes that column only.
//! [`HealthCheck::reconcile`] is the one place the two are made to agree.

use serde::{Deserialize, Serialize};

use super::backend::Backend;

/// How the health loop actively probes a backend.
///
/// Whether it probes at all is `Backend::health_check_enabled`, and how
/// often is `Backend::health_check_interval_s`; this type only says
/// what one probe is.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HealthCheck {
    /// An HTTP GET of `path` on the backend; a 2xx or 3xx answer is
    /// healthy. HTTP routes only: a stream never speaks HTTP to its
    /// backends.
    Http {
        /// The request path, e.g. `/healthz`, query string included.
        path: String,
    },
    /// A TCP connection that completes is healthy. The default, and
    /// what every backend without a path was probed by before 1.11.0.
    #[default]
    TcpConnect,
}

impl HealthCheck {
    /// The value this definition writes into the legacy
    /// `health_check_path` column: the path of an HTTP check, `None` for
    /// every other kind.
    pub fn legacy_path(&self) -> Option<&str> {
        match self {
            Self::Http { path } => Some(path.as_str()),
            Self::TcpConnect => None,
        }
    }

    /// The definition a backend row is read as, from its stored typed
    /// definition and its stored legacy path.
    ///
    /// The typed definition is honoured only while its projection onto
    /// the legacy column ([`HealthCheck::legacy_path`]) equals the stored
    /// path. When the two disagree, the row was last written by a binary
    /// that does not know the typed column (a 1.10.6 rollback), and the
    /// path is the truth: `Some(p)` reads as an HTTP check of `p`, `None`
    /// as a TCP connect. "Typed wins" would instead let a re-upgrade
    /// resurrect a probe the operator replaced while rolled back.
    ///
    /// The result's projection always equals `legacy_path`, so a reader
    /// sees one consistent pair whichever branch was taken.
    pub fn reconcile(stored: Option<HealthCheck>, legacy_path: Option<&str>) -> HealthCheck {
        match stored {
            Some(typed) if typed.legacy_path() == legacy_path => typed,
            _ => match legacy_path {
                Some(path) => Self::Http {
                    path: path.to_string(),
                },
                None => Self::TcpConnect,
            },
        }
    }
}

impl Backend {
    /// Set the active check, keeping the deprecated
    /// `health_check_path` equal to its projection.
    ///
    /// Assigning `health_check` alone leaves the pair disagreeing, and
    /// the store resolves a disagreement in favour of the path
    /// ([`HealthCheck::reconcile`]), so a writer that wants the typed
    /// value to stick goes through this setter.
    pub fn set_health_check(&mut self, check: HealthCheck) {
        self.health_check_path = check.legacy_path().map(str::to_string);
        self.health_check = check;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http(path: &str) -> HealthCheck {
        HealthCheck::Http {
            path: path.to_string(),
        }
    }

    /// The D-2 matrix: (stored typed, stored path, read as).
    fn matrix() -> Vec<(Option<HealthCheck>, Option<&'static str>, HealthCheck)> {
        vec![
            // Written by 1.10.6 or earlier.
            (None, None, HealthCheck::TcpConnect),
            (None, Some("/h"), http("/h")),
            // Written by 1.11.0.
            (Some(http("/h")), Some("/h"), http("/h")),
            (Some(HealthCheck::TcpConnect), None, HealthCheck::TcpConnect),
            // 1.10.6 edited the path after 1.11.0 wrote the row.
            (Some(http("/h")), Some("/x"), http("/x")),
            // 1.10.6 cleared the path.
            (Some(http("/h")), None, HealthCheck::TcpConnect),
            // 1.10.6 set a path on a TCP-checked backend.
            (Some(HealthCheck::TcpConnect), Some("/x"), http("/x")),
        ]
    }

    #[test]
    fn reconcile_reads_every_row_of_the_rollback_matrix() {
        for (stored, path, expected) in matrix() {
            let got = HealthCheck::reconcile(stored.clone(), path);
            assert_eq!(got, expected, "stored {stored:?}, path {path:?}");
            assert_eq!(
                got.legacy_path(),
                path,
                "the reconciled definition projects onto the stored path"
            );
        }
    }

    #[test]
    fn the_wire_shape_is_tagged_by_kind() {
        assert_eq!(
            serde_json::to_value(http("/healthz")).expect("serialize"),
            serde_json::json!({"kind": "http", "path": "/healthz"})
        );
        assert_eq!(
            serde_json::to_value(HealthCheck::TcpConnect).expect("serialize"),
            serde_json::json!({"kind": "tcp_connect"})
        );
        let parsed: HealthCheck =
            serde_json::from_str(r#"{"kind":"tcp_connect"}"#).expect("tcp_connect parses");
        assert_eq!(parsed, HealthCheck::TcpConnect);
        assert!(serde_json::from_str::<HealthCheck>(r#"{"kind":"http"}"#).is_err());
        assert!(
            serde_json::from_str::<HealthCheck>(r#"{"kind":"http","path":"/h","port":1}"#).is_err(),
            "an unknown field is refused"
        );
        assert!(serde_json::from_str::<HealthCheck>(r#"{"kind":"icmp"}"#).is_err());
    }

    #[test]
    fn the_setter_keeps_the_legacy_path_in_step() {
        let mut backend: Backend = serde_json::from_value(serde_json::json!({
            "id": "b-1",
            "address": "192.0.2.10:80",
            "weight": 1,
            "health_status": "healthy",
            "health_check_enabled": true,
            "health_check_interval_s": 10,
            "lifecycle_state": "normal",
            "active_connections": 0,
            "tls_upstream": false,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }))
        .expect("test setup: a backend without health_check deserialises");
        assert_eq!(backend.health_check, HealthCheck::TcpConnect);
        backend.set_health_check(http("/ready"));
        assert_eq!(backend.health_check_path.as_deref(), Some("/ready"));
        backend.set_health_check(HealthCheck::TcpConnect);
        assert_eq!(backend.health_check_path, None);
        assert_eq!(backend.health_check, HealthCheck::TcpConnect);
    }
}
