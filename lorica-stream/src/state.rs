// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Bind state per (stream, node), Story 12.2 D-h.
//!
//! The supervisor's registry is memory only: a restart recomputes it on
//! its first reconcile, so a failure that persists is reported again and
//! one that cleared is not invented. A failure is a value here, never an
//! error returned up the reconcile path, which is what keeps every other
//! listener unaffected by one stream's bind.

use std::collections::BTreeMap;
use std::sync::{Arc, PoisonError, RwLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer};

pub use lorica_worker::stream_sockets::BindFailureKind;

/// Why a binding is in [`BindState::Failed`], and since when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BindFailure {
    /// The classification an operator acts on.
    #[serde(serialize_with = "serialize_kind")]
    pub kind: BindFailureKind,
    /// The OS error's text (`Address already in use (os error 98)`), or
    /// the node-side check's own sentence for a refusal no syscall made.
    pub os_error: String,
    /// The port that failed; for a range, the first one that did.
    pub port: u16,
    /// When the binding entered the failed state. A retry that fails
    /// again keeps it.
    pub since: DateTime<Utc>,
}

fn serialize_kind<S: Serializer>(kind: &BindFailureKind, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(kind.as_str())
}

/// The bind state of one stream on one node.
///
/// Serialised as `{"state":"pending"}`,
/// `{"state":"bound","workers_serving":2,"workers":2}` or
/// `{"state":"failed","kind":"address_in_use","os_error":"...","port":5432,"since":"..."}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BindState {
    /// Desired here and not bound yet.
    Pending,
    /// The supervisor holds the sockets; `workers_serving` of `workers`
    /// acknowledged them.
    Bound {
        /// Workers that acknowledged every `attach` of the binding.
        workers_serving: u32,
        /// Workers on the node.
        workers: u32,
    },
    /// The last bind attempt failed.
    Failed(BindFailure),
}

/// The variant of a [`BindState`] without its data, and `unknown` for a
/// node whose state the control plane cannot vouch for (D-i).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindStateKind {
    /// See [`BindState::Pending`].
    Pending,
    /// See [`BindState::Bound`].
    Bound,
    /// See [`BindState::Failed`].
    Failed,
    /// No report, or the node is not in sync with the control plane.
    Unknown,
}

impl BindState {
    /// The variant without its data.
    pub fn kind(&self) -> BindStateKind {
        match self {
            BindState::Pending => BindStateKind::Pending,
            BindState::Bound { .. } => BindStateKind::Bound,
            BindState::Failed(_) => BindStateKind::Failed,
        }
    }
}

/// The supervisor's registry of bind states, keyed by stream id.
///
/// Cloning shares the registry: the reconcile driver writes through one
/// clone, the API and the heartbeat read through others.
#[derive(Debug, Clone, Default)]
pub struct StreamBindStates {
    inner: Arc<RwLock<BTreeMap<String, BindState>>>,
}

impl StreamBindStates {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    fn write<R>(&self, f: impl FnOnce(&mut BTreeMap<String, BindState>) -> R) -> R {
        // A panic while holding the lock leaves a map that is still
        // consistent (every write is a single insert or remove), so the
        // registry stays usable rather than failing every later reader.
        let mut guard = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        f(&mut guard)
    }

    fn read<R>(&self, f: impl FnOnce(&BTreeMap<String, BindState>) -> R) -> R {
        let guard = self.inner.read().unwrap_or_else(PoisonError::into_inner);
        f(&guard)
    }

    /// Mark `stream_id` pending. Returns the previous state.
    pub fn set_pending(&self, stream_id: &str) -> Option<BindState> {
        self.write(|m| m.insert(stream_id.to_string(), BindState::Pending))
    }

    /// Mark `stream_id` bound. Returns the previous state, so the caller
    /// can tell a recovery from a failure (`stream.bind` again, D-h).
    pub fn set_bound(
        &self,
        stream_id: &str,
        workers_serving: u32,
        workers: u32,
    ) -> Option<BindState> {
        self.write(|m| {
            m.insert(
                stream_id.to_string(),
                BindState::Bound {
                    workers_serving,
                    workers,
                },
            )
        })
    }

    /// Mark `stream_id` failed at `now`.
    ///
    /// Returns `true` when this is an entry into the failed state, which
    /// is when the `stream.bind_failed` audit row and the alert are owed
    /// (D-h); `false` for a retry that failed again, which keeps the
    /// original `since` and takes the latest kind, error and port.
    pub fn set_failed(
        &self,
        stream_id: &str,
        kind: BindFailureKind,
        os_error: String,
        port: u16,
        now: DateTime<Utc>,
    ) -> bool {
        self.write(|m| {
            let previous_since = match m.get(stream_id) {
                Some(BindState::Failed(f)) => Some(f.since),
                _ => None,
            };
            m.insert(
                stream_id.to_string(),
                BindState::Failed(BindFailure {
                    kind,
                    os_error,
                    port,
                    since: previous_since.unwrap_or(now),
                }),
            );
            previous_since.is_none()
        })
    }

    /// Forget `stream_id`: it is no longer desired on this node. Returns
    /// the previous state.
    pub fn remove(&self, stream_id: &str) -> Option<BindState> {
        self.write(|m| m.remove(stream_id))
    }

    /// The state of `stream_id`, `None` when it is not desired here.
    pub fn get(&self, stream_id: &str) -> Option<BindState> {
        self.read(|m| m.get(stream_id).cloned())
    }

    /// A copy of every state, for a reader that must not hold the lock.
    pub fn snapshot(&self) -> BTreeMap<String, BindState> {
        self.read(BTreeMap::clone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s)
            .expect("test setup: timestamp")
            .with_timezone(&Utc)
    }

    #[test]
    fn entering_failed_is_reported_once_and_keeps_its_since() {
        let states = StreamBindStates::new();
        states.set_pending("s1");
        let first = at("2026-11-14T10:00:00Z");
        assert!(states.set_failed(
            "s1",
            BindFailureKind::AddressInUse,
            "Address already in use (os error 98)".into(),
            5432,
            first,
        ));
        assert!(!states.set_failed(
            "s1",
            BindFailureKind::PermissionDenied,
            "Permission denied (os error 13)".into(),
            5432,
            at("2026-11-14T10:00:10Z"),
        ));
        match states.get("s1") {
            Some(BindState::Failed(f)) => {
                assert_eq!(f.since, first);
                assert_eq!(f.kind, BindFailureKind::PermissionDenied);
            }
            other => panic!("unexpected {other:?}"),
        }

        let previous = states.set_bound("s1", 2, 2);
        assert!(matches!(previous, Some(BindState::Failed(_))));
        assert!(states.set_failed(
            "s1",
            BindFailureKind::AddressInUse,
            "again".into(),
            5432,
            at("2026-11-14T11:00:00Z"),
        ));
    }

    #[test]
    fn clones_share_one_registry() {
        let writer = StreamBindStates::new();
        let reader = writer.clone();
        writer.set_bound("s1", 1, 2);
        assert_eq!(
            reader.get("s1"),
            Some(BindState::Bound {
                workers_serving: 1,
                workers: 2
            })
        );
        assert_eq!(reader.snapshot().len(), 1);
        assert!(writer.remove("s1").is_some());
        assert!(reader.get("s1").is_none());
    }

    #[test]
    fn serialises_to_the_api_shape() {
        let failed = BindState::Failed(BindFailure {
            kind: BindFailureKind::AddressInUse,
            os_error: "Address already in use (os error 98)".into(),
            port: 6000,
            since: at("2026-11-14T10:00:00Z"),
        });
        assert_eq!(
            serde_json::to_value(&failed).unwrap(),
            serde_json::json!({
                "state": "failed",
                "kind": "address_in_use",
                "os_error": "Address already in use (os error 98)",
                "port": 6000,
                "since": "2026-11-14T10:00:00Z",
            })
        );
        assert_eq!(
            serde_json::to_value(BindState::Bound {
                workers_serving: 3,
                workers: 4
            })
            .unwrap(),
            serde_json::json!({"state": "bound", "workers_serving": 3, "workers": 4})
        );
        assert_eq!(
            serde_json::to_value(BindState::Pending).unwrap(),
            serde_json::json!({"state": "pending"})
        );
        assert_eq!(
            serde_json::to_value(BindStateKind::Unknown).unwrap(),
            serde_json::json!("unknown")
        );
        assert_eq!(failed.kind(), BindStateKind::Failed);
    }
}
