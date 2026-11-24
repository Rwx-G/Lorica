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

//! What a pass reports (D-h): the events, the audit row each one
//! writes and the alert a failed bind raises.

use lorica_stream::{BindFailureKind, BindKey, ReleaseCause};

/// What a pass did, for the audit chain and the log (D-h).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PlaneEvent {
    /// A binding is held and attached (`stream.bind`).
    Bound {
        /// The binding.
        key: BindKey,
        /// Its generation.
        bind_gen: u64,
        /// Workers that acknowledged it.
        workers_serving: u32,
        /// Workers on the node.
        workers: u32,
    },
    /// A binding was released (`stream.release`).
    Released {
        /// The binding.
        key: BindKey,
        /// Its generation.
        bind_gen: u64,
        /// Why.
        cause: ReleaseCause,
    },
    /// A binding entered the failed state (`stream.bind_failed` and the
    /// `stream_bind_failed` alert), once per entry, never per retry.
    BindFailed {
        /// The binding.
        key: BindKey,
        /// The stream's name, which the alert carries and the key does
        /// not.
        name: String,
        /// The classification.
        kind: BindFailureKind,
        /// The OS error, or the node-side check's own sentence.
        os_error: String,
        /// The port that failed.
        port: u16,
    },
}

/// The `stream_bind_failed` alert of one entry into the failed state
/// (D-h), raised where its `stream.bind_failed` audit row is written.
pub(super) fn bind_failed_alert(
    node: &str,
    stream_id: &str,
    name: &str,
    kind: BindFailureKind,
    os_error: &str,
    port: u16,
) -> lorica_notify::AlertEvent {
    lorica_notify::AlertEvent::new(
        lorica_notify::events::AlertType::StreamBindFailed,
        format!("stream `{name}` failed to bind port {port} on {node}: {os_error}"),
    )
    .with_detail("stream_id", stream_id)
    .with_detail("stream_name", name)
    .with_detail("node", node)
    .with_detail("kind", kind.as_str())
    .with_detail("os_error", os_error)
    .with_detail("port", port.to_string())
}

/// The audit action, binding and hashed payload of `event` (D-h).
pub(super) fn audit_row<'a>(
    node: &str,
    event: &'a PlaneEvent,
) -> (&'static str, &'a BindKey, serde_json::Value) {
    let base = |key: &BindKey| {
        serde_json::json!({
            "node": node,
            "address": key.listen_address.to_string(),
            "port_first": key.port_first,
            "port_last": key.port_last,
            "protocol": key.protocol.as_str(),
        })
    };
    match event {
        PlaneEvent::Bound {
            key,
            bind_gen,
            workers_serving,
            workers,
        } => {
            let mut payload = base(key);
            payload["bind_gen"] = (*bind_gen).into();
            payload["workers_serving"] = (*workers_serving).into();
            payload["workers"] = (*workers).into();
            ("stream.bind", key, payload)
        }
        PlaneEvent::Released {
            key,
            bind_gen,
            cause,
        } => {
            let mut payload = base(key);
            payload["bind_gen"] = (*bind_gen).into();
            payload["cause"] = cause.as_str().into();
            ("stream.release", key, payload)
        }
        // The name is for the alert: the row names the stream by its
        // target id, like every other `stream.*` row.
        PlaneEvent::BindFailed {
            key,
            name: _,
            kind,
            os_error,
            port,
        } => {
            let mut payload = base(key);
            payload["kind"] = kind.as_str().into();
            payload["os_error"] = os_error.as_str().into();
            payload["port"] = (*port).into();
            ("stream.bind_failed", key, payload)
        }
    }
}
