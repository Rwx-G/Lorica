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

//! Every stream mutation lands in the audit chain with its origin
//! (Story 12.10 D-h): the stream handlers' rows, one row per stream a
//! TOML import changes, and one per stream a backend delete cascades
//! out of.

use std::collections::{BTreeMap, BTreeSet};

use axum::http::StatusCode;
use chrono::Utc;
use lorica_config::models::{Stream, StreamBackend, StreamProtocol};
use lorica_config::ConfigStore;
use serde_json::{json, Value};

use super::tests::{tcp, without_bind, Node};
use crate::audit::{hash_payload, AuditRecord};

/// Every audit row of `node`, oldest first.
async fn every_row(node: &Node) -> Vec<AuditRecord> {
    let log_store = node.state.log_store.clone().expect("log store");
    log_store.flush_audit().await.expect("the audit drains");
    let (mut rows, _) = log_store
        .query_audit(&crate::audit::AuditQuery {
            operator: None,
            action_prefix: None,
            from: None,
            to: None,
            limit: 1000,
            before_id: None,
            node_id: None,
        })
        .expect("audit query");
    rows.reverse();
    rows
}

/// The rows written since `seen` rows were.
async fn rows_since(node: &Node, seen: usize) -> Vec<AuditRecord> {
    every_row(node).await.split_off(seen)
}

/// The role the test session's admin holds, read from the store.
async fn admin_role(node: &Node) -> String {
    node.state
        .store
        .lock()
        .await
        .list_users()
        .expect("users")
        .into_iter()
        .find(|user| user.username == "admin")
        .expect("the admin")
        .role
        .as_str()
        .to_string()
}

/// Every stream as the list answers it, less `bind`, by id.
async fn listed_views(node: &Node) -> BTreeMap<String, Value> {
    let (status, listed) = node.call("GET", "/api/v1/streams", None).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    listed["data"]["streams"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|read| {
            let view = without_bind(read);
            (id_of(&view), view)
        })
        .collect()
}

fn id_of(view: &Value) -> String {
    view["id"].as_str().expect("an id").to_string()
}

/// [`tcp`] linking `primaries` and `backups`.
fn linked(name: &str, port: u16, primaries: &[&str], backups: &[&str]) -> Value {
    let mut body = tcp(name, port);
    body["backend_ids"] = json!(primaries);
    body["backup_backend_ids"] = json!(backups);
    body
}

/// A TCP stream on `0.0.0.0:port`, as a file would carry it.
fn file_stream(name: &str, port: u16) -> Stream {
    Stream::new(
        uuid::Uuid::new_v4().to_string(),
        name.to_string(),
        StreamProtocol::Tcp,
        "0.0.0.0".parse().expect("an address"),
        port,
        port,
        Utc::now(),
    )
}

/// A file carrying this node's backends, streams and stream links,
/// edited by `edit`. Built in a scratch store rather than from the
/// node's own export, which redacts what an import refuses to take back
/// (the users' password hashes among them).
async fn export_edited(node: &Node, edit: impl FnOnce(&ConfigStore)) -> String {
    let scratch = ConfigStore::open_in_memory().expect("test setup: scratch store");
    {
        let store = node.state.store.lock().await;
        for backend in store.list_backends().expect("backends") {
            scratch
                .create_backend(&backend)
                .expect("test setup: backend");
        }
        for stream in store.list_streams().expect("streams") {
            scratch.create_stream(&stream).expect("test setup: stream");
        }
        let mut links: BTreeMap<String, Vec<StreamBackend>> = BTreeMap::new();
        for link in store.list_stream_backends().expect("links") {
            links.entry(link.stream_id.clone()).or_default().push(link);
        }
        for (stream_id, links) in links {
            scratch
                .set_stream_links(&stream_id, &links)
                .expect("test setup: links");
        }
    }
    edit(&scratch);
    lorica_config::export::export_to_toml(&scratch).expect("test setup: export")
}

/// The stream ids the import preview names, from its stream diff and its
/// stream link diff (`"<name> (<id>)"` and `"<stream> -> <backend>"`).
fn previewed_stream_ids(preview: &Value) -> BTreeSet<String> {
    let entries = |entity: &str| -> Vec<String> {
        ["added", "modified", "removed"]
            .iter()
            .flat_map(|change| {
                preview[entity][change]
                    .as_array()
                    .expect("a change list")
                    .iter()
                    .map(|entry| entry.as_str().expect("a label").to_string())
                    .collect::<Vec<String>>()
            })
            .collect()
    };
    let streams = entries("streams").into_iter().map(|label| {
        label
            .rsplit_once(" (")
            .and_then(|(_, id)| id.strip_suffix(')'))
            .expect("a `name (id)` label")
            .to_string()
    });
    let links = entries("stream_backends").into_iter().map(|label| {
        label
            .split_once(" -> ")
            .expect("a `stream -> backend` label")
            .0
            .to_string()
    });
    streams.chain(links).collect()
}

#[tokio::test]
async fn an_import_writes_one_row_per_stream_it_changes_with_the_views_it_moved_between() {
    let node = Node::standalone().await;
    let first = node.backend("192.0.2.10:25").await;
    let second = node.backend("192.0.2.11:25").await;
    let kept = id_of(&node.created(linked("kept", 2525, &[&first], &[])).await);
    let edited = id_of(&node.created(linked("edited", 2526, &[&first], &[])).await);
    let relinked = id_of(&node.created(linked("relinked", 2527, &[&first], &[])).await);
    let gone = id_of(&node.created(linked("gone", 2528, &[], &[])).await);
    let added = file_stream("added", 2529);

    let file = export_edited(&node, |scratch| {
        let mut stream = scratch
            .get_stream(&edited)
            .expect("read")
            .expect("the edited stream");
        stream.max_connections = 64;
        scratch.update_stream(&stream).expect("test setup: edit");
        scratch
            .set_stream_backends(&relinked, std::slice::from_ref(&second))
            .expect("test setup: relink");
        scratch.delete_stream(&gone).expect("test setup: remove");
        scratch.create_stream(&added).expect("test setup: add");
    })
    .await;
    let body = json!({ "toml_content": file });
    let (status, preview) = node
        .call("POST", "/api/v1/config/import/preview", Some(body.clone()))
        .await;
    assert_eq!(status, StatusCode::OK, "{preview}");

    let before = listed_views(&node).await;
    let seen = every_row(&node).await.len();
    let (status, answer) = node.call("POST", "/api/v1/config/import", Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let after = listed_views(&node).await;
    let rows = rows_since(&node, seen).await;

    // The single import row comes first, with no payload, as before.
    let (import_row, stream_rows) = rows.split_first().expect("the import wrote rows");
    assert_eq!(import_row.action, "config.import");
    assert_eq!(
        (
            import_row.before_payload_hash.as_str(),
            import_row.after_payload_hash.as_str()
        ),
        ("", "")
    );

    // Then one row per changed stream, by id, each carrying the views
    // the list answered before and after.
    let hash = |view: Option<&Value>| hash_payload(view);
    let mut expected: Vec<(String, &str, String, String)> = vec![
        (
            added.id.clone(),
            "stream.create",
            String::new(),
            hash(after.get(&added.id)),
        ),
        (
            edited.clone(),
            "stream.update",
            hash(before.get(&edited)),
            hash(after.get(&edited)),
        ),
        (
            relinked.clone(),
            "stream.update",
            hash(before.get(&relinked)),
            hash(after.get(&relinked)),
        ),
        (
            gone.clone(),
            "stream.delete",
            hash(before.get(&gone)),
            String::new(),
        ),
    ];
    expected.sort();
    let written: Vec<(String, &str, String, String)> = stream_rows
        .iter()
        .map(|row| {
            assert_eq!(row.target_type, "stream");
            assert_eq!(
                (&row.operator_username, &row.operator_role),
                (&import_row.operator_username, &import_row.operator_role),
                "the importer is every row's actor"
            );
            (
                row.target_id.clone(),
                row.action.as_str(),
                row.before_payload_hash.clone(),
                row.after_payload_hash.clone(),
            )
        })
        .collect();
    assert_eq!(written, expected);
    assert!(
        !written.iter().any(|(id, ..)| *id == kept),
        "a stream the file carries unchanged gets no row"
    );
    assert_eq!(
        before
            .get(&kept)
            .map(|view| view["max_connections"].clone()),
        after.get(&kept).map(|view| view["max_connections"].clone()),
    );

    // The changed set is the one the preview showed: its stream diff
    // and its link diff together.
    let rows_named: BTreeSet<String> = written.iter().map(|(id, ..)| id.clone()).collect();
    assert_eq!(rows_named, previewed_stream_ids(&preview["data"]));

    // And an import of the same file again changes nothing.
    let seen = every_row(&node).await.len();
    let file = export_edited(&node, |_| {}).await;
    let (status, answer) = node
        .call(
            "POST",
            "/api/v1/config/import",
            Some(json!({ "toml_content": file })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let actions: Vec<String> = rows_since(&node, seen)
        .await
        .into_iter()
        .map(|row| row.action)
        .collect();
    assert_eq!(actions, vec!["config.import".to_string()]);
}

#[tokio::test]
async fn a_backend_delete_writes_one_unlink_row_per_stream_that_held_it() {
    let node = Node::standalone().await;
    let shared = node.backend("192.0.2.10:25").await;
    let other = node.backend("192.0.2.11:25").await;
    let as_primary = id_of(&node.created(linked("smtp", 2525, &[&shared], &[])).await);
    let as_backup = id_of(
        &node
            .created(linked("imap", 2526, &[&other], &[&shared]))
            .await,
    );
    let unrelated = id_of(&node.created(linked("pop", 2527, &[&other], &[])).await);

    let seen = every_row(&node).await.len();
    let (status, answer) = node
        .call("DELETE", &format!("/api/v1/backends/{shared}"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let rows = rows_since(&node, seen).await;

    let (backend_row, unlinked) = rows.split_first().expect("the delete wrote rows");
    assert_eq!(
        (backend_row.action.as_str(), backend_row.target_id.as_str()),
        ("backend.delete", shared.as_str())
    );
    let unlink = |was_backup: bool| {
        hash_payload(Some(
            &json!({ "backend_id": shared, "was_backup": was_backup, "rule": null }),
        ))
    };
    let mut expected = vec![
        (as_primary.clone(), String::new(), unlink(false)),
        (as_backup.clone(), String::new(), unlink(true)),
    ];
    expected.sort();
    let mut written: Vec<(String, String, String)> = unlinked
        .iter()
        .map(|row| {
            assert_eq!(row.action, "stream.backend_unlinked");
            assert_eq!(row.target_type, "stream");
            assert_eq!(
                (&row.operator_username, &row.operator_role),
                (&backend_row.operator_username, &backend_row.operator_role),
                "the backend's actor is every row's actor"
            );
            (
                row.target_id.clone(),
                row.before_payload_hash.clone(),
                row.after_payload_hash.clone(),
            )
        })
        .collect();
    written.sort();
    assert_eq!(written, expected);
    assert!(!written.iter().any(|(id, ..)| *id == unrelated));
}

#[tokio::test]
async fn every_stream_write_path_lands_a_chained_row_with_its_origin() {
    // D-h's table, walked: each path, the row it writes for the stream,
    // the target and the actor's role, then the chain verified whole.
    let node = Node::standalone().await;
    let role = admin_role(&node).await;
    let backend = node.backend("192.0.2.10:25").await;

    let seen = every_row(&node).await.len();
    let stream = id_of(&node.created(linked("smtp", 2525, &[&backend], &[])).await);
    let mut walked: Vec<(&str, String)> = vec![("stream.create", stream.clone())];

    for patch in [
        json!({ "max_connections": 64 }),
        json!({ "enabled": false }),
    ] {
        let (status, answer) = node.update(&stream, patch).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        walked.push(("stream.update", stream.clone()));
    }

    let imported = file_stream("imap", 2526);
    let file = export_edited(&node, |scratch| {
        scratch
            .create_stream(&imported)
            .expect("test setup: a stream the file adds");
    })
    .await;
    let (status, answer) = node
        .call(
            "POST",
            "/api/v1/config/import",
            Some(json!({ "toml_content": file })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    walked.push(("stream.create", imported.id.clone()));

    let (status, answer) = node
        .call("DELETE", &format!("/api/v1/backends/{backend}"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    walked.push(("stream.backend_unlinked", stream.clone()));

    let (status, answer) = node
        .call("DELETE", &format!("/api/v1/streams/{stream}"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    walked.push(("stream.delete", stream.clone()));

    let written: Vec<(String, String)> = rows_since(&node, seen)
        .await
        .into_iter()
        .filter(|row| row.action.starts_with("stream."))
        .map(|row| {
            assert_eq!(row.target_type, "stream", "{}", row.action);
            assert_eq!(row.operator_role, role, "{}", row.action);
            (row.action, row.target_id)
        })
        .collect();
    let walked: Vec<(String, String)> = walked
        .into_iter()
        .map(|(action, id)| (action.to_string(), id))
        .collect();
    assert_eq!(written, walked);

    let verdict = node
        .state
        .log_store
        .clone()
        .expect("log store")
        .verify_audit_chain()
        .expect("the chain reads");
    assert!(verdict.verified, "{verdict:?}");
}
