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

//! The dry-run variant of a management write (Story 11.2 AC #3): the
//! change a write would make, computed by the write's own body and
//! never stored.
//!
//! # Why the plane owns the preview
//!
//! AC #3 asks every mutating MCP tool for a counterpart that answers
//! the change it would make, against the current state, without making
//! it. AC #5 says validation is the API's and that `lorica-mcp`
//! reimplements no field check. Those two meet only here: a preview
//! computed by the MCP server would be a second implementation of the
//! defaults, the normalisation and the validators, and it would show a
//! change the apply then refuses. So the preview is the write handler
//! itself, run in [`WriteMode::Preview`]: it validates, it builds the
//! row it would store, and it stops before the store, the reload
//! signal and the audit row. What it answers is that row's view, and
//! for a patch the view before it beside the field-level difference.
//!
//! # What a preview can and cannot promise
//!
//! It runs every check the handler runs before it writes, the target
//! guard of [`crate::target`] included, so a change the grant refuses
//! is refused by the preview too. What only the store refuses on the
//! write itself, a duplicate hostname or a backend id that names
//! nothing, is refused by the apply and not by the preview, since the
//! preview makes no insert. The protocol offers no way to make a client
//! call the preview first either:
//! `docs/mcp.md` says in those terms that it is an affordance and not a
//! control.
//!
//! # The shape is data, not prose
//!
//! `{"dry_run": true, "operation", "before", "after", "changes"}`, with
//! `changes` a map of field name to `{"from", "to"}` over the two views.
//! The MCP server fences the whole of it as untrusted data like any
//! other answer, so a diff rendered in words would be prose about
//! configuration a model is about to act on; this is JSON it can read
//! and an operator can diff.

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::error::json_data;

/// Whether a write is made or only computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    /// Validate, store, signal the reload, write the audit row.
    Apply,
    /// Validate, build what would be stored, and answer it.
    Preview,
}

impl WriteMode {
    /// Whether this mode stops before the store.
    pub fn previews(self) -> bool {
        matches!(self, WriteMode::Preview)
    }
}

/// `?dry_run=true` on a write path of the automation plane.
///
/// A query parameter rather than a header or a path of its own, because
/// the scope matrix and the audit layer both read the path: a preview
/// sits behind the same scope as the write by construction, and the row
/// records `?dry_run` beside the verb the way it records any other
/// parameter name. Absent or `false` is the write.
///
/// `deny_unknown_fields`, because the one thing this query decides is
/// whether a write happens: `?dryrun=true` typed by hand into a direct
/// client was an apply, the key ignored. Any key that is not `dry_run`
/// is a 400 now. No management handler extracts this type, so the
/// dashboard's contract is untouched.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DryRunQuery {
    /// `true` to compute the change and write nothing.
    #[serde(default)]
    pub dry_run: bool,
}

impl DryRunQuery {
    /// The mode this query asks for.
    pub fn mode(&self) -> WriteMode {
        if self.dry_run {
            WriteMode::Preview
        } else {
            WriteMode::Apply
        }
    }
}

impl From<DryRunQuery> for WriteMode {
    fn from(query: DryRunQuery) -> WriteMode {
        query.mode()
    }
}

/// The answer a previewed write gives in place of the row it did not
/// store.
///
/// `before` is the view the resource has now (`None` on a create),
/// `after` the view it would have (`None` on a delete and on an action
/// that keeps the row, such as a renewal). A create's `after` is
/// stripped of the id and the clock, since a row that does not exist
/// has neither and the apply would mint its own.
pub fn previewed(
    operation: &str,
    before: Option<Value>,
    after: Option<Value>,
) -> axum::Json<Value> {
    let after = after.map(|mut view| {
        if before.is_none() {
            if let Some(object) = view.as_object_mut() {
                for minted_on_apply in ["id", "created_at", "updated_at"] {
                    object.remove(minted_on_apply);
                }
            }
        }
        view
    });
    let changes = match (&before, &after) {
        (Some(before), Some(after)) => Some(changes_between(before, after)),
        _ => None,
    };
    json_data(json!({
        "dry_run": true,
        "operation": operation,
        "before": before,
        "after": after,
        "changes": changes,
    }))
}

/// The fields whose value differs between two views, each as
/// `{"from", "to"}`, with a field on one side only reported against
/// `null`.
///
/// The one field a patch always moves, `updated_at`, is left out: it
/// is the clock's and not the caller's, and the apply will set it
/// again.
pub fn changes_between(before: &Value, after: &Value) -> Value {
    let empty = Map::new();
    let before = before.as_object().unwrap_or(&empty);
    let after = after.as_object().unwrap_or(&empty);
    let mut changes = Map::new();
    for name in before.keys().chain(after.keys()) {
        if name == "updated_at" || changes.contains_key(name) {
            continue;
        }
        let from = before.get(name).cloned().unwrap_or(Value::Null);
        let to = after.get(name).cloned().unwrap_or(Value::Null);
        if from != to {
            changes.insert(name.clone(), json!({ "from": from, "to": to }));
        }
    }
    Value::Object(changes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_preview_carries_the_two_views_and_the_fields_that_differ() {
        let before =
            json!({ "id": "r-1", "waf_enabled": false, "hostname": "a", "updated_at": "t0" });
        let after =
            json!({ "id": "r-1", "waf_enabled": true, "hostname": "a", "updated_at": "t1" });
        let answered = previewed("update", Some(before.clone()), Some(after.clone())).0;
        assert_eq!(answered["data"]["dry_run"], json!(true));
        assert_eq!(answered["data"]["operation"], json!("update"));
        assert_eq!(answered["data"]["before"], before);
        assert_eq!(answered["data"]["after"], after);
        assert_eq!(
            answered["data"]["changes"],
            json!({ "waf_enabled": { "from": false, "to": true } })
        );
    }

    #[test]
    fn a_created_row_has_no_id_and_no_clock_yet_and_a_deleted_one_no_after() {
        let created = previewed(
            "create",
            None,
            Some(
                json!({ "id": "would-be", "hostname": "a", "created_at": "t", "updated_at": "t" }),
            ),
        )
        .0;
        assert_eq!(created["data"]["after"], json!({ "hostname": "a" }));
        assert_eq!(created["data"]["before"], Value::Null);
        assert_eq!(created["data"]["changes"], Value::Null);

        let deleted = previewed("delete", Some(json!({ "id": "r-1" })), None).0;
        assert_eq!(deleted["data"]["before"], json!({ "id": "r-1" }));
        assert_eq!(deleted["data"]["after"], Value::Null);
        assert_eq!(deleted["data"]["changes"], Value::Null);
    }

    #[test]
    fn a_field_on_one_side_only_is_reported_against_null() {
        let changes = changes_between(
            &json!({ "name": "a", "gone": 1 }),
            &json!({ "name": "a", "added": 2 }),
        );
        assert_eq!(
            changes,
            json!({ "gone": { "from": 1, "to": null }, "added": { "from": null, "to": 2 } })
        );
    }

    #[test]
    fn dry_run_is_read_from_the_query_and_absent_means_the_write() {
        let previewing: DryRunQuery = serde_json::from_str(r#"{"dry_run": true}"#).expect("parses");
        assert_eq!(WriteMode::from(previewing), WriteMode::Preview);
        let absent: DryRunQuery = serde_json::from_str(r#"{}"#).expect("parses");
        assert_eq!(WriteMode::from(absent), WriteMode::Apply);
        assert!(WriteMode::Preview.previews());
        assert!(!WriteMode::Apply.previews());
    }

    #[test]
    fn a_key_that_is_not_dry_run_is_refused_rather_than_read_as_the_write() {
        // The whole-stack case, through the handlers' `Query` extractor,
        // is `a_mistyped_dry_run_is_refused_and_never_an_apply` in
        // `crate::tests`; this pins the attribute itself, which serde
        // applies the same way whatever the format.
        for query in [
            r#"{"dryrun": true}"#,
            r#"{"dry-run": true}"#,
            r#"{"dry_run": true, "dryrun": true}"#,
        ] {
            assert!(
                serde_json::from_str::<DryRunQuery>(query).is_err(),
                "{query} was read"
            );
        }
        let previewing: DryRunQuery = serde_json::from_str(r#"{"dry_run": true}"#).expect("parses");
        assert_eq!(previewing.mode(), WriteMode::Preview);
    }
}
