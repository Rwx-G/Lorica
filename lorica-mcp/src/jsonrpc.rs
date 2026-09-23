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

//! The JSON-RPC envelope, and nothing that performs I/O.
//!
//! # One direction only
//!
//! MCP revision 2026-07-28 constrains the message directions: a server
//! does not initiate JSON-RPC requests and a client does not send
//! JSON-RPC responses. So this module parses requests and notifications
//! and builds results and errors, and has no type for a response
//! arriving nor for a request leaving. A general JSON-RPC peer would be
//! building a direction the protocol forbids, and the read tier needs
//! none of it.
//!
//! # The handshake is gone
//!
//! There is no `initialize` in this revision. Every request carries its
//! own metadata under `params._meta`, keyed in the
//! `io.modelcontextprotocol/` namespace, and the call that replaces the
//! handshake is `server/discover`. [`Request::protocol_version`] reads
//! that metadata when the client sends it.
//!
//! # Two error channels
//!
//! What this module builds is the PROTOCOL channel: a malformed
//! request, an unknown method, an unknown tool. A tool that ran and
//! failed is not one of these; it is an ordinary result carrying
//! `isError: true`, built in [`crate::untrusted`], and the difference
//! is what lets a model tell "you asked for something that does not
//! exist" from "the thing you asked for refused you".

use serde_json::{json, Value};

/// The only JSON-RPC version this speaks.
pub const JSONRPC_VERSION: &str = "2.0";

/// The `_meta` key carrying the protocol revision the client speaks.
///
/// Revision 2026-07-28 moved the version out of a handshake and into
/// per-request metadata under the `io.modelcontextprotocol/` namespace.
/// This constant is the single place that spelling is written down: if
/// the specification renames the key, one edit here moves the whole
/// crate, and until then a request that carries no such key is treated
/// as carrying no claim rather than as claiming the wrong thing.
pub const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";

/// JSON-RPC error codes this server answers with.
///
/// The named set is the standard one; the revision's own `-32020`
/// `HeaderMismatch` belongs to the Streamable HTTP binding and is
/// declared by the adapter that can raise it, not here, where nothing
/// reads a header.
pub mod code {
    /// The line was not JSON.
    pub const PARSE_ERROR: i64 = -32700;
    /// The JSON was not a JSON-RPC request.
    pub const INVALID_REQUEST: i64 = -32600;
    /// No such method, or no such tool.
    pub const METHOD_NOT_FOUND: i64 = -32601;
    /// The method exists and its parameters do not fit it.
    pub const INVALID_PARAMS: i64 = -32602;
    /// This server broke.
    pub const INTERNAL_ERROR: i64 = -32603;
}

/// One well-formed message from a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The correlation id, or `None` for a notification, which is
    /// answered by silence and never by an error.
    pub id: Option<Value>,
    /// The method name, verbatim.
    pub method: String,
    /// `params` if the client sent an object, else an empty object.
    pub params: Value,
}

impl Request {
    /// The protocol revision this request claims, if it claims one.
    ///
    /// Absent is not a claim: see [`META_PROTOCOL_VERSION`].
    pub fn protocol_version(&self) -> Option<&str> {
        self.params
            .get("_meta")?
            .get(META_PROTOCOL_VERSION)?
            .as_str()
    }

    /// Whether this message expects an answer at all.
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

/// Why a message could not be read as a request.
///
/// Carries the id when one was recoverable, because a client
/// correlating by id cannot match an answer that omits it, and a
/// malformed request that still named its id deserves a matched error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestError {
    /// The id to answer under, or `Value::Null` when none was legible.
    pub id: Value,
    /// The JSON-RPC code.
    pub code: i64,
    /// What is wrong, in terms an implementer can act on.
    pub message: String,
}

/// Read one JSON-RPC message.
///
/// # Errors
///
/// [`RequestError`] with [`code::INVALID_REQUEST`] for anything that is
/// JSON but not a request: a missing or wrong `jsonrpc`, a missing or
/// non-string `method`, an `id` that is neither string nor number, or
/// `params` that is present and not an object. `params` is normalised
/// to an empty object when absent, so every caller downstream reads one
/// shape.
pub fn parse(message: Value) -> Result<Request, RequestError> {
    // Recovered before anything else is judged, so a request that got
    // its id right still gets a matched answer when the rest is wrong.
    let id = match message.get("id") {
        None | Some(Value::Null) => None,
        Some(value @ (Value::String(_) | Value::Number(_))) => Some(value.clone()),
        Some(_) => {
            return Err(RequestError {
                id: Value::Null,
                code: code::INVALID_REQUEST,
                message: "id must be a string or a number".to_string(),
            })
        }
    };
    let answering = id.clone().unwrap_or(Value::Null);

    let refuse = |message: &str| RequestError {
        id: answering.clone(),
        code: code::INVALID_REQUEST,
        message: message.to_string(),
    };

    if message.get("jsonrpc").and_then(Value::as_str) != Some(JSONRPC_VERSION) {
        return Err(refuse("every message carries jsonrpc: \"2.0\""));
    }
    let Some(method) = message.get("method").and_then(Value::as_str) else {
        return Err(refuse("method is required and is a string"));
    };
    let params = match message.get("params") {
        None | Some(Value::Null) => json!({}),
        Some(object @ Value::Object(_)) => object.clone(),
        Some(_) => return Err(refuse("params, when present, is an object")),
    };

    Ok(Request {
        id,
        method: method.to_string(),
        params,
    })
}

/// A successful answer to the request carrying `id`.
pub fn result(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": JSONRPC_VERSION, "id": id, "result": result })
}

/// A protocol error answering the request carrying `id`.
pub fn error(id: &Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": id,
        "error": { "code": code, "message": message },
    })
}

/// The answer to a line that was not JSON at all.
///
/// Its id is null because there was no request to read one from, which
/// is what JSON-RPC prescribes and the only honest answer available.
pub fn parse_error() -> Value {
    error(&Value::Null, code::PARSE_ERROR, "the message is not JSON")
}

impl RequestError {
    /// This refusal as the message that goes back on the wire.
    pub fn into_response(self) -> Value {
        error(&self.id, self.code, &self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_parses_into_its_three_parts() {
        let parsed = parse(json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/list",
            "params": { "cursor": "abc" },
        }))
        .expect("a well-formed request");
        assert_eq!(parsed.id, Some(json!(7)));
        assert_eq!(parsed.method, "tools/list");
        assert_eq!(parsed.params["cursor"], json!("abc"));
        assert!(!parsed.is_notification());
    }

    #[test]
    fn absent_params_read_as_an_empty_object() {
        // One shape downstream: a method reading `params.name` must not
        // have to know whether the client omitted `params` entirely.
        let parsed = parse(json!({ "jsonrpc": "2.0", "id": 1, "method": "server/discover" }))
            .expect("params is optional");
        assert_eq!(parsed.params, json!({}));
    }

    #[test]
    fn a_message_with_no_id_is_a_notification_and_not_an_error() {
        let parsed = parse(json!({ "jsonrpc": "2.0", "method": "notifications/cancelled" }))
            .expect("a notification is well formed");
        assert!(parsed.is_notification());
    }

    #[test]
    fn a_malformed_request_is_answered_under_the_id_it_did_name() {
        // A client correlating by id cannot match an answer that omits
        // it, so the id is recovered before the rest is judged.
        let refused =
            parse(json!({ "id": 42, "method": "tools/list" })).expect_err("no jsonrpc member");
        assert_eq!(refused.id, json!(42));
        assert_eq!(refused.code, code::INVALID_REQUEST);
        assert_eq!(refused.into_response()["id"], json!(42));

        for malformed in [
            json!({ "jsonrpc": "1.0", "id": 1, "method": "tools/list" }),
            json!({ "jsonrpc": "2.0", "id": 1 }),
            json!({ "jsonrpc": "2.0", "id": 1, "method": 5 }),
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": [] }),
            json!({ "jsonrpc": "2.0", "id": { "not": "scalar" }, "method": "tools/list" }),
        ] {
            let refused = parse(malformed.clone()).expect_err("a malformed request is refused");
            assert_eq!(refused.code, code::INVALID_REQUEST, "{malformed}");
        }
    }

    #[test]
    fn the_protocol_version_is_read_from_the_request_metadata() {
        // The handshake is gone in this revision: the version travels
        // per request under `params._meta`.
        let parsed = parse(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": { "_meta": { META_PROTOCOL_VERSION: "2026-07-28" } },
        }))
        .expect("a well-formed request");
        assert_eq!(parsed.protocol_version(), Some("2026-07-28"));

        // Absent is no claim, not a wrong claim.
        let bare = parse(json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }))
            .expect("a well-formed request");
        assert_eq!(bare.protocol_version(), None);
    }

    #[test]
    fn a_result_and_an_error_carry_the_envelope_and_never_both() {
        let answered = result(&json!(3), json!({ "tools": [] }));
        assert_eq!(answered["jsonrpc"], json!(JSONRPC_VERSION));
        assert_eq!(answered["id"], json!(3));
        assert!(answered.get("error").is_none());

        let refused = error(&json!(3), code::METHOD_NOT_FOUND, "no such method");
        assert_eq!(refused["error"]["code"], json!(code::METHOD_NOT_FOUND));
        assert!(refused.get("result").is_none());

        assert_eq!(parse_error()["error"]["code"], json!(code::PARSE_ERROR));
        assert_eq!(parse_error()["id"], Value::Null);
    }
}
