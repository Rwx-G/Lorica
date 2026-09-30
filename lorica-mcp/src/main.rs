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

#![deny(clippy::all)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

//! The Lorica management MCP server (Epic 11): a scope-gated tool
//! surface an operator's MCP client talks to, over the automation
//! plane and never over the management API.
//!
//! This is the stdio binding, and the only thing in the crate that ever
//! reads a file descriptor. Everything it drives - the configuration
//! intake, the JSON-RPC core, the tools of every tier and the seam they
//! reach the plane through - lives in the library beside it, because
//! the Streamable HTTP binding runs inside `lorica-api` and has to be
//! able to reach the same core. See `lorica-mcp/src/lib.rs` for why
//! that seam exists.
//!
//! # It binds nothing
//!
//! Both transports the epic ships leave the socket to someone else.
//! The local one is this binary, launched as a subprocess by the
//! client and speaking JSON-RPC over stdin and stdout. The remote one
//! is a path on the Story 10.3 automation listener, which already owns
//! the TLS, the source-CIDR allowlist, the connection caps and the
//! per-request audit. There is no third management plane and this
//! process opens no port of its own.
//!
//! # The protocol is hand-rolled
//!
//! Story 11.1 resolved PRD decision D5 against an MCP SDK. What an SDK
//! is worth here is its transports, and neither of ours is one it
//! offers: one mounts on an axum listener that already exists, the
//! other is a subprocess reading stdin. What is left after removing
//! them is the message types of a protocol that
//! [`lorica_mcp::MCP_PROTOCOL_REVISION`] made stateless, which is
//! little code. The cost is that spec drift is tracked by hand, and
//! `docs/mcp.md` is where that obligation is written down.
//!
//! # What goes where
//!
//! `stdout` carries JSON-RPC messages and nothing else, one per line.
//! Every word this binary writes for a human - the refusal of a
//! misconfiguration, what the token turned out to carry, why the
//! session ended - goes to `stderr`, and a client must not read
//! anything on `stderr` into the conversation.

use std::process::ExitCode;

use lorica_mcp::{HttpsPlane, McpServer, ServerConfig, StartupError, MCP_PROTOCOL_REVISION};

/// Refused configuration, a token whose scopes span two tiers included.
///
/// Separate from a protocol failure so a client launching this as a
/// subprocess can tell "you configured me wrongly" from "I broke",
/// which are fixed in different places. A token spanning two tiers is
/// the wrong token for this process, which is a configuration fault
/// even though the plane answered.
const EXIT_MISCONFIGURED: u8 = 78;

/// The automation plane could not be reached, or refused the token.
///
/// Distinct from [`EXIT_MISCONFIGURED`] because the configuration may
/// be perfect and the node down, the certificate untrusted or the token
/// withdrawn, and those are fixed somewhere else again.
const EXIT_PLANE_UNREACHABLE: u8 = 69;

/// The session ended on a stream fault rather than on the client
/// closing `stdin`.
const EXIT_SESSION_FAILED: u8 = 74;

fn main() -> ExitCode {
    let config = match ServerConfig::from_process() {
        Ok(config) => config,
        Err(refused) => {
            eprintln!("lorica-mcp: {refused}");
            return ExitCode::from(EXIT_MISCONFIGURED);
        }
    };

    let source = match HttpsPlane::new(&config) {
        Ok(source) => source,
        Err(refused) => {
            eprintln!("lorica-mcp: {refused}");
            return ExitCode::from(EXIT_MISCONFIGURED);
        }
    };

    // A current-thread runtime: this process answers one message at a
    // time by design (see `lorica_mcp::stdio`), so a thread pool would
    // be threads asleep in a subprocess an operator's editor launched.
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(reason) => {
            eprintln!("lorica-mcp: cannot start the async runtime: {reason}");
            return ExitCode::from(EXIT_SESSION_FAILED);
        }
    };

    runtime.block_on(async {
        eprintln!(
            "{} {} (MCP protocol revision {MCP_PROTOCOL_REVISION}) against {}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
            config.endpoint,
        );

        // AC #3: ask what this token may do before offering anything,
        // and refuse a token spanning two tiers (Story 11.4 AC #1).
        let server = match McpServer::introspect(&source).await {
            Ok(server) => server,
            Err(refused @ StartupError::Tier(_)) => {
                eprintln!("lorica-mcp: {refused}");
                return ExitCode::from(EXIT_MISCONFIGURED);
            }
            Err(refused) => {
                eprintln!("lorica-mcp: {refused}");
                return ExitCode::from(EXIT_PLANE_UNREACHABLE);
            }
        };
        // Written for the operator reading stderr, never for the model:
        // it names the token and what it did not get, which is what
        // somebody acts on when a tool is missing from their client.
        eprintln!("lorica-mcp: {}", server.startup_notice());

        match lorica_mcp::stdio::serve(
            &server,
            &source,
            tokio::io::BufReader::new(tokio::io::stdin()),
            tokio::io::stdout(),
        )
        .await
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(ended) => {
                eprintln!("lorica-mcp: {ended}");
                ExitCode::from(EXIT_SESSION_FAILED)
            }
        }
    })
}
