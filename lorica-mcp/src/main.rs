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
//! This is the stdio binding, and the only thing in the crate that will
//! ever read a file descriptor. Everything it will drive - the
//! configuration intake, the JSON-RPC core, the read tools and the
//! fetch seam they reach a read view through - lives in the library
//! beside it, because the Streamable HTTP binding runs inside
//! `lorica-api` and has to be able to reach the same core. See
//! `lorica-mcp/src/lib.rs` for why that seam exists before there is
//! anything to put through it.
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
//! # What this binary does today
//!
//! It reports its identity and exits. The configuration intake, the
//! JSON-RPC core, the startup introspection and the read tools are the
//! remaining lots of Story 11.1; nothing here pretends to be them.

use lorica_mcp::MCP_PROTOCOL_REVISION;

fn main() {
    println!(
        "{} {} (MCP protocol revision {MCP_PROTOCOL_REVISION})",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
    );
}
