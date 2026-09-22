# Epic 11 Context: Management MCP Server with Tiered Access

<!-- Compiled from planning artifacts. Edit freely. Regenerate with compile-epic-context if planning docs change. -->

## Goal

Let an operator drive Lorica from an MCP client the way they drive it from the dashboard, without giving that client more authority than the task needs. Three tiers: read (logs, WAF events, SLA, fleet status, configuration as it stands), config (routes, backends, certificates) and admin (operational settings only). A tier is not a mode the server switches between; it is the scope set of the token the server was started with, so a session that can read logs cannot write configuration by construction rather than by policy. The tiering is load-bearing rather than advisory because Lorica's read surface is largely text written by attackers (User-Agent strings, request paths, WAF payloads, SNI values, failed Basic-auth usernames). Handing that text to a language model is the feature and also the attack: if the same session holds a mutating tool, a log line becomes an instruction channel into production infrastructure.

## Stories

- Story 11.1: The `lorica-mcp` crate and the read tier
- Story 11.2: The config tier
- Story 11.3: The admin tier, and where it stops
- Story 11.4: Tier isolation, packaging and the operator story

## Requirements & Constraints

- Tiers are separate processes with separate tokens. No tool elevates, no reload widens a running server's scope, and a token spanning two tiers is refused at startup with the offending scopes named.
- The read tier ships first, alone, and must be useful on its own.
- Every tool is paginated with a hard cap on rows returned. A model asking for everything must not pull a database into a context window.
- No secret crosses the boundary: certificate private keys, notification and DNS-provider credentials, Basic-auth hashes, session cookies. Enforced by a test that walks every tool's output for forbidden field names, not by review.
- Every tool call is audited with the token public id, the tool name, arguments after redaction, and a marker identifying the transport as MCP, so the tamper-evident chain distinguishes a model from a dashboard session and from a CI call.
- Every mutation names exactly one resource. No pattern, no selector, no bulk deletion.
- Validation belongs to the management API. The MCP server reimplements no field check, so the two surfaces cannot drift.
- The data plane is untouched: no story may add a code path that runs inside `request_filter`.
- Deliberately out of scope: a separate MCP port, acting as an OAuth authorization server, user management and cluster mutations at any tier, prompts and resources beyond read-only listings, and any tool that accepts a query, filter expression or configuration blob.
- Release-blocking and owned by no single story: the user-facing MCP reference, the MCP actor and indirect-injection path added to the threat model, "which tier for which task" guidance in the hardening guide, the OpenAPI document green against its contract test, and changelog entries under Added and Security.
- The new crate is a workspace member: the three-Dockerfile rule applies, the bump checklist gains it, and its version follows the product line. Workspace tests, clippy with warnings denied, cargo audit and the frontend gates stay green at every commit. All work lands on one release branch with a single PR.

## Technical Decisions

**What the automation listener already supplies.** The epic rests entirely on the Story 10.3 surface merged in v1.8.0 and adds nothing to it: a second listener, off by default, reusing the management plane's TLS pair; a mandatory non-empty source-CIDR allowlist evaluated on the accepted socket before the TLS handshake; listener-wide handshake caps plus per-source connection and attempt budgets; a 64 KiB request-body cap; a refusal to start on a follower; hot-upgrade socket handoff. Authentication is `Authorization: Bearer` only, with no ambient credential. Tokens are `<public_id>.<secret>`, the secret stored as HMAC and verified in constant time, revocation immediate and uncached, expiry mandatory. Credential failures answer a uniform 401 with the precise reason only in the audit row; a missing scope answers 403 naming the scope. Every request is audited, reads included.

**The scope gate is fail-closed by omission.** The scope matrix is a single function whose default refuses every token, including one carrying every scope. A new path that is not declared in it is reachable by nobody, which looks like a broken build rather than a silent grant. Declare the MCP path with the feature, not after.

**A scope spelling lives in four places**: the Rust enum's serde renames, the string the API prints in a 403, the dashboard fixture, and the list the mint form actually offers. Some of them agreeing produces a token minted with a scope the gate never matches, or a scope the gate honours that no operator can mint. Two guards exist and neither crosses the language boundary: one pins the 403 string against the serde renames, the other pins the mint form against the fixture. Nothing pins the fixture against Rust, so a scope added on the Rust side alone leaves every test on both sides green. Unknown scope strings fail to deserialise rather than being dropped, so a token minted on a newer node is refused outright by an older one.

**Transport.** Streamable HTTP mounted as a path on the automation listener, plus stdio for the local subprocess case. No third management plane and no new port: an operator who has not enabled the automation listener gains no MCP surface. One shared, transport-agnostic server core with one adapter per binding; the two must not grow separate behaviour.

**The protocol revision this targets is stateless**, with no protocol-level sessions and no standalone GET stream. A single endpoint accepts POST and answers either one JSON object or a request-scoped SSE stream. Selected body fields are mirrored into headers so intermediaries can route without parsing bodies; the server validates the mirror against the body rather than trusting it, because Lorica is exactly the intermediary that rule protects. The `Origin` header must be validated and an invalid one answered 403, against DNS rebinding. The implemented revision is pinned and documented, with a maintenance note: the specification has moved three times in eighteen months.

**A tier is a scope set, never a runtime flag.** The server holds no notion of permission beyond "the API refused that". At startup it introspects its own token, registers only the tools its scopes cover, and never reconsults; a token with no usable scope produces a server with no tools and a clear message, not a server whose every call fails. Introspection needs an endpoint reachable by any live token with no scope required, since a read-tier token carries no environment scope. Gating writes behind an environment variable is the counter-pattern this epic explicitly refuses.

**The server is a client of the automation listener, not of the management API.** The management API stays on loopback with session credentials the MCP server never sees.

**No SDK.** The protocol core is a hand-rolled JSON-RPC loop. An SDK's value is its transports, and both are unusable here: the remote binding mounts on an axum listener that already owns TLS, the allowlist, the caps and the audit layer, and the local binding is a subprocess reading stdin. The accepted cost is tracking spec drift by hand, which the documentation obligation makes explicit.

**Injection hygiene is a property of the shared core, not of each tool.** Attacker-controlled text is returned in a delimited structured field whose tool description states that the delimited content is data and not instructions. The server never interpolates that text into a prose summary it generates and never editorialises. A tool added later without the delimiting would regress this silently, so it must be impossible to add one that misses it.

**The protocol offers no server-side confirmation.** A server cannot force a human in the loop; the client owns that. Safety therefore comes from tools that are narrow, unambiguously named, and impossible to invoke in bulk, never from assuming the client asks first.

## UX & Interaction Patterns

- Every mutating tool has a counterpart returning the change it would make against current state without making it, taking the same arguments, so a client can be configured to show a diff before applying.
- Token intake is from the environment or a config file, never from argv, where it would land in the process table.
- Setup shows its own blast radius: minting a token for a tier prints the credential once and prints what that tier can do next to it.
- The MCP binary ships in the `.deb` and `.rpm` and in the three Dockerfiles, but is not started by the systemd unit. The operator's MCP client launches it.
- Anything the admin tier can change must be reversible from the dashboard by a human who has lost their MCP client. A setting that could lock the operator out of the management plane is not in the tier.

## Cross-Story Dependencies

- The whole epic depends on Epic 10 Story 10.3; nothing is buildable without it.
- Story 11.1 blocks 11.2, 11.3 and 11.4. It fixes the shape of the shared core, both transport adapters, the scope plumbing and the introspection endpoint change. The later tiers have no transport of their own.
- Story 11.2 reverses Epic 10's deliberate exclusion of route, backend and certificate write scopes. The reversal is recorded as a pointer from the Epic 10 PRD so the earlier decision is not silently contradicted.
- Story 11.2 relies on the existing cluster replication path with no new code, and a config-tier server pointed at a follower is refused, matching the listener's own follower rule.
- Story 11.3 inherits the fleet-audit stance that cluster enrolment, revocation and break-glass stay human-only, and excludes identity operations for the same reason the tiering exists.
- Story 11.4 owns the one-process-one-tier startup check and the end-to-end profile covering all three tiers. Story 11.1 must not build anything that makes that check hard: the tool registry is populated once and there is no path that re-reads scopes on a running server.
