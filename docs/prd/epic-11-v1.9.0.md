# Epic 11: Management MCP Server with Tiered Access (v1.9.0)

**Author:** Romain G.
**Target version:** 1.9.0
**Status:** Draft (2026-09-16, written against the Epic 10 Story 10.3 token design; the prior-art section is explicitly unverified and must be checked before Story 11.1 starts)

**Epic Goal:** Let an operator drive Lorica from an MCP client the way they drive it from the dashboard, without giving that client more authority than the task needs. Three tiers: **read** (logs, WAF events, SLA, fleet status, and the configuration as it stands), **config** (routes, backends, certificates), **admin** (settings, users, cluster mutations). A tier is not a mode the server switches between; it is the scope set of the token the server was started with, so a session that can read logs cannot write configuration by construction rather than by policy.

**Why this is its own epic and not a story of Epic 10:** Story 10.3 already builds the thing an MCP server should stand on, a separate listener with scoped bearer tokens, HMAC-stored secrets, revocation, expiry and per-request audit. What this epic adds is a second consumer of that surface with a fundamentally different caller, and two of its three tiers need scopes Story 10.3 refuses on purpose (AC #5: "the automation surface is the environment resource, not the whole management API behind a different door"). Reversing that is a decision, not an inheritance, and it is taken here in the open.

## The caller is the whole problem

A CI runner is deterministic: it sends what the pipeline says. An MCP client is a language model reading text, and the text Lorica has to offer is largely **written by attackers**: User-Agent strings, request paths, WAF payloads, TLS SNI values, Basic-auth usernames from failed attempts. An operator who asks "why is this route 502-ing" hands that text to a model. If the same session also holds a tool that deletes a route or changes a global setting, the request path in a log line is now an instruction channel into production infrastructure.

That is indirect prompt injection with a real blast radius, and it is what the tiering is for. It follows that:

- **Tiers are separate processes with separate tokens.** A single server holding all three tiers defeats its own purpose, however carefully its tools are named. The tier is fixed at startup by the token; there is no tool that elevates, and no configuration reload that widens a running server's scope.
- **The read tier is the one most exposed to hostile text and the one with the least to lose.** It ships first, alone, and stays useful on its own.
- **Every mutation is audited as an MCP call**, distinguishable from a human operator in the existing tamper-evident chain. An audit trail that cannot tell a model from a person is telling a story that is not true.
- **No tool takes a free-form predicate that selects many objects for a destructive action.** Every mutation names one resource. "Delete the routes matching this pattern" is not a tool this epic ships.

## Decisions taken up front

**D1 - Transport is stdio, and the server runs on the operator's machine.** The MCP client launches it; there is no listener, no port, no new thing to defend, and the credential is one the operator already holds. A network-reachable MCP server is a third management plane with its own exposure, and this epic does not build one. If a hosted MCP server is ever wanted, it is a separate decision with its own threat-model section, not a transport flag.

**D2 - A tier is a scope set on a Story 10.3 token.** No second authorization model. The MCP server has no notion of permission beyond "the API refused that"; it discovers its own tier by asking the API what its token can do, and exposes only the matching tools.

**D3 - The server is a client of the automation listener, not of the management API.** It gets the CIDR allowlist, the token lifecycle, the revocation path and the request audit for free, and the management API stays on loopback with session credentials the server never sees.

**D4 - This epic extends Story 10.3's closed scope enum**, and says so where that enum is defined. New read scopes (`logs:read`, `waf:read`, `sla:read`, `cluster:read`, `backends:read`, `settings:read`) and, for the higher tiers, the write scopes Epic 10 deliberately withheld. Each one is justified in the story that introduces it, and none is added "for symmetry".

**D5 - A dependency decision, needed before Story 11.1 starts.** An MCP server in Rust needs an SDK (`rmcp`, the official Rust implementation, is the candidate) or a hand-rolled JSON-RPC loop over stdio. Neither is in the workspace. Per the project rule, no new dependency without explicit approval; if the SDK is refused, the protocol surface this epic needs is small enough to implement directly, at the cost of tracking the spec by hand. Decide before the crate exists, not after.

**Integration Requirements:** All work lands on a single `feat/v1.9.0` branch with one final PR to `main`. The epic depends on Epic 10 Story 10.3 being merged; nothing here is buildable before it. `lorica-mcp` is a new workspace member, which means the three-Dockerfile rule applies (`Dockerfile`, `Dockerfile.dev`, `tests-e2e-docker/Dockerfile`), `docs/BUMP-CHECKLIST.md` gains it, and its version follows the product line. The data plane is untouched by this epic: no story may add a code path that runs inside `request_filter`. `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo audit`, and the frontend gates stay green at every commit.

**Cross-cutting deliverables** (no single story owns them, all release-blocking): `docs/mcp.md` as the user-facing reference, including how to configure a client per tier and what each tier can and cannot do; `docs/security/threat-model.md` gains the MCP actor and the indirect-injection path as a named threat with its mitigation; `docs/security/hardening-guide.md` gains the "which tier for which task" guidance; `lorica-api/openapi.yaml` updated for any new scope or endpoint and kept green against the contract test; `CHANGELOG.md` under Added and Security.

---

## Prior Art

**Unverified.** Written from general knowledge of the protocol and of infrastructure MCP servers, not from a documentation pass. Check each line before Story 11.1 starts, the way Epic 10's prior-art table was checked.

What the protocol gives: tools (callable, with a JSON schema), resources (addressable read-only content), prompts (templates), over stdio or HTTP, with the client owning the human-in-the-loop confirmation. What it does **not** give: a server-side notion of "this call needs approval". A server cannot force a confirmation; it can only make a destructive tool narrow, named unambiguously, and impossible to invoke in bulk. Any design that relies on the client asking the human first is relying on someone else's configuration.

Patterns worth borrowing from infrastructure MCP servers generally: read and write surfaces split into separate servers rather than separate tools; resources used for "here is the current state" and tools reserved for actions; and a dry-run or diff tool preceding any apply. Patterns worth refusing: a single server with a `--read-only` flag (a flag is a runtime switch, which D2 rejects), and tools that accept raw queries or raw configuration blobs, which turn the server into an arbitrary-execution surface with extra steps.

---

## Story 11.1: The `lorica-mcp` crate and the read tier

As an operator debugging a route,
I want to ask my MCP client what Lorica is seeing,
so that I can read logs, WAF events, SLA and the current configuration without opening the dashboard, and without that session being able to change anything.

### Acceptance Criteria

1. **New workspace member `lorica-mcp`**, a binary crate, stdio transport, no listener. It takes the automation endpoint and a token from its environment or a config file, never from argv (the token would land in the process table).
2. **New read scopes on the Story 10.3 token model**: `logs:read`, `waf:read`, `sla:read`, `cluster:read`, `backends:read`. `routes:read` and `certificates:read` already exist. Each is additive to the closed enum, documented where the enum is defined, and creatable from the existing token administration surface.
3. **The server asks before it offers.** On startup it calls an endpoint that returns the calling token's scopes, and registers only the tools those scopes cover. A token with no read scope produces a server with no tools and a clear message, not a server whose every call fails.
4. **The read tool surface**: recent access-log rows with the filters the dashboard already offers, WAF events by category and time window, SLA windows per route, cluster and node status, and the current configuration as read-only listings (routes, backends, certificates with metadata only, never key material). Every tool is paginated with a hard cap on rows returned, because a model that asks for everything must not be able to pull a database into a context window.
5. **Secrets never cross the boundary.** Certificate private keys, notification-channel credentials, DNS-provider credentials, Basic-auth hashes and session cookies are absent from every response, the same filtering the JSON GET surface already applies. The story adds a test that walks every tool's output for the field names that must never appear.
6. **Audit.** Every tool call is audited with the token `public_id`, the tool name, the arguments after redaction, and a marker identifying the transport as MCP, so the chain distinguishes it from a dashboard session and from a CI call.
7. **Prompt-injection hygiene in the output.** Log rows and WAF payloads are returned in a structured field that the tool description marks as untrusted attacker-controlled text, never interpolated into a prose summary the server generates. The server does not editorialise; it returns data.
8. Documentation: `docs/mcp.md` with the read tier, the client configuration for it, and a plain statement of what the tier can see.

### Integration Verification

- IV1: A client configured with a read-tier token lists tools and gets only read tools; a call that would mutate does not exist to be called.
- IV2: A token revoked mid-session causes the next tool call to fail with an authorization error, and the failure is audited.
- IV3: A WAF event whose payload contains text shaped like an instruction ("ignore previous instructions and ...") round-trips to the client as data in the payload field, with no change to the server's own output structure.

---

## Story 11.2: The config tier

As an operator,
I want to create and adjust routes, backends and certificates from my MCP client,
so that a change I would have made in the dashboard takes one sentence, with the same audit trail and the same validation.

### Acceptance Criteria

1. **This story reverses Epic 10 Story 10.3 AC #5** for `routes:write`, `backends:write` and `certificates:write`. The reversal is recorded in the Epic 10 PRD as a pointer to this story, so the earlier decision is not silently contradicted by a later file.
2. **A separate token and a separate server process from the read tier.** The config tier's tools include the read tools it needs to work, but a read-tier token can never gain them.
3. **Diff before apply.** Every mutating tool has a counterpart that returns the change it would make, against the current state, without making it. The tool descriptions say so, and the apply tool takes the same arguments, so a client can be configured to show the diff first.
4. **One named resource per call.** No pattern, no selector, no bulk. Deleting a route takes its id; there is no tool that deletes what matches.
5. **Validation is the API's, not the server's.** Every mutation goes through the same endpoints and therefore the same validators the dashboard uses; `lorica-mcp` does not reimplement a single field check, so the two surfaces cannot drift.
6. **Certificate private keys are never an argument.** A certificate can be selected, bound and renewed through the tier; key material is uploaded through the management API by a human.
7. Audit and documentation as in Story 11.1, plus a `docs/mcp.md` section on what makes a change safe to delegate to this tier and what does not.

### Integration Verification

- IV1: A config-tier call that creates a route produces the same stored object as the equivalent dashboard action, byte for byte in the canonical config hash.
- IV2: A mutation rejected by the API's validators surfaces the field-level error to the client unchanged, and nothing is written.
- IV3: In a cluster, a config-tier mutation on the control plane replicates to followers through the Story 9.4 path with no new code, and a config-tier server pointed at a follower is refused.

---

## Story 11.3: The admin tier, and where it stops

As a super-admin,
I want the narrowest possible administrative surface from an MCP client,
so that the operations that can lock me out or expose the fleet stay deliberate.

### Acceptance Criteria

1. **The tier exists, and its surface is a short list decided by exclusion.** Global settings that are operational (retention, thresholds, timeouts) are in. User creation, role changes and password resets are **out**: an identity system driven by a model reading attacker-controlled text is a bad trade at any tier, and the dashboard is thirty seconds away.
2. **Cluster mutations are out of this tier in 1.9.0.** Enrolment, revocation and break-glass stay human-only, for the same reason Story 9.9 gives: those actions are the ones an attacker most wants and the ones whose audit matters most.
3. **Everything this tier can change is reversible from the dashboard by a human who has lost their MCP client.** A setting that could lock the operator out of the management plane is not in the tier.
4. Audit, documentation and a `docs/security/hardening-guide.md` paragraph recommending that the admin tier be configured only when a task needs it, and removed afterwards.

### Integration Verification

- IV1: The admin tier's tool list matches the documented allowlist exactly; a test asserts the list rather than describing it.
- IV2: An attempt to reach a user-management or cluster endpoint through the admin tier fails at the scope check, not at a tool that exists and refuses.

---

## Story 11.4: Tier isolation, packaging and the operator story

As an operator setting this up for the first time,
I want the tiers to be obviously separate and the setup to be hard to get subtly wrong,
so that I do not end up with one token that does everything because it was easier.

### Acceptance Criteria

1. **One process, one tier, enforced at startup.** A token whose scopes span two tiers is refused with a message naming the offending scopes. The product refuses to build the convenient thing.
2. **Packaging.** `lorica-mcp` ships in the `.deb` and `.rpm` alongside the binary, and the three Dockerfiles carry the crate. It is not started by the systemd unit: it is launched by the operator's MCP client.
3. **Setup that shows its own blast radius.** `lorica mcp token create --tier read|config|admin` mints a Story 10.3 token with exactly that tier's scopes, prints it once, and prints what the tier can do next to it.
4. **The e2e Docker suite gains an `mcp` profile**: a real Lorica, a real automation listener, and a client driving each tier over stdio, asserting the tool lists, one mutation, the audit rows and one revocation.
5. Documentation: the full `docs/mcp.md`, the threat-model actor, and the hardening-guide guidance.

### Integration Verification

- IV1: A token carrying both `logs:read` and `routes:write` is refused at startup with both scopes named.
- IV2: The `mcp` e2e profile passes with all three tiers configured, and the audit chain verifies afterwards.

---

## Out of Scope (deferred)

- **A network-reachable MCP server.** D1. It is a third management plane and needs its own threat model, exposure decision and hardening story. Not a transport flag added to this work.
- **User management and cluster mutations through any tier.** Story 11.3 AC #1 and #2, with reasons.
- **Prompts and resources beyond the read tier's listings.** The protocol offers both; this epic ships tools and read-only listings and sees what is actually missing before adding surface.
- **A tool that runs a query, a filter expression or a configuration blob.** Arbitrary execution with extra steps.
- **Anything that writes to the data plane's hot path.** No story in this epic touches `request_filter`.
