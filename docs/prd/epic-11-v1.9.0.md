# Epic 11: Management MCP Server with Tiered Access (v1.9.0)

**Author:** Romain G.
**Target version:** 1.9.0
**Status:** Draft (2026-09-16, written against the Epic 10 Story 10.3 token design. Revised the same day after a documentation pass on the MCP 2026-07-28 specification and on what infrastructure vendors ship: D1 reversed, the prior-art section replaced with verified material.)

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

**D1 - Streamable HTTP, mounted on the Story 10.3 automation listener, with stdio as the second transport.** The first draft of this PRD said stdio only. That was wrong on ergonomics and behind the ecosystem: it means a binary installed and configured on every machine, per tier, and the 2026-07-28 specification's remote transport is Streamable HTTP, which every hosted product in this space now speaks.

What survives from the original reasoning is the part that mattered: **no third management plane**. The MCP endpoint is a path on the automation listener Story 10.3 already builds, not a new port. It inherits that listener's TLS, its mandatory source-CIDR allowlist, its connection caps and per-IP limiter, its bearer tokens with HMAC-stored secrets and immediate revocation, and its per-request audit. An operator who does not enable the automation listener gains no MCP surface, and one who does gains a path, not a port.

Three properties of the current specification make this fit rather than force it: the protocol is transport-agnostic, so supporting both bindings costs one adapter; revision 2026-07-28 removed protocol-level sessions and made the protocol stateless, which matches a server whose state lives in the API behind it; and the transport's own security requirements are things this listener does or must now do anyway (see Story 11.1 AC #9).

stdio stays supported for the local case, where the client launches the server as a subprocess and no listener is involved at all. It is the better answer for a workstation-only setup and for anyone who does not want the automation listener enabled.

**D2 - A tier is a scope set on a Story 10.3 token.** No second authorization model. The MCP server has no notion of permission beyond "the API refused that"; it discovers its own tier by asking the API what its token can do, and exposes only the matching tools.

This is the pattern the field converged on: Scalr's MCP OAuth inherits Scalr's own RBAC, and Spacelift splits its surface under `mcp:read` and `mcp:write` scopes. The counter-pattern exists too, HashiCorp gates Terraform write operations behind an `ENABLE_TF_OPERATIONS=true` environment variable, and this epic refuses it: a runtime switch is one misconfiguration away from a session that reads hostile text and holds write tools, which is precisely the failure this tiering exists to prevent.

**D3 - The server is a client of the automation listener, not of the management API.** It gets the CIDR allowlist, the token lifecycle, the revocation path and the request audit for free, and the management API stays on loopback with session credentials the server never sees.

**D4 - This epic extends Story 10.3's closed scope enum**, and says so where that enum is defined. New read scopes (`logs:read`, `waf:read`, `sla:read`, `cluster:read`, `backends:read`, `settings:read`) and, for the higher tiers, the write scopes Epic 10 deliberately withheld. Each one is justified in the story that introduces it, and none is added "for symmetry".

**D5 - A dependency decision, needed before Story 11.1 starts.** An MCP server in Rust needs an SDK (`rmcp`, the official Rust implementation, is the candidate) or a hand-rolled JSON-RPC loop over stdio. Neither is in the workspace. Per the project rule, no new dependency without explicit approval; if the SDK is refused, the protocol surface this epic needs is small enough to implement directly, at the cost of tracking the spec by hand. Decide before the crate exists, not after.

**Integration Requirements:** All work lands on a single `feat/v1.9.0` branch with one final PR to `main`. The epic depends on Epic 10 Story 10.3 being merged; nothing here is buildable before it. `lorica-mcp` is a new workspace member, which means the three-Dockerfile rule applies (`Dockerfile`, `Dockerfile.dev`, `tests-e2e-docker/Dockerfile`), `docs/BUMP-CHECKLIST.md` gains it, and its version follows the product line. The data plane is untouched by this epic: no story may add a code path that runs inside `request_filter`. `cargo test --workspace`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo audit`, and the frontend gates stay green at every commit.

**Cross-cutting deliverables** (no single story owns them, all release-blocking): `docs/mcp.md` as the user-facing reference, including how to configure a client per tier and what each tier can and cannot do; `docs/security/threat-model.md` gains the MCP actor and the indirect-injection path as a named threat with its mitigation; `docs/security/hardening-guide.md` gains the "which tier for which task" guidance; `lorica-api/openapi.yaml` updated for any new scope or endpoint and kept green against the contract test; `CHANGELOG.md` under Added and Security.

---

## Prior Art

Verified against the specification and vendor documentation on 2026-09-16.

### The protocol as it stands

The 2026-07-28 revision defines two standard bindings, [stdio and Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports), and states that protocol semantics are identical on both: a binding defines framing and delivery, not meaning. Streamable HTTP is a single endpoint accepting POST, answering either with one JSON object or a request-scoped SSE stream. That revision **removed protocol-level sessions and the standalone GET stream**, making the protocol stateless. It also mirrors selected body fields into HTTP headers (`Mcp-Method`, `Mcp-Name`, `MCP-Protocol-Version`) so intermediaries can route and inspect without parsing bodies, and requires servers to reject any mismatch between header and body with a `HeaderMismatch` error, explicitly so that a load balancer routing on the header and a server executing on the body cannot disagree.

The transport page states three security requirements: servers **MUST** validate the `Origin` header and answer 403 when it is present and invalid, to prevent DNS rebinding; servers **SHOULD** bind only to localhost when running locally; servers **SHOULD** implement proper authentication. The specification also notes that custom transports over a reliable byte stream, such as a Unix domain socket, **SHOULD** reuse the stdio framing rather than inventing one, which is the cheapest future option if a socket-local binding is ever wanted.

What the protocol does **not** give: a server-side notion of "this call needs approval". A server cannot force a confirmation; the client owns the human-in-the-loop. A server can only make a destructive tool narrow, unambiguously named, and impossible to invoke in bulk. Any design that leans on the client asking a human first is leaning on someone else's configuration.

### What comparable products ship

| Product | Transport and auth | Tiering model | What Lorica takes |
|---|---|---|---|
| Cloudflare | Remote, OAuth with PKCE via `workers-oauth-provider`; account-scoped and user-scoped tokens | Token scope | Confirms remote-with-OAuth as the hosted norm, and that the scope lives on the token |
| Scalr | OAuth, **inheriting Scalr's own RBAC**; read scope covers environments, workspaces, runs, logs, policy results, drift, IAM, billing | Scope set mapped onto existing roles | The central idea of D2: the MCP tier is a projection of the product's existing authorization, not a new one |
| Spacelift | Scoped | `mcp:read` and `mcp:write` | Read and write as distinct scopes rather than one surface with a flag |
| HashiCorp (Terraform) | Local server | Write operations behind `ENABLE_TF_OPERATIONS=true` | The counter-pattern this epic refuses, see D2 |
| Kong | API-to-MCP conversion at the gateway (AI Gateway) | Gateway policy | Confirms the "the gateway already has the authorization, project it" framing |
| Grafana Cloud | Hosted MCP with per-service tokens | Per-service credential | Confirms that read-heavy observability surfaces are the ones shipped first |

Sources: the MCP specification transport pages linked above; Cloudflare's MCP repository and blog; Grafana Cloud MCP documentation; Scalr's and Spacelift's MCP documentation as summarised in a 2026 comparison of Terraform-platform MCP servers; Kong AI Gateway material.

### What the security literature says

The consensus in 2026 guidance, including the OWASP MCP Top 10 and the OWASP GenAI secure-MCP-development guide, lands on three things this epic already does or now does: least privilege per tool rather than per server, a progressive scope model that starts read-only and widens only when a task needs it, and explicit delimiting of aggregated external content with a statement that the delimited text is data rather than instructions. The named risk classes are tool poisoning, prompt injection, memory poisoning and tool interference; NSA and CISA published formal design guidance on the same problem the same year.

Lorica's position in that landscape is unusual in one way worth stating: most of these products expose an MCP surface over data their users produced. Lorica's read surface is **largely text produced by people attacking the operator**, which makes the injection path shorter and the tiering load-bearing rather than advisory.

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
7. **Prompt-injection hygiene in the output.** Log rows and WAF payloads are returned in a structured field that the tool description marks as untrusted attacker-controlled text, never interpolated into a prose summary the server generates. Following the OWASP guidance on aggregated external content, the field is delimited and the tool description states in terms that the delimited text is data and not instructions. The server does not editorialise; it returns data.
8. Documentation: `docs/mcp.md` with the read tier, the client configuration for both transports, and a plain statement of what the tier can see.
9. **Streamable HTTP on the automation listener, and the spec's security requirements met where they land.** The MCP endpoint is a path on the Story 10.3 listener, authenticated by the same bearer token. The `Origin` header is validated and an invalid one answered 403 (the specification's only MUST on this transport, against DNS rebinding); `MCP-Protocol-Version` is pinned to the revision this crate implements and an unknown version answered per the spec; the header-versus-body mirror (`Mcp-Method`, `Mcp-Name`) is validated rather than trusted, because Lorica is exactly the kind of intermediary that mismatch rule exists to protect. The listener already provides TLS, the source-CIDR allowlist, connection caps and the per-IP limiter.
10. **stdio for the local case**, the same tool surface over a client-launched subprocess, no listener required. One adapter, one shared server core: the protocol is transport-agnostic and the two bindings must not grow separate behaviour.
11. **A protocol-version maintenance note in `docs/mcp.md`.** The specification has moved three times in eighteen months, most recently removing sessions and the GET stream. The crate states which revision it implements and the release notes say when that changes.

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

- **A separate MCP port.** D1 keeps the endpoint on the Story 10.3 automation listener. A second listener would be a third management plane with its own exposure, and nothing in the protocol requires one.
- **OAuth as an authorization server.** The specification's authorization framework and what Cloudflare or Scalr offer is an OAuth flow with user consent; Lorica issues its own scoped tokens and that is what this epic uses. Becoming an OAuth authorization server is a product decision of its own, not a side effect of shipping an MCP endpoint.
- **User management and cluster mutations through any tier.** Story 11.3 AC #1 and #2, with reasons.
- **Prompts and resources beyond the read tier's listings.** The protocol offers both; this epic ships tools and read-only listings and sees what is actually missing before adding surface.
- **A tool that runs a query, a filter expression or a configuration blob.** Arbitrary execution with extra steps.
- **Anything that writes to the data plane's hot path.** No story in this epic touches `request_filter`.
