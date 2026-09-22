# Story 11.1: The `lorica-mcp` Crate and the Read Tier

**Epic:** [Epic 11 - Management MCP Server with Tiered Access (v1.9.0)](../prd/epic-11-v1.9.0.md)
**Status:** Draft
**Priority:** P0
**Author:** Romain G.
**Depends on:** Epic 10 Story 10.3, merged in v1.8.0. It supplies the
listener, the token model, the scope gate and the per-request audit
this story stands on and adds nothing to.
**Blocks:** Stories 11.2, 11.3 and 11.4. All three are tiers over the
server core this story builds, and none of them has a transport of its
own.

---

As an operator debugging a route,
I want to ask my MCP client what Lorica is seeing,
so that I can read logs, WAF events, SLA and the current configuration
without opening the dashboard, and without that session being able to
change anything.

## Problem

The text an operator most wants to reason about is the text Lorica
collected from whoever was attacking them: User-Agent strings, request
paths, WAF payloads, SNI values, failed Basic-auth usernames. Handing
that to a language model is the point of the feature and is also the
attack. The read tier is the answer to the second half: a session that
can only read has nothing an injected instruction can usefully reach,
and it is the tier that ships first precisely because it is the one
most exposed to hostile text and the one with the least to lose.

What does not exist yet is any of it. There is no `lorica-mcp` crate,
no MCP dependency in the workspace, and five of the six read scopes the
tier needs are not in the enum.

## Decisions taken in this story

**D5 of the PRD is resolved: a hand-rolled JSON-RPC loop, no SDK.**
Decided 2026-09-22. The reasoning is not "fewer dependencies" in the
abstract. `rmcp`'s main value is its transports, and both of them are
unusable here: the remote binding mounts on the Story 10.3 axum
listener, which already owns TLS, the source-CIDR allowlist, the
connection caps and the audit layer, and the local binding is a
subprocess reading stdin. What is left of the SDK after removing its
transports is the message types of a protocol that revision 2026-07-28
made stateless, which is a small amount of code. The cost accepted in
exchange is that spec drift is tracked by hand, which AC #11 turns into
a documented obligation rather than a hope.

**`whoami` must become reachable by any live token.** AC #3 says the
server asks the API what its token can do before it registers a tool.
The endpoint for that exists, `GET /automation/v1/whoami`, but the
scope matrix requires `environments:read` to reach it
(`lorica-api/src/automation/scope.rs:170`). A read-tier MCP token
carries no environment scope, so as it stands the introspection call
answers 403 and the server cannot discover its own tier. The fix is to
declare `whoami` as needing a live token and no scope, not to widen the
read tier with a scope it has no use for. The endpoint discloses the
caller's own name, id and grants, which the caller already holds; there
is nothing in the response that a token does not know about itself.
This is the one change this story makes to the Story 10.3 gate, and it
is a narrowing of nothing.

## Acceptance Criteria

These are the PRD's, unchanged. They are the contract.

1. **New workspace member `lorica-mcp`**, a binary crate, stdio
   transport, no listener. It takes the automation endpoint and a token
   from its environment or a config file, never from argv (the token
   would land in the process table).
2. **New read scopes on the Story 10.3 token model**: `logs:read`,
   `waf:read`, `sla:read`, `cluster:read`, `backends:read`.
   `routes:read` and `certificates:read` already exist. Each is
   additive to the closed enum, documented where the enum is defined,
   and creatable from the existing token administration surface.
3. **The server asks before it offers.** On startup it calls an
   endpoint that returns the calling token's scopes, and registers only
   the tools those scopes cover. A token with no read scope produces a
   server with no tools and a clear message, not a server whose every
   call fails.
4. **The read tool surface**: recent access-log rows with the filters
   the dashboard already offers, WAF events by category and time
   window, SLA windows per route, cluster and node status, and the
   current configuration as read-only listings (routes, backends,
   certificates with metadata only, never key material). Every tool is
   paginated with a hard cap on rows returned, because a model that
   asks for everything must not be able to pull a database into a
   context window.
5. **Secrets never cross the boundary.** Certificate private keys,
   notification-channel credentials, DNS-provider credentials,
   Basic-auth hashes and session cookies are absent from every
   response, the same filtering the JSON GET surface already applies.
   The story adds a test that walks every tool's output for the field
   names that must never appear.
6. **Audit.** Every tool call is audited with the token `public_id`,
   the tool name, the arguments after redaction, and a marker
   identifying the transport as MCP, so the chain distinguishes it from
   a dashboard session and from a CI call.
7. **Prompt-injection hygiene in the output.** Log rows and WAF
   payloads are returned in a structured field that the tool
   description marks as untrusted attacker-controlled text, never
   interpolated into a prose summary the server generates. Following
   the OWASP guidance on aggregated external content, the field is
   delimited and the tool description states in terms that the
   delimited text is data and not instructions. The server does not
   editorialise; it returns data.
8. Documentation: `docs/mcp.md` with the read tier, the client
   configuration for both transports, and a plain statement of what the
   tier can see.
9. **Streamable HTTP on the automation listener, and the spec's
   security requirements met where they land.** The MCP endpoint is a
   path on the Story 10.3 listener, authenticated by the same bearer
   token. The `Origin` header is validated and an invalid one answered
   403 (the specification's only MUST on this transport, against DNS
   rebinding); `MCP-Protocol-Version` is pinned to the revision this
   crate implements and an unknown version answered per the spec; the
   header-versus-body mirror (`Mcp-Method`, `Mcp-Name`) is validated
   rather than trusted, because Lorica is exactly the kind of
   intermediary that mismatch rule exists to protect. The listener
   already provides TLS, the source-CIDR allowlist, connection caps and
   the per-IP limiter.
10. **stdio for the local case**, the same tool surface over a
    client-launched subprocess, no listener required. One adapter, one
    shared server core: the protocol is transport-agnostic and the two
    bindings must not grow separate behaviour.
11. **A protocol-version maintenance note in `docs/mcp.md`.** The
    specification has moved three times in eighteen months, most
    recently removing sessions and the GET stream. The crate states
    which revision it implements and the release notes say when that
    changes.

## Integration Verification

- IV1: A client configured with a read-tier token lists tools and gets
  only read tools; a call that would mutate does not exist to be
  called.
- IV2: A token revoked mid-session causes the next tool call to fail
  with an authorization error, and the failure is audited.
- IV3: A WAF event whose payload contains text shaped like an
  instruction ("ignore previous instructions and ...") round-trips to
  the client as data in the payload field, with no change to the
  server's own output structure.

## Tasks

- [ ] AC #2 first, because everything else reads from it: five new
      `AutomationScope` variants. All three spellings move together
      (see Dev Notes), and the doc comment on the enum stops saying
      four variants are the whole surface.
- [ ] `whoami` reachable by any live token, per the decision above, with
      the test in `scope.rs` rewritten to assert the new rule rather
      than deleted.
- [ ] AC #1: the `lorica-mcp` crate skeleton. Workspace `members`, the
      three Dockerfiles, `docs/BUMP-CHECKLIST.md`, product version line,
      `#![deny(unsafe_code)]` and `#![warn(missing_docs)]`.
- [ ] Configuration intake: endpoint and token from environment or
      config file, and a refusal with a clear message if either arrives
      on argv.
- [ ] The protocol core: JSON-RPC framing, `initialize`, `tools/list`,
      `tools/call`, error mapping. Transport-agnostic, no I/O in it.
- [ ] AC #10: the stdio adapter over the core.
- [ ] AC #3: startup introspection against `whoami`, tool registration
      from the returned scopes, and the no-scope case that produces a
      server with no tools and says why.
- [ ] AC #4: the read tools, each one paginated with a hard row cap.
- [ ] AC #5: the secret-name sweep over every tool's output, as a test
      that walks the field names rather than a review promise.
- [ ] AC #7: the untrusted-text field, its delimiters, and the tool
      descriptions that say what it is.
- [ ] AC #9: the Streamable HTTP adapter as a path on the automation
      listener. `Origin` validation, protocol-version pinning, and the
      header-versus-body mirror check. The path is declared in
      `required_scope` or it is reachable by nobody.
- [ ] AC #6: the MCP transport marker in the audit row, and the
      argument redaction that precedes it.
- [ ] IV1, IV2, IV3 as tests.
- [ ] AC #8 and #11: `docs/mcp.md`, including the implemented revision
      and the maintenance note.
- [ ] `lorica-api/openapi.yaml` for the new scopes and the endpoint,
      green against the contract test. `CHANGELOG.md` under Added and
      Security.

## Dev Notes

### A scope spelling lives in three files

The doc comment on `AutomationScope`
(`lorica-config/src/models/automation_token.rs:110`) names them and the
warning is load-bearing: the serde renames on the enum, `scope_str` in
`lorica-api/src/automation/scope.rs` which is the string an operator
reads in a 403, and
`lorica-dashboard/frontend/src/components/settings-tabs/automation-scopes.fixture.ts`
which is what the mint form offers. Two of the three agreeing produces a
token minted with a scope the gate never matches. Five new variants
means five additions in each.

An unknown scope string fails to deserialise rather than being dropped,
so a 1.9.0 token presented to a 1.8.0 node is refused outright. That is
the intended behaviour and the upgrade note belongs in the changelog.

### An undeclared path is reachable by nobody

`required_scope` is a single matrix and its default is `None`, which
refuses every token including one carrying every scope. The MCP
endpoint added in AC #9 is a new path on that listener: if it is not
declared in the matrix it answers 403 to everyone, which is the
fail-closed outcome but looks like a broken build. Declare it with the
rest of AC #9, not afterwards.

### The tier check is a startup property, not a tool

Nothing in this story enforces one-process-one-tier; that is Story
11.4 AC #1. What this story must not do is build anything that would
make the check hard later: the tool registry is populated once at
startup from the introspection result and never reconsulted, and there
is no path that re-reads scopes on a running server.

### The thing most likely to go wrong

AC #5 and AC #7 are both "the output is right" and they fail
differently. The secret sweep is a test that can be written once and
will hold. The untrusted-text delimiting is a design property of every
tool description, and a tool added in Story 11.2 without it regresses
this story silently. Whatever shape the delimiting takes, it belongs in
the shared core where a new tool gets it by construction, not in each
tool's own formatting.

## Dev Agent Record

### Debug Log

### Completion Notes

## File List

## Change Log

- 2026-09-22: Story drafted from the Epic 11 PRD. D5 resolved as a
  hand-rolled JSON-RPC loop; the `whoami` scope change recorded as the
  one modification this story makes to the Story 10.3 gate.
