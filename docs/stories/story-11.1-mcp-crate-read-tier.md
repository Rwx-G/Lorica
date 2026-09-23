# Story 11.1: The `lorica-mcp` Crate and the Read Tier

**Epic:** [Epic 11 - Management MCP Server with Tiered Access (v1.9.0)](../prd/epic-11-v1.9.0.md)
**Status:** Review
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

The story ships in four lots, agreed 2026-09-22. Each one ends on a tree
that builds and passes its gates, so none of them is a skeleton waiting
for the next. The order is a dependency order, not a preference: every
lot reads from the one before it.

### Lot 1: the scope surface and a crate that compiles

- [x] AC #2, first because everything else reads from it: five new
      `AutomationScope` variants. All four spellings move together
      (see Dev Notes), and the doc comment on the enum stops saying
      four variants are the whole surface and stops saying the
      vocabulary lives in three places.
- [x] Close the unguarded Rust-to-TypeScript edge, following the
      `openapi_contract.rs` idiom exactly: an integration test under
      `lorica-api/tests/` that reads the committed file with
      `include_str!`, asserts the extraction found something before
      comparing (or a broken parser passes by comparing two empty
      sets), diffs both directions and `panic!`s with a message naming
      what to do. Diff-style, never auto-write.
- [x] Rename the fixture to `automation-scopes.generated.ts`. Prettier
      does not exist here and is banned by `lorica-frontend.md`, so
      there is nothing to exempt; `eslint.config.js:83` already ignores
      `**/*.generated.ts` and nothing matches it yet. It stays
      committed, since the Vitest gate imports it, and it must be
      `--strict` clean on its own because `tsconfig.app.json:20` sweeps
      in every `src/**/*.ts` regardless of the eslint ignore.
- [x] `whoami` reachable by any live token, per the decision above.
      This is not a one-line change (see Dev Notes): `required_scope`
      returns `Option<AutomationScope>`, where `None` already means
      "refused for everyone", so the third state needs a type.
      `whoami`'s match is path-only today, so the new arm takes a
      method guard or a future `POST /whoami` inherits it.
- [x] Retarget, never delete, the two tests that prove the scope gate
      end to end and that break by construction here
      (`lorica-api/src/tests.rs:9356` and `:9423`). They are the only
      two that drive a real 403 through the whole stack; deleting them
      leaves the gate unproven while every suite stays green.
- [x] A sentinel for "no scope required" in `openapi-automation.yaml`
      and the arm that reads it in
      `lorica-api/tests/openapi_contract.rs:184`. The contract test
      currently fails any documented operation without an
      `x-required-scope`, so the state is unrepresentable and the gate
      would go red on a correct implementation.
- [x] AC #1, the crate skeleton only. It builds and does nothing. The
      enumerations it has to land in are listed in the Code Map, and
      there are far more than the three Dockerfiles the AC names.

### Lot 2: the automation read surface, then the core and the tools

Absorbing the read surface into this lot was decided 2026-09-22. The
lot carries two natures of work and that is accepted: the endpoints
have to exist before a client of them means anything.

- [x] The automation plane gains its read surface, because it has none
      (see Dev Notes): logs, WAF events and stats, SLA, cluster and
      node status, backends, routes, certificate metadata. Each one
      declared in `required_scope`, paginated with a hard cap,
      stripped of secrets, audited, and documented in
      `openapi-automation.yaml` against the contract test.

- [x] The fix pass over that half, from five parallel audits of
      `031d9e0e` and `4610b594`: the log read's ordering defect, the
      unbounded `offset`, the fleet roster's removal from this plane,
      the AC #5 sweep derived from the scope matrix rather than
      transcribed beside it, and the field-name SET pinned rather than
      only its forbidden subset. The `lorica-mcp` library seam lands
      here too, ahead of the lot it serves, because it is free while
      the crate is empty. See the Completion Notes.

- [x] AC #1, the rest: configuration intake, endpoint and token from
      environment or config file, and a refusal with a clear message if
      either arrives on argv.
- [x] The protocol core: JSON-RPC framing, `server/discover`,
      `tools/list`, `tools/call`, error mapping. Transport-agnostic, no
      I/O in it. **Not `initialize`**: that method belongs to the eras
      this revision replaced, and the Dev Note "What revision
      2026-07-28 actually requires" has the normative detail read from
      the specification rather than from the PRD.
- [x] AC #3: startup introspection against `whoami`, tool registration
      from the returned scopes, and the no-scope case that produces a
      server with no tools and says why.
- [x] AC #4: the read tools, each one paginated with a hard row cap.
- [x] AC #5: the secret-name sweep over every tool's output, as a test
      that walks the field names rather than a review promise.
- [x] AC #7: the untrusted-text field, its delimiters, and the tool
      descriptions that say what it is. It lives in the shared core, so
      a tool added later gets it by construction.

### Lot 3: stdio, and the first calls that actually flow

- [x] AC #10: the stdio adapter over the core.
- [x] The concrete HTTPS `ReadSource` the adapter needs, with a named
      CA bundle and no way to switch verification off.
- [x] AC #6: the transport marker in the audit row, in the only honest
      shape available (see Dev Notes). It lands here rather than in lot
      2 because nothing reaches the listener until a transport exists
      to carry it.
- [x] IV1, IV2, IV3 as tests.
- [x] AC #8: `docs/mcp.md` for the read tier over stdio. AC #11's
      revision statement and maintenance note landed with it rather
      than waiting for lot 4, because a document that omits which
      revision it describes is worse than no document.

### Lot 4: the Streamable HTTP binding

- [x] AC #9: the Streamable HTTP adapter as a path on the automation
      listener. `Origin` validation, protocol-version pinning, and the
      header-versus-body mirror check. The path is declared in
      `required_scope` or it is reachable by nobody.
- [x] AC #11: the implemented revision and the maintenance note in
      `docs/mcp.md`, and the client configuration for the second
      transport.
- [x] `lorica-api/openapi.yaml` for the new scopes and the endpoint,
      green against the contract test. `CHANGELOG.md` under Added and
      Security. The endpoint is an automation-plane path, so it is
      documented in `openapi-automation.yaml`; `openapi.yaml`'s scope
      enum was already updated in lot 1, as its Completion Notes
      record, and that document describes the management socket, which
      the MCP endpoint is not on.
- [x] The two items lot 2 deferred here because both need the
      dependency this lot creates: the in-process `ReadSource` over the
      read handlers, and the guard pinning each tool's declared scope
      against what `required_scope` requires of the path it reads.
- [x] Authorization per tool call, which the scope matrix cannot
      express as it stands. Decided 2026-09-23: the endpoint is
      declared `AnyLiveToken` and every `tools/call` is authorized
      against the presented token's scopes. See the Dev Note below.
- [x] The fix pass over lots 2b, 3 and 4, from five parallel audits of
      `1e19c93a`, `cc3a46c8` and `ebcf8874`: the invocation budget the
      HTTP binding did not have, the audit row that said `ok` for every
      refused call, the assertion headers a caller could overwrite the
      tool with, the fence that rescanned per depth, and the guard that
      guarded nothing. See the Completion Notes.

## Dev Notes

### A scope spelling lives in six places, and one edge is guarded by nothing

The doc comment on `AutomationScope`
(`lorica-config/src/models/automation_token.rs:110`) says three. It is
wrong, and so was the first draft of this note. The copies are:

1. the serde renames on the enum itself;
2. `scope_str`, `lorica-api/src/automation/scope.rs:153`, the string an
   operator reads in a 403;
3. `scope_wire_name`, `lorica-api/src/automation/audit.rs:254`;
4. `AUTOMATION_AUDIT_REASONS`, `lorica-api/src/automation/audit.rs:127`,
   which embeds scope names inside refusal reasons and is hand-typed;
5. `automation-scopes.fixture.ts` under
   `lorica-dashboard/frontend/src/components/settings-tabs/`;
6. `ALL_SCOPES` in `AutomationTokensTab.svelte`, what the mint form
   actually renders.

Tests pin 2, 3 and 4 against 1, and `AutomationTokensTab.test.ts` pins
6 against 5. **Nothing pins 5 against anything in Rust.** That is the
language boundary, and it is the one edge with no guard: add a variant
on the Rust side and forget the fixture, and the Rust suite passes, the
frontend suite passes, and the mint form simply cannot offer the scope.
Silent in both directions.

Going from four scopes to nine multiplies the occasions. Lot 1
therefore closes that edge rather than adding five more unguarded
entries, per `.claude/rules/derived-not-transcribed.md`, which names
this exact pair as the trigger to build a vector set rather than write
another lock-step comment. The fixture becomes derived from the enum
and exempt from prettier, because a formatter rewriting a shared
artefact turns a byte comparison into noise on every line.

### The automation plane has no read surface to be a client of

AC #4 reads as though the tools wrap endpoints that exist. They do not.
`build_automation_router` (`lorica-api/src/automation/router.rs:123`)
mounts exactly four entries: `whoami`, the environments collection, and
one environment by name for GET, PUT and DELETE. There is no logs path,
no WAF path, no SLA path, no cluster path, no backends path, no routes
path and no certificates path on that listener.

The management API has all of them (`/api/v1/logs`, `/api/v1/waf/events`,
`/api/v1/waf/stats`, `/api/v1/sla/overview`, `/api/v1/sla/routes/{id}`,
`/api/v1/backends`, `/api/v1/routes`, and the certificate paths), but
PRD decision D3 puts the MCP server on the automation listener
precisely so it never holds a management credential. So the surface has
to be built, not borrowed. That work is the first half of lot 2.

This is the largest thing the story's own acceptance criteria do not
say out loud, and it is why lot 2 carries two natures of work.

### A scopeless token cannot exist

AC #3 says a token with no read scope produces a server with no tools.
Minting refuses an empty `scopes` array
(`lorica-api/src/automation/automation_tokens/tests.rs:609`), so the
case is never "a token carrying nothing": it is "a token carrying some
scope, none of which this tier uses". `docs/mcp.md` must not promise
the scopeless token, because an operator cannot mint one.

An unknown scope string fails to deserialise rather than being dropped,
so a 1.9.0 token presented to a 1.8.0 node is refused outright. That is
the intended behaviour and the upgrade note belongs in the changelog.

### What revision 2026-07-28 actually requires

Read from the specification pages on 2026-09-23, not from the PRD's
summary of them. The PRD was written against a reading of 2026-09-16
and is right in outline and wrong in one structural detail.

**There is no `initialize` in this revision.** The lot 2 task below
said the core implements "`initialize`, `tools/list`, `tools/call`".
That is the shape of protocol versions up to and including 2025-11-25.
In 2026-07-28 the handshake is gone and every request carries its own
metadata in `_meta.io.modelcontextprotocol/*`: the protocol version,
the client info, the client capabilities. The discovery call that
replaces the handshake is **`server/discover`**, which answers a
`DiscoverResult` carrying `supportedVersions`. The core methods this
crate implements are therefore `server/discover`, `tools/list` and
`tools/call`, plus `notifications/cancelled` on stdio.

**The message directions are constrained.** Servers do not initiate
JSON-RPC requests and clients do not send JSON-RPC responses. Anything
the server needs from the client travels as an `InputRequiredResult`
that the client answers by retrying the original call. The read tier
needs none of that, but a core written as a general JSON-RPC peer would
be building a direction the protocol forbids.

**stdio framing.** One JSON-RPC message per line, newline-delimited,
UTF-8, no embedded newlines. `stdout` carries nothing that is not a
valid MCP message; `stderr` is free for logging and the client is told
not to read anything into it. The server exits promptly when `stdin`
closes or reads EOF: that is the portable graceful-shutdown signal.

**Streamable HTTP, the parts that are MUST.** A single endpoint
accepting POST. `Origin` validated on every connection, and a present
but invalid one answered `403`. Every POST carries `MCP-Protocol-Version`,
`Mcp-Method` (from `method`) and, for `tools/call`, `Mcp-Name` (from
`params.name`). Each MUST equal its body counterpart; a mismatch, a
missing required header or an invalid character is `400` with JSON-RPC
error code **-32020** `HeaderMismatch`. A version the server does not
implement is `400` with `UnsupportedProtocolVersionError` listing what
it does support. An unknown method is **`404`** with `-32601`, which is
not what a JSON-RPC server usually does and is deliberate: it lets a
client tell a modern server from a legacy one. A notification POST is
`202` with no body, though this revision defines no client-to-server
notification over HTTP.

**Header values may be Base64-sentinel encoded** as `=?base64?...?=`
when they cannot be plain ASCII, and a server MUST decode before
comparing to the body. Comparing the raw header to the body instead
would make the mismatch check bypassable, which is the whole reason the
check exists.

**What this revision removed, and what to answer if it arrives.** No
protocol-level sessions, no standalone GET stream, no `Last-Event-ID`
resumability. `GET` or `DELETE` on the endpoint answers `405`. An
`Mcp-Session-Id` header is ignored and never echoed. A `Last-Event-ID`
is ignored.

**The tool surface, read from the same source.** A `tools/list` result
carries `resultType: "complete"`, a `tools` array, and optionally
`nextCursor`, `ttlMs` and `cacheScope`. A tool definition is `name`,
optional `title`, `description`, optional `icons`, `inputSchema` and
optional `outputSchema` and `annotations`. `inputSchema` MUST be a
valid JSON Schema object and never `null`; a tool taking no arguments
declares `{"type": "object", "additionalProperties": false}`. Tool
names are 1 to 128 characters from `[A-Za-z0-9_.-]`, case-sensitive.

A `tools/call` result carries `content` (an array of typed blocks:
`text`, `image`, `audio`, `resource_link`, `resource`), an `isError`
flag, and optionally `structuredContent` conforming to the declared
`outputSchema`. A tool that returns structured content SHOULD also put
the serialised JSON in a text block.

**Two error channels, and they are not interchangeable.** A protocol
error is a JSON-RPC error and covers an unknown tool or a malformed
request. A tool execution error is a normal result with
`isError: true`, and it is what a model can read and correct. An
authorization refusal from the API behind us is an execution error, not
a protocol error: the model should see it and stop, not retry blindly.

**The specification explicitly blesses the tier design.** The tool set
"MUST NOT vary per-connection or as a side effect of other requests on
the connection", but it "MAY vary by the authorization presented on the
request, for example returning only the tools the caller's granted
scopes permit, since credentials are per-request input, not connection
state". AC #3 is therefore the sanctioned pattern rather than a
deviation.

**Four server MUSTs on tools** land on us: validate every tool input,
implement access controls, **rate limit tool invocations**, and
sanitise tool outputs. The HTTP binding inherits the automation
listener's per-IP limiter for the third; stdio has no limiter at all
and the crate owns that one itself.

> Amended 2026-09-23 by the fix pass over lot 4: the sentence about
> the HTTP binding was wrong. The listener's per-IP limiter counts
> connections at accept, and a keep-alive or HTTP/2 caller issues
> requests without opening one, so it bounds no invocation. The budget
> is the core's on both bindings, per token, held by the process on
> the HTTP binding. See the fix-pass Completion Notes.

**Decision taken here:** this crate implements 2026-07-28 and nothing
else. No `initialize` fallback for older clients, no legacy era. AC #11
already requires the crate to state its revision, and a second era
would double the surface that has to stay correct against attacker-fed
text.

Whether to also speak the `initialize` era for clients that have not
moved was put to the maintainer on 2026-09-23 and **refused**: one era,
and the specification already gives a client a deterministic way to
detect a modern server rather than guessing. Worth revisiting only on
evidence, meaning a real client that fails to connect, not on the
suspicion that some might.

### AC #6 cannot be wholly true over stdio, so the row says which half is

AC #6 asks that a tool call be audited with the token's `public_id`,
the tool name, the redacted arguments and a marker naming the transport
as MCP. Two of those four are not observable where the audit is
written. The MCP server is a separate process that reaches the plane
over HTTP, and at that layer there is no tool: a tool is a concept of
the protocol the server speaks, not of the one it speaks over.

The shape taken, decided 2026-09-23 rather than left to the
implementation: the server declares the transport and the tool name in
`lorica-asserted-transport` and `lorica-asserted-tool`, and the node
records them inside an `asserted[...]` clause that appears nowhere else
in the row. Everything outside that clause is something the node
established: the principal from verifying the credential, the method,
path and query parameter names from the request line, the status from
what it answered.

Anyone holding a live token can send any header, so both asserted
values are bounded in length and character set before they reach a row.
The two spellings are pinned between the crates by
`lorica-api/tests/mcp_asserted_headers.rs`, which reads the emitting
source rather than depending on the crate, so the API does not gain a
dependency on the MCP server in order to agree with it.

What this does not give: proof. It gives provenance, clearly labelled.
An audit trail that cannot tell a claim from a proof is telling a story
that is not true, which is the reasoning the epic already gives for
distinguishing a model from a person.

> Amended 2026-09-23 by the fix pass over lot 4: this note is about
> stdio. On the Streamable HTTP binding the node holds the facts: it
> routed the request to the MCP path, parsed the body, refused it
> unless `Mcp-Name` agreed, and resolved the tool against the
> catalogue. The row for that binding records the tool and the
> declared argument names as established, outside any `asserted[...]`
> clause, and ignores the two `lorica-asserted-*` headers on that path.
> See the fix-pass Completion Notes.

### AC #1 and AC #9 are not in conflict

AC #1 says "stdio transport, no listener" and AC #9 mounts Streamable
HTTP on the automation listener. Read top-down that looks like a
contradiction, and a developer building the crate before reaching AC #9
will resolve it the wrong way. It is not one: `lorica-mcp` opens no
socket of its own in either binding. The HTTP adapter runs inside
`lorica-api`, on the listener Story 10.3 already built, which is
precisely what "no third management plane" means. The crate stays a
subprocess and a library; the listener stays the only thing that binds.

### The MCP endpoint cannot be declared behind one scope

Decided 2026-09-23, in lot 4, because the matrix has no state that fits
and guessing one would have been the wrong kind of cheap.

`required_scope` answers one requirement per `(method, path)`. An MCP
request carries its own tool, and each tool has its own scope, so there
is no single answer that is true of the endpoint. The three shapes
available were: declare it behind the widest read scope, which grants
nine reads to a token that should reach one; declare it behind each
tool's scope by inspecting the body in the gate, which puts body
parsing in a middleware that runs before the body is read; or declare
it `AnyLiveToken` and authorize per call inside.

The third is what landed. `ScopeRequirement::AnyLiveToken` already
exists for `whoami`, and it is not a wider grant in either case: it is
the statement that the path's own gate is somewhere else. For `whoami`
that somewhere else is "nothing is disclosed". For the MCP endpoint it
is `McpServer::over`, which builds that request's tool registry from
the scopes the presented principal carries, so a tool the token cannot
reach is absent from its `tools/list` and unknown to its `tools/call`.
The specification blesses precisely this: a tool set "MAY vary by the
authorization presented on the request ... since credentials are
per-request input, not connection state", while it "MUST NOT vary
per-connection or as a side effect of other requests".

**That per-tool check reads the matrix and not a third table.** There
were already two statements of one rule: a scope per tool in
`lorica-mcp`'s catalogue and a scope per path in `required_scope`.
`lorica-api/tests/mcp_catalogue_scopes.rs` pins them, one assertion per
catalogue entry, with the path taken from `ToolSpec::path_for` rather
than typed again and both spellings resolved through `AutomationScope`
rather than compared as strings.

The loosening direction is what makes this a security guard rather than
a tidiness one, and the in-process binding is why. The adapter calls
the read HANDLER, not the listener, so the scope gate does not run on
the read it performs: a tool declaring a looser scope than its path
would read what the gate would have refused. The tightening direction
is the quiet one, where the tool simply never registers, nothing fails,
and an operator concludes the feature does not work.

### An undeclared path is reachable by nobody

`required_scope` is a single matrix and its default is `None`, which
refuses every token including one carrying every scope. The MCP
endpoint added in AC #9 is a new path on that listener: if it is not
declared in the matrix it answers 403 to everyone, which is the
fail-closed outcome but looks like a broken build. Declare it with the
rest of AC #9, not afterwards.

### AC #4's "cluster and node status" is served in part

Decided 2026-09-23, during the fix pass. AC #4 asks for "cluster and
node status". This surface answers the first and not the second:
`/automation/v1/cluster/status` is mounted, the fleet roster is not.

The reason is that the roster is the one cluster read the management
API gates at `Operator` rather than `Viewer`
(`middleware/authorize.rs`), and the comment there gives the grounds in
terms that apply verbatim to a token: it discloses each follower's
source address and the hostnames whose certificate private keys it
holds. Epic 9 raised that floor on purpose (backlog #69). The first
implementation read the roster at `Role::Viewer` and recorded that as a
narrowing; it is not one. `Role::Viewer` gates exactly one field of
that answer, `resources`, so `session_peer`, `selected_for_hostnames`
and `certificate_ids` crossed at every role and therefore to every
`cluster:read` token, off-box, behind a credential with no role at all.
On a delegated fleet that hands a model the map of which node holds
which private key and where each follower dials from.

`/cluster/status` is `Viewer` on both planes, carries the node's role,
build, applied generation and hash, and on a control plane a one-line
entry per fleet member. That is the answer the story's own motivating
question needs ("why is this route 502-ing"); the roster is not.

**Decided 2026-09-23: it stays out.** The maintainer was offered a
projection stripping those three fields, and a dedicated
operator-equivalent scope, and refused both. The roster is not on this
plane and `cluster:read` reaches status alone.

The reasoning that follows still stands and is kept because it is what
would have to be answered if the question ever reopens. Such a
projection would cost this module its "nothing here filters" property,
which is the property the whole wrapper design rests on, so it needs a
test of its own if it lands. Meanwhile `docs/mcp.md` must not promise a
node listing.

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

## Code Map

Investigated 2026-09-22. Line numbers are from that day's tree.

### The scope gate, what lot 1 changes

- `lorica-api/src/automation/scope.rs:67` `required_scope`, the whole
  matrix. `:71` the whoami arm, path-only with no method match. `:94`
  the fail-closed fallback. `:108` `authorize_scope`, which runs inside
  the bearer gate and requires the principal extension.
- `lorica-api/src/automation/scope.rs:153` `scope_str`.
- `lorica-api/src/automation/audit.rs:254` `scope_wire_name`, `:127`
  `AUTOMATION_AUDIT_REASONS`, `:282` `refusal_reason`. The last one
  maps "no scope in the matrix" to `no_declared_scope`; the new state
  must map to no reason at all, or a handler-raised 403 gets
  mislabelled.
- `lorica-api/src/automation/auth.rs:200` `AutomationPrincipal`, `:314`
  its extractor, `:376` where it enters the extensions. It already
  carries everything `whoami` returns. Nothing to change here.
- `lorica-api/src/automation/router.rs:123` the router and its layer
  order, documented at `:109`. Audit outermost and unconditional, then
  the panic net, then the bearer gate, then the scope gate.
- `lorica-api/src/automation/mod.rs:92` re-exports `required_scope`.
  The contract test reaches it as `lorica_api::automation::...`, so a
  new type must be public and re-exported beside it.

Tests that pin the current rule and must be updated rather than
removed: the doctest at `scope.rs:52`, `whoami_needs_only_the_read_scope`
`scope.rs:168`, `an_undeclared_path_is_reachable_by_nobody...`
`scope.rs:176`, `the_layer_refuses_an_undeclared_path...` `scope.rs:233`
(which transcribes all four scopes in a principal literal and has to
grow to nine), and in `audit.rs` the pair at `:508` and `:544`. In
`lorica-api/src/tests.rs`, `:9356` and `:9423` break by construction:
they use whoami as the negative scope case and are the only two that
drive a real 403 through the full stack.

- `lorica-api/openapi-automation.yaml:91` and the prose at `:87`.
- `lorica-api/tests/openapi_contract.rs:184`, which fails any documented
  operation lacking `x-required-scope` and otherwise compares it to a
  serialised `AutomationScope`. "No scope" is unrepresentable there
  today.

### The artefact guard, the idiom to copy

`lorica-api/tests/openapi_contract.rs` is the house pattern and the one
to follow: `include_str!` on the committed file, an extraction sanity
assertion before any comparison, two `BTreeSet`s diffed both ways, and
a `panic!` carrying a message that tells the developer what to do. It
is explicit that nothing is auto-written. Put the new reader in
`tests/` rather than `src/`, so a renamed fixture is a test failure
with a readable message rather than a compile error.

There is no `insta`, no golden-file crate and no snapshot directory in
the workspace.

### Adding a workspace member, the full list

`.claude/rules/lorica-rust.md:78` names four items and is incomplete.
The last crates added were `lorica-challenge` and `lorica-geoip` in
`7e2831e2`; copy that. Build breaks without:

- `Cargo.toml:34` members.
- `Dockerfile:57`, `Dockerfile.dev:50`, `tests-e2e-docker/Dockerfile:47`,
  each appending a `COPY` line before the `tinyufo` line.
- `ci-check.Dockerfile:32` and `:39`. A fourth Dockerfile the rule does
  not mention.

Then the enumerations that fail quietly: `.github/workflows/ci.yml:45`,
`:204` and `:253`; `docs/BUMP-CHECKLIST.md:8` and its hand-duplicated
twin `.claude/skills/bump-version/bump-checklist.md:20`; the crate
tables in `README.md:365`, `FORK.md:64` and `CONTRIBUTING.md:32`; the
crate lists in the `run-tests` and `build-deb` skills; the inventories
under `docs/architecture/`.

Nothing to change in `deny.toml`, `.cargo/audit.toml`, the `dist/`
packaging scripts or the RPM spec: they package one binary and the only
crate list there is the Debian copyright stanza for the forked crates.

Manifest shape: copy `lorica-geoip/Cargo.toml:1`. Version hard-coded,
no `[workspace.package]`, dependencies declared directly except the
Pingora-inherited ones, siblings by path. There is no `[lints]` table
anywhere; lints are inner attributes at the top of the root source
file.

### Frontend gates

`eslint.config.js:83` already ignores `**/*.generated.ts` and nothing
matches it. `tsconfig.app.json:20` sweeps every `src/**/*.ts`
regardless, so the generated file must be strict-clean. Three local
gates, all required: `npm run check`, `npm run lint`, `npx vitest run`.
The existing consumer is
`AutomationTokensTab.test.ts:8` and `:52`.

### Do not touch

The data plane. No story in this epic adds a code path inside
`request_filter`.

## Dev Agent Record

### Debug Log

Lot 1, 2026-09-22. Gates run, all on the branch as it stands:

- `cargo fmt --all -- --check` on the Windows host: clean (it needed one
  pass of `cargo fmt --all` first, on two files).
- `cargo build -p lorica-mcp` in `rust:1-bookworm` with
  `RUSTFLAGS=-D warnings`: clean.
- `cargo test -p lorica-config -p lorica-api`: 826 + 495 unit, 2 in the
  new `tests/automation_scope_fixture.rs`, 3 in `tests/openapi_contract.rs`,
  8 + 18 doctests. 0 failed.
- `cargo clippy -p lorica-config -p lorica-waf -p lorica-api -p lorica-notify -p lorica-bench -p lorica-mcp -- -D warnings`: clean.
- `cargo clippy -p lorica-api -p lorica-cluster --all-targets -- -D warnings`: clean.
- `cargo clippy -p lorica --all-targets --features otel -- -D warnings`:
  clean. Run because the binary links both changed crates.
- Frontend: `svelte-check --tsconfig ./tsconfig.app.json` 0 errors 0
  warnings, `tsc -p tsconfig.node.json` clean, `eslint .` clean,
  `vitest run` 502 passed across 25 files. Vitest ran in `node:22-slim`
  over a fresh `pnpm install --frozen-lockfile`: the host's
  `node_modules` has no rolldown native binding for its Node 25.

`cargo audit` was NOT run: no dependency changed in this lot and
`lorica-mcp` declares none.

Lot 2, first half (the automation read surface), 2026-09-23. Gates run
in `rust:1-bookworm` with `RUSTFLAGS=-D warnings` unless noted:

- `cargo fmt --all -- --check` on the Windows host: clean (it needed
  one pass of `cargo fmt --all` first, on three files).
- `cargo test -p lorica-config -p lorica-api`: 843 + 495 unit, 2 in
  `tests/automation_scope_fixture.rs`, 3 in `tests/openapi_contract.rs`,
  8 + 18 doctests. 0 failed. The lib count went 826 -> 843.
- `cargo test -p lorica-api --test openapi_contract --test automation_scope_fixture`:
  3 + 2 passed, 0 failed.
- `cargo clippy -p lorica-config -p lorica-waf -p lorica-api -p lorica-notify -p lorica-bench -p lorica-mcp -- -D warnings`: clean.
- `cargo clippy -p lorica-api -p lorica-cluster --all-targets -- -D warnings`: clean.
- `cargo clippy -p lorica --all-targets --features otel -- -D warnings`:
  clean. Run because `get_status`'s return type changed and the binary
  links the crate.

`cargo audit` was NOT run: no dependency changed. Nothing in this half
touches the frontend, so its three gates were not re-run.

Lot 2, the fix pass over the first half, 2026-09-23. Gates run in
`rust:1-bookworm` with `RUSTFLAGS=-D warnings` unless noted:

- `cargo fmt --all -- --check` on the Windows host: clean (it needed
  one pass of `cargo fmt --all` first, on three files).
- `cargo test -p lorica-config -p lorica-api`: 853 + 495 unit, 3 in
  `tests/automation_scope_fixture.rs`, 4 in `tests/openapi_contract.rs`,
  8 + 18 doctests. 0 failed. The `lorica-api` lib count went 843 -> 853.
- `cargo test -p lorica-api --test openapi_contract --test automation_scope_fixture`:
  4 + 3 passed, 0 failed.
- `cargo test -p lorica-mcp`: 2 passed (the library's seam tests; the
  crate had no test target at all before it had a `lib.rs`).
- `cargo build -p lorica-mcp`: clean.
- `cargo clippy -p lorica-config -p lorica-waf -p lorica-api -p lorica-notify -p lorica-bench -p lorica-mcp -- -D warnings`: clean.
- `cargo clippy -p lorica-api -p lorica-cluster --all-targets -- -D warnings`: clean.
- `cargo clippy -p lorica --all-targets --features otel -- -D warnings`:
  clean.

- `README.md`'s product-crate test count, recomputed with the
  `docs/BUMP-CHECKLIST.md` recipe rather than incremented by hand:
  2663 -> 2694. It had already drifted by the first half of this lot
  and nothing recomputes it.

`cargo audit` was NOT run: no dependency was added or bumped.
`lorica-mcp` still declares none, and the response-hardening headers
are a `from_fn` middleware rather than a new `tower-http` feature for
two constants. Nothing here touches the frontend.

**Every fix was watched failing before it was watched passing.** Each
defect was reintroduced in the tree, the named test run, and the file
restored byte-exact (md5 checked before and after):

- the log reversal removed: `the_first_page_of_the_log_is_the_newest_rows_and_the_offset_walks_backwards`
  answered `["ordered-34" ..= "ordered-38"]` where it wanted
  `["ordered-39" ..= "ordered-35"]`, which is the defect exactly: the
  window's oldest end, with the newest row unreachable.
- `page_within` swapped back to `page` on the WAF read:
  `an_offset_past_what_a_source_can_answer_is_refused_and_not_an_empty_page`
  got 200 where it wanted 400.
- the roster path declared again in the matrix:
  `automation::scope::tests::the_fleet_roster_is_reachable_by_no_token_on_this_plane`
  and `tests::the_fleet_roster_is_not_reachable_on_the_automation_plane`
  both failed.
- a path added to `scope::READ_SURFACE` and to nothing else:
  `no_automation_read_answer_carries_a_secret_field_name` immediately
  drove it and failed on its 200 assertion, which is the property the
  hand-written `AUTOMATION_READS` could not have.
- the field-name pin failed on its first run by construction, listing
  all 139 names the surface answers; the committed list is that output.

Lot 2, second half (the protocol core and the read tools), 2026-09-23.
Gates run in `rust:1-bookworm` with `RUSTFLAGS=-D warnings` unless
noted:

- `cargo fmt --all -- --check` on the Windows host: clean (it needed
  one pass of `cargo fmt --all` first, on the five new files).
- `cargo build -p lorica-mcp`: clean.
- `cargo test -p lorica-mcp`: 48 passed, 0 failed. The crate went from
  2 tests to 48.
- `cargo test -p lorica-config -p lorica-api`: 853 + 495 unit, 3 in
  `tests/automation_scope_fixture.rs`, 4 in `tests/openapi_contract.rs`,
  8 + 18 doctests. 0 failed, unchanged from the fix pass as expected:
  nothing outside `lorica-mcp/` was touched.
- `cargo clippy -p lorica-config -p lorica-waf -p lorica-api -p lorica-notify -p lorica-bench -p lorica-mcp -- -D warnings`: clean.
- `git ls-files --eol -o --exclude-standard lorica-mcp`: `w/lf` on all
  five new files, and `i/lf w/lf` on the four already tracked. Checked
  this way and not with the `awk` recipe, which reports 0 on CRLF files
  on this host.
- `README.md`'s product-crate test count, recomputed with the
  `docs/BUMP-CHECKLIST.md` recipe rather than incremented by hand:
  2694 -> 2740.

`cargo audit`: run, because `lorica-mcp/Cargo.toml` gained entries and
`Cargo.lock` changed. Exit 0 over 651 crate dependencies, no
vulnerability, and the same two allowed unmaintained warnings the
cycle already carries (`RUSTSEC-2024-0388` on `derivative`,
`RUSTSEC-2025-0134` on `rustls-pemfile`). The `Cargo.lock` diff is
eight lines naming the four runtime crates and the one dev crate under
`lorica-mcp`: no `[[package]]` entry was added and no version moved
anywhere, which is why the advisory result cannot differ from the
previous run and why none of these is a new dependency in the sense
the project forbids without approval. Run in a container with its own
target directory rather than the shared `lorica-target` volume: with
`CARGO_TARGET_DIR` pointed at the volume, `cargo install cargo-audit`
contends with every other `cargo` in this session for the same lock
and stalled for forty minutes on a link step.

**Every new test was watched failing before it was watched passing.**
Each property was removed from the tree with a one-line substitution,
the named test run, and the tree restored from a pristine copy checked
with `md5sum` before and after. Eighteen probes, seventeen of which
introduced the defect they meant to (the eighteenth, a `sed` over an
arm containing `&id`, was void because `&` is the whole match in a
`sed` replacement; `discovery_names_the_one_revision_this_crate_implements`
is therefore covered by `initialize` answering `METHOD_NOT_FOUND` in
the same test rather than by a probe). What failed, and how:

- the argv refusal removed: `an_argument_refuses_the_start_and_says_where_the_token_goes_instead`
  built a configuration out of `--token <secret>` rather than refusing.
- the token character check removed: `a_token_that_cannot_travel_in_a_header_is_refused_without_being_quoted`
  accepted a token carrying a newline.
- the scope filter in `McpServer::over` replaced by `true`: both
  `the_server_asks_what_its_token_can_do_before_it_offers_anything` and
  `a_token_carrying_no_scope_of_this_tier_starts_with_no_tools_and_says_why`
  failed, the second registering nine tools for a token carrying only
  `environments:write`.
- the numeric range check removed: `a_value_outside_its_declaration_is_refused_before_it_reaches_the_plane`
  let `limit=201` and `status=600` reach a built path.
- the percent-encoding removed: `a_resource_id_is_one_encoded_segment_and_cannot_move_the_read`
  built `/automation/v1/sla/routes/../../whoami`.
- a `secret_hmac` key added to the `server/discover` result:
  `no_answer_this_server_builds_carries_a_credential_field_name` drove
  it immediately, which is the property a hand-listed sweep could not
  have.
- the untrusted notice dropped from `ToolSpec::description`:
  `every_tool_description_states_that_the_delimited_text_is_data`
  failed on every tool.
- the fence suffix pinned rather than grown:
  `a_payload_that_spells_the_marker_cannot_close_the_block` found the
  forged END marker closing the block early, with the rest of the
  payload outside it.
- `delimited` bypassed in `answer`: `the_server_writes_no_prose_but_its_own_notice`
  failed with no block to find.
- `isError` flipped to false in `execution_error`:
  `an_authorization_refusal_is_an_execution_error_and_not_a_protocol_one`
  failed, which is the flag a model reads to stop.
- the invocation budget removed: `tool_invocations_are_rate_limited_and_the_limit_is_an_execution_error`
  ran past 120 calls.
- `logs:read` misspelled as `log:read` in the catalogue:
  `every_scope_the_catalogue_names_is_one_the_token_model_declares`
  failed, which is the cross-crate edge this crate would otherwise
  carry silently.
- the notification guard removed: `a_notification_is_answered_by_silence`
  got a `METHOD_NOT_FOUND` response to a `notifications/cancelled`.
- the blank-variable filter removed:
  `a_file_carries_them_when_the_environment_does_not_and_loses_when_it_does`
  let an environment variable set to the empty string shadow the
  file's value.
- the self-decided refusal fenced anyway:
  `a_failure_this_server_decided_by_itself_fences_nothing` found the
  notice above an empty block, which tells a model that silence is
  data.
- `PAGINATION` appended twice in `ToolSpec::params`:
  `every_input_schema_is_an_object_that_admits_nothing_undeclared`
  failed on the name-uniqueness assertion, which is what stops a
  filter that shares a name with a window argument from travelling
  twice in one query string.

Lot 4 (the Streamable HTTP binding), 2026-09-23. Gates run in
`rust:1-bookworm` with `RUSTFLAGS=-D warnings` unless noted:

- `cargo fmt --all -- --check` on the Windows host: clean (it needed
  one pass of `cargo fmt --all` first, on four files).
- `cargo build -p lorica-mcp`: clean.
- `cargo test -p lorica-mcp`: 65 passed, 0 failed. Unchanged: this lot
  touches the crate's `lib.rs` documentation and nothing else in it.
- `cargo test -p lorica-config -p lorica-api`: 885 + 495 unit, 3 in
  `tests/automation_scope_fixture.rs`, 3 in
  `tests/mcp_asserted_headers.rs`, 4 in the new
  `tests/mcp_catalogue_scopes.rs`, 4 in `tests/openapi_contract.rs`,
  8 + 18 doctests. 0 failed. The `lorica-api` lib count went 857 -> 885
  and `mcp_asserted_headers.rs` 2 -> 3.
- `cargo test -p lorica-api --test openapi_contract --test mcp_catalogue_scopes --test mcp_asserted_headers --test automation_scope_fixture`:
  4 + 4 + 3 + 3 passed, 0 failed.
- `cargo clippy -p lorica-config -p lorica-waf -p lorica-api -p lorica-notify -p lorica-bench -p lorica-mcp -- -D warnings`: clean.
- `cargo clippy -p lorica-api -p lorica-cluster --all-targets -- -D warnings`:
  one failure first, `called .err().expect() on a Result value` in the
  new module's test helper, fixed to `expect_err`; clean after. Worth
  recording because the first clippy invocation does NOT pass
  `--all-targets`, so it compiled none of this and stayed green.
- `cargo clippy -p lorica --all-targets --features otel -- -D warnings`:
  clean. Run because the binary links `lorica-api`, which gained a
  dependency.
- `cargo clippy -p lorica-mcp --all-targets -- -D warnings`: clean. Not
  one of the three the Lint job runs; added here because the first one
  covers the crate without its tests.
- `cargo audit`: run, because `Cargo.lock` changed. Exit 0 over 651
  crate dependencies, and the same two allowed unmaintained warnings
  the cycle already carries (`RUSTSEC-2024-0388` on `derivative`,
  `RUSTSEC-2025-0134` on `rustls-pemfile`). The `Cargo.lock` diff is
  two lines, `lorica-mcp` and `percent-encoding` under `lorica-api`:
  no `[[package]]` entry was added and no version moved anywhere,
  which is why the result cannot differ from the previous run and why
  neither is a new dependency in the sense the project forbids without
  approval. Run in a container with its own target directory rather
  than the shared volume, for the reason lot 2 recorded.
- `git ls-files --eol`: `w/lf` on both new files and consistent on
  every modified one, with the index `lf` throughout. Checked this way
  and not with `awk`, which reports 0 on CRLF files on this host.
- `README.md`'s product-crate test count, recomputed with the
  `docs/BUMP-CHECKLIST.md` recipe rather than incremented by hand:
  2763 -> 2796, in BOTH places, the shell comment and the
  `Lorica%20Tests-N` badge. `grep -n 2763 README.md CONTRIBUTING.md`
  answers nothing.

Nothing here touches the frontend, so its three gates were not re-run.

**Every new test was watched failing before it was watched passing.**
Sixteen probes: each property was removed from the tree with a single
substitution, the named test was run, and the file was restored and
checked byte for byte with md5 before and after. Fifteen introduced the
defect they meant to on the first attempt; the sixteenth was void and
what it exposed is recorded below it.

- the Origin refusal removed: `an_origin_header_is_refused_whatever_it_names`
  and `an_origin_header_is_refused_through_the_whole_stack` both failed.
- an absent `MCP-Protocol-Version` read as the supported one:
  `every_post_carries_the_protocol_version_and_an_absent_one_is_a_mismatch`
  failed.
- the unsupported-revision check removed:
  `a_version_this_server_does_not_implement_names_what_it_does` failed.
- the header-versus-`_meta` version check removed:
  `the_version_header_must_equal_the_one_the_body_meta_names` failed.
- the `Mcp-Method` mirror check removed:
  `the_method_header_must_equal_the_body_method` failed.
- the `Mcp-Name` mirror check removed:
  `the_name_header_is_required_on_a_call_and_must_equal_the_body`
  failed.
- the decoded sentinel discarded and the raw header compared instead:
  `a_header_is_decoded_out_of_its_base64_sentinel_before_it_is_compared`
  failed.
- the sentinel wire shape moved away from `=?base64?...?=`: the same
  test failed.
- the unknown-method 404 removed:
  `a_method_this_server_does_not_implement_is_a_404` failed.
- a notification answered 200 instead of 202:
  `a_notification_is_accepted_with_no_body_at_all` failed.
- the per-tool authorization replaced by the whole catalogue:
  `the_tool_set_is_the_one_the_presented_token_can_reach_and_nothing_else`
  failed, offering nine tools to a token carrying `logs:read`.
- the MCP path declared for `POST` alone in the matrix:
  `the_verbs_this_revision_removed_answer_405_and_not_403` failed with
  a 403 where the revision asks for a 405.
- the `Mcp-Name` header dropped from the asserted clause:
  `a_tool_call_on_this_binding_is_audited_on_the_path_that_is_its_transport`
  failed with a row naming no tool.
- one tool declaring a scope its path does not sit behind:
  `every_mcp_tool_names_the_scope_its_path_sits_behind` failed, which
  is the guard lot 2 deferred here.
- one read left out of the in-process dispatch:
  `every_registered_tool_answers_through_the_endpoint_without_leaving_the_process`
  failed on that tool's `isError`, which is the property a hand-listed
  dispatch could not have.
- the in-process adapter importing an HTTP client:
  `this_module_opens_no_connection_of_its_own` failed.

**The void probe, and what it found.** Changing `SENTINEL_PREFIX` did
not fail the sentinel test on its first version, because that test
built its own sentinel FROM the constant: the mutation moved both sides
together and the comparison still held. That is a test that would have
stayed green while every real sentinel arrived undecoded. The test now
writes the wire shape out literally and asserts the constants equal it,
which is the direction the derived-not-transcribed rule runs in here:
the constant is derived from the specification, not the test from the
constant. Both probes fail against the corrected test.

Lot 4, the fix pass, 2026-09-23. Gates run in `rust:1-bookworm` with
`RUSTFLAGS=-D warnings` unless noted, one container at a time, after
the post-lot-4 e2e suite had written its teardown line:

- `cargo fmt --all -- --check` on the Windows host: clean (it needed
  one pass of `cargo fmt --all` first, on eight files).
- `cargo test -p lorica-mcp`: 74 passed, 0 failed. The crate went from
  65 tests to 74. One failure on the first run,
  `no_code_is_declared_that_this_server_never_answers_with`, because
  the new module doc spelled the code the scan forbids; the sentence
  was reworded to name it without the number.
- `cargo test -p lorica-config -p lorica-api`: 894 + 495 unit (one
  pre-existing ignored in `lorica-config`, untouched here), 3 in
  `tests/automation_scope_fixture.rs`, 3 in
  `tests/mcp_asserted_headers.rs`, 4 in `tests/mcp_catalogue_scopes.rs`,
  4 in `tests/openapi_contract.rs`, 8 + 18 doctests. 0 failed. The
  `lorica-api` lib count went 885 -> 894.
- Every integration test under `lorica-api/tests/` by name, as above:
  `automation_scope_fixture` 3, `mcp_asserted_headers` 3,
  `mcp_catalogue_scopes` 4, `openapi_contract` 4.
- `cargo clippy -p lorica-config -p lorica-waf -p lorica-api -p lorica-notify -p lorica-bench -- -D warnings`: clean.
- `cargo clippy -p lorica-api -p lorica-cluster --all-targets -- -D warnings`: clean.
- `cargo clippy -p lorica --all-targets --features otel -- -D warnings`:
  clean. Run because the binary constructs `AppState`, which gained a
  field.
- `cargo clippy -p lorica-mcp --all-targets -- -D warnings`: clean.
- `git ls-files --eol`: index `lf` on every changed file; the working
  tree shows `crlf` on the six of them the `core.autocrlf=true`
  checkout already held that way (untouched neighbours such as
  `lorica-api/src/logs.rs` show the same), and `lf` on the rest. No
  file changed ending.
- `README.md`'s product-crate test count, recomputed with the
  `docs/BUMP-CHECKLIST.md` recipe rather than incremented by hand:
  2796 -> 2814, in BOTH places, the shell comment and the
  `Lorica%20Tests-N` badge. `grep -n 2796 README.md CONTRIBUTING.md`
  answers nothing.

`cargo audit` was NOT run: no dependency was added or bumped and
`Cargo.lock` is untouched. `reqwest`'s `redirect` and `https_only` are
builder calls on a crate already here. Nothing here touches the
frontend.

**Every fix was watched failing before it was watched passing.** Each
defect was reintroduced in the tree with one substitution, the named
test run in the container, and the file restored from a copy and
checked with `md5sum` before and after (`8aed6ed4...` for `mcp.rs`,
`e205a604...` for `audit.rs`, `e89a1fb6...` for `untrusted.rs`,
`36bcdc69...` for `server.rs`, identical on every restore):

- the HTTP binding built its server over a fresh limiter again:
  `the_invocation_budget_binds_across_requests_on_this_binding` failed
  at the call past the budget, which answered `isError: false`.
- `McpServer::sharing` ignoring the limiter it is handed:
  `a_shared_limiter_keeps_a_tokens_window_across_the_servers_built_over_it`
  failed, the fresh server over the same token finding a fresh window.
- the audit layer keying the MCP row on the status again:
  `iv2_on_this_binding_a_tool_outside_the_grant_and_a_revoked_token_are_audited_as_refusals`
  failed with `automation.request.ok` where it wanted
  `automation.request.forbidden:certificates:read`.
- the lot 4 precedence restored (`lorica-asserted-tool` read on the
  MCP path and the claim kept over the record):
  `the_assertion_headers_cannot_replace_the_tool_the_node_ran_on_this_binding`
  failed with a row naming `lorica_waf_stats` for a call that ran
  `lorica_logs`.
- the one-pass fence choosing one past the deepest depth instead of
  the first free one:
  `the_one_pass_fence_answers_what_the_rescanning_one_did` failed on
  the body carrying depth 3 alone.
- the rescanning fence swapped back in, timed on the seeded input:
  `a_body_seeded_with_every_depth_costs_one_pass_and_not_one_per_depth`
  passed in 11.36 s (`finished in`), against 0.03 s one-pass. That
  test asserts the marker and not the clock, so this is the
  measurement rather than a probe that fails; the correctness probe is
  the one above it.
- a reference to `TRANSPORT_MARKER` added inside `mcp_endpoint`:
  `the_streamable_http_binding_asserts_nothing_and_needs_no_marker_of_its_own`
  failed. Its first version, which compared two path strings, would
  have stayed green.

### Completion Notes

**The third state is a type, not a sentinel scope.** `required_scope`
now returns `Option<ScopeRequirement>`: `None` keeps its meaning
(nothing declared, reachable by nobody), `Some(AnyLiveToken)` is the
new state and `Some(Scope(..))` the old one. `audit::refusal_reason`
maps `AnyLiveToken` to no reason, so a handler-raised 403 on `whoami`
is not mislabelled as a missing grant. The `whoami` arm is guarded on
`GET`, and a test asserts `POST`, `PUT` and `DELETE` on that path stay
undeclared.

**`AutomationScope::ALL` was added and is load-bearing.** The Dev Notes
call for closing the Rust-to-TypeScript edge rather than adding five
more unguarded entries, and the guard needs something in Rust that can
walk the vocabulary. `ALL` is that, pinned by
`all_carries_every_variant_the_enum_declares`, which reads this file's
own source with `include_str!` and compares the serde renames it finds
against `ALL`. Every list that used to retype the variants now walks
`ALL`: the `scope_str` spelling test, the `scope_wire_name` /
`AUTOMATION_AUDIT_REASONS` test, the widest-token principal in the
scope-layer test, and the new fixture gate.

**A seventh copy of the vocabulary existed and the Dev Notes do not
name it.** `AutomationScope` in
`lorica-dashboard/frontend/src/lib/api.ts` is a TypeScript union of the
same strings, and `ALL_SCOPES` is typed against it, so the union had to
grow or the branch would not typecheck. It is now pinned in one
direction by construction: `automation-scopes.generated.ts` is declared
`readonly AutomationScope[]`, so a scope in the generated file and
missing from the union fails `npm run check`, and the generated file is
itself diffed against `ALL` by the Rust gate.

**`ALL_SCOPES` is derived rather than restated.** It maps the generated
list, sorting the writes last so the reads stay first in the form. That
made the two old spelling tests vacuous, so they were replaced by one
that renders the create dialog and asserts a checkbox per wire scope,
and one that asserts the read-before-write order.

**Scope of the doc edits.** The whoami change and the five new scopes
touch prose in `docs/automation.md`, `README.md`,
`docs/architecture/api-design-and-integration.md` and both OpenAPI
documents. `openapi.yaml`'s `AutomationScope` enum was updated here
although lot 4 lists it: leaving the published mint schema short of the
scopes the mint form offers would be false for three lots. Fold it into
lot 4's bullet if that is not wanted.

**Not done, and deliberately.** `.claude/skills/bump-version/bump-checklist.md`
and the crate lists in the `run-tests` and `build-deb` skills are named
in the Code Map but live under `.claude/`, which this pass was told to
read only. They still need `lorica-mcp`.

**What the binary does.** It prints its name, version and the MCP
protocol revision it implements, then exits. No configuration intake,
no JSON-RPC, no transport: those are lots 2 and 3, and nothing here
stands in for them.

---

Lot 2, first half. `lorica-mcp/` was not touched: the JSON-RPC core and
the tools are the second half and nothing here stands in for them.

**Eleven paths, all `GET`.** `/automation/v1/logs` (`logs:read`),
`/waf/events` and `/waf/stats` (`waf:read`), `/sla/overview` and
`/sla/routes/{id}` (`sla:read`), `/cluster/status`, `/cluster/nodes`
and `/cluster/nodes/{id}` (`cluster:read`), `/backends`
(`backends:read`), `/routes` (`routes:read`), `/certificates`
(`certificates:read`). `required_scope` consults the read matrix for
`GET` alone, so no verb the router does not mount inherits a grant, and
a test asserts `POST`, `PUT`, `DELETE` and `PATCH` stay undeclared on
every one of them.

> Amended 2026-09-23 by the fix pass below: nine, not eleven.
> `/cluster/nodes` and `/cluster/nodes/{id}` were removed from this
> plane. See "AC #4's cluster and node status is served in part" in the
> Dev Notes for why, and the fix-pass notes for what moved.

**Every handler is a wrapper and computes nothing.** `logs`,
`waf/events`, `waf/stats`, `backends`, `routes` and `certificates` call
the management handler directly, which was possible because none of
those six takes a `Session`. The other three needed a split rather than
a rewrite: `sla::get_sla_overview` and `sla::get_route_sla` took a
`Session` only for the `?node=` cluster proxy, and `cluster::list_nodes`
and `cluster::get_node` only for the role that gates per-node host
telemetry. Those four now call `sla::local_sla_overview`,
`sla::local_route_sla`, `cluster::roster` and `cluster::one_node`, and
the automation handlers call the same four. `cluster::get_status`
changed from `impl IntoResponse` to `Json<Value>` so its answer can be
passed through; an opaque return type cannot be.

**Two deliberate narrowings against the management plane**, both
recorded in `docs/automation.md` and in the OpenAPI descriptions. The
SLA reads do not accept `?node=`: the proxy carries an Operator floor
and an automation credential has no role to weigh against it. The fleet
roster is read at `Role::Viewer`, so the Operator-only per-node CPU,
memory and disk figures are absent; the scope vocabulary cannot express
"this token is an operator", so reading anything above the floor would
hand every `cluster:read` token a view an operator kept for operators.

> Amended 2026-09-23: the second of those was not a narrowing.
> `Role::Viewer` gates one field of that answer and the endpoint as a
> whole sits at `Operator` on the management plane, so the roster was
> being served a role below where its own matrix put it. The paths are
> gone rather than narrowed.

**The page envelope carries no `total`.** Collections answer
`{"data": {"items": [...], "page": {limit, offset, returned, has_more}}}`.
`limit` is clamped to 200 server-side with no parameter that raises it,
50 by default. `total` was dropped on purpose: the log store counts
every match, the WAF buffer counts what it returned and a store listing
counts rows, so one field would have meant three things. Every source
is asked for one row past the window instead, which makes `has_more`
exact everywhere and costs one row.

**A management answer that changed shape is a 500, not an empty page.**
`rows()` pulls the array out of the management envelope by name and
refuses when it is not there. The failure it declines to hide: someone
renames `backends` in the management view, this surface keeps answering
200 with nothing in it, and an operator reads "no backends".

**AC #5 is a test, not a review promise.**
`no_automation_read_answer_carries_a_secret_field_name` seeds a node
with a certificate, a backend, a route carrying Basic auth, five log
rows and five WAF events, then drives every read path with a token
carrying `AutomationScope::ALL` and walks every key name and every
string value of every answer. Keys are matched as substrings against a
credential vocabulary; values are checked for PEM private-key blocks.
The sweep asserts it walked more than a hundred field names, because an
empty answer on every path would pass it trivially. `session` is
deliberately absent from the marker list: the roster legitimately
reports `session_peer` and `session_last_seen_unix`, which are
connection facts, so `session_id` and `cookie` are named instead.

**Audit needed nothing.** The audit layer is outermost and
unconditional, so every new path lands a row by construction, and
`AUTOMATION_AUDIT_REASONS` already carried all nine scope spellings
from lot 1.

**Not done here, and by scope.** `openapi.yaml` gains nothing: these
are automation-plane paths and that document describes the management
socket. `CHANGELOG.md` was updated under Added and Security although
lot 4 lists the changelog, because a read surface that ships without a
security note in the same edit is a note nobody writes later.

---

Lot 2, the fix pass over the first half, 2026-09-23. Five parallel
audits of `031d9e0e` and `4610b594` (security, architecture, quality,
performance, debt). Everything below is fixed in the same cycle; the
only thing carried forward is named as open, not deferred.

**The log read answered nearly the same window at every offset.** Both
log sources fetch the newest `scan` rows and hand them back OLDEST
first: the store runs `ORDER BY id DESC LIMIT ?` and then reverses
(`log_store.rs`), the in-memory fallback returns the tail of a
chronological buffer. `Page::of` walked that array from the FRONT, so
`skip(offset)` walked the window's oldest end. The arithmetic: with
more rows in the table than the scan, the array is exactly
`offset + limit + 1` long, index `offset+limit` is the newest row, and
`rows[offset .. offset+limit]` is the 2nd- through (limit+1)-th-newest
**whatever `offset` is**. The newest row was unreachable at every
offset, consecutive pages overlapped almost entirely, and
`has_more = rows.len() > offset + limit` was permanently true, so a
consumer honouring it paged forever over duplicates. `/waf/events` was
never affected: it returns descending and is not reversed. Fixed by
reversing to newest-first in `list_logs` before the window is cut, so
the two reads now agree and `offset` walks backwards in time. This is
the read tier's primary use case and NO test in the suite used `offset`
at all; the new one asserts which rows come back, not how many.

**`offset` was the caller's lever on how much work the node did.**
`limit` was clamped and `offset` was not, and `scan()` feeds the
source's own row budget, so `?offset=9999&limit=200` made the node run
a `COUNT(*)`, fetch 10 000 rows, build 10 000 `LogEntry` values and
serialise them, under the one `LogStore` mutex the audit drain shares,
to answer with one row. The same gap made the envelope answer
`{"items": [], "has_more": false}` on any window past a source's own
clamp. `PageQuery::page_within(depth)` now refuses such an offset with
a 400 naming the deepest window the requested `limit` can reach; the
two depths are `logs::LOGS_QUERY_MAX_ROWS` and
`waf::WAF_EVENTS_MAX_ROWS`, both newly named where the clamp is applied
rather than transcribed here. The unclamped sources keep `page()`: an
empty window on a listing the node holds in full is the truth.

**The fleet roster left this plane.** See the Dev Note. `read.rs` loses
`list_cluster_nodes`, `get_cluster_node` and `AUTOMATION_VIEW_ROLE`
(which had nothing left to gate and would not have compiled under
`-D warnings`); `scope.rs` loses `CLUSTER_NODES_PATH`; the router, the
OpenAPI document and `docs/automation.md` lose the two paths, and the
`NotAControlPlane` response component with them. `cluster::roster` and
`cluster::one_node` stay: the management handlers they were split out
of still call them, so the split is not reverted, only its second
consumer. Two tests assert the paths are refused, one on the matrix and
one through the whole stack.

**The AC #5 sweep is derived from the matrix, not typed beside it.**
`AUTOMATION_READS` hand-listed 8 paths while `scope::READ_SURFACE` and
the router declared 11, and three places said the sweep walked every
answer. The const is gone; `READ_SURFACE` moved to `scope.rs`'s module
level under `#[cfg(test)]` and both sweeps iterate it, substituting the
seeded route id for the one entry that names a resource. A path added
to the matrix now enters both sweeps by construction, which the probe
in the Debug Log demonstrates. The fixture is a control plane, so
`/cluster/status` answers its widest shape rather than a standalone
node's. The false claim is corrected in `read.rs`'s module doc, in the
test's own doc, in `docs/automation.md` and in this file.

**The field-name SET is pinned, not just its forbidden subset.** The
marker sweep asks whether a credential got out. It cannot ask what is
on this plane at all, and the answers are the management plane's own
views, so a field that is sensitive but not credential-shaped would
arrive with every gate green: `NodeResponse` used `#[serde(flatten)]`
over a store model, which is how a new column ships itself.
`every_automation_read_answers_only_the_field_names_this_surface_committed_to`
walks every read on the seeded node, collects the key names and diffs
them both ways against `AUTOMATION_READ_FIELD_NAMES`, 139 entries,
following the `openapi_contract.rs` idiom: extraction sanity first,
both directions, a `panic!` naming the decision, nothing auto-written.

**The rest, all from the same audits.** `local_sla_overview` takes the
window and stops one route past it, so the config-store mutex is no
longer held for `2R` queries to answer `?limit=1`. `list_backends`
builds the two merged worker maps once instead of `2B` times. `?search=`
is capped at 256 bytes on this plane, and `%` and `_` are escaped with
an `ESCAPE` clause in the store, so a search for `%` matches a per cent
sign on both planes rather than every row. The answer carries a 256 KiB
byte ceiling beside the row ceiling, dropping rows whole and reporting
the shortfall through `returned` and `has_more`. The audit row carries
the NAMES of the query parameters used, bounded in count and length,
and `automation_requests_by_path_total` counts per declared path
template (`scope::path_template`, derived from the same match
`required_scope` reads, so a caller-chosen id cannot become a label).
`openapi_contract.rs` gains a gate comparing the documented query
parameters of the three reused-filter reads against the serde field
names of the structs they reuse. The misplaced scope-array example
moved from `PipelineIdentity.user_login` to `WhoAmI.scopes`. The
cross-language scope guard strips comments before counting quoted
strings, so a commented-out entry no longer reads as present. The route
SLA 404 no longer echoes the caller's id back into a body a model
reads. The router adds `Cache-Control: no-store` and
`X-Content-Type-Options: nosniff` as a `from_fn` middleware, which
needs no new `tower-http` feature. `automation_token.rs` drops its
hand-written "four".

**`lorica-mcp` gains a library target.** It was binary-only with no
`lib.rs`, and lot 4 mounts the Streamable HTTP adapter INSIDE
`lorica-api`, which needs to depend on this crate. `lib.rs` carries
`MCP_PROTOCOL_REVISION`, a `ReadError` that keeps the status the
automation plane chose (an authorization refusal is a tool EXECUTION
error, not a protocol one, and that only survives if the status crosses
the seam), and `ReadSource`, one method taking a built path and
answering the JSON body verbatim. `main.rs` is now the stdio binary
over the library. **Nothing else was built**: no JSON-RPC core, no
tools, neither adapter. `lorica-api` does NOT yet depend on the crate;
that belongs to the lot that mounts the adapter. The seam is here now
because what decides whether AC #10's "one shared core" holds is how
the FIRST tool body reaches a read view, and that is cheaper to settle
while there are no tool bodies.

**Not done, and named rather than hidden.** No per-token request-rate
budget on the automation router: the listener's budgets are
connection-level and a keep-alive caller can issue requests without
one. The architecture audit proposes a per-principal in-flight cap;
that is a design decision, not a fix, and it belongs with the MCP
adapter that will be its heaviest caller. No OTel span on this plane
either (inherited from Story 10.3). Neither is deferred debt from this
story's own work; both are raised here so the next lot starts from a
true picture.

---

Lot 2, second half, 2026-09-23. `lorica-api` was not touched: this half
is entirely inside `lorica-mcp/`.

**Five modules, and the boundary each one holds.** `config.rs` is
AC #1, `jsonrpc.rs` the envelope, `untrusted.rs` AC #7, `tools.rs`
AC #4 and `server.rs` AC #3 plus the dispatch. `lib.rs` keeps the fetch
seam the fix pass landed and now names where each acceptance criterion
lives, so the next reader does not have to grep for it.

**AC #7 is the only way out, not a rule to follow.** The Dev Notes say
the regression to expect is a tool added later that formats its own
prose summary of a log row. A tool here cannot: `ToolSpec` is DATA, not
code. It has a name, a scope, a path and a parameter list, and no body.
The most a tool produces is a path; `untrusted::answer` and
`untrusted::execution_error` are the only two constructors of a
`tools/call` result in the crate and both take bytes that came from
outside, never a sentence a tool wrote.
`ToolSpec::description` appends `untrusted::NOTICE`
and `ToolSpec::definition` attaches `untrusted::output_schema`, so a
tool written in Story 11.2 carries the marking without its author
knowing the module exists.

The fence is grown, not fixed. `untrusted::fence` pads the marker stem
until neither marker occurs in the body, so a WAF matched value that
spells the END marker is inside the block rather than closing it. That
is deterministic and needs no RNG, which would have been a dependency
for a property this simple.

`structuredContent` carries the plane's body verbatim under ONE key
named `untrusted`, whose schema description is the same notice. The
page envelope is Lorica's own and trustworthy and it still sits under
that key: a boundary drawn INSIDE the answer is a boundary somebody has
to keep drawing correctly, and over-marking costs a consumer one level
of nesting.

**The two error channels are wired the way the Dev Notes require.** An
unknown tool, an unknown method, a malformed request and arguments that
do not fit the declared schema are JSON-RPC errors: no tool ran. From
the fetch onwards everything is a normal result with `isError: true`,
including the plane's 403, so a model reads the refusal and stops
instead of rewording the call. The prose above each fence is this
server's own constant sentence; the plane's own words go inside the
fence, because its 404 and 400 messages are shaped by what the caller
asked for.

**Nothing echoes the caller's text.** A rejected argument name, a
rejected value, an unknown tool name: none of them is repeated into a
message this server generates. The reader of those messages is the one
party that acts on them, so the rule AC #7 states about row text is
applied to argument text as well. The refusals name the declared
vocabulary instead, which is what a client actually needs.

**AC #3's registry is built once and never reconsulted.**
`McpServer::introspect` fetches `whoami`, and `McpServer::over` filters
the catalogue by the scopes it reported. There is no path that re-reads
scopes on a running server, which is what keeps Story 11.4's
one-process-one-tier check cheap. `over` is public because the
Streamable HTTP adapter has the principal on the request already and
asking `whoami` over a socket to learn what the process just
authenticated would be absurd.

The no-tool case is a token carrying scopes none of which this tier
uses, as the Dev Notes require, never a scopeless one.
`startup_notice()` names the token's `public_id`, what it carries, what
the tier uses and what to do. It is written for the operator reading
stderr and an adapter must not put it in a tool answer. The token's
operator-facing NAME is deliberately not kept on `Identity`: the id is
what somebody withdraws by, and the name is operator-authored text with
nowhere safe to go.

**A dependency decision, and why it is not a new dependency.** The four
runtime crates (`serde`, `serde_json`, `toml`, `percent-encoding`) are
each already in `Cargo.lock` at the version a sibling pins, and
`Cargo.lock`'s diff is eight lines naming them under `lorica-mcp` with
no version moving anywhere. `lorica-config` is a DEV dependency only:
it is what lets `every_scope_the_catalogue_names_is_one_the_token_model_declares`
parse this crate's seven scope strings back into `AutomationScope` and
diff the complement, closing the edge
`.claude/rules/derived-not-transcribed.md` is about, without putting
bundled SQLite in the dependency graph of a stdio subprocess that reads
no database. No MCP SDK, per D5.

**A rate limiter landed here rather than in an adapter.** Revision
2026-07-28 puts four server MUSTs on tools and the third is to rate
limit invocations; the Dev Notes record that the HTTP binding inherits
the listener's per-IP limiter and stdio has no limiter at all. The
budget is in the core, where every invocation of either binding passes,
rather than in the one adapter that lacks one. 120 calls a minute
bounds a model in a retry loop and not an operator reading a log, and
going over is an execution error so the model sees it.

**The `_meta` key spelling, corrected against the specification.** It
was first written `io.modelcontextprotocol/protocol-version` and
flagged as unverified. The specification spells it
**`io.modelcontextprotocol/protocolVersion`**, camelCase, and is
explicit about it: the Streamable HTTP binding requires the
`MCP-Protocol-Version` header to equal "the
`io.modelcontextprotocol/protocolVersion` field carried in the request
body's `_meta`". `jsonrpc::META_PROTOCOL_VERSION` now carries that
spelling, and it remains the single place it is written.

The sibling keys the same namespace defines, which lot 3 and lot 4 will
need and which are camelCase for the same reason:
`io.modelcontextprotocol/clientInfo`,
`io.modelcontextprotocol/clientCapabilities`, and on stdio
`io.modelcontextprotocol/subscriptionId` for correlating a
`subscriptions/listen` stream.

The version check stays deliberately lenient: a request carrying no
such key makes no claim and is answered, and only a version that IS
present and is not ours is refused. `server/discover` is exempt,
because it is how a client learns which revisions the server speaks.

**Not done here, and by scope.** No implementation of `ReadSource` that
speaks HTTPS: the core is generic over the seam and both concrete
sources belong to the bindings that hold a client or a request, which
is lot 3 and lot 4. `main.rs` therefore reads its configuration,
reports what it found on stderr and exits; the argv refusal is real and
observable there, the transport is not. No `docs/mcp.md`, no audit
transport marker, no `CHANGELOG.md` entry: the crate has no
user-visible behaviour until a transport carries it, and a changelog
line about a tool surface nobody can reach would be false for a lot.

**Named rather than hidden.** The tool paths are this crate's copy of
the automation plane's path vocabulary and nothing pins them against
`scope::required_scope`. They cannot be derived without depending on
`lorica-api`, which this crate must not do from `src/` and which lot 4
inverts anyway by making `lorica-api` depend on this crate. The guard
belongs in `lorica-api/tests/` in the lot that adds that dependency,
and it is one assertion per catalogue entry.

---

Lot 4, 2026-09-23. The Streamable HTTP binding, the in-process read
source, and the per-tool authorization the scope matrix cannot express.

**One module, and where its boundary is.**
`lorica-api/src/automation/mcp.rs` holds the whole binding: the
endpoint, the transport rules revision 2026-07-28 puts on a POST, and
`InProcessReads`. It decides nothing a method MEANS: every answer comes
from `lorica_mcp::server::McpServer::handle`, the same core the stdio
binary runs, which is what makes AC #10's "one shared core, two
bindings" a property of the code rather than a promise. `examine` is
pure, which is what lets every normative point of the transport be
asserted without a listener; the handler is the six lines around it.

**`lorica-api` now depends on `lorica-mcp`.** That is the inversion the
lot exists to make, and it is one-directional: nothing in `lorica-mcp`
depends on `lorica-api`, or the stdio subprocess would carry the whole
management crate and its bundled SQLite. `percent-encoding` joins it as
a direct dependency of `lorica-api`, because the tool layer encodes a
resource id into one path segment and the in-process source has to
decode it the way the listener's own extractor would have. Both crates
were already in `Cargo.lock` at the version a sibling pins.

**Authorization per tool, against the matrix and not a third table.**
See the Dev Note. `McpServer::over` builds the registry from the
presented principal's scopes, per request, and
`tests/mcp_catalogue_scopes.rs` is the guard lot 2 named: one assertion
per catalogue entry, path taken from the tool itself, spellings
resolved through `AutomationScope`.

**The in-process source is a dispatch over `scope.rs`'s own path
constants**, which were made `pub(super)` rather than retyped in the
adapter, so there is no third list of the read paths. A tool naming a
path with no arm is a 500 and not an empty answer, and
`every_registered_tool_answers_through_the_endpoint_without_leaving_the_process`
drives every registered tool through the endpoint, asserts `isError:
false` on each, and sweeps the answers for credential-shaped field
names. That last part is not redundant with the AC #5 sweep: the
in-process route bypasses the scope gate by design, so it needs its own
evidence that it does not also bypass the filtering. It does not, and
cannot, because it calls the same handler.

**Every `Origin` is refused, and that is the decision rather than the
default.** The specification's one MUST here is against DNS rebinding.
The usual implementation, accepting an origin whose host matches the
request's `Host`, is exactly what rebinding defeats: the attacker's
page and the attacker's DNS name agree with each other. This plane
serves no browser at all, and an MCP client speaking to it directly
sends no `Origin`, so a present one means a page is driving the
endpoint. An operator-configured allowlist is the additive change if a
browser front end ever needs one.

**`GET` and `DELETE` answer 405, which needed a matrix arm.** The MCP
path is declared for every method, unlike `whoami`, whose arm is
guarded on `GET`. The reason is the opposite of the usual one: leaving
the removed verbs undeclared would make the scope gate answer 403
first, which tells a client its token lacks a grant when the truth is
that the path answers one verb. The router mounts `post` alone and axum
produces the 405.

**The audit row for this binding, and why it says less than the stdio
one.** The stdio server asserts both its transport and its tool in two
headers of Lorica's own. This binding asserts neither, and needs to
assert only one: the node routed the request to `/automation/v1/mcp`
itself, so the path already in the row IS the transport, established.
The tool name comes from the revision's own `Mcp-Name`, which a
conforming client already sends, and `audit::asserted_clause` now reads
it into the same `asserted[...]` clause. It is labelled a claim even
though `mcp.rs` refuses a request whose header and body disagree: that
check runs INSIDE the audit layer, which writes a row for the refusals
too, so on a 200 row the mirror did hold and on a 400 row the value is
exactly what somebody claimed. One labelling that is never wrong beats
two that each need the status read first. Asking a conforming client
for a second header saying what `Mcp-Name` already says would have been
asking it to speak a dialect.

**`tests/mcp_asserted_headers.rs` stopped parsing source**, which its
own documentation said to do in this lot. It compared `include_str!`
extractions because neither crate could see the other; now
`lorica-api` depends on `lorica-mcp` and it compares the constants
themselves. A comparison that cannot misparse is worth more than one
that reads a file and might.

**The answer is one JSON object and not an SSE stream.** The revision
permits either. Every method this tier implements answers in one
message, so a stream would be an SSE frame per response and a second
framing to keep correct for nothing. `X-Accel-Buffering` is an SSE
concern and is correspondingly absent; if a streaming tool ever lands,
it arrives with both.

**No per-process rate budget on this binding, deliberately.** The
core's 120-calls-a-minute budget lives on an `McpServer`, and this
binding builds one per request, so it never fires here. That is
correct: the revision's "rate limit tool invocations" MUST is met by
the listener's connection caps and per-IP limiter, which stdio does not
have and which is why the core carries a budget at all. Moving the
budget to shared process state would make it a cross-token limiter on a
multi-tenant socket, which is a different policy nobody has decided.

> Amended 2026-09-23 by the fix pass below: that paragraph was wrong
> on both counts. The listener's budgets count connections, not calls,
> so the MUST was not met on this binding; and a budget keyed by the
> token's `public_id` is per token and not cross-token, which answers
> the objection. The budget is now held by the process and spent per
> token on both bindings.

**Not done, and named rather than hidden.** No per-token request-rate
budget on the automation router, which lot 2 raised as open: the
architecture audit's per-principal in-flight cap is still a design
decision, and this binding is now its heaviest plausible caller rather
than a hypothetical one. No OTel span on this plane either, inherited
from Story 10.3. `.claude/skills/bump-version/bump-checklist.md` and
the crate lists in the `run-tests` and `build-deb` skills still need
`lorica-mcp`, for the same reason lot 1 recorded: they live under
`.claude/`, which this pass was told to read only.

---

Lot 4, the fix pass, 2026-09-23. Five parallel audits of `1e19c93a`,
`cc3a46c8` and `ebcf8874` (security, architecture, quality,
performance, debt). Every finding that is a fix is fixed here and has a
test that was watched failing first; every finding that is a decision
is named at the end with its reason, and nothing is silently skipped.

**The HTTP binding had no invocation rate limit, and three documents
said it did.** `McpServer::over` was built per request and dropped
with it, so the core's budget counted one call and reset; the lot 2
and lot 4 notes, `docs/mcp.md` and a `CHANGELOG.md` bullet said the
listener's per-IP limiter bounded the binding, and that limiter counts
connections at accept, not requests. The budget now lives in
`lorica_mcp::server::InvocationLimiter`, a bounded map of fixed windows
keyed by the token's `public_id`. `McpServer::sharing(identity,
limiter)` is the constructor the HTTP binding uses over
`AppState::mcp_invocations`, one limiter for the process; `over` keeps
the stdio shape with a limiter of its own. The map holds at most
`MAX_TRACKED_TOKENS` (1024) live windows, sweeps elapsed ones when
full, and refuses a token that still finds no room rather than
evicting a live window, because eviction would hand a caller holding
more tokens than the ceiling a fresh budget per call. Every sentence
that claimed the listener covered this is corrected: `server.rs`'s
module and constant docs, `docs/mcp.md` "Rate limiting",
`docs/automation.md`'s MCP section, the two `CHANGELOG.md` bullets
that contradicted each other, and the two paragraphs of this file
amended above. Guarded by
`the_invocation_budget_binds_across_requests_on_this_binding` through
the whole stack, and
`a_shared_limiter_keeps_a_tokens_window_across_the_servers_built_over_it`
and `the_limiter_holds_a_bounded_number_of_windows_and_refuses_past_it`
in the core.

**The HTTP audit row and both request metrics said `ok` for every
refused call.** The audit layer keyed the outcome word on the status,
and the core answers everything it produced with a 200: a call on a
tool the token does not hold, a schema refusal, the rate limit and a
plane refusal all audited as `automation.request.ok`. The core now
reports what a message came to, `server::Outcome`, a closed vocabulary
(`Silence`, `Ok`, `ToolNotRegistered`, `InvalidParams`, `RateLimited`,
`Refused(status)`, `Failed`, `ProtocolError`), through
`McpServer::handle_reporting` and `McpServer::respond`; `handle` is
unchanged for stdio and the tests. The HTTP handler attaches an
`McpCallRecord` (tool, declared argument names, outcome) to the
response, and the audit layer, which is outermost and sees the
response after the request's extensions are gone, derives the word
from it: `ok`; `forbidden:<scope>` for a tool the catalogue knows and
the token does not hold, the same word and scope the read path behind
that tool writes; `forbidden:unknown_tool`; `refused:invalid_params`,
`refused:rate_limited`, `refused:protocol_error`; and for a tool that
ran and whose read the plane refused, the word that status already has
on every other row. The vocabulary stays the plane's five words, so the
metric label set does not grow; the four new reasons are in
`AUTOMATION_AUDIT_REASONS` and in `docs/automation.md`. Guarded by
`iv2_on_this_binding_a_tool_outside_the_grant_and_a_revoked_token_are_audited_as_refusals`
through the whole stack, `every_answer_reports_what_it_came_to` in the
core and `an_mcp_row_takes_its_outcome_from_the_core_and_not_from_the_200`
on the mapping. One nuance in the finding as stated: the revoked-token
half of IV2 was already true on this binding, since the bearer gate
refuses a revoked token with a 401 before the core runs and that row
said `unauthenticated:token_revoked` already; the test now proves it
alongside the half that was wrong.

**The asserted tool could be replaced or erased on the HTTP binding.**
`asserted_clause` read `lorica-asserted-tool` first and `Mcp-Name` raw
second, so a caller could name a different tool in the row than the one
the node ran, or send `Mcp-Name` in a Base64 sentinel and leave the row
with nothing readable. On `MCP_PATH` the audit layer now ignores both
`lorica-asserted-*` headers entirely. When the core ran, the record
above carries the tool the body named, which the mirror check proved
equal to the header, and the declared argument names it carried, and
the row writes them outside any clause:
`POST /automation/v1/mcp tool=lorica_logs?limit,search`. The argument
names are the `Param` vocabulary and never a caller's key, which is the
AC #6 "arguments after redaction" this binding did not record at all.
Only a POST the core never saw records the decoded `Mcp-Name`, through
the same `mirrored` decoder the mismatch check uses, as
`asserted[tool=...]`. Guarded by
`the_assertion_headers_cannot_replace_the_tool_the_node_ran_on_this_binding`
through the whole stack and the two unit tests on the clauses.

**`fence()` rescanned the whole body once per marker depth.** The
marker grew one `#` at a time and each step ran two `contains` over up
to 256 KiB, and a WAF row can seed markers at every depth. `fence` is
now one pass: every occurrence of either marker prefix yields the depth
it takes (the run of `#` behind it, when closed by the dashes), and the
answer is the first depth not taken, which is the same marker the loop
chose for every input. The old loop is kept in the test module as
`fence_by_rescanning` and
`the_one_pass_fence_answers_what_the_rescanning_one_did` compares the
two over the edge cases (a depth taken with no lower one taken, a run
not closed by dashes, a run longer than the depth under test, markers
touching). `a_body_seeded_with_every_depth_costs_one_pass_and_not_one_per_depth`
is the input the old shape paid for, 2000 depths; its timings under
both shapes are in the Debug Log. The performance report's bound on the
number of depths was loose: a depth-`k` marker costs about 30 + `k`
bytes, so a 256 KiB body holds roughly 700 distinct depths, not
thousands. The fix stands either way.

**A guard that guarded nothing.**
`the_streamable_http_binding_asserts_nothing_and_needs_no_marker_of_its_own`
compared two path strings and read no header. It now scans the
adapter's own source, the house style its siblings in `mcp.rs` use,
for the two assertion header constants, the transport marker and the
`lorica-asserted-` spelling, with a positive control on
`InProcessReads` and `McpCallRecord` so the scan cannot silently read
the wrong file. Watched failing by adding a reference to
`TRANSPORT_MARKER` inside `mcp_endpoint`.

**The rest, all from the same audits.** `scope_wire_name` is gone;
`scope::scope_str` is `pub(super)` and `audit.rs` calls it, one
spelling and one test. The MCP tool-name grammar is one function,
`tools::fits_tool_name_grammar` with `tools::TOOL_NAME_MAX_BYTES`, read
by the catalogue test, by the stdio client and by `audit::assertable`;
`http::is_assertable_tool` is gone. `jsonrpc::code::INTERNAL_ERROR` is
removed with the sentence that claimed the server answers with it, and
`no_code_is_declared_that_this_server_never_answers_with` pins the
absence. `jsonrpc::unsupported_protocol_version` is the one shape for
a revision this server does not speak, used by the core and by the
HTTP adapter, so a client negotiating from
`error.data.supportedVersions` works on both bindings.
`is_published_reason` reads the scope spellings from
`AutomationScope::ALL` through `scope_str` instead of a hand-typed
block in `AUTOMATION_AUDIT_REASONS`. The stdio client follows no
redirect and is `https_only`, pinned by a source scan. A route id of
`.` or `..` is refused before it builds a path, because `%2E` and
`%2E%2E` are dot segments to a WHATWG URL parser. The request path and
`User-Agent` are cut to 2048 and 512 bytes on a char boundary before
they reach a row. `stdio::read_message` applies the ceiling on the
newline branch too, and its EOF comment now says what the code does.
`ServerConfig::from_process` reads `args_os` so a non-UTF-8 argument
is refused rather than printed by a panic. `ReadError`'s `Display`
quotes at most 512 bytes of a refusal body, for the captive-portal
case. `examine` hands the core the parsed `Request`, so the HTTP
binding no longer clones the body's `Value` and parses it twice. Over
stdio, a call the server refuses by itself now writes one line on
stderr in the server's own words, since no row on the node can record
it; `docs/mcp.md` says so. The "nine entries" and "seven scope
spellings" counts are gone from the comments.

**Recorded as decisions, not done.**

- *A per-answer nonce in the fence marker* (security Low). The marker
  stays deterministic. The string property holds: the chosen marker
  occurs nowhere in the body, so the block cannot be closed early; the
  residual is a model that has learned the unpadded terminator across
  a session and must honour the notice about inner markers. A nonce
  needs a CSPRNG, and none is reachable from `lorica-mcp` without a new
  direct dependency (`rustls` holds one transitively through `reqwest`
  and exposes no API this crate could call), which needs approval.
  Revisit on evidence: a real client shown to follow a forged
  terminator.
- *A `client` feature flag on `lorica-mcp`* (architecture Low). Not
  done. It would gate `config`, `http` and `stdio` behind a default-on
  feature so `lorica-api` links only the core. The dead code is not a
  hazard and every dependency is already in the tree; a feature is one
  more thing the CI lists have to agree on.
- *The four copies of a 256 KiB answer between the handler and the
  wire* (performance Medium). Measure first, as the report itself says.
  Not done.
- *End-user secrets in query strings reach the model* (security
  Medium). `docs/mcp.md` now says plainly that "no secret leaves" is
  about Lorica's own secrets, and that request paths with their query
  strings, client addresses, User-Agents and WAF matched values are
  text end users and attackers wrote, may carry their own credentials,
  and cross unredacted because this plane cannot recognise what it
  would be redacting. Stripping query-string values in the management
  plane's log pipeline is a behaviour change for the dashboard and a
  decision, not a fix. **Open.**
- *The tier has no representation in the code* (architecture Medium,
  for Story 11.4). `over` is infallible and "the tier" is implicitly
  the whole catalogue. Story 11.4's one-tier check needs a tier table
  in `lorica-mcp` and a fallible constructor both bindings run, or the
  HTTP binding will serve a `logs:read + routes:write` token both tool
  sets. The overlap rule ("a token whose scopes span two tiers" when
  the config tier includes read scopes) is undefined and must be
  written down there. Recorded for 11.4; nothing here.
- *The in-process read source is a second router that cannot carry a
  write, and the tool model is GET-shaped* (architecture High and
  Medium, for Story 11.2). Recorded as a Dev Note in
  `docs/stories/story-11.2-config-tier.md` with the options the report
  gives and the recommended one. Nothing structural changed here.
- *A locally refused stdio call lands no row on the node.* The stderr
  line is the trace; making the node record it would mean the stdio
  server calling the plane about a call it refused, which is a design
  choice not taken.
- *A group- or world-readable `LORICA_MCP_CONFIG` file* (security
  Info). No warning added: the file is the operator's, and the check is
  platform-specific in a crate whose development host is Windows.
- *Repeated `Mcp-*` headers judged on their first value* (security
  Info). No change, as the report itself concludes.

## File List

Added:

- `lorica-mcp/Cargo.toml`
- `lorica-mcp/src/main.rs`
- `lorica-api/tests/automation_scope_fixture.rs`
- `lorica-dashboard/frontend/src/components/settings-tabs/automation-scopes.generated.ts`
- `lorica-api/src/automation/read.rs` (lot 2)
- `lorica-mcp/src/lib.rs`, `config.rs`, `jsonrpc.rs`, `untrusted.rs`,
  `tools.rs`, `server.rs` (lot 2)
- `lorica-mcp/src/stdio.rs`, `lorica-mcp/src/http.rs` (lot 3)
- `lorica-api/tests/mcp_asserted_headers.rs` (lot 3)
- `docs/mcp.md` (lot 3)

Removed:

- `lorica-dashboard/frontend/src/components/settings-tabs/automation-scopes.fixture.ts`
  (renamed to `.generated.ts`)

Modified:

- `Cargo.toml`, `Cargo.lock`
- `Dockerfile`, `Dockerfile.dev`, `tests-e2e-docker/Dockerfile`,
  `ci-check.Dockerfile`
- `.github/workflows/ci.yml`
- `lorica-config/src/models/automation_token.rs`
- `lorica-api/src/automation/scope.rs`
- `lorica-api/src/automation/audit.rs`
- `lorica-api/src/automation/mod.rs`
- `lorica-api/src/tests.rs`
- `lorica-api/tests/openapi_contract.rs`
- `lorica-api/openapi-automation.yaml`, `lorica-api/openapi.yaml`
- `lorica-dashboard/frontend/src/lib/api.ts`
- `lorica-dashboard/frontend/src/components/settings-tabs/AutomationTokensTab.svelte`
- `lorica-dashboard/frontend/src/components/settings-tabs/AutomationTokensTab.test.ts`
- `CHANGELOG.md`, `README.md`, `FORK.md`, `CONTRIBUTING.md`
- `docs/automation.md`, `docs/BUMP-CHECKLIST.md`,
  `docs/architecture/source-tree.md`,
  `docs/architecture/component-architecture.md`,
  `docs/architecture/api-design-and-integration.md`
- `docs/stories/story-11.1-mcp-crate-read-tier.md`

Modified in lot 2 (first half):

- `lorica-api/src/automation/mod.rs`, `.../router.rs`, `.../scope.rs`
- `lorica-api/src/cluster/mod.rs`, `lorica-api/src/sla.rs`,
  `lorica-api/src/routes/mod.rs`
- `lorica-api/src/tests.rs`
- `lorica-api/openapi-automation.yaml`
- `CHANGELOG.md`, `docs/automation.md`,
  `docs/architecture/api-design-and-integration.md`
- `docs/stories/story-11.1-mcp-crate-read-tier.md`

Added in lot 2 (the fix pass):

- `lorica-mcp/src/lib.rs`

Modified in lot 2 (the fix pass):

- `lorica-api/src/automation/read.rs`, `.../scope.rs`, `.../router.rs`,
  `.../audit.rs`, `.../mod.rs`
- `lorica-api/src/logs.rs`, `lorica-api/src/log_store.rs`,
  `lorica-api/src/waf.rs`, `lorica-api/src/sla.rs`,
  `lorica-api/src/backends.rs`, `lorica-api/src/metrics.rs`
- `lorica-api/src/tests.rs`
- `lorica-api/tests/openapi_contract.rs`,
  `lorica-api/tests/automation_scope_fixture.rs`
- `lorica-api/openapi-automation.yaml`
- `lorica-config/src/models/automation_token.rs`
- `lorica-mcp/Cargo.toml`, `lorica-mcp/src/main.rs`
- `CHANGELOG.md`, `README.md`, `docs/automation.md`
- `docs/stories/story-11.1-mcp-crate-read-tier.md`

Added in lot 2 (the second half):

- `lorica-mcp/src/config.rs`
- `lorica-mcp/src/jsonrpc.rs`
- `lorica-mcp/src/untrusted.rs`
- `lorica-mcp/src/tools.rs`
- `lorica-mcp/src/server.rs`

Modified in lot 2 (the second half):

- `lorica-mcp/Cargo.toml`, `lorica-mcp/src/lib.rs`,
  `lorica-mcp/src/main.rs`
- `Cargo.lock`, `README.md`
- `docs/stories/story-11.1-mcp-crate-read-tier.md`

Added in lot 4:

- `lorica-api/src/automation/mcp.rs`
- `lorica-api/tests/mcp_catalogue_scopes.rs`

Modified in lot 4:

- `lorica-api/Cargo.toml`, `Cargo.lock`
- `lorica-api/src/automation/mod.rs`, `.../router.rs`, `.../scope.rs`,
  `.../audit.rs`
- `lorica-api/src/tests.rs`
- `lorica-api/tests/mcp_asserted_headers.rs`
- `lorica-api/openapi-automation.yaml`
- `lorica-mcp/src/lib.rs`
- `CHANGELOG.md`, `README.md`
- `docs/mcp.md`, `docs/automation.md`
- `docs/stories/story-11.1-mcp-crate-read-tier.md`

Modified in lot 4 (the fix pass):

- `lorica-mcp/src/server.rs`, `.../jsonrpc.rs`, `.../untrusted.rs`,
  `.../tools.rs`, `.../http.rs`, `.../stdio.rs`, `.../config.rs`,
  `.../lib.rs`
- `lorica-api/src/automation/mcp.rs`, `.../audit.rs`, `.../scope.rs`,
  `.../mod.rs`
- `lorica-api/src/server.rs` (`AppState::mcp_invocations`), and the
  `AppState` constructors in `lorica-api/src/tests.rs`,
  `lorica-api/src/automation_tokens/tests.rs`,
  `lorica-api/src/oidc_issuers/tests.rs`, `lorica-api/src/acme/tests.rs`,
  `lorica/src/startup/single.rs`, `lorica/src/startup/supervisor.rs`
- `lorica-api/tests/mcp_asserted_headers.rs`
- `CHANGELOG.md`, `README.md`
- `docs/mcp.md`, `docs/automation.md`
- `docs/stories/story-11.1-mcp-crate-read-tier.md`,
  `docs/stories/story-11.2-config-tier.md`

## Change Log

- 2026-09-22: Story drafted from the Epic 11 PRD. D5 resolved as a
  hand-rolled JSON-RPC loop; the `whoami` scope change recorded as the
  one modification this story makes to the Story 10.3 gate.
- 2026-09-22: Tasks split into four lots and the status moved to
  InProgress. The lots are increments of this story inside the v1.9.0
  cycle, not deferred work: `docs/backlog.md` stays the only backlog.
- 2026-09-22: Code Map added from a codebase investigation, and four
  things the acceptance criteria assume but the tree contradicts are
  recorded in Dev Notes: the automation plane has no read surface, the
  scope vocabulary has six copies rather than three, "no scope
  required" is representable neither in `required_scope` nor in the
  OpenAPI contract test, and the frontend has no prettier to exempt a
  generated file from. Lot 2 absorbs the read surface by decision of
  the same day.
- 2026-09-22: Lot 1 landed. Five read scopes on `AutomationScope`, with
  `AutomationScope::ALL` added as the one list every restatement now
  walks; the Rust-to-TypeScript edge closed by
  `lorica-api/tests/automation_scope_fixture.rs` over the renamed
  `automation-scopes.generated.ts`; `whoami` moved to the new
  `ScopeRequirement::AnyLiveToken` state, documented in
  `openapi-automation.yaml` as `x-required-scope: any-live-token` and
  read by the contract test; the two end-to-end scope tests retargeted
  at the environment collection; and `lorica-mcp` added as a workspace
  member at 1.8.0. A seventh copy of the scope vocabulary was found in
  `lorica-dashboard/frontend/src/lib/api.ts`, which the Dev Notes' list
  of six does not mention.
- 2026-09-22: AC #4 confirmed at its full width after the question was
  put explicitly. All five read families stay in scope: logs, WAF, SLA,
  cluster and node status, and the read-only configuration listings.
  The narrower "logs and WAF first" increment was offered and refused,
  so lot 2 builds the whole read surface.
- 2026-09-23: the first half of lot 2 landed, the automation plane's
  read surface. Eleven `GET` paths in `lorica-api/src/automation/read.rs`,
  every one a wrapper over the management handler that already answers
  it, each declared in `required_scope` in the same edit and documented
  in `openapi-automation.yaml` with its `x-required-scope`. Four
  management handlers were split rather than rewritten so the
  automation plane could reach their computation without a `Session`
  (`sla::local_sla_overview`, `sla::local_route_sla`, `cluster::roster`,
  `cluster::one_node`), and `cluster::get_status` returns a concrete
  `Json` so its answer can be passed through. Collections answer a
  `{items, page}` envelope whose 200-row ceiling the caller cannot
  raise, and AC #5's secret sweep walks every field name and string
  value of every answer. `lorica-mcp/` untouched: the JSON-RPC core and
  the tools are the second half of the lot. Corrected the same day by
  the entry below: eleven became nine, and the sweep walked eight of
  the eleven rather than every answer.
- 2026-09-23: the fix pass over that half, from five parallel audits
  (security, architecture, quality, performance, debt) of `031d9e0e`
  and `4610b594`. One High each from three of them proved out and is
  fixed here. **The log read answered nearly the same window at every
  `offset` and never the newest row**, because both sources hand back
  their newest window oldest-first and the pager walked it from the
  front; rows are newest-first now and a test asserts which rows come
  back, which no test did before. **`offset` was unclamped**, which
  bought a 200x work amplification under the mutex the audit drain
  shares and made the envelope answer an empty page with
  `has_more: false` past a source's own clamp; an offset a source
  cannot reach is now a 400 naming the depth. **The fleet roster left
  this plane**: `/cluster/nodes` and `/cluster/nodes/{id}` were serving
  a `Viewer` view of an answer the management API gates at `Operator`
  because it names each follower's address and the hostnames whose
  private keys it holds, so AC #4's "cluster and node status" is now
  served in part, status yes and roster no, pending a decision recorded
  in the Dev Notes. **The AC #5 sweep is derived from
  `scope::READ_SURFACE`** rather than transcribed beside it, and a
  second test pins the whole set of field names each answer carries.
  Also: the SLA overview and the backend listing stop computing what
  they are about to discard, `?search=` is length-bounded and its
  wildcards escaped in the store, the answer carries a byte ceiling
  beside the row ceiling, the audit row names the query parameters used
  (never their values) and a per-path counter joins the plane-wide one,
  the OpenAPI document's reused query vocabulary is pinned against the
  structs it restates, and the cross-language scope guard stops
  counting commented-out entries. `lorica-mcp` gains a `lib.rs` with
  the fetch seam lot 4 needs and nothing else: no JSON-RPC core, no
  tools, no adapter.
- 2026-09-23: the second half of lot 2 landed, entirely inside
  `lorica-mcp/` and touching `lorica-api` not at all. Five modules:
  `config.rs` (AC #1, endpoint and token from the environment or a
  TOML file, argv refused outright because an argument publishes the
  token to `/proc`, and a redacting `Secret` so no `Debug` rendering
  prints it), `jsonrpc.rs` (the envelope, no I/O, no direction the
  revision forbids), `untrusted.rs` (AC #7), `tools.rs` (AC #4, nine
  read tools) and `server.rs` (AC #3 and the dispatch). The core
  methods are `server/discover`, `tools/list` and `tools/call`, plus
  `notifications/cancelled`; there is **no `initialize`**, and a test
  asserts it answers `METHOD_NOT_FOUND`. **AC #7 is structural rather
  than a convention**: a `ToolSpec` is data with no body, so the most
  a tool produces is a path, `untrusted::answer` is the sole
  constructor of a tool result, the notice is appended by
  `ToolSpec::description` and the fence marker grows until it appears
  nowhere in the payload, so a WAF matched value that spells the END
  marker cannot close the block. **The two error channels are
  separate**: an unknown tool or an argument outside the declared
  schema is a JSON-RPC error, and everything from the fetch onwards,
  the plane's 403 included, is a result with `isError: true` so a
  model reads the refusal and stops. Nothing echoes caller text into a
  message this server generates. The invocation rate limit the
  revision requires lives in the core rather than in the stdio
  adapter, because that is where both bindings pass. The four runtime
  dependencies are all already in `Cargo.lock` at their siblings'
  versions and no version moved; `lorica-config` is a dev dependency
  alone, guarding the seven scope spellings this crate names against
  `AutomationScope`. Not done and named: no HTTPS `ReadSource`, no
  transport, no `docs/mcp.md`, no changelog line, and no guard pinning
  the catalogue's paths against `scope::required_scope`, which belongs
  in `lorica-api/tests/` in the lot that makes `lorica-api` depend on
  this crate.

- 2026-09-23: Lot 3. The stdio adapter, the HTTPS `ReadSource` the
  adapter needs, the audit marker in its asserted-versus-established
  shape, IV1 to IV3, and `docs/mcp.md`. The crate went from 48 tests to
  65 and `lorica-api` from 853 to 857.

  The machine rebooted mid-lot. The code survived in the working tree
  and the gates were run afterwards rather than trusted: build, both
  test suites and clippy all clean under `RUSTFLAGS=-D warnings`.
  `cargo fmt` had not been run before the interruption and was, which
  is the gate that most often slips because no other gate reveals it.

  AC #11's revision statement and maintenance note landed here with
  `docs/mcp.md` rather than waiting for lot 4. A document that does not
  say which revision it describes is worse than no document, and the
  specification has moved three times in eighteen months.

  Still open for lot 4: the Streamable HTTP adapter, and the guard
  pinning the tool catalogue's paths against `scope::required_scope`,
  which needs the `lorica-api` dependency that lot inverts.

- 2026-09-23: Lot 4, the last of the story. The Streamable HTTP binding
  as `POST /automation/v1/mcp`, one path on the Story 10.3 listener
  rather than a port, so an operator who has not enabled that listener
  gains no MCP surface. `lorica-api` now depends on `lorica-mcp`, which
  is the inversion this lot exists to make: the adapter runs in process
  and reaches the read handlers directly, because dialling the listener
  it is mounted on would be refused by that listener's own source
  allowlist. The transport rules are implemented and each has a test:
  every `Origin` refused with 403, `MCP-Protocol-Version`, `Mcp-Method`
  and `Mcp-Name` validated against the body rather than trusted and
  Base64-sentinel decoded BEFORE the comparison, `-32020` for a
  mismatch, a 400 naming the supported revisions for a version this
  server does not speak, a **404** for a method it does not implement,
  202 for a notification, 405 for the `GET` and `DELETE` the revision
  removed, and an `Mcp-Session-Id` ignored and never echoed.
  **Authorization is per tool call**, decided the same day and recorded
  in a new Dev Note: the endpoint cannot be declared behind one scope
  because an MCP request carries its own tool, so it is declared
  `AnyLiveToken` and `McpServer::over` builds each request's tool
  registry from the scopes that request's token carries. The guard lot
  2 deferred here landed with it: `tests/mcp_catalogue_scopes.rs` pins
  each tool's declared scope against what the matrix requires of the
  path it reads, one assertion per entry, which matters because the
  in-process route bypasses the scope gate by design.
  `tests/mcp_asserted_headers.rs` stopped parsing source and compares
  constants, as its own documentation said to do in this lot. Sixteen
  probes; one was void and exposed a test that built its sentinel from
  the constant it was meant to guard, now corrected to the literal wire
  shape.

- 2026-09-23: the fix pass over lots 2b, 3 and 4, from five parallel
  audits (security, architecture, quality, performance, debt) of
  `1e19c93a`, `cc3a46c8` and `ebcf8874`. **The Streamable HTTP binding
  had no tool-invocation rate limit** while three documents said the
  listener's per-IP limiter covered it; the budget is now the token's,
  a bounded per-`public_id` window held by the process
  (`AppState::mcp_invocations`, `McpServer::sharing`), on both
  bindings, and every sentence that claimed otherwise is corrected,
  the two contradicting `CHANGELOG.md` bullets included. **The HTTP
  audit row and the request metrics said `ok` for every refused
  call**, because the core answers everything it produced with a 200;
  the core now reports an `Outcome` per message, the handler attaches
  an `McpCallRecord` to the response, and the row and the metrics take
  their word from it in the plane's existing five-word vocabulary,
  with `unknown_tool`, `invalid_params`, `rate_limited` and
  `protocol_error` as the new published reasons. **The asserted tool
  could be replaced or erased on that binding**; the two
  `lorica-asserted-*` headers are ignored on the MCP path, the tool
  the node ran and the declared argument names it carried are written
  as established, and only a POST the core never saw records the
  decoded `Mcp-Name` as a claim. **`fence()` is one pass** with the
  same marker for every input, pinned against the old loop kept as a
  test reference: 11.36 s against 0.03 s on a body seeded with 2000
  depths. **The guard that guarded nothing** scans the adapter's
  source with a positive control. Also: one `scope_str`, one tool-name
  grammar across the crates, `INTERNAL_ERROR` removed with the
  sentence that claimed it, one shape for the unsupported-revision
  refusal on both bindings, scope reasons derived from
  `AutomationScope::ALL`, no redirect and HTTPS only on the stdio
  client, `.` and `..` refused as route ids, path and `User-Agent`
  bounded in the row, the stdio ceiling on both read branches, one
  parse of the HTTP body instead of two, and a stderr line for a call
  the stdio server refuses by itself. `docs/mcp.md` now says "no
  secret leaves" is about Lorica's own secrets and that end-user query
  strings cross unredacted; redaction there is recorded as open, not
  done. The in-process seam's inability to carry a write is recorded
  as a Dev Note in Story 11.2 with the options and a recommendation.
  `lorica-mcp` went from 65 tests to 74 and `lorica-api` from 885 to
  894.
