# Story 11.1: The `lorica-mcp` Crate and the Read Tier

**Epic:** [Epic 11 - Management MCP Server with Tiered Access (v1.9.0)](../prd/epic-11-v1.9.0.md)
**Status:** InProgress
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

- [ ] AC #1, the rest: configuration intake, endpoint and token from
      environment or config file, and a refusal with a clear message if
      either arrives on argv.
- [ ] The protocol core: JSON-RPC framing, `server/discover`,
      `tools/list`, `tools/call`, error mapping. Transport-agnostic, no
      I/O in it. **Not `initialize`**: that method belongs to the eras
      this revision replaced, and the Dev Note "What revision
      2026-07-28 actually requires" has the normative detail read from
      the specification rather than from the PRD.
- [ ] AC #3: startup introspection against `whoami`, tool registration
      from the returned scopes, and the no-scope case that produces a
      server with no tools and says why.
- [ ] AC #4: the read tools, each one paginated with a hard row cap.
- [ ] AC #5: the secret-name sweep over every tool's output, as a test
      that walks the field names rather than a review promise.
- [ ] AC #7: the untrusted-text field, its delimiters, and the tool
      descriptions that say what it is. It lives in the shared core, so
      a tool added later gets it by construction.

### Lot 3: stdio, and the first calls that actually flow

- [ ] AC #10: the stdio adapter over the core.
- [ ] AC #6: the MCP transport marker in the audit row, and the
      argument redaction that precedes it. It lands here rather than in
      lot 2 because nothing reaches the listener until a transport
      exists to carry it.
- [ ] IV1, IV2, IV3 as tests.
- [ ] AC #8: `docs/mcp.md` for the read tier over stdio.

### Lot 4: the Streamable HTTP binding

- [ ] AC #9: the Streamable HTTP adapter as a path on the automation
      listener. `Origin` validation, protocol-version pinning, and the
      header-versus-body mirror check. The path is declared in
      `required_scope` or it is reachable by nobody.
- [ ] AC #11: the implemented revision and the maintenance note in
      `docs/mcp.md`, and the client configuration for the second
      transport.
- [ ] `lorica-api/openapi.yaml` for the new scopes and the endpoint,
      green against the contract test. `CHANGELOG.md` under Added and
      Security.

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

**Decision taken here:** this crate implements 2026-07-28 and nothing
else. No `initialize` fallback for older clients, no legacy era. AC #11
already requires the crate to state its revision, and a second era
would double the surface that has to stay correct against attacker-fed
text. Whether to also speak the `initialize` era for clients that have
not moved is a product decision, and it is open.

### AC #1 and AC #9 are not in conflict

AC #1 says "stdio transport, no listener" and AC #9 mounts Streamable
HTTP on the automation listener. Read top-down that looks like a
contradiction, and a developer building the crate before reaching AC #9
will resolve it the wrong way. It is not one: `lorica-mcp` opens no
socket of its own in either binding. The HTTP adapter runs inside
`lorica-api`, on the listener Story 10.3 already built, which is
precisely what "no third management plane" means. The crate stays a
subprocess and a library; the listener stays the only thing that binds.

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

## File List

Added:

- `lorica-mcp/Cargo.toml`
- `lorica-mcp/src/main.rs`
- `lorica-api/tests/automation_scope_fixture.rs`
- `lorica-dashboard/frontend/src/components/settings-tabs/automation-scopes.generated.ts`
- `lorica-api/src/automation/read.rs` (lot 2)

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
  the tools are the second half of the lot.
