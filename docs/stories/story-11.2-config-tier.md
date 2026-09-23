# Story 11.2: The Config Tier

**Epic:** [Epic 11 - Management MCP Server with Tiered Access (v1.9.0)](../prd/epic-11-v1.9.0.md)
**Status:** InProgress
**Priority:** P1
**Author:** Romain G.
**Depends on:** Story 11.1, all of it. The shared core, both transport
adapters, the scope plumbing and the introspection change are built
there and this story adds a tier over them, not a second server.
**Blocks:** nothing. Story 11.3 depends on 11.1, not on this.

---

As an operator,
I want to create and adjust routes, backends and certificates from my
MCP client,
so that a change I would have made in the dashboard takes one sentence,
with the same audit trail and the same validation.

## Problem

The read tier is useful and cannot act. The gap between reading "this
route is 502-ing because its only healthy backend was drained" and
fixing it is a dashboard session, and for a change that takes one
sentence to describe that is most of the work.

What makes this tier different from the read tier is not the verb. It
is that a session holding a mutating tool while reading attacker-
authored text is the exact failure the epic's tiering exists to
prevent. Everything below follows from that: the tier is a separate
process with a separate token, every mutation names one resource, and
nothing takes a predicate.

## Decisions taken in this story

**The automation plane has no write surface either.** This is the same
discovery Story 11.1 made about reads, and it is worth stating before
anyone estimates this story. `build_automation_router` serves the
environment resource and `whoami`, plus the nine read paths Story 11.1
added. There is no route write, no backend write, no certificate
binding on that listener. Under PRD decision D3 the MCP server is a
client of the automation plane and never of the management API, so
this story builds those endpoints before it builds a single tool. That
is the bulk of it, exactly as it was for 11.1.

**The reversal is recorded where the earlier decision lives.** Epic 10
Story 10.3 AC #5 says the automation surface is the environment
resource and not the management API behind a different door. AC #1
below reverses that for three write scopes. A pointer goes into the
Epic 10 PRD so the earlier decision is not silently contradicted by a
later file, per that story's own instruction.

## Acceptance Criteria

These are the PRD's, unchanged. They are the contract.

1. **This story reverses Epic 10 Story 10.3 AC #5** for `routes:write`,
   `backends:write` and `certificates:write`. The reversal is recorded
   in the Epic 10 PRD as a pointer to this story, so the earlier
   decision is not silently contradicted by a later file.
2. **A separate token and a separate server process from the read
   tier.** The config tier's tools include the read tools it needs to
   work, but a read-tier token can never gain them.
3. **Diff before apply.** Every mutating tool has a counterpart that
   returns the change it would make, against the current state, without
   making it. The tool descriptions say so, and the apply tool takes
   the same arguments, so a client can be configured to show the diff
   first.
4. **One named resource per call.** No pattern, no selector, no bulk.
   Deleting a route takes its id; there is no tool that deletes what
   matches.
5. **Validation is the API's, not the server's.** Every mutation goes
   through the same endpoints and therefore the same validators the
   dashboard uses; `lorica-mcp` does not reimplement a single field
   check, so the two surfaces cannot drift.
6. **Certificate private keys are never an argument.** A certificate
   can be selected, bound and renewed through the tier; key material is
   uploaded through the management API by a human.
7. Audit and documentation as in Story 11.1, plus a `docs/mcp.md`
   section on what makes a change safe to delegate to this tier and
   what does not.

## Integration Verification

- IV1: A config-tier call that creates a route produces the same stored
  object as the equivalent dashboard action, byte for byte in the
  canonical config hash.
- IV2: A mutation rejected by the API's validators surfaces the
  field-level error to the client unchanged, and nothing is written.
- IV3: In a cluster, a config-tier mutation on the control plane
  replicates to followers through the Story 9.4 path with no new code,
  and a config-tier server pointed at a follower is refused.

## Tasks

### Lot 1: the write scopes and the automation write surface

- [x] Three new `AutomationScope` variants: `routes:write`,
      `backends:write`, `certificates:write`. Every restatement moves
      with them; Story 11.1's Dev Notes name all of them and the guards
      that now catch a miss.
- [x] The write paths on the automation listener, each declared in
      `required_scope` with its verb, each going through the management
      plane's own handler and validators, each audited. The follower
      refusal (409) is inherited, not rewritten.
- [x] `openapi-automation.yaml` and the contract test.
- [x] The field-name pin test from Story 11.1 grows the request side:
      what a caller may send is as much a contract as what it receives.
- [x] AC #1: the Epic 10 PRD pointer at Story 10.3 AC #5, made precise
      (the three scopes, the story file, what bounds the reversal and
      what stands). Landed with lot 1 because the reversal is what lot
      1 ships; lot 2's AC #7 bullet keeps the `docs/mcp.md` half.

### Lot 2: the tier

- [ ] AC #2: the tier is chosen by the token's scopes at startup, over
      the same core. The read tools it needs come with it.
- [ ] AC #3: a preview counterpart per mutating tool, sharing the apply
      tool's arguments, computing the change against current state and
      writing nothing.
- [ ] AC #4: one named resource per call, enforced by the tool schemas
      rather than by a check inside the handler.
- [ ] AC #6: no argument anywhere in this tier accepts key material.
      A test asserts the tool schemas, not the handlers.
- [ ] IV1, IV2, IV3.
- [ ] AC #7: the `docs/mcp.md` section, and the Epic 10 PRD pointer.

## Dev Notes

### What "diff before apply" can and cannot promise

AC #3 asks for a preview tool per mutation. The protocol offers the
server no way to force a human to look at it: revision 2026-07-28 has
no server-initiated confirmation, and a client is free to call the
apply tool without ever calling the preview. The specification is
explicit that safety comes from tools that are narrow, unambiguously
named and impossible to invoke in bulk, never from assuming the client
asks first.

So the preview is an affordance, not a control. `docs/mcp.md` should
say that in those terms rather than implying a guarantee the protocol
cannot make.

### The in-process seam cannot carry a write, and this story must resolve that before its first write tool

Recorded 2026-09-23 from the architecture audit of Story 11.1's lot 4.
Nothing structural was changed there; this is the constraint the first
write tool on the Streamable HTTP binding meets.

`InProcessReads` in `lorica-api/src/automation/mcp.rs` is a second,
hand-written router. It dispatches over `scope.rs`'s path constants to
`super::read::*` directly, so three tables route the same reads (the
`.route(...)` literals in `router.rs`, the arms of
`scope::declaration`, and that `match`), and because it calls the
handlers rather than the router below its auth layer, the scope matrix
does not run on the in-process path at all: `McpServer::sharing`'s
registry filter is the only authorization, and
`tests/mcp_catalogue_scopes.rs` is what makes that acceptable for a
closed list of `GET` paths with no principal-dependent logic. The seam
itself, `ReadSource::fetch(path, reason)`, carries a path and nothing
else: no method, no body, no principal, no connection info, no headers.
The one existing automation write handler
(`environments::put_environment`) needs all five. The pin test compares
each tool against `required_scope(&Method::GET, ..)` and cannot pin a
write tool either, so a mis-declared write over this seam would be a
write-tier privilege escalation guarded by a test that only knows how
to ask about `GET`.

The options the audit gives, in the order it ranks them:

1. **Route in process instead of dispatching by hand.** Split
   `build_automation_router` into an inner router (routes plus
   `authorize_scope`, excluding `MCP_PATH`) and the outer layers (auth,
   hardening, audit, panic net). The adapter's source builds an
   `http::Request` carrying the method, path, body, the caller's
   `AutomationPrincipal` and `ConnectInfo` as extensions, and `oneshot`s
   it into the inner router. `ReadSource::fetch(path)` becomes
   `call(method, path, body)` on both implementations. The scope matrix
   then authorises every in-process call exactly as it does over stdio,
   the dispatch `match` disappears, the write handlers work unchanged
   with their per-token checks (`allowed_hostnames`,
   `allowed_backend_cidrs`) and their own domain audit rows, and the pin
   test degrades from security boundary to UX guard. Costs one request
   construction and one middleware pass per tool call, and the inner
   router must be built once (a `OnceLock` or a field on `AppState`).
2. **Generalise the seam and grow the dispatch.** Widen `ReadSource`
   to carry method, body and principal, and extend the hand-written
   match with the write arms. Every write then lives in four tables,
   and the only thing between a mis-declared write tool and an
   unauthorised mutation is the pin test, which has to learn every
   verb.

The tool model has the same shape problem one level up: `ToolSpec` is
`GET`-and-query shaped and validates every field, while AC #5 says
`lorica-mcp` does not reimplement a single field check and route,
backend and certificate bodies are nested objects `Text` and `Count`
cannot express. The audit's direction: extend `ToolSpec` with a method
and an optional body whose `inputSchema` is derived from the plane's
request schema in `openapi-automation.yaml`, with `lorica-mcp` checking
only shape, size and the single resource id; declare each mutation
once and generate its preview and apply tools from it, so AC #3's
"same arguments" is one declaration; and let the plane own preview as
a dry-run variant of each write endpoint, declared in the matrix under
the same scope.

Option 1 is the recommendation. Decide it in lot 1, before the first
write path is declared, because it changes what the write handlers are
called through.

### The cluster case is the interesting one

IV3 wants a config-tier mutation on a control plane to replicate with
no new code, and a config-tier server pointed at a follower to be
refused. The second half is already true and free: the automation
listener refuses to start on a node holding a follower identity, and
Story 10.3 IV3 covers it. The first half is a genuine verification
rather than a feature, and it belongs in the e2e cluster profile.

## Dev Agent Record

### Debug Log

Lot 1, 2026-09-23. Gates run in `rust:1-bookworm` with
`RUSTFLAGS=-D warnings`, one container at a time, unless noted:

- `cargo fmt --all -- --check` on the Windows host: clean (it needed
  one pass of `cargo fmt --all` first, on six files).
- `cargo test --no-fail-fast -p lorica-config -p lorica-api`: 908 + 495
  unit (one pre-existing ignored in `lorica-config`, untouched here),
  3 in `tests/automation_scope_fixture.rs`, 3 in
  `tests/mcp_asserted_headers.rs`, 4 in `tests/mcp_catalogue_scopes.rs`,
  6 in `tests/openapi_contract.rs`, 8 + 18 doctests. 0 failed. The
  `lorica-api` lib count went 894 -> 908 and `openapi_contract.rs`
  4 -> 6. The first run had one failure, in a probe of my own:
  `a_write_on_a_sub_resource_names_exactly_one_resource` expected
  `PUT /automation/v1/routes/certificate` to be undeclared, and it is a
  route whose id is `certificate`, one segment under the collection,
  which the matrix rightly answers with `routes:write`. The test now
  asserts that reading.
- Every integration test under `lorica-api/tests/` by name, as above:
  `automation_scope_fixture` 3, `mcp_asserted_headers` 3,
  `mcp_catalogue_scopes` 4, `openapi_contract` 6.
- `cargo test -p lorica-mcp`: 73 passed, **1 failed**, expected and
  outside this lot's files:
  `tools::tests::every_scope_the_catalogue_names_is_one_the_token_model_declares`
  asserts the complement of the catalogue's scopes is exactly
  `{environments:read, environments:write}` and now finds the three
  write scopes in it. See the Completion Notes; the fix is lot 2's.
- `cargo clippy -p lorica-config -p lorica-waf -p lorica-api -p lorica-notify -p lorica-bench -- -D warnings`: clean.
- `cargo clippy -p lorica-api -p lorica-cluster --all-targets -- -D warnings`: clean.
- `cargo clippy -p lorica --all-targets --features otel -- -D warnings`:
  clean. Run because the binary's `cli.rs` changed and it links
  `lorica-api`.
- `cargo clippy -p lorica-mcp --all-targets -- -D warnings`: clean.
- Frontend, in `node:22-slim` over a fresh `pnpm install
  --frozen-lockfile` on an in-container copy of the tree:
  `svelte-check --tsconfig ./tsconfig.app.json` 0 errors 0 warnings,
  `tsc -p tsconfig.node.json` clean, `eslint` clean, `vitest run` 502
  passed across 25 files. Run because the generated scope fixture and
  the `api.ts` union changed; the mint form derives its checkboxes from
  the fixture and the test beside it asserts one per wire scope.
- `git ls-files --eol`: index `lf` on every changed file; the working
  tree shows `crlf` on the ones the `core.autocrlf=true` checkout
  already held that way and `lf` on the rest, with the new
  `automation/write.rs` at `w/lf`. No file changed ending. Checked this
  way and not with `awk`.
- No em dash (U+2014) in any changed file, checked with a byte grep.
- `README.md`'s product-crate test count, recomputed with the
  `docs/BUMP-CHECKLIST.md` recipe over the README's own crate list
  with `--no-fail-fast`: 2814 -> 2830, in BOTH places, the shell
  comment and the `Lorica%20Tests-N` badge. Summing every `passed`
  figure the run printed gives 2829, because the one out-of-scope
  `lorica-mcp` assertion counts as not passed until lot 2 fixes it;
  the recipe's own `ok.`-only sum gives 2756 for the same reason (it
  drops that binary's 73 whole). 2830 is the figure a green tree
  prints, and it is 2814 plus the 14 `lorica-api` lib tests and the 2
  contract tests this lot added. `grep -n 2814 README.md CONTRIBUTING.md`
  answers nothing.

`cargo audit` was NOT run: no dependency was added or bumped and
`Cargo.lock` is untouched.

**Every new test was watched failing before it was watched passing.**
Eleven probes: each defect was reintroduced with one `sed`
substitution, the named tests run in the container, and the file
restored from a copy and checked with `md5sum` before and after
(identical on every restore). Three probes were void on their first
attempt for mechanical reasons and were rerun: two substitutions left a
variable unused, which `-D warnings` refuses before any test runs, and
one passed two filters to an integration test without `--`; the third
rerun also needed a doc line on the smuggled field because the crate
denies `missing_docs`. What failed, and how:

- `POST /automation/v1/routes` undeclared in the matrix:
  `every_write_path_declares_its_scope_on_its_verb_and_on_no_other`,
  `an_automation_write_path_needs_its_own_scope_and_no_other` (403 to
  the token carrying `routes:write`) and
  `automation_openapi_declares_the_scope_the_gate_enforces` all failed.
- the hostname grant removed from the route write:
  `iv2_a_refusal_by_the_management_validators_arrives_unchanged_and_writes_nothing`
  (a hostname outside the grant answered 201, not 403) and
  `every_name_a_route_write_claims_is_checked_against_the_grant`
  failed.
- the CIDR grant removed from the backend create:
  `the_backend_grant_bounds_what_a_backend_write_may_point_at` failed.
- the automation route create made a lookalike (`waf_mode` dropped
  before the management body ran):
  `iv1_a_route_created_through_the_automation_plane_is_the_dashboards_route_byte_for_byte`
  failed on the canonical bytes, which is exactly the drift the test
  exists for.
- a `smuggled_pem` field added to the management `CreateRouteRequest`:
  `every_automation_write_accepts_exactly_the_field_names_this_surface_committed_to`
  failed naming the field as accepted and not pinned, and
  `no_automation_write_accepts_key_material` failed naming it against
  the `pem` marker. One management change, two guards.
- a `key_pem` property added to the documented binding body:
  `no_automation_write_accepts_key_material` failed on the document
  half.
- `POST /automation/v1/certificates` declared in the matrix behind
  `certificates:write`:
  `no_path_that_takes_key_material_is_declared_for_any_verb`,
  `a_certificate_is_bound_and_renewed_through_the_plane_and_never_uploaded`
  (the upload stopped answering 403) and
  `no_automation_write_accepts_key_material` (the matrix half) failed.
- the backend create audited as the node instead of the token:
  `a_write_through_the_automation_plane_lands_the_management_row_and_the_request_row`
  failed on the row's role and principal.
- the managed-row check removed from `update_route_as`:
  `a_row_an_environment_owns_is_refused_through_the_automation_plane_as_on_the_management_one`
  failed (200 where a 409 was owed), which is the inherited refusal
  proven to be inherited.
- `POST /automation/v1/routes` declared behind `routes:read`:
  `every_mcp_tool_reads_a_path_this_plane_declares_for_get_and_no_read_scope_reaches_another_verb`
  and `every_write_path_declares_its_scope_on_its_verb_and_on_no_other`
  failed.
- `'routes:write'` removed from the generated TypeScript fixture:
  `the_dashboard_fixture_carries_exactly_the_scopes_the_enum_declares`
  failed, the Story 11.1 guard doing its job on the new entries.

Which test guards what:

- AC #1: `docs/prd/epic-10-v1.8.0.md` Story 10.3 AC #5 (prose; no
  test).
- AC #5 and IV1: `iv1_a_route_created_through_the_automation_plane_is_the_dashboards_route_byte_for_byte`
  (`lorica-api/src/tests.rs`), watched failing on the lookalike probe.
- IV2: `iv2_a_refusal_by_the_management_validators_arrives_unchanged_and_writes_nothing`
  (same file), watched failing on the grant probe; the "nothing
  written" half is the canonical-bytes equality before and after.
- AC #6, lot 1's half: `no_automation_write_accepts_key_material` and
  `every_automation_write_accepts_exactly_the_field_names_this_surface_committed_to`
  (`tests/openapi_contract.rs`),
  `no_path_that_takes_key_material_is_declared_for_any_verb`
  (`scope.rs`),
  `a_certificate_is_bound_and_renewed_through_the_plane_and_never_uploaded`
  and `a_bind_body_carries_the_id_and_nothing_else`, all watched
  failing.
- The scope gate on every write: `every_write_path_declares_its_scope_on_its_verb_and_on_no_other`,
  `no_write_path_is_reachable_by_a_token_holding_every_other_scope`
  (matrix and layer, `scope.rs`) and
  `an_automation_write_path_needs_its_own_scope_and_no_other` (whole
  stack), watched failing.
- Audit on both layers: `a_write_through_the_automation_plane_lands_the_management_row_and_the_request_row`,
  watched failing.
- The inherited 409: `a_row_an_environment_owns_is_refused_through_the_automation_plane_as_on_the_management_one`,
  watched failing.
- The grants: `the_backend_grant_bounds_what_a_backend_write_may_point_at`,
  `every_name_a_route_write_claims_is_checked_against_the_grant`,
  `a_wildcard_is_refused_even_under_a_wildcard_grant`; the first two
  watched failing, the third not probed separately (it shares the
  function the second probe removed).
- IV3: not this lot's. The follower half is Story 10.3 IV3's startup
  refusal, unchanged; the replication half belongs in the e2e cluster
  profile, as the Dev Notes say.

### Completion Notes

Lot 1, 2026-09-23. The write scopes and the automation plane's write
surface. `lorica-mcp/` was not touched: the tools, the tier and the
in-process seam decision (option 1 of the Dev Note) are lot 2.

**The management handlers were split, not wrapped.** `create_route`,
`update_route`, `delete_route` (`routes/crud.rs`), `create_backend`,
`update_backend`, `delete_backend` (`backends.rs`) and
`renew_certificate` (`acme/renewal.rs`) each became a thin axum wrapper
that builds the `AuditContext` from the session and a `pub(crate)`
`_as(state, actor, ...)` body holding everything else. The automation
handlers in the new `automation/write.rs` call the `_as` body with the
token's audit identity, the same `audit_context` the environment
resource uses (now `pub(super)`). That is what makes AC #5 and IV1
properties of the code: there is one implementation of a route write,
and the automation plane's row is that function's row. IV2 follows for
the same reason, and the "nothing written" half is asserted on the
canonical encoding of the whole store before and after.

**Eight paths, one verb each.** `POST /automation/v1/routes`,
`PUT|DELETE /automation/v1/routes/{id}`,
`PUT /automation/v1/routes/{id}/certificate`,
`POST /automation/v1/backends`, `PUT|DELETE /automation/v1/backends/{id}`,
`POST /automation/v1/certificates/{id}/renew`. `write_declaration` in
`scope.rs` answers `None` for `GET` before it looks at a path and names
its verb per arm, so the read surface inherits no write scope and no
unmounted verb inherits anything. `scope::WRITE_SURFACE` is the
spelled-out list the matrix tests and the end-to-end tests both walk,
the way `READ_SURFACE` is for the reads.

**The token's grants apply to every write, and that is a decision this
lot took.** The story says the writes go through the management
validators and nothing about `allowed_hostnames` or
`allowed_backend_cidrs`, which the token model documents as "enforced
at use time". Not applying them would have made a `routes:write` token
unbounded by the two fields an operator believes bound it. So every
hostname a route write claims (the route's own and each alias) must be
inside the hostname grant (403; a wildcard alias is refused outright,
since a wildcard grant would match it label for label and hand the
token every host under the parent in one row), and every backend
address must be an `ip:port` inside the CIDR grant (403; a name is 422,
as on the environment resource). The CIDR check is
`environments::ensure_backend_address_granted`, extracted from
`validate_backends` so the two writers of a backend row share one
rule. This is authorization, not validation, and AC #5 is about the
latter. Recorded here so the maintainer can reverse it if it is not
wanted.

**"Select, bind and renew" is read as bind and renew.** The brief
names three certificate verbs; the code has two management operations
that take no key material, the route's `certificate_id` and the ACME
renewal. Selecting a certificate is naming its id in the bind body, and
the id comes from `GET /automation/v1/certificates`. The other reading,
a `PUT /automation/v1/certificates/{id}` restricted to the ACME
settings (`acme_auto_renew`, `acme_method`, `acme_dns_provider_id`),
was not built: nothing in the story asks for it and it would be a
narrowed body of its own, which is the shape AC #5 is wary of. Flagged
as an interpretation, not a finding.

**The follower refusal is the listener's, at startup.** There is no
409 on the automation plane and none was added: `refuse_to_listen` in
`lorica/src/startup/automation.rs` exits a follower before the socket
opens, and a node becomes a follower only through a restart, so a
write cannot reach this plane on a follower. The management plane's
`follower_read_only` middleware (the 409) was deliberately not layered
onto this router: it would guard a state the listener cannot be in.
The brief's "(409)" is read as that refusal; if a per-request 409 was
meant, it is one `.layer(from_fn(follower_read_only))` inside the scope
gate, and it is not here.

**The request-side pin derives the struct from the router.**
`tests/openapi_contract.rs` reads the non-`GET` `.route(` calls off
`router.rs`, finds each handler's `Json<T>` in `write.rs` or
`environments.rs`, finds `pub struct T {` in the four sources a write
body can live in, and diffs the serde field names against
`AUTOMATION_WRITE_FIELD_NAMES` per `(METHOD, path)`, both ways, with a
panic naming the decision. The environment `PUT` is pinned too, since
it is a write with a body. Two things are typed by hand: the committed
lists, which is the point, and the four source files.

**AC #6 is asserted three ways in the same file.** The three PEM-taking
management paths are mounted under no verb and declared for no verb;
no request struct a write deserialises has a top-level field matching
`pem`, `private_key` or `csr`; and no documented write body declares
such a property, with the binding pinned to exactly `certificate_id`.
`scope.rs` and `src/tests.rs` say the same thing at the matrix and
through the whole stack, with a token carrying every scope.

**Not done, and named.** `lorica-mcp/src/tools.rs`'s
`every_scope_the_catalogue_names_is_one_the_token_model_declares`
asserts the complement of the catalogue's scopes is exactly the two
environment scopes; with three write scopes on the enum it fails, and
the fix is the same three lines `tests/mcp_catalogue_scopes.rs` gained.
It lives under `lorica-mcp/`, which this lot was told not to touch,
and naming the write scopes there is lot 2's decision. `docs/mcp.md`
is untouched for the same reason. `README.md`'s v1.8.0 feature bullet
still lists four scopes and has since Story 11.1 added five; not this
lot's sentence to rewrite.

## File List

Added in lot 1:

- `lorica-api/src/automation/write.rs`

Modified in lot 1:

- `lorica-config/src/models/automation_token.rs`
- `lorica-api/src/automation/scope.rs`, `.../router.rs`, `.../mod.rs`,
  `.../environments.rs`
- `lorica-api/src/routes/crud.rs`, `lorica-api/src/backends.rs`,
  `lorica-api/src/acme/renewal.rs`, `lorica-api/src/acme/mod.rs`
- `lorica-api/src/tests.rs`
- `lorica-api/tests/openapi_contract.rs`,
  `lorica-api/tests/mcp_catalogue_scopes.rs`
- `lorica-api/openapi-automation.yaml`, `lorica-api/openapi.yaml`
- `lorica-dashboard/frontend/src/lib/api.ts`,
  `lorica-dashboard/frontend/src/components/settings-tabs/automation-scopes.generated.ts`
- `lorica/src/cli.rs`
- `CHANGELOG.md`, `README.md`, `docs/automation.md`,
  `docs/prd/epic-10-v1.8.0.md`
- `docs/stories/story-11.2-config-tier.md`

## Change Log

- 2026-09-23: Lot 1 landed. Three write scopes on `AutomationScope`,
  with every restatement moved (`scope_str`, both OpenAPI enums, the
  generated TypeScript fixture and the `api.ts` union, the CLI help
  text, which now points at the document instead of listing four of
  twelve). Eight write paths on the automation listener in
  `automation/write.rs`, each the management handler's own body run
  with the token as the actor after that handler was split into a
  wrapper and a `_as` body, each declared in `required_scope` for its
  verb alone, each bounded by the token's hostname and backend grants
  before it runs, each landing the management-side audit row under the
  token's identity beside the plane's request row. IV1 proven byte for
  byte on the canonical encoding, IV2 proven on the message and on the
  store. `openapi-automation.yaml` documents every path with its
  `x-required-scope`, and `tests/openapi_contract.rs` gains the
  request-side field-name pin per write path and the three-way AC #6
  assertion. The Epic 10 PRD pointer at Story 10.3 AC #5 names the
  three scopes and the story. Recorded as decisions: the grants apply
  to every write; "select" is the id the bind names; the follower
  refusal stays the listener's startup one. Not done: the complement
  assertion in `lorica-mcp/src/tools.rs`, which is lot 2's file.

- 2026-09-23: Drafted from the Epic 11 PRD, after Story 11.1's lot 2
  established that the automation plane had no read surface. The same
  is true of writes and is recorded here before anyone estimates this
  story.
