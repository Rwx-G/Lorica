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

- [x] The in-process seam: option 1 of the Dev Note below, decided and
      built before the first write tool. `ReadSource::fetch(path)`
      became `AutomationPlane::call(verb, path, body)` on both
      implementations, and the in-process binding runs the plane's own
      router under the scope gate instead of dispatching by hand.
- [x] AC #2: the tier is chosen by the token's scopes at startup, over
      the same core. The read tools it needs come with it.
- [x] AC #3: a preview counterpart per mutating tool, sharing the apply
      tool's arguments, computing the change against current state and
      writing nothing. The plane owns it as `?dry_run=true` on every
      write path.
- [x] AC #4: one named resource per call, enforced by the tool schemas
      rather than by a check inside the handler.
- [x] AC #6: no argument anywhere in this tier accepts key material.
      A test asserts the tool schemas, not the handlers.
- [x] IV1, IV2 through the tier. IV3's follower half is Story 10.3's
      startup refusal, run here; its replication half belongs in the
      cluster e2e profile and is not proven by this lot.
- [x] AC #7: the `docs/mcp.md` section (the Epic 10 PRD pointer landed
      with lot 1), and audit as in 11.1 on both bindings, verified.

### Lot 3: the audit findings on the tier

- [x] Security Critical: the grants bound what a write targets, not
      only what it claims. A target guard per `_as` body, built from
      the token and run inside the store closure that writes, on the
      row it writes; one whole-stack test per mutation, each watched
      failing before the fix.
- [x] Security High: `forward_auth` and `mirror` refused from an
      automation token and withdrawn from the tools; every
      `backend_ids` list, in every position, resolved under the lock
      and held to the CIDR grant and to environment ownership. Watched
      failing before the fix.
- [x] The two documents corrected: `docs/mcp.md` now says what the
      code does and `docs/automation.md` no longer states the gap as
      intended.
- [x] Performance High: the route update validates outside the store
      lock, as the create does.
- [x] Quality Medium: `ROUTE_UPDATE_FIELDS` pinned to
      `ROUTE_CREATE_FIELDS` plus a named patch-only delta.
- [x] Quality Low: the backend delete preview reports the drain the
      apply starts.
- [x] Architecture Medium 1 (the fix half): the renewal's method and
      provider resolved before the preview branch, so the preview
      refuses what the apply refuses, as a 400.
- [x] Architecture Medium 2: one `authorized()` for every
      authorization-class layer, on both routers, and a test walking
      every declared path through the in-process router.
- [x] Debt Low: the lot 2 probe count corrected to the fourteen bullets
      it counts.

### Lot 4: the security Mediums and Lows the last pass recorded

- [x] Security Medium: `mtls` refused from a token (403, the reason
      named), withdrawn from the tools, named in
      `NOT_OFFERED_TO_A_MODEL`; the key-material sweep walks the Rust
      request structs into every struct they nest, with a positive
      control. `docs/mcp.md`'s sentence corrected and made true again.
- [x] Security Low: `certificate_id` on a route write needs
      `certificates:write` (403). Watched failing before the fix.
- [x] Security Low: `DryRunQuery` is `deny_unknown_fields`, so
      `?dryrun=true` is a 400 and not an apply; the MCP tools carry
      their key check into every nested object a route body declares,
      each vocabulary pinned against the nested struct both ways; the
      two document sentences corrected. Watched failing before the fix.
- [x] Security Medium: a renewal from a token is budgeted per
      certificate: 409 in flight, 429 inside the interval read off
      `not_before`, 429 during the loop's CA cooldown, on a ledger the
      loop and the manual path share. The dashboard's renew unchanged.
      Watched failing before the fix.
- [x] Security Low: a preview needs the read scope of the row it
      answers. Watched failing before the fix on every write path.
- [x] Security Info (the IPv6 finding): an IPv4-mapped address is
      weighed as the IPv4 it maps to, in
      `ensure_backend_address_granted`, on a claim and on a stored row.
      Watched failing before the fix on the report's input.
- [x] Security Info: `InProcessPlane::new` is test-only.
- [x] `proxy_headers` withheld from the model, by the maintainer's
      decision of 2026-09-23: refused from a token (403), withdrawn from
      the tools, named in `NOT_OFFERED_TO_A_MODEL`. Watched failing
      before the refusal existed.
- [x] Recorded, not built: the dry run on the management API (the
      report's own remediation is "none required"). Reason in the Dev
      Note.

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

> Taken in lot 2, 2026-09-23: option 1, as recommended, and nothing in
> the code argued against it. `build_automation_router` is now built
> from `plane_routes()`, the route table without the MCP endpoint, and
> `in_process_router()` is that table under `authorize_scope` alone,
> held in a `OnceLock` because it captures no state: the `AppState`,
> the `AutomationPrincipal` and the `ConnectInfo` travel as request
> extensions, which is where the handlers and the gate read them from
> on the listener. The dispatch `match` is gone, the write handlers run
> unchanged with their grants and their audit rows, and the pin test
> now compares every tool on its verb. What the tool model became is
> under the Completion Notes: `ToolSpec` gained a `Kind`, a `Mutation`
> is declared once and both its tools are built from it, and the plane
> owns the preview as `?dry_run=true`.

### The grant bounds the target, and a body cannot carry that

Recorded 2026-09-23 from the security audit of lots 1 and 2 (Critical
and High). Lot 1 decided that the token's grants apply to every write,
and applied them to what a body CLAIMS: the hostname and the aliases a
route write names, the address a backend write points at. A write that
names a row by id claims nothing in its body and reached the row all
the same: `PUT /automation/v1/routes/{id}` with `{"waf_enabled":
false}` passed the grant check on an empty claim and disabled the WAF
on any route; the delete, the certificate binding and the renewal
checked no target; the backend update checked only a new address. A
token minted for `*.review.example.com` and `10.0.0.0/8` reached every
production route and backend on the node, and a managed route of
another pipeline's environment, whose delete cascaded that environment
past the environment resource's own ownership rule. `docs/automation.md`
stated the gap as intended ("a route update that names no hostname
claims nothing and is checked against nothing") and `docs/mcp.md`
promised the opposite. Both were wrong in the direction that matters:
the second was false, and the first described a hole as a rule.

The fix is where the report put it and no cheaper: the target is
authorized INSIDE the store closure that performs the write, on the
row that closure read and is about to write, so the check and the
write see one row and nothing can move between them. Each `_as` body
takes a guard from the new `lorica-api/src/target.rs`, unbounded from
the management wrapper (the session's role was checked at the door)
and built from the token in `automation/write.rs`, which stays the one
place the grant rules are spelled. The rules: a route's current
hostname and every current alias, and after a patch its new ones,
inside `allowed_hostnames`; a backend's stored address, and a new one,
inside `allowed_backend_cidrs` through the same
`ensure_backend_address_granted`; a certificate's `domain` and every
SAN inside `allowed_hostnames`, weighed as the grant spells them so a
wildcard certificate covering exactly the grant's namespace is
renewable; a route or a backend an environment owns reachable only when
`caller_may_access`, the environment resource's rule, would let the
token reach that environment, a mark whose environment row is gone
treated as unowned. A refusal names the row by id and echoes none of
its values, so a token probing ids outside its grant reads no
production hostname off the answer, and the guard runs on the row as
read BEFORE the managed-row 409, so the environment's name is not
disclosed either. The preview runs the guard as the apply does.

The High is the same finding one field over: `allowed_backend_cidrs`
bounded a backend's `address` and none of the five other ways a route
body points somewhere. `forward_auth` and `mirror` are refused from a
token outright, whatever the value, and withdrawn from the tools; every
`backend_ids` list, top level and inside `path_rules`, `header_rules`
and `traffic_splits`, is resolved under the lock, and each backend the
write links ANEW must sit inside the CIDR grant and belong to no other
principal's environment. A backend the route already carries is not
re-weighed by a patch that leaves the links alone, which is what keeps
`{"waf_enabled": true}` on a route an operator pointed outside the grant
the write it was.

Two things this leaves as decisions rather than fixes. The security
report's Mediums and Lows (the renewal's per-certificate budget, `mtls`
and `proxy_headers` offered to a model, `certificate_id` under
`routes:write`, `deny_unknown_fields` on `DryRunQuery`, the IPv6
mapped-address grant) were not in this pass's brief and are recorded
here for the maintainer. And the guard is a callback, not a tier table:
the architecture report's two Highs are Stories 11.3 and 11.4's.

> Taken in lot 4, 2026-09-23: every item of that list was a fix and not
> a decision, and security does not bend to convenience, so lot 4 built
> them. What each became is under "The Mediums and Lows were fixes"
> below and in the lot 4 Completion Notes. `proxy_headers` was the one
> this pass first left as recorded, because the field is also the
> ordinary way to set `X-Forwarded-*` and cache headers and the read
> tier already returns it; the maintainer decided the same day that it
> is withheld from the model on the same footing as
> `basic_auth_password`, `forward_auth`, `mirror` and `mtls`, for the
> reason the refusal carries: a static header map to the upstream is
> where a credential would go. It is refused from a token (403),
> withdrawn from the tools and named in `NOT_OFFERED_TO_A_MODEL`; the
> plane still accepts it from any other automation client, and the read
> tier still returns it, which is the same shape as `basic_auth_username`
> beside the withheld password.

### The Mediums and Lows were fixes, and this is what they became

Recorded 2026-09-23, lot 4.

**`mtls` is a trust anchor, and a schema sweep cannot see below a body
field.** `{"route": {"mtls": {"ca_cert_pem": "...", "required": true}}}`
from a config-tier session replaced the CA whose client certificates a
route accepts; the AC #6 sweep walked the published `inputSchema`,
whose body properties are `{}`, so it saw `mtls` and never
`mtls.ca_cert_pem`. The field is refused from a token outright,
clearing included, beside `forward_auth` and `mirror`, withdrawn from
the tools and named in `NOT_OFFERED_TO_A_MODEL` as a
client-authentication trust anchor. The sweep now walks the Rust
request struct the handler deserialises, from each field a tool offers
into every struct it nests (`tests/openapi_contract.rs` reads the
nested request modules and `lorica-config`'s `route.rs` for that), and
carries a positive control: over the whole struct, offered or not, the
walk must find at least one nested key-material name and every such
name must sit under a withheld field, so a walk that had gone blind
would fail rather than pass. The schema sweep stays, extended into
array `items`, as the guard on what a client is shown.

**A body's `deny_unknown_fields` is the dashboard's contract to change,
and the query's is not.** `DryRunQuery` is `deny_unknown_fields`: the
one thing it decides is whether a write happens, no management handler
extracts it, and `?dryrun=true` from a direct client was an apply. The
four request structs and what they nest stay as they are, because
`deny_unknown_fields` on them changes what the dashboard may send, a
decision the maintainer takes and not a fix pass. Instead the MCP tool
carries its key check down: a `Body` declares `Nested` vocabularies
for every field that is an object or a list of objects (`ROUTE_NESTED`
in `tools.rs` is the list, and the pin is what says it is complete),
the schema publishes them with `additionalProperties: false`, `checked_body`
recurses through them, and `tests/openapi_contract.rs` pins each list
against the nested struct both ways, checks `list` against the field
being a `Vec`, and refuses an offered field whose type is a struct
with no vocabulary declared, so the next nested object a route body
grows is a red gate and not a silent drop. A `skip_deserializing`
field (`HeaderRuleRequest::disabled`) is left out of what a caller may
send, and the source scan learned to leave it out too. Values are
still never looked at: a nested value that is not an object, `null`
to leave a field alone or a wrong type, passes to the plane's
validators as before.

**The renewal budget is the certificate's, not the token's.** The MCP
limiter counts calls per token and the scarce resource is orders per
identifier set at the CA, so the bound went where the resource is. A
`RenewalLedger` on `AppState` holds the in-flight ids and the CA
cooldown map that was the background loop's local variable; the loop
sweeps, reads and writes that ledger and marks its own orders in
flight, the manual path takes the mark for the duration of the order
(an RAII value released on completion, failure or unwind), and a
token's renewal, apply and preview alike, is refused 409 while an
order for the id is open, 429 while the CA cooldown stands, and 429
when `not_before` is less than `MIN_TOKEN_RENEWAL_INTERVAL_HOURS` ago,
with the wait in `Retry-After` and the reason in the message
(`ApiError::RateLimitedBecause`, a 429 that can say why). The interval
is read off `not_before`, which every issuance path writes as the
order's instant, so no column was added; its value and reason sit on
the constant. The budget runs before the plan is resolved, so a token
asking twice about a manual certificate learns about its own pace
before the row's method, and the test distinguishes the operator's
path by that ordering without placing an order. Two things changed for
everyone, deliberately: the loop skips a certificate a manual renewal
has in flight rather than racing it on the HTTP-01 slot, and a manual
renewal the CA rate-limits records the cooldown so the loop and the
next token stay away from an identifier set the CA already refused.
The operator's answers are unchanged.

**Scopes bound each other now.** `certificate_id` on a route write
needs `certificates:write`, the empty string included since unbinding
is a binding change, the same rule the environment resource applies
to an explicit certificate id; and a preview needs the read scope of
the row it answers, `routes:read` for a route and for the binding
(which answers the route), `backends:read` for a backend,
`certificates:read` for a renewal. Both are checked in the automation
handler before the body runs, in `write.rs`, the one place the grant
rules are spelled. A token minted as `docs/mcp.md` says carries the
read scopes already.

**The mapped address.** The report ranked it Info and speculative; it
is real on reading the code: `ConnectionFilterPolicy::accepts` asks
`IpNet::contains` on the address as parsed, and `[::ffff:127.0.0.1]:80`
parses as V6, so `::/0` contained it while the connect reached IPv4
loopback. `ensure_backend_address_granted` weighs
`addr.ip().to_canonical()`, which both writers of a backend row and the
target guard go through; the stored address is unchanged, since what is
stored is what the proxy dials.

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

Lot 2, 2026-09-23. Gates run in `rust:1-bookworm` with
`RUSTFLAGS=-D warnings`, one container at a time:

- `cargo fmt --all -- --check` on the Windows host: clean (it needed
  one pass of `cargo fmt --all` first, on eleven files).
- `cargo test -p lorica-mcp`: 85 passed, 0 failed. The crate went from
  74 to 85, and lot 1's expected failure on the complement assertion is
  gone: the complement is the two environment scopes.
- `cargo test --no-fail-fast -p lorica-config -p lorica-api`: 918 + 495
  unit (the one pre-existing ignored in `lorica-config`), 3 in
  `tests/automation_scope_fixture.rs`, 3 in `tests/mcp_asserted_headers.rs`,
  6 in `tests/mcp_catalogue_scopes.rs`, 9 in `tests/openapi_contract.rs`,
  8 + 18 doctests. 0 failed. `lorica-api` lib 908 -> 918,
  `mcp_catalogue_scopes` 4 -> 6, `openapi_contract` 6 -> 9.
- Every integration test under `lorica-api/tests/` by name:
  `automation_scope_fixture` 3, `mcp_asserted_headers` 3,
  `mcp_catalogue_scopes` 6, `openapi_contract` 9.
- `cargo clippy -p lorica-config -p lorica-waf -p lorica-api -p lorica-notify -p lorica-bench -- -D warnings`:
  one failure first, `using clone on type Option<ConnectInfo<SocketAddr>>
  which implements the Copy trait` in `InProcessPlane`, fixed to a
  copy; clean after. The two other Lint invocations reported the same
  one line and are clean after it.
- `cargo clippy -p lorica-api -p lorica-cluster --all-targets -- -D warnings`: clean.
- `cargo clippy -p lorica --all-targets --features otel -- -D warnings`:
  clean. Run because the binary links `lorica-api`, whose router split.
- `cargo clippy -p lorica-mcp --all-targets -- -D warnings`: clean.
- `cargo test -p lorica --bin lorica -- a_follower_refuses_to_open_the_automation_listener`:
  1 passed, the IV3 follower half, Story 10.3's test run on the target
  it lives in (`startup::automation` is under `main.rs`, and the first
  attempt on `--lib` filtered it out).
- `cargo audit`: run, because `Cargo.lock` changed (`percent-encoding`
  left `lorica-api`'s dependency list; no `[[package]]` entry moved).
  Exit 0 over 651 crate dependencies, the same two allowed
  unmaintained warnings the cycle carries (`RUSTSEC-2024-0388` on
  `derivative`, `RUSTSEC-2025-0134` on `rustls-pemfile`). Run in a
  container with its own target directory, for the reason Story 11.1
  recorded.
- `git ls-files --eol`: index `lf` on every changed file, the working
  tree `crlf` on the ones the checkout already held that way and `lf`
  on the rest; the new `preview.rs` at `w/lf`. No file changed ending.
  Checked this way and not with `awk`.
- No em dash (U+2014) in any changed file, checked with a byte grep.
- `README.md`'s product-crate test count, recomputed with the
  `docs/BUMP-CHECKLIST.md` recipe over the README's own crate list
  with `--no-fail-fast`: 2830 -> 2856 in BOTH places, the shell
  comment and the `Lorica%20Tests-N` badge; 66 binaries, none failed,
  and the `ok.`-only sum equals the sum of every `passed`.
  `grep -n 2830 README.md CONTRIBUTING.md` answers nothing.

The frontend was not touched and its gates were not re-run.

**Every new test was watched failing before it was watched passing.**
Fourteen probes, each a one-substitution defect applied by a script on
the host, the named tests run in the container, the file restored from
a copy and its md5 compared before and after (identical on every
restore). One was void on its first attempt: `cargo fmt` had rewrapped
the line it targeted, and it was rerun against the formatted source.
(This paragraph said fifteen until the 2026-09-23 debt audit counted
the bullets below and found fourteen; the list was always the record,
the number was the miscount.) What failed, and how:

- the scope filter in `McpServer::sharing` replaced by `true`:
  `a_token_carrying_only_read_scopes_registers_no_write_tool_and_cannot_call_one`
  and `iv1_a_read_tier_token_lists_only_read_tools_and_a_mutation_cannot_be_called`
  (stdio) failed, a read-tier token finding `lorica_route_create`
  registered.
- `lorica_route_delete` declared behind `routes:read`:
  `a_read_tool_is_a_get_behind_a_read_scope_and_a_write_tool_a_write_behind_a_write_scope`
  failed in `lorica-mcp`, and `every_mcp_tool_names_the_scope_its_verb_and_path_sit_behind`
  and `the_scopes_the_catalogue_uses_are_every_scope_but_the_environment_ones`
  failed in `tests/mcp_catalogue_scopes.rs`: the cross-crate guard,
  on the verb, doing what it is for.
- the preview's `dry_run=true` not appended:
  `every_mutation_declares_an_apply_tool_and_a_preview_taking_the_same_arguments`,
  `a_write_call_carries_the_verb_the_body_and_for_a_preview_the_dry_run_flag`
  and the stdio config-tier test failed.
- the preview tool not built from the mutation (`all.push(mutation.tool(true))`
  removed): the same AC #3 test failed on `find(preview)`, and
  `a_config_tier_token_registers_its_mutations_with_their_previews_and_the_reads_it_holds`
  failed on the registry.
- the undeclared-field check on a body disabled:
  `a_body_is_checked_for_shape_and_size_and_its_values_are_never_looked_at`
  failed (rerun after the void attempt).
- `basic_auth_password` added to the route create's field list:
  `no_argument_of_any_tool_takes_key_material_or_a_credential` and
  `no_tool_definition_names_a_credential` failed in `lorica-mcp`, and
  `no_mcp_tool_argument_takes_key_material` and
  `every_mcp_write_tool_declares_exactly_the_fields_its_handler_accepts_less_the_ones_not_offered`
  failed in `tests/openapi_contract.rs`, the second naming the field
  as offered against its recorded reason.
- `ca_pem` added to the backend field list:
  `no_argument_of_any_tool_takes_key_material_or_a_credential` failed
  on the `pem` marker.
- `lorica_route_delete` given a body with a `pattern` field:
  `a_write_tool_names_one_resource_by_one_id_and_takes_no_selector`
  failed.
- the scope gate removed from `in_process_router()`:
  `the_in_process_plane_runs_the_scope_gate_and_refuses_what_the_matrix_refuses`
  failed, the principal lacking `logs:read` reading the log in process.
  That is the whole reason for option 1, watched.
- the preview branch of `update_route_as` disabled inside the store
  closure: `a_preview_through_the_config_tier_answers_the_change_and_writes_nothing`
  and `every_write_path_previews_under_dry_run_and_writes_nothing`
  failed on the canonical bytes, a preview having written.
- `InProcessPlane::call` sending a lookalike body with `waf_mode`
  dropped: `iv1_a_route_created_through_the_config_tier_is_the_dashboards_route_byte_for_byte`
  failed on the canonical bytes.
- the refusal body emptied on the in-process seam:
  `iv2_a_refusal_through_the_config_tier_arrives_unchanged_and_writes_nothing`
  failed, the dashboard's message missing from the fence.
- the principal's name swapped before the in-process request:
  `a_write_through_the_config_tier_lands_the_management_row_and_the_mcp_row`
  failed on the management row's identity.
- `DryRun` replaced by `PageLimit` on one write in the document:
  `every_automation_write_documents_dry_run_and_no_read_does` failed.

Which test guards what:

- The seam decision: `the_in_process_plane_runs_the_scope_gate_and_refuses_what_the_matrix_refuses`
  (`automation/mcp.rs`), `this_module_opens_no_connection_of_its_own`
  (its positive control now the router call and the absence of any
  hand-called handler), and `the_streamable_http_binding_asserts_nothing_and_needs_no_marker_of_its_own`
  (`tests/mcp_asserted_headers.rs`, positive control renamed).
- AC #2: `a_read_tool_is_a_get_behind_a_read_scope_and_a_write_tool_a_write_behind_a_write_scope`,
  `a_token_carrying_only_read_scopes_registers_no_write_tool_and_cannot_call_one`,
  `a_config_tier_token_registers_its_mutations_with_their_previews_and_the_reads_it_holds`
  (`lorica-mcp`), the stdio pair, `the_scopes_the_catalogue_uses_are_every_scope_but_the_environment_ones`
  (`tests/mcp_catalogue_scopes.rs`) and
  `the_config_tier_on_this_binding_is_the_tokens_scopes_and_a_read_tier_token_gains_no_write`
  (`src/tests.rs`, whole stack; not probed separately, it shares the
  filter the first probe replaced).
- AC #3: `every_mutation_declares_an_apply_tool_and_a_preview_taking_the_same_arguments`,
  `a_write_call_carries_the_verb_the_body_and_for_a_preview_the_dry_run_flag`,
  `a_preview_through_the_config_tier_answers_the_change_and_writes_nothing`,
  `every_write_path_previews_under_dry_run_and_writes_nothing`,
  `every_automation_write_documents_dry_run_and_no_read_does`, and
  the `preview.rs` unit tests (not probed; they pin the answer shape).
- AC #4: `a_write_tool_names_one_resource_by_one_id_and_takes_no_selector`.
- AC #5: `a_body_is_checked_for_shape_and_size_and_its_values_are_never_looked_at`
  and the IV1 test.
- AC #6: `no_argument_of_any_tool_takes_key_material_or_a_credential`
  (`lorica-mcp`), `no_mcp_tool_argument_takes_key_material` and
  `every_mcp_write_tool_declares_exactly_the_fields_its_handler_accepts_less_the_ones_not_offered`
  (`tests/openapi_contract.rs`).
- AC #7, audit: `a_write_through_the_config_tier_lands_the_management_row_and_the_mcp_row`
  and the IV2 test's rows; `docs/mcp.md` is prose.
- IV1: `iv1_a_route_created_through_the_config_tier_is_the_dashboards_route_byte_for_byte`.
- IV2: `iv2_a_refusal_through_the_config_tier_arrives_unchanged_and_writes_nothing`,
  and `a_validators_refusal_of_a_write_is_an_execution_error_carrying_the_planes_words`
  at the core (not probed separately; it shares the refusal path the
  emptied-body probe broke).
- IV3: `a_follower_refuses_to_open_the_automation_listener`
  (`lorica/src/startup/automation.rs`), Story 10.3's, run here and
  not probed (it is not this lot's test). The replication half is not
  proven by this lot.
- The seam's shape: `a_verb_spells_itself_the_way_the_request_line_does`
  and `the_write_tools_body_cap_is_the_planes` (not probed; they pin
  constants).

Lot 3, 2026-09-23. Gates run in `rust:1-bookworm` with
`RUSTFLAGS=-D warnings`, one container at a time, after the e2e suite
that was running from the previous lot had torn down:

- `cargo fmt --all -- --check` on the Windows host: clean, after one
  `cargo fmt --all` pass over the moved patch block.
- `cargo test --no-fail-fast -p lorica-config -p lorica-api`: the
  first run compiled nothing, `lorica-mcp` refusing an unused constant
  under `-D warnings` (`ROUTE_UPDATE_ONLY_FIELDS` is a test vector and
  is `#[cfg(test)]` now). The second run: 925 passed, 4 failed, all
  four on the fixtures and not on the fix. Three were the seeded
  certificate: the management upload reads the SANs off the test PEM,
  whose names are not under the grant, so the renewal guard refused the
  fixture's own certificate in `a_certificate_is_bound_and_renewed_through_the_plane_and_never_uploaded`,
  `every_write_path_previews_under_dry_run_and_writes_nothing` and the
  new `a_renewal_preview_refuses_what_the_apply_refuses`; the fixture
  clears the SANs after the upload and each test that needs one sets
  its own. The fourth was `every_registered_tool_answers_through_the_endpoint_without_leaving_the_process`,
  whose token was granted `*.read.example.com` and whose seeded route
  answers on `read.example.com` itself, which the one-label wildcard
  does not cover: the route update preview was refused on its target,
  exactly as the fix intends, and the token now carries the exact name
  beside the wildcard. Both are the guard doing its job on fixtures
  that predate it.
- The README product-crate list with `--no-fail-fast` and
  `--features otel`, which is the `docs/BUMP-CHECKLIST.md` recipe and
  a superset of the previous gate: 66 binaries, none failed, the
  `ok.`-only sum equal to the sum of every `passed`, 2868.
  `lorica-api` lib 918 -> 929 (the seven whole-stack tests, two
  `write.rs` unit tests, one `target.rs` unit test, the in-process
  walk in `mcp.rs`), `lorica-mcp` 85 -> 86 (the vocabulary pin),
  `automation_scope_fixture` 3, `mcp_asserted_headers` 3,
  `mcp_catalogue_scopes` 6, `openapi_contract` 9. `README.md` moved
  2856 -> 2868 in BOTH places; `grep -n 2856 README.md CONTRIBUTING.md`
  answers nothing.
- The three Lint clippy invocations and
  `cargo clippy -p lorica-mcp --all-targets -- -D warnings`: the first
  three failed on one line, `needless_option_as_deref` in
  `apply_route_patch` (the roster parameter is already `Option<&[_]>`;
  the `.as_deref()` came with the block from the closure, where the
  variable was owned). Fixed to `node_roster`, a no-op on behaviour;
  all four clean on the rerun. The test run above was not repeated for
  a one-token change the compiler proves equivalent.
- `cargo audit`: NOT run. No dependency added or bumped; `Cargo.lock`
  is untouched.
- `git ls-files --eol`: index `lf` on every changed file, the working
  tree `crlf` on the ones the checkout already held that way and `lf`
  on the rest; the new `target.rs` at `w/lf`. Checked this way and not
  with `awk`.
- No em dash (U+2014) in any changed file, checked with a byte grep.

**The seven new tests were watched failing before the fix, on the
unfixed sources.** They were written first, into `tests.rs` alone, and
run in the container before any source file was touched; then the fix
landed and they were run again. Not a probe reintroducing a defect: the
defect was the code as committed. What failed, and how:

- `a_route_write_is_refused_when_the_route_it_names_is_outside_the_grant`:
  `PUT {"waf_enabled": false}` on the production route answered 200
  where a 403 was owed (the Critical's first input).
- `a_managed_route_goes_through_the_plane_only_for_its_environments_owner`:
  the `DELETE` of another pipeline's route answered 200.
- `a_backend_write_is_refused_when_the_backend_it_names_is_outside_the_grant`:
  `PUT {"address": "10.9.9.9:80"}` on the production backend answered
  200, the redirect of production traffic the report describes.
- `a_renewal_is_refused_when_the_certificate_covers_a_name_outside_the_grant`:
  the renewal of `www.example.com` answered 500, the ACME order having
  been attempted for a certificate the token had no business with.
- `a_route_body_cannot_aim_traffic_or_credentials_outside_the_grant`:
  a create carrying `forward_auth` at `https://collector.attacker.example.net/v`
  answered 201 (the High's first input).
- `a_backend_delete_preview_reports_the_drain_the_apply_starts`:
  `after` was null where the closing row was owed.
- `a_renewal_preview_refuses_what_the_apply_refuses`: the preview of a
  `dns01-manual` certificate answered 200 where the apply answers a
  refusal.

The `write.rs` unit tests (`a_certificate_is_renewable_when_every_name_it_carries_is_inside_the_grant`,
`forward_auth_and_mirror_are_refused_from_a_token_whatever_the_value`),
the `target.rs` unit test, the `mcp.rs` walk
(`every_declared_path_reaches_its_handler_in_process`) and the
`lorica-mcp` vocabulary pin
(`the_update_vocabulary_is_the_create_vocabulary_plus_what_only_a_patch_has`)
were not watched failing: they pin functions and constants that did
not exist before this lot, or a structural property that held already
(the walk), and the whole-stack tests above are the ones that guard the
findings.

Which test guards what:

- The Critical, per mutation: route update, delete and certificate
  binding in `a_route_write_is_refused_when_the_route_it_names_is_outside_the_grant`;
  the managed-row ownership rule in `a_managed_route_goes_through_the_plane_only_for_its_environments_owner`;
  backend update and delete in `a_backend_write_is_refused_when_the_backend_it_names_is_outside_the_grant`;
  the renewal in `a_renewal_is_refused_when_the_certificate_covers_a_name_outside_the_grant`.
  Each asserts the 403, the grant named in the message, the preview
  refused alike, the store's canonical bytes unchanged, the row's
  fields unchanged, and the `automation.request.forbidden` rows.
- The High: `a_route_body_cannot_aim_traffic_or_credentials_outside_the_grant`,
  on the report's inputs (both `forward_auth` addresses, `mirror`,
  `backend_ids` in all four positions, an environment-owned backend),
  create and update, apply and preview, with the positive controls
  that a link inside the grant and a patch leaving the links alone
  still write; and the vocabulary withdrawal through
  `every_mcp_write_tool_declares_exactly_the_fields_its_handler_accepts_less_the_ones_not_offered`
  (the two `NOT_OFFERED_TO_A_MODEL` entries) and
  `the_update_vocabulary_is_the_create_vocabulary_plus_what_only_a_patch_has`.
- The performance High: no new test; `iv1_*`, `every_write_path_previews_under_dry_run_and_writes_nothing`
  and every route-update test pass through `apply_route_patch` and the
  re-read closure, which is what shows the reorder changed no answer.
- Quality Medium: `the_update_vocabulary_is_the_create_vocabulary_plus_what_only_a_patch_has`.
- Quality Low: `a_backend_delete_preview_reports_the_drain_the_apply_starts`.
- Architecture Medium 1: `a_renewal_preview_refuses_what_the_apply_refuses`.
- Architecture Medium 2: `every_declared_path_reaches_its_handler_in_process`,
  and `the_in_process_plane_runs_the_scope_gate_and_refuses_what_the_matrix_refuses`
  still passing over `authorized()`.

Lot 4, 2026-09-23. Gates run in `rust:1-bookworm` with
`RUSTFLAGS=-D warnings`, one container at a time, each started only
once no `rust:1-bookworm` container was running:

- `cargo fmt --all -- --check` on the Windows host: clean, after a
  `cargo fmt --all` pass before each container run (three in all).
- The red run, on the sources as committed plus the tests and the
  inert scaffolding they compile against: `cargo test -p lorica-mcp
  --lib` 1 passed 2 failed, `--test openapi_contract` 0 passed 3
  failed, `cargo test -p lorica-api --lib` 0 passed 6 failed, on the
  names listed under "watched failing" below.
- The first green run: the six whole-stack tests and the unit tests
  passed on the fixes, and three OTHER tests failed, each on the
  harness and not on a finding: `tests/mcp_asserted_headers.rs`
  scans `mcp.rs` up to its first `#[cfg(test)]` and the attribute on
  `InProcessPlane::new` had moved the `impl AutomationPlane` block past
  it; `lorica-mcp`'s `no_answer_this_server_builds_carries_a_credential_field_name`
  found `cookie_ttl_s` in the tool list now that nested schemas are
  published; and the new struct walk asserted that every body nests
  something, which `BindCertificateRequest` does not. Plus the
  renewal test's last assertion, which expected no `certificate.`
  audit row and found the fixture's own upload row. All four
  corrected in the tests and the constructor, none in a fix.
- The first full gate: the product recipe refused to compile
  `lorica-api`, `associated function new is never used`, the
  `pub(crate)` constructor being test-only in fact; moved into the
  test module. Clippy 1 to 3 said the same line, clippy 4 clean.
- The second full gate: `cargo test -p lorica-mcp` 88 passed (86 ->
  88). The README product-crate list with `--no-fail-fast` and
  `--features otel`, the `docs/BUMP-CHECKLIST.md` recipe and a
  superset of `cargo test -p lorica-config -p lorica-api`: 69
  binaries, `lorica-api` lib 937 (929 -> 937), `lorica-config` 495
  (the one pre-existing ignored), `tests/automation_scope_fixture.rs`
  3, `tests/mcp_asserted_headers.rs` 3, `tests/mcp_catalogue_scopes.rs`
  6, `tests/openapi_contract.rs` 11 (9 -> 11), doctests 8 + 18, the
  sum of every `passed` 2879 with ONE failure:
  `proxy_wiring::ai_bot_reload_tests::rebuild_from_store_swaps_global_handle`
  in the `lorica` lib, 433 passed 1 failed. That test writes the
  process-wide merged-crawler handle and says it is the only one that
  does; `worker_rpc.rs`'s two-phase reload tests in the same binary
  reach `apply_per_process_reload_state`, which rebuilds the same
  handle from their own store. Rerun in a container of its own: the
  module alone 7 passed, the whole `lorica` lib twice 434 passed each.
  A pre-existing race on a global, in a crate this lot touched only to
  name the new `AppState` field, and left as a follow-up rather than
  fixed here. With that binary green the sum is 2880, and the
  `ok.`-only sum plus its 434 agrees.
- The three Lint clippy invocations and
  `cargo clippy -p lorica-mcp --all-targets -- -D warnings`: clean on
  the second full gate.
- `cargo audit`: NOT run. No dependency added or bumped; `Cargo.lock`
  is untouched (`git status` names it nowhere).
- The third full gate, after the maintainer's `proxy_headers`
  decision, in one container: `cargo test -p lorica-mcp` 88 passed;
  the product recipe 69 binaries, none failed (the `lorica` lib 434
  this time), `lorica-api` lib 938, `openapi_contract` 11, the
  `ok.`-only sum equal to the sum of every `passed`, 2881; the four
  clippy invocations clean; `cargo fmt --all -- --check` clean on the
  host before it.
- `README.md`'s product-crate test count: 2868 -> 2881 in BOTH
  places, the shell comment and the `Lorica%20Tests-N` badge;
  `grep -n 2868 README.md CONTRIBUTING.md` answers nothing (nor 2880,
  the figure the second gate gave before the `proxy_headers` test).
  The thirteen are the nine `lorica-api` lib tests, the two contract
  tests and the two `lorica-mcp` tests this lot added.
- `git ls-files --eol`: index `lf` on every changed file. Working tree
  `crlf` on the files the checkout held that way and `lf` on the
  rest, with one exception: `lorica-api/src/acme/renewal.rs` was
  `w/crlf` and is `w/lf` after rustfmt rewrote it on the host, an
  ending the index never held. Checked this way and not with `awk`.
- No em dash (U+2014) in any changed file, checked with a byte grep.

**Every new test was watched failing before the fix, on the sources
as committed.** The tests were written into the suite first with the
scaffolding they need to compile and none of the checks, run in the
container, then the fixes landed and they were run again. What failed,
and how:

- `a_route_body_cannot_install_a_client_authentication_trust_anchor`:
  `POST /automation/v1/routes` with `{"mtls": {"ca_cert_pem": <a CA>,
  "required": true}}` answered 201 where a 403 was owed, the report's
  own body installed.
- `no_mcp_tool_body_field_takes_key_material_at_any_depth_of_its_request_struct`:
  `lorica_route_create offers mtls, under which ca_cert_pem matches the
  key-material marker pem`, the sweep seeing what the schema sweep
  could not; `every_mcp_write_tool_declares_exactly_the_fields_its_handler_accepts_less_the_ones_not_offered`
  named `mtls` as offered against its recorded reason, and
  `every_mcp_write_tool_declares_its_nested_vocabularies_against_the_nested_structs`
  named `mtls` as `Option<MtlsConfigRequest>, an object the tool offers
  with no nested vocabulary`; in `lorica-mcp`,
  `the_update_vocabulary_is_the_create_vocabulary_plus_what_only_a_patch_has`
  said `mtls is offered`.
- `a_certificate_binding_on_a_route_write_needs_the_certificates_write_scope`:
  the create with `certificate_id` from a token holding `routes:write`
  and `routes:read` answered 201.
- `a_mistyped_dry_run_is_refused_and_never_an_apply`:
  `POST /automation/v1/routes?dryrun=true` answered 201, the route
  created.
- `a_nested_typo_is_refused_at_the_tool_and_a_declared_nested_key_passes`
  (`lorica-mcp`): `{"path_rules": [{"path": "/x", "backend_idz":
  ["b"]}]}` built a call, the typo travelling.
- `a_token_renews_one_certificate_at_a_time_and_not_twice_inside_the_interval`:
  the first assertion, a renewal of a certificate whose order is in
  flight, answered 400 (the plan's refusal of the manual method) where
  a 409 was owed, the budget absent; the 429 assertions sit behind it
  in the same test and were first seen passing on the fix, not
  separately seen failing.
- `a_preview_needs_the_read_scope_of_the_row_it_answers`:
  `POST /automation/v1/routes?dry_run=true` from a token holding
  `routes:write` alone answered 200, the row shown.
- `an_ipv4_mapped_address_is_weighed_as_the_ipv4_it_maps_to`
  (`write.rs`): `[::ffff:127.0.0.1]:80` under a `::/0` grant was
  accepted, the report's input.
- `a_route_body_cannot_carry_a_static_header_map_to_the_upstream`, in
  a container of its own after the maintainer's decision: the create
  with `proxy_headers` answered 201 where a 403 was owed; in the same
  run `every_mcp_write_tool_declares_exactly_the_fields_its_handler_accepts_less_the_ones_not_offered`
  and `the_update_vocabulary_is_the_create_vocabulary_plus_what_only_a_patch_has`
  named `proxy_headers` as offered.

Not watched failing, because they pin functions that did not exist
before this lot or a shape that held already:
`forward_auth_mirror_mtls_and_proxy_headers_are_refused_from_a_token_whatever_the_value`
(renamed from `forward_auth_and_mirror_...` and extended twice),
`a_certificate_id_on_a_route_write_needs_the_certificate_scope_and_a_preview_its_read_scope`,
`a_key_that_is_not_dry_run_is_refused_rather_than_read_as_the_write`
(`preview.rs`),
`every_nested_vocabulary_sits_on_a_field_its_body_offers_and_is_sorted`
(`lorica-mcp`), and the three `RateLimitedBecause` lines in
`error.rs`'s tests.

Which test guards what:

- Item 1, `mtls` and the blind sweep:
  `a_route_body_cannot_install_a_client_authentication_trust_anchor`
  (whole stack, create, update and previews, the clearing value, the
  dashboard's own path still setting it),
  `no_mcp_tool_body_field_takes_key_material_at_any_depth_of_its_request_struct`
  (the struct walk, with its positive control), the vocabulary pin and
  `the_update_vocabulary_...` on the withdrawal.
- Item 2, `certificate_id` under `routes:write`:
  `a_certificate_binding_on_a_route_write_needs_the_certificates_write_scope`.
- Item 3, the typo: `a_mistyped_dry_run_is_refused_and_never_an_apply`
  on the plane, `a_nested_typo_is_refused_at_the_tool_and_a_declared_nested_key_passes`
  at the tool, and `every_mcp_write_tool_declares_its_nested_vocabularies_against_the_nested_structs`
  holding the nested lists to the structs.
- Item 4, the renewal budget:
  `a_token_renews_one_certificate_at_a_time_and_not_twice_inside_the_interval`,
  all three refusals, the preview, the operator's path and the
  management trail.
- Item 5, the preview's read scope:
  `a_preview_needs_the_read_scope_of_the_row_it_answers`, one entry per
  `WRITE_SURFACE` path.
- Item 6, the mapped address:
  `an_ipv4_mapped_address_is_weighed_as_the_ipv4_it_maps_to`, on the
  claim and on the stored row through the guard.
- `proxy_headers`, the maintainer's decision:
  `a_route_body_cannot_carry_a_static_header_map_to_the_upstream`
  (whole stack, create, update, both previews, the clearing `{}`, the
  dashboard still setting it), the vocabulary pin and
  `the_update_vocabulary_...` on the withdrawal.

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

---

Lot 2, 2026-09-23. The tier, over the write surface lot 1 built.

**The seam decision came first, and it is option 1.** Nothing in the
code argued for option 2. `lorica-mcp`'s trait is `AutomationPlane`
with one method, `call(verb, path, body, reason)`, where `Verb` is a
four-variant enum of this crate's own (the plane mounts nothing under a
fifth verb, and `lorica-mcp` takes no `http` dependency for four
spellings) and the body is a `serde_json::Value` the tool layer already
bounded. `ReadSource`, `ReadError` and `HttpsReadSource` are
`AutomationPlane`, `PlaneError` and `HttpsPlane`: a trait whose method
performs a `DELETE` cannot keep a name that says it reads. On the stdio
side `HttpsPlane::call` serialises the body itself rather than through
`reqwest`'s JSON helper, which is a feature this crate does not enable,
and gives a write 120 seconds against a read's 30, because a
certificate renewal is an ACME order made while the request is open and
a client that gives up at a read's timeout is a handler the listener
drops mid-order.

On the in-process side `router.rs` now has `plane_routes()`, the route
table without the MCP endpoint, from which both `build_automation_router`
(every layer, endpoint included) and `in_process_router()` (the scope
gate alone, in a `OnceLock` since it captures no state) are built.
`InProcessPlane::call` builds the `http::Request` the seam describes,
inserts the `AppState`, the caller's `AutomationPrincipal` and its
`ConnectInfo` as extensions, carries the caller's `User-Agent`, and
`oneshot`s it into that router. The dispatch `match`, `one_segment_under`,
`query()` and `refusal()` are gone, and with them `lorica-api`'s
`percent-encoding` dependency, which existed for the decoding the
dispatch did by hand. The scope matrix therefore runs on every
in-process call, which `the_in_process_plane_runs_the_scope_gate_and_refuses_what_the_matrix_refuses`
proves with a principal lacking `logs:read` refused 403 on a read, a
principal lacking `routes:write` refused 403 on a write before the body
is looked at, a principal carrying every scope refused 403 on an
undeclared path, and the MCP endpoint itself answering 404 from inside,
so a tool cannot reach the endpoint running it. The write handlers run
unchanged: their grant checks refuse with the listener's 403 and their
`_as` bodies write the management row under the token's identity, with
the MCP POST's own address, which the audit test through the tier
asserts. The MCP POST is the request the audit layer records; the
in-process router has no audit layer, so there is one request row per
tool call and never a second for the call it made, which the same test
pins.

**The tool model.** `ToolSpec` gained a `Kind`: `Read`, or `Write`
carrying the verb, the optional action segment after the id
(`certificate`, `renew`), the optional `Body`, whether the tool
previews, and the name of its counterpart. A `Mutation` is declared
once in `MUTATIONS` (apply name, preview name, summary, scope, verb,
path, resource, action, body) and `catalogue()`, a `OnceLock` over
`READS` plus two tools per mutation, is what `CATALOGUE` became. That
is AC #3's "same arguments" by construction and not by discipline: the
preview is the same `ToolSpec` with `previews: true`, `call_for`
appends `dry_run=true` to its query, and `description()` writes the
sentence each way (`lorica_route_create_preview` names
`lorica_route_create` and says it writes nothing; the apply names its
preview and says a client configured to show a diff calls it first).
`definition()` suffixes the preview's title. A `Body` names its
argument (`route`, `backend`, `binding`), the management struct it is
(`CreateRouteRequest` and its siblings, for the client to read the
fields' meaning in `openapi.yaml`), and the sorted top-level field
names this tier offers. `call_for` checks shape and nothing else: the
body is an object, its keys are declared (an undeclared one refused
without being echoed, because the plane would have dropped it silently
and the caller would believe it set something), and its serialised
weight is under `MAX_BODY_BYTES`, pinned by
`the_write_tools_body_cap_is_the_planes` against
`AUTOMATION_BODY_CAP`, now `pub`. Values are never looked at (AC #5),
which `a_body_is_checked_for_shape_and_size_and_its_values_are_never_looked_at`
asserts by passing a hostname that is a number through.

**Where the field vocabulary comes from, and the two fields it does not
carry.** The lists in `tools.rs` are typed, and
`every_mcp_write_tool_declares_exactly_the_fields_its_handler_accepts_less_the_ones_not_offered`
in `tests/openapi_contract.rs` pins each against the request struct the
handler behind the tool's `(verb, path)` deserialises, both ways,
reusing lot 1's source scanners and resolving the handler from the
tool's own call. The only difference it tolerates is
`NOT_OFFERED_TO_A_MODEL`, two entries with their reasons: `managed_by`,
refused by the plane on input, and `basic_auth_password`, a credential
a model would be choosing or relaying and which would cross the
model's host in the clear. That second exclusion is a decision of this
lot and not the story's: the story says nothing about it, the read
tier's own `no_tool_definition_names_a_credential` would have failed
on the word, and a narrowed vocabulary is not a narrowed body in AC #5's
sense, since every field the tier does offer reaches the same
validators. The plane still accepts the field from any other automation
client. Recorded here so the maintainer can reverse it; if reversed,
the read tier's credential test needs a home for the word.

Deriving the schema from `openapi-automation.yaml`, as the audit's
direction suggested, was not done: that document does not restate the
management bodies, by lot 1's decision, and the management `openapi.yaml`
is pinned to its structs by nothing. The struct is the one authority
both crates can be checked against, and the pin above is that check.
The property schemas are empty (`{}`): a type would be a transcription
of the Rust type the pin cannot verify, and the body's description
points a client at the schema name in `openapi.yaml` instead.

**The preview is the plane's, as `?dry_run=true`.** A query rather
than a header or a path of its own, because the matrix and the audit
row read the path: a preview sits behind the write's scope by
construction and its request row records `?dry_run` beside the verb.
`crate::preview` holds `WriteMode { Apply, Preview }`, `DryRunQuery`,
and `previewed(operation, before, after)`, which answers
`{"data": {"dry_run": true, "operation", "before", "after", "changes"}}`
with `changes` a field-level `{from, to}` map over the two views,
`updated_at` left out, and a create's `after` stripped of the id and
the clock the apply would mint. Every `_as` body took a `WriteMode`:
create stops before `db_blocking`, update and delete return from inside
the store closure before the write (update reads the backend links
before the patch only on a preview, to fill the `before` view the audit
row deliberately leaves empty), the backend delete returns before it
marks the row closing, and the renewal returns the certificate's
metadata after the ACME-only refusal. What only the store refuses, a
duplicate hostname or an unknown backend id, is refused by the apply
alone; `docs/mcp.md` and the `DryRun` parameter say so. The management
wrappers pass `Apply`; the automation handlers read the query.

**AC #2 by construction.** `McpServer::sharing` is the same filter it
was, over a catalogue where every write tool declares a write scope and
every read tool a read scope, which
`a_read_tool_is_a_get_behind_a_read_scope_and_a_write_tool_a_write_behind_a_write_scope`
pins in `lorica-mcp` and
`the_scopes_the_catalogue_uses_are_every_scope_but_the_environment_ones`
pins from the side that holds the enum. The complement both assert is
now the two environment scopes alone. `startup_notice` names the tier
(`McpServer::tier`, the config tier once any tool that changes
something is registered, a naming for the operator and not Story
11.4's table) and asks a config tier about the read scopes it lacks,
since that tier finds ids through them, while a read tier is not asked
for a write scope. A first cut of `read_scopes()` filtered on
`changes_nothing()`, which a preview satisfies, and so counted the
write scopes as the read tier's; three tests caught it on the first
run and it filters on `Kind` now.

**Audit on the tier, verified rather than assumed.** The lot 4 fix
pass's plumbing carries a write unchanged: `named_call` reads
`argument_names()` so the row shows `tool=lorica_route_update?id,route`
and never a body field name, `mcp_outcome` maps `Outcome::Refused(403)`
to `forbidden` with no reason for a grant refusal and `Refused(400)` to
`refused` for a validator's, and the management row lands beside the
request row under the token's identity. All three are asserted by
`a_write_through_the_config_tier_lands_the_management_row_and_the_mcp_row`
and the IV2 test through the tier. Over stdio the row is the plane's
own `POST /automation/v1/routes asserted[transport=mcp-stdio,tool=...]`,
`?dry_run` included for a preview; `docs/mcp.md` shows both.

**IV3.** The follower half is `a_follower_refuses_to_open_the_automation_listener`
in `lorica/src/startup/automation.rs`, unchanged and run in this lot's
gates. The replication half is a cluster property no unit test on this
crate can prove: a route written through the tier is the same row a
dashboard write lands, so it rides Story 9.4's replication with no new
code, and asserting that takes the e2e cluster profile. Not proven
here, and said so rather than faked.

**Not done, and named.** The stdio binding's HTTPS client is exercised
against a real listener only by the e2e suite, so `HttpsPlane::call`'s
body serialisation and the write timeout are covered by the source
scans and by the in-process binding's tests of the same seam, not by a
socket test in this lot. No tier table and no refusal of a token
spanning two tiers: Story 11.4's, and `docs/mcp.md` says the operator
keeps the two tokens apart until then.

---

Lot 3, 2026-09-23. The audit findings on lots 1 and 2, the security
Critical first. The finding and the fix are in the Dev Note "The grant
bounds the target, and a body cannot carry that"; what follows is how
it was built and what it changed beyond the finding.

**The guard is a callback the body runs, not a check the handler
makes.** `lorica-api/src/target.rs` holds `RouteGuard`, `BackendGuard`
and `CertificateGuard`: each an optional `Arc<dyn Fn>` with
`unbounded()` for the management wrappers and `bounded(check)` for the
automation handlers, cloneable so one guard serves the two closures
the update now runs. The `_as` bodies call `guard.check(...)` inside
their `db_blocking` closure, on the row they just read: the route
bodies hand it `RouteTarget { before, after, backend_ids }`, the
backend bodies the row before and the row after the patch, the renewal
the certificate. `target.rs` knows the shape of a guard and none of the
rules; `automation/write.rs` builds the three from the token and stays
the one place the grant is spelled, so `routes::crud`, `backends` and
`acme::renewal` depend on no automation type. The create's preview now
takes the store lock for the guard's reads, which is the one cost the
route create pays that it did not.

**The route update validates outside the lock, and that is the
performance High.** `apply_route_patch(route, body, roster)` is the
former closure body, pure: every validator, the regex compiles
included, runs on a snapshot read under the lock and released. The
writing closure re-reads the row, runs the guard and the managed-row
refusal on it, writes the patched row when the row is the snapshot
(compared as `serde_json::Value`, since `Route` derives no
`PartialEq`), and applies the patch again to the row as it stands when
another writer moved it in between, so the last writer wins on the row
it saw and nothing is written over a change nobody read.
`UpdateRouteRequest` and the three nested request structs it holds
derive `Clone` for that second application. The first closure also
runs the guard and the 409, so a caller outside the grant is refused
before any validator runs and learns nothing from a validator's
message.

**The two documents said two different wrong things.** `docs/mcp.md`
promised that a config-tier token is bounded by `allowed_hostnames`
and `allowed_backend_cidrs`, which five of eight mutations did not
honour; `docs/automation.md` said an update naming no host is checked
against nothing, which described the hole as the rule. Both now say
what the code does, the second at the length the rule deserves.

**Withdrawn from the tools, refused by the plane.** `forward_auth` and
`mirror` left `ROUTE_CREATE_FIELDS` and `ROUTE_UPDATE_FIELDS` and
joined `NOT_OFFERED_TO_A_MODEL` with their reasons, so the pin test
holds the withdrawal both ways; `write.rs` refuses either field from a
token with a 403 naming it, a clearing value included. The tool
summaries name the target rule beside the claim rule.

**The preview promises what the apply does, twice over.** The backend
delete's preview answers the row marked `closing` for a backend in
normal service and `null` for one already closing, which is the two
things the apply does. The renewal's method and provider resolution
left `renew_with_method` for `plan_renewal`, run before the preview
branch and executed by `execute_renewal` on apply; the background loop
runs the same three steps through `renew_with_method`. A row the plan
refuses is a 400 naming it on both planes where it was a 500 from
inside the order, which the CHANGELOG records under Fixed.

**One `authorized()` on both routers.** `router.rs` gained the one
function holding every authorization-class layer, called by
`in_process_router()` and `build_automation_router()` alike, and
`mcp.rs` gained a test walking every `READ_SURFACE` and `WRITE_SURFACE`
path through the in-process plane with a full-scope principal,
asserting no 500 and no 403: a handler that came to extract something
only a listener layer provides fails there rather than in production.

**Recorded, not built.** The security report's Mediums and Lows and the
architecture report's Highs are decisions for the maintainer and for
Stories 11.3 and 11.4, listed at the end of the Dev Note above. The
architecture Medium on observability (the resource id and a
correlation id on the MCP request row, a per-tool metric) is a design
choice about the audit row's columns and was left as one.

---

Lot 4, 2026-09-23. The security Mediums and Lows lot 3 recorded rather
than built. The finding-by-finding account is in the Dev Note "The
Mediums and Lows were fixes, and this is what they became"; what
follows is how it was built and what it changed beyond the findings.

**Red before green, on the code as committed.** The tests were written
first, with the scaffolding they compile against (the `RenewalLedger`
type and its `AppState` field, the `RenewalBudget` parameter plumbed
and inert, the `Nested` type and `ROUTE_NESTED` declared and not yet
read by `checked_body` or `input_schema`, `mtls` named in
`NOT_OFFERED_TO_A_MODEL` while the tools still offered it), and run in
the container before any fix landed. Every one failed on the finding's
own input, as the Debug Log records; then the fixes landed and they
were run again.

**Two crates, one ledger.** `lorica-api/src/acme/renewal.rs` gained
`RenewalLedger` (in-flight ids, the CA cooldown map), `InFlightRenewal`
(the RAII mark), `RenewalBudget` and `MIN_TOKEN_RENEWAL_INTERVAL_HOURS`,
all re-exported from `crate::acme`; `AppState.renewals` holds one per
process, and every `AppState` literal in the workspace (seven in
`lorica-api`, two in the `lorica` binary's startup) names it. The
background loop's local `rate_limit_cooldown` map is gone into the
ledger, and `in_cooldown` and `cooldown_from_error` stay the pure
functions the acme tests exercise, the ledger calling the first.
`ApiError` gained `RateLimitedBecause { retry_after_s, reason }`, a 429
that names why, mapped to the same status, code and `Retry-After` as
`RateLimited`. `renew_certificate_as` takes the budget as a parameter
rather than reading it off the guard, because "the guard is bounded"
and "the actor is a token" are one fact today and two tomorrow.

**The tool model grew a depth.** `Body.nested: &'static [Nested]`,
each `Nested { field, list, fields, nested }`; `field_schemas` builds
the object or array schema with `additionalProperties: false` at every
level and `keys_declared` walks a body the same way, so the schema a
client validates against and the check the server performs still read
one declaration. The lorica-api pin
(`every_mcp_write_tool_declares_its_nested_vocabularies_against_the_nested_structs`)
reads seven more sources than lot 2's: the nested request modules under
`routes/` and `lorica-config`'s `models/route.rs`, through
`include_str!` with a relative path, since the three model structs a
route body embeds live there. The struct scanner (`serde_field_names`)
learned `skip_deserializing`, and `serde_fields_with_types` keeps the
declared type beside each name so the pin can follow it into the next
struct and tell a `Vec` from a single object. The published
`bot_protection.cookie_ttl_s` carries the word `cookie`, so the two
credential-word sweeps in `lorica-mcp` skip exactly that name through
one `#[cfg(test)]` constant with its reason
(`NAMED_FOR_A_LIFETIME_NOT_A_CREDENTIAL`), rather than dropping the
word.

**`write.rs` stays the one place the scope rules are spelled.**
`ensure_certificate_binding_granted` and `ensure_preview_readable`
sit beside `ensure_hostnames_granted`; `refuse_unbounded_reach` took
`mtls` as its third field. `DryRunQuery::mode()` was added so a
handler can read the mode before handing the query on. The
environment resource's `ensure_backend_address_granted` weighs
`to_canonical()`, so the fix reaches the environment `PUT` as well as
the backend writes and the target guard.

**Two Infos taken along.** `InProcessPlane` has no production
constructor any more: `new` lives in the module's test block, and the
struct literal in `mcp_endpoint`, built from the principal the outer
gate installed, is the one way a plane is made. Two cuts came before
that one: `#[cfg(test)]` on the method moved the `impl AutomationPlane`
block past the `#[cfg(test)]` split `tests/mcp_asserted_headers.rs`
scans the module by, and that test caught it; `pub(crate)` alone left
the method unused in the non-test build, which `-D warnings` refused
in the product gate. The management API's
`?dry_run` remains an ordinary write, as the report's own remediation
says; the `DryRun` parameter's description now says the query is
strict on this plane.

**`proxy_headers`, the maintainer's decision.** Withheld on the same
shape as the other four: a fourth argument to `refuse_unbounded_reach`
(403, "a static header map to the upstream is where a credential would
go"), out of both route vocabularies, into `NOT_OFFERED_TO_A_MODEL`
with that reason, and a whole-stack sibling of the `mtls` test,
`a_route_body_cannot_carry_a_static_header_map_to_the_upstream`, on
create, update, both previews, the clearing `{}`, with the dashboard
still setting it. Red before the refusal existed: the create answered
201, and the two pins named the field as offered.

**Not done, and named.** The request structs stay lenient to unknown
keys, for the reason in the Dev Note. `openapi-automation.yaml` describes the new
refusals on the three operations they land on and on the `DryRun`
parameter; it does not restate the nested vocabularies, which are the
tools' schema and the pin's.

## File List

Added in lot 4: nothing.

Modified in lot 4:

- `lorica-api/src/automation/write.rs`, `.../environments.rs`,
  `.../mcp.rs`
- `lorica-api/src/acme/renewal.rs`, `lorica-api/src/acme/mod.rs`,
  `lorica-api/src/acme/tests.rs`
- `lorica-api/src/error.rs`, `lorica-api/src/preview.rs`,
  `lorica-api/src/server.rs`
- `lorica-api/src/tests.rs`, `lorica-api/src/automation/audit.rs`,
  `lorica-api/src/automation_tokens/tests.rs`,
  `lorica-api/src/oidc_issuers/tests.rs` (the `AppState` literals)
- `lorica-api/tests/openapi_contract.rs`
- `lorica-api/openapi-automation.yaml`
- `lorica-mcp/src/tools.rs`, `lorica-mcp/src/server.rs`
- `lorica/src/startup/single.rs`, `lorica/src/startup/supervisor.rs`
- `CHANGELOG.md`, `README.md`, `docs/mcp.md`, `docs/automation.md`
- `docs/stories/story-11.2-config-tier.md`

Added in lot 3:

- `lorica-api/src/target.rs`

Modified in lot 3:

- `lorica-api/src/automation/write.rs`, `.../router.rs`, `.../mcp.rs`,
  `.../environments.rs`
- `lorica-api/src/routes/crud.rs`, `.../path_rules.rs`,
  `.../header_rules.rs`, `.../traffic_splits.rs`
- `lorica-api/src/backends.rs`, `lorica-api/src/acme/renewal.rs`,
  `lorica-api/src/preview.rs`, `lorica-api/src/lib.rs`
- `lorica-api/src/tests.rs`, `lorica-api/tests/openapi_contract.rs`
- `lorica-mcp/src/tools.rs`
- `CHANGELOG.md`, `README.md`, `docs/mcp.md`, `docs/automation.md`
- `docs/stories/story-11.2-config-tier.md`

Added in lot 2:

- `lorica-api/src/preview.rs`

Modified in lot 2:

- `lorica-mcp/src/lib.rs`, `.../tools.rs`, `.../server.rs`,
  `.../http.rs`, `.../stdio.rs`, `.../main.rs`, `.../untrusted.rs`
- `lorica-api/src/automation/mcp.rs`, `.../router.rs`, `.../write.rs`,
  `.../mod.rs`
- `lorica-api/src/routes/crud.rs`, `lorica-api/src/backends.rs`,
  `lorica-api/src/acme/renewal.rs`, `lorica-api/src/certificates.rs`,
  `lorica-api/src/lib.rs`
- `lorica-api/src/tests.rs`
- `lorica-api/tests/mcp_catalogue_scopes.rs`,
  `lorica-api/tests/openapi_contract.rs`,
  `lorica-api/tests/mcp_asserted_headers.rs`
- `lorica-api/openapi-automation.yaml`
- `lorica-api/Cargo.toml`, `Cargo.lock` (`percent-encoding` dropped
  from `lorica-api`: the in-process decoding it was added for is gone
  with the dispatch)
- `CHANGELOG.md`, `README.md`, `docs/mcp.md`, `docs/automation.md`
- `docs/stories/story-11.2-config-tier.md`

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

- 2026-09-23: Lot 4, the security Mediums and Lows lot 3 had recorded.
  `mtls` refused from a token, withdrawn from the tools and named as a
  client-authentication trust anchor; the key-material sweep walks the
  request structs into every struct they nest, with a positive control.
  `certificate_id` on a route write needs `certificates:write`.
  `DryRunQuery` is `deny_unknown_fields`, so a mistyped `?dry_run` is a
  400; the MCP tools carry their key check into every nested object a
  route body declares, each vocabulary pinned against its struct. A
  renewal from a token is budgeted per certificate (409 in flight, 429
  inside 48 hours of issuance, 429 during a CA cooldown) on a ledger
  the background loop and the manual path share. A preview needs the
  read scope of the row it answers. An IPv4-mapped IPv6 address is
  weighed as the IPv4 it maps to. `InProcessPlane::new` is test-only.
  Both documents and the automation OpenAPI corrected.
  Seven whole-stack tests and one unit test in `lorica-api`, each
  watched failing before the fix on the finding's own input;
  `proxy_headers` withheld from the model the same day, by the
  maintainer's decision, on the same shape as `mtls`.

- 2026-09-23: Lot 3, the audit findings on the tier. The security
  Critical: the grants bounded what a write claimed and never what it
  targeted, so a `routes:write` token reached any route, backend or
  certificate on the node by id. Every `_as` body now takes a target
  guard (`lorica-api/src/target.rs`), unbounded from the management
  wrapper and built from the token in `automation/write.rs`, run inside
  the store closure that writes on the row it writes: hostname and
  aliases against `allowed_hostnames`, stored address against
  `allowed_backend_cidrs`, every certificate name against
  `allowed_hostnames`, environment ownership through
  `caller_may_access`. The High: `forward_auth` and `mirror` refused
  from a token and withdrawn from the tools, every `backend_ids` list
  in every position resolved under the lock and held to the CIDR grant
  and to ownership. Both documents corrected. Also: the route update
  validates outside the store lock; `ROUTE_UPDATE_FIELDS` pinned to the
  create's plus a named delta; the backend delete preview reports the
  drain; the renewal resolves its method and provider before the
  preview branch and refuses as a 400 what it refused as a 500; one
  `authorized()` on both routers with a test walking every declared
  path in process; the lot 2 probe count corrected. Seven whole-stack
  tests in `lorica-api/src/tests.rs`, each watched failing before the
  fix on the finding's own input.

- 2026-09-23: Lot 2 landed, the tier itself. The in-process seam
  decision was taken first and as recommended: `lorica-mcp`'s seam is
  `AutomationPlane::call(verb, path, body, reason)` on both
  implementations, and the Streamable HTTP binding builds the request
  a tool describes and runs it through the plane's own router under
  the scope gate, principal and connection info as extensions, so the
  matrix authorizes an in-process call as it does one over the socket
  and the write handlers run unchanged with their grants and their own
  audit rows; the hand-written dispatch is gone. Eight `Mutation`s
  declared once in `lorica-mcp/src/tools.rs`, each built into an apply
  tool and a `_preview` tool by `catalogue()`, so the pair takes the
  same arguments by construction and a mutation cannot ship without
  its preview; the tier is `McpServer::sharing`'s scope filter over
  that catalogue, per process over stdio and per request over
  Streamable HTTP, and every write tool declares a write scope, pinned,
  so a read-tier token can never gain one. A write tool checks shape
  and nothing else: one `id`, a body whose top-level fields are the
  handler's (pinned against the request struct both ways, less
  `managed_by` and `basic_auth_password`, each named with its reason),
  a weight under the plane's cap. The plane owns the preview:
  `?dry_run=true` on every write path runs the management body in
  `WriteMode::Preview`, which validates, builds what it would store,
  and stops before the store, the reload and the audit row, answering
  `{dry_run, operation, before, after, changes}`. IV1 and IV2 proven
  through the tier over the HTTP binding; audit verified on both rows;
  `docs/mcp.md` gains the config tier, the affordance-not-control
  statement and the delegation section. `lorica-mcp` went from 74
  tests to 85, `lorica-api` from 908 to 918, `mcp_catalogue_scopes`
  from 4 to 6 and `openapi_contract` from 6 to 9.

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
