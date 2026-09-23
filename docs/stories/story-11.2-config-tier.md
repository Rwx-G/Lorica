# Story 11.2: The Config Tier

**Epic:** [Epic 11 - Management MCP Server with Tiered Access (v1.9.0)](../prd/epic-11-v1.9.0.md)
**Status:** Draft
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

- [ ] Three new `AutomationScope` variants: `routes:write`,
      `backends:write`, `certificates:write`. Every restatement moves
      with them; Story 11.1's Dev Notes name all of them and the guards
      that now catch a miss.
- [ ] The write paths on the automation listener, each declared in
      `required_scope` with its verb, each going through the management
      plane's own handler and validators, each audited. The follower
      refusal (409) is inherited, not rewritten.
- [ ] `openapi-automation.yaml` and the contract test.
- [ ] The field-name pin test from Story 11.1 grows the request side:
      what a caller may send is as much a contract as what it receives.

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

### Completion Notes

## File List

## Change Log

- 2026-09-23: Drafted from the Epic 11 PRD, after Story 11.1's lot 2
  established that the automation plane had no read surface. The same
  is true of writes and is recorded here before anyone estimates this
  story.
