# Story 11.3: The Admin Tier, and Where It Stops

**Epic:** [Epic 11 - Management MCP Server with Tiered Access (v1.9.0)](../prd/epic-11-v1.9.0.md)
**Status:** Draft
**Priority:** P2
**Author:** Romain G.
**Depends on:** Story 11.1, all of it. Not on Story 11.2: this tier is
a third scope set over the same core, not a widening of the config
tier.
**Blocks:** nothing.

---

As a super-admin,
I want the narrowest possible administrative surface from an MCP
client,
so that the operations that can lock me out or expose the fleet stay
deliberate.

## Problem

Every tier so far was defined by what it can reach. This one is
defined by what it refuses, and the refusals are the deliverable. A
tier that grows by accretion, one useful setting at a time, ends up
being the management API with extra steps, which is the outcome the
whole epic is arranged to prevent.

## Open question, blocking the acceptance criteria

**AC #1's allowlist is not decided.** The PRD says the surface is "a
short list decided by exclusion" and names what is out (user creation,
role changes, password resets) and one category that is in
(operational global settings: retention, thresholds, timeouts). It
does not enumerate the settings themselves, and AC #1 of IV1 wants a
test asserting the list exactly rather than describing it.

Deciding which settings an MCP client may change is a product
judgement about blast radius, not a technical one, and it is the
maintainer's. This story cannot pass its own IV1 until that list
exists. **Do not start implementation before it is written down here.**

The constraint AC #3 gives is the useful filter: everything this tier
can change must be reversible from the dashboard by a human who has
lost their MCP client. A setting that could lock the operator out of
the management plane is out by construction. Applying that filter to
the settings surface is the first task below.

## Acceptance Criteria

These are the PRD's, unchanged. They are the contract.

1. **The tier exists, and its surface is a short list decided by
   exclusion.** Global settings that are operational (retention,
   thresholds, timeouts) are in. User creation, role changes and
   password resets are **out**: an identity system driven by a model
   reading attacker-controlled text is a bad trade at any tier, and the
   dashboard is thirty seconds away.
2. **Cluster mutations are out of this tier in 1.9.0.** Enrolment,
   revocation and break-glass stay human-only, for the same reason
   Story 9.9 gives: those actions are the ones an attacker most wants
   and the ones whose audit matters most.
3. **Everything this tier can change is reversible from the dashboard
   by a human who has lost their MCP client.** A setting that could
   lock the operator out of the management plane is not in the tier.
4. Audit, documentation and a `docs/security/hardening-guide.md`
   paragraph recommending that the admin tier be configured only when a
   task needs it, and removed afterwards.

## Integration Verification

- IV1: The admin tier's tool list matches the documented allowlist
  exactly; a test asserts the list rather than describing it.
- IV2: An attempt to reach a user-management or cluster endpoint
  through the admin tier fails at the scope check, not at a tool that
  exists and refuses.

## Tasks

- [ ] **First, and blocking:** enumerate the settings this tier may
      change, by walking the settings surface and applying AC #3's
      reversibility filter to each one. Record the list and the
      exclusion reason per entry in this file. This is a decision, not
      an implementation step.
- [ ] The scope or scopes the tier stands on, and the automation-plane
      settings endpoints behind them. As in Stories 11.1 and 11.2, the
      plane does not serve this today.
- [ ] AC #2: a test proving enrolment, revocation and break-glass are
      unreachable through this tier, at the scope check.
- [ ] IV1 as an exact list assertion, derived from the allowlist rather
      than transcribed beside it.
- [ ] IV2: the refusal happens at the scope gate, so the tool does not
      exist to be called rather than existing and saying no.
- [ ] AC #4: audit, `docs/mcp.md`, and the hardening-guide paragraph.

## Dev Notes

### Why the refusal must be at the gate, not in the tool

IV2 distinguishes two failures that look identical to a user and are
not the same at all. A tool that exists and refuses has been offered to
the model, which means it is in the context, which means an injected
instruction can name it and a future change can weaken its check. A
tool that was never registered cannot be named. The scope matrix
already refuses an undeclared path for every token, so the work is to
keep those paths undeclared rather than to add a check.

### The tier that is most tempting to widen

Every request to add one more setting to this tier will be reasonable
on its own terms. The list in this file, once written, is the artefact
that makes widening a decision with a name on it rather than a commit.
Keep the exclusion reason beside each entry, because the reason is what
a later reader needs and the entry alone will not carry it.

## Dev Agent Record

### Debug Log

### Completion Notes

## File List

## Change Log

- 2026-09-23: Drafted from the Epic 11 PRD. AC #1's allowlist is
  deliberately left empty and marked blocking: it is a product decision
  about blast radius and it belongs to the maintainer, not to whoever
  implements the story.
