# Story 11.4: Tier Isolation, Packaging and the Operator Story

**Epic:** [Epic 11 - Management MCP Server with Tiered Access (v1.9.0)](../prd/epic-11-v1.9.0.md)
**Status:** Draft
**Priority:** P1
**Author:** Romain G.
**Depends on:** Stories 11.1, 11.2 and 11.3. The isolation check has to
know what a tier is, and the e2e profile drives all three.
**Blocks:** the release. AC #2 and AC #5 are what make the epic
installable and explicable rather than merely built.

---

As an operator setting this up for the first time,
I want the tiers to be obviously separate and the setup to be hard to
get subtly wrong,
so that I do not end up with one token that does everything because it
was easier.

## Problem

Every safety property this epic claims rests on one operational fact:
that the person deploying it made three tokens instead of one. Nothing
so far enforces that. A token carrying `logs:read` and `routes:write`
starts a server that reads attacker-authored text and holds a mutating
tool, which is precisely the session the tiering exists to prevent, and
today it would start without complaint.

## Acceptance Criteria

These are the PRD's, unchanged. They are the contract.

1. **One process, one tier, enforced at startup.** A token whose scopes
   span two tiers is refused with a message naming the offending
   scopes. The product refuses to build the convenient thing.
2. **Packaging.** `lorica-mcp` ships in the `.deb` and `.rpm` alongside
   the binary, and the three Dockerfiles carry the crate. It is not
   started by the systemd unit: it is launched by the operator's MCP
   client.
3. **Setup that shows its own blast radius.** `lorica mcp token create
   --tier read|config|admin` mints a Story 10.3 token with exactly that
   tier's scopes, prints it once, and prints what the tier can do next
   to it.
4. **The e2e Docker suite gains an `mcp` profile**: a real Lorica, a
   real automation listener, and a client driving each tier over stdio,
   asserting the tool lists, one mutation, the audit rows and one
   revocation.
5. Documentation: the full `docs/mcp.md`, the threat-model actor, and
   the hardening-guide guidance.

## Integration Verification

- IV1: A token carrying both `logs:read` and `routes:write` is refused
  at startup with both scopes named.
- IV2: The `mcp` e2e profile passes with all three tiers configured,
  and the audit chain verifies afterwards.

## Tasks

- [ ] AC #1: the tier partition as data, and the startup refusal. The
      partition is derived from one table, not restated per tier, or it
      will drift the first time a scope moves between tiers.
- [ ] AC #3: `lorica mcp token create --tier`, minting through the
      existing Story 10.3 path rather than a second minting route. The
      printed blast radius is derived from the tier's scope set, never
      transcribed beside it.
- [ ] AC #2: packaging. `dist/build-deb.sh`, `dist/rpm/lorica.spec`,
      the four Dockerfiles (not three: `ci-check.Dockerfile` is the one
      the written rule omits), and the systemd unit left deliberately
      untouched with a comment saying why.
- [ ] AC #4: the `mcp` e2e profile.
- [ ] AC #5: `docs/mcp.md` complete, the MCP actor and the indirect
      injection path in `docs/security/threat-model.md`, the tier
      guidance in `docs/security/hardening-guide.md`.
- [ ] IV1 and IV2.

## Dev Notes

### The CLI question this story inherits and must settle

AC #3 specifies `lorica mcp token create --tier read|config|admin`,
while `docs/automation.md` documents `lorica automation token create
--scope ...` for the same Story 10.3 tokens. Nothing says whether the
first is a wrapper over the second or a second command, and two ways to
mint one credential is how an operator ends up with a token nobody can
explain.

The reading that costs least: `lorica mcp token create --tier` is a
thin front end that resolves a tier to its scope set and calls the
existing path, so there is one minting route, one audit shape and one
place where a token is born. It should say so in its own help text.

Recorded here because the epic context compilation flagged it as
unreconciled and it belongs to this story.

### Packaging a binary the unit does not start

AC #2 ships `lorica-mcp` in the packages and AC #2 also says the
systemd unit must not start it. Both halves matter. An MCP server is
launched by the client that talks to it, and a long-running system
service holding an automation token would be exactly the ambient
credential this design refuses. The unit file should carry a comment
saying that the omission is deliberate, because the next person to
read it will assume it is an oversight.

### Where the isolation check cannot help

AC #1 refuses a token spanning two tiers at startup. It cannot refuse
an operator who mints three tokens and gives all three to one client,
nor one who runs the admin tier permanently because it was convenient
once. AC #4 of Story 11.3 asks the hardening guide to recommend
removing the admin tier after the task that needed it; this story is
where that guidance actually lands.

## Dev Agent Record

### Debug Log

### Completion Notes

## File List

## Change Log

- 2026-09-23: Drafted from the Epic 11 PRD, carrying the unreconciled
  CLI question the Epic 11 context compilation surfaced.
