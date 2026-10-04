/**
 * The automation scope strings exactly as they travel on the wire,
 * sorted. Derived from Rust, not authored here.
 *
 * The vocabulary is owned by the serde renames on `AutomationScope` in
 * `lorica-automation-policy/src/scope.rs`, collected there as
 * `AutomationScope::ALL`. This file is the same set spelled for the
 * dashboard, and `lorica-api/tests/automation_scope_fixture.rs` diffs
 * the two in both directions on every `cargo test` run. Nothing writes
 * it automatically: when that gate goes red, edit the list below to
 * match the enum the message names.
 *
 * The MCP tier section at the end is held tighter: the same test
 * renders it from the policy crate's tier table and its `resolve`, and
 * compares the bytes. It carries a vector set the mint form's own tier
 * reading is replayed against, so the form's warning and the refusal
 * `lorica-mcp` prints cannot disagree.
 *
 * It is the only guard on this language boundary. Without it a variant
 * added on the Rust side passes the Rust suite, passes the frontend
 * suite, and leaves the mint form unable to offer the scope, silently
 * in both directions. `AutomationTokensTab.svelte` derives `ALL_SCOPES`
 * from the list below rather than restating it, so the chain runs enum
 * to fixture to form.
 *
 * Typed as the `AutomationScope` union rather than `string[]` on
 * purpose: that makes a scope present here and absent from the union a
 * `npm run check` failure, so the two TypeScript surfaces cannot drift
 * either.
 *
 * No local formatter touches it: the emitting side owns its shape, and
 * a reformat would turn a byte comparison into noise on every line.
 * `eslint.config.js` ignores `**\/*.generated.ts` for that reason.
 */
import type { AutomationScope } from '../../lib/api';

export const AUTOMATION_SCOPE_WIRE_STRINGS: readonly AutomationScope[] = [
  'backends:read',
  'backends:write',
  'certificates:read',
  'certificates:write',
  'cluster:read',
  'environments:read',
  'environments:write',
  'logs:read',
  'routes:read',
  'routes:write',
  'settings:write',
  'sla:read',
  'waf:read',
];

/**
 * The scopes whose paths consult a token's hostname and backend
 * grants, sorted. Owned by `AutomationScope::is_grant_bounded` in the
 * same Rust file, and diffed against it in both directions by the same
 * test. A token carrying one of these needs both grants; a token
 * carrying none carries neither, and the dashboard renders its grants
 * as not applicable.
 */
export const GRANT_BOUNDED_SCOPES: readonly AutomationScope[] = [
  'backends:write',
  'certificates:write',
  'environments:write',
  'routes:write',
];

// BEGIN MCP TIERS: rendered from lorica-automation-policy by
// lorica-api/tests/automation_scope_fixture.rs, which prints the section as it
// must read when the committed one differs. Replace it with that; never edit
// it by hand.

/** An MCP tier, in increasing order of reach (`Tier::ALL`). */
export type McpTier = 'read' | 'config' | 'admin';

/**
 * One row of `TIERS`: the scopes that make a token this tier, and the
 * scopes of another tier its tools need and so allow beside its own.
 */
export interface McpTierDefinition {
  readonly tier: McpTier;
  readonly requires: readonly AutomationScope[];
  readonly tolerates: readonly AutomationScope[];
}

/** The tier partition, in increasing order of reach. */
export const MCP_TIERS: readonly McpTierDefinition[] = [
  {
    tier: 'read',
    requires: ['logs:read', 'waf:read', 'sla:read', 'cluster:read', 'backends:read', 'routes:read', 'certificates:read', 'environments:read'],
    tolerates: [],
  },
  {
    tier: 'config',
    requires: ['routes:write', 'backends:write', 'certificates:write', 'environments:write'],
    tolerates: ['backends:read', 'routes:read', 'certificates:read'],
  },
  {
    tier: 'admin',
    requires: ['settings:write'],
    tolerates: [],
  },
];

/**
 * What `resolve` answers for one scope set: the tier its highest-reaching
 * scopes make it (`null` for none), the scopes that name that tier, and the
 * scopes that tier does not allow. A set with no offending scope is one tier
 * and starts lorica-mcp; any other is refused there.
 */
export interface McpTierVector {
  readonly scopes: readonly AutomationScope[];
  readonly tier: McpTier | null;
  readonly anchoring: readonly AutomationScope[];
  readonly offending: readonly AutomationScope[];
}

export const MCP_TIER_VECTORS: readonly McpTierVector[] = [
  { scopes: [], tier: null, anchoring: [], offending: [] },
  { scopes: ['environments:write'], tier: 'config', anchoring: ['environments:write'], offending: [] },
  { scopes: ['environments:read'], tier: 'read', anchoring: ['environments:read'], offending: [] },
  { scopes: ['routes:read'], tier: 'read', anchoring: ['routes:read'], offending: [] },
  { scopes: ['certificates:read'], tier: 'read', anchoring: ['certificates:read'], offending: [] },
  { scopes: ['logs:read'], tier: 'read', anchoring: ['logs:read'], offending: [] },
  { scopes: ['waf:read'], tier: 'read', anchoring: ['waf:read'], offending: [] },
  { scopes: ['sla:read'], tier: 'read', anchoring: ['sla:read'], offending: [] },
  { scopes: ['cluster:read'], tier: 'read', anchoring: ['cluster:read'], offending: [] },
  { scopes: ['backends:read'], tier: 'read', anchoring: ['backends:read'], offending: [] },
  { scopes: ['routes:write'], tier: 'config', anchoring: ['routes:write'], offending: [] },
  { scopes: ['backends:write'], tier: 'config', anchoring: ['backends:write'], offending: [] },
  { scopes: ['certificates:write'], tier: 'config', anchoring: ['certificates:write'], offending: [] },
  { scopes: ['settings:write'], tier: 'admin', anchoring: ['settings:write'], offending: [] },
  { scopes: ['environments:write', 'environments:read'], tier: 'config', anchoring: ['environments:write'], offending: ['environments:read'] },
  { scopes: ['environments:write', 'routes:read'], tier: 'config', anchoring: ['environments:write'], offending: [] },
  { scopes: ['environments:write', 'certificates:read'], tier: 'config', anchoring: ['environments:write'], offending: [] },
  { scopes: ['environments:write', 'logs:read'], tier: 'config', anchoring: ['environments:write'], offending: ['logs:read'] },
  { scopes: ['environments:write', 'waf:read'], tier: 'config', anchoring: ['environments:write'], offending: ['waf:read'] },
  { scopes: ['environments:write', 'sla:read'], tier: 'config', anchoring: ['environments:write'], offending: ['sla:read'] },
  { scopes: ['environments:write', 'cluster:read'], tier: 'config', anchoring: ['environments:write'], offending: ['cluster:read'] },
  { scopes: ['environments:write', 'backends:read'], tier: 'config', anchoring: ['environments:write'], offending: [] },
  { scopes: ['environments:write', 'routes:write'], tier: 'config', anchoring: ['environments:write', 'routes:write'], offending: [] },
  { scopes: ['environments:write', 'backends:write'], tier: 'config', anchoring: ['environments:write', 'backends:write'], offending: [] },
  { scopes: ['environments:write', 'certificates:write'], tier: 'config', anchoring: ['environments:write', 'certificates:write'], offending: [] },
  { scopes: ['environments:write', 'settings:write'], tier: 'admin', anchoring: ['settings:write'], offending: ['environments:write'] },
  { scopes: ['environments:read', 'routes:read'], tier: 'read', anchoring: ['environments:read', 'routes:read'], offending: [] },
  { scopes: ['environments:read', 'certificates:read'], tier: 'read', anchoring: ['environments:read', 'certificates:read'], offending: [] },
  { scopes: ['environments:read', 'logs:read'], tier: 'read', anchoring: ['environments:read', 'logs:read'], offending: [] },
  { scopes: ['environments:read', 'waf:read'], tier: 'read', anchoring: ['environments:read', 'waf:read'], offending: [] },
  { scopes: ['environments:read', 'sla:read'], tier: 'read', anchoring: ['environments:read', 'sla:read'], offending: [] },
  { scopes: ['environments:read', 'cluster:read'], tier: 'read', anchoring: ['environments:read', 'cluster:read'], offending: [] },
  { scopes: ['environments:read', 'backends:read'], tier: 'read', anchoring: ['environments:read', 'backends:read'], offending: [] },
  { scopes: ['environments:read', 'routes:write'], tier: 'config', anchoring: ['routes:write'], offending: ['environments:read'] },
  { scopes: ['environments:read', 'backends:write'], tier: 'config', anchoring: ['backends:write'], offending: ['environments:read'] },
  { scopes: ['environments:read', 'certificates:write'], tier: 'config', anchoring: ['certificates:write'], offending: ['environments:read'] },
  { scopes: ['environments:read', 'settings:write'], tier: 'admin', anchoring: ['settings:write'], offending: ['environments:read'] },
  { scopes: ['routes:read', 'certificates:read'], tier: 'read', anchoring: ['routes:read', 'certificates:read'], offending: [] },
  { scopes: ['routes:read', 'logs:read'], tier: 'read', anchoring: ['routes:read', 'logs:read'], offending: [] },
  { scopes: ['routes:read', 'waf:read'], tier: 'read', anchoring: ['routes:read', 'waf:read'], offending: [] },
  { scopes: ['routes:read', 'sla:read'], tier: 'read', anchoring: ['routes:read', 'sla:read'], offending: [] },
  { scopes: ['routes:read', 'cluster:read'], tier: 'read', anchoring: ['routes:read', 'cluster:read'], offending: [] },
  { scopes: ['routes:read', 'backends:read'], tier: 'read', anchoring: ['routes:read', 'backends:read'], offending: [] },
  { scopes: ['routes:read', 'routes:write'], tier: 'config', anchoring: ['routes:write'], offending: [] },
  { scopes: ['routes:read', 'backends:write'], tier: 'config', anchoring: ['backends:write'], offending: [] },
  { scopes: ['routes:read', 'certificates:write'], tier: 'config', anchoring: ['certificates:write'], offending: [] },
  { scopes: ['routes:read', 'settings:write'], tier: 'admin', anchoring: ['settings:write'], offending: ['routes:read'] },
  { scopes: ['certificates:read', 'logs:read'], tier: 'read', anchoring: ['certificates:read', 'logs:read'], offending: [] },
  { scopes: ['certificates:read', 'waf:read'], tier: 'read', anchoring: ['certificates:read', 'waf:read'], offending: [] },
  { scopes: ['certificates:read', 'sla:read'], tier: 'read', anchoring: ['certificates:read', 'sla:read'], offending: [] },
  { scopes: ['certificates:read', 'cluster:read'], tier: 'read', anchoring: ['certificates:read', 'cluster:read'], offending: [] },
  { scopes: ['certificates:read', 'backends:read'], tier: 'read', anchoring: ['certificates:read', 'backends:read'], offending: [] },
  { scopes: ['certificates:read', 'routes:write'], tier: 'config', anchoring: ['routes:write'], offending: [] },
  { scopes: ['certificates:read', 'backends:write'], tier: 'config', anchoring: ['backends:write'], offending: [] },
  { scopes: ['certificates:read', 'certificates:write'], tier: 'config', anchoring: ['certificates:write'], offending: [] },
  { scopes: ['certificates:read', 'settings:write'], tier: 'admin', anchoring: ['settings:write'], offending: ['certificates:read'] },
  { scopes: ['logs:read', 'waf:read'], tier: 'read', anchoring: ['logs:read', 'waf:read'], offending: [] },
  { scopes: ['logs:read', 'sla:read'], tier: 'read', anchoring: ['logs:read', 'sla:read'], offending: [] },
  { scopes: ['logs:read', 'cluster:read'], tier: 'read', anchoring: ['logs:read', 'cluster:read'], offending: [] },
  { scopes: ['logs:read', 'backends:read'], tier: 'read', anchoring: ['logs:read', 'backends:read'], offending: [] },
  { scopes: ['logs:read', 'routes:write'], tier: 'config', anchoring: ['routes:write'], offending: ['logs:read'] },
  { scopes: ['logs:read', 'backends:write'], tier: 'config', anchoring: ['backends:write'], offending: ['logs:read'] },
  { scopes: ['logs:read', 'certificates:write'], tier: 'config', anchoring: ['certificates:write'], offending: ['logs:read'] },
  { scopes: ['logs:read', 'settings:write'], tier: 'admin', anchoring: ['settings:write'], offending: ['logs:read'] },
  { scopes: ['waf:read', 'sla:read'], tier: 'read', anchoring: ['waf:read', 'sla:read'], offending: [] },
  { scopes: ['waf:read', 'cluster:read'], tier: 'read', anchoring: ['waf:read', 'cluster:read'], offending: [] },
  { scopes: ['waf:read', 'backends:read'], tier: 'read', anchoring: ['waf:read', 'backends:read'], offending: [] },
  { scopes: ['waf:read', 'routes:write'], tier: 'config', anchoring: ['routes:write'], offending: ['waf:read'] },
  { scopes: ['waf:read', 'backends:write'], tier: 'config', anchoring: ['backends:write'], offending: ['waf:read'] },
  { scopes: ['waf:read', 'certificates:write'], tier: 'config', anchoring: ['certificates:write'], offending: ['waf:read'] },
  { scopes: ['waf:read', 'settings:write'], tier: 'admin', anchoring: ['settings:write'], offending: ['waf:read'] },
  { scopes: ['sla:read', 'cluster:read'], tier: 'read', anchoring: ['sla:read', 'cluster:read'], offending: [] },
  { scopes: ['sla:read', 'backends:read'], tier: 'read', anchoring: ['sla:read', 'backends:read'], offending: [] },
  { scopes: ['sla:read', 'routes:write'], tier: 'config', anchoring: ['routes:write'], offending: ['sla:read'] },
  { scopes: ['sla:read', 'backends:write'], tier: 'config', anchoring: ['backends:write'], offending: ['sla:read'] },
  { scopes: ['sla:read', 'certificates:write'], tier: 'config', anchoring: ['certificates:write'], offending: ['sla:read'] },
  { scopes: ['sla:read', 'settings:write'], tier: 'admin', anchoring: ['settings:write'], offending: ['sla:read'] },
  { scopes: ['cluster:read', 'backends:read'], tier: 'read', anchoring: ['cluster:read', 'backends:read'], offending: [] },
  { scopes: ['cluster:read', 'routes:write'], tier: 'config', anchoring: ['routes:write'], offending: ['cluster:read'] },
  { scopes: ['cluster:read', 'backends:write'], tier: 'config', anchoring: ['backends:write'], offending: ['cluster:read'] },
  { scopes: ['cluster:read', 'certificates:write'], tier: 'config', anchoring: ['certificates:write'], offending: ['cluster:read'] },
  { scopes: ['cluster:read', 'settings:write'], tier: 'admin', anchoring: ['settings:write'], offending: ['cluster:read'] },
  { scopes: ['backends:read', 'routes:write'], tier: 'config', anchoring: ['routes:write'], offending: [] },
  { scopes: ['backends:read', 'backends:write'], tier: 'config', anchoring: ['backends:write'], offending: [] },
  { scopes: ['backends:read', 'certificates:write'], tier: 'config', anchoring: ['certificates:write'], offending: [] },
  { scopes: ['backends:read', 'settings:write'], tier: 'admin', anchoring: ['settings:write'], offending: ['backends:read'] },
  { scopes: ['routes:write', 'backends:write'], tier: 'config', anchoring: ['routes:write', 'backends:write'], offending: [] },
  { scopes: ['routes:write', 'certificates:write'], tier: 'config', anchoring: ['routes:write', 'certificates:write'], offending: [] },
  { scopes: ['routes:write', 'settings:write'], tier: 'admin', anchoring: ['settings:write'], offending: ['routes:write'] },
  { scopes: ['backends:write', 'certificates:write'], tier: 'config', anchoring: ['backends:write', 'certificates:write'], offending: [] },
  { scopes: ['backends:write', 'settings:write'], tier: 'admin', anchoring: ['settings:write'], offending: ['backends:write'] },
  { scopes: ['certificates:write', 'settings:write'], tier: 'admin', anchoring: ['settings:write'], offending: ['certificates:write'] },
  { scopes: ['logs:read', 'waf:read', 'sla:read', 'cluster:read', 'backends:read', 'routes:read', 'certificates:read', 'environments:read'], tier: 'read', anchoring: ['logs:read', 'waf:read', 'sla:read', 'cluster:read', 'backends:read', 'routes:read', 'certificates:read', 'environments:read'], offending: [] },
  { scopes: ['routes:write', 'backends:write', 'certificates:write', 'environments:write', 'backends:read', 'routes:read', 'certificates:read'], tier: 'config', anchoring: ['routes:write', 'backends:write', 'certificates:write', 'environments:write'], offending: [] },
  { scopes: ['settings:write'], tier: 'admin', anchoring: ['settings:write'], offending: [] },
];
// END MCP TIERS
