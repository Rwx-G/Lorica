/**
 * The automation scope strings exactly as they travel on the wire,
 * sorted. Derived from Rust, not authored here.
 *
 * The vocabulary is owned by the serde renames on `AutomationScope` in
 * `lorica-config/src/models/automation_token.rs`, collected there as
 * `AutomationScope::ALL`. This file is the same set spelled for the
 * dashboard, and `lorica-api/tests/automation_scope_fixture.rs` diffs
 * the two in both directions on every `cargo test` run. Nothing writes
 * it automatically: when that gate goes red, edit the list below to
 * match the enum the message names.
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
