/**
 * The automation scope strings exactly as they travel on the wire,
 * sorted, as the fixture the frontend is pinned against.
 *
 * The wire spelling is owned by Rust, in two places that already agree
 * with each other:
 *
 * - `AutomationScope`'s `#[serde(rename = "...")]` attributes in
 *   `lorica-config/src/models/automation_token.rs`, which is what a
 *   token document serialises to and deserialises from;
 * - `scope_str` in `lorica-api/src/automation/scope.rs`, which is what
 *   a 403 names as the missing grant.
 *
 * Nothing generates this client, so a rename on either Rust side is
 * caught here and nowhere else: `AutomationTokensTab.svelte` restates
 * the same four strings in `ALL_SCOPES`, and the test beside this file
 * asserts the two lists are the same set. Change one, the gate fails,
 * and the person renaming the scope is told where the other copy is.
 */
export const AUTOMATION_SCOPE_WIRE_STRINGS: readonly string[] = [
  'certificates:read',
  'environments:read',
  'environments:write',
  'routes:read',
];
