import { writable, derived } from 'svelte/store';

import { clusterStatus, isReadOnlyNode } from './cluster';

/** RBAC role of the logged-in account (Story 8.3). */
export type Role = 'super_admin' | 'operator' | 'viewer';

export type AuthState =
  | { status: 'unauthenticated' }
  | { status: 'must_change_password' }
  | { status: 'authenticated'; username: string; role: Role };

export const auth = writable<AuthState>({ status: 'unauthenticated' });

/**
 * True when the logged-in role may mutate state (Operator or
 * SuperAdmin). Pages gate mutating controls on this so a Viewer sees
 * a read-only dashboard; the server-side authorization middleware is
 * the actual enforcement.
 */
export const canWrite = derived(
  [auth, clusterStatus],
  ([a, cluster]) =>
    a.status === 'authenticated' &&
    (a.role === 'operator' || a.role === 'super_admin') &&
    !isReadOnlyNode(cluster),
);

/**
 * True when the logged-in role is SuperAdmin AND this node accepts
 * local mutations.
 *
 * Read-only mode is ORTHOGONAL to role (Story 9.7 AC #4): a follower
 * replaces its configuration from the control plane on every apply, so
 * a local edit by a SuperAdmin is not merely discouraged, it is lost
 * at the next replication round. Deriving over the cluster state as
 * well as the role is what stops the dashboard offering an action the
 * fleet will silently undo.
 *
 * Break-glass reopens both stores, which is exactly what that window
 * is for.
 */
export const isSuperAdmin = derived(
  [auth, clusterStatus],
  ([a, cluster]) =>
    a.status === 'authenticated' && a.role === 'super_admin' && !isReadOnlyNode(cluster),
);

/**
 * The role alone, ignoring read-only mode.
 *
 * For the controls that must stay available on a follower: the two
 * that are how an operator gets OUT of read-only mode (opening a
 * break-glass window, leaving the fleet), and local account
 * management, whose table replication never writes.
 */
export const isSuperAdminRole = derived(
  auth,
  (a) => a.status === 'authenticated' && a.role === 'super_admin',
);

/**
 * Write permission from the role alone, ignoring read-only mode.
 *
 * The counterpart of [`isSuperAdminRole`], for the actions the server
 * still serves on a follower because they touch no replicated
 * configuration. The authoritative list is `follower_local_request`
 * in `lorica-api/src/middleware/authorize.rs`, and this store exists
 * so the dashboard can match it rather than hide controls the server
 * would have honoured.
 *
 * Use `canWrite` for anything that edits configuration. Reach for this
 * one only against a path that allow-list actually names, and say
 * which at the call site.
 */
export const canWriteRole = derived(
  auth,
  (a) => a.status === 'authenticated' && (a.role === 'operator' || a.role === 'super_admin'),
);
