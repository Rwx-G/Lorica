import { writable, derived } from 'svelte/store';

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
  auth,
  (a) => a.status === 'authenticated' && (a.role === 'operator' || a.role === 'super_admin'),
);

/** True when the logged-in role is SuperAdmin (settings writes, user management). */
export const isSuperAdmin = derived(
  auth,
  (a) => a.status === 'authenticated' && a.role === 'super_admin',
);
