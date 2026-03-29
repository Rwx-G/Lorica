import { writable } from 'svelte/store';

export type AuthState =
  | { status: 'unauthenticated' }
  | { status: 'must_change_password' }
  | { status: 'authenticated' };

export const auth = writable<AuthState>({ status: 'unauthenticated' });
