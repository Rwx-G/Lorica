import { writable, derived } from 'svelte/store';

export const hash = writable(window.location.hash.slice(1) || '/');

window.addEventListener('hashchange', () => {
  hash.set(window.location.hash.slice(1) || '/');
});

export function navigate(path: string) {
  window.location.hash = path;
}

/**
 * Split a hash into its page path and its query, so a link can carry a
 * filter (`/logs?view=streams&stream=<id>`) without becoming a page of
 * its own: the loader map and the sidebar key on the path alone.
 */
export function splitHash(value: string): { path: string; query: URLSearchParams } {
  const at = value.indexOf('?');
  const path = at === -1 ? value : value.slice(0, at);
  const query = new URLSearchParams(at === -1 ? '' : value.slice(at + 1));
  return { path: path || '/', query };
}

export const currentPath = derived(hash, ($hash) => splitHash($hash).path);

export const currentQuery = derived(hash, ($hash) => splitHash($hash).query);
