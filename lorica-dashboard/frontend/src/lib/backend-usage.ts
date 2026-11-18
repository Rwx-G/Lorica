/**
 * Which routes and streams use each backend (Story 12.10 D-j), joined in
 * the browser from the route and stream lists. Not a field of the backend
 * view: that view is also the automation `backends:read` answer, and a
 * token without `streams:read` must not learn stream names through it.
 */

import type { RouteResponse, StreamResponse } from './api';

/** One stream's link to a backend: a primary or a backup, at the stream level or in a TLS rule. */
export interface StreamLink {
  stream: StreamResponse;
  backup: boolean;
  /** The TLS rule linking it, `null` at the stream level. */
  rule: string | null;
}

export interface BackendUsage {
  routes: RouteResponse[];
  streams: StreamLink[];
}

/** Every backend's users, by backend id; a backend no one uses is absent. */
export function backendUsage(
  routes: readonly RouteResponse[],
  streams: readonly StreamResponse[],
): Record<string, BackendUsage> {
  const usage: Record<string, BackendUsage> = {};
  const of = (id: string) => (usage[id] ??= { routes: [], streams: [] });
  for (const route of routes) {
    for (const id of route.backends) of(id).routes.push(route);
  }
  for (const stream of streams) {
    for (const id of stream.backend_ids) of(id).streams.push({ stream, backup: false, rule: null });
    for (const id of stream.backup_backend_ids) of(id).streams.push({ stream, backup: true, rule: null });
    for (const rule of stream.match_rules) {
      for (const id of rule.backend_ids ?? []) of(id).streams.push({ stream, backup: false, rule: rule.name });
      for (const id of rule.backup_backend_ids ?? []) of(id).streams.push({ stream, backup: true, rule: rule.name });
    }
  }
  return usage;
}

/** The UDP streams among a backend's users, which keep its active checks off until 1.12.0. */
export function udpStreamsOf(usage: BackendUsage | undefined): StreamResponse[] {
  return (usage?.streams ?? []).filter((link) => link.stream.protocol === 'udp').map((link) => link.stream);
}
