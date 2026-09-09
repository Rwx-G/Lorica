import { writable, derived, type Readable } from 'svelte/store';

/**
 * What this node is in the fleet (Story 9.7).
 *
 * `standalone` is the default install and the state the whole cluster
 * UI hides itself in: an operator who never clustered must not see a
 * node filter, a fleet badge or a read-only banner.
 */
export type ClusterRole = 'standalone' | 'control_plane' | 'follower';

/** One node as `GET /api/v1/cluster/status` reports it. */
export interface FleetEntry {
  node_id: string;
  name: string;
  status: 'pending' | 'active' | 'revoked';
  connected: boolean;
  last_seen_at: string | null;
  version: string;
  applied_config_generation: number;
}

/** Payload of `GET /api/v1/cluster/status`. */
export interface ClusterStatus {
  role: ClusterRole;
  build_version: string;
  node_id: string | null;
  node_name: string | null;
  control_plane: string | null;
  connection_state: string | null;
  applied_config_generation: number;
  applied_config_hash: string;
  break_glass_until: string | null;
  fleet: FleetEntry[];
}

/** One node in the roster, as `GET /api/v1/cluster/nodes` reports it. */
export interface ClusterNodeResponse {
  node: {
    node_id: string;
    name: string;
    status: 'pending' | 'active' | 'revoked';
    version: string;
    schema_version: number;
    applied_config_generation: number;
    applied_config_hash: string;
    last_seen_at: string | null;
    enrolled_at: string;
  };
  connected: boolean;
  session_peer: string | null;
  session_last_seen_unix: number | null;
  /**
   * Hostnames whose route selectors already name this node
   * (Story 9.5 D15). Shown when approving a pending node, because
   * activating is the moment those selectors start handing it keys.
   */
  selected_for_hostnames: string[];
}

/**
 * One fanned-in access row, as `GET /api/v1/cluster/logs` returns it
 * (`FleetAccessRow` in `lorica-api/src/cluster_telemetry_store.rs`).
 *
 * Narrower than the single-node `LogEntry`: the fan-in schema carries
 * only the columns the fleet table shows, so `is_xff`, `xff_proxy_ip`
 * and `source` are absent rather than empty.
 */
export interface FleetAccessRow {
  /** Cursor for pagination: the control plane's own row id. */
  id: number;
  /** The node that produced the row. */
  node_id: string;
  timestamp: string;
  method: string;
  path: string;
  host: string;
  status: number;
  latency_ms: number;
  backend: string;
  /** Empty when the request did not fail, never null. */
  error: string;
  client_ip: string;
  request_id: string;
}

/**
 * One fanned-in WAF event, as `GET /api/v1/cluster/waf-events` returns
 * it (`FleetWafRow` in `lorica-api/src/cluster_telemetry_store.rs`).
 */
export interface FleetWafRow {
  id: number;
  node_id: string;
  rule_id: number;
  description: string;
  category: string;
  severity: number;
  matched_field: string;
  /** Already truncated by the origin node. */
  matched_value: string;
  timestamp: string;
  client_ip: string;
  route_hostname: string;
  action: string;
}

/**
 * One node's view of one banned client, as
 * `GET /api/v1/cluster/bans` returns it.
 *
 * A snapshot, not a history: bans are in-memory state on each node,
 * so this is lossy across a node restart by construction (9.6 D3).
 * There is no row id, so this endpoint is not paginated.
 */
export interface FleetBanRow {
  node_id: string;
  client_ip: string;
  /** Seconds left when the origin node took the snapshot. */
  remaining_s: number;
  reason: string;
  /** When the control plane recorded the snapshot, RFC 3339. */
  observed_at: string;
}

/**
 * The live cluster view, refreshed by the Cluster page and the header
 * badge. `null` until the first successful read, which is NOT the same
 * as standalone: a failed read must not make a follower look like a
 * standalone install and quietly re-enable write controls.
 */
export const clusterStatus = writable<ClusterStatus | null>(null);

/**
 * This node's role, or `standalone` once we know it is not clustered.
 *
 * `null` while unknown. Consumers that gate WRITES must treat `null`
 * as "not yet known" and not as "standalone".
 */
export const nodeRole: Readable<ClusterRole | null> = derived(
  clusterStatus,
  (s) => (s === null ? null : s.role),
);

/**
 * Whether a break-glass window is open right now (Story 9.4 AC #11).
 *
 * Recomputed from the timestamp rather than trusted as a boolean, so a
 * window that expires while the tab is open stops being reported as
 * open without waiting for the next poll.
 */
export function breakGlassActive(
  status: ClusterStatus | null,
  now: Date = new Date(),
): boolean {
  if (!status?.break_glass_until) return false;
  const until = Date.parse(status.break_glass_until);
  return Number.isFinite(until) && until > now.getTime();
}

/**
 * Whether local mutations are refused because this node is a follower
 * (Story 9.7 AC #4).
 *
 * A follower's configuration is replaced by the control plane on every
 * apply, so a local edit is not merely discouraged, it is lost. The
 * exception is an open break-glass window, which is exactly what that
 * window is for.
 *
 * Returns `false` while the role is unknown, deliberately: the server
 * is the enforcement, and blanking the UI on a slow status read would
 * be worse than briefly showing controls the server will refuse.
 */
export function isReadOnlyNode(
  status: ClusterStatus | null,
  now: Date = new Date(),
): boolean {
  if (status === null) return false;
  return status.role === 'follower' && !breakGlassActive(status, now);
}

/** True on a node that is part of a fleet, either side of it. */
export function isClustered(status: ClusterStatus | null): boolean {
  return status !== null && status.role !== 'standalone';
}

/** How the header badge should present the fleet (AC #6). */
export type BadgeTone = 'ok' | 'warning';

/** What the header badge shows. */
export interface FleetBadge {
  tone: BadgeTone;
  /** Short label, e.g. `Control plane 2/3`. */
  label: string;
  /** Why it is in a warning state, for the title attribute. */
  reason: string | null;
}

/**
 * How stale a node's last contact may be before the badge warns.
 *
 * Three heartbeat intervals: one missed beat is a hiccup, three is a
 * node that has stopped talking.
 */
export const STALE_AFTER_MS = 90_000;

/**
 * Build the header badge (AC #6).
 *
 * Warns on three distinct conditions, and names WHICH one in the
 * reason, because "something is wrong with the fleet" is not
 * actionable at 03:00:
 *
 * - a node the control plane expects is not connected,
 * - a connected node has not been heard from recently,
 * - a break-glass window is open somewhere.
 *
 * Returns `null` on a standalone install, which is what keeps the
 * whole cluster UI invisible there.
 */
export function fleetBadge(
  status: ClusterStatus | null,
  now: Date = new Date(),
): FleetBadge | null {
  if (!isClustered(status) || status === null) return null;

  if (status.role === 'follower') {
    const glass = breakGlassActive(status, now);
    return {
      tone: glass ? 'warning' : 'ok',
      label: 'Follower',
      reason: glass ? 'Break-glass is open: local edits are allowed and will be overwritten' : null,
    };
  }

  // Revoked nodes are not expected to connect, so they are neither in
  // the numerator nor the denominator.
  const expected = status.fleet.filter((n) => n.status !== 'revoked');
  const connected = expected.filter((n) => n.connected);
  const stale = connected.filter((n) => {
    if (!n.last_seen_at) return false;
    const seen = Date.parse(n.last_seen_at);
    return Number.isFinite(seen) && now.getTime() - seen > STALE_AFTER_MS;
  });

  const label = `Control plane ${connected.length}/${expected.length}`;
  if (connected.length < expected.length) {
    const missing = expected.length - connected.length;
    return {
      tone: 'warning',
      label,
      reason: `${missing} node${missing === 1 ? '' : 's'} not connected`,
    };
  }
  if (stale.length > 0) {
    return {
      tone: 'warning',
      label,
      reason: `${stale.length} node${stale.length === 1 ? '' : 's'} last seen over 90s ago`,
    };
  }
  if (breakGlassActive(status, now)) {
    return { tone: 'warning', label, reason: 'A break-glass window is open' };
  }
  return { tone: 'ok', label, reason: null };
}

/**
 * The join command an operator runs on the new node (AC #2).
 *
 * Deliberately does NOT contain the token. `argv` is readable through
 * `/proc`, lands in shell history and is logged verbatim by CI and
 * configuration-management `command` modules, so the token goes on
 * stdin and is offered in its own copy field.
 */
export function joinCommand(controlPlane: string): string {
  return `lorica cluster join --control-plane ${controlPlane} --token-stdin`;
}

/**
 * Seconds until a token expires, or 0 once it has.
 *
 * Used to tell an operator how long they have, since a minted token is
 * shown once and cannot be recovered.
 */
export function secondsUntil(expiresAt: string, now: Date = new Date()): number {
  const at = Date.parse(expiresAt);
  if (!Number.isFinite(at)) return 0;
  return Math.max(0, Math.floor((at - now.getTime()) / 1000));
}
