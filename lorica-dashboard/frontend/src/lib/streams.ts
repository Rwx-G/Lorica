/**
 * Stream plane presentation shared by the System page's budget panel
 * and the Cluster page's node drawer (Story 12.2).
 */

import type {
  NodeStreamBinding,
  NodeStreamPlane,
  StreamBindStateKind,
  StreamPortsEntry,
} from './api';

/** The shared badge class each bind state renders with. */
export const BIND_STATE_BADGE: Record<StreamBindStateKind, string> = {
  bound: 'badge-green',
  pending: 'badge-orange',
  failed: 'badge-red',
  unknown: 'badge-gray',
};

/**
 * Where a stream listens, as an operator types it into a client:
 * `0.0.0.0:5432`, `[::]:7000`, `192.0.2.10:6000-6009`.
 */
export function streamEndpoint(listenAddress: string, portFirst: number, portLast: number): string {
  const host = listenAddress.includes(':') ? `[${listenAddress}]` : listenAddress;
  const ports = portFirst === portLast ? `${portFirst}` : `${portFirst}-${portLast}`;
  return `${host}:${ports}`;
}

/** One stream of a node, with its bind state there. */
export interface NodeStreamRow {
  id: string;
  /** The stream's name, or its id for a binding the control plane does not target here. */
  name: string;
  /** `null` for a binding the control plane does not target here. */
  port: StreamPortsEntry | null;
  /** `null` while the node has sent no stream plane report. */
  state: StreamBindStateKind | null;
  /** The node's entry for a binding that is not bound. */
  binding: NodeStreamBinding | null;
}

/**
 * Each stream a node binds, with its state read the way the control
 * plane documents it: a targeted stream the node's report does not list
 * is bound (the server lists every targeted stream as `unknown` itself
 * while the node drifts), unless the report was cut, which leaves an
 * unlisted stream `unknown` as the budget view reads it. A binding the
 * node reports for a stream the control plane does not target there is
 * kept, by id, rather than dropped: a failure an operator cannot see is
 * the one they need.
 */
export function nodeStreamRows(
  ports: readonly StreamPortsEntry[],
  plane: NodeStreamPlane | null,
): NodeStreamRow[] {
  const listed = new Map((plane?.bindings ?? []).map((b) => [b.stream_id, b]));
  const unlisted: StreamBindStateKind = plane?.truncated ? 'unknown' : 'bound';
  const rows: NodeStreamRow[] = ports.map((port) => {
    const binding = listed.get(port.id) ?? null;
    return {
      id: port.id,
      name: port.name,
      port,
      state: plane === null ? null : (binding?.state ?? unlisted),
      binding,
    };
  });
  const targeted = new Set(ports.map((p) => p.id));
  for (const binding of plane?.bindings ?? []) {
    if (targeted.has(binding.stream_id)) continue;
    rows.push({ id: binding.stream_id, name: binding.stream_id, port: null, state: binding.state, binding });
  }
  return rows;
}

/** How many of a node's bindings are in each state that is not bound. */
export function unboundCounts(
  plane: NodeStreamPlane,
): Record<Exclude<StreamBindStateKind, 'bound'>, number> {
  const counts = { pending: 0, failed: 0, unknown: 0 };
  for (const binding of plane.bindings) counts[binding.state] += 1;
  return counts;
}
