/**
 * Stream presentation shared by the Streams page (Story 12.10), the
 * System page's budget panel and the Cluster page's node drawer (Story
 * 12.2).
 */

import type {
  NodeStreamBinding,
  NodeStreamPlane,
  StreamBindFailureKind,
  StreamBindStateKind,
  StreamLiveCounters,
  StreamPortsEntry,
  StreamResponse,
  StreamStatus,
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

/**
 * The badges a stream can carry in 1.11.0, each derived from fields the
 * API returns (Story 12.10 D-c). Silent client (Story 12.15) and
 * transparent mode (Story 12.13) are not here: their fields do not
 * exist yet, so their badge could never render. Each of those stories
 * adds its kind to this union, which `STREAM_BADGES` and the `switch` in
 * `deriveBadge` then refuse to compile without.
 */
export type StreamBadgeKind =
  | 'failed_bind'
  | 'unbounded_responses'
  | 'no_sni'
  | 'local_backend'
  | 'drains_on_upgrade'
  | 'unverified_upstream';

/** The shared badge colour a stream badge renders with. */
export type StreamBadgeTone = 'red' | 'orange' | 'blue' | 'gray';

export const STREAM_BADGES: Record<StreamBadgeKind, { label: string; tone: StreamBadgeTone; help: string }> = {
  failed_bind: {
    label: 'failed bind',
    tone: 'red',
    help: 'A node that should bind the stream failed to.',
  },
  unbounded_responses: {
    label: 'unbounded responses',
    tone: 'orange',
    help: 'The UDP response bounds are lifted: a backend may send any amount back, which a spoofed source can turn into reflection.',
  },
  no_sni: {
    label: 'no SNI',
    tone: 'orange',
    help: 'A rule admits clients that name no server.',
  },
  local_backend: {
    label: 'local backend',
    tone: 'orange',
    help: 'The stream may forward to a local address of the node (loopback, link-local, localhost or one of its own).',
  },
  drains_on_upgrade: {
    label: 'drains on upgrade',
    tone: 'blue',
    help: 'Lorica holds TLS keys for these connections, so a hot upgrade drains them. In 1.11.0 a hot upgrade drains every stream; this names the ones that keep draining once a later release transfers the others.',
  },
  unverified_upstream: {
    label: 'unverified upstream',
    tone: 'red',
    help: 'Upstream TLS accepts any backend certificate.',
  },
};

/** One badge as the list row and the drawer header render it. */
export interface StreamBadge {
  kind: StreamBadgeKind;
  /** The kind's label, with its suffix when the stream qualifies it. */
  label: string;
  /** The shared badge class. */
  className: string;
  /** The tooltip. */
  help: string;
}

/** One place a stream failed to bind: this node, or a node of the fleet. */
export interface BindFailure {
  node: string;
  kind?: StreamBindFailureKind;
  port?: number;
  os_error?: string;
  since?: string;
}

/** Every failed binding of a stream in its status, this node's first. */
export function bindFailures(status: StreamStatus | null): BindFailure[] {
  if (!status) return [];
  const failures: BindFailure[] = [];
  if (status.bind?.state === 'failed') {
    const { kind, port, os_error, since } = status.bind;
    failures.push({ node: status.counters?.node_name ?? 'this node', kind, port, os_error, since });
  }
  for (const node of status.nodes ?? []) {
    if (node.state !== 'failed') continue;
    const { kind, port, os_error, since } = node;
    failures.push({ node: node.node_name, kind, port, os_error, since });
  }
  return failures;
}

/** One line per failure: node, kind, port, OS error, since. */
export function describeBindFailure(f: BindFailure): string {
  const parts = [f.node, f.kind ?? 'failed'];
  if (f.port !== undefined) parts.push(`port ${f.port}`);
  if (f.os_error) parts.push(f.os_error);
  if (f.since) parts.push(`since ${f.since}`);
  return parts.join(', ');
}

function badge(kind: StreamBadgeKind, suffix: string | null, help?: string): StreamBadge {
  const definition = STREAM_BADGES[kind];
  return {
    kind,
    label: suffix ? `${definition.label} (${suffix})` : definition.label,
    className: `badge-${definition.tone}`,
    help: help ?? definition.help,
  };
}

function deriveBadge(kind: StreamBadgeKind, stream: StreamResponse, status: StreamStatus | null): StreamBadge | null {
  const allowlisted = stream.source_allow_cidrs.length > 0;
  switch (kind) {
    case 'failed_bind': {
      const failures = bindFailures(status);
      if (failures.length === 0) return null;
      return badge(kind, null, failures.map(describeBindFailure).join('\n'));
    }
    case 'unbounded_responses':
      if (!stream.udp?.unbounded_responses) return null;
      return badge(kind, allowlisted ? 'allowlisted' : null);
    case 'no_sni':
      if (!stream.match_rules.some((rule) => rule.matcher.kind === 'no_sni')) return null;
      return badge(kind, allowlisted ? 'allowlisted' : stream.no_sni_acknowledged ? 'acknowledged' : null);
    case 'local_backend':
      return stream.allow_local_backend ? badge(kind, null) : null;
    case 'drains_on_upgrade':
      return stream.drains_on_upgrade ? badge(kind, null) : null;
    case 'unverified_upstream':
      return stream.upstream_tls?.skip_verify ? badge(kind, null) : null;
    default: {
      const unreachable: never = kind;
      return unreachable;
    }
  }
}

/** Every badge `stream` carries, in the order of `STREAM_BADGES`. */
export function streamBadges(stream: StreamResponse, status: StreamStatus | null): StreamBadge[] {
  return (Object.keys(STREAM_BADGES) as StreamBadgeKind[])
    .map((kind) => deriveBadge(kind, stream, status))
    .filter((b): b is StreamBadge => b !== null);
}

/** A stream's backends: primaries and backups, a TLS stream's summed over its rules. */
export function streamBackendCounts(stream: StreamResponse): { primaries: number; backups: number } {
  if (stream.match_rules.length > 0) {
    return stream.match_rules.reduce(
      (sum, rule) => ({
        primaries: sum.primaries + (rule.backend_ids?.length ?? 0),
        backups: sum.backups + (rule.backup_backend_ids?.length ?? 0),
      }),
      { primaries: 0, backups: 0 },
    );
  }
  return { primaries: stream.backend_ids.length, backups: stream.backup_backend_ids.length };
}

/** Every backend id a stream links, a TLS stream's through its rules. */
export function streamBackendIds(stream: StreamResponse): string[] {
  const ids = [...stream.backend_ids, ...stream.backup_backend_ids];
  for (const rule of stream.match_rules) {
    ids.push(...(rule.backend_ids ?? []), ...(rule.backup_backend_ids ?? []));
  }
  return [...new Set(ids)];
}

/**
 * Where a stream is bound: on a control plane, how many of the nodes
 * that should bind it hold it; elsewhere, this node's state. `null`
 * when nothing binds it here and no node is listed.
 */
export function bindSummary(
  status: StreamStatus | null,
): { state: StreamBindStateKind; label: string } | null {
  if (!status) return null;
  if (status.nodes !== null) {
    const total = status.nodes.length;
    const bound = status.nodes.filter((n) => n.state === 'bound').length;
    if (total === 0) return null;
    const worst: StreamBindStateKind = status.nodes.some((n) => n.state === 'failed')
      ? 'failed'
      : bound === total
        ? 'bound'
        : status.nodes.some((n) => n.state === 'pending')
          ? 'pending'
          : 'unknown';
    return { state: worst, label: `bound on ${bound} of ${total} node${total === 1 ? '' : 's'}` };
  }
  if (!status.bind) return null;
  const { state, workers_serving, workers } = status.bind;
  if (state === 'bound' && workers !== undefined && workers_serving !== undefined && workers_serving < workers) {
    return { state, label: `bound (${workers_serving}/${workers} workers)` };
  }
  return { state, label: state };
}

/** One reading of a stream's counters and when it was taken. */
export interface CounterSample {
  at: number;
  counters: StreamLiveCounters;
}

/** Per-second rates between two readings; `null` where a total went down (a restart) or no time passed. */
export interface StreamRates {
  accepted_per_s: number | null;
  upload_bytes_per_s: number | null;
  download_bytes_per_s: number | null;
}

/**
 * The rates between two successive readings of one stream's counters,
 * computed in the browser (D-e). A total that went down is a process
 * restart: that interval has no rate, never a negative one.
 */
export function ratesBetween(a: CounterSample, b: CounterSample): StreamRates {
  const seconds = (b.at - a.at) / 1000;
  const rate = (before: number, after: number): number | null =>
    seconds <= 0 || after < before ? null : (after - before) / seconds;
  return {
    accepted_per_s: rate(a.counters.accepted_total, b.counters.accepted_total),
    upload_bytes_per_s: rate(a.counters.bytes_upload_total, b.counters.bytes_upload_total),
    download_bytes_per_s: rate(a.counters.bytes_download_total, b.counters.bytes_download_total),
  };
}
