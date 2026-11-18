import { describe, it, expect } from 'vitest';

import type { NodeStreamPlane, StreamLiveCounters, StreamPortsEntry, StreamResponse } from './api';
import {
  BIND_STATE_BADGE,
  STREAM_BADGES,
  bindSummary,
  nodeStreamRows,
  ratesBetween,
  streamBackendCounts,
  streamBackendIds,
  streamBadges,
  streamEndpoint,
  unboundCounts,
  type StreamBadgeKind,
} from './streams';
import { status, stream, udpSettings } from '../test-stream-fixtures';

/**
 * A stream that carries `kind` and nothing else, built from the field
 * the badge is derived from. A `switch` without a default arm, so a new
 * kind is a type error here until it has its fixture.
 */
function carrying(kind: StreamBadgeKind): { stream: StreamResponse; status: ReturnType<typeof status> } {
  switch (kind) {
    case 'failed_bind':
      return {
        stream: stream(),
        status: status({
          bind: { state: 'failed', kind: 'address_in_use', port: 5432, os_error: 'Address already in use (os error 98)', since: '2026-11-18T10:00:00Z' },
        }),
      };
    case 'unbounded_responses':
      return { stream: stream({ protocol: 'udp', udp: udpSettings({ unbounded_responses: true }) }), status: status() };
    case 'no_sni':
      return {
        stream: stream({
          tls_mode: 'passthrough',
          backend_ids: [],
          match_rules: [{ name: 'bare', matcher: { kind: 'no_sni' }, backend_ids: ['b1'] }],
        }),
        status: status(),
      };
    case 'local_backend':
      return { stream: stream({ allow_local_backend: true }), status: status() };
    case 'drains_on_upgrade':
      return { stream: stream({ drains_on_upgrade: true }), status: status() };
    case 'unverified_upstream':
      return { stream: stream({ upstream_tls: { skip_verify: true } }), status: status() };
  }
}

const KINDS = Object.keys(STREAM_BADGES) as StreamBadgeKind[];

function counters(overrides: Partial<StreamLiveCounters> = {}): StreamLiveCounters {
  return {
    node_name: null,
    active: 0,
    pending: 0,
    accepted_total: 0,
    bytes_upload_total: 0,
    bytes_download_total: 0,
    refused: [],
    ended: [],
    datagrams_dropped: [],
    ...overrides,
  };
}

describe('streamBadges', () => {
  it('derives no badge from a stream with every flag at its default', () => {
    expect(streamBadges(stream(), status())).toEqual([]);
  });

  it.each(KINDS)('derives %s from its field, and only it', (kind) => {
    const { stream: s, status: st } = carrying(kind);
    expect(streamBadges(s, st).map((b) => b.kind)).toEqual([kind]);
  });

  it('renders every kind with a shared badge class, a label and a help text', () => {
    for (const kind of KINDS) {
      const { stream: s, status: st } = carrying(kind);
      const [b] = streamBadges(s, st);
      expect(['badge-green', 'badge-orange', 'badge-red', 'badge-blue', 'badge-gray']).toContain(b.className);
      expect(b.label).toContain(STREAM_BADGES[kind].label);
      expect(b.help.length).toBeGreaterThan(0);
    }
  });

  it('suffixes unbounded responses with "allowlisted" behind a source allowlist', () => {
    const open = streamBadges(stream({ protocol: 'udp', udp: udpSettings({ unbounded_responses: true }) }), null);
    expect(open[0].label).toBe('unbounded responses');
    const fenced = streamBadges(
      stream({ protocol: 'udp', udp: udpSettings({ unbounded_responses: true }), source_allow_cidrs: ['192.0.2.0/24'] }),
      null,
    );
    expect(fenced[0].label).toBe('unbounded responses (allowlisted)');
  });

  it('suffixes no SNI with "allowlisted" or "acknowledged", the allowlist first', () => {
    const base = carrying('no_sni').stream;
    expect(streamBadges({ ...base, no_sni_acknowledged: true }, null)[0].label).toBe('no SNI (acknowledged)');
    expect(
      streamBadges({ ...base, no_sni_acknowledged: true, source_allow_cidrs: ['192.0.2.0/24'] }, null)[0].label,
    ).toBe('no SNI (allowlisted)');
  });

  it('puts every failed node in the failed-bind tooltip: node, kind, port, OS error, since', () => {
    const st = status({
      bind: null,
      nodes: [
        { node_id: 'n1', node_name: 'host01', state: 'bound' },
        { node_id: 'n2', node_name: 'host02', state: 'failed', kind: 'address_in_use', port: 5432, os_error: 'Address already in use (os error 98)', since: '2026-11-18T10:00:00Z' },
        { node_id: 'n3', node_name: 'host03', state: 'failed', kind: 'source_ports' },
      ],
    });
    const [b] = streamBadges(stream(), st);
    expect(b.help.split('\n')).toEqual([
      'host02, address_in_use, port 5432, Address already in use (os error 98), since 2026-11-18T10:00:00Z',
      'host03, source_ports',
    ]);
  });
});

describe('bindSummary', () => {
  it('counts the nodes bound on a control plane', () => {
    const summary = bindSummary(
      status({
        nodes: [
          { node_id: 'n1', node_name: 'host01', state: 'bound' },
          { node_id: 'n2', node_name: 'host02', state: 'failed', kind: 'fd_budget' },
        ],
      }),
    );
    expect(summary).toEqual({ state: 'failed', label: 'bound on 1 of 2 nodes' });
  });

  it('reads this node elsewhere, naming workers that have not acknowledged', () => {
    expect(bindSummary(status())?.label).toBe('bound');
    expect(bindSummary(status({ bind: { state: 'bound', workers_serving: 1, workers: 2 } }))?.label).toBe(
      'bound (1/2 workers)',
    );
    expect(bindSummary(status({ bind: null }))).toBeNull();
  });
});

describe('ratesBetween', () => {
  it('divides the growth of each total by the seconds between readings', () => {
    const rates = ratesBetween(
      { at: 0, counters: counters({ accepted_total: 10, bytes_upload_total: 1000, bytes_download_total: 0 }) },
      { at: 5000, counters: counters({ accepted_total: 20, bytes_upload_total: 6000, bytes_download_total: 500 }) },
    );
    expect(rates).toEqual({ accepted_per_s: 2, upload_bytes_per_s: 1000, download_bytes_per_s: 100 });
  });

  it('gives no rate, never a negative one, across a restart', () => {
    const rates = ratesBetween(
      { at: 0, counters: counters({ accepted_total: 100, bytes_upload_total: 9000 }) },
      { at: 5000, counters: counters({ accepted_total: 3, bytes_upload_total: 9000 }) },
    );
    expect(rates.accepted_per_s).toBeNull();
    expect(rates.upload_bytes_per_s).toBe(0);
  });

  it('gives no rate when no time passed', () => {
    const sample = { at: 1000, counters: counters({ accepted_total: 1 }) };
    expect(ratesBetween(sample, sample).accepted_per_s).toBeNull();
  });
});

describe('stream backends', () => {
  it('counts primaries and backups, a TLS stream over its rules', () => {
    expect(streamBackendCounts(stream({ backend_ids: ['a', 'b'], backup_backend_ids: ['c'] }))).toEqual({
      primaries: 2,
      backups: 1,
    });
    const tls = stream({
      tls_mode: 'passthrough',
      backend_ids: [],
      match_rules: [
        { name: 'one', matcher: { kind: 'tls', server_names: ['a.example.com'] }, backend_ids: ['a'], backup_backend_ids: ['b'] },
        { name: 'two', matcher: { kind: 'tls', server_names: ['b.example.com'] }, backend_ids: ['c'] },
      ],
    });
    expect(streamBackendCounts(tls)).toEqual({ primaries: 2, backups: 1 });
    expect(streamBackendIds(tls).sort()).toEqual(['a', 'b', 'c']);
  });
});

function port(id: string, name: string): StreamPortsEntry {
  return { id, name, protocol: 'tcp', listen_address: '0.0.0.0', port_first: 5432, port_last: 5432 };
}

function plane(overrides: Partial<NodeStreamPlane> = {}): NodeStreamPlane {
  return { bound_count: 0, listen_sockets_used: 0, bindings: [], truncated: false, ...overrides };
}

describe('streamEndpoint', () => {
  it('writes a single port, a range, and brackets an IPv6 address', () => {
    expect(streamEndpoint('0.0.0.0', 5432, 5432)).toBe('0.0.0.0:5432');
    expect(streamEndpoint('192.0.2.10', 6000, 6009)).toBe('192.0.2.10:6000-6009');
    expect(streamEndpoint('::', 7000, 7000)).toBe('[::]:7000');
  });
});

describe('BIND_STATE_BADGE', () => {
  it('maps every state to a shared badge class', () => {
    // The shared badges are the ones `app-contrast.test.ts` holds to AA.
    for (const badge of Object.values(BIND_STATE_BADGE)) {
      expect(['badge-green', 'badge-orange', 'badge-red', 'badge-gray']).toContain(badge);
    }
    expect(BIND_STATE_BADGE.failed).toBe('badge-red');
  });
});

describe('nodeStreamRows', () => {
  it('reads a targeted stream the report does not list as bound', () => {
    const rows = nodeStreamRows([port('s1', 'pg')], plane({ bound_count: 1 }));
    expect(rows).toHaveLength(1);
    expect(rows[0].state).toBe('bound');
    expect(rows[0].binding).toBeNull();
  });

  it('takes a listed binding state and its failure', () => {
    const rows = nodeStreamRows(
      [port('s1', 'pg'), port('s2', 'dns')],
      plane({
        bindings: [
          {
            stream_id: 's2',
            state: 'failed',
            kind: 'address_in_use',
            os_error: 'Address already in use (os error 98)',
            port: 53,
            since: '2026-11-14T10:00:00Z',
          },
        ],
      }),
    );
    expect(rows.map((r) => [r.name, r.state])).toEqual([
      ['pg', 'bound'],
      ['dns', 'failed'],
    ]);
    expect(rows[1].binding?.os_error).toContain('os error 98');
  });

  it('reads an unlisted stream as unknown once the report was cut', () => {
    // A cut list says nothing of what it left out, failures included.
    const rows = nodeStreamRows([port('s1', 'pg')], plane({ truncated: true }));
    expect(rows[0].state).toBe('unknown');
  });

  it('claims no state at all before the node has reported', () => {
    // No report is not "bound": nothing vouches for the node yet.
    const rows = nodeStreamRows([port('s1', 'pg')], null);
    expect(rows[0].state).toBeNull();
  });

  it('keeps a binding the control plane does not target there, by id', () => {
    const rows = nodeStreamRows(
      [],
      plane({ bindings: [{ stream_id: 'orphan', state: 'pending' }] }),
    );
    expect(rows).toEqual([
      { id: 'orphan', name: 'orphan', port: null, state: 'pending', binding: { stream_id: 'orphan', state: 'pending' } },
    ]);
  });
});

describe('unboundCounts', () => {
  it('counts each state that is not bound', () => {
    const counts = unboundCounts(
      plane({
        bindings: [
          { stream_id: 'a', state: 'failed' },
          { stream_id: 'b', state: 'failed' },
          { stream_id: 'c', state: 'pending' },
          { stream_id: 'd', state: 'unknown' },
        ],
      }),
    );
    expect(counts).toEqual({ failed: 2, pending: 1, unknown: 1 });
  });
});
