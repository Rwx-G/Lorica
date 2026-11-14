import { describe, it, expect } from 'vitest';

import type { NodeStreamPlane, StreamPortsEntry } from './api';
import { BIND_STATE_BADGE, nodeStreamRows, streamEndpoint, unboundCounts } from './streams';

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
