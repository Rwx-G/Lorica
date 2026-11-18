import { describe, it, expect } from 'vitest';

import type { RouteResponse } from './api';
import { backendUsage, udpStreamsOf } from './backend-usage';
import { stream, udpSettings } from '../test-stream-fixtures';

function route(id: string, hostname: string, backends: string[]): RouteResponse {
  return { id, hostname, backends } as RouteResponse;
}

describe('backendUsage', () => {
  it('joins a route, a TCP stream with a backup and a TLS stream per rule', () => {
    const tcp = stream({ id: 's1', name: 'pg', backend_ids: ['a'], backup_backend_ids: ['b'] });
    const tls = stream({
      id: 's2',
      name: 'edge',
      tls_mode: 'passthrough',
      backend_ids: [],
      match_rules: [
        { name: 'db', matcher: { kind: 'tls', server_names: ['db.example.com'] }, backend_ids: ['a'], backup_backend_ids: ['c'] },
      ],
    });
    const usage = backendUsage([route('r1', 'app.example.com', ['a'])], [tcp, tls]);

    expect(usage.a.routes.map((r) => r.hostname)).toEqual(['app.example.com']);
    expect(usage.a.streams.map((l) => [l.stream.name, l.backup, l.rule])).toEqual([
      ['pg', false, null],
      ['edge', false, 'db'],
    ]);
    expect(usage.b.streams.map((l) => [l.stream.name, l.backup])).toEqual([['pg', true]]);
    expect(usage.b.routes).toEqual([]);
    expect(usage.c.streams.map((l) => [l.stream.name, l.backup, l.rule])).toEqual([['edge', true, 'db']]);
    expect(usage.unused).toBeUndefined();
  });

  it('names the UDP streams among the users', () => {
    const udp = stream({ id: 's3', name: 'dns', protocol: 'udp', udp: udpSettings(), backend_ids: ['a'] });
    const usage = backendUsage([], [stream({ backend_ids: ['a'] }), udp]);
    expect(udpStreamsOf(usage.a).map((s) => s.name)).toEqual(['dns']);
    expect(udpStreamsOf(undefined)).toEqual([]);
  });
});
