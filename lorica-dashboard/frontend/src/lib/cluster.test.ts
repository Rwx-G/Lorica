import { describe, it, expect } from 'vitest';
import {
  breakGlassActive,
  fleetBadge,
  isClustered,
  isReadOnlyNode,
  joinCommand,
  secondsUntil,
  type ClusterStatus,
  type FleetEntry,
} from './cluster';

const NOW = new Date('2026-09-09T12:00:00Z');

function node(over: Partial<FleetEntry> = {}): FleetEntry {
  return {
    node_id: 'node-a',
    name: 'edge-01',
    status: 'active',
    connected: true,
    last_seen_at: '2026-09-09T11:59:50Z',
    version: '1.7.0',
    applied_config_generation: 7,
    ...over,
  };
}

function status(over: Partial<ClusterStatus> = {}): ClusterStatus {
  return {
    role: 'control_plane',
    build_version: '1.7.0',
    node_id: null,
    node_name: null,
    control_plane: null,
    connection_state: null,
    applied_config_generation: 7,
    applied_config_hash: 'abc',
    break_glass_until: null,
    fleet: [],
    ...over,
  };
}

describe('break-glass', () => {
  it('is recomputed from the timestamp, not trusted as a flag', () => {
    // A window that lapses while the tab is open must stop reading as
    // open without waiting for the next poll.
    const open = status({ break_glass_until: '2026-09-09T12:00:01Z' });
    const lapsed = status({ break_glass_until: '2026-09-09T11:59:59Z' });
    expect(breakGlassActive(open, NOW)).toBe(true);
    expect(breakGlassActive(lapsed, NOW)).toBe(false);
  });

  it('treats an unparseable timestamp as closed', () => {
    expect(breakGlassActive(status({ break_glass_until: 'not a date' }), NOW)).toBe(false);
  });
});

describe('read-only gating', () => {
  it('a follower is read-only unless break-glass is open', () => {
    expect(isReadOnlyNode(status({ role: 'follower' }), NOW)).toBe(true);
    expect(
      isReadOnlyNode(
        status({ role: 'follower', break_glass_until: '2026-09-09T12:30:00Z' }),
        NOW,
      ),
    ).toBe(false);
  });

  it('a control plane and a standalone node are never read-only', () => {
    expect(isReadOnlyNode(status({ role: 'control_plane' }), NOW)).toBe(false);
    expect(isReadOnlyNode(status({ role: 'standalone' }), NOW)).toBe(false);
  });

  it('an unknown role does not blank the UI', () => {
    // The server is the enforcement. Hiding every control during a
    // slow status read would be worse than briefly showing one the
    // server will refuse.
    expect(isReadOnlyNode(null, NOW)).toBe(false);
  });
});

describe('isClustered', () => {
  it('is false on a standalone install and while unknown', () => {
    expect(isClustered(status({ role: 'standalone' }))).toBe(false);
    expect(isClustered(null)).toBe(false);
  });

  it('is true on both sides of a fleet', () => {
    expect(isClustered(status({ role: 'control_plane' }))).toBe(true);
    expect(isClustered(status({ role: 'follower' }))).toBe(true);
  });
});

describe('fleet badge', () => {
  it('is absent on a standalone install, which hides the whole cluster UI', () => {
    expect(fleetBadge(status({ role: 'standalone' }), NOW)).toBeNull();
    expect(fleetBadge(null, NOW)).toBeNull();
  });

  it('counts connected against expected and stays calm when they match', () => {
    const s = status({ fleet: [node(), node({ node_id: 'node-b', name: 'edge-02' })] });
    expect(fleetBadge(s, NOW)).toEqual({
      tone: 'ok',
      label: 'Control plane 2/2',
      reason: null,
    });
  });

  it('excludes revoked nodes from both sides of the count', () => {
    // A revoked node is not expected to connect, so counting it would
    // leave the badge permanently warning after a deliberate removal.
    const s = status({
      fleet: [node(), node({ node_id: 'node-b', status: 'revoked', connected: false })],
    });
    expect(fleetBadge(s, NOW)?.label).toBe('Control plane 1/1');
    expect(fleetBadge(s, NOW)?.tone).toBe('ok');
  });

  it('warns and says how many nodes are missing', () => {
    const s = status({
      fleet: [node(), node({ node_id: 'node-b', connected: false })],
    });
    const badge = fleetBadge(s, NOW);
    expect(badge?.tone).toBe('warning');
    expect(badge?.reason).toBe('1 node not connected');
  });

  it('warns on a stale heartbeat even when every node is connected', () => {
    const s = status({
      fleet: [node({ last_seen_at: '2026-09-09T11:58:00Z' })],
    });
    const badge = fleetBadge(s, NOW);
    expect(badge?.tone).toBe('warning');
    expect(badge?.reason).toContain('last seen');
  });

  it('warns while break-glass is open on the control plane', () => {
    const s = status({
      fleet: [node()],
      break_glass_until: '2026-09-09T12:30:00Z',
    });
    expect(fleetBadge(s, NOW)?.reason).toBe('A break-glass window is open');
  });

  it('reports a follower as a follower, warning only under break-glass', () => {
    expect(fleetBadge(status({ role: 'follower' }), NOW)).toEqual({
      tone: 'ok',
      label: 'Follower',
      reason: null,
    });
    const glass = status({ role: 'follower', break_glass_until: '2026-09-09T12:30:00Z' });
    expect(fleetBadge(glass, NOW)?.tone).toBe('warning');
  });
});

describe('join command', () => {
  it('never contains the token', () => {
    // argv is readable through /proc, lands in shell history and is
    // logged verbatim by CI and config-management command modules.
    const cmd = joinCommand('cp.example.com:9444');
    expect(cmd).toContain('--token-stdin');
    expect(cmd).not.toContain('--token ');
    expect(cmd).toBe('lorica cluster join --control-plane cp.example.com:9444 --token-stdin');
  });
});

describe('secondsUntil', () => {
  it('counts down and floors at zero', () => {
    expect(secondsUntil('2026-09-09T12:01:00Z', NOW)).toBe(60);
    expect(secondsUntil('2026-09-09T11:59:00Z', NOW)).toBe(0);
  });

  it('treats an unparseable expiry as already expired', () => {
    expect(secondsUntil('nonsense', NOW)).toBe(0);
  });
});
