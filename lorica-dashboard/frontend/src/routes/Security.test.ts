import { render, screen, waitFor } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { auth } from '../lib/auth';
import { api, type NodeVerifyResult } from '../lib/api';
import { clusterStatus, type ClusterNodeResponse, type ClusterStatus } from '../lib/cluster';
import Security from './Security.svelte';

function controlPlane(): ClusterStatus {
  return {
    role: 'control_plane',
    build_version: '1.9.2',
    node_id: 'cp',
    node_name: 'control',
    control_plane: null,
    connection_state: null,
    applied_config_generation: 4,
    applied_config_hash: 'abc',
    break_glass_until: null,
    fleet: [],
  };
}

function node(id: string, name: string): ClusterNodeResponse {
  return {
    node_id: id,
    name,
    status: 'active',
    version: '1.9.2',
    schema_version: 1,
    applied_config_generation: 4,
    applied_config_hash: 'abc',
    last_seen_at: null,
    enrolled_at: '2026-09-09T00:00:00Z',
    connected: true,
    session_peer: '192.0.2.10:9444',
    session_last_seen_unix: null,
    drifted: false,
    applied_generation: 4,
    applied_hash: 'abc',
    from_live_session: true,
    selected_for_hostnames: [],
    certificate_ids: [],
    resources: null,
  };
}

/** Render the page, open the audit tab and verify, with `chain` as the one follower verdict. */
async function verifyWith(chain: NodeVerifyResult) {
  vi.spyOn(api, 'verifyAudit').mockResolvedValue({
    data: {
      verified: chain.verified && (chain.backup?.verified ?? true),
      nodes: [{ node_id: '', verified: true, total_rows: 3 }, chain],
    },
  });
  render(Security);
  (screen.getByText('Audit log') as HTMLElement).click();
  await waitFor(() => expect(screen.getByText('Verify chain integrity')).toBeInTheDocument());
  (screen.getByText('Verify chain integrity') as HTMLElement).click();
  await waitFor(() =>
    expect(screen.getByText(/edge-a: chain verified, 40 rows/)).toBeInTheDocument(),
  );
}

beforeEach(() => {
  vi.restoreAllMocks();
  auth.set({ status: 'authenticated', username: 'admin', role: 'super_admin' });
  clusterStatus.set(controlPlane());
  vi.spyOn(api, 'getWafStats').mockResolvedValue({
    data: {
      total_events: 0,
      total_24h: 0,
      total_1h: 0,
      rule_count: 0,
      by_category: [],
      by_category_1h: [],
    },
  });
  vi.spyOn(api, 'getWafRules').mockResolvedValue({ data: { rules: [], total: 0, enabled: 0 } });
  vi.spyOn(api, 'getBlocklistStatus').mockResolvedValue({
    data: { enabled: false, ip_count: 0, source: '' },
  });
  vi.spyOn(api, 'listCustomRules').mockResolvedValue({ data: { rules: [], total: 0 } });
  vi.spyOn(api, 'getFleetWafEvents').mockResolvedValue({ data: { rows: [], next_cursor: null } });
  vi.spyOn(api, 'getFleetBans').mockResolvedValue({ data: [] });
  vi.spyOn(api, 'listAudit').mockResolvedValue({ data: { entries: [], total: 0 } });
  vi.spyOn(api, 'listClusterNodes').mockResolvedValue({ data: [node('id-a', 'edge-a')] });
});

afterEach(() => {
  vi.useRealTimers();
  clusterStatus.set(null);
  auth.set({ status: 'unauthenticated' });
});

/** The figure on the stat card labelled `label`. */
function statValue(label: string): string | null | undefined {
  return screen.getByText(label).closest('.stat-card')?.querySelector('.stat-value')?.textContent;
}

describe('Security page, WAF counters', () => {
  const counters = {
    total_events: 100000,
    total_24h: 4200,
    total_1h: 640,
    rule_count: 40,
    by_category: [{ category: 'xss', count: 100000 }],
    by_category_1h: [{ category: 'xss', count: 640 }],
  };

  it('shows the last hour, the last day and the stored total, labelled apart', async () => {
    vi.spyOn(api, 'getWafStats').mockResolvedValue({ data: counters });
    render(Security);

    await waitFor(() => expect(statValue('Events (1h)')).toBe('640'));
    expect(statValue('Events (24h)')).toBe('4200');
    expect(statValue('Stored events')).toBe('100000');
    expect(screen.getByText('Stored events').closest('.stat-card')).toHaveAttribute(
      'title',
      expect.stringContaining('retention'),
    );
    expect(screen.queryByText('Total Events')).toBeNull();
  });

  it('re-reads the counters so the windows roll without a click', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const stats = vi
      .spyOn(api, 'getWafStats')
      .mockResolvedValueOnce({ data: counters })
      .mockResolvedValue({ data: { ...counters, total_1h: 3 } });
    render(Security);
    await waitFor(() => expect(statValue('Events (1h)')).toBe('640'));

    await vi.advanceTimersByTimeAsync(30000);
    await waitFor(() => expect(statValue('Events (1h)')).toBe('3'));
    expect(stats).toHaveBeenCalledTimes(2);
  });
});

describe('Security page, fan-in backup verdict', () => {
  it('reports a verified backup beside the chain it came from', async () => {
    await verifyWith({
      node_id: 'id-a',
      verified: true,
      total_rows: 40,
      backup: { verified: true, total_rows: 1200 },
    });

    const line = screen.getByText(/fan-in backup verified/);
    expect(line).toHaveTextContent('edge-a: fan-in backup verified, 1200 rows');
    expect(line).toHaveAttribute('role', 'status');
  });

  it('reports a broken backup as an alert of its own, the chain staying green', async () => {
    // A tampered backup is a different finding from a tampered chain:
    // the live chain's verdict must not absorb it, and the backup's
    // must name the row it broke at.
    await verifyWith({
      node_id: 'id-a',
      verified: true,
      total_rows: 40,
      backup: {
        verified: false,
        total_rows: 16,
        first_break_id: 17,
        first_break_reason: 'chain_hash_mismatch',
      },
    });

    const line = screen.getByText(/fan-in backup BROKEN/);
    expect(line).toHaveTextContent('edge-a: fan-in backup BROKEN at row 17: chain_hash_mismatch');
    expect(line).toHaveAttribute('role', 'alert');
    expect(screen.queryByText(/fan-in backup verified/)).toBeNull();
    expect(screen.getByText(/edge-a: chain verified, 40 rows/)).toHaveAttribute('role', 'status');
  });

  it('shows no backup line for a node the cap never moved rows from', async () => {
    await verifyWith({ node_id: 'id-a', verified: true, total_rows: 40 });

    expect(screen.queryByText(/fan-in backup/)).toBeNull();
  });
});
