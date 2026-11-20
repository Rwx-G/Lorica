import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { auth } from '../lib/auth';
import { api, type NodeVerifyResult, type WafEvent } from '../lib/api';
import {
  ALL_FOLLOWERS,
  clusterStatus,
  type ClusterNodeResponse,
  type ClusterStatus,
  type FleetWafRow,
} from '../lib/cluster';
import Security, { STATS_REFRESH_MS } from './Security.svelte';

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

/** A WAF event whose matched value is `matched`, which the table shows verbatim. */
function wafEvent(matched: string): WafEvent {
  return {
    rule_id: 942100,
    description: 'SQL injection',
    category: 'sql_injection',
    severity: 5,
    matched_field: 'path',
    matched_value: matched,
    timestamp: '2026-11-20T10:00:00Z',
    client_ip: '192.0.2.10',
    route_hostname: 'app.example.com',
    action: 'blocked',
  };
}

function fanInWafRow(id: number, nodeId: string, matched: string): FleetWafRow {
  return { ...wafEvent(matched), id, node_id: nodeId };
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
      stored_in: 'none',
    },
  });
  vi.spyOn(api, 'getWafRules').mockResolvedValue({ data: { rules: [], total: 0, enabled: 0 } });
  vi.spyOn(api, 'getBlocklistStatus').mockResolvedValue({
    data: { enabled: false, ip_count: 0, source: '' },
  });
  vi.spyOn(api, 'listCustomRules').mockResolvedValue({ data: { rules: [], total: 0 } });
  vi.spyOn(api, 'getWafEvents').mockResolvedValue({ data: { events: [], total: 0, rule_count: 0 } });
  vi.spyOn(api, 'listBans').mockResolvedValue({ data: { bans: [], total: 0 } } as never);
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
    stored_in: 'log_store' as const,
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

  it('labels the count as the in-memory events when no log store is open', async () => {
    vi.spyOn(api, 'getWafStats').mockResolvedValue({
      data: { ...counters, total_events: 480, stored_in: 'memory' },
    });
    render(Security);

    await waitFor(() => expect(statValue('Events in memory')).toBe('480'));
    expect(screen.queryByText('Stored events')).toBeNull();
    const card = screen.getByText('Events in memory').closest('.stat-card');
    expect(card).toHaveAttribute('title', expect.stringContaining('No log store'));
    expect(card).not.toHaveAttribute('title', expect.stringContaining('retention'));
  });

  it('re-reads the counters so the windows roll without a click', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const stats = vi
      .spyOn(api, 'getWafStats')
      .mockResolvedValueOnce({ data: counters })
      .mockResolvedValue({ data: { ...counters, total_1h: 3 } });
    render(Security);
    await waitFor(() => expect(statValue('Events (1h)')).toBe('640'));

    await vi.advanceTimersByTimeAsync(STATS_REFRESH_MS);
    await waitFor(() => expect(statValue('Events (1h)')).toBe('3'));
    expect(stats).toHaveBeenCalledTimes(2);
  });
});

describe('Security page, node filter on a control plane', () => {
  function nodeFilter(): HTMLSelectElement {
    return screen.getByLabelText('Filter by node') as HTMLSelectElement;
  }

  it("shows the control plane's own events and bans by default", async () => {
    // Its own events and bans are never fanned in, so opening on the
    // fan-in store hid them.
    render(Security);
    await waitFor(() => expect(api.getWafEvents).toHaveBeenCalled());
    expect(api.listBans).toHaveBeenCalled();
    expect(api.getFleetWafEvents).not.toHaveBeenCalled();
    expect(api.getFleetBans).not.toHaveBeenCalled();
  });

  it('reads the fan-in store for every follower, without a node parameter', async () => {
    render(Security);
    await waitFor(() => expect(nodeFilter()).toBeInTheDocument());

    await fireEvent.change(nodeFilter(), { target: { value: ALL_FOLLOWERS } });
    await waitFor(() => expect(api.getFleetWafEvents).toHaveBeenCalled());
    expect(vi.mocked(api.getFleetWafEvents).mock.calls[0][0]).not.toHaveProperty('node');
  });

  it('reads one follower by id', async () => {
    render(Security);
    await waitFor(() => expect(screen.getByRole('option', { name: 'edge-a' })).toBeInTheDocument());

    await fireEvent.change(nodeFilter(), { target: { value: 'id-a' } });
    await waitFor(() =>
      expect(api.getFleetWafEvents).toHaveBeenCalledWith(expect.objectContaining({ node: 'id-a' })),
    );
  });

  it('labels each fanned-in event with its node, and drops Clear Events for them', async () => {
    vi.mocked(api.getWafEvents).mockResolvedValue({
      data: { events: [wafEvent('/own')], total: 1, rule_count: 0 },
    });
    vi.mocked(api.getFleetWafEvents).mockResolvedValue({
      data: { rows: [fanInWafRow(7, 'node-b', '/from-b')], next_cursor: null },
    });
    render(Security);
    await waitFor(() => expect(screen.getByText('Clear Events')).toBeInTheDocument());

    await fireEvent.change(nodeFilter(), { target: { value: ALL_FOLLOWERS } });
    await waitFor(() => expect(screen.getByText('/from-b')).toBeInTheDocument());
    expect(screen.getByText('/from-b').closest('tr')?.querySelector('td')?.textContent).toBe(
      'node-b',
    );
    expect(screen.queryByText('Clear Events')).toBeNull();
  });

  it('reloads the events when the filter changes on the Bans tab', async () => {
    // Events and bans share the filter. A switch made on Bans used to
    // leave the events table holding the previous store's rows, under
    // the new choice's columns and Clear Events.
    vi.mocked(api.getWafEvents).mockResolvedValue({
      data: { events: [wafEvent('/own')], total: 1, rule_count: 0 },
    });
    vi.mocked(api.getFleetWafEvents).mockResolvedValue({
      data: { rows: [fanInWafRow(7, 'id-a', '/from-a')], next_cursor: null },
    });
    render(Security);
    await waitFor(() => expect(screen.getByText('/own')).toBeInTheDocument());

    (screen.getByText('Bans') as HTMLElement).click();
    // The Bans tab mounts its own filter, which loads the roster again.
    await waitFor(() => expect(screen.getByText('No IPs currently banned.')).toBeInTheDocument());
    await waitFor(() => expect(nodeFilter().querySelector('option[value="id-a"]')).not.toBeNull());
    await fireEvent.change(nodeFilter(), { target: { value: 'id-a' } });
    await waitFor(() => expect(api.getFleetBans).toHaveBeenCalledWith('id-a'));

    (screen.getByText('Events') as HTMLElement).click();
    await waitFor(() => expect(screen.getByText('/from-a')).toBeInTheDocument());
    expect(screen.queryByText('/own')).toBeNull();
    expect(screen.queryByText('Clear Events')).toBeNull();
  });

  it("drops this node's events when they land after a follower was picked", async () => {
    let releaseLocal: (value: unknown) => void = () => {};
    vi.mocked(api.getWafEvents).mockImplementationOnce(
      () => new Promise((resolve) => (releaseLocal = resolve)) as never,
    );
    vi.mocked(api.getFleetWafEvents).mockResolvedValue({
      data: { rows: [fanInWafRow(7, 'id-a', '/from-a')], next_cursor: null },
    });
    render(Security);
    await waitFor(() => expect(screen.getByRole('option', { name: 'edge-a' })).toBeInTheDocument());

    await fireEvent.change(nodeFilter(), { target: { value: 'id-a' } });
    await waitFor(() => expect(screen.getByText('/from-a')).toBeInTheDocument());
    releaseLocal({ data: { events: [wafEvent('/own')], total: 1, rule_count: 0 } });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(screen.queryByText('/own')).toBeNull();
    expect(screen.getByText('/from-a')).toBeInTheDocument();
  });

  it('keeps the audit node selector while the events show this node', async () => {
    // The audit log fans into this node's own store, so its selector
    // does not follow the events filter.
    render(Security);
    (screen.getByText('Audit log') as HTMLElement).click();
    await waitFor(() =>
      expect(screen.getByLabelText('Filter audit by node')).toBeInTheDocument(),
    );
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
