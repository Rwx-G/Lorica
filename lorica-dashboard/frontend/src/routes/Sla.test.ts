import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { api, type SlaSummary } from '../lib/api';
import { auth } from '../lib/auth';
import { clusterStatus, type ClusterNodeResponse, type ClusterStatus } from '../lib/cluster';
import Sla from './Sla.svelte';

const ROUTE_ID = 'route-1';

function controlPlane(): ClusterStatus {
  return {
    role: 'control_plane',
    build_version: '1.10.9',
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

function follower(id: string, name: string): ClusterNodeResponse {
  return {
    node_id: id,
    name,
    status: 'active',
    version: '1.10.9',
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

function summary(window: string): SlaSummary {
  return {
    route_id: ROUTE_ID,
    window,
    total_requests: 1000,
    successful_requests: 999,
    sla_pct: 99.9,
    avg_latency_ms: 12,
    p50_latency_ms: 10,
    p95_latency_ms: 30,
    p99_latency_ms: 50,
    target_pct: 99.9,
    meets_target: true,
  };
}

/** Every route-detail action that acts on this node's store. */
const THIS_NODE_ACTIONS = ['Configure', 'Export CSV', 'Export JSON', 'Clear SLA'];

beforeEach(() => {
  vi.restoreAllMocks();
  auth.set({ status: 'authenticated', username: 'admin', role: 'super_admin' });
  clusterStatus.set(controlPlane());
  vi.spyOn(api, 'listClusterNodes').mockResolvedValue({ data: [follower('node-b', 'edge-b')] });
  vi.spyOn(api, 'listRoutes').mockResolvedValue({ data: { routes: [] } });
  vi.spyOn(api, 'getSlaOverview').mockResolvedValue({ data: [summary('24h')] });
  vi.spyOn(api, 'getRouteSla').mockResolvedValue({ data: [summary('24h')] });
  vi.spyOn(api, 'getRouteSlaActive').mockResolvedValue({ data: [] });
  vi.spyOn(api, 'getRouteSlaBuckets').mockResolvedValue({ data: [] });
  vi.spyOn(api, 'getSlaConfig').mockResolvedValue({
    data: {
      route_id: ROUTE_ID,
      target_pct: 99.9,
      max_latency_ms: 500,
      success_status_min: 200,
      success_status_max: 399,
      created_at: '2026-11-18T10:00:00Z',
      updated_at: '2026-11-18T10:00:00Z',
    },
  });
});

afterEach(() => {
  clusterStatus.set(null);
  auth.set({ status: 'unauthenticated' });
});

describe('Sla page', () => {
  it("offers no action on this node's store while a follower is picked", async () => {
    render(Sla);
    const card = (await screen.findByText(ROUTE_ID)).closest('button') as HTMLElement;
    await fireEvent.click(card);
    for (const name of THIS_NODE_ACTIONS) {
      expect(await screen.findByRole('button', { name })).toBeInTheDocument();
    }

    await screen.findByRole('option', { name: 'edge-b' });
    await fireEvent.change(screen.getByRole('combobox', { name: 'Filter by node' }), {
      target: { value: 'node-b' },
    });
    await waitFor(() => expect(api.getRouteSla).toHaveBeenCalledWith(ROUTE_ID, 'node-b'));
    await screen.findByText('Passive SLA (Real Traffic)');
    for (const name of THIS_NODE_ACTIONS) {
      expect(screen.queryByRole('button', { name })).toBeNull();
    }
  });

  it("keeps this node's figures when the previous node's answer lands last", async () => {
    // A node switch re-reads the overview while an earlier read may
    // still be in flight; the late one must not overwrite the new
    // node's figures.
    let releaseFirst: (value: { data: SlaSummary[] }) => void = () => {};
    vi.mocked(api.getSlaOverview)
      .mockImplementationOnce(() => new Promise((resolve) => (releaseFirst = resolve)))
      .mockResolvedValue({ data: [{ ...summary('24h'), sla_pct: 42 }] });
    render(Sla);

    await screen.findByRole('option', { name: 'edge-b' });
    await fireEvent.change(screen.getByRole('combobox', { name: 'Filter by node' }), {
      target: { value: 'node-b' },
    });
    await screen.findByText('42.00%');

    releaseFirst({ data: [{ ...summary('24h'), sla_pct: 11 }] });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(screen.getByText('42.00%')).toBeInTheDocument();
    expect(screen.queryByText('11.00%')).toBeNull();
  });
});
