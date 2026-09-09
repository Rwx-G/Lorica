import { render, screen, waitFor } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { auth } from '../lib/auth';
import { api } from '../lib/api';
import {
  clusterStatus,
  type ClusterNodeResponse,
  type ClusterStatus,
  type FleetWafRow,
} from '../lib/cluster';
import Cluster from './Cluster.svelte';

function status(role: ClusterStatus['role']): ClusterStatus {
  return {
    role,
    build_version: '1.7.0',
    node_id: 'cp',
    node_name: 'control',
    control_plane: role === 'follower' ? 'cp.example.com:9444' : null,
    connection_state: role === 'follower' ? 'connected' : null,
    applied_config_generation: 4,
    applied_config_hash: 'abc',
    break_glass_until: null,
    fleet: [],
  };
}

function node(id: string, name: string, certificateIds: string[] = []): ClusterNodeResponse {
  // FLAT, matching `#[serde(flatten)]` on the server's registry row.
  // The first version of this fixture nested them under `node`, which
  // made every test here pass against a shape the API never sends.
  return {
    node_id: id,
    name,
    status: 'active',
    version: '1.7.0',
    schema_version: 1,
    applied_config_generation: 4,
    applied_config_hash: 'abc',
    last_seen_at: null,
    enrolled_at: '2026-09-09T00:00:00Z',
    connected: true,
    session_peer: '192.0.2.10:9444',
    session_last_seen_unix: null,
    selected_for_hostnames: [],
    certificate_ids: certificateIds,
    resources: null,
  };
}

function wafRow(nodeId: string, clientIp: string): FleetWafRow {
  return {
    id: 1,
    node_id: nodeId,
    rule_id: 942100,
    description: 'SQL injection',
    category: 'sqli',
    severity: 5,
    matched_field: 'ARGS:id',
    matched_value: "1 OR 1=1",
    timestamp: '2026-09-09T10:00:00Z',
    client_ip: clientIp,
    route_hostname: 'shop.example.com',
    action: 'block',
  };
}

function certificate(id: string, domain: string) {
  return {
    id,
    domain,
    san_domains: [],
    fingerprint: 'ab',
    issuer: 'Test CA',
    not_before: '2026-01-01T00:00:00Z',
    not_after: '2027-01-01T00:00:00Z',
    is_acme: false,
    acme_auto_renew: false,
    created_at: '2026-01-01T00:00:00Z',
  };
}

beforeEach(() => {
  vi.restoreAllMocks();
  auth.set({ status: 'authenticated', username: 'admin', role: 'super_admin' });
  vi.spyOn(api, 'getFleetBans').mockResolvedValue({ data: [] });
  vi.spyOn(api, 'listCertificates').mockResolvedValue({ data: { certificates: [] } });
});

afterEach(() => {
  clusterStatus.set(null);
  auth.set({ status: 'unauthenticated' });
});

describe('Cluster page, node drawer', () => {
  it('discards a response for a node the operator has moved off', async () => {
    // The race this pins: open node A, open node B before A answers,
    // A lands last. Without a guard the drawer shows A's WAF events
    // under B's name, which in the incident this drawer exists for is
    // worse than showing nothing at all.
    clusterStatus.set(status('control_plane'));
    vi.spyOn(api, 'listClusterNodes').mockResolvedValue({
      data: [node('id-a', 'edge-a'), node('id-b', 'edge-b')],
    });

    // Held in an object so the assignment inside the mock does not
    // narrow the binding to `never` for the later call.
    const slow: { release?: () => void } = {};
    vi.spyOn(api, 'getFleetWafEvents').mockImplementation((params) => {
      if (params.node === 'id-a') {
        return new Promise((resolve) => {
          slow.release = () =>
            resolve({ data: { rows: [wafRow('id-a', '192.0.2.11')], next_cursor: null } });
        });
      }
      return Promise.resolve({
        data: { rows: [wafRow('id-b', '192.0.2.22')], next_cursor: null },
      });
    });

    render(Cluster);
    await waitFor(() => expect(screen.getByText('edge-a')).toBeInTheDocument());

    (screen.getAllByText('edge-a')[0] as HTMLElement).click();
    // The effect has to run between the two clicks. Svelte batches
    // them otherwise, `drawerLoadedFor` goes straight to B, and A's
    // request is never made: a correct outcome, but not the one this
    // test is about.
    await waitFor(() => expect(slow.release).toBeDefined());

    (screen.getAllByText('edge-b')[0] as HTMLElement).click();
    await waitFor(() => expect(screen.getByText('192.0.2.22')).toBeInTheDocument());

    // A's slow response lands now, on a drawer showing B.
    slow.release?.();
    await Promise.resolve();

    expect(screen.queryByText('192.0.2.11')).toBeNull();
    expect(screen.getByText('192.0.2.22')).toBeInTheDocument();
  });

  it('lists the certificates the control plane says the node receives', async () => {
    // Not derived from `selected_for_hostnames`: that field omits
    // fleet-wide routes, so a node holding every fleet-wide
    // certificate used to be shown as holding none.
    clusterStatus.set(status('control_plane'));
    vi.spyOn(api, 'listClusterNodes').mockResolvedValue({
      data: [node('id-a', 'edge-a', ['cert-fleetwide'])],
    });
    vi.spyOn(api, 'getFleetWafEvents').mockResolvedValue({
      data: { rows: [], next_cursor: null },
    });
    vi.mocked(api.listCertificates).mockResolvedValue({
      data: {
        certificates: [
          certificate('cert-fleetwide', 'shop.example.com'),
          certificate('cert-other', 'unrelated.example.com'),
        ],
      },
    });

    render(Cluster);
    await waitFor(() => expect(screen.getByText('edge-a')).toBeInTheDocument());
    (screen.getAllByText('edge-a')[0] as HTMLElement).click();

    await waitFor(() => expect(screen.getByText('shop.example.com')).toBeInTheDocument());
    expect(screen.queryByText('unrelated.example.com')).toBeNull();
  });

  it('says a failed read failed rather than reporting nothing to report', async () => {
    clusterStatus.set(status('control_plane'));
    vi.spyOn(api, 'listClusterNodes').mockResolvedValue({ data: [node('id-a', 'edge-a')] });
    vi.spyOn(api, 'getFleetWafEvents').mockResolvedValue({
      error: { code: 'internal', message: 'the telemetry database is not open' },
    });

    render(Cluster);
    await waitFor(() => expect(screen.getByText('edge-a')).toBeInTheDocument());
    (screen.getAllByText('edge-a')[0] as HTMLElement).click();

    await waitFor(() =>
      expect(screen.getByText(/the telemetry database is not open/)).toBeInTheDocument(),
    );
  });
});

describe('Cluster page, follower controls', () => {
  it('offers break-glass and leave on a follower', async () => {
    // Story 9.7 AC #7 banners the read-only state; these two are the
    // only ways out of it. Gating them on read-only mode, as the first
    // pass did, left an operator on an unreachable edge with an alarm
    // and no lever.
    clusterStatus.set(status('follower'));
    vi.spyOn(api, 'listClusterNodes').mockResolvedValue({ data: [] });

    render(Cluster);

    await waitFor(() => expect(screen.getByText('Open break-glass')).toBeInTheDocument());
    expect(screen.getByText('Leave the fleet')).toBeInTheDocument();
  });

  it('offers neither on a control plane, which owns the configuration', async () => {
    clusterStatus.set(status('control_plane'));
    vi.spyOn(api, 'listClusterNodes').mockResolvedValue({ data: [] });

    render(Cluster);

    await waitFor(() => expect(screen.getByText('Add node')).toBeInTheDocument());
    expect(screen.queryByText('Open break-glass')).toBeNull();
    expect(screen.queryByText('Leave the fleet')).toBeNull();
  });

  it('hides them from an operator, who cannot open a window either way', async () => {
    auth.set({ status: 'authenticated', username: 'ops', role: 'operator' });
    clusterStatus.set(status('follower'));
    vi.spyOn(api, 'listClusterNodes').mockResolvedValue({ data: [] });

    render(Cluster);

    await waitFor(() =>
      expect(screen.getByText(/configuration is replaced from the control plane/)).toBeInTheDocument(),
    );
    expect(screen.queryByText('Open break-glass')).toBeNull();
  });
});
