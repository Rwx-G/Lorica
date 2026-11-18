import { render, screen, waitFor, within } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { auth } from '../lib/auth';
import { api, type StreamPortsEntry } from '../lib/api';
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
    // The server's verdict, flattened onto the row like the registry
    // fields above it. A fixture that omits it is a shape the API
    // never sends.
    drifted: false,
    applied_generation: 4,
    applied_hash: 'abc',
    from_live_session: true,
    selected_for_hostnames: [],
    certificate_ids: certificateIds,
    resources: null,
    stream_plane: null,
    stream_ports: [],
  };
}

function streamPort(id: string, name: string, portFirst: number, listenAddress = '0.0.0.0'): StreamPortsEntry {
  return { id, name, protocol: 'tcp', listen_address: listenAddress, port_first: portFirst, port_last: portFirst };
}

/** Open `name`'s drawer once the roster has loaded. */
async function openDrawer(name: string) {
  render(Cluster);
  await waitFor(() => expect(screen.getByText(name)).toBeInTheDocument());
  (screen.getAllByText(name)[0] as HTMLElement).click();
  await waitFor(() => expect(screen.getByLabelText('Node detail')).toBeInTheDocument());
  return screen.getByLabelText('Node detail');
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
    san_ips: [],
    fingerprint: 'ab',
    issuer: 'Test CA',
    subject: `CN=${domain}`,
    not_before: '2026-01-01T00:00:00Z',
    not_after: '2027-01-01T00:00:00Z',
    is_acme: false,
    acme_auto_renew: false,
    created_at: '2026-01-01T00:00:00Z',
    source: 'manual' as const,
    adcs_authority_id: null,
    adcs_template: null,
    adcs_template_oid: null,
    adcs_request_id: null,
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

describe('Cluster page, stream bindings', () => {
  beforeEach(() => {
    clusterStatus.set(status('control_plane'));
    vi.spyOn(api, 'getFleetWafEvents').mockResolvedValue({ data: { rows: [], next_cursor: null } });
  });

  it('shows a failed binding with its kind and OS error, and the rest as bound', async () => {
    vi.spyOn(api, 'listClusterNodes').mockResolvedValue({
      data: [
        {
          ...node('id-a', 'edge-a'),
          stream_ports: [streamPort('s-pg', 'pg', 5432), streamPort('s-smtp', 'smtp', 6000)],
          stream_plane: {
            bound_count: 1,
            listen_sockets_used: 1,
            bindings: [
              {
                stream_id: 's-smtp',
                stream_name: 'smtp',
                state: 'failed',
                kind: 'address_in_use',
                os_error: 'Address already in use (os error 98)',
                port: 6000,
                since: '2026-11-14T10:00:00Z',
              },
            ],
            truncated: false,
            fd_limit: 65536,
            worker_count: 4,
          },
        },
      ],
    });

    const drawer = await openDrawer('edge-a');
    const pgRow = within(drawer).getByText('pg').closest('tr') as HTMLElement;
    expect(within(pgRow).getByText('bound')).toHaveClass('badge', 'badge-green');
    const smtpRow = within(drawer).getByText('smtp').closest('tr') as HTMLElement;
    expect(within(smtpRow).getByText('failed')).toHaveClass('badge', 'badge-red');
    expect(within(drawer).getByText('address_in_use')).toBeInTheDocument();
    expect(within(drawer).getByText('Address already in use (os error 98)')).toBeInTheDocument();
    expect(within(drawer).getByText(/fd limit 65536, 4 workers/)).toBeInTheDocument();

    // The fleet table counts it too, so a failure shows without opening a drawer.
    const tableRow = screen.getAllByText('edge-a')[0].closest('tr') as HTMLElement;
    expect(within(tableRow).getByText('1 failed')).toHaveClass('badge', 'badge-red');
  });

  it('reads the unknown the server sends under drift as unknown', async () => {
    vi.spyOn(api, 'listClusterNodes').mockResolvedValue({
      data: [
        {
          ...node('id-a', 'edge-a'),
          drifted: true,
          stream_ports: [streamPort('s-pg', 'pg', 5432)],
          stream_plane: {
            bound_count: 0,
            listen_sockets_used: 0,
            bindings: [{ stream_id: 's-pg', stream_name: 'pg', state: 'unknown' }],
            truncated: false,
          },
        },
      ],
    });

    const drawer = await openDrawer('edge-a');
    const row = within(drawer).getByText('pg').closest('tr') as HTMLElement;
    expect(within(row).getByText('unknown')).toHaveClass('badge', 'badge-gray');
    expect(within(drawer).getByText(/cannot be vouched for/)).toBeInTheDocument();
    // A Viewer's view carries no fd figures; the summary does not invent them.
    expect(within(drawer).queryByText(/fd limit/)).toBeNull();
  });

  it('claims no state for a node that has not reported yet', async () => {
    vi.spyOn(api, 'listClusterNodes').mockResolvedValue({
      data: [{ ...node('id-a', 'edge-a'), stream_ports: [streamPort('s-pg', 'pg', 5432)] }],
    });

    const drawer = await openDrawer('edge-a');
    expect(within(drawer).getByText('This node has not reported its stream bindings yet.')).toBeInTheDocument();
    const row = within(drawer).getByText('pg').closest('tr') as HTMLElement;
    expect(within(row).queryByText('bound')).toBeNull();
  });

  it('lists the stream ports a pending node will open, fleet-wide ones included', async () => {
    vi.spyOn(api, 'listClusterNodes').mockResolvedValue({
      data: [
        {
          ...node('id-a', 'edge-a'),
          status: 'pending',
          stream_ports: [
            streamPort('s-pg', 'pg', 5432),
            { ...streamPort('s-dns', 'dns-fleetwide', 53, '::'), protocol: 'udp' },
          ],
        },
      ],
    });

    const drawer = await openDrawer('edge-a');
    const ports = within(drawer).getByRole('list', { name: 'Stream ports' });
    expect(within(ports).getByText(/TCP\s+0\.0\.0\.0:5432/)).toBeInTheDocument();
    expect(within(ports).getByText(/UDP\s+\[::\]:53/)).toBeInTheDocument();
    expect(within(ports).getByText(/dns-fleetwide/)).toBeInTheDocument();
  });

  it('names a binding outside the stream ports, and marks one no longer configured', async () => {
    vi.spyOn(api, 'listClusterNodes').mockResolvedValue({
      data: [
        {
          ...node('id-a', 'edge-a'),
          stream_ports: [streamPort('s-pg', 'pg', 5432)],
          stream_plane: {
            bound_count: 1,
            listen_sockets_used: 1,
            bindings: [
              { stream_id: 's-old', stream_name: 'legacy-smtp', state: 'failed', kind: 'source_ports', os_error: 'no source port left', port: 25 },
              { stream_id: '5f0c0000-0000-4000-8000-000000000000', stream_name: null, state: 'pending' },
            ],
            truncated: false,
          },
        },
      ],
    });

    const drawer = await openDrawer('edge-a');
    const named = within(drawer).getByText('legacy-smtp').closest('tr') as HTMLElement;
    expect(within(named).getByText('failed')).toHaveClass('badge-red');
    expect(within(named).queryByText('not in this configuration')).toBeNull();
    expect(within(drawer).getByText('source_ports')).toBeInTheDocument();
    const gone = within(drawer).getByText(/5f0c0000-0000-4000-8000-000000000000/).closest('tr') as HTMLElement;
    expect(within(gone).getByText('not in this configuration')).toBeInTheDocument();
  });

  it('says a pending node no stream targets opens no stream port', async () => {
    vi.spyOn(api, 'listClusterNodes').mockResolvedValue({
      data: [{ ...node('id-a', 'edge-a'), status: 'pending' }],
    });

    const drawer = await openDrawer('edge-a');
    expect(within(drawer).getByText(/opens no stream port/)).toBeInTheDocument();
  });
});

describe('Cluster page, revocation', () => {
  it('keeps the certificates a revoked node walks off with on screen', async () => {
    // Revocation cuts access, not possession: the node keeps the
    // private keys it held. A toast scrolls away; the list stays
    // until the operator dismisses it.
    clusterStatus.set(status('control_plane'));
    vi.spyOn(api, 'listClusterNodes').mockResolvedValue({
      data: [node('id-a', 'edge-a', ['cert-1'])],
    });
    vi.spyOn(api, 'getFleetWafEvents').mockResolvedValue({
      data: { rows: [], next_cursor: null },
    });
    vi.mocked(api.listCertificates).mockResolvedValue({
      data: { certificates: [certificate('cert-1', 'fleet.example.com')] },
    });
    vi.spyOn(api, 'revokeClusterNode').mockResolvedValue({
      data: {
        node_id: 'id-a',
        name: 'edge-a',
        newly_revoked: true,
        session_ended: true,
        certificates_to_reissue: ['cert-1'],
      },
    });

    render(Cluster);
    await waitFor(() => expect(screen.getByText('edge-a')).toBeInTheDocument());
    (screen.getAllByText('edge-a')[0] as HTMLElement).click();
    await waitFor(() => expect(screen.getByText('Revoke node')).toBeInTheDocument());
    (screen.getByText('Revoke node') as HTMLElement).click();
    await waitFor(() => expect(screen.getByText('Revoke')).toBeInTheDocument());
    (screen.getByText('Revoke') as HTMLElement).click();

    await waitFor(() =>
      expect(screen.getByText(/keeps the private key of 1 certificate/)).toBeInTheDocument(),
    );
    expect(screen.getByText('cert-1')).toBeInTheDocument();
    expect(screen.getByText(/fleet\.example\.com/)).toBeInTheDocument();
  });
});

/**
 * A variant class (`btn-primary`, `btn-cancel`, ...) only sets colours;
 * padding, radius and font come from the `btn` base class in `app.css`.
 * This page shipped with bare variants, which rendered as unstyled
 * browser buttons.
 */
function expectVariantButtonsHaveBase() {
  const variants = Array.from(document.querySelectorAll('button')).filter((b) =>
    /\bbtn-(primary|secondary|danger|cancel)\b/.test(b.className),
  );
  expect(variants.length).toBeGreaterThan(0);
  for (const button of variants) expect(button).toHaveClass('btn');
}

describe('Cluster page, button styles', () => {
  it('gives the page, drawer and add-node dialog buttons the shared base class', async () => {
    clusterStatus.set(status('control_plane'));
    vi.spyOn(api, 'listClusterNodes').mockResolvedValue({ data: [node('id-a', 'edge-a')] });
    vi.spyOn(api, 'getFleetWafEvents').mockResolvedValue({
      data: { rows: [], next_cursor: null },
    });

    render(Cluster);
    await waitFor(() => expect(screen.getByText('edge-a')).toBeInTheDocument());
    (screen.getAllByText('edge-a')[0] as HTMLElement).click();
    await waitFor(() => expect(screen.getByText('Revoke node')).toBeInTheDocument());
    screen.getByRole('button', { name: 'Add node' }).click();
    await waitFor(() => expect(screen.getByText('Mint token')).toBeInTheDocument());

    expect(screen.getByRole('button', { name: 'Cancel' })).toHaveClass('btn', 'btn-cancel');
    expect(screen.getByRole('button', { name: 'Mint token' })).toHaveClass('btn', 'btn-primary');
    expectVariantButtonsHaveBase();
  });

  it('gives the follower controls the shared base class', async () => {
    clusterStatus.set(status('follower'));
    vi.spyOn(api, 'listClusterNodes').mockResolvedValue({ data: [] });

    render(Cluster);
    await waitFor(() => expect(screen.getByText('Open break-glass')).toBeInTheDocument());

    expect(screen.getByRole('button', { name: 'Leave the fleet' })).toHaveClass('btn', 'btn-danger');
    expectVariantButtonsHaveBase();
  });

  it('renders the node status and connection as the shared badges', async () => {
    clusterStatus.set(status('control_plane'));
    vi.spyOn(api, 'listClusterNodes').mockResolvedValue({
      data: [{ ...node('id-a', 'edge-a'), status: 'pending', connected: false }],
    });

    render(Cluster);
    await waitFor(() => expect(screen.getByText('edge-a')).toBeInTheDocument());

    expect(screen.getByText('pending')).toHaveClass('badge', 'badge-orange');
    expect(screen.getByText('offline')).toHaveClass('badge', 'badge-gray');
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
