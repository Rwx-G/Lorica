import { render, screen, waitFor } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { api } from '../lib/api';
import { clusterStatus, type ClusterStatus } from '../lib/cluster';
import NodeFilter from './NodeFilter.svelte';

function status(role: ClusterStatus['role']): ClusterStatus {
  return {
    role,
    build_version: '1.7.0',
    node_id: 'node-a',
    node_name: 'edge-01',
    control_plane: role === 'follower' ? 'cp.example.com:9444' : null,
    connection_state: null,
    applied_config_generation: 4,
    applied_config_hash: 'abc',
    break_glass_until: null,
    fleet: [],
  };
}

function node(id: string, name: string, state: 'pending' | 'active' | 'revoked') {
  return {
    node: {
      node_id: id,
      name,
      status: state,
      version: '1.7.0',
      schema_version: 1,
      applied_config_generation: 4,
      applied_config_hash: 'abc',
      last_seen_at: null,
      enrolled_at: '2026-09-09T00:00:00Z',
    },
    connected: true,
    session_peer: null,
    session_last_seen_unix: null,
    selected_for_hostnames: [],
    resources: null,
  };
}

beforeEach(() => {
  vi.restoreAllMocks();
});

afterEach(() => {
  clusterStatus.set(null);
});

describe('NodeFilter', () => {
  it('renders nothing at all on a standalone install', async () => {
    // AC #5 says hidden entirely, not disabled: a select with one
    // option would suggest a cluster that is not there.
    const list = vi.spyOn(api, 'listClusterNodes');
    clusterStatus.set(status('standalone'));
    const { container } = render(NodeFilter, {
      props: { value: '', onchange: () => {} },
    });
    expect(container.querySelector('select')).toBeNull();
    expect(list).not.toHaveBeenCalled();
  });

  it('renders nothing before the cluster status is known', () => {
    // `null` is "not read yet", which is not the same as standalone.
    // Rendering an empty filter here would flash a control that then
    // disappears on a standalone node.
    const { container } = render(NodeFilter, {
      props: { value: '', onchange: () => {} },
    });
    expect(container.querySelector('select')).toBeNull();
  });

  it('lists the fleet, leaving out revoked nodes', async () => {
    vi.spyOn(api, 'listClusterNodes').mockResolvedValue({
      data: [
        node('id-a', 'edge-01', 'active'),
        node('id-b', 'edge-02', 'pending'),
        node('id-c', 'edge-gone', 'revoked'),
      ],
    });
    clusterStatus.set(status('control_plane'));
    render(NodeFilter, { props: { value: '', onchange: () => {} } });

    await waitFor(() => expect(screen.getByText('edge-01')).toBeInTheDocument());
    // A pending node produces rows the moment it connects, so it
    // belongs in the filter; a revoked one never will again.
    expect(screen.getByText('edge-02')).toBeInTheDocument();
    expect(screen.queryByText('edge-gone')).toBeNull();
    expect(screen.getByText('All nodes')).toBeInTheDocument();
  });

  it('keeps the "all nodes" option when the roster read fails', async () => {
    // The filter is an aid, not a gate. A failed roster read must
    // leave the page usable rather than trap it on one node.
    vi.spyOn(api, 'listClusterNodes').mockResolvedValue({
      error: { code: 'internal', message: 'nope' },
    });
    clusterStatus.set(status('control_plane'));
    render(NodeFilter, { props: { value: '', onchange: () => {} } });

    await waitFor(() => expect(screen.getByText('All nodes')).toBeInTheDocument());
  });
});
