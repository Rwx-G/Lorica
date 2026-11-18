import { render, screen, waitFor } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { api, type SystemResponse } from '../lib/api';
import { auth, type Role } from '../lib/auth';
import System from './System.svelte';

const SYSTEM: SystemResponse = {
  host: {
    cpu_usage_percent: 12,
    cpu_count: 4,
    memory_total_bytes: 8_000_000_000,
    memory_used_bytes: 2_000_000_000,
    memory_usage_percent: 25,
    disk_root: null,
    disk_data: null,
  },
  process: { memory_bytes: 100_000_000, cpu_usage_percent: 1 },
  proxy: {
    version: '1.11.0',
    uptime_seconds: 60,
    active_connections: 0,
    http_port: 8080,
    https_port: 8443,
    pid: 1234,
  },
};

function signIn(role: Role) {
  auth.set({ status: 'authenticated', username: 'user01', role });
}

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(api, 'getSystem').mockResolvedValue({ data: SYSTEM });
  vi.spyOn(api, 'getWorkers').mockResolvedValue({ data: { workers: [], total: 0 } });
  vi.spyOn(api, 'getStreamBudget').mockResolvedValue({
    data: {
      nodes: [
        {
          node_id: null,
          node_name: null,
          reported_at: '2026-11-14T10:00:00Z',
          fd_limit: 65536,
          base_reserve: 1024,
          http_reserve: 32768,
          stream_budget: 31744,
          worker_count: 2,
          listen_socket_cap: 2048,
          listen_sockets_used: 0,
          worker_fds_committed: 0,
          supervisor_fds_committed: 0,
          worker_drain_timeout_s: 30,
          usable_source_ports: 27208,
          session_ceiling: 27208,
          session_ceiling_bound_by: 'source_ports',
          udp_sessions_committed: 0,
          over_ceiling: false,
          source_pools: [],
          streams: [],
        },
      ],
    },
  });
});

afterEach(() => {
  auth.set({ status: 'unauthenticated' });
});

describe('System page, stream fd budget', () => {
  it.each<Role>(['operator', 'super_admin'])('shows the budget panel to %s', async (role) => {
    signIn(role);
    render(System);
    await waitFor(() => expect(screen.getByText('Stream fd budget')).toBeInTheDocument());
    expect(api.getStreamBudget).toHaveBeenCalled();
    expect(screen.getByText('65,536')).toBeInTheDocument();
  });

  it('neither shows nor asks for it as a Viewer, whom the server refuses node capacity', async () => {
    // Asking anyway would raise the role toast on every five-second refresh.
    signIn('viewer');
    render(System);
    await waitFor(() => expect(screen.getByText('Lorica Process')).toBeInTheDocument());
    expect(screen.queryByText('Stream fd budget')).toBeNull();
    expect(api.getStreamBudget).not.toHaveBeenCalled();
  });

  it('says a failed read failed rather than showing an empty budget', async () => {
    signIn('operator');
    vi.mocked(api.getStreamBudget).mockResolvedValue({
      error: { code: 'internal', message: 'the store is not open' },
    });
    render(System);
    await waitFor(() =>
      expect(screen.getByText(/Could not read the stream fd budget: the store is not open/)).toBeInTheDocument(),
    );
  });
});
