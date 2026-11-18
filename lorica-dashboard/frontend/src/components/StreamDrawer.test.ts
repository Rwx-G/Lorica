import { render, screen, fireEvent, waitFor, within } from '@testing-library/svelte';
import { get } from 'svelte/store';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { api, type BackendResponse } from '../lib/api';
import { auth, type Role } from '../lib/auth';
import { toasts } from '../lib/toast';
import iv1Create from '../lib/stream-iv1-create.json';
import { status, stream, udpSettings } from '../test-stream-fixtures';
import StreamDrawer from './StreamDrawer.svelte';

const BACKEND: BackendResponse = {
  id: '<BACKEND_ID>',
  address: '10.0.0.10:5432',
  name: 'pg-01',
  group_name: '',
  weight: 100,
  health_status: 'healthy',
  lifecycle_state: 'active',
  active_connections: 0,
  health_check_enabled: false,
  health_check_interval_s: 10,
  health_check: { kind: 'tcp_connect' },
  health_check_path: null,
  tls_upstream: false,
  tls_skip_verify: false,
  tls_sni: null,
  h2_upstream: false,
  ewma_score_us: 0,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

function signIn(role: Role) {
  auth.set({ status: 'authenticated', username: 'user01', role });
}

function props(overrides: Record<string, unknown> = {}) {
  return {
    open: true,
    editing: null,
    status: null,
    backends: [BACKEND],
    certificates: [],
    onsave: vi.fn(),
    onclose: vi.fn(),
    ...overrides,
  };
}

function tab(name: string): HTMLElement {
  return screen.getByRole('tab', { name });
}

beforeEach(() => {
  vi.restoreAllMocks();
  signIn('operator');
});

afterEach(() => {
  auth.set({ status: 'unauthenticated' });
});

describe('StreamDrawer (Story 12.10 Lot D2)', () => {
  it('creates a stream from a name, a port and one backend with exactly the IV1 request', async () => {
    const create = vi.spyOn(api, 'createStream').mockResolvedValue({ data: { ...stream(), name: 'iv1-tcp' } });
    render(StreamDrawer, { props: props() });
    await fireEvent.input(screen.getByLabelText('Name'), { target: { value: iv1Create.name } });
    await fireEvent.input(screen.getByLabelText('Port (first)'), { target: { value: String(iv1Create.port_first) } });
    await fireEvent.click(tab('Backends'));
    const primaries = screen.getAllByRole('checkbox')[0];
    await fireEvent.click(primaries);
    await fireEvent.click(screen.getByRole('button', { name: 'Create' }));
    expect(create).toHaveBeenCalledWith(iv1Create);
  });

  it('shows the tabs of a TCP stream and of a UDP one', async () => {
    const { unmount } = render(StreamDrawer, { props: props({ editing: stream() }) });
    expect(screen.queryByRole('tab', { name: 'UDP' })).toBeNull();
    expect(tab('TLS')).toBeInTheDocument();
    unmount();
    render(StreamDrawer, { props: props({ editing: stream({ protocol: 'udp', udp: udpSettings() }) }) });
    expect(screen.queryByRole('tab', { name: 'TLS' })).toBeNull();
    expect(tab('UDP')).toBeInTheDocument();
  });

  it('labels every cap per node on the tabs that hold them', async () => {
    render(StreamDrawer, { props: props({ editing: stream({ backend_ids: ['<BACKEND_ID>'] }) }) });
    await fireEvent.click(tab('Connection'));
    expect(screen.getByLabelText('Max connections (per node)')).toBeInTheDocument();
    await fireEvent.click(tab('Protection'));
    for (const label of [
      'Max connections per source (per node)',
      'Max pending connections (per node)',
      'Openings per second per source (per node)',
      'Openings per second (per node)',
    ]) {
      expect(screen.getByLabelText(label)).toBeInTheDocument();
    }
    await fireEvent.click(tab('Backends'));
    expect(screen.getByLabelText(/^Max active to .* \(per node\)$/)).toBeInTheDocument();
  });

  it('shows a refusal on the tab holding the field it names', async () => {
    vi.spyOn(api, 'updateStream').mockResolvedValue({
      error: { code: 'unprocessable', message: 'udp.max_sessions must be between 1 and 1048576', status: 422 },
    });
    render(StreamDrawer, { props: props({ editing: stream({ protocol: 'udp', udp: udpSettings() }) }) });
    await fireEvent.click(screen.getByRole('button', { name: 'Update' }));
    await waitFor(() => expect(tab('UDP')).toHaveAttribute('aria-selected', 'true'));
    expect(screen.getByRole('alert')).toHaveTextContent('udp.max_sessions must be between');
    expect(screen.getByLabelText('Max sessions (per node)')).toBeInTheDocument();
  });

  it('suspends the two response bounds while responses are unbounded', async () => {
    render(StreamDrawer, {
      props: props({ editing: stream({ protocol: 'udp', udp: udpSettings({ unbounded_responses: true }) }) }),
    });
    await fireEvent.click(tab('UDP'));
    expect(screen.getByLabelText('Responses per request')).toBeDisabled();
    expect(screen.getByLabelText('Response bytes per request byte')).toBeDisabled();
    expect(screen.getByLabelText('Max sessions (per node)')).toBeEnabled();
  });

  it('states the hole next to each control that opens one', async () => {
    render(StreamDrawer, { props: props({ editing: stream() }) });
    await fireEvent.click(tab('Connection'));
    const accept = screen.getByLabelText('Accept PROXY protocol').closest('.form-group') as HTMLElement;
    expect(accept.textContent).toContain('pose as any client');
    const local = screen.getByLabelText('Allow a local backend').closest('.form-group') as HTMLElement;
    expect(local.textContent).toContain('local address');
  });

  it('shows the stream badges in its header', () => {
    render(StreamDrawer, {
      props: props({
        editing: stream({ allow_local_backend: true }),
        status: status({ bind: { state: 'failed', kind: 'fd_budget' } }),
      }),
    });
    const header = screen.getByLabelText('Stream badges');
    expect(within(header).getByText('local backend')).toBeInTheDocument();
    expect(within(header).getByText('failed bind')).toBeInTheDocument();
  });

  it('shows each warning of a save as a warning toast, apart from the saved one', async () => {
    toasts.set([]);
    const warning = 'port 5432 is not bound on node web01 yet';
    vi.spyOn(api, 'updateStream').mockResolvedValue({ data: { ...stream(), warnings: [warning] } });
    render(StreamDrawer, { props: props({ editing: stream() }) });
    await fireEvent.click(screen.getByRole('button', { name: 'Update' }));
    await waitFor(() => expect(get(toasts)).toHaveLength(2));
    const [warned, saved] = get(toasts);
    expect(warned).toMatchObject({ type: 'warning', message: expect.stringContaining(warning) });
    expect(saved.type).toBe('success');
  });

  it('lets a Viewer read a stream but not save it', () => {
    signIn('viewer');
    render(StreamDrawer, { props: props({ editing: stream() }) });
    expect(screen.queryByRole('button', { name: 'Update' })).toBeNull();
    expect(screen.getByLabelText('Name')).toBeDisabled();
  });
});
