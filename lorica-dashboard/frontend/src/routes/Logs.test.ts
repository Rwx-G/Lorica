import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { api } from '../lib/api';
import { auth } from '../lib/auth';
import { clusterStatus, type ClusterStatus } from '../lib/cluster';
import { hash } from '../lib/router';
import { streamLogsHref } from '../lib/stream-links';
import Logs from './Logs.svelte';

const POLL_MS = 5000;

/**
 * A WebSocket whose close event is delivered on a later task, as a
 * browser delivers it: the page's own `close()` call returns first.
 */
class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  closed = false;

  constructor(public url: string) {
    FakeWebSocket.instances.push(this);
  }

  open() {
    this.onopen?.();
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    setTimeout(() => this.onclose?.(), 0);
  }
}

function controlPlane(): ClusterStatus {
  return {
    role: 'control_plane',
    build_version: '1.10.8',
    node_id: 'node-a',
    node_name: 'edge-01',
    control_plane: null,
    connection_state: null,
    applied_config_generation: 1,
    applied_config_hash: 'abc',
    break_glass_until: null,
    fleet: [],
  };
}

let getLogs: ReturnType<typeof vi.spyOn>;
let getFleetLogs: ReturnType<typeof vi.spyOn>;
let getStreamLogs: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  vi.restoreAllMocks();
  FakeWebSocket.instances = [];
  vi.stubGlobal('WebSocket', FakeWebSocket);
  localStorage.removeItem('lorica-logs-autorefresh');
  getLogs = vi.spyOn(api, 'getLogs').mockResolvedValue({ data: { entries: [], total: 0 } } as never);
  getFleetLogs = vi.spyOn(api, 'getFleetLogs').mockResolvedValue({ data: { rows: [] } } as never);
  getStreamLogs = vi.spyOn(api, 'getStreamLogs').mockResolvedValue({ data: { entries: [], total: 0 } } as never);
  vi.spyOn(api, 'getStreamStatus').mockResolvedValue({ data: { streams: [] } } as never);
  vi.spyOn(api, 'listClusterNodes').mockResolvedValue({ data: [] });
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  hash.set('/');
  localStorage.clear();
  clusterStatus.set(null);
  auth.set({ status: 'unauthenticated' });
});

describe('Logs page, HTTP / Streams switch (Story 12.9)', () => {
  beforeEach(() => {
    // No live tail here: these cases are about which table is shown.
    localStorage.setItem('lorica-logs-autorefresh', 'false');
    auth.set({ status: 'authenticated', username: 'user01', role: 'viewer' });
  });

  it('opens on the HTTP table and switches to the stream table', async () => {
    hash.set('/logs');
    render(Logs);
    expect(screen.getByRole('button', { name: 'HTTP' })).toHaveAttribute('aria-pressed', 'true');
    await waitFor(() => expect(api.getLogs).toHaveBeenCalled());
    expect(api.getStreamLogs).not.toHaveBeenCalled();

    await fireEvent.click(screen.getByRole('button', { name: 'Streams' }));
    expect(screen.getByRole('button', { name: 'Streams' })).toHaveAttribute('aria-pressed', 'true');
    await waitFor(() => expect(api.getStreamLogs).toHaveBeenCalled());
    expect(screen.getByLabelText('End reason')).toBeInTheDocument();
  });

  it('opens on the stream table filtered on the stream a Streams page link names', async () => {
    hash.set(streamLogsHref('pg-id').slice(1));
    render(Logs);
    expect(screen.getByRole('button', { name: 'Streams' })).toHaveAttribute('aria-pressed', 'true');
    await waitFor(() => expect(api.getStreamLogs).toHaveBeenCalled());
    expect(vi.mocked(api.getStreamLogs).mock.calls[0][0]).toMatchObject({ stream_id: 'pg-id' });
  });
});

describe('Logs page live tail', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    auth.set({ status: 'authenticated', username: 'admin', role: 'super_admin' });
  });

  it('stops polling once the page is left, after the socket close event lands', async () => {
    const { unmount } = render(Logs);
    expect(FakeWebSocket.instances).toHaveLength(1);

    unmount();
    const callsAtUnmount = getLogs.mock.calls.length;
    await vi.advanceTimersByTimeAsync(POLL_MS * 6);

    expect(FakeWebSocket.instances[0].closed).toBe(true);
    expect(getLogs.mock.calls.length).toBe(callsAtUnmount);
  });

  it('polls until the socket opens, then stops, and polls again when it drops', async () => {
    render(Logs);
    const socket = FakeWebSocket.instances[0];
    const afterMount = getLogs.mock.calls.length;

    socket.open();
    await vi.advanceTimersByTimeAsync(POLL_MS * 2);
    expect(getLogs.mock.calls.length).toBe(afterMount);

    socket.close();
    await vi.advanceTimersByTimeAsync(POLL_MS);
    expect(getLogs.mock.calls.length).toBe(afterMount + 1);
  });

  it('opens no socket and polls the fan-in store on the fleet view', async () => {
    clusterStatus.set(controlPlane());
    render(Logs);
    await vi.advanceTimersByTimeAsync(POLL_MS);

    expect(FakeWebSocket.instances).toHaveLength(0);
    expect(getFleetLogs).toHaveBeenCalledTimes(2);
  });

  it('closes the socket when the cluster status turns the page into the fleet view', async () => {
    render(Logs);
    const socket = FakeWebSocket.instances[0];

    clusterStatus.set(controlPlane());
    await vi.advanceTimersByTimeAsync(0);

    expect(socket.closed).toBe(true);
    expect(FakeWebSocket.instances).toHaveLength(1);
  });

  it('neither polls nor opens a socket with auto-refresh off', async () => {
    localStorage.setItem('lorica-logs-autorefresh', 'false');
    render(Logs);
    await vi.advanceTimersByTimeAsync(POLL_MS * 3);

    expect(FakeWebSocket.instances).toHaveLength(0);
    expect(getLogs).toHaveBeenCalledTimes(1);
  });

  it('closes the socket and stops the HTTP polling when the Streams view is picked', async () => {
    render(Logs);
    const socket = FakeWebSocket.instances[0];
    const afterMount = getLogs.mock.calls.length;
    await vi.advanceTimersByTimeAsync(POLL_MS);
    expect(getLogs.mock.calls.length).toBe(afterMount + 1);

    await fireEvent.click(screen.getByRole('button', { name: 'Streams' }));
    const callsAtSwitch = getLogs.mock.calls.length;
    await vi.advanceTimersByTimeAsync(POLL_MS * 3);

    expect(socket.closed).toBe(true);
    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(getLogs.mock.calls.length).toBe(callsAtSwitch);
    expect(getStreamLogs.mock.calls.length).toBeGreaterThan(1);
  });

  it('stops the stream table polling once the page is left', async () => {
    hash.set(streamLogsHref('pg-id').slice(1));
    const { unmount } = render(Logs);
    await vi.advanceTimersByTimeAsync(POLL_MS);
    expect(getStreamLogs.mock.calls.length).toBeGreaterThan(1);

    unmount();
    const callsAtUnmount = getStreamLogs.mock.calls.length;
    await vi.advanceTimersByTimeAsync(POLL_MS * 3);

    expect(getStreamLogs.mock.calls.length).toBe(callsAtUnmount);
    expect(FakeWebSocket.instances).toHaveLength(0);
  });
});
