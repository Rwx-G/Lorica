import { fireEvent, render, screen } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { api, type LogEntry } from '../lib/api';
import { auth } from '../lib/auth';
import {
  ALL_FOLLOWERS,
  clusterStatus,
  type ClusterNodeResponse,
  type ClusterStatus,
  type FleetAccessRow,
} from '../lib/cluster';
import Logs from './Logs.svelte';

const POLL_MS = 5000;

function nodeFilter(): HTMLSelectElement {
  return screen.getByLabelText('Filter by node') as HTMLSelectElement;
}

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
    build_version: '1.10.9',
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

function follower(id: string, name: string): ClusterNodeResponse {
  return {
    node_id: id,
    name,
    status: 'active',
    version: '1.10.9',
    schema_version: 1,
    applied_config_generation: 1,
    applied_config_hash: 'abc',
    last_seen_at: null,
    enrolled_at: '2026-09-09T00:00:00Z',
    connected: true,
    session_peer: '192.0.2.10:9444',
    session_last_seen_unix: null,
    drifted: false,
    applied_generation: 1,
    applied_hash: 'abc',
    from_live_session: true,
    selected_for_hostnames: [],
    certificate_ids: [],
    resources: null,
  };
}

function localEntry(id: number, path: string): LogEntry {
  return {
    id,
    timestamp: '2026-11-20T10:00:00Z',
    method: 'GET',
    path,
    host: 'app.example.com',
    status: 200,
    latency_ms: 3,
    backend: '10.0.0.10:8080',
    error: null,
    client_ip: '192.0.2.10',
    is_xff: false,
    xff_proxy_ip: '',
    source: '',
    request_id: `req-${id}`,
  };
}

function fanInRow(id: number, nodeId: string, path: string): FleetAccessRow {
  return {
    id,
    node_id: nodeId,
    timestamp: '2026-11-20T10:00:00Z',
    method: 'GET',
    path,
    host: 'app.example.com',
    status: 200,
    latency_ms: 3,
    backend: '10.0.0.10:8080',
    error: '',
    client_ip: '192.0.2.10',
    request_id: `req-${id}`,
  };
}

/** The text of the first cell of the row showing `path`: the Node cell when there is one. */
function firstCellOf(path: string): string | null | undefined {
  return screen.getByText(path).closest('tr')?.querySelector('td')?.textContent;
}

let getLogs: ReturnType<typeof vi.spyOn>;
let getFleetLogs: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  vi.restoreAllMocks();
  vi.useFakeTimers();
  FakeWebSocket.instances = [];
  vi.stubGlobal('WebSocket', FakeWebSocket);
  localStorage.removeItem('lorica-logs-autorefresh');
  auth.set({ status: 'authenticated', username: 'admin', role: 'super_admin' });
  getLogs = vi.spyOn(api, 'getLogs').mockResolvedValue({ data: { entries: [], total: 0 } } as never);
  getFleetLogs = vi
    .spyOn(api, 'getFleetLogs')
    .mockResolvedValue({ data: { rows: [], next_cursor: null } });
  vi.spyOn(api, 'listClusterNodes').mockResolvedValue({ data: [follower('node-b', 'edge-02')] });
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  clusterStatus.set(null);
  auth.set({ status: 'unauthenticated' });
});

describe('Logs page live tail', () => {
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

  it('neither polls nor opens a socket with auto-refresh off', async () => {
    localStorage.setItem('lorica-logs-autorefresh', 'false');
    render(Logs);
    await vi.advanceTimersByTimeAsync(POLL_MS * 3);

    expect(FakeWebSocket.instances).toHaveLength(0);
    expect(getLogs).toHaveBeenCalledTimes(1);
  });
});

describe('Logs page on a control plane', () => {
  it('shows its own log, live, by default', async () => {
    // The 1.10.8 regression: the control plane opened on the fan-in
    // store, which never holds its own traffic, so its Logs page stayed
    // empty however much it proxied.
    getLogs.mockResolvedValue({ data: { entries: [localEntry(1, '/own')], total: 1 } } as never);
    clusterStatus.set(controlPlane());
    render(Logs);
    await vi.advanceTimersByTimeAsync(POLL_MS);

    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(FakeWebSocket.instances[0].closed).toBe(false);
    expect(getFleetLogs).not.toHaveBeenCalled();
    expect(screen.getByText('/own')).toBeInTheDocument();
    expect(screen.queryByText('Node')).toBeNull();
  });

  it('keeps the live tail when the cluster status arrives after mount', async () => {
    render(Logs);
    const socket = FakeWebSocket.instances[0];

    clusterStatus.set(controlPlane());
    await vi.advanceTimersByTimeAsync(0);

    expect(socket.closed).toBe(false);
    expect(FakeWebSocket.instances).toHaveLength(1);
  });

  it('polls every follower with the socket closed, its actions and local-only filters gone', async () => {
    clusterStatus.set(controlPlane());
    render(Logs);
    const socket = FakeWebSocket.instances[0];
    await vi.advanceTimersByTimeAsync(0);
    // Present first, so their absence below is the switch's doing.
    expect(screen.getByText('Export')).toBeInTheDocument();
    expect(screen.getByText('Clear')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Search logs...')).toBeInTheDocument();

    await fireEvent.change(nodeFilter(), { target: { value: ALL_FOLLOWERS } });
    await vi.advanceTimersByTimeAsync(POLL_MS);

    expect(socket.closed).toBe(true);
    expect(getFleetLogs).toHaveBeenCalledTimes(2);
    expect(getFleetLogs.mock.calls[0][0]).not.toHaveProperty('node');
    // Export and Clear act on this node's own log, not on the rows shown.
    expect(screen.queryByText('Export')).toBeNull();
    expect(screen.queryByText('Clear')).toBeNull();
    // The fan-in read filters on host and time only.
    expect(screen.queryByPlaceholderText('Search logs...')).toBeNull();
    expect(screen.queryByPlaceholderText('Filter by Client IP...')).toBeNull();
    expect(screen.queryByText('All statuses')).toBeNull();
    expect(screen.getByPlaceholderText('Filter by host...')).toBeInTheDocument();
  });

  it('labels each fanned-in row with the node that produced it', async () => {
    getFleetLogs.mockResolvedValue({
      data: {
        rows: [fanInRow(7, 'node-b', '/from-b'), fanInRow(8, 'node-c', '/from-c')],
        next_cursor: null,
      },
    });
    clusterStatus.set(controlPlane());
    render(Logs);
    await vi.advanceTimersByTimeAsync(0);

    await fireEvent.change(nodeFilter(), { target: { value: ALL_FOLLOWERS } });
    await vi.advanceTimersByTimeAsync(0);

    expect(screen.getByText('Node')).toBeInTheDocument();
    expect(firstCellOf('/from-b')).toBe('node-b');
    expect(firstCellOf('/from-c')).toBe('node-c');
    // An empty error is no error, as on this node's own rows.
    const errorCell = screen.getByText('/from-b').closest('tr')?.querySelector('.error-col');
    expect(errorCell?.textContent?.trim()).toBe('-');
  });

  it("drops this node's read when it lands after a follower was picked", async () => {
    // Responses land in any order. A late local page would otherwise
    // replace the follower's rows and carry them under the wrong columns.
    let releaseLocal: (value: unknown) => void = () => {};
    getLogs.mockImplementationOnce(() => new Promise((resolve) => (releaseLocal = resolve)));
    getFleetLogs.mockResolvedValue({
      data: { rows: [fanInRow(7, 'node-b', '/from-b')], next_cursor: null },
    });
    clusterStatus.set(controlPlane());
    render(Logs);
    await vi.advanceTimersByTimeAsync(0);

    await fireEvent.change(nodeFilter(), { target: { value: 'node-b' } });
    await vi.advanceTimersByTimeAsync(0);
    releaseLocal({ data: { entries: [localEntry(7, '/own')], total: 1 } });
    await vi.advanceTimersByTimeAsync(0);

    expect(screen.queryByText('/own')).toBeNull();
    expect(firstCellOf('/from-b')).toBe('node-b');
  });

  it('reads one follower by id, then goes back to the live tail for this node', async () => {
    getFleetLogs.mockResolvedValue({
      data: { rows: [fanInRow(7, 'node-b', '/from-b')], next_cursor: null },
    });
    clusterStatus.set(controlPlane());
    render(Logs);
    await vi.advanceTimersByTimeAsync(0);

    await fireEvent.change(nodeFilter(), { target: { value: 'node-b' } });
    await vi.advanceTimersByTimeAsync(0);
    expect(getFleetLogs).toHaveBeenLastCalledWith(expect.objectContaining({ node: 'node-b' }));
    expect(screen.getByText('/from-b')).toBeInTheDocument();

    const localReads = getLogs.mock.calls.length;
    await fireEvent.change(nodeFilter(), { target: { value: '' } });
    // The follower's rows go at once, not when this node's read lands.
    expect(screen.queryByText('/from-b')).toBeNull();
    await vi.advanceTimersByTimeAsync(0);

    expect(getLogs.mock.calls.length).toBe(localReads + 1);
    expect(FakeWebSocket.instances).toHaveLength(2);
    expect(FakeWebSocket.instances[1].closed).toBe(false);
  });
});
