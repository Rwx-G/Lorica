import { render, screen, fireEvent, waitFor, within } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { api, streamLogsQuery, type StreamLogEntry, type StreamStatus } from '../lib/api';
import { auth, type Role } from '../lib/auth';
import { clusterStatus, type ClusterNodeResponse, type ClusterStatus } from '../lib/cluster';
import StreamLogView from './StreamLogView.svelte';

function row(overrides: Partial<StreamLogEntry> = {}): StreamLogEntry {
  return {
    id: 1,
    timestamp: '2026-11-18T10:00:00.000Z',
    entry: 'ended',
    stream_id: 'pg-id',
    stream_name: 'pg',
    protocol: 'tcp',
    listen_port: 5432,
    client_ip: '192.0.2.10',
    client_port: 40000,
    proxied_from: '',
    backend_id: 'b1',
    backend_address: '10.0.0.10:5432',
    attempts: 1,
    bytes_upload: 2048,
    bytes_download: 4096,
    datagrams_upload: null,
    datagrams_download: null,
    duration_ms: 1200,
    connect_ms: 3,
    tls_mode: 'none',
    sni: '',
    alpn: '',
    client_cert: null,
    detected_protocol: null,
    end_reason: 'client_close',
    refusal_reason: '',
    suppressed: 0,
    ...overrides,
  };
}

const STATUS: StreamStatus[] = [
  { id: 'pg-id', name: 'pg', protocol: 'tcp', bind: null, nodes: null, counters: null },
  { id: 'dns-id', name: 'dns', protocol: 'udp', bind: null, nodes: null, counters: null },
];

function signIn(role: Role) {
  auth.set({ status: 'authenticated', username: 'user01', role });
}

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(api, 'getStreamStatus').mockResolvedValue({ data: { streams: STATUS } });
  vi.spyOn(api, 'getStreamLogs').mockResolvedValue({
    data: {
      entries: [
        row(),
        row({
          id: 2,
          stream_id: 'dns-id',
          stream_name: 'dns',
          protocol: 'udp',
          client_ip: '198.51.100.7',
          end_reason: 'refused',
          refusal_reason: 'source_denied',
          backend_address: '',
          connect_ms: null,
          tls_mode: '',
        }),
        row({ id: 3, client_ip: '203.0.113.9', entry: 'refusals_suppressed', suppressed: 41, end_reason: 'refused', listen_port: 0 }),
      ],
      total: 3,
    },
  });
  signIn('operator');
});

afterEach(() => {
  auth.set({ status: 'unauthenticated' });
});

function rowOf(text: string): HTMLElement {
  return screen.getByText(text).closest('tr') as HTMLElement;
}

describe('StreamLogView', () => {
  it('shows each row with its stream, client, backend and end', async () => {
    render(StreamLogView, { props: { autoRefresh: false } });
    await screen.findByText('192.0.2.10:40000');
    const ended = rowOf('192.0.2.10:40000');
    expect(within(ended).getByText('10.0.0.10:5432')).toBeInTheDocument();
    expect(within(ended).getByText('client_close')).toHaveClass('badge', 'badge-gray');
    expect(within(ended).getByText('3 ms')).toBeInTheDocument();
  });

  it('reads a refusal red with its reason, and a suppressed count orange', async () => {
    render(StreamLogView, { props: { autoRefresh: false } });
    await screen.findByText('source_denied');
    const refused = screen.getByText('source_denied').closest('tr') as HTMLElement;
    expect(within(refused).getByText('refused')).toHaveClass('badge-red');
    expect(screen.getByText('41 refusals suppressed')).toHaveClass('badge-orange');
  });

  it('opens filtered on the stream a link named', async () => {
    render(StreamLogView, { props: { autoRefresh: false, initialStreamId: 'dns-id' } });
    await waitFor(() => expect(api.getStreamLogs).toHaveBeenCalled());
    expect(vi.mocked(api.getStreamLogs).mock.calls[0][0]).toMatchObject({ stream_id: 'dns-id' });
    await waitFor(() => expect((screen.getByLabelText('Stream') as HTMLSelectElement).value).toBe('dns-id'));
  });

  it('sends the reason filters as typed, and offers the words on screen', async () => {
    render(StreamLogView, { props: { autoRefresh: false } });
    await screen.findByText('source_denied');
    const offered = Array.from(document.querySelectorAll('#stream-end-reasons option')).map(
      (o) => (o as HTMLOptionElement).value,
    );
    expect(offered).toEqual(['client_close', 'refused']);
    const input = screen.getByLabelText('End reason');
    await fireEvent.input(input, { target: { value: 'idle_timeout' } });
    await fireEvent.keyDown(input, { key: 'Enter' });
    await waitFor(() =>
      expect(vi.mocked(api.getStreamLogs).mock.lastCall?.[0]).toMatchObject({ end_reason: 'idle_timeout' }),
    );
  });

  it('shows the server refusal of an unknown word', async () => {
    vi.mocked(api.getStreamLogs).mockResolvedValue({
      error: { code: 'bad_request', message: 'unknown end_reason "nope"; expected one of client_close, ...' },
    });
    render(StreamLogView, { props: { autoRefresh: false } });
    expect(await screen.findByRole('alert')).toHaveTextContent('unknown end_reason');
  });

  it('offers Clear to an Operator and not to a Viewer', async () => {
    const { unmount } = render(StreamLogView, { props: { autoRefresh: false } });
    expect(screen.getByRole('button', { name: 'Clear' })).toBeInTheDocument();
    unmount();
    signIn('viewer');
    render(StreamLogView, { props: { autoRefresh: false } });
    expect(screen.queryByRole('button', { name: 'Clear' })).toBeNull();
  });

  it('clears after confirmation', async () => {
    const clear = vi.spyOn(api, 'clearStreamLogs').mockResolvedValue({ data: { message: 'ok' } });
    render(StreamLogView, { props: { autoRefresh: false } });
    await screen.findByText('source_denied');
    await fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
    const dialog = screen.getByRole('dialog');
    await fireEvent.click(within(dialog).getByRole('button', { name: 'Clear' }));
    expect(clear).toHaveBeenCalled();
    await waitFor(() => expect(screen.queryByText('source_denied')).toBeNull());
  });

  it('exports the rows the filters select', async () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    render(StreamLogView, { props: { autoRefresh: false, initialStreamId: 'pg-id' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Export' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Download' }));
    expect(open).toHaveBeenCalledWith('/api/v1/stream-logs/export?stream_id=pg-id&format=csv', '_blank');
  });
});

function controlPlane(): ClusterStatus {
  return {
    role: 'control_plane',
    build_version: '1.11.0',
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
    version: '1.11.0',
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
    stream_plane: null,
    stream_ports: [],
  };
}

describe('StreamLogView on a control plane', () => {
  beforeEach(() => {
    vi.spyOn(api, 'listClusterNodes').mockResolvedValue({ data: [follower('node-b', 'edge-02')] });
    vi.spyOn(api, 'getFleetStreamLogs').mockResolvedValue({
      data: { node: 'node-b', entries: [row({ id: 7, client_ip: '198.51.100.20' })] },
    });
    clusterStatus.set(controlPlane());
  });

  afterEach(() => {
    clusterStatus.set(null);
  });

  async function pick(choice: string) {
    await screen.findByRole('option', { name: 'edge-02' });
    await fireEvent.change(screen.getByLabelText('Filter by node'), { target: { value: choice } });
  }

  it("opens on this node's own rows, with its actions and no Node column", async () => {
    render(StreamLogView, { props: { autoRefresh: false } });
    await screen.findByText('192.0.2.10:40000');
    expect(api.getStreamLogs).toHaveBeenCalled();
    expect(api.getFleetStreamLogs).not.toHaveBeenCalled();
    expect((screen.getByLabelText('Filter by node') as HTMLSelectElement).value).toBe('');
    expect(screen.queryByRole('option', { name: 'All followers' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Export' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Clear' })).toBeInTheDocument();
    expect(screen.queryByRole('columnheader', { name: 'Node' })).toBeNull();
  });

  it("reads a picked follower's fanned-in rows under the filters, labelled, with no action on this node", async () => {
    render(StreamLogView, { props: { autoRefresh: false, initialStreamId: 'pg-id' } });
    await screen.findByText('192.0.2.10:40000');

    await pick('node-b');
    await screen.findByText('198.51.100.20:40000');

    expect(api.getFleetStreamLogs).toHaveBeenLastCalledWith('node-b', expect.objectContaining({ stream_id: 'pg-id' }));
    expect(screen.queryByText('192.0.2.10:40000')).toBeNull();
    expect(screen.getByRole('columnheader', { name: 'Node' })).toBeInTheDocument();
    expect(within(rowOf('198.51.100.20:40000')).getAllByRole('cell')[0]).toHaveTextContent('node-b');
    expect(screen.getByText('1 entries')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Export' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Clear' })).toBeNull();
  });

  it("drops this node's read when it lands after a follower was picked", async () => {
    let releaseLocal: (value: unknown) => void = () => {};
    vi.mocked(api.getStreamLogs).mockImplementationOnce(
      () => new Promise((resolve) => (releaseLocal = resolve)) as never,
    );
    render(StreamLogView, { props: { autoRefresh: false } });

    await pick('node-b');
    await screen.findByText('198.51.100.20:40000');
    releaseLocal({ data: { entries: [row()], total: 1 } });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(screen.queryByText('192.0.2.10:40000')).toBeNull();
    expect(within(rowOf('198.51.100.20:40000')).getAllByRole('cell')[0]).toHaveTextContent('node-b');
  });

  it("empties a follower's rows at once when this node is picked again", async () => {
    render(StreamLogView, { props: { autoRefresh: false } });
    await pick('node-b');
    await screen.findByText('198.51.100.20:40000');
    vi.mocked(api.getStreamLogs).mockImplementation(() => new Promise(() => {}) as never);

    await fireEvent.change(screen.getByLabelText('Filter by node'), { target: { value: '' } });

    expect(screen.queryByText('198.51.100.20:40000')).toBeNull();
    expect(screen.queryByRole('columnheader', { name: 'Node' })).toBeNull();
  });

  it('offers no node filter to a Viewer, who reads this node only', async () => {
    signIn('viewer');
    render(StreamLogView, { props: { autoRefresh: false } });
    await screen.findByText('192.0.2.10:40000');
    expect(screen.queryByLabelText('Filter by node')).toBeNull();
    expect(api.getFleetStreamLogs).not.toHaveBeenCalled();
  });
});

describe('streamLogsQuery', () => {
  it('omits every unset filter', () => {
    expect(streamLogsQuery({})).toBe('');
    expect(streamLogsQuery({ stream_id: '', client_ip: undefined })).toBe('');
  });

  it('carries the node of a fan-in read', () => {
    expect(Object.fromEntries(new URLSearchParams(streamLogsQuery({ node: 'node-b', limit: 5 }).slice(1)))).toEqual({
      node: 'node-b',
      limit: '5',
    });
  });

  it('carries each set filter and the page', () => {
    const qs = new URLSearchParams(
      streamLogsQuery({ end_reason: 'refused', refusal_reason: 'geoip', limit: 200, before_id: 9 }).slice(1),
    );
    expect(Object.fromEntries(qs)).toEqual({
      end_reason: 'refused',
      refusal_reason: 'geoip',
      limit: '200',
      before_id: '9',
    });
  });
});
