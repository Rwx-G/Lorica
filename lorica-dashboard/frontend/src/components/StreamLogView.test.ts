import { render, screen, fireEvent, waitFor, within } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { api, streamLogsQuery, type StreamLogEntry, type StreamStatus } from '../lib/api';
import { auth, type Role } from '../lib/auth';
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

describe('streamLogsQuery', () => {
  it('omits every unset filter', () => {
    expect(streamLogsQuery({})).toBe('');
    expect(streamLogsQuery({ stream_id: '', client_ip: undefined })).toBe('');
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
