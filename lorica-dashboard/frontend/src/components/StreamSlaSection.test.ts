import { render, screen, fireEvent, waitFor, within } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { api, type StreamSlaSummary, type StreamStatus } from '../lib/api';
import { auth, type Role } from '../lib/auth';
import StreamSlaSection from './StreamSlaSection.svelte';

function summary(overrides: Partial<StreamSlaSummary> = {}): StreamSlaSummary {
  return {
    stream_id: 'pg-id',
    window: '24h',
    judged_count: 1000,
    success_count: 999,
    failure_count: 1,
    sla_pct: 99.9,
    avg_connect_latency_ms: 4.4,
    p50_connect_latency_ms: 3,
    p95_connect_latency_ms: 9,
    p99_connect_latency_ms: 20,
    target_pct: 99.9,
    meets_target: true,
    ...overrides,
  };
}

const STATUS: StreamStatus[] = [
  { id: 'pg-id', name: 'pg', protocol: 'tcp', bind: null, nodes: null, counters: null },
  { id: 'dns-id', name: 'dns', protocol: 'udp', bind: null, nodes: null, counters: null },
];

const UDP = {
  stream_id: 'dns-id',
  avg_connect_latency_ms: null,
  p50_connect_latency_ms: null,
  p95_connect_latency_ms: null,
  p99_connect_latency_ms: null,
};

function signIn(role: Role) {
  auth.set({ status: 'authenticated', username: 'user01', role });
}

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(api, 'getStreamStatus').mockResolvedValue({ data: { streams: STATUS } });
  vi.spyOn(api, 'getStreamSlaOverview').mockResolvedValue({
    data: [
      summary({ window: '1h' }),
      summary(),
      summary({ ...UDP, window: '1h' }),
      summary({ ...UDP, sla_pct: 90, meets_target: false }),
    ],
  });
  vi.spyOn(api, 'getStreamSla').mockImplementation(async (id: string) => ({
    data: ['1h', '24h', '7d', '30d'].map((window) =>
      summary(id === 'dns-id' ? { ...UDP, window } : { window }),
    ),
  }));
  vi.spyOn(api, 'getStreamSlaBuckets').mockResolvedValue({ data: [] });
  vi.spyOn(api, 'getStreamSlaConfig').mockImplementation(async (id: string) => ({
    data: {
      stream_id: id,
      target_pct: 99.9,
      max_connect_latency_ms: 500,
      created_at: '2026-11-18T10:00:00Z',
      updated_at: '2026-11-18T10:00:00Z',
    },
  }));
  signIn('operator');
});

afterEach(() => {
  auth.set({ status: 'unauthenticated' });
});

function card(name: string): HTMLElement {
  return screen.getByText(name).closest('button') as HTMLElement;
}

describe('StreamSlaSection', () => {
  it('shows one card per stream from its 24h row, with its breach state', async () => {
    render(StreamSlaSection);
    await screen.findByText('pg');
    expect(within(card('pg')).getByText('99.90%')).toBeInTheDocument();
    expect(within(card('pg')).getByText('meets target')).toHaveClass('badge-green');
    expect(within(card('dns')).getByText('breached')).toHaveClass('badge-red');
    expect(screen.getAllByRole('button', { name: /24h/ })).toHaveLength(2);
  });

  it('shows connect latency for TCP and availability only for UDP', async () => {
    render(StreamSlaSection);
    await screen.findByText('pg');
    expect(within(card('pg')).getByText('4 ms avg connect')).toBeInTheDocument();
    expect(within(card('dns')).queryByText(/avg connect/)).toBeNull();

    await fireEvent.click(card('pg'));
    await screen.findByRole('columnheader', { name: 'p95' });
    await fireEvent.click(card('dns'));
    await waitFor(() => expect(screen.queryByRole('columnheader', { name: 'p95' })).toBeNull());
    expect(screen.getAllByRole('row')).toHaveLength(5);
  });

  it('opens on the stream a link named', async () => {
    render(StreamSlaSection, { props: { initialStreamId: 'dns-id' } });
    await waitFor(() => expect(api.getStreamSla).toHaveBeenCalledWith('dns-id', undefined));
  });

  it("reads a picked follower's own figures and offers nothing that acts on this node", async () => {
    render(StreamSlaSection, { props: { initialStreamId: 'pg-id', node: 'node-2' } });
    await waitFor(() => expect(api.getStreamSla).toHaveBeenCalledWith('pg-id', 'node-2'));
    expect(api.getStreamSlaOverview).toHaveBeenCalledWith('node-2');
    expect(api.getStreamSlaBuckets).toHaveBeenCalledWith('pg-id', { node: 'node-2' });
    await screen.findByRole('columnheader', { name: 'p95' });
    for (const name of ['Configure', 'Export CSV', 'Export JSON', 'Clear SLA']) {
      expect(screen.queryByRole('button', { name })).toBeNull();
    }
  });

  it('re-reads the open stream on the node the picker moves to', async () => {
    const { rerender } = render(StreamSlaSection, { props: { initialStreamId: 'pg-id' } });
    await waitFor(() => expect(api.getStreamSla).toHaveBeenCalledWith('pg-id', undefined));
    await rerender({ initialStreamId: 'pg-id', node: 'node-2' });
    await waitFor(() => expect(api.getStreamSla).toHaveBeenCalledWith('pg-id', 'node-2'));
    expect(api.getStreamSlaOverview).toHaveBeenLastCalledWith('node-2');
  });

  it('saves a target and leaves the latency bound out on UDP', async () => {
    const update = vi.spyOn(api, 'updateStreamSlaConfig').mockResolvedValue({
      data: {
        stream_id: 'dns-id',
        target_pct: 99,
        max_connect_latency_ms: 500,
        created_at: '2026-11-18T10:00:00Z',
        updated_at: '2026-11-18T10:00:00Z',
      },
    });
    render(StreamSlaSection, { props: { initialStreamId: 'dns-id' } });
    await screen.findByText('pg');
    await fireEvent.click(await screen.findByRole('button', { name: 'Configure' }));
    expect(screen.queryByLabelText('Max connect latency (ms)')).toBeNull();
    await fireEvent.input(screen.getByLabelText('Target availability (%)'), { target: { value: '99' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(update).toHaveBeenCalledWith('dns-id', { target_pct: 99 });
  });

  it('sends both fields on TCP and shows the server refusal in the dialog', async () => {
    const update = vi.spyOn(api, 'updateStreamSlaConfig').mockResolvedValue({
      error: { code: 'bad_request', message: 'max_connect_latency_ms must be positive', status: 400 },
    });
    render(StreamSlaSection, { props: { initialStreamId: 'pg-id' } });
    await fireEvent.click(await screen.findByRole('button', { name: 'Configure' }));
    await fireEvent.input(screen.getByLabelText('Max connect latency (ms)'), { target: { value: '0' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(update).toHaveBeenCalledWith('pg-id', { target_pct: 99.9, max_connect_latency_ms: 0 });
    const dialog = screen.getByRole('dialog');
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('must be positive');
  });

  it('offers Configure and Clear to an Operator only', async () => {
    signIn('viewer');
    render(StreamSlaSection, { props: { initialStreamId: 'pg-id' } });
    await screen.findByRole('button', { name: 'Export CSV' });
    expect(screen.queryByRole('button', { name: 'Configure' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Clear SLA' })).toBeNull();
  });

  it('deletes the history after confirmation', async () => {
    const clear = vi.spyOn(api, 'clearStreamSla').mockResolvedValue({
      data: { stream_id: 'pg-id', deleted_buckets: 12 },
    });
    render(StreamSlaSection, { props: { initialStreamId: 'pg-id' } });
    await fireEvent.click(await screen.findByRole('button', { name: 'Clear SLA' }));
    await fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Clear all data' }));
    expect(clear).toHaveBeenCalledWith('pg-id');
  });
});
