import { render, screen, fireEvent, waitFor, within } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { api, type GlobalSettingsResponse } from '../lib/api';
import { auth, type Role } from '../lib/auth';
import { streamLogsHref, streamSlaHref } from '../lib/stream-links';
import { status, stream, udpSettings } from '../test-stream-fixtures';
import Streams from './Streams.svelte';

const PG = stream();
const DNS = stream({
  id: 'dns-id',
  name: 'dns',
  group_name: 'infra',
  protocol: 'udp',
  listen_address: '::',
  port_first: 53,
  port_last: 53,
  udp: udpSettings({ unbounded_responses: true }),
  backup_backend_ids: ['b2'],
});

function signIn(role: Role) {
  auth.set({ status: 'authenticated', username: 'user01', role });
}

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(api, 'listStreams').mockResolvedValue({ data: { streams: [PG, DNS] } });
  vi.spyOn(api, 'getStreamStatus').mockResolvedValue({
    data: {
      streams: [
        status({
          counters: {
            node_name: null,
            active: 3,
            pending: 0,
            accepted_total: 10,
            bytes_upload_total: 1024,
            bytes_download_total: 2048,
            refused: [],
            ended: [],
            datagrams_dropped: [],
          },
        }),
        status({
          id: 'dns-id',
          name: 'dns',
          protocol: 'udp',
          bind: { state: 'failed', kind: 'address_in_use', port: 53, os_error: 'Address already in use (os error 98)', since: '2026-11-18T10:00:00Z' },
        }),
      ],
    },
  });
  vi.spyOn(api, 'getSettings').mockResolvedValue({
    data: { worker_drain_timeout_s: 45 } as GlobalSettingsResponse,
  });
  signIn('operator');
});

afterEach(() => {
  auth.set({ status: 'unauthenticated' });
});

function rowOf(name: string): HTMLElement {
  return screen.getByText(name, { selector: 'td.name, td.name *' }).closest('tr') as HTMLElement;
}

describe('Streams page (Story 12.10 Lot D1)', () => {
  it('lists every stream with its protocol, endpoint, backends and bind state', async () => {
    render(Streams);
    await screen.findByText('[::]:53');
    const dns = rowOf('dns');
    expect(within(dns).getByText('UDP')).toBeInTheDocument();
    expect(within(dns).getByText('1 primary, 1 backup')).toBeInTheDocument();
    expect(within(dns).getByText('failed')).toHaveClass('badge', 'badge-red');
    expect(within(rowOf('pg')).getByText('0.0.0.0:5432')).toBeInTheDocument();
    expect(within(rowOf('pg')).getByText('bound')).toHaveClass('badge-green');
  });

  it('shows the derived badges, and the failed bind with its tooltip', async () => {
    render(Streams);
    await screen.findByText('[::]:53');
    const dns = rowOf('dns');
    expect(within(dns).getByText('unbounded responses')).toHaveClass('badge-orange');
    const failed = within(dns).getByText('failed bind');
    expect(failed.getAttribute('title')).toBe(
      'this node, address_in_use, port 53, Address already in use (os error 98), since 2026-11-18T10:00:00Z',
    );
    expect(within(rowOf('pg')).queryByText('failed bind')).toBeNull();
  });

  it("shows this node's counters", async () => {
    render(Streams);
    await screen.findByText('3 active');
  });

  it('searches over name, group and endpoint', async () => {
    render(Streams);
    await screen.findByText('[::]:53');
    const search = screen.getByLabelText('Search streams');
    await fireEvent.input(search, { target: { value: 'infra' } });
    expect(screen.queryByText('0.0.0.0:5432')).toBeNull();
    await fireEvent.input(search, { target: { value: '5432' } });
    expect(screen.queryByText('[::]:53')).toBeNull();
    expect(screen.getByText('0.0.0.0:5432')).toBeInTheDocument();
  });

  it('links each stream to its log table and its SLA', async () => {
    render(Streams);
    await screen.findByText('[::]:53');
    expect(within(rowOf('dns')).getByRole('link', { name: 'Logs' })).toHaveAttribute('href', streamLogsHref('dns-id'));
    expect(within(rowOf('dns')).getByRole('link', { name: 'SLA' })).toHaveAttribute('href', streamSlaHref('dns-id'));
  });

  it('sends enabled alone to disable a stream', async () => {
    const update = vi.spyOn(api, 'updateStream').mockResolvedValue({ data: { ...PG, enabled: false } });
    render(Streams);
    await fireEvent.click(await screen.findByRole('button', { name: 'Disable pg' }));
    expect(update).toHaveBeenCalledWith('pg-id', { enabled: false });
  });

  it('sends enabled alone to enable one', async () => {
    vi.mocked(api.listStreams).mockResolvedValue({ data: { streams: [{ ...PG, enabled: false }] } });
    const update = vi.spyOn(api, 'updateStream').mockResolvedValue({ data: PG });
    render(Streams);
    await fireEvent.click(await screen.findByRole('button', { name: 'Enable pg' }));
    expect(update).toHaveBeenCalledWith('pg-id', { enabled: true });
  });

  it('says a delete drains established connections for the drain timeout, then deletes', async () => {
    const del = vi.spyOn(api, 'deleteStream').mockResolvedValue({ data: { message: 'deleted' } });
    render(Streams);
    await waitFor(() => expect(api.getSettings).toHaveBeenCalled());
    await fireEvent.click(await screen.findByRole('button', { name: 'Delete pg' }));
    const dialog = screen.getByRole('dialog');
    expect(dialog.textContent).toContain('drain for 45 s');
    expect(dialog.textContent).toContain('config_removed');
    await fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));
    expect(del).toHaveBeenCalledWith('pg-id');
  });

  it('offers a Viewer no write action', async () => {
    signIn('viewer');
    render(Streams);
    await screen.findByText('[::]:53');
    expect(screen.queryByRole('button', { name: /^(Enable|Disable|Delete) / })).toBeNull();
    expect(within(rowOf('pg')).getByRole('link', { name: 'Logs' })).toBeInTheDocument();
  });
});
