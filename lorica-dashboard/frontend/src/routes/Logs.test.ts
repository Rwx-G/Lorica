import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { api } from '../lib/api';
import { auth } from '../lib/auth';
import { hash } from '../lib/router';
import { streamLogsHref } from '../lib/stream-links';
import Logs from './Logs.svelte';

beforeEach(() => {
  vi.restoreAllMocks();
  // No live tail in a unit test: the page would open a WebSocket.
  localStorage.setItem('lorica-logs-autorefresh', 'false');
  vi.spyOn(api, 'getLogs').mockResolvedValue({ data: { entries: [], total: 0 } });
  vi.spyOn(api, 'getStreamLogs').mockResolvedValue({ data: { entries: [], total: 0 } });
  vi.spyOn(api, 'getStreamStatus').mockResolvedValue({ data: { streams: [] } });
  auth.set({ status: 'authenticated', username: 'user01', role: 'viewer' });
});

afterEach(() => {
  hash.set('/');
  localStorage.clear();
  auth.set({ status: 'unauthenticated' });
});

describe('Logs page, HTTP / Streams switch (Story 12.9)', () => {
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
