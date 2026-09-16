import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach } from 'vitest';

import { api, type RecentCapture } from '../../lib/api';
import RecentCaptures from './RecentCaptures.svelte';

function capture(requestId: string, ruleId: string): RecentCapture {
  return {
    kind: 'capture',
    rule_id: ruleId,
    rule_name: 'checkout 5xx',
    route_id: 'route-1',
    request_id: requestId,
    timestamp: '2026-01-01T00:00:00Z',
    client_ip: '10.0.0.7',
    is_xff: false,
    backend: '10.0.0.2:8080',
    latency_ms: 1234,
    error: null,
    request: {
      method: 'POST',
      uri: '/checkout',
      version: 'HTTP/1.1',
      headers: [['Content-Type', 'application/json']],
      body: '{}',
      body_encoding: 'utf8',
      body_bytes_total: 2,
      truncated: false,
      body_skipped: null,
      body_elided: false,
    },
    response: {
      status: 503,
      headers: [],
      body: '',
      body_encoding: 'base64',
      body_bytes_total: 0,
      truncated: false,
      body_skipped: null,
      body_elided: false,
    },
  };
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('RecentCaptures', () => {
  it('downloads the row it was clicked on, by request id and rule id', async () => {
    vi.spyOn(api, 'listRecentCaptures').mockResolvedValue({
      data: { captures: [capture('req-abc', 'cap-1')], capacity: 50 },
    });
    const download = vi.spyOn(api, 'downloadRecentCapture').mockResolvedValue({ ok: true });
    render(RecentCaptures);
    const button = await screen.findByRole('button', { name: 'Download capture req-abc' });
    expect(button.getAttribute('data-request-id')).toBe('req-abc');
    await fireEvent.click(button);
    await waitFor(() => expect(download).toHaveBeenCalledWith('req-abc', 'cap-1'));
  });

  it('says plainly when the ring is unavailable on a --workers node', async () => {
    vi.spyOn(api, 'listRecentCaptures').mockResolvedValue({
      error: {
        code: 'service_unavailable',
        message: 'the recent-captures ring is per worker and this node runs --workers',
      },
    });
    render(RecentCaptures);
    const note = await screen.findByRole('note');
    expect(note.textContent).toMatch(/not available on this node/);
    expect(note.textContent).toMatch(/--workers/);
    expect(screen.queryByText(/No capture has been emitted/)).toBeNull();
  });
});
