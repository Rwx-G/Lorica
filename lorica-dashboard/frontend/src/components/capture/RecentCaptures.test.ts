import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

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

/// The component takes its cadence from the page, so a test that does
/// not drive `refreshKey` gets exactly one read.
function props(refreshKey = 0) {
  return { refreshKey };
}

beforeEach(() => {
  // Fake timers so nothing this component or the testing library
  // schedules outlives the test that scheduled it.
  vi.useFakeTimers({ shouldAdvanceTime: true });
  vi.restoreAllMocks();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('RecentCaptures', () => {
  it('downloads the row it was clicked on, by request id and rule id', async () => {
    vi.spyOn(api, 'listRecentCaptures').mockResolvedValue({
      data: { captures: [capture('req-abc', 'cap-1')], capacity: 50 },
    });
    const download = vi.spyOn(api, 'downloadRecentCapture').mockResolvedValue({ ok: true });
    const { unmount } = render(RecentCaptures, { props: props() });
    const button = await screen.findByRole('button', { name: 'Download capture req-abc' });
    expect(button.getAttribute('data-request-id')).toBe('req-abc');
    await fireEvent.click(button);
    await waitFor(() => expect(download).toHaveBeenCalledWith('req-abc', 'cap-1'));
    unmount();
  });

  it('says plainly when the ring is unavailable on a --workers node', async () => {
    vi.spyOn(api, 'listRecentCaptures').mockResolvedValue({
      error: {
        code: 'service_unavailable',
        message: 'the recent-captures ring is per worker and this node runs --workers',
      },
    });
    const { unmount } = render(RecentCaptures, { props: props() });
    const note = await screen.findByRole('note');
    expect(note.textContent).toMatch(/not available on this node/);
    expect(note.textContent).toMatch(/--workers/);
    expect(screen.queryByText(/No capture has been emitted/)).toBeNull();
    unmount();
  });

  it('names the ring size the node reported and never a built-in one', async () => {
    vi.spyOn(api, 'listRecentCaptures').mockResolvedValue({
      data: { captures: [capture('req-abc', 'cap-1')], capacity: 12 },
    });
    const { unmount } = render(RecentCaptures, { props: props() });
    expect(await screen.findByText(/last 12 on this process/)).toBeInTheDocument();
    expect(screen.queryByText(/4 KiB/)).toBeNull();
    unmount();
  });

  it('reports an elided body with the length the node stored', async () => {
    const elided = capture('req-abc', 'cap-1');
    elided.request.body_elided = true;
    elided.request.body_elided_total = 1_048_576;
    vi.spyOn(api, 'listRecentCaptures').mockResolvedValue({
      data: { captures: [elided], capacity: 50 },
    });
    const { unmount } = render(RecentCaptures, { props: props() });
    await fireEvent.click(await screen.findByRole('button', { name: 'Show' }));
    expect(await screen.findByText(/Elided in the list of 1\.0 MiB stored/)).toBeInTheDocument();
    unmount();
  });

  it('re-reads the ring when the page bumps the refresh key, and never twice at once', async () => {
    let resolveSecond: (() => void) | undefined;
    const list = vi.spyOn(api, 'listRecentCaptures');
    list.mockResolvedValueOnce({
      data: { captures: [capture('req-abc', 'cap-1')], capacity: 50 },
    });
    list.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveSecond = () => resolve({ data: { captures: [], capacity: 50 } });
        }),
    );

    const { unmount, rerender } = render(RecentCaptures, { props: props(0) });
    // The first read has landed once its row is on screen.
    await screen.findByText('checkout 5xx');
    expect(list).toHaveBeenCalledTimes(1);

    await rerender(props(1));
    expect(list).toHaveBeenCalledTimes(2);

    // The second read is still outstanding: a further tick is dropped
    // rather than stacked on top of it.
    await rerender(props(2));
    expect(list).toHaveBeenCalledTimes(2);

    resolveSecond?.();
    unmount();
  });

  it('drops a read that lands after the component is gone', async () => {
    let resolveRead: (() => void) | undefined;
    const list = vi.spyOn(api, 'listRecentCaptures').mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveRead = () =>
            resolve({ error: { code: 'network_error', message: 'Unable to reach the server.' } });
        }),
    );

    const { unmount } = render(RecentCaptures, { props: props() });
    await waitFor(() => expect(list).toHaveBeenCalledTimes(1));
    const signal = list.mock.calls[0][0];
    unmount();
    expect(signal?.aborted).toBe(true);

    // Resolving now must not touch a torn-down tree, so the error the
    // late answer carries never reaches the DOM.
    resolveRead?.();
    await vi.advanceTimersByTimeAsync(0);
    expect(screen.queryByText(/Unable to reach the server/)).toBeNull();
  });
});
