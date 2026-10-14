import { render, screen, waitFor } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { api, type WafStatsResponse } from '../lib/api';
import Overview, { REFRESH_MS } from './Overview.svelte';

function wafStats(overrides: Partial<WafStatsResponse> = {}): WafStatsResponse {
  return {
    total_events: 100000,
    total_24h: 4200,
    total_1h: 640,
    rule_count: 40,
    by_category: [{ category: 'sql_injection', count: 90000 }],
    by_category_1h: [
      { category: 'xss', count: 600 },
      { category: 'sql_injection', count: 40 },
    ],
    stored_in: 'log_store',
    ...overrides,
  };
}

/** The value a `Card` titled `title` shows. */
function cardValue(title: string): string | null | undefined {
  return screen.getByText(title).closest('.card')?.querySelector('.card-value')?.textContent;
}

beforeEach(() => {
  vi.restoreAllMocks();
  vi.useFakeTimers({ shouldAdvanceTime: true });
  localStorage.setItem('lorica_helper_dismissed', 'true');
  vi.spyOn(api, 'getStatus').mockResolvedValue({
    data: {
      routes_count: 1,
      backends_count: 1,
      backends_healthy: 1,
      backends_degraded: 0,
      backends_down: 0,
      certificates_count: 0,
      certificates_expiring_soon: 0,
      log_store: { persisting: true, cause: null },
    },
  });
  vi.spyOn(api, 'getSystem').mockResolvedValue({});
  vi.spyOn(api, 'getSlaOverview').mockResolvedValue({ data: [] });
  vi.spyOn(api, 'getCacheStats').mockResolvedValue({});
  vi.spyOn(api, 'listBans').mockResolvedValue({ data: { bans: [], total: 0 } });
  vi.spyOn(api, 'getWorkers').mockResolvedValue({ data: { workers: [], total: 0 } });
  vi.spyOn(api, 'listProbes').mockResolvedValue({ data: [] });
});

afterEach(() => {
  vi.useRealTimers();
  localStorage.clear();
});

describe('Overview WAF cards', () => {
  it('leads with the last hour, not the retained total', async () => {
    vi.spyOn(api, 'getWafStats').mockResolvedValue({ data: wafStats() });
    render(Overview);

    await waitFor(() => expect(screen.getByText('WAF Events (1h)')).toBeInTheDocument());
    expect(cardValue('WAF Events (1h)')).toBe('640');
    expect(screen.queryByText('100000')).toBeNull();
  });

  it('names the top category of the last hour', async () => {
    vi.spyOn(api, 'getWafStats').mockResolvedValue({ data: wafStats() });
    render(Overview);

    await waitFor(() => expect(screen.getByText('Top Category (1h)')).toBeInTheDocument());
    expect(cardValue('Top Category (1h)')).toBe('XSS (600)');
  });

  it('shows no top category when the last hour is quiet', async () => {
    vi.spyOn(api, 'getWafStats').mockResolvedValue({
      data: wafStats({ total_1h: 0, by_category_1h: [] }),
    });
    render(Overview);

    await waitFor(() => expect(screen.getByText('WAF Events (1h)')).toBeInTheDocument());
    expect(cardValue('WAF Events (1h)')).toBe('0');
    expect(screen.queryByText('Top Category (1h)')).toBeNull();
  });

  it('re-reads the counters so the window rolls', async () => {
    const stats = vi
      .spyOn(api, 'getWafStats')
      .mockResolvedValueOnce({ data: wafStats() })
      .mockResolvedValue({ data: wafStats({ total_1h: 12 }) });
    render(Overview);
    await waitFor(() => expect(cardValue('WAF Events (1h)')).toBe('640'));

    await vi.advanceTimersByTimeAsync(REFRESH_MS);
    await waitFor(() => expect(cardValue('WAF Events (1h)')).toBe('12'));
    expect(stats).toHaveBeenCalledTimes(2);
  });
});
