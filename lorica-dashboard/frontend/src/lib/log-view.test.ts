import { describe, it, expect, vi } from 'vitest';

import type { ApiResponse } from './api';
import { TIME_RANGES, createScopedLoader, formatLogTimestamp, rangeStart, type ScopedReads } from './log-view';

/** A read whose response the test hands over when it chooses. */
function deferred<T>(): { promise: Promise<ApiResponse<T>>; land: (res: ApiResponse<T>) => void } {
  let land: (res: ApiResponse<T>) => void = () => {};
  const promise = new Promise<ApiResponse<T>>((resolve) => (land = resolve));
  return { promise, land };
}

function reads(local: Promise<ApiResponse<string>>, fanIn: Promise<ApiResponse<string>> = local): ScopedReads<string, string, string> {
  return {
    local: vi.fn(() => local),
    fanIn: vi.fn(() => fanIn),
    showLocal: vi.fn(),
    showFanIn: vi.fn(),
  };
}

describe('createScopedLoader', () => {
  it('drops a response that lands after a newer read started, and shows the newer one', async () => {
    const load = createScopedLoader();
    const older = deferred<string>();
    const newer = deferred<string>();
    const first = reads(older.promise);
    const second = reads(newer.promise);

    const olderOutcome = load({ store: 'local' }, first);
    const newerOutcome = load({ store: 'local' }, second);
    newer.land({ data: 'newer page' });
    older.land({ data: 'older page' });

    expect(await newerOutcome).toEqual({ stale: false, error: '' });
    expect(await olderOutcome).toEqual({ stale: true });
    expect(second.showLocal).toHaveBeenCalledWith('newer page');
    expect(first.showLocal).not.toHaveBeenCalled();
  });

  it('drops an older read even when it lands first: only the latest read is shown', async () => {
    const load = createScopedLoader();
    const older = deferred<string>();
    const newer = deferred<string>();
    const first = reads(older.promise);
    const second = reads(newer.promise);

    const olderOutcome = load({ store: 'local' }, first);
    const newerOutcome = load({ store: 'fan-in', node: 'node-b' }, second);
    older.land({ data: 'this node' });
    expect(await olderOutcome).toEqual({ stale: true });
    newer.land({ data: 'follower' });

    expect(await newerOutcome).toEqual({ stale: false, error: '' });
    expect(first.showLocal).not.toHaveBeenCalled();
    expect(second.showFanIn).toHaveBeenCalledWith('follower');
  });

  it('drops a stale error as well as a stale page', async () => {
    const load = createScopedLoader();
    const older = deferred<string>();
    const olderOutcome = load({ store: 'local' }, reads(older.promise));
    await load({ store: 'local' }, reads(Promise.resolve({ data: 'page' })));
    older.land({ error: { code: 'internal', message: 'store busy' } });
    expect(await olderOutcome).toEqual({ stale: true });
  });

  it('reads the store the scope names, passing the follower to the fan-in read', async () => {
    const load = createScopedLoader();
    const local = reads(Promise.resolve({ data: 'own' }), Promise.resolve({ data: 'fanned' }));
    await load({ store: 'fan-in', node: 'node-b' }, local);
    expect(local.fanIn).toHaveBeenCalledWith('node-b');
    expect(local.local).not.toHaveBeenCalled();
    expect(local.showFanIn).toHaveBeenCalledWith('fanned');
    expect(local.showLocal).not.toHaveBeenCalled();
  });

  it('returns the error of the latest read and shows nothing', async () => {
    const load = createScopedLoader();
    const failing = reads(Promise.resolve({ error: { code: 'forbidden', message: 'not allowed' } }));
    expect(await load({ store: 'local' }, failing)).toEqual({ stale: false, error: 'not allowed' });
    expect(failing.showLocal).not.toHaveBeenCalled();
  });

  it('keeps one sequence per table: two loaders never drop each other', async () => {
    const httpTable = createScopedLoader();
    const streamTable = createScopedLoader();
    const slow = deferred<string>();
    const http = reads(slow.promise);
    const httpOutcome = httpTable({ store: 'local' }, http);
    await streamTable({ store: 'local' }, reads(Promise.resolve({ data: 'stream page' })));
    slow.land({ data: 'http page' });
    expect(await httpOutcome).toEqual({ stale: false, error: '' });
    expect(http.showLocal).toHaveBeenCalledWith('http page');
  });
});

describe('rangeStart', () => {
  const NOW = Date.parse('2026-11-22T12:00:00.000Z');

  it.each(TIME_RANGES.map((r) => [r.value, r.ms] as const))('the range "%s" starts back from now', (value, ms) => {
    expect(rangeStart(value, NOW)).toBe(ms > 0 ? new Date(NOW - ms).toISOString() : undefined);
  });

  it('puts no lower bound for All time', () => {
    expect(rangeStart('', NOW)).toBeUndefined();
  });

  it('reads 1h as an hour', () => {
    expect(rangeStart('1h', NOW)).toBe('2026-11-22T11:00:00.000Z');
  });
});

describe('formatLogTimestamp', () => {
  it('shows a value that is not a date as it came', () => {
    expect(formatLogTimestamp('not a date')).toBe('not a date');
  });

  it('formats a date to the second', () => {
    const ts = '2026-11-18T10:00:05.000Z';
    expect(formatLogTimestamp(ts)).toBe(
      new Date(ts).toLocaleString([], { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    );
  });
});
