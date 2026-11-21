/**
 * What the HTTP and the stream access log tables share: the time-range
 * filter, the timestamp format, and the read of the store a node filter
 * choice names, with responses that are no longer the latest dropped.
 */

import type { ApiResponse } from './api';

/** The time-range filter's choices: `ms` back from now, `0` for no lower bound. */
export const TIME_RANGES: readonly { value: string; label: string; ms: number }[] = [
  { value: '', label: 'All time', ms: 0 },
  { value: '5m', label: 'Last 5 min', ms: 5 * 60_000 },
  { value: '15m', label: 'Last 15 min', ms: 15 * 60_000 },
  { value: '1h', label: 'Last 1 hour', ms: 60 * 60_000 },
  { value: '6h', label: 'Last 6 hours', ms: 6 * 60 * 60_000 },
  { value: '24h', label: 'Last 24 hours', ms: 24 * 60 * 60_000 },
];

/** The lower bound a time-range choice puts on a read, as ISO 8601; `undefined` for none. */
export function rangeStart(value: string, now: number = Date.now()): string | undefined {
  const range = TIME_RANGES.find((r) => r.value === value);
  return range && range.ms > 0 ? new Date(now - range.ms).toISOString() : undefined;
}

/** A row's time, to the second; a value that is not a date is shown as it came. */
export function formatLogTimestamp(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString([], { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

/**
 * The store a read goes to. `N` is what names the follower: a view
 * offering "All followers" reads the fan-in store with no node
 * (`NodeScope`), one that reads a follower at a time always names one.
 */
export type LogScope<N> = { store: 'local' } | { store: 'fan-in'; node: N };

export interface ScopedReads<L, F, N> {
  /** This node's own table. */
  local: () => Promise<ApiResponse<L>>;
  /** The rows the followers fanned in. */
  fanIn: (node: N) => Promise<ApiResponse<F>>;
  /** Put this node's page on screen. */
  showLocal: (data: L) => void;
  /** Put the fan-in page on screen. */
  showFanIn: (data: F) => void;
}

/** `stale`: a later read started before this one landed, and nothing was shown. Otherwise `error` is `''` once a page is on screen. */
export type ScopedOutcome = { stale: true } | { stale: false; error: string };

/**
 * One table's reader. Polls, Refresh, filter changes and node switches
 * overlap and their responses land in any order, so a response is shown
 * only while its read is the table's latest: a late page from one store
 * would otherwise land under the other store's controls.
 */
export function createScopedLoader(): <L, F, N>(scope: LogScope<N>, reads: ScopedReads<L, F, N>) => Promise<ScopedOutcome> {
  let latest = 0;
  return async (scope, reads) => {
    const ticket = ++latest;
    if (scope.store === 'fan-in') {
      const res = await reads.fanIn(scope.node);
      return ticket === latest ? settle(res, reads.showFanIn) : { stale: true };
    }
    const res = await reads.local();
    return ticket === latest ? settle(res, reads.showLocal) : { stale: true };
  };
}

function settle<T>(res: ApiResponse<T>, show: (data: T) => void): ScopedOutcome {
  if (res.error) return { stale: false, error: res.error.message };
  if (res.data !== undefined) show(res.data);
  return { stale: false, error: '' };
}
