/**
 * The links that open the Logs and SLA pages on one stream (Story 12.9
 * Lot H), built and read in one place so the Streams page's links and
 * the pages they open cannot disagree on a parameter name.
 */

/** The Logs page's two tables. */
export type LogsView = 'http' | 'streams';

const VIEW = 'view';
const STREAM = 'stream';

/** `#/logs` showing the stream table, filtered on `streamId` when given. */
export function streamLogsHref(streamId?: string): string {
  const query = new URLSearchParams({ [VIEW]: 'streams' });
  if (streamId) query.set(STREAM, streamId);
  return `#/logs?${query}`;
}

/** `#/sla` with the stream `streamId` selected. */
export function streamSlaHref(streamId: string): string {
  return `#/sla?${new URLSearchParams({ [STREAM]: streamId })}`;
}

/** The table a Logs link asks for; the HTTP one unless it names the stream table. */
export function logsViewOf(query: URLSearchParams): LogsView {
  return query.get(VIEW) === 'streams' ? 'streams' : 'http';
}

/** The stream a Logs or SLA link names, `''` for none. */
export function streamOf(query: URLSearchParams): string {
  return query.get(STREAM) ?? '';
}
