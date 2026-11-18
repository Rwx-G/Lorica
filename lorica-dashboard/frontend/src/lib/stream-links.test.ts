import { describe, it, expect } from 'vitest';

import { splitHash } from './router';
import { logsViewOf, streamLogsHref, streamOf, streamSlaHref } from './stream-links';

/** What the page a link opens reads from it, through the router's own split. */
function opened(href: string) {
  return splitHash(href.replace(/^#/, ''));
}

describe('stream links', () => {
  it('opens the Logs page on the stream table filtered on the stream', () => {
    const { path, query } = opened(streamLogsHref('5f0c-id'));
    expect(path).toBe('/logs');
    expect(logsViewOf(query)).toBe('streams');
    expect(streamOf(query)).toBe('5f0c-id');
  });

  it('opens the stream table unfiltered when no stream is named', () => {
    const { query } = opened(streamLogsHref());
    expect(logsViewOf(query)).toBe('streams');
    expect(streamOf(query)).toBe('');
  });

  it('opens the SLA page with the stream selected', () => {
    const { path, query } = opened(streamSlaHref('5f0c-id'));
    expect(path).toBe('/sla');
    expect(streamOf(query)).toBe('5f0c-id');
  });

  it('reads a plain Logs link as the HTTP table', () => {
    expect(logsViewOf(opened('/logs').query)).toBe('http');
    expect(logsViewOf(opened('/logs?view=other').query)).toBe('http');
  });

  it('keeps the page path free of the query, so the loader map and the sidebar match it', () => {
    expect(splitHash('/logs?view=streams').path).toBe('/logs');
    expect(splitHash('').path).toBe('/');
    expect(splitHash('?view=streams').path).toBe('/');
  });
});
