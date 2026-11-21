<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    type StreamLogEntry,
    type StreamLogsFilter,
    type StreamStatus,
  } from '../lib/api';
  import { canReadFleet, canWrite } from '../lib/auth';
  import { nodeScope } from '../lib/cluster';
  import { formatBytes } from '../lib/format';
  import { TIME_RANGES, createScopedLoader, formatLogTimestamp, rangeStart, type LogScope } from '../lib/log-view';
  import ConfirmDialog from './ConfirmDialog.svelte';
  import NodeFilter from './NodeFilter.svelte';

  interface Props {
    /** The stream a link opened the table on, `''` for every stream. */
    initialStreamId?: string;
    /** Re-read the page every 5 s while true. */
    autoRefresh: boolean;
  }

  let { initialStreamId = '', autoRefresh }: Props = $props();

  // Rows reach this table from the store only: the stream log has no
  // live tail, so the page polls.
  const REFRESH_MS = 5000;

  let entries: StreamLogEntry[] = $state([]);
  let total = $state(0);
  let error = $state('');
  let loading = $state(true);
  let streams: StreamStatus[] = $state([]);

  // A link sets the starting filter only; the operator's pick wins after.
  // svelte-ignore state_referenced_locally
  let filterStream = $state(initialStreamId);
  let filterEndReason = $state('');
  let filterRefusalReason = $state('');
  let filterClientIp = $state('');
  let filterTimeRange = $state('');
  let filterLimit = $state(200);

  /**
   * Node filter choice (Story 9.7 D23): `''` for this node, or a
   * follower's id. This node is the default because its own rows never
   * fan in. No "All followers": the server reads one follower's stream
   * rows at a time.
   */
  let filterNode = $state('');
  /**
   * Where the next read goes. Without `canReadFleet` there is no filter,
   * so always here. The filter offers no "All followers", so a fan-in
   * read always names one.
   */
  const scope = $derived.by<LogScope<string>>(() => {
    const choice = $canReadFleet ? nodeScope(filterNode) : { store: 'local' as const };
    return choice.store === 'fan-in' && choice.node ? { store: 'fan-in', node: choice.node } : { store: 'local' };
  });
  /**
   * Which store the rows on screen came from. The Node column and the
   * actions on this node's own log follow it rather than the filter.
   */
  let entriesSource = $state<LogScope<string>['store']>('local');
  /** The follower the fan-in rows on screen came from, for the Node column. */
  let entriesNode = $state('');

  let showExport = $state(false);
  let exportFormat = $state<'csv' | 'json'>('csv');
  let showClearConfirm = $state(false);

  /**
   * The words offered in the reason filters are the ones the rows on
   * screen carry: the dashboard holds no copy of the server's enums, and
   * a word it does not offer can still be typed, the server answering an
   * unknown one with the words it accepts.
   */
  const endReasonsSeen = $derived([...new Set(entries.map((e) => e.end_reason).filter((w) => w))].sort());
  const refusalReasonsSeen = $derived(
    [...new Set(entries.map((e) => e.refusal_reason).filter((w) => w))].sort(),
  );

  function currentFilter(): StreamLogsFilter {
    const filter: StreamLogsFilter = {};
    if (filterStream) filter.stream_id = filterStream;
    if (filterEndReason.trim()) filter.end_reason = filterEndReason.trim();
    if (filterRefusalReason.trim()) filter.refusal_reason = filterRefusalReason.trim();
    if (filterClientIp.trim()) filter.client_ip = filterClientIp.trim();
    const from = rangeStart(filterTimeRange);
    if (from) filter.from = from;
    return filter;
  }

  const readScoped = createScopedLoader();

  async function loadRows() {
    const query = { ...currentFilter(), limit: filterLimit };
    const outcome = await readScoped(scope, {
      local: () => api.getStreamLogs(query),
      // A follower's rows come from the fan-in store, under the same
      // filters, with no count: the count is the page itself.
      fanIn: (node) => api.getFleetStreamLogs(node, query),
      showLocal: (data) => {
        entries = data.entries;
        entriesNode = '';
        entriesSource = 'local';
        total = data.total;
      },
      showFanIn: (data) => {
        entries = data.entries;
        entriesNode = data.node;
        entriesSource = 'fan-in';
        total = data.entries.length;
      },
    });
    if (outcome.stale) return;
    error = outcome.error;
    loading = false;
  }

  /**
   * A new node filter choice. The rows on screen belong to the previous
   * one, possibly in the other store, so they go before the read rather
   * than sitting under the new choice's controls until it lands.
   */
  function selectNode(choice: string) {
    filterNode = choice;
    entries = [];
    entriesNode = '';
    total = 0;
    entriesSource = scope.store;
    error = '';
    loading = true;
    void loadRows();
  }

  async function loadStreams() {
    const res = await api.getStreamStatus();
    if (res.data) streams = res.data.streams;
  }

  async function clearRows() {
    const res = await api.clearStreamLogs();
    if (res.error) {
      error = res.error.message;
    } else {
      entries = [];
      total = 0;
    }
  }

  function download() {
    window.open(api.streamLogsExportUrl(currentFilter(), exportFormat), '_blank');
  }

  onMount(() => {
    void loadStreams();
    void loadRows();
  });

  $effect(() => {
    if (!autoRefresh) return;
    const timer = setInterval(() => void loadRows(), REFRESH_MS);
    return () => clearInterval(timer);
  });

  function client(e: StreamLogEntry): string {
    if (!e.client_ip) return '-';
    const host = e.client_ip.includes(':') ? `[${e.client_ip}]` : e.client_ip;
    return e.client_port ? `${host}:${e.client_port}` : host;
  }

  /** Bytes each way, with the datagram counts a UDP row carries. */
  function traffic(e: StreamLogEntry, direction: 'upload' | 'download'): string {
    const bytes = direction === 'upload' ? e.bytes_upload : e.bytes_download;
    const datagrams = direction === 'upload' ? e.datagrams_upload : e.datagrams_download;
    const size = formatBytes(bytes);
    return datagrams === null ? size : `${size} (${datagrams} dgram)`;
  }

  /** A refusal reads red, a suppressed count orange, any other end neutral. */
  function endBadge(e: StreamLogEntry): string {
    if (e.entry === 'refusals_suppressed') return 'badge-orange';
    if (e.refusal_reason) return 'badge-red';
    return 'badge-gray';
  }
</script>

<div class="stream-log-toolbar">
  <button class="btn btn-secondary" onclick={() => void loadRows()}>Refresh</button>
  <!-- Export and Clear act on this node's own stream log, so they are
       absent while the table shows a follower's rows. -->
  {#if entriesSource === 'local'}
    <button class="btn btn-secondary" onclick={() => (showExport = !showExport)}>Export</button>
    {#if $canWrite}
      <button class="btn btn-danger" onclick={() => (showClearConfirm = true)}>Clear</button>
    {/if}
  {/if}
</div>

{#if showExport && entriesSource === 'local'}
  <div class="export-panel">
    <p class="hint">The rows matching the filters below, oldest first.</p>
    <label class="export-label">
      Format
      <select class="filter-select" bind:value={exportFormat}>
        <option value="csv">CSV</option>
        <option value="json">JSON</option>
      </select>
    </label>
    <button class="btn btn-primary" onclick={download}>Download</button>
  </div>
{/if}

<div class="filters">
  <NodeFilter value={filterNode} onchange={selectNode} />
  <select class="filter-select" aria-label="Stream" bind:value={filterStream} onchange={() => void loadRows()}>
    <option value="">All streams</option>
    {#each streams as s (s.id)}
      <option value={s.id}>{s.name}</option>
    {/each}
    {#if filterStream && !streams.some((s) => s.id === filterStream)}
      <option value={filterStream}>{filterStream}</option>
    {/if}
  </select>
  <input
    type="text"
    class="filter-input"
    aria-label="End reason"
    placeholder="End reason..."
    list="stream-end-reasons"
    bind:value={filterEndReason}
    onkeydown={(e) => { if (e.key === 'Enter') void loadRows(); }}
    onchange={() => void loadRows()}
  />
  <datalist id="stream-end-reasons">
    {#each endReasonsSeen as word (word)}<option value={word}></option>{/each}
  </datalist>
  <input
    type="text"
    class="filter-input"
    aria-label="Refusal reason"
    placeholder="Refusal reason..."
    list="stream-refusal-reasons"
    bind:value={filterRefusalReason}
    onkeydown={(e) => { if (e.key === 'Enter') void loadRows(); }}
    onchange={() => void loadRows()}
  />
  <datalist id="stream-refusal-reasons">
    {#each refusalReasonsSeen as word (word)}<option value={word}></option>{/each}
  </datalist>
  <input
    type="text"
    class="filter-input"
    aria-label="Client IP"
    placeholder="Filter by Client IP..."
    bind:value={filterClientIp}
    onkeydown={(e) => { if (e.key === 'Enter') void loadRows(); }}
  />
  <select class="filter-select" aria-label="Time range" bind:value={filterTimeRange} onchange={() => void loadRows()}>
    {#each TIME_RANGES as tr (tr.value)}
      <option value={tr.value}>{tr.label}</option>
    {/each}
  </select>
  <select class="filter-select" aria-label="Rows" bind:value={filterLimit} onchange={() => void loadRows()}>
    <option value={100}>100</option>
    <option value={200}>200</option>
    <option value={1000}>1 000</option>
    <option value={5000}>5 000</option>
    <option value={10000}>10 000</option>
  </select>
  <span class="entry-count">{entries.length === total ? `${total} entries` : `${entries.length} of ${total} entries`}</span>
</div>

{#if error}
  <div class="error-banner" role="alert">{error}</div>
{/if}

{#if loading}
  <p class="loading">Loading...</p>
{:else if entries.length === 0}
  <div class="empty-state">
    <p>No stream log entries. A row is written when a stream connection or UDP session ends, or is refused.</p>
  </div>
{:else}
  <div class="table-wrapper">
    <table>
      <thead>
        <tr>
          {#if entriesSource === 'fan-in'}
            <th>Node</th>
          {/if}
          <th>Time</th>
          <th>Stream</th>
          <th>Client</th>
          <th class="num">Port</th>
          <th>Backend</th>
          <th class="num">Upload</th>
          <th class="num">Download</th>
          <th class="num">Duration</th>
          <th class="num">Connect</th>
          <th>TLS</th>
          <th>End</th>
        </tr>
      </thead>
      <tbody>
        {#each [...entries].reverse() as entry (entry.id)}
          <tr>
            {#if entriesSource === 'fan-in'}
              <td class="mono">{entriesNode}</td>
            {/if}
            <td class="mono time-col">{formatLogTimestamp(entry.timestamp)}</td>
            <td>
              {entry.stream_name || entry.stream_id}
              <span class="proto">{entry.protocol.toUpperCase()}</span>
            </td>
            <td class="mono" title={entry.proxied_from ? `Through a PROXY header from ${entry.proxied_from}` : undefined}>
              {client(entry)}{#if entry.proxied_from}<span class="proxied" aria-label="through PROXY protocol">(p)</span>{/if}
            </td>
            <td class="num">{entry.listen_port || '-'}</td>
            <td class="mono" title={entry.attempts > 1 ? `${entry.attempts} connect attempts` : undefined}>
              {entry.backend_address || '-'}
            </td>
            {#if entry.entry === 'refusals_suppressed'}
              <td colspan="5" class="text-muted">-</td>
            {:else}
              <td class="num">{traffic(entry, 'upload')}</td>
              <td class="num">{traffic(entry, 'download')}</td>
              <td class="num">{entry.duration_ms} ms</td>
              <td class="num">{entry.connect_ms === null ? '-' : `${entry.connect_ms} ms`}</td>
              <td>
                {#if entry.tls_mode && entry.tls_mode !== 'none'}
                  {entry.tls_mode}{entry.sni ? ` ${entry.sni}` : ''}{entry.alpn ? ` (${entry.alpn})` : ''}
                  {#if entry.client_cert}<span class="text-muted"> client cert {entry.client_cert}</span>{/if}
                {:else}
                  <span class="text-muted">-</span>
                {/if}
              </td>
            {/if}
            <td>
              {#if entry.entry === 'refusals_suppressed'}
                <span class="badge {endBadge(entry)}">{entry.suppressed} refusals suppressed</span>
              {:else}
                <span class="badge {endBadge(entry)}">{entry.end_reason}</span>
                {#if entry.refusal_reason}<span class="refusal">{entry.refusal_reason}</span>{/if}
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

{#if showClearConfirm}
  <ConfirmDialog
    title="Clear Stream Logs"
    message="This will permanently delete every stream log entry. This action cannot be undone."
    confirmLabel="Clear"
    onconfirm={() => { showClearConfirm = false; void clearRows(); }}
    oncancel={() => (showClearConfirm = false)}
  />
{/if}

<style>
  .stream-log-toolbar {
    display: flex;
    gap: var(--space-3);
    margin-bottom: var(--space-4);
  }
  .export-panel {
    display: flex;
    align-items: flex-end;
    gap: var(--space-4);
    flex-wrap: wrap;
    padding: var(--space-3) var(--space-4);
    margin-bottom: var(--space-4);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg-card);
  }
  .export-panel .hint {
    flex-basis: 100%;
    margin: 0;
  }
  .export-label {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    font-size: var(--text-sm);
    color: var(--color-text-muted);
    font-weight: 500;
  }
  .filters {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    margin-bottom: var(--space-4);
    flex-wrap: wrap;
  }
  .filter-input,
  .filter-select {
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: var(--text-md);
  }
  .filter-input {
    width: 170px;
  }
  .filter-input:focus,
  .filter-select:focus {
    outline: none;
    border-color: var(--color-primary);
    box-shadow: 0 0 0 3px var(--color-primary-subtle);
  }
  .entry-count {
    font-size: var(--text-base);
    color: var(--color-text-muted);
    white-space: nowrap;
  }
  .time-col {
    white-space: nowrap;
    color: var(--color-text-muted);
  }
  .proto {
    margin-left: var(--space-1);
    font-size: var(--text-xs);
    color: var(--color-text-muted);
  }
  .proxied {
    margin-left: 0.25rem;
    font-size: var(--text-xs);
    color: var(--color-primary-text);
    cursor: help;
  }
  .refusal {
    margin-left: var(--space-1);
    font-family: var(--mono);
    font-size: var(--text-sm);
  }
</style>
