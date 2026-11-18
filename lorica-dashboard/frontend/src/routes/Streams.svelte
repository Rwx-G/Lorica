<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type StreamReadResponse, type StreamStatus } from '../lib/api';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import { canWrite } from '../lib/auth';
  import { nodeRole } from '../lib/cluster';
  import { formatBytes } from '../lib/format';
  import { streamLogsHref, streamSlaHref } from '../lib/stream-links';
  import {
    BIND_STATE_BADGE,
    bindFailures,
    bindSummary,
    describeBindFailure,
    ratesBetween,
    streamBackendCounts,
    streamBadges,
    streamEndpoint,
    type CounterSample,
    type StreamRates,
  } from '../lib/streams';
  import { showToast } from '../lib/toast';

  /** As on the System page: the live counters move every 5 s. */
  const REFRESH_MS = 5000;

  let streams: StreamReadResponse[] = $state([]);
  let statuses: Record<string, StreamStatus> = $state({});
  let rates: Record<string, StreamRates> = $state({});
  // The previous reading of each stream, for the rates; not rendered.
  let lastSamples: Record<string, CounterSample> = {};
  let drainTimeoutS: number | null = $state(null);
  let error = $state('');
  let loading = $state(true);

  let searchQuery = $state('');
  let groupFilter = $state('');
  let sortColumn = $state('');
  let sortDirection: 'asc' | 'desc' = $state('asc');

  let deleting: StreamReadResponse | null = $state(null);
  let togglingId: string | null = $state(null);

  async function loadStreams() {
    const res = await api.listStreams();
    if (res.error) {
      error = res.error.message;
    } else if (res.data) {
      streams = res.data.streams;
      error = '';
    }
    loading = false;
  }

  async function loadStatus() {
    const res = await api.getStreamStatus();
    if (!res.data) return;
    const now = Date.now();
    const nextStatuses: Record<string, StreamStatus> = {};
    const nextRates: Record<string, StreamRates> = {};
    const nextSamples: Record<string, CounterSample> = {};
    for (const status of res.data.streams) {
      nextStatuses[status.id] = status;
      if (!status.counters) continue;
      const sample = { at: now, counters: status.counters };
      const previous = lastSamples[status.id];
      if (previous) nextRates[status.id] = ratesBetween(previous, sample);
      nextSamples[status.id] = sample;
    }
    statuses = nextStatuses;
    rates = nextRates;
    lastSamples = nextSamples;
  }

  async function loadDrainTimeout() {
    const res = await api.getSettings();
    if (res.data) drainTimeoutS = res.data.worker_drain_timeout_s;
  }

  async function reload() {
    await Promise.all([loadStreams(), loadStatus()]);
  }

  onMount(() => {
    void reload();
    void loadDrainTimeout();
    const timer = setInterval(() => {
      if (document.visibilityState === 'visible') void loadStatus();
    }, REFRESH_MS);
    return () => clearInterval(timer);
  });

  async function toggleEnabled(stream: StreamReadResponse) {
    if (togglingId === stream.id) return;
    togglingId = stream.id;
    const res = await api.updateStream(stream.id, { enabled: !stream.enabled });
    togglingId = null;
    if (res.error) {
      showToast(`Failed to ${stream.enabled ? 'disable' : 'enable'} ${stream.name}: ${res.error.message}`, 'error');
      return;
    }
    showToast(`${stream.name} ${stream.enabled ? 'disabled' : 'enabled'}`, 'success');
    await reload();
  }

  async function handleDelete() {
    const target = deleting;
    deleting = null;
    if (!target) return;
    const res = await api.deleteStream(target.id);
    if (res.error) {
      error = res.error.message;
      return;
    }
    showToast(`Stream ${target.name} deleted`, 'success');
    await reload();
  }

  /** What a delete does to the connections the stream holds (Story 12.2 AC #8). */
  function deleteMessage(stream: StreamReadResponse): string {
    const drain = drainTimeoutS === null ? 'the drain timeout (Settings)' : `${drainTimeoutS} s`;
    return `Delete the stream ${stream.name}? Its listening ports close on every node. Established connections drain for ${drain}, then close with the end reason config_removed. This action cannot be undone.`;
  }

  function disableHint(stream: StreamReadResponse): string {
    return stream.enabled
      ? 'Disable: the stream is unbound on every node, its connections drain, and its ports stay reserved'
      : 'Enable';
  }

  /** Same pill colour as Routes for the same group name. */
  function groupHue(name: string): number {
    let hash = 0x811c9dc5;
    for (let i = 0; i < name.length; i++) {
      hash = (hash ^ name.charCodeAt(i)) >>> 0;
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return hash % 360;
  }

  function endpointOf(s: StreamReadResponse): string {
    return streamEndpoint(s.listen_address, s.port_first, s.port_last);
  }

  function perSecond(value: number | null | undefined, unit: 'bytes' | 'count'): string {
    if (value === null || value === undefined) return '-';
    return unit === 'bytes' ? `${formatBytes(value)}/s` : `${value.toFixed(1)}/s`;
  }

  const SORT_KEYS: Record<string, (s: StreamReadResponse) => string | number> = {
    name: (s) => s.name,
    protocol: (s) => s.protocol,
    endpoint: (s) => endpointOf(s),
    backends: (s) => streamBackendCounts(s).primaries + streamBackendCounts(s).backups,
    bind: (s) => bindSummary(statuses[s.id] ?? null)?.state ?? '',
    traffic: (s) => statuses[s.id]?.counters?.active ?? -1,
    enabled: (s) => (s.enabled ? 1 : 0),
  };

  function toggleSort(col: string) {
    if (sortColumn === col) {
      sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
    } else {
      sortColumn = col;
      sortDirection = 'asc';
    }
  }

  function sortMark(col: string): string {
    if (sortColumn !== col) return '';
    return sortDirection === 'asc' ? '↑' : '↓';
  }

  const availableGroups: string[] = $derived.by(() => {
    const seen: Record<string, true> = {};
    for (const s of streams) if (s.group_name) seen[s.group_name] = true;
    return Object.keys(seen).sort();
  });

  const visible: StreamReadResponse[] = $derived.by(() => {
    let result = streams;
    const q = searchQuery.trim().toLowerCase();
    if (q) {
      result = result.filter(
        (s) =>
          s.name.toLowerCase().includes(q) ||
          s.group_name.toLowerCase().includes(q) ||
          endpointOf(s).toLowerCase().includes(q),
      );
    }
    if (groupFilter === '_none') result = result.filter((s) => !s.group_name);
    else if (groupFilter) result = result.filter((s) => s.group_name === groupFilter);
    const key = SORT_KEYS[sortColumn];
    if (key) {
      result = [...result].sort((a, b) => {
        const va = key(a);
        const vb = key(b);
        if (va < vb) return sortDirection === 'asc' ? -1 : 1;
        if (va > vb) return sortDirection === 'asc' ? 1 : -1;
        return 0;
      });
    }
    return result;
  });

  const COLUMNS: { key: string; label: string }[] = [
    { key: 'name', label: 'Stream' },
    { key: 'protocol', label: 'Protocol' },
    { key: 'endpoint', label: 'Endpoint' },
    { key: 'backends', label: 'Backends' },
    { key: 'bind', label: 'Bind' },
    { key: 'traffic', label: 'Traffic on this node' },
    { key: 'enabled', label: 'Enabled' },
  ];
</script>

<div class="streams-page">
  <div class="page-header">
    <h1>Streams</h1>
  </div>

  {#if $nodeRole === 'control_plane'}
    <p class="text-muted fleet-note">
      Traffic figures are this node's own counters; most stream traffic runs on
      the followers that bind the streams. The fleet's view is the
      <a href="#/sla">stream SLA</a>.
    </p>
  {/if}

  {#if error}
    <div class="error-banner" role="alert">{error}</div>
  {/if}

  {#if loading}
    <p class="loading">Loading...</p>
  {:else if streams.length === 0}
    <div class="empty-state">
      <p>No streams configured yet. A stream forwards TCP connections or UDP datagrams from a listening port to its backends.</p>
    </div>
  {:else}
    <div class="filter-bar">
      <input
        type="text"
        class="search-input"
        bind:value={searchQuery}
        placeholder="Search by name, group or endpoint..."
        aria-label="Search streams"
      />
      {#if availableGroups.length > 0}
        <select class="group-filter" bind:value={groupFilter} aria-label="Filter by group">
          <option value="">All groups</option>
          <option value="_none">Ungrouped</option>
          {#each availableGroups as g (g)}
            <option value={g}>{g}</option>
          {/each}
        </select>
      {/if}
    </div>
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            {#each COLUMNS as col (col.key)}
              <th
                class="sortable"
                tabindex="0"
                role="button"
                onclick={() => toggleSort(col.key)}
                onkeydown={(e) => { if (e.key === 'Enter') toggleSort(col.key); }}
              >{col.label} {sortMark(col.key)}</th>
            {/each}
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {#each visible as stream (stream.id)}
            {@const status = statuses[stream.id] ?? null}
            {@const summary = bindSummary(status)}
            {@const failures = bindFailures(status)}
            {@const counts = streamBackendCounts(stream)}
            {@const counters = status?.counters ?? null}
            <tr class:row-disabled={!stream.enabled}>
              <td class="name">
                {stream.name}
                {#if stream.group_name}
                  <span class="group-pill" style="--pill-hue: {groupHue(stream.group_name)}" title="Group: {stream.group_name}">{stream.group_name}</span>
                {/if}
                <div class="badges">
                  {#each streamBadges(stream, status) as b (b.kind)}
                    <span class="badge {b.className}" title={b.help}>{b.label}</span>
                  {/each}
                </div>
              </td>
              <td>{stream.protocol.toUpperCase()}{stream.tls_mode !== 'none' ? ` / TLS ${stream.tls_mode}` : ''}</td>
              <td class="mono">{endpointOf(stream)}</td>
              <td>
                {#if counts.primaries + counts.backups === 0}
                  <span class="text-muted">None</span>
                {:else}
                  {counts.primaries} primary{counts.backups > 0 ? `, ${counts.backups} backup` : ''}
                {/if}
              </td>
              <td>
                {#if summary}
                  <span class="badge {BIND_STATE_BADGE[summary.state]}">{summary.label}</span>
                  {#each failures as f (f.node)}
                    <div class="failure" title={describeBindFailure(f)}>{f.node}: {f.kind ?? 'failed'}{f.port !== undefined ? ` (port ${f.port})` : ''}</div>
                  {/each}
                {:else}
                  <span class="text-muted" title="Not bound on this node: disabled, not targeted here, or not reconciled yet">-</span>
                {/if}
              </td>
              <td class="traffic">
                {#if counters}
                  <div>{counters.active} active{counters.pending > 0 ? `, ${counters.pending} pending` : ''}</div>
                  <div class="text-muted">
                    {perSecond(rates[stream.id]?.accepted_per_s, 'count')} new,
                    up {perSecond(rates[stream.id]?.upload_bytes_per_s, 'bytes')},
                    down {perSecond(rates[stream.id]?.download_bytes_per_s, 'bytes')}
                  </div>
                {:else}
                  <span class="text-muted" title="Nothing has counted this stream on this node yet">-</span>
                {/if}
              </td>
              <td>
                <span class="enabled-indicator" class:on={stream.enabled}>{stream.enabled ? 'Yes' : 'No'}</span>
              </td>
              <td class="actions">
                <a class="btn btn-secondary btn-sm" href={streamLogsHref(stream.id)} title="Access log of {stream.name}">Logs</a>
                <a class="btn btn-secondary btn-sm" href={streamSlaHref(stream.id)} title="SLA of {stream.name}">SLA</a>
                {#if $canWrite}
                  <button
                    class="btn btn-secondary btn-sm"
                    title={disableHint(stream)}
                    aria-label="{stream.enabled ? 'Disable' : 'Enable'} {stream.name}"
                    disabled={togglingId === stream.id}
                    onclick={() => void toggleEnabled(stream)}
                  >{stream.enabled ? 'Disable' : 'Enable'}</button>
                  <button class="btn btn-danger btn-sm" aria-label="Delete {stream.name}" onclick={() => (deleting = stream)}>Delete</button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

{#if deleting}
  <ConfirmDialog
    title="Delete Stream"
    message={deleteMessage(deleting)}
    onconfirm={() => void handleDelete()}
    oncancel={() => (deleting = null)}
  />
{/if}

<style>
  .streams-page { max-width: none; }
  .fleet-note { margin: 0 0 var(--space-4); font-size: var(--text-sm); }
  .filter-bar { display: flex; gap: var(--space-2); margin-bottom: var(--space-4); }
  .search-input { width: 100%; max-width: 400px; padding: var(--space-2) var(--space-3); border: 1px solid var(--color-border); border-radius: var(--radius-md); background: var(--color-bg-input); color: var(--color-text); font-size: var(--text-md); }
  .search-input:focus { outline: none; border-color: var(--color-primary); box-shadow: 0 0 0 3px var(--color-primary-subtle); }
  .group-filter { padding: 0.375rem 0.5rem; border: 1px solid var(--color-border); border-radius: 0.375rem; background: var(--color-bg-input); color: var(--color-text); font-size: 0.875rem; }
  .sortable { cursor: pointer; user-select: none; white-space: nowrap; }
  .sortable:hover { color: var(--color-text-heading); }
  .name { font-weight: 600; color: var(--color-text-heading); }
  .badges { display: flex; flex-wrap: wrap; gap: var(--space-1); margin-top: var(--space-1); font-weight: 400; }
  .badges .badge { cursor: help; font-size: var(--text-xs); }
  .group-pill {
    display: inline-block;
    padding: 0.125rem 0.5rem;
    margin-left: var(--space-2);
    border-radius: var(--radius-full, 9999px);
    background: hsl(var(--pill-hue) 55% 35% / 0.18);
    color: hsl(var(--pill-hue) 60% 45%);
    border: 1px solid hsl(var(--pill-hue) 55% 35% / 0.35);
    font-size: var(--text-xs);
    font-weight: 600;
  }
  .failure { font-size: var(--text-xs); color: var(--color-red-text); margin-top: var(--space-1); cursor: help; }
  .traffic { font-size: var(--text-sm); white-space: nowrap; }
  .enabled-indicator { color: var(--color-text-muted); }
  .enabled-indicator.on { color: var(--color-green); }
  tr.row-disabled td { opacity: 0.7; }
  .actions { display: flex; gap: var(--space-1); flex-wrap: wrap; }
  .btn-sm { padding: var(--space-1) var(--space-2); font-size: var(--text-sm); text-decoration: none; }
</style>
