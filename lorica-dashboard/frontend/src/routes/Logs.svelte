<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { api, type LogEntry, type LogsQuery } from '../lib/api';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';

  let entries: LogEntry[] = $state([]);
  let total = $state(0);
  let error = $state('');
  let loading = $state(true);
  let showClearConfirm = $state(false);

  // Filters
  let searchText = $state('');
  let filterRoute = $state('');
  let filterClientIp = $state('');
  let filterStatusCategory = $state('');
  let filterTimeRange = $state('');
  let autoRefresh = $state(true);

  // Export controls
  let showExport = $state(false);
  let exportFormat = $state<'csv' | 'json'>('csv');
  let exportFrom = $state('');
  let exportTo = $state('');

  // Initialize default export date range (last 24 hours)
  function initExportDefaults() {
    const now = new Date();
    const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    // Format as datetime-local value (YYYY-MM-DDTHH:MM)
    exportTo = now.toISOString().slice(0, 16);
    exportFrom = yesterday.toISOString().slice(0, 16);
  }

  function exportLogs() {
    const params = new URLSearchParams();
    if (exportFrom) params.set('time_from', new Date(exportFrom).toISOString());
    if (exportTo) params.set('time_to', new Date(exportTo).toISOString());
    params.set('format', exportFormat);
    window.open(`/api/v1/logs/export?${params}`, '_blank');
  }

  let refreshInterval: ReturnType<typeof setInterval> | null = null;
  let ws: WebSocket | null = null;
  let wsConnected = $state(false);

  function connectWebSocket() {
    if (ws) return;
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${proto}//${location.host}/api/v1/logs/ws`);

    ws.onopen = () => {
      wsConnected = true;
      stopAutoRefresh(); // No need to poll when WS is active
    };

    ws.onmessage = (event) => {
      try {
        const entry: LogEntry = JSON.parse(event.data);
        // Apply client-side filters before adding
        if (matchesFilters(entry)) {
          entries = [...entries.slice(-499), entry];
          total = entries.length;
        }
      } catch { /* ignore malformed messages */ }
    };

    ws.onclose = () => {
      wsConnected = false;
      ws = null;
      // Fall back to polling if WS disconnects
      if (autoRefresh) startAutoRefresh();
    };

    ws.onerror = () => {
      ws?.close();
    };
  }

  function disconnectWebSocket() {
    ws?.close();
    ws = null;
    wsConnected = false;
  }

  function matchesFilters(e: LogEntry): boolean {
    if (filterStatusCategory === '2xx' && (e.status < 200 || e.status > 299)) return false;
    if (filterStatusCategory === '3xx' && (e.status < 300 || e.status > 399)) return false;
    if (filterStatusCategory === '4xx' && (e.status < 400 || e.status > 499)) return false;
    if (filterStatusCategory === '5xx' && (e.status < 500 || e.status > 599)) return false;
    if (searchText.trim()) {
      const s = searchText.trim().toLowerCase();
      if (!e.method.toLowerCase().includes(s)
        && !e.path.toLowerCase().includes(s)
        && !e.host.toLowerCase().includes(s)
        && !e.backend.toLowerCase().includes(s)) return false;
    }
    if (filterRoute.trim() && !e.host.includes(filterRoute.trim())) return false;
    if (filterClientIp.trim() && !e.client_ip.startsWith(filterClientIp.trim())) return false;
    return true;
  }

  async function loadLogs() {
    const params: LogsQuery = { limit: 500 };
    if (searchText.trim()) params.search = searchText.trim();
    if (filterRoute.trim()) params.route = filterRoute.trim();
    if (filterClientIp.trim()) params.client_ip = filterClientIp.trim();
    if (filterStatusCategory === '2xx') { params.status_min = 200; params.status_max = 299; }
    else if (filterStatusCategory === '3xx') { params.status_min = 300; params.status_max = 399; }
    else if (filterStatusCategory === '4xx') { params.status_min = 400; params.status_max = 499; }
    else if (filterStatusCategory === '5xx') { params.status_min = 500; params.status_max = 599; }

    if (filterTimeRange) {
      const now = new Date();
      let from: Date;
      if (filterTimeRange === '5m') from = new Date(now.getTime() - 5 * 60 * 1000);
      else if (filterTimeRange === '15m') from = new Date(now.getTime() - 15 * 60 * 1000);
      else if (filterTimeRange === '1h') from = new Date(now.getTime() - 60 * 60 * 1000);
      else if (filterTimeRange === '6h') from = new Date(now.getTime() - 6 * 60 * 60 * 1000);
      else from = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      params.time_from = from.toISOString();
    }

    const res = await api.getLogs(params);
    if (res.error) {
      error = res.error.message;
    } else if (res.data) {
      entries = res.data.entries;
      total = res.data.total;
      error = '';
    }
    loading = false;
  }

  async function handleClearLogs() {
    const res = await api.clearLogs();
    if (res.error) {
      error = res.error.message;
    } else {
      entries = [];
      total = 0;
    }
  }

  function startAutoRefresh() {
    stopAutoRefresh();
    if (autoRefresh) {
      refreshInterval = setInterval(loadLogs, 5000);
    }
  }

  function stopAutoRefresh() {
    if (refreshInterval) {
      clearInterval(refreshInterval);
      refreshInterval = null;
    }
  }

  function statusColor(status: number): string {
    if (status >= 500) return 'var(--color-red)';
    if (status >= 400) return 'var(--color-orange)';
    if (status >= 300) return 'var(--color-text-muted)';
    if (status >= 200) return 'var(--color-green)';
    return 'var(--color-text)';
  }

  function formatTimestamp(ts: string): string {
    try {
      const d = new Date(ts);
      return d.toLocaleString([], { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return ts;
    }
  }

  onMount(() => {
    loadLogs();          // Initial load via REST
    connectWebSocket();  // Then switch to real-time WS
  });

  onDestroy(() => {
    stopAutoRefresh();
    disconnectWebSocket();
  });

  // Restart auto-refresh when toggle changes
  $effect(() => {
    if (autoRefresh) {
      startAutoRefresh();
    } else {
      stopAutoRefresh();
    }
  });

  const statusCategories = [
    { value: '', label: 'All statuses' },
    { value: '2xx', label: '2xx Success' },
    { value: '3xx', label: '3xx Redirect' },
    { value: '4xx', label: '4xx Client Error' },
    { value: '5xx', label: '5xx Server Error' },
  ];

  const timeRanges = [
    { value: '', label: 'All time' },
    { value: '5m', label: 'Last 5 min' },
    { value: '15m', label: 'Last 15 min' },
    { value: '1h', label: 'Last 1 hour' },
    { value: '6h', label: 'Last 6 hours' },
    { value: '24h', label: 'Last 24 hours' },
  ];
</script>

<div class="logs-page">
  <div class="page-header">
    <h1>Access Logs</h1>
    <div class="header-actions">
      <label class="auto-refresh">
        <input type="checkbox" bind:checked={autoRefresh} />
        <span>{wsConnected ? 'Live (WebSocket)' : 'Auto-refresh (5s)'}</span>
        {#if wsConnected}<span class="ws-dot" title="WebSocket connected"></span>{/if}
      </label>
      <button class="btn btn-secondary" onclick={loadLogs}>Refresh</button>
      <button
        class="btn btn-secondary"
        onclick={() => { if (!showExport) initExportDefaults(); showExport = !showExport; }}
      >Export</button>
      <button class="btn btn-danger" onclick={() => (showClearConfirm = true)}>Clear</button>
    </div>
  </div>

  {#if showExport}
    <div class="export-panel">
      <div class="export-row">
        <label class="export-label">
          From
          <input type="datetime-local" class="export-input" bind:value={exportFrom} />
        </label>
        <label class="export-label">
          To
          <input type="datetime-local" class="export-input" bind:value={exportTo} />
        </label>
        <label class="export-label">
          Format
          <select class="export-select" bind:value={exportFormat}>
            <option value="csv">CSV</option>
            <option value="json">JSON</option>
          </select>
        </label>
        <button class="btn btn-primary" onclick={exportLogs}>Download</button>
      </div>
    </div>
  {/if}

  <div class="filters">
    <input
      type="text"
      class="filter-input search-input"
      placeholder="Search logs..."
      bind:value={searchText}
      onkeydown={(e) => { if (e.key === 'Enter') loadLogs(); }}
    />
    <input
      type="text"
      class="filter-input ip-input"
      placeholder="Filter by Client IP..."
      bind:value={filterClientIp}
      onkeydown={(e) => { if (e.key === 'Enter') loadLogs(); }}
    />
    <input
      type="text"
      class="filter-input route-input"
      placeholder="Filter by host..."
      bind:value={filterRoute}
      onkeydown={(e) => { if (e.key === 'Enter') loadLogs(); }}
    />
    <select class="filter-select" bind:value={filterStatusCategory} onchange={loadLogs}>
      {#each statusCategories as cat}
        <option value={cat.value}>{cat.label}</option>
      {/each}
    </select>
    <select class="filter-select" bind:value={filterTimeRange} onchange={loadLogs}>
      {#each timeRanges as tr}
        <option value={tr.value}>{tr.label}</option>
      {/each}
    </select>
    <span class="entry-count">{total} entries</span>
  </div>

  {#if error}
    <div class="error-banner">{error}</div>
  {/if}

  {#if loading}
    <p class="loading">Loading...</p>
  {:else if entries.length === 0}
    <div class="empty-state">
      <p>No log entries yet. Logs appear when requests are proxied.</p>
    </div>
  {:else}
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Method</th>
            <th>Client IP</th>
            <th>Host</th>
            <th>Path</th>
            <th>Status</th>
            <th>Latency</th>
            <th>Backend</th>
            <th>Error</th>
          </tr>
        </thead>
        <tbody>
          {#each [...entries].reverse() as entry (entry.id)}
            <tr>
              <td class="mono time-col">{formatTimestamp(entry.timestamp)}</td>
              <td class="method-col">
                <span class="method-badge">{entry.method}</span>
              </td>
              <td class="mono ip-col">
                {#if entry.source === 'loadtest'}
                  <span class="source-badge loadtest" title="Request from Lorica load test engine">Load Test</span>
                {:else if entry.client_ip === '127.0.0.1' && !entry.is_xff}
                  <span class="source-badge internal" title="Request from localhost (health check or internal)">Internal</span>
                {:else}
                  {entry.client_ip || '-'}
                  {#if entry.is_xff}
                    <span class="xff-indicator" title="IP from X-Forwarded-For{entry.xff_proxy_ip ? ` - forwarded by ${entry.xff_proxy_ip}` : ''}">(i)</span>
                  {/if}
                {/if}
              </td>
              <td class="host-col">{entry.host}</td>
              <td class="mono path-col" title={entry.path}>{entry.path}</td>
              <td>
                <span class="status-code" style="color: {statusColor(entry.status)}">
                  {entry.status}
                </span>
              </td>
              <td class="mono">{entry.latency_ms}ms</td>
              <td class="mono backend-col">{entry.backend}</td>
              <td class="error-col">
                {#if entry.error}
                  <span class="error-text" title={entry.error}>{entry.error}</span>
                {:else}
                  <span class="text-muted">-</span>
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
      title="Clear Logs"
      message="This will permanently delete all log entries. This action cannot be undone."
      confirmLabel="Clear"
      onconfirm={() => { showClearConfirm = false; handleClearLogs(); }}
      oncancel={() => (showClearConfirm = false)}
    />
  {/if}
</div>

<style>
  .logs-page { max-width: none; }

  .header-actions {
    display: flex;
    align-items: center;
    gap: var(--space-3);
  }

  .auto-refresh {
    display: flex;
    align-items: center;
    gap: 0.375rem;
    font-size: var(--text-base);
    color: var(--color-text-muted);
    cursor: pointer;
  }

  .auto-refresh input {
    accent-color: var(--color-primary);
  }

  .export-panel {
    padding: var(--space-3) var(--space-4);
    margin-bottom: var(--space-4);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg-card);
  }

  .export-row {
    display: flex;
    align-items: flex-end;
    gap: var(--space-4);
    flex-wrap: wrap;
  }

  .export-label {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    font-size: var(--text-sm);
    color: var(--color-text-muted);
    font-weight: 500;
  }

  .export-input,
  .export-select {
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: var(--text-md);
  }

  .export-input:focus,
  .export-select:focus {
    outline: none;
    border-color: var(--color-primary);
    box-shadow: 0 0 0 3px var(--color-primary-subtle);
  }

  .filters {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    margin-bottom: var(--space-4);
  }

  .filter-input {
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: var(--text-md);
  }

  .filter-input:focus {
    outline: none;
    border-color: var(--color-primary);
    box-shadow: 0 0 0 3px var(--color-primary-subtle);
  }

  .search-input {
    flex: 1;
    min-width: 200px;
  }

  .route-input {
    width: 180px;
  }

  .ip-input {
    width: 160px;
  }

  .filter-select {
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: var(--text-md);
  }

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

  .method-badge {
    display: inline-block;
    padding: 0.0625rem 0.375rem;
    border-radius: var(--radius-sm);
    font-size: 0.6875rem;
    font-weight: 600;
    font-family: var(--mono);
    background: var(--color-primary-subtle);
    color: var(--color-primary);
  }

  .ip-col {
    white-space: nowrap;
  }

  .xff-indicator {
    display: inline-block;
    font-size: 0.625rem;
    font-weight: 700;
    color: var(--color-primary);
    margin-left: 0.25rem;
    cursor: help;
  }

  .source-badge {
    display: inline-block;
    font-size: 0.625rem;
    font-weight: 600;
    padding: 0.1rem 0.375rem;
    border-radius: 9999px;
    cursor: help;
  }

  .source-badge.loadtest {
    background: rgba(245, 158, 11, 0.15);
    color: var(--color-orange);
  }

  .source-badge.internal {
    background: rgba(148, 163, 184, 0.15);
    color: var(--color-text-muted);
  }

  .host-col {
    max-width: 180px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .path-col {
    max-width: 250px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .status-code {
    font-family: var(--mono);
    font-weight: 600;
    font-size: var(--text-base);
  }

  .backend-col {
    max-width: 160px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--color-text-muted);
  }

  .error-col {
    max-width: 200px;
  }

  .error-text {
    color: var(--color-red);
    font-size: var(--text-sm);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    display: block;
    max-width: 200px;
  }

  .ws-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--color-green);
    margin-left: 6px;
    vertical-align: middle;
    animation: pulse 2s ease-in-out infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }
</style>
