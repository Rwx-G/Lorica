<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { api, type LogEntry, type LogsQuery } from '../lib/api';

  let entries: LogEntry[] = $state([]);
  let total = $state(0);
  let error = $state('');
  let loading = $state(true);

  // Filters
  let searchText = $state('');
  let filterRoute = $state('');
  let filterStatusCategory = $state('');
  let filterTimeRange = $state('');
  let autoRefresh = $state(true);

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
    return true;
  }

  async function loadLogs() {
    const params: LogsQuery = { limit: 500 };
    if (searchText.trim()) params.search = searchText.trim();
    if (filterRoute.trim()) params.route = filterRoute.trim();
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
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
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
      <button class="btn btn-danger" onclick={handleClearLogs}>Clear</button>
    </div>
  </div>

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
</div>

<style>
  .logs-page {
    max-width: 1400px;
  }

  .page-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 1rem;
  }

  .page-header h1 {
    margin: 0;
  }

  .header-actions {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .auto-refresh {
    display: flex;
    align-items: center;
    gap: 0.375rem;
    font-size: 0.8125rem;
    color: var(--color-text-muted);
    cursor: pointer;
  }

  .auto-refresh input {
    accent-color: var(--color-primary);
  }

  .filters {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 1rem;
  }

  .filter-input {
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
  }

  .filter-input:focus {
    outline: none;
    border-color: var(--color-primary);
  }

  .search-input {
    flex: 1;
    min-width: 200px;
  }

  .route-input {
    width: 180px;
  }

  .filter-select {
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
  }

  .filter-select:focus {
    outline: none;
    border-color: var(--color-primary);
  }

  .entry-count {
    font-size: 0.8125rem;
    color: var(--color-text-muted);
    white-space: nowrap;
  }

  .error-banner {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid var(--color-red);
    border-radius: 0.5rem;
    color: var(--color-red);
    padding: 0.75rem 1rem;
    margin-bottom: 1rem;
  }

  .loading {
    color: var(--color-text-muted);
  }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 3rem 0;
    color: var(--color-text-muted);
  }

  .table-wrapper {
    overflow-x: auto;
  }

  table {
    width: 100%;
    border-collapse: collapse;
  }

  th {
    text-align: left;
    padding: 0.5rem 0.75rem;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--color-text-muted);
    border-bottom: 1px solid var(--color-border);
    white-space: nowrap;
  }

  td {
    padding: 0.375rem 0.75rem;
    border-bottom: 1px solid var(--color-border);
    font-size: 0.8125rem;
    vertical-align: middle;
  }

  tr:hover td {
    background: rgba(255, 255, 255, 0.02);
  }

  .mono {
    font-family: var(--mono);
    font-size: 0.75rem;
  }

  .time-col {
    white-space: nowrap;
    color: var(--color-text-muted);
  }

  .method-badge {
    display: inline-block;
    padding: 0.0625rem 0.375rem;
    border-radius: 0.25rem;
    font-size: 0.6875rem;
    font-weight: 600;
    font-family: var(--mono);
    background: rgba(59, 130, 246, 0.1);
    color: var(--color-primary);
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
    font-size: 0.8125rem;
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
    font-size: 0.75rem;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    display: block;
    max-width: 200px;
  }

  .text-muted {
    color: var(--color-text-muted);
  }

  .btn {
    padding: 0.5rem 1rem;
    border-radius: 0.375rem;
    font-weight: 500;
    border: none;
    font-size: 0.875rem;
  }

  .btn-secondary {
    background: var(--color-bg-input);
    color: var(--color-text);
  }

  .btn-secondary:hover {
    background: var(--color-bg-hover);
  }

  .btn-danger {
    background: rgba(239, 68, 68, 0.1);
    color: var(--color-red);
  }

  .btn-danger:hover {
    background: rgba(239, 68, 68, 0.2);
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
