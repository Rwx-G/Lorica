<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { api, type SystemResponse } from '../lib/api';
  import Card from '../components/Card.svelte';

  let system: SystemResponse | null = $state(null);
  let error = $state('');
  let loading = $state(true);
  let autoRefresh = $state(true);
  let refreshInterval: ReturnType<typeof setInterval> | null = null;

  async function loadSystem() {
    const res = await api.getSystem();
    if (res.error) {
      error = res.error.message;
    } else if (res.data) {
      system = res.data;
      error = '';
    }
    loading = false;
  }

  function startAutoRefresh() {
    stopAutoRefresh();
    if (autoRefresh) {
      refreshInterval = setInterval(loadSystem, 5000);
    }
  }

  function stopAutoRefresh() {
    if (refreshInterval) {
      clearInterval(refreshInterval);
      refreshInterval = null;
    }
  }

  function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    const val = bytes / Math.pow(1024, i);
    return `${val.toFixed(1)} ${units[i]}`;
  }

  function formatUptime(seconds: number): string {
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    const parts: string[] = [];
    if (d > 0) parts.push(`${d}d`);
    if (h > 0) parts.push(`${h}h`);
    if (m > 0) parts.push(`${m}m`);
    parts.push(`${s}s`);
    return parts.join(' ');
  }

  function gaugeColor(percent: number): string {
    if (percent >= 90) return 'var(--color-red)';
    if (percent >= 70) return 'var(--color-orange)';
    return 'var(--color-green)';
  }

  onMount(() => {
    loadSystem();
    startAutoRefresh();
  });

  onDestroy(stopAutoRefresh);

  $effect(() => {
    if (autoRefresh) {
      startAutoRefresh();
    } else {
      stopAutoRefresh();
    }
  });
</script>

<div class="system-page">
  <div class="page-header">
    <h1>System</h1>
    <div class="header-actions">
      <label class="auto-refresh">
        <input type="checkbox" bind:checked={autoRefresh} />
        <span>Auto-refresh (5s)</span>
      </label>
      <button class="btn btn-secondary" onclick={loadSystem}>Refresh</button>
    </div>
  </div>

  {#if error}
    <div class="error-banner">{error}</div>
  {/if}

  {#if loading}
    <p class="loading">Loading...</p>
  {:else if system}
    <h2>Proxy</h2>
    <div class="card-grid">
      <Card title="Version" value={system.proxy.version} />
      <Card title="Uptime" value={formatUptime(system.proxy.uptime_seconds)} />
      <Card title="Active Connections" value={system.proxy.active_connections} />
    </div>

    <h2>Host Resources</h2>
    <div class="gauges-grid">
      <div class="gauge-card">
        <span class="gauge-label">CPU</span>
        <div class="gauge-bar-bg">
          <div
            class="gauge-bar-fill"
            style="width: {system.host.cpu_usage_percent}%; background: {gaugeColor(system.host.cpu_usage_percent)}"
          ></div>
        </div>
        <span class="gauge-value" style="color: {gaugeColor(system.host.cpu_usage_percent)}">
          {system.host.cpu_usage_percent.toFixed(1)}%
        </span>
        <span class="gauge-detail">{system.host.cpu_count} cores</span>
      </div>

      <div class="gauge-card">
        <span class="gauge-label">Memory</span>
        <div class="gauge-bar-bg">
          <div
            class="gauge-bar-fill"
            style="width: {system.host.memory_usage_percent}%; background: {gaugeColor(system.host.memory_usage_percent)}"
          ></div>
        </div>
        <span class="gauge-value" style="color: {gaugeColor(system.host.memory_usage_percent)}">
          {system.host.memory_usage_percent.toFixed(1)}%
        </span>
        <span class="gauge-detail">{formatBytes(system.host.memory_used_bytes)} / {formatBytes(system.host.memory_total_bytes)}</span>
      </div>

      <div class="gauge-card">
        <span class="gauge-label">Disk</span>
        <div class="gauge-bar-bg">
          <div
            class="gauge-bar-fill"
            style="width: {system.host.disk_usage_percent}%; background: {gaugeColor(system.host.disk_usage_percent)}"
          ></div>
        </div>
        <span class="gauge-value" style="color: {gaugeColor(system.host.disk_usage_percent)}">
          {system.host.disk_usage_percent.toFixed(1)}%
        </span>
        <span class="gauge-detail">{formatBytes(system.host.disk_used_bytes)} / {formatBytes(system.host.disk_total_bytes)}</span>
      </div>
    </div>

    <h2>Lorica Process</h2>
    <div class="card-grid">
      <Card title="Process Memory" value={formatBytes(system.process.memory_bytes)} />
      <Card title="Process CPU" value="{system.process.cpu_usage_percent.toFixed(1)}%" />
    </div>
  {/if}
</div>

<style>
  .system-page {
    max-width: 900px;
  }

  .page-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 1.5rem;
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

  h2 {
    margin-top: 1.5rem;
    margin-bottom: 0.75rem;
    font-size: 1rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--color-text-muted);
  }

  .card-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: 1rem;
  }

  .gauges-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
    gap: 1rem;
  }

  .gauge-card {
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-radius: 0.75rem;
    padding: 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .gauge-label {
    font-size: 0.8125rem;
    color: var(--color-text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .gauge-bar-bg {
    width: 100%;
    height: 0.5rem;
    background: var(--color-bg-input);
    border-radius: 9999px;
    overflow: hidden;
  }

  .gauge-bar-fill {
    height: 100%;
    border-radius: 9999px;
    transition: width 0.3s ease;
  }

  .gauge-value {
    font-size: 1.75rem;
    font-weight: 700;
  }

  .gauge-detail {
    font-size: 0.8125rem;
    color: var(--color-text-muted);
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
</style>
