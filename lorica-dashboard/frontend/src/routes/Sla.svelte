<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    type SlaSummary,
    type RouteResponse,
    type SlaConfigResponse,
    type SlaBucket,
  } from '../lib/api';

  let routes: RouteResponse[] = $state([]);
  let overview: SlaSummary[] = $state([]);
  let error = $state('');
  let loading = $state(true);

  let selectedRouteId = $state('');
  let passiveSla: SlaSummary[] = $state([]);
  let activeSla: SlaSummary[] = $state([]);
  let slaConfig: SlaConfigResponse | null = $state(null);
  let buckets: SlaBucket[] = $state([]);
  let detailLoading = $state(false);

  let showConfigModal = $state(false);
  let cfgTargetPct = $state(99.9);
  let cfgMaxLatency = $state(500);
  let cfgStatusMin = $state(200);
  let cfgStatusMax = $state(399);
  let cfgSaving = $state(false);

  async function loadData() {
    loading = true;
    error = '';
    const [routesRes, overviewRes] = await Promise.all([
      api.listRoutes(),
      api.getSlaOverview(),
    ]);
    if (routesRes.data) routes = routesRes.data.routes;
    if (overviewRes.data) overview = overviewRes.data;
    if (routesRes.error) error = routesRes.error.message;
    loading = false;
  }

  onMount(loadData);

  async function selectRoute(routeId: string) {
    selectedRouteId = routeId;
    detailLoading = true;
    const [passiveRes, activeRes, configRes, bucketsRes] = await Promise.all([
      api.getRouteSla(routeId),
      api.getRouteSlaActive(routeId),
      api.getSlaConfig(routeId),
      api.getRouteSlaBuckets(routeId, { source: 'passive' }),
    ]);
    if (passiveRes.data) passiveSla = passiveRes.data;
    if (activeRes.data) activeSla = activeRes.data;
    if (configRes.data) slaConfig = configRes.data;
    if (bucketsRes.data) buckets = bucketsRes.data;
    detailLoading = false;
  }

  function openConfigModal() {
    if (!slaConfig) return;
    cfgTargetPct = slaConfig.target_pct;
    cfgMaxLatency = slaConfig.max_latency_ms;
    cfgStatusMin = slaConfig.success_status_min;
    cfgStatusMax = slaConfig.success_status_max;
    showConfigModal = true;
  }

  async function saveConfig() {
    cfgSaving = true;
    const res = await api.updateSlaConfig(selectedRouteId, {
      target_pct: cfgTargetPct,
      max_latency_ms: cfgMaxLatency,
      success_status_min: cfgStatusMin,
      success_status_max: cfgStatusMax,
    });
    cfgSaving = false;
    if (res.data) {
      slaConfig = res.data;
      showConfigModal = false;
    }
  }

  async function handleExport(format: 'json' | 'csv') {
    const res = await api.exportSla(selectedRouteId, format);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sla-${selectedRouteId}.${format}`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function slaColor(pct: number, target: number): string {
    if (pct >= target) return 'var(--color-green)';
    if (pct >= target - 1) return 'var(--color-orange)';
    return 'var(--color-red)';
  }

  function getRouteHostname(routeId: string): string {
    return routes.find((r) => r.id === routeId)?.hostname ?? routeId;
  }
</script>

<div class="sla-page">
  <div class="page-header">
    <h1>SLA Monitoring</h1>
  </div>

  {#if error}
    <div class="error-banner">{error}</div>
  {/if}

  {#if loading}
    <p class="loading">Loading SLA data...</p>
  {:else}
    <!-- Overview cards -->
    <div class="overview-grid">
      {#each overview as s}
        {@const hostname = getRouteHostname(s.route_id)}
        <button
          class="sla-card"
          class:selected={selectedRouteId === s.route_id}
          onclick={() => selectRoute(s.route_id)}
        >
          <div class="sla-card-header">
            <span class="sla-hostname">{hostname}</span>
            <span class="sla-window">24h</span>
          </div>
          <div class="sla-pct" style="color: {slaColor(s.sla_pct, s.target_pct)}">
            {s.total_requests > 0 ? s.sla_pct.toFixed(2) + '%' : 'No data'}
          </div>
          <div class="sla-meta">
            <span>{s.total_requests.toLocaleString()} req</span>
            <span>{s.avg_latency_ms.toFixed(0)}ms avg</span>
          </div>
        </button>
      {/each}
      {#if overview.length === 0}
        <p class="text-muted">No routes with SLA data yet.</p>
      {/if}
    </div>

    <!-- Detail view -->
    {#if selectedRouteId}
      <div class="detail-section">
        {#if detailLoading}
          <p class="loading">Loading route SLA...</p>
        {:else}
          <div class="detail-header">
            <h2>{getRouteHostname(selectedRouteId)}</h2>
            <div class="detail-actions">
              <button class="btn btn-small" onclick={openConfigModal}>Configure</button>
              <button class="btn btn-small" onclick={() => handleExport('csv')}>Export CSV</button>
              <button class="btn btn-small" onclick={() => handleExport('json')}>Export JSON</button>
            </div>
          </div>

          <!-- Passive vs Active side-by-side -->
          <div class="sla-comparison">
            <div class="sla-column">
              <h3>Passive SLA (Real Traffic)</h3>
              {#if passiveSla.length > 0}
                <table>
                  <thead><tr><th>Window</th><th>SLA %</th><th>Requests</th><th>p50</th><th>p95</th><th>p99</th></tr></thead>
                  <tbody>
                    {#each passiveSla as s}
                      <tr>
                        <td>{s.window}</td>
                        <td style="color: {slaColor(s.sla_pct, s.target_pct)}; font-weight: 600;">
                          {s.total_requests > 0 ? s.sla_pct.toFixed(2) + '%' : '-'}
                        </td>
                        <td>{s.total_requests.toLocaleString()}</td>
                        <td class="mono">{s.p50_latency_ms}ms</td>
                        <td class="mono">{s.p95_latency_ms}ms</td>
                        <td class="mono">{s.p99_latency_ms}ms</td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              {:else}
                <p class="text-muted">No passive SLA data.</p>
              {/if}
            </div>

            <div class="sla-column">
              <h3>Active SLA (Probes)</h3>
              {#if activeSla.length > 0}
                <table>
                  <thead><tr><th>Window</th><th>SLA %</th><th>Probes</th><th>p50</th><th>p95</th><th>p99</th></tr></thead>
                  <tbody>
                    {#each activeSla as s}
                      <tr>
                        <td>{s.window}</td>
                        <td style="color: {slaColor(s.sla_pct, s.target_pct)}; font-weight: 600;">
                          {s.total_requests > 0 ? s.sla_pct.toFixed(2) + '%' : '-'}
                        </td>
                        <td>{s.total_requests.toLocaleString()}</td>
                        <td class="mono">{s.p50_latency_ms}ms</td>
                        <td class="mono">{s.p95_latency_ms}ms</td>
                        <td class="mono">{s.p99_latency_ms}ms</td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              {:else}
                <p class="text-muted">No active probes configured.</p>
              {/if}
            </div>
          </div>

          <!-- Config info -->
          {#if slaConfig}
            <div class="config-info">
              <span>Target: <strong>{slaConfig.target_pct}%</strong></span>
              <span>Max latency: <strong>{slaConfig.max_latency_ms}ms</strong></span>
              <span>Success: <strong>{slaConfig.success_status_min}-{slaConfig.success_status_max}</strong></span>
            </div>
          {/if}

          <!-- Recent buckets -->
          {#if buckets.length > 0}
            <h3>Recent Buckets (last 24h)</h3>
            <div class="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Requests</th>
                    <th>Success</th>
                    <th>Errors</th>
                    <th>Avg Latency</th>
                    <th>p95</th>
                  </tr>
                </thead>
                <tbody>
                  {#each buckets.slice(-30) as b}
                    <tr>
                      <td class="mono">{new Date(b.bucket_start).toLocaleTimeString()}</td>
                      <td>{b.request_count}</td>
                      <td style="color: var(--color-green)">{b.success_count}</td>
                      <td style="color: {b.error_count > 0 ? 'var(--color-red)' : 'var(--color-text-muted)'}">{b.error_count}</td>
                      <td class="mono">{b.request_count > 0 ? (b.latency_sum_ms / b.request_count).toFixed(0) : 0}ms</td>
                      <td class="mono">{b.latency_p95_ms}ms</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}
        {/if}
      </div>
    {/if}
  {/if}

  <!-- Config modal -->
  {#if showConfigModal}
    <div class="overlay" role="dialog" onclick={(e) => { if (e.target === e.currentTarget) showConfigModal = false; }}>
      <div class="modal">
        <h2>SLA Configuration</h2>
        <div class="form-group">
          <label>Target SLA (%)</label>
          <input type="number" bind:value={cfgTargetPct} step="0.1" min="0" max="100" />
        </div>
        <div class="form-group">
          <label>Max Latency (ms)</label>
          <input type="number" bind:value={cfgMaxLatency} min="1" />
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>Success Status Min</label>
            <input type="number" bind:value={cfgStatusMin} min="100" max="599" />
          </div>
          <div class="form-group">
            <label>Success Status Max</label>
            <input type="number" bind:value={cfgStatusMax} min="100" max="599" />
          </div>
        </div>
        <div class="form-actions">
          <button class="btn btn-cancel" onclick={() => (showConfigModal = false)}>Cancel</button>
          <button class="btn btn-primary" onclick={saveConfig} disabled={cfgSaving}>
            {cfgSaving ? 'Saving...' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .sla-page { max-width: 1200px; }
  .page-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.5rem; }
  .page-header h1 { margin: 0; }
  .error-banner { background: rgba(239, 68, 68, 0.1); border: 1px solid var(--color-red); border-radius: 0.5rem; color: var(--color-red); padding: 0.75rem 1rem; margin-bottom: 1rem; }
  .loading { color: var(--color-text-muted); }
  .text-muted { color: var(--color-text-muted); }

  .overview-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .sla-card { background: var(--color-bg-card); border: 1px solid var(--color-border); border-radius: 0.75rem; padding: 1rem; text-align: left; cursor: pointer; transition: border-color 0.15s; }
  .sla-card:hover { border-color: var(--color-primary); }
  .sla-card.selected { border-color: var(--color-primary); box-shadow: 0 0 0 1px var(--color-primary); }
  .sla-card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
  .sla-hostname { font-weight: 600; font-size: 0.875rem; color: var(--color-text-heading); }
  .sla-window { font-size: 0.75rem; color: var(--color-text-muted); }
  .sla-pct { font-size: 1.5rem; font-weight: 700; margin-bottom: 0.25rem; }
  .sla-meta { display: flex; gap: 1rem; font-size: 0.75rem; color: var(--color-text-muted); }

  .detail-section { margin-top: 1rem; }
  .detail-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1rem; }
  .detail-header h2 { margin: 0; }
  .detail-actions { display: flex; gap: 0.5rem; }

  .sla-comparison { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 1.5rem; }
  .sla-column { background: var(--color-bg-card); border: 1px solid var(--color-border); border-radius: 0.75rem; padding: 1rem; }
  .sla-column h3 { margin: 0 0 0.75rem; font-size: 0.875rem; }

  .config-info { display: flex; gap: 1.5rem; padding: 0.75rem 1rem; background: var(--color-bg-card); border: 1px solid var(--color-border); border-radius: 0.5rem; font-size: 0.8125rem; color: var(--color-text-muted); margin-bottom: 1.5rem; }

  .table-wrapper { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 0.5rem 0.75rem; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--color-text-muted); border-bottom: 1px solid var(--color-border); }
  td { padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--color-border); font-size: 0.8125rem; }
  .mono { font-family: var(--mono); }

  .btn-small { padding: 0.375rem 0.75rem; border-radius: 0.375rem; font-size: 0.8125rem; font-weight: 500; border: 1px solid var(--color-border); background: var(--color-bg-card); color: var(--color-text); cursor: pointer; }
  .btn-small:hover { background: var(--color-bg-hover); }

  .overlay { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.5); display: flex; align-items: center; justify-content: center; z-index: 100; }
  .modal { background: var(--color-bg-card); border: 1px solid var(--color-border); border-radius: 0.75rem; padding: 1.5rem; width: 90%; max-width: 440px; }
  .modal h2 { margin: 0 0 1.25rem; }
  .form-group { margin-bottom: 1rem; }
  .form-group label { display: block; font-size: 0.8125rem; font-weight: 500; color: var(--color-text-muted); margin-bottom: 0.375rem; }
  .form-group input[type="number"] { width: 100%; padding: 0.5rem 0.75rem; border: 1px solid var(--color-border); border-radius: 0.375rem; background: var(--color-bg-input); color: var(--color-text); font-size: 0.875rem; }
  .form-group input:focus { outline: none; border-color: var(--color-primary); }
  .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
  .form-actions { display: flex; justify-content: flex-end; gap: 0.75rem; margin-top: 1.5rem; }
  .btn { padding: 0.5rem 1rem; border-radius: 0.375rem; font-weight: 500; border: none; font-size: 0.875rem; cursor: pointer; }
  .btn-primary { background: var(--color-primary); color: white; }
  .btn-primary:hover { background: var(--color-primary-hover); }
  .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-cancel { background: var(--color-bg-input); color: var(--color-text); }
  .btn-cancel:hover { background: var(--color-bg-hover); }
</style>
