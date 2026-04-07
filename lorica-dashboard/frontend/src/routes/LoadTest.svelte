<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import {
    api,
    type LoadTestConfigResponse,
    type LoadTestResultResponse,
    type LoadTestProgress,
    type LoadTestComparison,
    type CreateLoadTestRequest,
    type UpdateLoadTestRequest,
    type RouteResponse,
  } from '../lib/api';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import { showToast } from '../lib/toast';

  let configs: LoadTestConfigResponse[] = $state([]);
  let routes: RouteResponse[] = $state([]);
  let error = $state('');
  let loading = $state(true);

  // Live test state
  let progress: LoadTestProgress | null = $state(null);
  let sseSource: EventSource | null = $state(null);

  // Results
  let selectedConfigId = $state('');
  let results: LoadTestResultResponse[] = $state([]);
  let comparison: LoadTestComparison | null = $state(null);
  let resultsLoading = $state(false);

  // Form
  let showForm = $state(false);
  let editingConfig: LoadTestConfigResponse | null = $state(null);
  let formName = $state('');
  let formRouteId = $state('');
  let formPathSuffix = $state('/');
  let formMethod = $state('GET');
  let formConcurrency = $state(10);
  let formRps = $state(100);
  let formDuration = $state(30);
  let formErrorThreshold = $state(10.0);
  let formCron = $state('');
  let formError = $state('');
  let formSubmitting = $state(false);

  // Confirm
  let pendingStartId = $state('');
  let startWarnings: string[] = $state([]);
  let showConfirmStart = $state(false);
  let deletingConfig: LoadTestConfigResponse | null = $state(null);

  async function loadData() {
    loading = true;
    error = '';
    const [res, routesRes] = await Promise.all([
      api.listLoadTestConfigs(),
      api.listRoutes(),
    ]);
    if (res.data) configs = res.data;
    if (res.error) error = res.error.message;
    routes = (routesRes.data?.routes ?? []).filter((r) => r.enabled);
    loading = false;
  }

  onMount(() => {
    loadData();
    connectSSE();
  });

  onDestroy(() => {
    if (sseSource) sseSource.close();
  });

  function connectSSE() {
    const es = new EventSource('/api/v1/loadtest/stream');
    es.addEventListener('progress', (e) => {
      try { progress = JSON.parse(e.data); } catch {}
    });
    es.addEventListener('idle', () => {
      if (progress?.active) {
        progress = null;
        // Reload results when test finishes
        if (selectedConfigId) loadResults(selectedConfigId);
      } else {
        progress = null;
      }
    });
    es.onerror = () => {
      progress = null;
    };
    sseSource = es;
  }

  function openCreateForm() {
    editingConfig = null;
    formName = '';
    formRouteId = '';
    formPathSuffix = '/';
    formMethod = 'GET';
    formConcurrency = 10;
    formRps = 100;
    formDuration = 30;
    formErrorThreshold = 10.0;
    formCron = '';
    formError = '';
    showForm = true;
  }

  function openEditForm(config: LoadTestConfigResponse) {
    editingConfig = config;
    formName = config.name;

    // Parse route + path from the existing config's Host header
    const hostHeader = config.headers?.Host ?? '';
    const matched = routes.find((r) => r.hostname === hostHeader);
    formRouteId = matched?.id ?? '';

    // Extract path suffix from the target_url
    try {
      const u = new URL(config.target_url);
      formPathSuffix = u.pathname || '/';
    } catch {
      formPathSuffix = '/';
    }

    formMethod = config.method;
    formConcurrency = config.concurrency;
    formRps = config.requests_per_second;
    formDuration = config.duration_s;
    formErrorThreshold = config.error_threshold_pct;
    formCron = config.schedule_cron ?? '';
    formError = '';
    showForm = true;
  }

  function validate(): string {
    if (!formName.trim()) return 'Name is required';
    if (!formRouteId) return 'Select a route';
    if (formConcurrency < 1 || formConcurrency > 10000) return 'Concurrency must be between 1 and 10000';
    if (formRps < 1 || formRps > 100000) return 'Requests/sec must be between 1 and 100000';
    if (formDuration < 5 || formDuration > 3600) return 'Duration must be between 5 and 3600 seconds';
    if (formErrorThreshold < 1 || formErrorThreshold > 100) return 'Error threshold must be between 1 and 100%';
    return '';
  }

  async function handleSubmit() {
    const err = validate();
    if (err) {
      formError = err;
      return;
    }

    const selectedRoute = routes.find((r) => r.id === formRouteId);
    if (!selectedRoute) {
      formError = 'Select a route';
      return;
    }

    // Build target URL pointing to the local proxy
    const proto = selectedRoute.certificate_id ? 'https' : 'http';
    const port = selectedRoute.certificate_id ? 8443 : 8080;
    const suffix = formPathSuffix.startsWith('/') ? formPathSuffix : `/${formPathSuffix}`;
    const targetUrl = `${proto}://127.0.0.1:${port}${suffix}`;
    const headers: Record<string, string> = { Host: selectedRoute.hostname };

    formSubmitting = true;
    formError = '';

    if (editingConfig) {
      const body: UpdateLoadTestRequest = {
        name: formName,
        target_url: targetUrl,
        method: formMethod,
        headers,
        concurrency: formConcurrency,
        requests_per_second: formRps,
        duration_s: formDuration,
        error_threshold_pct: formErrorThreshold,
        schedule_cron: formCron || undefined,
      };
      const res = await api.updateLoadTestConfig(editingConfig.id, body);
      formSubmitting = false;
      if (res.error) { formError = res.error.message; return; }
      showToast('Test config updated', 'success');
    } else {
      const body: CreateLoadTestRequest = {
        name: formName,
        target_url: targetUrl,
        method: formMethod,
        headers,
        concurrency: formConcurrency,
        requests_per_second: formRps,
        duration_s: formDuration,
        error_threshold_pct: formErrorThreshold,
        schedule_cron: formCron || undefined,
      };
      const res = await api.createLoadTestConfig(body);
      formSubmitting = false;
      if (res.error) { formError = res.error.message; return; }
      showToast('Test config created', 'success');
    }

    showForm = false;
    editingConfig = null;
    await loadData();
  }

  async function handleStart(configId: string) {
    const res = await api.startLoadTest(configId);
    if (res.error) { error = res.error.message; return; }
    if (res.data?.status === 'requires_confirmation') {
      pendingStartId = configId;
      startWarnings = res.data.warnings ?? [];
      showConfirmStart = true;
    } else {
      showToast('Load test started', 'success');
    }
  }

  async function handleConfirmedStart() {
    showConfirmStart = false;
    const res = await api.startLoadTestConfirmed(pendingStartId);
    if (res.error) error = res.error.message;
    pendingStartId = '';
  }

  async function handleAbort() {
    await api.abortLoadTest();
    showToast('Load test aborted', 'success');
  }

  async function handleClone(id: string, name: string) {
    await api.cloneLoadTestConfig(id, `${name} (copy)`);
    showToast('Test config cloned', 'success');
    await loadData();
  }

  async function handleDelete() {
    if (!deletingConfig) return;
    await api.deleteLoadTestConfig(deletingConfig.id);
    showToast('Test config deleted', 'success');
    deletingConfig = null;
    if (selectedConfigId === deletingConfig?.id) {
      selectedConfigId = '';
      results = [];
      comparison = null;
    }
    await loadData();
  }

  async function loadResults(configId: string) {
    selectedConfigId = configId;
    resultsLoading = true;
    const [resResults, resCompare] = await Promise.all([
      api.getLoadTestResults(configId),
      api.compareLoadTestResults(configId),
    ]);
    if (resResults.data) results = resResults.data;
    if (resCompare.data) comparison = resCompare.data;
    resultsLoading = false;
  }

  function formatDelta(val: number | null): string {
    if (val === null) return '-';
    const sign = val >= 0 ? '+' : '';
    return `${sign}${val.toFixed(1)}%`;
  }

  function formatTarget(config: LoadTestConfigResponse): string {
    const host = config.headers?.Host;
    let path = '';
    try { path = new URL(config.target_url).pathname; } catch { /* ignore */ }
    return host ? `${host}${path}` : config.target_url;
  }

  function deltaColor(val: number | null, invertGood: boolean = false): string {
    if (val === null) return 'var(--color-text-muted)';
    const good = invertGood ? val > 0 : val < 0;
    if (Math.abs(val) < 2) return 'var(--color-text-muted)';
    return good ? 'var(--color-green)' : 'var(--color-red)';
  }
</script>

<div class="loadtest-page">
  <div class="page-header">
    <h1>Load Testing</h1>
    <button class="btn btn-primary" onclick={openCreateForm}>New Test Config</button>
  </div>

  {#if error}
    <div class="error-banner">{error}</div>
  {/if}

  <!-- Live progress panel -->
  {#if progress?.active}
    <div class="live-panel">
      <div class="live-header">
        <span class="live-dot"></span>
        <span class="live-title">Test Running</span>
        <button class="btn btn-danger-small" onclick={handleAbort}>Abort</button>
      </div>
      <div class="live-stats">
        <div class="live-stat">
          <span class="live-label">Requests</span>
          <span class="live-value">{progress.total_requests.toLocaleString()}</span>
        </div>
        <div class="live-stat">
          <span class="live-label">RPS</span>
          <span class="live-value">{progress.current_rps.toFixed(0)}</span>
        </div>
        <div class="live-stat">
          <span class="live-label">Avg Latency</span>
          <span class="live-value">{progress.avg_latency_ms.toFixed(0)}ms</span>
        </div>
        <div class="live-stat">
          <span class="live-label">Error Rate</span>
          <span class="live-value" style="color: {progress.error_rate_pct > 5 ? 'var(--color-red)' : 'var(--color-green)'}">
            {progress.error_rate_pct.toFixed(1)}%
          </span>
        </div>
        <div class="live-stat">
          <span class="live-label">Elapsed</span>
          <span class="live-value">{progress.elapsed_s.toFixed(0)}s</span>
        </div>
      </div>
      {#if progress.aborted}
        <div class="abort-reason">Aborted: {progress.abort_reason}</div>
      {/if}
    </div>
  {/if}

  {#if loading}
    <p class="loading">Loading test configurations...</p>
  {:else if configs.length === 0}
    <div class="empty-state">
      <p>No load test configurations yet.</p>
      <button class="btn btn-primary" onclick={openCreateForm}>Create your first test</button>
    </div>
  {:else}
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Target</th>
            <th>Concurrency</th>
            <th>RPS</th>
            <th>Duration</th>
            <th>Schedule</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each configs as c}
            <tr class:selected={selectedConfigId === c.id}>
              <td>
                <button class="link-btn" onclick={() => loadResults(c.id)}>{c.name}</button>
              </td>
              <td class="mono small">{formatTarget(c)}</td>
              <td>{c.concurrency}</td>
              <td>{c.requests_per_second}</td>
              <td>{c.duration_s}s</td>
              <td class="mono small">{c.schedule_cron ?? 'Manual'}</td>
              <td class="actions">
                <button class="btn btn-small btn-run" onclick={() => handleStart(c.id)} disabled={!!progress?.active} title={progress?.active ? 'Another test is already running' : 'Run this test'}>
                  Run
                </button>
                <button class="btn-icon" onclick={() => openEditForm(c)} title="Edit">
                  {@html editIcon}
                </button>
                <button class="btn-icon" onclick={() => handleClone(c.id, c.name)} title="Clone">
                  {@html cloneIcon}
                </button>
                <button class="btn-icon btn-icon-danger" onclick={() => (deletingConfig = c)} title="Delete">
                  {@html trashIcon}
                </button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}

  <!-- Results panel -->
  {#if selectedConfigId}
    <div class="results-section">
      <h2>Results</h2>
      {#if resultsLoading}
        <p class="loading">Loading results...</p>
      {:else if results.length === 0}
        <div class="empty-state">
          <p>No test runs yet for this configuration.</p>
          <p class="text-muted">Click the Run button in the table above to execute a test.</p>
        </div>
      {:else}
        <!-- Comparison card -->
        {#if comparison}
          <div class="comparison-card">
            <h3>Latest vs Previous</h3>
            <div class="comparison-grid">
              <div class="comp-item">
                <span class="comp-label">Avg Latency</span>
                <span class="comp-value">{comparison.current.avg_latency_ms.toFixed(1)}ms</span>
                <span class="comp-delta" style="color: {deltaColor(comparison.latency_delta_pct)}">
                  {formatDelta(comparison.latency_delta_pct)}
                </span>
              </div>
              <div class="comp-item">
                <span class="comp-label">Throughput</span>
                <span class="comp-value">{comparison.current.throughput_rps.toFixed(0)} rps</span>
                <span class="comp-delta" style="color: {deltaColor(comparison.throughput_delta_pct, true)}">
                  {formatDelta(comparison.throughput_delta_pct)}
                </span>
              </div>
              <div class="comp-item">
                <span class="comp-label">p99</span>
                <span class="comp-value">{comparison.current.p99_latency_ms}ms</span>
              </div>
              <div class="comp-item">
                <span class="comp-label">Errors</span>
                <span class="comp-value">{comparison.current.failed_requests}</span>
              </div>
            </div>
          </div>
        {/if}

        <!-- History table -->
        <div class="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Date</th>
                <th>Requests</th>
                <th>Success</th>
                <th>Failed</th>
                <th>Avg Latency</th>
                <th>p95</th>
                <th>p99</th>
                <th>RPS</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {#each results as r}
                <tr>
                  <td class="mono small">{new Date(r.started_at).toLocaleString()}</td>
                  <td>{r.total_requests.toLocaleString()}</td>
                  <td style="color: var(--color-green)">{r.successful_requests.toLocaleString()}</td>
                  <td style="color: {r.failed_requests > 0 ? 'var(--color-red)' : 'var(--color-text-muted)'}">{r.failed_requests}</td>
                  <td class="mono">{r.avg_latency_ms.toFixed(1)}ms</td>
                  <td class="mono">{r.p95_latency_ms}ms</td>
                  <td class="mono">{r.p99_latency_ms}ms</td>
                  <td>{r.throughput_rps.toFixed(0)}</td>
                  <td>
                    {#if r.aborted}
                      <span class="status-aborted" title={r.abort_reason ?? ''}>Aborted</span>
                    {:else}
                      <span class="status-done">Done</span>
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </div>
  {/if}

  {#if deletingConfig}
    <ConfirmDialog
      title="Delete Test Config"
      message="Delete '{deletingConfig.name}'? All associated results will be lost."
      confirmLabel="Delete"
      onconfirm={handleDelete}
      oncancel={() => (deletingConfig = null)}
    />
  {/if}

  {#if showConfirmStart}
    <ConfirmDialog
      title="Exceeds Safe Limits"
      message="This test exceeds configured safe limits: {startWarnings.join(', ')}. Proceed anyway?"
      confirmLabel="Start Anyway"
      onconfirm={handleConfirmedStart}
      oncancel={() => (showConfirmStart = false)}
    />
  {/if}

  {#if showForm}
    <div class="overlay" role="dialog" onclick={(e) => { if (e.target === e.currentTarget) { showForm = false; editingConfig = null; } }}>
      <div class="modal">
        <h2>{editingConfig ? 'Edit Load Test' : 'New Load Test'}</h2>
        {#if formError}
          <div class="form-error">{formError}</div>
        {/if}

        <div class="form-group">
          <label>Name <span class="required">*</span></label>
          <input type="text" bind:value={formName} placeholder="Weekly backend stress test" />
        </div>

        <div class="form-group">
          <label>Route <span class="required">*</span></label>
          <select bind:value={formRouteId}>
            <option value="">Select a route...</option>
            {#each routes as route}
              <option value={route.id}>{route.hostname}{route.path_prefix !== '/' ? route.path_prefix : ''}</option>
            {/each}
          </select>
        </div>
        <div class="form-group">
          <label>Path</label>
          <input type="text" bind:value={formPathSuffix} placeholder="/" />
          <span class="hint">Path suffix appended to the route (e.g., /api/health)</span>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label>Method</label>
            <select bind:value={formMethod}>
              <option>GET</option><option>POST</option><option>PUT</option><option>HEAD</option>
            </select>
          </div>
          <div class="form-group">
            <label>Duration (s)</label>
            <input type="number" bind:value={formDuration} min="5" max="3600" />
          </div>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label>Concurrency</label>
            <input type="number" bind:value={formConcurrency} min="1" max="10000" />
            <span class="hint">Number of simultaneous connections to the target.</span>
          </div>
          <div class="form-group">
            <label>Requests/sec</label>
            <input type="number" bind:value={formRps} min="1" max="100000" />
            <span class="hint">Target throughput. Total requests = RPS x Duration.</span>
          </div>
        </div>

        <div class="form-group">
          <label>Error Abort Threshold (%)</label>
          <input type="number" bind:value={formErrorThreshold} min="1" max="100" step="0.5" />
        </div>

        <div class="form-group">
          <label>Schedule (cron, optional)</label>
          <input type="text" bind:value={formCron} placeholder="0 3 * * 1 (Mon 03:00)" />
          <span class="hint">5-field cron: min hour dom month dow</span>
        </div>

        <div class="form-actions">
          <button class="btn btn-cancel" onclick={() => { showForm = false; editingConfig = null; }}>Cancel</button>
          <button class="btn btn-primary" onclick={handleSubmit} disabled={formSubmitting}>
            {formSubmitting ? 'Saving...' : editingConfig ? 'Update' : 'Create'}
          </button>
        </div>
      </div>
    </div>
  {/if}
</div>

<script lang="ts" module>
  const editIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>';
  const cloneIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
  const trashIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>';
</script>

<style>
  .loadtest-page { max-width: none; }

  /* Live progress panel */
  .live-panel { background: var(--color-bg-card); border: 2px solid var(--color-primary); border-radius: var(--radius-xl); padding: var(--space-4) var(--space-5); margin-bottom: var(--space-6); box-shadow: var(--shadow-md); }
  .live-header { display: flex; align-items: center; gap: var(--space-3); margin-bottom: var(--space-3); }
  .live-dot { width: 10px; height: 10px; border-radius: 50%; background: var(--color-green); animation: pulse 1.5s infinite; }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
  .live-title { font-weight: 600; flex: 1; }
  .btn-danger-small { padding: var(--space-1) var(--space-3); border-radius: var(--radius-md); font-size: var(--text-base); font-weight: 500; border: none; background: var(--color-red); color: white; cursor: pointer; transition: background-color var(--transition-fast); }
  .btn-danger-small:hover { filter: brightness(0.9); }
  .live-stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: var(--space-4); }
  .live-stat { text-align: center; }
  .live-label { display: block; font-size: var(--text-xs); text-transform: uppercase; letter-spacing: 0.05em; color: var(--color-text-muted); margin-bottom: var(--space-1); }
  .live-value { font-size: 1.25rem; font-weight: 700; font-family: var(--mono); }
  .abort-reason { margin-top: var(--space-3); padding: var(--space-2) var(--space-3); background: var(--color-red-subtle); border-radius: var(--radius-md); color: var(--color-red); font-size: var(--text-base); }

  /* Config table extras */
  tr.selected td { background: var(--color-primary-subtle); }
  .link-btn { background: none; border: none; color: var(--color-primary); font-weight: 600; cursor: pointer; font-size: var(--text-md); padding: 0; text-align: left; transition: color var(--transition-fast); }
  .link-btn:hover { text-decoration: underline; }
  .btn-small { padding: var(--space-1) 0.625rem; border-radius: var(--radius-md); font-size: var(--text-base); font-weight: 500; border: 1px solid var(--color-border); background: transparent; color: var(--color-text); cursor: pointer; transition: background-color var(--transition-fast); }
  .btn-run { border-color: var(--color-green); color: var(--color-green); }
  .btn-run:hover { background: var(--color-green-subtle); }
  .btn-run:disabled { opacity: 0.4; cursor: not-allowed; }

  /* Comparison card */
  .results-section { margin-top: var(--space-8); }
  .results-section h2 { margin: 0 0 var(--space-4); }
  .comparison-card { background: var(--color-bg-card); border: 1px solid var(--color-border); border-radius: var(--radius-xl); padding: var(--space-4) var(--space-5); margin-bottom: var(--space-6); box-shadow: var(--shadow-sm); }
  .comparison-card h3 { margin: 0 0 var(--space-3); font-size: var(--text-md); }
  .comparison-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: var(--space-4); }
  .comp-item { text-align: center; }
  .comp-label { display: block; font-size: var(--text-xs); text-transform: uppercase; letter-spacing: 0.05em; color: var(--color-text-muted); margin-bottom: var(--space-1); }
  .comp-value { display: block; font-size: var(--text-lg); font-weight: 700; font-family: var(--mono); }
  .comp-delta { display: block; font-size: var(--text-base); font-weight: 600; margin-top: 2px; }
  .status-done { color: var(--color-green); font-weight: 500; }
  .status-aborted { color: var(--color-red); font-weight: 500; cursor: help; }
</style>
