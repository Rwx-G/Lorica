<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    type ProbeConfigResponse,
    type ProbeResultResponse,
    type RouteResponse,
    type CreateProbeRequest,
    type UpdateProbeRequest,
  } from '../lib/api';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import { showToast } from '../lib/toast';

  let probes: ProbeConfigResponse[] = $state([]);
  let routes: RouteResponse[] = $state([]);
  let error = $state('');
  let loading = $state(true);

  let showForm = $state(false);
  let editingProbe: ProbeConfigResponse | null = $state(null);
  let formRouteId = $state('');
  let formMethod = $state('GET');
  let formPath = $state('/');
  let formExpectedStatus = $state(200);
  let formInterval = $state(30);
  let formTimeout = $state(5000);
  let formEnabled = $state(true);
  let formError = $state('');
  let formSubmitting = $state(false);

  let deletingProbe: ProbeConfigResponse | null = $state(null);

  let historyProbe: ProbeConfigResponse | null = $state(null);
  let historyResults: ProbeResultResponse[] = $state([]);
  let historyLoading = $state(false);

  const methods = ['GET', 'HEAD', 'POST'];

  async function loadData() {
    loading = true;
    error = '';
    const [probesRes, routesRes] = await Promise.all([
      api.listProbes(),
      api.listRoutes(),
    ]);
    if (probesRes.data) probes = probesRes.data;
    if (routesRes.data) routes = routesRes.data.routes;
    if (probesRes.error) error = probesRes.error.message;
    loading = false;
  }

  onMount(loadData);

  function getRouteLabel(routeId: string): string {
    const r = routes.find((rt) => rt.id === routeId);
    return r ? `${r.hostname}${r.path_prefix}` : routeId;
  }

  function openCreateForm() {
    editingProbe = null;
    formRouteId = routes[0]?.id ?? '';
    formMethod = 'GET';
    formPath = '/';
    formExpectedStatus = 200;
    formInterval = 30;
    formTimeout = 5000;
    formEnabled = true;
    formError = '';
    showForm = true;
  }

  function openEditForm(p: ProbeConfigResponse) {
    editingProbe = p;
    formRouteId = p.route_id;
    formMethod = p.method;
    formPath = p.path;
    formExpectedStatus = p.expected_status;
    formInterval = p.interval_s;
    formTimeout = p.timeout_ms;
    formEnabled = p.enabled;
    formError = '';
    showForm = true;
  }

  function validate(): string {
    if (!formPath.startsWith('/')) return 'Path must start with /';
    if (formInterval < 5 || formInterval > 3600) return 'Interval must be between 5 and 3600 seconds';
    if (formTimeout < 1000 || formTimeout > 60000) return 'Timeout must be between 1000 and 60000 ms';
    if (formExpectedStatus < 100 || formExpectedStatus > 599) return 'Expected status must be between 100 and 599';
    return '';
  }

  async function handleSubmit() {
    const err = validate();
    if (err) {
      formError = err;
      return;
    }
    formSubmitting = true;
    formError = '';

    if (editingProbe) {
      const body: UpdateProbeRequest = {
        method: formMethod,
        path: formPath,
        expected_status: formExpectedStatus,
        interval_s: formInterval,
        timeout_ms: formTimeout,
        enabled: formEnabled,
      };
      const res = await api.updateProbe(editingProbe.id, body);
      if (res.error) { formError = res.error.message; formSubmitting = false; return; }
      showToast('Probe updated', 'success');
    } else {
      const body: CreateProbeRequest = {
        route_id: formRouteId,
        method: formMethod,
        path: formPath,
        expected_status: formExpectedStatus,
        interval_s: formInterval,
        timeout_ms: formTimeout,
      };
      const res = await api.createProbe(body);
      if (res.error) { formError = res.error.message; formSubmitting = false; return; }
      showToast('Probe created', 'success');
    }

    formSubmitting = false;
    showForm = false;
    await loadData();
  }

  async function handleDelete() {
    if (!deletingProbe) return;
    await api.deleteProbe(deletingProbe.id);
    showToast('Probe deleted', 'success');
    deletingProbe = null;
    await loadData();
  }

  async function showHistory(probe: ProbeConfigResponse) {
    historyProbe = probe;
    historyLoading = true;
    // v1.5.1 audit M-11 : capture the requested probe id before
    // the fetch dispatches so a follow-up click on another
    // probe (race) does not let the stale history response
    // overwrite the new selection's view. `historyProbe` is the
    // source of truth for the current selection.
    const captured = probe.id;
    const res = await api.probeHistory(probe.id, 50);
    if (historyProbe?.id !== captured) return;
    historyResults = res.data?.results ?? [];
    historyLoading = false;
  }
</script>

<div class="probes-page">
  <div class="page-header">
    <h1>Active Probes</h1>
    <button class="btn btn-primary" onclick={openCreateForm} disabled={routes.length === 0}>Add Probe</button>
  </div>

  {#if error}
    <div class="error-banner">{error}</div>
  {/if}

  {#if loading}
    <p class="loading">Loading probes...</p>
  {:else if probes.length === 0}
    <div class="empty-state">
      <p>No active probes configured.</p>
      <p class="text-muted small">Probes send synthetic health checks to backends at regular intervals.</p>
      {#if routes.length > 0}
        <button class="btn btn-primary" onclick={openCreateForm}>Add your first probe</button>
      {:else}
        <p class="text-muted small">Create a route first to add probes.</p>
      {/if}
    </div>
  {:else}
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>Route</th>
            <th>Method</th>
            <th>Path</th>
            <th>Expected</th>
            <th>Interval</th>
            <th>Timeout</th>
            <th>Status</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each probes as p (p.id)}
            <tr>
              <td class="route-label">{getRouteLabel(p.route_id)}</td>
              <td><span class="method-badge">{p.method}</span></td>
              <td class="mono">{p.path}</td>
              <td>{p.expected_status}</td>
              <td>{p.interval_s}s</td>
              <td>{p.timeout_ms}ms</td>
              <td>
                {#if p.enabled}
                  <span class="status-on">Active</span>
                {:else}
                  <span class="status-off">Disabled</span>
                {/if}
              </td>
              <td class="actions">
                <button class="btn-icon" onclick={() => showHistory(p)} title="History" aria-label="History">
                  <!-- eslint-disable-next-line svelte/no-at-html-tags -->
                  {@html historyIcon}
                </button>
                <button class="btn-icon" onclick={() => openEditForm(p)} title="Edit" aria-label="Edit">
                  <!-- eslint-disable-next-line svelte/no-at-html-tags -->
                  {@html editIcon}
                </button>
                <button class="btn-icon btn-icon-danger" onclick={() => (deletingProbe = p)} title="Delete" aria-label="Delete">
                  <!-- eslint-disable-next-line svelte/no-at-html-tags -->
                  {@html trashIcon}
                </button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}

  {#if deletingProbe}
    <ConfirmDialog
      title="Delete Probe"
      message="Delete probe {deletingProbe.method} {deletingProbe.path} for route {getRouteLabel(deletingProbe.route_id)}?"
      confirmLabel="Delete"
      onconfirm={handleDelete}
      oncancel={() => (deletingProbe = null)}
    />
  {/if}

  {#if showForm}
    <div class="overlay" role="dialog" aria-modal="true" tabindex="-1" onclick={(e) => { if (e.target === e.currentTarget) showForm = false; }} onkeydown={(e) => { if (e.key === 'Escape') showForm = false; }}>
      <div class="modal">
        <h2>{editingProbe ? 'Edit Probe' : 'Add Probe'}</h2>

        {#if formError}
          <div class="form-error">{formError}</div>
        {/if}

        {#if !editingProbe}
          <div class="form-group">
            <label for="probe-route">Route <span class="required">*</span></label>
            <select id="probe-route" bind:value={formRouteId}>
              {#each routes as r (r.id)}
                <option value={r.id}>{r.hostname}{r.path_prefix}</option>
              {/each}
            </select>
          </div>
        {/if}

        <div class="form-row">
          <div class="form-group">
            <label for="probe-method">Method</label>
            <select id="probe-method" bind:value={formMethod}>
              {#each methods as m (m)}
                <option value={m}>{m}</option>
              {/each}
            </select>
          </div>
          <div class="form-group">
            <label for="probe-expected-status">Expected Status</label>
            <input id="probe-expected-status" type="number" bind:value={formExpectedStatus} min="100" max="599" />
          </div>
        </div>

        <div class="form-group">
          <label for="probe-path">Path</label>
          <input id="probe-path" type="text" bind:value={formPath} placeholder="/" />
        </div>

        <div class="form-row">
          <div class="form-group">
            <label for="probe-interval">Interval (s)</label>
            <input id="probe-interval" type="number" bind:value={formInterval} min="5" max="3600" />
          </div>
          <div class="form-group">
            <label for="probe-timeout">Timeout (ms)</label>
            <input id="probe-timeout" type="number" bind:value={formTimeout} min="1000" max="60000" />
          </div>
        </div>

        {#if editingProbe}
          <div class="form-group">
            <label class="checkbox-item">
              <input type="checkbox" bind:checked={formEnabled} />
              Enabled
            </label>
          </div>
        {/if}

        <div class="form-actions">
          <button class="btn btn-cancel" onclick={() => (showForm = false)}>Cancel</button>
          <button class="btn btn-primary" onclick={handleSubmit} disabled={formSubmitting}>
            {formSubmitting ? 'Saving...' : editingProbe ? 'Update' : 'Create'}
          </button>
        </div>
      </div>
    </div>
  {/if}

  {#if historyProbe}
    <div class="overlay" onclick={(e) => { if (e.target === e.currentTarget) historyProbe = null; }} onkeydown={(e) => { if (e.key === 'Escape') historyProbe = null; }} role="dialog" aria-modal="true" tabindex="-1">
      <div class="modal modal-wide" role="document">
        <h3>Probe History - {historyProbe.method} {historyProbe.path}</h3>
        {#if historyLoading}
          <p class="loading">Loading...</p>
        {:else if historyResults.length === 0}
          <p class="empty-text">No execution history yet.</p>
        {:else}
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Status</th>
                  <th>Latency</th>
                  <th>Result</th>
                  <th>Error</th>
                </tr>
              </thead>
              <tbody>
                {#each historyResults as r, i (i)}
                  <tr>
                    <td>{new Date(r.executed_at).toLocaleString()}</td>
                    <td>{r.status_code}</td>
                    <td>{r.latency_ms} ms</td>
                    <td>
                      <span class="badge {r.success ? 'badge-green' : 'badge-red'}">
                        {r.success ? 'OK' : 'FAIL'}
                      </span>
                    </td>
                    <td class="error-cell">{r.error ?? '-'}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}
        <div class="actions">
          <button class="btn btn-cancel" onclick={() => historyProbe = null}>Close</button>
        </div>
      </div>
    </div>
  {/if}
</div>

<script lang="ts" module>
  const historyIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>';
  const editIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>';
  const trashIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>';
</script>

<style>
  .probes-page { max-width: none; }
  .route-label { font-weight: 600; color: var(--color-text-heading); }
  .method-badge { display: inline-block; padding: 0.125rem 0.5rem; border-radius: var(--radius-full); font-size: var(--text-sm); font-weight: 600; background: var(--color-primary-subtle); color: var(--color-primary); font-family: var(--mono); }
  .status-on { color: var(--color-green); font-weight: 500; }
  .status-off { color: var(--color-text-muted); }
  .modal-wide { max-width: 700px; }
  .badge-green { background: rgba(34, 197, 94, 0.1); color: var(--color-green); padding: 0.125rem 0.5rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 500; }
  .badge-red { background: rgba(239, 68, 68, 0.1); color: var(--color-red); padding: 0.125rem 0.5rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 500; }
  .error-cell { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: var(--text-xs); color: var(--color-text-muted); }
</style>
