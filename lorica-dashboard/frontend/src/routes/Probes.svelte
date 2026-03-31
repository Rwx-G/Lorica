<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    type ProbeConfigResponse,
    type RouteResponse,
    type CreateProbeRequest,
    type UpdateProbeRequest,
  } from '../lib/api';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';

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

  async function handleSubmit() {
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
    }

    formSubmitting = false;
    showForm = false;
    await loadData();
  }

  async function handleDelete() {
    if (!deletingProbe) return;
    await api.deleteProbe(deletingProbe.id);
    deletingProbe = null;
    await loadData();
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
          {#each probes as p}
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
                <button class="btn-icon" onclick={() => openEditForm(p)} title="Edit">
                  {@html editIcon}
                </button>
                <button class="btn-icon btn-icon-danger" onclick={() => (deletingProbe = p)} title="Delete">
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
    <div class="overlay" role="dialog" onclick={(e) => { if (e.target === e.currentTarget) showForm = false; }}>
      <div class="modal">
        <h2>{editingProbe ? 'Edit Probe' : 'Add Probe'}</h2>

        {#if formError}
          <div class="form-error">{formError}</div>
        {/if}

        {#if !editingProbe}
          <div class="form-group">
            <label>Route <span class="required">*</span></label>
            <select bind:value={formRouteId}>
              {#each routes as r}
                <option value={r.id}>{r.hostname}{r.path_prefix}</option>
              {/each}
            </select>
          </div>
        {/if}

        <div class="form-row">
          <div class="form-group">
            <label>Method</label>
            <select bind:value={formMethod}>
              {#each methods as m}
                <option value={m}>{m}</option>
              {/each}
            </select>
          </div>
          <div class="form-group">
            <label>Expected Status</label>
            <input type="number" bind:value={formExpectedStatus} min="100" max="599" />
          </div>
        </div>

        <div class="form-group">
          <label>Path</label>
          <input type="text" bind:value={formPath} placeholder="/" />
        </div>

        <div class="form-row">
          <div class="form-group">
            <label>Interval (s)</label>
            <input type="number" bind:value={formInterval} min="5" max="3600" />
          </div>
          <div class="form-group">
            <label>Timeout (ms)</label>
            <input type="number" bind:value={formTimeout} min="1000" max="30000" />
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
</div>

<script lang="ts" module>
  const editIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>';
  const trashIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>';
</script>

<style>
  .probes-page { max-width: 1100px; }
  .page-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.5rem; }
  .page-header h1 { margin: 0; }
  .error-banner { background: rgba(239, 68, 68, 0.1); border: 1px solid var(--color-red); border-radius: 0.5rem; color: var(--color-red); padding: 0.75rem 1rem; margin-bottom: 1rem; }
  .loading { color: var(--color-text-muted); }
  .text-muted { color: var(--color-text-muted); }
  .small { font-size: 0.8125rem; }
  .empty-state { display: flex; flex-direction: column; align-items: center; gap: 0.5rem; padding: 3rem 0; color: var(--color-text-muted); }
  .table-wrapper { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 0.75rem 1rem; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--color-text-muted); border-bottom: 1px solid var(--color-border); }
  td { padding: 0.75rem 1rem; border-bottom: 1px solid var(--color-border); font-size: 0.875rem; vertical-align: middle; }
  tr:hover td { background: rgba(255, 255, 255, 0.02); }
  .mono { font-family: var(--mono); font-size: 0.8125rem; }
  .route-label { font-weight: 600; color: var(--color-text-heading); }
  .method-badge { display: inline-block; padding: 0.125rem 0.5rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; background: rgba(59, 130, 246, 0.1); color: var(--color-primary); font-family: var(--mono); }
  .status-on { color: var(--color-green); font-weight: 500; }
  .status-off { color: var(--color-text-muted); }
  .actions { display: flex; gap: 0.25rem; }
  .btn-icon { display: flex; align-items: center; justify-content: center; width: 2rem; height: 2rem; border: none; border-radius: 0.375rem; background: none; color: var(--color-text-muted); transition: background-color 0.15s, color 0.15s; cursor: pointer; }
  .btn-icon:hover { background: var(--color-bg-hover); color: var(--color-text); }
  .btn-icon-danger:hover { background: rgba(239, 68, 68, 0.1); color: var(--color-red); }
  .overlay { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.5); display: flex; align-items: center; justify-content: center; z-index: 100; }
  .modal { background: var(--color-bg-card); border: 1px solid var(--color-border); border-radius: 0.75rem; padding: 1.5rem; width: 90%; max-width: 480px; max-height: 90vh; overflow-y: auto; }
  .modal h2 { margin: 0 0 1.25rem; }
  .form-error { background: rgba(239, 68, 68, 0.1); border: 1px solid var(--color-red); border-radius: 0.375rem; color: var(--color-red); padding: 0.5rem 0.75rem; font-size: 0.8125rem; margin-bottom: 1rem; }
  .form-group { margin-bottom: 1rem; }
  .form-group label { display: block; font-size: 0.8125rem; font-weight: 500; color: var(--color-text-muted); margin-bottom: 0.375rem; }
  .required { color: var(--color-red); }
  .form-group input[type="text"], .form-group input[type="number"], .form-group select { width: 100%; padding: 0.5rem 0.75rem; border: 1px solid var(--color-border); border-radius: 0.375rem; background: var(--color-bg-input); color: var(--color-text); font-size: 0.875rem; }
  .form-group input:focus, .form-group select:focus { outline: none; border-color: var(--color-primary); }
  .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
  .checkbox-item { display: flex; align-items: center; gap: 0.5rem; font-size: 0.8125rem; cursor: pointer; }
  .checkbox-item input[type="checkbox"] { accent-color: var(--color-primary); }
  .form-actions { display: flex; justify-content: flex-end; gap: 0.75rem; margin-top: 1.5rem; }
  .btn { padding: 0.5rem 1rem; border-radius: 0.375rem; font-weight: 500; border: none; font-size: 0.875rem; cursor: pointer; }
  .btn-primary { background: var(--color-primary); color: white; }
  .btn-primary:hover { background: var(--color-primary-hover); }
  .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-cancel { background: var(--color-bg-input); color: var(--color-text); }
  .btn-cancel:hover { background: var(--color-bg-hover); }
</style>
