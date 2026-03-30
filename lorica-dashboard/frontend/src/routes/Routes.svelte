<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    type RouteResponse,
    type BackendResponse,
    type CertificateResponse,
    type CreateRouteRequest,
    type UpdateRouteRequest,
  } from '../lib/api';
  import StatusBadge from '../components/StatusBadge.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';

  let routes: RouteResponse[] = $state([]);
  let backends: BackendResponse[] = $state([]);
  let certificates: CertificateResponse[] = $state([]);
  let error = $state('');
  let loading = $state(true);

  // Form state
  let showForm = $state(false);
  let editingRoute: RouteResponse | null = $state(null);
  let formHostname = $state('');
  let formPathPrefix = $state('/');
  let formBackendIds: string[] = $state([]);
  let formCertificateId = $state('');
  let formLoadBalancing = $state('round_robin');
  let formTopologyType = $state('single_vm');
  let formWafEnabled = $state(false);
  let formWafMode = $state('detection');
  let formEnabled = $state(true);
  let formError = $state('');
  let formSubmitting = $state(false);

  // Delete state
  let deletingRoute: RouteResponse | null = $state(null);

  const loadBalancingOptions = [
    { value: 'round_robin', label: 'Round Robin' },
    { value: 'consistent_hash', label: 'Consistent Hash' },
    { value: 'random', label: 'Random' },
    { value: 'peak_ewma', label: 'Peak EWMA' },
  ];

  const topologyOptions = [
    { value: 'single_vm', label: 'Single VM' },
    { value: 'ha', label: 'High Availability' },
    { value: 'docker_swarm', label: 'Docker Swarm' },
    { value: 'kubernetes', label: 'Kubernetes' },
    { value: 'custom', label: 'Custom' },
  ];

  async function loadData() {
    loading = true;
    error = '';
    const [routesRes, backendsRes, certsRes] = await Promise.all([
      api.listRoutes(),
      api.listBackends(),
      api.listCertificates(),
    ]);
    if (routesRes.error) {
      error = routesRes.error.message;
    } else if (routesRes.data) {
      routes = routesRes.data.routes;
    }
    if (backendsRes.data) {
      backends = backendsRes.data.backends;
    }
    if (certsRes.data) {
      certificates = certsRes.data.certificates;
    }
    loading = false;
  }

  onMount(loadData);

  function openCreateForm() {
    editingRoute = null;
    formHostname = '';
    formPathPrefix = '/';
    formBackendIds = [];
    formCertificateId = '';
    formLoadBalancing = 'round_robin';
    formTopologyType = 'single_vm';
    formWafEnabled = false;
    formWafMode = 'detection';
    formEnabled = true;
    formError = '';
    showForm = true;
  }

  function openEditForm(route: RouteResponse) {
    editingRoute = route;
    formHostname = route.hostname;
    formPathPrefix = route.path_prefix;
    formBackendIds = [...route.backends];
    formCertificateId = route.certificate_id ?? '';
    formLoadBalancing = route.load_balancing;
    formTopologyType = route.topology_type;
    formWafEnabled = route.waf_enabled;
    formWafMode = route.waf_mode ?? 'detection';
    formEnabled = route.enabled;
    formError = '';
    showForm = true;
  }

  function closeForm() {
    showForm = false;
    editingRoute = null;
  }

  function handleFormKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      closeForm();
    } else if (e.key === 'Enter' && !formSubmitting && (e.target as HTMLElement)?.tagName !== 'SELECT') {
      e.preventDefault();
      handleSubmit();
    }
  }

  async function handleSubmit() {
    if (!formHostname.trim()) {
      formError = 'Hostname is required';
      return;
    }
    formSubmitting = true;
    formError = '';

    if (editingRoute) {
      const body: UpdateRouteRequest = {
        hostname: formHostname,
        path_prefix: formPathPrefix,
        backend_ids: formBackendIds,
        certificate_id: formCertificateId || undefined,
        load_balancing: formLoadBalancing,
        topology_type: formTopologyType,
        waf_enabled: formWafEnabled,
        waf_mode: formWafMode,
        enabled: formEnabled,
      };
      const res = await api.updateRoute(editingRoute.id, body);
      if (res.error) {
        formError = res.error.message;
        formSubmitting = false;
        return;
      }
    } else {
      const body: CreateRouteRequest = {
        hostname: formHostname,
        path_prefix: formPathPrefix || '/',
        backend_ids: formBackendIds.length > 0 ? formBackendIds : undefined,
        certificate_id: formCertificateId || undefined,
        load_balancing: formLoadBalancing,
        topology_type: formTopologyType,
        waf_enabled: formWafEnabled,
        waf_mode: formWafMode,
      };
      const res = await api.createRoute(body);
      if (res.error) {
        formError = res.error.message;
        formSubmitting = false;
        return;
      }
    }

    formSubmitting = false;
    closeForm();
    await loadData();
  }

  async function handleDelete() {
    if (!deletingRoute) return;
    const res = await api.deleteRoute(deletingRoute.id);
    if (res.error) {
      error = res.error.message;
    }
    deletingRoute = null;
    await loadData();
  }

  function toggleBackend(id: string) {
    if (formBackendIds.includes(id)) {
      formBackendIds = formBackendIds.filter((b) => b !== id);
    } else {
      formBackendIds = [...formBackendIds, id];
    }
  }

  function certLabel(id: string): string {
    const c = certificates.find((c) => c.id === id);
    return c ? c.domain : id.slice(0, 8);
  }

  function resolveHealthStatus(route: RouteResponse): 'healthy' | 'degraded' | 'down' | 'unknown' {
    if (route.backends.length === 0) return 'unknown';
    const statuses = route.backends.map((bid) => {
      const b = backends.find((b) => b.id === bid);
      return b?.health_status ?? 'unknown';
    });
    if (statuses.every((s) => s === 'healthy')) return 'healthy';
    if (statuses.some((s) => s === 'healthy')) return 'degraded';
    if (statuses.every((s) => s === 'down')) return 'down';
    return 'unknown';
  }
</script>

<div class="routes-page">
  <div class="page-header">
    <h1>Routes</h1>
    <button class="btn btn-primary" onclick={openCreateForm}>+ New Route</button>
  </div>

  {#if error}
    <div class="error-banner">{error}</div>
  {/if}

  {#if loading}
    <p class="loading">Loading...</p>
  {:else if routes.length === 0}
    <div class="empty-state">
      <p>No routes configured yet.</p>
      <button class="btn btn-primary" onclick={openCreateForm}>Create your first route</button>
    </div>
  {:else}
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>Hostname</th>
            <th>Path</th>
            <th>Backends</th>
            <th>TLS</th>
            <th>WAF</th>
            <th>Health</th>
            <th>Enabled</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {#each routes as route (route.id)}
            <tr>
              <td class="hostname">{route.hostname}</td>
              <td class="mono">{route.path_prefix}</td>
              <td>
                {#if route.backends.length === 0}
                  <span class="text-muted">None</span>
                {:else}
                  <span class="backend-count">{route.backends.length} backend{route.backends.length > 1 ? 's' : ''}</span>
                {/if}
              </td>
              <td>
                {#if route.certificate_id}
                  <span class="tls-on" title={certLabel(route.certificate_id)}>TLS</span>
                {:else}
                  <span class="tls-off">-</span>
                {/if}
              </td>
              <td>
                {#if route.waf_enabled}
                  <span class="waf-on" title={route.waf_mode === 'blocking' ? 'Blocking' : 'Detection'}>{route.waf_mode === 'blocking' ? 'Block' : 'Detect'}</span>
                {:else}
                  <span class="waf-off">-</span>
                {/if}
              </td>
              <td><StatusBadge status={resolveHealthStatus(route)} /></td>
              <td>
                <span class="enabled-indicator" class:on={route.enabled} class:off={!route.enabled}>
                  {route.enabled ? 'Yes' : 'No'}
                </span>
              </td>
              <td class="actions">
                <button class="btn-icon" title="Edit" onclick={() => openEditForm(route)}>
                  {@html editIcon}
                </button>
                <button class="btn-icon btn-icon-danger" title="Delete" onclick={() => { deletingRoute = route; }}>
                  {@html trashIcon}
                </button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

{#if showForm}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div class="overlay" onclick={closeForm} onkeydown={handleFormKeydown} role="dialog" aria-modal="true" tabindex="-1">
    <div class="modal" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()} role="document">
      <h2>{editingRoute ? 'Edit Route' : 'New Route'}</h2>

      {#if formError}
        <div class="form-error">{formError}</div>
      {/if}

      <div class="form-group">
        <label for="hostname">Hostname <span class="required">*</span></label>
        <input id="hostname" type="text" bind:value={formHostname} placeholder="example.com" />
      </div>

      <div class="form-group">
        <label for="path">Path prefix</label>
        <input id="path" type="text" bind:value={formPathPrefix} placeholder="/" />
      </div>

      <div class="form-group">
        <span class="field-label">Backends</span>
        {#if backends.length === 0}
          <p class="text-muted small">No backends available</p>
        {:else}
          <div class="checkbox-list">
            {#each backends as b (b.id)}
              <label class="checkbox-item">
                <input type="checkbox" checked={formBackendIds.includes(b.id)} onchange={() => toggleBackend(b.id)} />
                <span>{b.address}</span>
                <StatusBadge status={b.health_status === 'healthy' ? 'healthy' : b.health_status === 'degraded' ? 'degraded' : b.health_status === 'down' ? 'down' : 'unknown'} />
              </label>
            {/each}
          </div>
        {/if}
      </div>

      <div class="form-group">
        <label for="certificate">TLS Certificate</label>
        <select id="certificate" bind:value={formCertificateId}>
          <option value="">None (no TLS)</option>
          {#each certificates as c (c.id)}
            <option value={c.id}>{c.domain}</option>
          {/each}
        </select>
      </div>

      <div class="form-row">
        <div class="form-group">
          <label for="lb">Load Balancing</label>
          <select id="lb" bind:value={formLoadBalancing}>
            {#each loadBalancingOptions as opt}
              <option value={opt.value}>{opt.label}</option>
            {/each}
          </select>
        </div>

        <div class="form-group">
          <label for="topo">Topology</label>
          <select id="topo" bind:value={formTopologyType}>
            {#each topologyOptions as opt}
              <option value={opt.value}>{opt.label}</option>
            {/each}
          </select>
        </div>
      </div>

      <div class="form-group">
        <label class="checkbox-item">
          <input type="checkbox" bind:checked={formWafEnabled} />
          <span>Enable WAF</span>
        </label>
      </div>

      {#if formWafEnabled}
        <div class="form-group">
          <label for="waf-mode">WAF Mode</label>
          <select id="waf-mode" bind:value={formWafMode}>
            <option value="detection">Detection (log only)</option>
            <option value="blocking">Blocking (reject 403)</option>
          </select>
        </div>
      {/if}

      {#if editingRoute}
        <div class="form-group">
          <label class="checkbox-item">
            <input type="checkbox" bind:checked={formEnabled} />
            <span>Enabled</span>
          </label>
        </div>
      {/if}

      <div class="form-actions">
        <button class="btn btn-cancel" onclick={closeForm}>Cancel</button>
        <button class="btn btn-primary" disabled={formSubmitting} onclick={handleSubmit}>
          {formSubmitting ? 'Saving...' : editingRoute ? 'Update' : 'Create'}
        </button>
      </div>
    </div>
  </div>
{/if}

{#if deletingRoute}
  <ConfirmDialog
    title="Delete Route"
    message="Are you sure you want to delete the route for {deletingRoute.hostname}{deletingRoute.path_prefix}? This action cannot be undone."
    onconfirm={handleDelete}
    oncancel={() => { deletingRoute = null; }}
  />
{/if}

<script lang="ts" module>
  const editIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>';
  const trashIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>';
</script>

<style>
  .routes-page {
    max-width: 1100px;
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
    gap: 1rem;
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
    padding: 0.75rem 1rem;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--color-text-muted);
    border-bottom: 1px solid var(--color-border);
  }

  td {
    padding: 0.75rem 1rem;
    border-bottom: 1px solid var(--color-border);
    font-size: 0.875rem;
    vertical-align: middle;
  }

  tr:hover td {
    background: rgba(255, 255, 255, 0.02);
  }

  .hostname {
    font-weight: 600;
    color: var(--color-text-heading);
  }

  .mono {
    font-family: var(--mono);
    font-size: 0.8125rem;
  }

  .text-muted {
    color: var(--color-text-muted);
  }

  .small {
    font-size: 0.8125rem;
  }

  .backend-count {
    color: var(--color-text);
  }

  .tls-on {
    display: inline-block;
    padding: 0.125rem 0.5rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 500;
    background: rgba(34, 197, 94, 0.1);
    color: var(--color-green);
  }

  .tls-off {
    color: var(--color-text-muted);
  }

  .waf-on {
    display: inline-block;
    padding: 0.125rem 0.5rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 500;
    background: rgba(251, 146, 60, 0.1);
    color: var(--color-orange, #fb923c);
  }

  .waf-off {
    color: var(--color-text-muted);
  }

  .enabled-indicator.on {
    color: var(--color-green);
  }

  .enabled-indicator.off {
    color: var(--color-text-muted);
  }

  .actions {
    display: flex;
    gap: 0.25rem;
  }

  .btn-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 2rem;
    height: 2rem;
    border: none;
    border-radius: 0.375rem;
    background: none;
    color: var(--color-text-muted);
    transition: background-color 0.15s, color 0.15s;
  }

  .btn-icon:hover {
    background: var(--color-bg-hover);
    color: var(--color-text);
  }

  .btn-icon-danger:hover {
    background: rgba(239, 68, 68, 0.1);
    color: var(--color-red);
  }

  /* Modal / Form */
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }

  .modal {
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-radius: 0.75rem;
    padding: 1.5rem;
    width: 90%;
    max-width: 520px;
    max-height: 90vh;
    overflow-y: auto;
  }

  .modal h2 {
    margin: 0 0 1.25rem;
  }

  .form-error {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid var(--color-red);
    border-radius: 0.375rem;
    color: var(--color-red);
    padding: 0.5rem 0.75rem;
    font-size: 0.8125rem;
    margin-bottom: 1rem;
  }

  .form-group {
    margin-bottom: 1rem;
  }

  .form-group label,
  .form-group .field-label {
    display: block;
    font-size: 0.8125rem;
    font-weight: 500;
    color: var(--color-text-muted);
    margin-bottom: 0.375rem;
  }

  .required {
    color: var(--color-red);
  }

  .form-group input[type="text"],
  .form-group select {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
  }

  .form-group input[type="text"]:focus,
  .form-group select:focus {
    outline: none;
    border-color: var(--color-primary);
  }

  .form-row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
  }

  .checkbox-list {
    display: flex;
    flex-direction: column;
    gap: 0.375rem;
    max-height: 150px;
    overflow-y: auto;
    padding: 0.5rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
  }

  .checkbox-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8125rem;
    cursor: pointer;
  }

  .checkbox-item input[type="checkbox"] {
    accent-color: var(--color-primary);
  }

  .form-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.75rem;
    margin-top: 1.5rem;
  }

  .btn {
    padding: 0.5rem 1rem;
    border-radius: 0.375rem;
    font-weight: 500;
    border: none;
    font-size: 0.875rem;
  }

  .btn-primary {
    background: var(--color-primary);
    color: white;
  }

  .btn-primary:hover {
    background: var(--color-primary-hover);
  }

  .btn-primary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .btn-cancel {
    background: var(--color-bg-input);
    color: var(--color-text);
  }

  .btn-cancel:hover {
    background: var(--color-bg-hover);
  }
</style>
