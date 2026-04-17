<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    type RouteResponse,
    type BackendResponse,
    type CertificateResponse,
  } from '../lib/api';
  import StatusBadge from '../components/StatusBadge.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import RouteDrawer from '../components/RouteDrawer.svelte';
  import NginxImportWizard from '../components/NginxImportWizard.svelte';
  import { showToast } from '../lib/toast';

  let routes: RouteResponse[] = $state([]);
  let backends: BackendResponse[] = $state([]);
  let certificates: CertificateResponse[] = $state([]);
  let error = $state('');
  let loading = $state(true);

  // Drawer state
  let showDrawer = $state(false);
  let editingRoute: RouteResponse | null = $state(null);

  // Nginx import wizard state
  let showImportWizard = $state(false);

  // Search and sort state
  let searchQuery = $state('');
  let sortColumn = $state('');
  let sortDirection: 'asc' | 'desc' = $state('asc');

  function toggleSort(col: string) {
    if (sortColumn === col) {
      sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
    } else {
      sortColumn = col;
      sortDirection = 'asc';
    }
  }

  // Delete state
  let deletingRoute: RouteResponse | null = $state(null);

  // Confirmation gate for enabling maintenance (503 for every client).
  // Disabling maintenance restores service, so no gate there.
  let maintenanceEnableTarget: RouteResponse | null = $state(null);

  // Prevents a double-click from firing two PUTs before the list reloads.
  let togglingRouteId: string | null = $state(null);

  function requestMaintenanceToggle(route: RouteResponse) {
    if (togglingRouteId === route.id) return;
    if (route.maintenance_mode) {
      // Turning OFF: safe, restores normal service, fire immediately.
      void applyMaintenance(route, false);
    } else {
      // Turning ON: 503 to every subsequent client, confirm first.
      maintenanceEnableTarget = route;
    }
  }

  async function applyMaintenance(route: RouteResponse, next: boolean) {
    togglingRouteId = route.id;
    const res = await api.updateRoute(route.id, { maintenance_mode: next });
    if (res.error) {
      showToast(`Failed to toggle maintenance: ${res.error.message}`, 'error');
    } else {
      showToast(
        next
          ? `Maintenance ON for ${route.hostname}${route.path_prefix}`
          : `Maintenance OFF for ${route.hostname}${route.path_prefix}`,
        'success',
      );
    }
    togglingRouteId = null;
    await loadData();
  }

  async function confirmEnableMaintenance() {
    const t = maintenanceEnableTarget;
    maintenanceEnableTarget = null;
    if (t) await applyMaintenance(t, true);
  }

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
    showDrawer = true;
  }

  function openEditForm(route: RouteResponse) {
    editingRoute = route;
    showDrawer = true;
  }

  async function handleDelete() {
    if (!deletingRoute) return;
    const res = await api.deleteRoute(deletingRoute.id);
    if (res.error) {
      error = res.error.message;
    } else {
      showToast('Route deleted', 'success');
    }
    deletingRoute = null;
    await loadData();
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

  let filteredRoutes: RouteResponse[] = $derived.by(() => {
    let result = routes;
    if (searchQuery.trim()) {
      const q = searchQuery.trim().toLowerCase();
      result = result.filter((r) =>
        r.hostname.toLowerCase().includes(q) ||
        r.path_prefix.toLowerCase().includes(q) ||
        r.id.toLowerCase().includes(q) ||
        r.hostname_aliases.some((a) => a.toLowerCase().includes(q))
      );
    }
    if (sortColumn) {
      result = [...result].sort((a, b) => {
        let va: string | number = '';
        let vb: string | number = '';
        switch (sortColumn) {
          case 'route': va = a.hostname.toLowerCase(); vb = b.hostname.toLowerCase(); break;
          case 'path': va = a.path_prefix.toLowerCase(); vb = b.path_prefix.toLowerCase(); break;
          case 'backends': va = a.backends.length; vb = b.backends.length; break;
          case 'health': va = resolveHealthStatus(a); vb = resolveHealthStatus(b); break;
          case 'enabled': va = a.enabled ? 1 : 0; vb = b.enabled ? 1 : 0; break;
        }
        if (va < vb) return sortDirection === 'asc' ? -1 : 1;
        if (va > vb) return sortDirection === 'asc' ? 1 : -1;
        return 0;
      });
    }
    return result;
  });
</script>

<div class="routes-page">
  <div class="page-header">
    <h1>Routes</h1>
    <div class="header-actions">
      <button class="btn btn-secondary" onclick={() => { showImportWizard = true; }}>Import from Nginx</button>
      <button class="btn btn-primary" onclick={openCreateForm}>+ New Route</button>
    </div>
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
    <div class="filter-bar">
      <input type="text" class="search-input" bind:value={searchQuery} placeholder="Search by hostname, path, or route id..." />
    </div>
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th class="sortable" tabindex="0" role="button" onclick={() => toggleSort('route')} onkeydown={(e) => { if (e.key === 'Enter') toggleSort('route'); }}>
              Route {sortColumn === 'route' ? (sortDirection === 'asc' ? '\u2191' : '\u2193') : ''}
            </th>
            <th class="sortable" tabindex="0" role="button" onclick={() => toggleSort('path')} onkeydown={(e) => { if (e.key === 'Enter') toggleSort('path'); }}>
              Path {sortColumn === 'path' ? (sortDirection === 'asc' ? '\u2191' : '\u2193') : ''}
            </th>
            <th class="sortable" tabindex="0" role="button" onclick={() => toggleSort('backends')} onkeydown={(e) => { if (e.key === 'Enter') toggleSort('backends'); }}>
              Backends {sortColumn === 'backends' ? (sortDirection === 'asc' ? '\u2191' : '\u2193') : ''}
            </th>
            <th>TLS</th>
            <th>WAF</th>
            <th class="sortable" tabindex="0" role="button" onclick={() => toggleSort('health')} onkeydown={(e) => { if (e.key === 'Enter') toggleSort('health'); }}>
              Health {sortColumn === 'health' ? (sortDirection === 'asc' ? '\u2191' : '\u2193') : ''}
            </th>
            <th class="sortable" tabindex="0" role="button" onclick={() => toggleSort('enabled')} onkeydown={(e) => { if (e.key === 'Enter') toggleSort('enabled'); }}>
              Enabled {sortColumn === 'enabled' ? (sortDirection === 'asc' ? '\u2191' : '\u2193') : ''}
            </th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {#each filteredRoutes as route (route.id)}
            <tr class:row-maintenance={route.maintenance_mode}>
              <td class="hostname">
                {route.hostname}
                {#if route.hostname_aliases.length > 0}
                  <span class="alias-badge" title={route.hostname_aliases.join(', ')}>+{route.hostname_aliases.length}</span>
                {/if}
                {#if route.maintenance_mode}
                  <span class="maintenance-badge" title="Route is in maintenance: all requests return 503">MAINT</span>
                {/if}
              </td>
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
                <button class="btn-icon" title="Edit" aria-label="Edit" onclick={() => openEditForm(route)}>
                  <!-- eslint-disable-next-line svelte/no-at-html-tags -->
                  {@html editIcon}
                </button>
                <button
                  class="btn-icon btn-icon-maintenance"
                  class:active={route.maintenance_mode}
                  title={route.maintenance_mode ? 'Disable maintenance mode' : 'Enable maintenance mode (returns 503 to all requests)'}
                  aria-label={route.maintenance_mode ? 'Disable maintenance' : 'Enable maintenance'}
                  aria-pressed={route.maintenance_mode}
                  disabled={togglingRouteId === route.id}
                  onclick={() => requestMaintenanceToggle(route)}
                >
                  <!-- eslint-disable-next-line svelte/no-at-html-tags -->
                  {@html wrenchIcon}
                </button>
                <button class="btn-icon btn-icon-danger" title="Delete" aria-label="Delete" onclick={() => { deletingRoute = route; }}>
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
</div>

<RouteDrawer
  open={showDrawer}
  editing={editingRoute}
  {backends}
  {certificates}
  onsave={loadData}
  onclose={() => { showDrawer = false; editingRoute = null; }}
/>

<NginxImportWizard
  open={showImportWizard}
  onclose={() => { showImportWizard = false; }}
  onimported={loadData}
/>

{#if deletingRoute}
  <ConfirmDialog
    title="Delete Route"
    message="Are you sure you want to delete the route for {deletingRoute.hostname}{deletingRoute.path_prefix}? This action cannot be undone."
    onconfirm={handleDelete}
    oncancel={() => { deletingRoute = null; }}
  />
{/if}

{#if maintenanceEnableTarget}
  <ConfirmDialog
    title="Enable Maintenance Mode"
    message="All requests to {maintenanceEnableTarget.hostname}{maintenanceEnableTarget.path_prefix} will immediately return 503 Service Unavailable with Retry-After. Existing in-flight responses are not affected. Continue?"
    confirmLabel="Enable maintenance"
    confirmStyle="warning"
    onconfirm={confirmEnableMaintenance}
    oncancel={() => { maintenanceEnableTarget = null; }}
  />
{/if}

<script lang="ts" module>
  const editIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>';
  const trashIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>';
  const wrenchIcon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>';
</script>

<style>
  .routes-page { max-width: none; }

  .filter-bar { margin-bottom: var(--space-4); }
  .search-input { width: 100%; max-width: 400px; padding: var(--space-2) var(--space-3); border: 1px solid var(--color-border); border-radius: var(--radius-md); background: var(--color-bg-input); color: var(--color-text); font-size: var(--text-md); }
  .search-input:focus { outline: none; border-color: var(--color-primary); box-shadow: 0 0 0 3px var(--color-primary-subtle); }
  .sortable { cursor: pointer; user-select: none; }
  .sortable:hover { color: var(--color-text-heading); }

  .header-actions {
    display: flex;
    gap: var(--space-2);
    align-items: center;
  }

  .hostname {
    font-weight: 600;
    color: var(--color-text-heading);
  }

  .alias-badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 1.4em;
    height: 1.4em;
    padding: 0 0.3em;
    margin-left: var(--space-2);
    border-radius: var(--radius-full, 9999px);
    background: var(--color-primary-subtle);
    color: var(--color-primary);
    font-size: var(--text-xs);
    font-weight: 600;
    cursor: help;
  }

  .backend-count {
    color: var(--color-text);
  }

  .tls-on {
    display: inline-block;
    padding: 0.125rem 0.5rem;
    border-radius: var(--radius-full);
    font-size: var(--text-sm);
    font-weight: 500;
    background: var(--color-green-subtle);
    color: var(--color-green);
  }

  .tls-off {
    color: var(--color-text-muted);
  }

  .waf-on {
    display: inline-block;
    padding: 0.125rem 0.5rem;
    border-radius: var(--radius-full);
    font-size: var(--text-sm);
    font-weight: 500;
    background: var(--color-orange-subtle);
    color: var(--color-orange);
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

  /* Whole-row visual: tint + left border accent so the operator
     sees at a glance which routes are serving 503. Applies to every
     <td> so the background covers the full row edge-to-edge even
     when individual cells set their own backgrounds. */
  tr.row-maintenance td {
    background: var(--color-orange-subtle, rgba(255, 170, 0, 0.08));
  }
  tr.row-maintenance td:first-child {
    box-shadow: inset 3px 0 0 0 var(--color-orange, #f59e0b);
  }

  .maintenance-badge {
    display: inline-block;
    padding: 0.125rem 0.5rem;
    margin-left: var(--space-2);
    border-radius: var(--radius-full);
    font-size: var(--text-xs);
    font-weight: 700;
    letter-spacing: 0.05em;
    background: var(--color-orange-subtle);
    color: var(--color-orange);
    cursor: help;
  }

  .btn-icon-maintenance.active {
    color: var(--color-orange);
  }
</style>
