<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    type BackendResponse,
    type CreateBackendRequest,
    type UpdateBackendRequest,
  } from '../lib/api';
  import StatusBadge from '../components/StatusBadge.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';

  let backends: BackendResponse[] = $state([]);
  let error = $state('');
  let loading = $state(true);

  let showForm = $state(false);
  let editingBackend: BackendResponse | null = $state(null);
  let formAddress = $state('');
  let formWeight = $state(100);
  let formHealthCheckEnabled = $state(true);
  let formHealthCheckInterval = $state(10);
  let formHealthCheckPath = $state('');
  let formTlsUpstream = $state(false);
  let formError = $state('');
  let formSubmitting = $state(false);

  let deletingBackend: BackendResponse | null = $state(null);

  async function loadData() {
    loading = true;
    error = '';
    const res = await api.listBackends();
    if (res.error) {
      error = res.error.message;
    } else if (res.data) {
      backends = res.data.backends;
    }
    loading = false;
  }

  onMount(loadData);

  function openCreateForm() {
    editingBackend = null;
    formAddress = '';
    formWeight = 100;
    formHealthCheckEnabled = true;
    formHealthCheckInterval = 10;
    formHealthCheckPath = '';
    formTlsUpstream = false;
    formError = '';
    showForm = true;
  }

  function openEditForm(b: BackendResponse) {
    editingBackend = b;
    formAddress = b.address;
    formWeight = b.weight;
    formHealthCheckEnabled = b.health_check_enabled;
    formHealthCheckInterval = b.health_check_interval_s;
    formHealthCheckPath = b.health_check_path ?? '';
    formTlsUpstream = b.tls_upstream;
    formError = '';
    showForm = true;
  }

  async function handleSubmit() {
    if (!formAddress.trim()) {
      formError = 'Address is required (e.g. 10.0.0.1:8080)';
      return;
    }
    formSubmitting = true;
    formError = '';

    if (editingBackend) {
      const body: UpdateBackendRequest = {
        address: formAddress,
        weight: formWeight,
        health_check_enabled: formHealthCheckEnabled,
        health_check_interval_s: formHealthCheckInterval,
        health_check_path: formHealthCheckPath || undefined,
        tls_upstream: formTlsUpstream,
      };
      const res = await api.updateBackend(editingBackend.id, body);
      if (res.error) {
        formError = res.error.message;
        formSubmitting = false;
        return;
      }
    } else {
      const body: CreateBackendRequest = {
        address: formAddress,
        weight: formWeight,
        health_check_enabled: formHealthCheckEnabled,
        health_check_interval_s: formHealthCheckInterval,
        health_check_path: formHealthCheckPath || undefined,
        tls_upstream: formTlsUpstream,
      };
      const res = await api.createBackend(body);
      if (res.error) {
        formError = res.error.message;
        formSubmitting = false;
        return;
      }
    }

    formSubmitting = false;
    showForm = false;
    await loadData();
  }

  async function handleDelete() {
    if (!deletingBackend) return;
    const res = await api.deleteBackend(deletingBackend.id);
    if (res.error) {
      error = res.error.message;
    }
    deletingBackend = null;
    await loadData();
  }

  function handleKeydown(e: KeyboardEvent) {
    if (showForm && e.key === 'Escape') showForm = false;
    if (showForm && e.key === 'Enter' && !formSubmitting) handleSubmit();
  }
</script>

<svelte:window onkeydown={handleKeydown} />

<div class="backends-page">
  <div class="page-header">
    <h1>Backends</h1>
    <button class="btn btn-primary" onclick={openCreateForm}>Add Backend</button>
  </div>

  {#if error}
    <div class="error-banner">{error}</div>
  {/if}

  {#if loading}
    <p class="loading">Loading backends...</p>
  {:else if backends.length === 0}
    <div class="empty-state">
      <p>No backends configured yet.</p>
      <button class="btn btn-primary" onclick={openCreateForm}>Add your first backend</button>
    </div>
  {:else}
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>Address</th>
            <th>Health</th>
            <th>Weight</th>
            <th>Health Check</th>
            <th>TLS</th>
            <th>Connections</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each backends as b}
            <tr>
              <td class="mono">{b.address}</td>
              <td><StatusBadge status={b.health_status} /></td>
              <td>{b.weight}</td>
              <td>
                {#if b.health_check_enabled}
                  <span class="badge-on">{b.health_check_path ? `HTTP ${b.health_check_path}` : 'TCP'}</span>
                  <span class="text-muted small"> / {b.health_check_interval_s}s</span>
                {:else}
                  <span class="text-muted">Disabled</span>
                {/if}
              </td>
              <td>
                {#if b.tls_upstream}
                  <span class="badge-on">TLS</span>
                {:else}
                  <span class="text-muted">Plain</span>
                {/if}
              </td>
              <td class="mono">{b.active_connections}</td>
              <td class="actions">
                <button class="btn-icon" onclick={() => openEditForm(b)} title="Edit">
                  {@html editIcon}
                </button>
                <button class="btn-icon btn-icon-danger" onclick={() => (deletingBackend = b)} title="Delete">
                  {@html trashIcon}
                </button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}

  {#if deletingBackend}
    <ConfirmDialog
      title="Delete Backend"
      message="Delete backend {deletingBackend.address}? Routes using this backend will lose it from their pool."
      confirmLabel="Delete"
      onconfirm={handleDelete}
      oncancel={() => (deletingBackend = null)}
    />
  {/if}

  {#if showForm}
    <div class="overlay" role="dialog" onclick={(e) => { if (e.target === e.currentTarget) showForm = false; }}>
      <div class="modal">
        <h2>{editingBackend ? 'Edit Backend' : 'Add Backend'}</h2>

        {#if formError}
          <div class="form-error">{formError}</div>
        {/if}

        <div class="form-group">
          <label>Address <span class="required">*</span></label>
          <input type="text" bind:value={formAddress} placeholder="10.0.0.1:8080" />
        </div>

        <div class="form-row">
          <div class="form-group">
            <label>Weight</label>
            <input type="number" bind:value={formWeight} min="1" max="1000" />
          </div>
          <div class="form-group">
            <label>Health Check Interval (s)</label>
            <input type="number" bind:value={formHealthCheckInterval} min="5" max="300" />
          </div>
        </div>

        <div class="form-group">
          <label>Health Check Path (empty = TCP only)</label>
          <input type="text" bind:value={formHealthCheckPath} placeholder="/healthz" />
        </div>

        <div class="form-row">
          <div class="form-group">
            <label class="checkbox-item">
              <input type="checkbox" bind:checked={formHealthCheckEnabled} />
              Health check enabled
            </label>
          </div>
          <div class="form-group">
            <label class="checkbox-item">
              <input type="checkbox" bind:checked={formTlsUpstream} />
              TLS upstream
            </label>
          </div>
        </div>

        <div class="form-actions">
          <button class="btn btn-cancel" onclick={() => (showForm = false)}>Cancel</button>
          <button class="btn btn-primary" onclick={handleSubmit} disabled={formSubmitting}>
            {formSubmitting ? 'Saving...' : editingBackend ? 'Update' : 'Create'}
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
  .backends-page { max-width: 1100px; }
  .page-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.5rem; }
  .page-header h1 { margin: 0; }
  .error-banner { background: rgba(239, 68, 68, 0.1); border: 1px solid var(--color-red); border-radius: 0.5rem; color: var(--color-red); padding: 0.75rem 1rem; margin-bottom: 1rem; }
  .loading { color: var(--color-text-muted); }
  .empty-state { display: flex; flex-direction: column; align-items: center; gap: 1rem; padding: 3rem 0; color: var(--color-text-muted); }
  .table-wrapper { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 0.75rem 1rem; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--color-text-muted); border-bottom: 1px solid var(--color-border); }
  td { padding: 0.75rem 1rem; border-bottom: 1px solid var(--color-border); font-size: 0.875rem; vertical-align: middle; }
  tr:hover td { background: rgba(255, 255, 255, 0.02); }
  .mono { font-family: var(--mono); font-size: 0.8125rem; }
  .text-muted { color: var(--color-text-muted); }
  .small { font-size: 0.8125rem; }
  .badge-on { display: inline-block; padding: 0.125rem 0.5rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 500; background: rgba(34, 197, 94, 0.1); color: var(--color-green); }
  .actions { display: flex; gap: 0.25rem; }
  .btn-icon { display: flex; align-items: center; justify-content: center; width: 2rem; height: 2rem; border: none; border-radius: 0.375rem; background: none; color: var(--color-text-muted); transition: background-color 0.15s, color 0.15s; }
  .btn-icon:hover { background: var(--color-bg-hover); color: var(--color-text); }
  .btn-icon-danger:hover { background: rgba(239, 68, 68, 0.1); color: var(--color-red); }
  .overlay { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.5); display: flex; align-items: center; justify-content: center; z-index: 100; }
  .modal { background: var(--color-bg-card); border: 1px solid var(--color-border); border-radius: 0.75rem; padding: 1.5rem; width: 90%; max-width: 480px; max-height: 90vh; overflow-y: auto; }
  .modal h2 { margin: 0 0 1.25rem; }
  .form-error { background: rgba(239, 68, 68, 0.1); border: 1px solid var(--color-red); border-radius: 0.375rem; color: var(--color-red); padding: 0.5rem 0.75rem; font-size: 0.8125rem; margin-bottom: 1rem; }
  .form-group { margin-bottom: 1rem; }
  .form-group label { display: block; font-size: 0.8125rem; font-weight: 500; color: var(--color-text-muted); margin-bottom: 0.375rem; }
  .required { color: var(--color-red); }
  .form-group input[type="text"], .form-group input[type="number"] { width: 100%; padding: 0.5rem 0.75rem; border: 1px solid var(--color-border); border-radius: 0.375rem; background: var(--color-bg-input); color: var(--color-text); font-size: 0.875rem; }
  .form-group input:focus { outline: none; border-color: var(--color-primary); }
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
