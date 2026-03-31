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
  let formName = $state('');
  let formGroupName = $state('');
  let formWeight = $state(100);
  let formHealthCheckEnabled = $state(true);
  let formHealthCheckInterval = $state(10);
  let formHealthCheckPath = $state('');
  let formTlsUpstream = $state(false);
  let formError = $state('');
  let formSubmitting = $state(false);

  let addressError = $state('');

  let deletingBackend: BackendResponse | null = $state(null);

  const ADDRESS_PATTERN = /^[a-zA-Z0-9._-]+:\d{1,5}$/;

  function validateAddress(value: string): string {
    if (!value.trim()) return 'Address is required (e.g. 10.0.0.1:8080)';
    if (!ADDRESS_PATTERN.test(value.trim())) return 'Address must be in host:port format';
    const port = parseInt(value.split(':').pop()!, 10);
    if (port < 1 || port > 65535) return 'Port must be between 1 and 65535';
    return '';
  }

  function validate(): string {
    const addrErr = validateAddress(formAddress);
    if (addrErr) return addrErr;
    if (formWeight < 1 || formWeight > 1000) return 'Weight must be between 1 and 1000';
    if (formHealthCheckInterval < 5 || formHealthCheckInterval > 3600) return 'Health check interval must be between 5 and 3600 seconds';
    return '';
  }

  function handleAddressBlur() {
    addressError = validateAddress(formAddress);
  }

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
    formName = '';
    formGroupName = '';
    formWeight = 100;
    formHealthCheckEnabled = true;
    formHealthCheckInterval = 10;
    formHealthCheckPath = '';
    formTlsUpstream = false;
    formError = '';
    addressError = '';
    showForm = true;
  }

  function openEditForm(b: BackendResponse) {
    editingBackend = b;
    formAddress = b.address;
    formName = b.name ?? '';
    formGroupName = b.group_name ?? '';
    formWeight = b.weight;
    formHealthCheckEnabled = b.health_check_enabled;
    formHealthCheckInterval = b.health_check_interval_s;
    formHealthCheckPath = b.health_check_path ?? '';
    formTlsUpstream = b.tls_upstream;
    formError = '';
    addressError = '';
    showForm = true;
  }

  async function handleSubmit() {
    const err = validate();
    if (err) {
      formError = err;
      return;
    }
    formSubmitting = true;
    formError = '';

    if (editingBackend) {
      const body: UpdateBackendRequest = {
        address: formAddress,
        name: formName || undefined,
        group_name: formGroupName || undefined,
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
        name: formName || undefined,
        group_name: formGroupName || undefined,
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
            <th>Name</th>
            <th>Group</th>
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
              <td>{b.name || '-'}</td>
              <td>{b.group_name || '-'}</td>
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
          <input type="text" bind:value={formAddress} placeholder="10.0.0.1:8080" pattern="^[a-zA-Z0-9._-]+:\d{1,5}$" onblur={handleAddressBlur} />
          {#if addressError}
            <span class="field-error">{addressError}</span>
          {/if}
        </div>

        <div class="form-row">
          <div class="form-group">
            <label>Name</label>
            <input type="text" bind:value={formName} placeholder="e.g. web-server-01, wazuh-node" />
          </div>
          <div class="form-group">
            <label>Group</label>
            <input type="text" bind:value={formGroupName} placeholder="e.g. kubernetes, production, dmz" />
          </div>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label>Weight</label>
            <input type="number" bind:value={formWeight} min="1" max="1000" />
          </div>
          <div class="form-group">
            <label>Health Check Interval (s)</label>
            <input type="number" bind:value={formHealthCheckInterval} min="5" max="3600" />
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
  .backends-page { max-width: none; }
  .badge-on { display: inline-block; padding: 0.125rem 0.5rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 500; background: rgba(34, 197, 94, 0.1); color: var(--color-green); }
  .field-error { display: block; color: var(--color-red); font-size: var(--text-xs); margin-top: 0.25rem; }
</style>
