<script lang="ts">
  import { api, type SecurityHeaderPreset } from '../../lib/api';
  import ConfirmDialog from '../ConfirmDialog.svelte';
  import { showToast } from '../../lib/toast';

  interface Props {
    customPresets: SecurityHeaderPreset[];
    expanded: boolean;
    toggleSection: () => void;
  }

  let {
    customPresets = $bindable(),
    expanded,
    toggleSection,
  }: Props = $props();

  const builtinPresets: Array<{ name: string; description: string }> = [
    { name: 'strict', description: 'X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy: no-referrer, Permissions-Policy: camera=(), microphone=(), geolocation=()' },
    { name: 'moderate', description: 'X-Frame-Options: SAMEORIGIN, X-Content-Type-Options: nosniff, Referrer-Policy: strict-origin-when-cross-origin' },
    { name: 'none', description: 'No security headers added' },
  ];

  let showPresetForm = $state(false);
  let presetEditing: number | null = $state(null);
  let presetName = $state('');
  let presetHeaders = $state('');
  let presetError = $state('');
  let presetSaving = $state(false);
  let deletingPresetIdx: number | null = $state(null);

  function headersToText(headers: Record<string, string>): string {
    return Object.entries(headers).map(([k, v]) => `${k}=${v}`).join('\n');
  }

  function textToHeaders(text: string): Record<string, string> {
    const headers: Record<string, string> = {};
    for (const line of text.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const idx = trimmed.indexOf('=');
      if (idx < 1) continue;
      headers[trimmed.slice(0, idx).trim()] = trimmed.slice(idx + 1).trim();
    }
    return headers;
  }

  function openPresetCreate() {
    presetEditing = null;
    presetName = '';
    presetHeaders = '';
    presetError = '';
    showPresetForm = true;
  }

  function openPresetEdit(idx: number) {
    const p = customPresets[idx];
    presetEditing = idx;
    presetName = p.name;
    presetHeaders = headersToText(p.headers);
    presetError = '';
    showPresetForm = true;
  }

  async function savePreset() {
    if (!presetName.trim()) {
      presetError = 'Name is required.';
      return;
    }
    const headers = textToHeaders(presetHeaders);
    if (Object.keys(headers).length === 0) {
      presetError = 'At least one header (Key=Value) is required.';
      return;
    }
    presetSaving = true;
    presetError = '';
    const updated = [...customPresets];
    if (presetEditing !== null) {
      updated[presetEditing] = { name: presetName.trim(), headers };
    } else {
      updated.push({ name: presetName.trim(), headers });
    }
    const res = await api.updateSettings({ custom_security_presets: updated });
    if (res.error) {
      presetError = res.error.message;
    } else {
      customPresets = res.data?.custom_security_presets ?? updated;
      showPresetForm = false;
      showToast(presetEditing !== null ? 'Preset updated' : 'Preset created', 'success');
    }
    presetSaving = false;
  }

  async function confirmDeletePreset() {
    if (deletingPresetIdx === null) return;
    const updated = customPresets.filter((_, i) => i !== deletingPresetIdx);
    const res = await api.updateSettings({ custom_security_presets: updated });
    if (!res.error) {
      customPresets = res.data?.custom_security_presets ?? updated;
    }
    deletingPresetIdx = null;
  }
</script>

<section class="settings-section">
  <button class="settings-collapsible-header" class:open={expanded} onclick={toggleSection}>
    <h2>Security Header Presets</h2>
    <span class="settings-chevron" class:expanded></span>
  </button>
  {#if expanded}
    <div class="settings-section-body">
      <p class="settings-hint">Custom presets appear alongside builtin presets (strict, moderate, none) in the route security headers dropdown.</p>

      <div class="settings-table-wrap">
        <table class="settings-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Headers</th>
              <th>Type</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {#each builtinPresets as bp}
              <tr>
                <td><code>{bp.name}</code></td>
                <td class="preset-desc">{bp.description}</td>
                <td><span class="badge badge-builtin">builtin</span></td>
                <td><span class="text-muted">builtin</span></td>
              </tr>
            {/each}
            {#each customPresets as cp, idx}
              <tr>
                <td><code>{cp.name}</code></td>
                <td class="preset-desc">{Object.keys(cp.headers).length} header{Object.keys(cp.headers).length !== 1 ? 's' : ''}</td>
                <td><span class="badge badge-custom">custom</span></td>
                <td class="settings-actions-cell">
                  <button class="settings-btn-action settings-btn-edit" onclick={() => openPresetEdit(idx)}>Edit</button>
                  <button class="settings-btn-action settings-btn-delete" onclick={() => deletingPresetIdx = idx}>Delete</button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <div class="settings-actions-left">
        <button class="btn btn-primary" onclick={openPresetCreate}>Add Preset</button>
      </div>
    </div>
  {/if}
</section>

<!-- Preset form modal -->
{#if showPresetForm}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div class="settings-overlay" onclick={(e) => { if (e.target === e.currentTarget) showPresetForm = false; }} onkeydown={(e) => { if (e.key === 'Escape') showPresetForm = false; }} role="dialog" aria-modal="true" tabindex="-1">
    <div class="settings-dialog" role="document">
      <h3>{presetEditing !== null ? 'Edit' : 'Add'} Security Header Preset</h3>
      <div class="settings-form-row">
        <label for="preset-name">Preset Name <span class="settings-required">*</span></label>
        <input id="preset-name" type="text" bind:value={presetName} placeholder="e.g. my-api-preset" />
      </div>
      <div class="settings-form-row">
        <label for="preset-headers">Headers (one per line, Key=Value) <span class="settings-required">*</span></label>
        <textarea id="preset-headers" bind:value={presetHeaders} rows="6" placeholder="X-Frame-Options=DENY&#10;X-Content-Type-Options=nosniff&#10;Referrer-Policy=no-referrer"></textarea>
      </div>
      {#if presetError}
        <div class="settings-form-error">{presetError}</div>
      {/if}
      <div class="settings-dialog-actions">
        <button class="btn btn-cancel" onclick={() => showPresetForm = false}>Cancel</button>
        <button class="btn btn-primary" onclick={savePreset} disabled={presetSaving}>
          {presetSaving ? 'Saving...' : 'Save'}
        </button>
      </div>
    </div>
  </div>
{/if}

<!-- Delete preset confirm -->
{#if deletingPresetIdx !== null}
  <ConfirmDialog
    title="Delete Security Header Preset"
    message="Are you sure you want to delete the preset '{customPresets[deletingPresetIdx]?.name}'?"
    onconfirm={confirmDeletePreset}
    oncancel={() => deletingPresetIdx = null}
  />
{/if}

<style>
  .badge {
    display: inline-block;
    padding: 0.125rem 0.5rem;
    border-radius: 0.25rem;
    font-size: 0.75rem;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }

  .badge-builtin {
    background: var(--color-bg-input);
    color: var(--color-text-muted);
  }

  .badge-custom {
    background: var(--color-primary-subtle);
    color: var(--color-primary);
  }

  .preset-desc {
    font-size: 0.8125rem;
    color: var(--color-text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .text-muted {
    color: var(--color-text-muted);
    font-size: var(--text-xs);
    font-style: italic;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.875rem;
  }

  th {
    text-align: left;
    padding: 0.625rem 0.75rem;
    border-bottom: 1px solid var(--color-border);
    color: var(--color-text-muted);
    font-weight: 500;
    font-size: 0.8125rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  td {
    padding: 0.625rem 0.75rem;
    border-bottom: 1px solid var(--color-border);
    vertical-align: middle;
  }

  td code {
    font-family: var(--mono);
    font-size: 0.8125rem;
    background: var(--color-bg-input);
    padding: 0.125rem 0.375rem;
    border-radius: 0.25rem;
  }
</style>
