<script lang="ts">
  import { api, type ImportDiffResponse } from '../../lib/api';

  interface Props {
    expanded: boolean;
    toggleSection: () => void;
    onReload: () => Promise<void>;
  }

  let { expanded, toggleSection, onReload }: Props = $props();

  let exporting = $state(false);
  let exportError = $state('');
  let importFile: File | null = $state(null);
  let importToml = $state('');
  let importError = $state('');
  let importDiff: ImportDiffResponse | null = $state(null);
  let importPreviewing = $state(false);
  let importApplying = $state(false);
  let importSuccess = $state('');

  async function handleExport() {
    exporting = true;
    exportError = '';
    const res = await api.exportConfig();
    if (res.error) {
      exportError = res.error.message;
    } else if (res.data) {
      const blob = new Blob([res.data], { type: 'application/toml' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'lorica-config.toml';
      a.click();
      URL.revokeObjectURL(url);
    }
    exporting = false;
  }

  async function handleFileSelect(e: Event) {
    const target = e.target as HTMLInputElement;
    const file = target.files?.[0];
    if (!file) return;
    importFile = file;
    importToml = await file.text();
    importDiff = null;
    importError = '';
    importSuccess = '';
  }

  async function previewImport() {
    if (!importToml.trim()) {
      importError = 'No TOML content provided.';
      return;
    }
    importPreviewing = true;
    importError = '';
    importDiff = null;
    const res = await api.importPreview(importToml);
    if (res.error) {
      importError = res.error.message;
    } else if (res.data) {
      importDiff = res.data;
    }
    importPreviewing = false;
  }

  async function applyImport() {
    importApplying = true;
    importError = '';
    importSuccess = '';
    const res = await api.importConfig(importToml);
    if (res.error) {
      importError = res.error.message;
    } else {
      importSuccess = 'Configuration imported successfully.';
      importDiff = null;
      importToml = '';
      importFile = null;
      await onReload();
    }
    importApplying = false;
  }

  function cancelImport() {
    importDiff = null;
    importError = '';
    importToml = '';
    importFile = null;
  }

  function diffHasChanges(diff: ImportDiffResponse): boolean {
    const e = (d: { added: string[]; modified: string[]; removed: string[] }) =>
      d.added.length > 0 || d.modified.length > 0 || d.removed.length > 0;
    return (
      e(diff.routes) || e(diff.backends) || e(diff.certificates) ||
      e(diff.route_backends) || e(diff.notification_configs) ||
      e(diff.user_preferences) || e(diff.admin_users) ||
      diff.global_settings.changes.length > 0
    );
  }
</script>

<section class="settings-section">
  <button class="settings-collapsible-header" class:open={expanded} onclick={toggleSection}>
    <h2>Configuration Export / Import</h2>
    <span class="settings-chevron" class:expanded></span>
  </button>
  {#if expanded}
    <div class="settings-section-body">
      <div class="export-import-grid">
        <!-- Export -->
        <div class="settings-form-card">
          <h3>Export</h3>
          <p class="settings-hint">Download the full configuration as a TOML file.</p>
          {#if exportError}
            <div class="settings-form-error">{exportError}</div>
          {/if}
          <div class="actions-center">
            <button class="btn btn-primary" onclick={handleExport} disabled={exporting}>
              {exporting ? 'Exporting...' : 'Download TOML'}
            </button>
          </div>
        </div>

        <!-- Import -->
        <div class="settings-form-card">
          <h3>Import</h3>
          <p class="settings-hint">Upload a TOML file to preview and apply changes.</p>
          {#if !importDiff}
            <div class="actions-center">
              <label class="file-input-label">
                <input type="file" accept=".toml,text/plain" onchange={handleFileSelect} style="display:none" />
                {importFile ? importFile.name : 'Choose TOML file...'}
              </label>
            </div>
            {#if importToml}
              <p class="file-info">File loaded: {importFile?.name} ({importToml.length} bytes)</p>
            {/if}
            {#if importError}
              <div class="settings-form-error">{importError}</div>
            {/if}
            {#if importSuccess}
              <div class="form-success">{importSuccess}</div>
            {/if}
            <div class="actions-center">
              <button class="btn btn-primary" onclick={previewImport} disabled={!importToml || importPreviewing}>
                {importPreviewing ? 'Analyzing...' : 'Preview Changes'}
              </button>
            </div>
          {/if}
        </div>
      </div>

      <!-- Diff preview -->
      {#if importDiff}
        <div class="diff-preview">
          <h3>Import Preview</h3>
          {#if !diffHasChanges(importDiff)}
            <p class="settings-empty-text">No changes detected - the imported configuration is identical to the current one.</p>
          {:else}
            {@const sections = [
              { label: 'Routes', diff: importDiff.routes },
              { label: 'Backends', diff: importDiff.backends },
              { label: 'Certificates', diff: importDiff.certificates },
              { label: 'Route-Backend Links', diff: importDiff.route_backends },
              { label: 'Notification Configs', diff: importDiff.notification_configs },
              { label: 'User Preferences', diff: importDiff.user_preferences },
              { label: 'Admin Users', diff: importDiff.admin_users },
            ]}
            {#each sections as sec}
              {#if sec.diff.added.length > 0 || sec.diff.modified.length > 0 || sec.diff.removed.length > 0}
                <div class="diff-section">
                  <h4>{sec.label}</h4>
                  {#if sec.diff.added.length > 0}
                    <ul class="diff-list diff-added">
                      {#each sec.diff.added as item}
                        <li>+ {item}</li>
                      {/each}
                    </ul>
                  {/if}
                  {#if sec.diff.modified.length > 0}
                    <ul class="diff-list diff-modified">
                      {#each sec.diff.modified as item}
                        <li>~ {item}</li>
                      {/each}
                    </ul>
                  {/if}
                  {#if sec.diff.removed.length > 0}
                    <ul class="diff-list diff-removed">
                      {#each sec.diff.removed as item}
                        <li>- {item}</li>
                      {/each}
                    </ul>
                  {/if}
                </div>
              {/if}
            {/each}
            {#if importDiff.global_settings.changes.length > 0}
              <div class="diff-section">
                <h4>Global Settings</h4>
                <ul class="diff-list diff-modified">
                  {#each importDiff.global_settings.changes as ch}
                    <li>~ {ch.key}: {ch.old_value} -&gt; {ch.new_value}</li>
                  {/each}
                </ul>
              </div>
            {/if}
          {/if}
          {#if importError}
            <div class="settings-form-error">{importError}</div>
          {/if}
          <div class="diff-actions">
            <button class="btn btn-cancel" onclick={cancelImport}>Cancel</button>
            {#if diffHasChanges(importDiff)}
              <button class="btn btn-primary" onclick={applyImport} disabled={importApplying}>
                {importApplying ? 'Applying...' : 'Apply Import'}
              </button>
            {/if}
          </div>
        </div>
      {/if}
    </div>
  {/if}
</section>

<style>
  .form-success {
    color: var(--color-green);
    font-size: 0.8125rem;
    margin: 0.5rem 0;
  }

  .file-info {
    font-size: 0.8125rem;
    color: var(--color-text-muted);
    margin: 0.5rem 0;
  }

  .export-import-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin-bottom: 1rem;
  }

  .diff-preview {
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-radius: 0.75rem;
    padding: 1.25rem;
  }

  .diff-preview h3 {
    margin: 0 0 1rem;
  }

  .diff-section {
    margin-bottom: 1rem;
  }

  .diff-section h4 {
    color: var(--color-text-heading);
    font-size: 0.875rem;
    margin: 0 0 0.5rem;
  }

  .diff-list {
    list-style: none;
    margin: 0;
    padding: 0;
    font-family: var(--mono);
    font-size: 0.8125rem;
  }

  .diff-list li {
    padding: 0.25rem 0.5rem;
    border-radius: 0.25rem;
    margin-bottom: 0.125rem;
  }

  .diff-added li {
    background: var(--color-green-subtle);
    color: var(--color-green);
  }

  .diff-modified li {
    background: var(--color-orange-subtle);
    color: var(--color-orange);
  }

  .diff-removed li {
    background: var(--color-red-subtle);
    color: var(--color-red);
  }

  .diff-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.75rem;
    margin-top: 1rem;
  }

  :global(.actions-center) {
    display: flex;
    justify-content: center;
    gap: 0.75rem;
    margin-top: 0.75rem;
  }

  .file-input-label {
    display: inline-flex;
    align-items: center;
    padding: 0.5rem 1rem;
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    background: var(--color-bg-input);
    color: var(--color-text-muted);
    font-size: 0.875rem;
    cursor: pointer;
    transition: all 0.15s;
  }
  .file-input-label:hover {
    background: var(--color-bg-hover);
    border-color: var(--color-primary);
    color: var(--color-text);
  }
</style>
