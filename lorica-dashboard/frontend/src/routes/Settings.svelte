<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    type GlobalSettingsResponse,
    type NotificationConfigResponse,
    type UserPreferenceResponse,
    type ImportDiffResponse,
  } from '../lib/api';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';

  // Global settings
  let settings: GlobalSettingsResponse | null = $state(null);
  let settingsForm = $state({ management_port: 9443, log_level: 'info', default_health_check_interval_s: 10, cert_warning_days: 30, cert_critical_days: 7, default_topology_type: 'single_vm' });
  let settingsSaving = $state(false);
  let settingsMsg = $state('');
  let settingsError = $state('');

  // Notifications
  let notifications: NotificationConfigResponse[] = $state([]);
  let showNotifForm = $state(false);
  let notifEditing: NotificationConfigResponse | null = $state(null);
  let notifChannel = $state('email');
  let notifEnabled = $state(true);
  let notifConfig = $state('');
  let notifAlertTypes = $state('');
  let notifError = $state('');
  let notifSaving = $state(false);
  let deletingNotif: NotificationConfigResponse | null = $state(null);
  let testingNotif = $state('');
  let testNotifResult = $state('');

  // Preferences
  let preferences: UserPreferenceResponse[] = $state([]);
  let deletingPref: UserPreferenceResponse | null = $state(null);

  // Export/Import
  let exporting = $state(false);
  let exportError = $state('');
  let importFile: File | null = $state(null);
  let importToml = $state('');
  let importError = $state('');
  let importDiff: ImportDiffResponse | null = $state(null);
  let importPreviewing = $state(false);
  let importApplying = $state(false);
  let importSuccess = $state('');

  // Theme
  let theme = $state<'dark' | 'light'>('light');

  let loading = $state(true);
  let error = $state('');

  async function loadAll() {
    loading = true;
    error = '';
    const [settingsRes, notifRes, prefRes] = await Promise.all([
      api.getSettings(),
      api.listNotifications(),
      api.listPreferences(),
    ]);
    if (settingsRes.error) {
      error = settingsRes.error.message;
    } else if (settingsRes.data) {
      settings = settingsRes.data;
      settingsForm = { ...settingsRes.data };
    }
    if (notifRes.data) {
      notifications = notifRes.data.notifications;
    }
    if (prefRes.data) {
      preferences = prefRes.data.preferences;
      const themePref = prefRes.data.preferences.find((p) => p.preference_key === 'theme');
      if (themePref && (themePref.value === 'always' || themePref.value === 'never')) {
        theme = themePref.value === 'always' ? 'light' : 'dark';
        applyTheme(theme);
      }
    }
    loading = false;
  }

  onMount(loadAll);

  // ---- Theme ----

  function applyTheme(t: 'dark' | 'light') {
    document.documentElement.setAttribute('data-theme', t);
  }

  async function toggleTheme() {
    theme = theme === 'dark' ? 'light' : 'dark';
    applyTheme(theme);
    const themePref = preferences.find((p) => p.preference_key === 'theme');
    if (themePref) {
      await api.updatePreference(themePref.id, theme === 'light' ? 'always' : 'never');
    }
    await loadAll();
  }

  // ---- Settings ----

  async function saveSettings() {
    settingsSaving = true;
    settingsMsg = '';
    settingsError = '';
    const res = await api.updateSettings(settingsForm);
    if (res.error) {
      settingsError = res.error.message;
    } else if (res.data) {
      settings = res.data;
      settingsForm = { ...res.data };
      settingsMsg = 'Settings saved.';
      setTimeout(() => settingsMsg = '', 3000);
    }
    settingsSaving = false;
  }

  // ---- Notifications ----

  function openNotifCreate() {
    notifEditing = null;
    notifChannel = 'email';
    notifEnabled = true;
    notifConfig = '';
    notifAlertTypes = '';
    notifError = '';
    showNotifForm = true;
  }

  function openNotifEdit(nc: NotificationConfigResponse) {
    notifEditing = nc;
    notifChannel = nc.channel;
    notifEnabled = nc.enabled;
    notifConfig = nc.config;
    notifAlertTypes = nc.alert_types.join(', ');
    notifError = '';
    showNotifForm = true;
  }

  async function saveNotification() {
    notifSaving = true;
    notifError = '';
    const alertArr = notifAlertTypes.split(',').map((s) => s.trim()).filter(Boolean);
    const body = { channel: notifChannel, enabled: notifEnabled, config: notifConfig, alert_types: alertArr };

    if (notifEditing) {
      const res = await api.updateNotification(notifEditing.id, body);
      if (res.error) { notifError = res.error.message; notifSaving = false; return; }
    } else {
      const res = await api.createNotification(body);
      if (res.error) { notifError = res.error.message; notifSaving = false; return; }
    }
    showNotifForm = false;
    notifSaving = false;
    await loadAll();
  }

  async function confirmDeleteNotif() {
    if (!deletingNotif) return;
    await api.deleteNotification(deletingNotif.id);
    deletingNotif = null;
    await loadAll();
  }

  async function handleTestNotif(id: string) {
    testingNotif = id;
    testNotifResult = '';
    const res = await api.testNotification(id);
    if (res.error) {
      testNotifResult = `Error: ${res.error.message}`;
    } else {
      testNotifResult = `Valid (${res.data?.channel})`;
    }
    testingNotif = '';
    setTimeout(() => testNotifResult = '', 3000);
  }

  // ---- Preferences ----

  async function changePrefValue(pref: UserPreferenceResponse, newVal: string) {
    await api.updatePreference(pref.id, newVal);
    await loadAll();
  }

  async function confirmDeletePref() {
    if (!deletingPref) return;
    await api.deletePreference(deletingPref.id);
    deletingPref = null;
    await loadAll();
  }

  // ---- Export ----

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

  // ---- Import ----

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
      await loadAll();
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

<div class="settings-page">
  <div class="page-header">
    <h1>Settings</h1>
  </div>

  {#if error}
    <div class="error-banner">{error}</div>
  {/if}

  {#if loading}
    <p class="loading">Loading...</p>
  {:else}
    <!-- Theme -->
    <section class="section">
      <div class="section-header">
        <h2>Appearance</h2>
        <button class="btn btn-secondary" onclick={toggleTheme}>
          {theme === 'dark' ? 'Switch to Light' : 'Switch to Dark'}
        </button>
      </div>
      <p class="section-hint">Current theme: {theme}.</p>
    </section>

    <!-- Global Settings -->
    <section class="section">
      <h2>Global Configuration</h2>
      <div class="form-card">
        <div class="form-row">
          <label for="mgmt-port">Management Port</label>
          <input id="mgmt-port" type="number" bind:value={settingsForm.management_port} min="1" max="65535" disabled />
          <span class="hint">Read-only - requires restart to change</span>
        </div>
        <div class="form-row">
          <label for="log-level">Log Level</label>
          <select id="log-level" bind:value={settingsForm.log_level}>
            <option value="trace">trace</option>
            <option value="debug">debug</option>
            <option value="info">info</option>
            <option value="warn">warn</option>
            <option value="error">error</option>
          </select>
        </div>
        <div class="form-row">
          <label for="hc-interval">Default Health Check Interval (s)</label>
          <input id="hc-interval" type="number" bind:value={settingsForm.default_health_check_interval_s} min="1" max="3600" />
        </div>
        <div class="form-row">
          <label for="cert-warn">Certificate Warning Threshold (days)</label>
          <input id="cert-warn" type="number" bind:value={settingsForm.cert_warning_days} min="1" max="365" />
        </div>
        <div class="form-row">
          <label for="cert-crit">Certificate Critical Threshold (days)</label>
          <input id="cert-crit" type="number" bind:value={settingsForm.cert_critical_days} min="1" max="365" />
        </div>
        <div class="form-row">
          <label for="default-topo">Default Topology Type</label>
          <select id="default-topo" bind:value={settingsForm.default_topology_type}>
            <option value="single_vm">Single VM (passive only)</option>
            <option value="ha">High Availability (active probes)</option>
            <option value="docker_swarm">Docker Swarm</option>
            <option value="kubernetes">Kubernetes</option>
            <option value="custom">Custom</option>
          </select>
        </div>
        {#if settingsError}
          <div class="form-error">{settingsError}</div>
        {/if}
        {#if settingsMsg}
          <div class="form-success">{settingsMsg}</div>
        {/if}
        <div class="form-actions">
          <button class="btn btn-primary" onclick={saveSettings} disabled={settingsSaving}>
            {settingsSaving ? 'Saving...' : 'Save Settings'}
          </button>
        </div>
      </div>
    </section>

    <!-- Notification Preferences -->
    <section class="section">
      <div class="section-header">
        <h2>Notification Channels</h2>
        <button class="btn btn-primary" onclick={openNotifCreate}>Add Channel</button>
      </div>
      <p class="section-hint">Stdout logging is always enabled. Configure additional channels below.</p>

      {#if notifications.length === 0}
        <p class="empty-text">No notification channels configured.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Channel</th>
                <th>Enabled</th>
                <th>Alert Types</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {#each notifications as nc}
                <tr>
                  <td class="capitalize">{nc.channel}</td>
                  <td>
                    <span class="status-dot" class:enabled={nc.enabled} class:disabled={!nc.enabled}></span>
                    {nc.enabled ? 'Yes' : 'No'}
                  </td>
                  <td>{nc.alert_types.join(', ') || '-'}</td>
                  <td class="actions-cell">
                    <button class="btn-link" onclick={() => handleTestNotif(nc.id)} disabled={testingNotif === nc.id}>Test</button>
                    <button class="btn-link" onclick={() => openNotifEdit(nc)}>Edit</button>
                    <button class="btn-link danger" onclick={() => deletingNotif = nc}>Delete</button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>

    <!-- Preference Memory -->
    <section class="section">
      <h2>Preference Memory</h2>
      <p class="section-hint">Stored decisions for prompts (never/always/once).</p>

      {#if preferences.length === 0}
        <p class="empty-text">No stored preferences.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Key</th>
                <th>Value</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {#each preferences as pref}
                <tr>
                  <td><code>{pref.preference_key}</code></td>
                  <td>
                    <select
                      value={pref.value}
                      onchange={(e) => changePrefValue(pref, (e.target as HTMLSelectElement).value)}
                    >
                      <option value="never">never</option>
                      <option value="always">always</option>
                      <option value="once">once</option>
                    </select>
                  </td>
                  <td class="actions-cell">
                    <button class="btn-link danger" onclick={() => deletingPref = pref}>Delete</button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>

    <!-- Export/Import -->
    <section class="section">
      <h2>Configuration Export / Import</h2>

      <div class="export-import-grid">
        <!-- Export -->
        <div class="form-card">
          <h3>Export</h3>
          <p class="section-hint">Download the full configuration as a TOML file.</p>
          {#if exportError}
            <div class="form-error">{exportError}</div>
          {/if}
          <button class="btn btn-primary" onclick={handleExport} disabled={exporting}>
            {exporting ? 'Exporting...' : 'Download TOML'}
          </button>
        </div>

        <!-- Import -->
        <div class="form-card">
          <h3>Import</h3>
          <p class="section-hint">Upload a TOML file to preview and apply changes.</p>
          {#if !importDiff}
            <div class="form-row">
              <label for="import-file">TOML File</label>
              <input id="import-file" type="file" accept=".toml,text/plain" onchange={handleFileSelect} />
            </div>
            {#if importToml}
              <p class="file-info">File loaded: {importFile?.name} ({importToml.length} bytes)</p>
            {/if}
            {#if importError}
              <div class="form-error">{importError}</div>
            {/if}
            {#if importSuccess}
              <div class="form-success">{importSuccess}</div>
            {/if}
            <button class="btn btn-primary" onclick={previewImport} disabled={!importToml || importPreviewing}>
              {importPreviewing ? 'Analyzing...' : 'Preview Changes'}
            </button>
          {/if}
        </div>
      </div>

      <!-- Diff preview -->
      {#if importDiff}
        <div class="diff-preview">
          <h3>Import Preview</h3>
          {#if !diffHasChanges(importDiff)}
            <p class="empty-text">No changes detected - the imported configuration is identical to the current one.</p>
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
                    <li>~ {ch.key}: {ch.old_value} -> {ch.new_value}</li>
                  {/each}
                </ul>
              </div>
            {/if}
          {/if}
          {#if importError}
            <div class="form-error">{importError}</div>
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
    </section>
  {/if}
</div>

<!-- Notification form modal -->
{#if showNotifForm}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div class="overlay" onclick={() => showNotifForm = false} onkeydown={(e) => { if (e.key === 'Escape') showNotifForm = false; }} role="dialog" aria-modal="true" tabindex="-1">
    <div class="dialog" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()} role="document">
      <h3>{notifEditing ? 'Edit' : 'Add'} Notification Channel</h3>
      <div class="form-row">
        <label for="notif-channel">Channel</label>
        <select id="notif-channel" bind:value={notifChannel}>
          <option value="email">Email (SMTP)</option>
          <option value="webhook">Webhook (HTTP)</option>
        </select>
      </div>
      <div class="form-row">
        <label for="notif-enabled">
          <input id="notif-enabled" type="checkbox" bind:checked={notifEnabled} />
          Enabled
        </label>
      </div>
      <div class="form-row">
        <label for="notif-config">Configuration (JSON)</label>
        <textarea id="notif-config" bind:value={notifConfig} rows="4" placeholder={notifChannel === 'email'
          ? '{"smtp_host": "...", "smtp_port": 587, "from": "...", "to": ["..."]}'
          : '{"url": "https://...", "method": "POST"}'}></textarea>
      </div>
      <div class="form-row">
        <label for="notif-alerts">Alert Types (comma-separated)</label>
        <input id="notif-alerts" type="text" bind:value={notifAlertTypes} placeholder="backend_down, cert_expiring, health_change" />
      </div>
      {#if notifError}
        <div class="form-error">{notifError}</div>
      {/if}
      <div class="actions">
        <button class="btn btn-cancel" onclick={() => showNotifForm = false}>Cancel</button>
        <button class="btn btn-primary" onclick={saveNotification} disabled={notifSaving}>
          {notifSaving ? 'Saving...' : 'Save'}
        </button>
      </div>
    </div>
  </div>
{/if}

<!-- Delete notification confirm -->
{#if deletingNotif}
  <ConfirmDialog
    title="Delete Notification Channel"
    message="Are you sure you want to delete the {deletingNotif.channel} notification channel?"
    onconfirm={confirmDeleteNotif}
    oncancel={() => deletingNotif = null}
  />
{/if}

<!-- Delete preference confirm -->
{#if deletingPref}
  <ConfirmDialog
    title="Delete Preference"
    message="Are you sure you want to delete the preference '{deletingPref.preference_key}'?"
    onconfirm={confirmDeletePref}
    oncancel={() => deletingPref = null}
  />
{/if}

<style>
  .settings-page {
    max-width: 900px;
  }

  .page-header {
    margin-bottom: 1.5rem;
  }

  .page-header h1 {
    margin: 0;
  }

  .section {
    margin-bottom: 2rem;
  }

  .section-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .section-header h2 {
    margin: 0;
  }

  .section-hint {
    color: var(--color-text-muted);
    font-size: 0.8125rem;
    margin: 0.25rem 0 1rem;
  }

  .form-card {
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-radius: 0.75rem;
    padding: 1.25rem;
  }

  .form-row {
    margin-bottom: 1rem;
  }

  .form-row label {
    display: block;
    font-size: 0.8125rem;
    color: var(--color-text-muted);
    margin-bottom: 0.375rem;
  }

  .form-row input[type='number'],
  .form-row input[type='text'],
  .form-row select,
  .form-row textarea {
    width: 100%;
    padding: 0.5rem 0.75rem;
    background: var(--color-bg-input);
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    color: var(--color-text);
    font-family: var(--sans);
    font-size: 0.875rem;
  }

  .form-row input[type='file'] {
    font-size: 0.875rem;
    color: var(--color-text-muted);
  }

  .form-row textarea {
    font-family: var(--mono);
    resize: vertical;
  }

  .form-row input:disabled {
    opacity: 0.5;
  }

  .hint {
    display: block;
    font-size: 0.75rem;
    color: var(--color-text-muted);
    margin-top: 0.25rem;
  }

  .form-actions {
    margin-top: 0.5rem;
  }

  .form-error {
    color: var(--color-red);
    font-size: 0.8125rem;
    margin: 0.5rem 0;
  }

  .form-success {
    color: var(--color-green);
    font-size: 0.8125rem;
    margin: 0.5rem 0;
  }

  .empty-text {
    color: var(--color-text-muted);
    font-size: 0.875rem;
  }

  .file-info {
    font-size: 0.8125rem;
    color: var(--color-text-muted);
    margin: 0.5rem 0;
  }

  /* Tables */
  .table-wrap {
    overflow-x: auto;
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

  td select {
    padding: 0.25rem 0.5rem;
    background: var(--color-bg-input);
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    color: var(--color-text);
    font-size: 0.8125rem;
  }

  .capitalize {
    text-transform: capitalize;
  }

  .status-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin-right: 0.375rem;
    vertical-align: middle;
  }

  .status-dot.enabled {
    background: var(--color-green);
  }

  .status-dot.disabled {
    background: var(--color-text-muted);
  }

  .actions-cell {
    display: flex;
    gap: 0.75rem;
  }

  .btn-link {
    background: none;
    border: none;
    color: var(--color-primary);
    font-size: 0.8125rem;
    padding: 0;
    cursor: pointer;
  }

  .btn-link:hover {
    text-decoration: underline;
  }

  .btn-link.danger {
    color: var(--color-red);
  }

  /* Export/Import grid */
  .export-import-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin-bottom: 1rem;
  }

  /* Diff preview */
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
    background: rgba(34, 197, 94, 0.1);
    color: var(--color-green);
  }

  .diff-modified li {
    background: rgba(245, 158, 11, 0.1);
    color: var(--color-orange);
  }

  .diff-removed li {
    background: rgba(239, 68, 68, 0.1);
    color: var(--color-red);
  }

  .diff-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.75rem;
    margin-top: 1rem;
  }

  /* Modal */
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }

  .dialog {
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-radius: 0.75rem;
    padding: 1.5rem;
    max-width: 500px;
    width: 90%;
  }

  .dialog h3 {
    margin: 0 0 1rem;
  }

  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.75rem;
    margin-top: 1rem;
  }

  /* Buttons */
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

  .btn-secondary {
    background: var(--color-bg-input);
    color: var(--color-text);
  }

  .btn-secondary:hover {
    background: var(--color-bg-hover);
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
</style>
