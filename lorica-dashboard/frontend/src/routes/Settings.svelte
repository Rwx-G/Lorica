<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    type GlobalSettingsResponse,
    type NotificationConfigResponse,
    type UserPreferenceResponse,
    type ImportDiffResponse,
    type SecurityHeaderPreset,
  } from '../lib/api';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import { showToast } from '../lib/toast';

  // Global settings
  let settings: GlobalSettingsResponse | null = $state(null);
  let settingsForm = $state({ management_port: 9443, log_level: 'info', default_health_check_interval_s: 10, cert_warning_days: 30, cert_critical_days: 7, default_topology_type: 'single_vm', max_global_connections: 0, flood_threshold_rps: 0, waf_ban_threshold: 5, waf_ban_duration_s: 3600, access_log_retention: 100000, sla_purge_enabled: false, sla_purge_retention_days: 90, sla_purge_schedule: 'first_of_month' });
  let settingsSaving = $state(false);
  let settingsMsg = $state('');
  let settingsError = $state('');

  // Security header presets
  let customPresets: SecurityHeaderPreset[] = $state([]);
  let showPresetForm = $state(false);
  let presetEditing: number | null = $state(null);
  let presetName = $state('');
  let presetHeaders = $state('');
  let presetError = $state('');
  let presetSaving = $state(false);
  let deletingPresetIdx: number | null = $state(null);

  const builtinPresets: Array<{ name: string; description: string }> = [
    { name: 'strict', description: 'X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy: no-referrer, Permissions-Policy: camera=(), microphone=(), geolocation=()' },
    { name: 'moderate', description: 'X-Frame-Options: SAMEORIGIN, X-Content-Type-Options: nosniff, Referrer-Policy: strict-origin-when-cross-origin' },
    { name: 'none', description: 'No security headers added' },
  ];

  // Notifications
  let notifications: NotificationConfigResponse[] = $state([]);
  let showNotifForm = $state(false);
  let notifEditing: NotificationConfigResponse | null = $state(null);
  let notifChannel = $state('email');
  let notifEnabled = $state(true);
  let notifConfig = $state('');
  // Email fields
  let notifSmtpHost = $state('');
  let notifSmtpPort = $state(587);
  let notifSmtpUsername = $state('');
  let notifSmtpPassword = $state('');
  let notifFromAddress = $state('');
  let notifToAddress = $state('');
  // Webhook/Slack fields
  let notifUrl = $state('');
  let notifAuthHeader = $state('');
  // Alert type checkboxes
  let notifAlertBackendDown = $state(false);
  let notifAlertCertExpiring = $state(false);
  let notifAlertWafAlert = $state(false);
  let notifAlertConfigChanged = $state(false);
  let notifAlertSlaBreached = $state(false);
  let notifAlertIpBanned = $state(false);
  let notifError = $state('');
  let notifSaving = $state(false);
  let deletingNotif: NotificationConfigResponse | null = $state(null);
  let testingNotif = $state('');

  // Preferences
  let preferences: UserPreferenceResponse[] = $state([]);
  let deletingPref: UserPreferenceResponse | null = $state(null);

  // Notification history
  interface NotifEvent {
    alert_type: string;
    summary: string;
    timestamp: string;
    details: Record<string, string>;
  }
  let notifHistory: NotifEvent[] = $state([]);

  // Getting started guide (localStorage)
  const HELPER_KEY = 'lorica_helper_dismissed';
  let helperGuideVisible = $state(localStorage.getItem(HELPER_KEY) !== 'true');

  function toggleHelperGuide() {
    helperGuideVisible = !helperGuideVisible;
    if (helperGuideVisible) {
      localStorage.removeItem(HELPER_KEY);
    } else {
      localStorage.setItem(HELPER_KEY, 'true');
    }
  }

  // Self-signed certificate preference (localStorage)
  const SS_PREF_KEY = 'lorica_self_signed_pref';
  let selfSignedPrefValue = $state<string | null>(localStorage.getItem(SS_PREF_KEY));

  function setSelfSignedPref(value: 'never' | 'always' | 'once') {
    localStorage.setItem(SS_PREF_KEY, value);
    selfSignedPrefValue = value;
  }

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
  let theme = $state<'dark' | 'light'>(
    (document.documentElement.getAttribute('data-theme') as 'dark' | 'light') || 'light'
  );

  // Collapsible sections
  const SECTIONS_KEY = 'lorica_settings_sections';
  const defaultSections: Record<string, boolean> = {
    appearance: true,
    global: true,
    notifications: true,
    presets: true,
    history: true,
    preferences: true,
    export: true,
    ban_rules: true,
  };
  let expandedSections = $state<Record<string, boolean>>((() => {
    try {
      const saved = localStorage.getItem(SECTIONS_KEY);
      return saved ? { ...defaultSections, ...JSON.parse(saved) } : { ...defaultSections };
    } catch {
      return { ...defaultSections };
    }
  })());

  function toggleSection(key: string) {
    expandedSections[key] = !expandedSections[key];
    localStorage.setItem(SECTIONS_KEY, JSON.stringify(expandedSections));
  }

  let loading = $state(true);
  let error = $state('');

  async function loadAll() {
    loading = true;
    error = '';
    const [settingsRes, notifRes, prefRes, histRes] = await Promise.all([
      api.getSettings(),
      api.listNotifications(),
      api.listPreferences(),
      api.notificationHistory(),
    ]);
    if (settingsRes.error) {
      error = settingsRes.error.message;
    } else if (settingsRes.data) {
      settings = settingsRes.data;
      settingsForm = { ...settingsRes.data };
      customPresets = settingsRes.data.custom_security_presets ?? [];
    }
    if (notifRes.data) {
      notifications = notifRes.data.notifications;
    }
    if (histRes.data) {
      notifHistory = histRes.data.events;
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

  // ---- Security Header Presets ----

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

  // ---- Notifications ----

  function openNotifCreate() {
    notifEditing = null;
    notifChannel = 'email';
    notifEnabled = true;
    notifConfig = '';
    notifSmtpHost = '';
    notifSmtpPort = 587;
    notifSmtpUsername = '';
    notifSmtpPassword = '';
    notifFromAddress = '';
    notifToAddress = '';
    notifUrl = '';
    notifAuthHeader = '';
    notifAlertBackendDown = false;
    notifAlertCertExpiring = false;
    notifAlertWafAlert = false;
    notifAlertConfigChanged = false;
    notifAlertSlaBreached = false;
    notifAlertIpBanned = false;
    notifError = '';
    showNotifForm = true;
  }

  function openNotifEdit(nc: NotificationConfigResponse) {
    notifEditing = nc;
    notifChannel = nc.channel;
    notifEnabled = nc.enabled;
    notifConfig = nc.config;

    // Parse config JSON into individual fields
    try {
      const cfg = JSON.parse(nc.config);
      if (nc.channel === 'email') {
        notifSmtpHost = cfg.smtp_host || '';
        notifSmtpPort = cfg.smtp_port || 587;
        notifSmtpUsername = cfg.smtp_username || '';
        notifSmtpPassword = ''; // masked, don't populate
        notifFromAddress = cfg.from_address || '';
        notifToAddress = cfg.to_address || '';
        notifUrl = '';
        notifAuthHeader = '';
      } else {
        notifUrl = cfg.url || '';
        notifAuthHeader = cfg.auth_header || '';
        notifSmtpHost = '';
        notifSmtpPort = 587;
        notifSmtpUsername = '';
        notifSmtpPassword = '';
        notifFromAddress = '';
        notifToAddress = '';
      }
    } catch {
      // ignore parse errors, fields stay at defaults
    }

    // Populate alert type checkboxes
    const types = nc.alert_types || [];
    notifAlertBackendDown = types.includes('backend_down');
    notifAlertCertExpiring = types.includes('cert_expiring');
    notifAlertWafAlert = types.includes('waf_alert');
    notifAlertConfigChanged = types.includes('config_changed');
    notifAlertSlaBreached = types.includes('sla_breached');
    notifAlertIpBanned = types.includes('ip_banned');

    notifError = '';
    showNotifForm = true;
  }

  async function saveNotification() {
    notifSaving = true;
    notifError = '';

    // Build config JSON from individual fields
    let configObj: Record<string, unknown>;
    if (notifChannel === 'email') {
      configObj = {
        smtp_host: notifSmtpHost,
        smtp_port: notifSmtpPort,
        from_address: notifFromAddress,
        to_address: notifToAddress,
      };
      if (notifSmtpUsername) configObj.smtp_username = notifSmtpUsername;
      if (notifSmtpPassword) configObj.smtp_password = notifSmtpPassword;
      else if (notifEditing) configObj.smtp_password = '********'; // preserve existing
    } else {
      configObj = { url: notifUrl };
      if (notifChannel === 'webhook' && notifAuthHeader) configObj.auth_header = notifAuthHeader;
    }
    const configStr = JSON.stringify(configObj);

    // Build alert_types array from checkboxes
    const alertArr: string[] = [];
    if (notifAlertBackendDown) alertArr.push('backend_down');
    if (notifAlertCertExpiring) alertArr.push('cert_expiring');
    if (notifAlertWafAlert) alertArr.push('waf_alert');
    if (notifAlertConfigChanged) alertArr.push('config_changed');
    if (notifAlertSlaBreached) { alertArr.push('sla_breached'); alertArr.push('sla_recovered'); }
    if (notifAlertIpBanned) alertArr.push('ip_banned');

    const body = { channel: notifChannel, enabled: notifEnabled, config: configStr, alert_types: alertArr };

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
    const res = await api.testNotification(id);
    if (res.error) {
      showToast(`Test failed: ${res.error.message}`, 'error');
    } else {
      showToast(`Test notification sent via ${res.data?.channel}`, 'success');
    }
    testingNotif = '';
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
      <button class="collapsible-header" class:open={expandedSections.appearance} onclick={() => toggleSection('appearance')}>
        <h2>Appearance</h2>
        <span class="chevron" class:expanded={expandedSections.appearance}></span>
      </button>
      {#if expandedSections.appearance}
        <div class="section-body">
          <p class="section-hint">Current theme: {theme}.</p>
          <div class="actions">
            <button class="btn btn-secondary" onclick={toggleTheme}>
              {theme === 'dark' ? 'Switch to Light' : 'Switch to Dark'}
            </button>
          </div>
        </div>
      {/if}
    </section>

    <!-- Global Settings -->
    <section class="section">
      <button class="collapsible-header" class:open={expandedSections.global} onclick={() => toggleSection('global')}>
        <h2>Global Configuration</h2>
        <span class="chevron" class:expanded={expandedSections.global}></span>
      </button>
      {#if expandedSections.global}
      <div class="section-body">
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
        <div class="form-row">
          <label for="max-global-conn">Max Global Connections</label>
          <input id="max-global-conn" type="number" bind:value={settingsForm.max_global_connections} min="0" max="1000000" />
          <span class="hint">0 = unlimited. New requests get 503 when limit is reached.</span>
        </div>
        <div class="form-row">
          <label for="flood-threshold">Flood Detection Threshold (RPS)</label>
          <input id="flood-threshold" type="number" bind:value={settingsForm.flood_threshold_rps} min="0" max="1000000" />
          <span class="hint">0 = disabled. When exceeded, per-IP rate limits are halved.</span>
        </div>
        <div class="form-row">
          <label for="waf-ban-threshold">WAF Auto-ban Threshold</label>
          <input id="waf-ban-threshold" type="number" bind:value={settingsForm.waf_ban_threshold} min="0" max="1000" />
          <span class="hint">Ban IP after this many WAF blocks per worker (0 = disabled, default 3). With N workers, up to N x threshold requests may pass before the ban triggers.</span>
        </div>
        <div class="form-row">
          <label for="waf-ban-duration">WAF Ban Duration (seconds)</label>
          <input id="waf-ban-duration" type="number" bind:value={settingsForm.waf_ban_duration_s} min="0" max="604800" />
          <span class="hint">How long to ban (default 3600 = 1 hour, max 7 days).</span>
        </div>
        <div class="form-row">
          <label for="s-log-retention">Access Log Retention (entries)</label>
          <input id="s-log-retention" type="number" min="0" bind:value={settingsForm.access_log_retention} />
          <span class="hint">Maximum entries in persistent log store (0 = unlimited).</span>
        </div>

        <h3 class="subsection-title">SLA Data Purge</h3>
        <div class="form-row">
          <label for="sla-purge-toggle" class="toggle-label">
            <input id="sla-purge-toggle" type="checkbox" bind:checked={settingsForm.sla_purge_enabled} />
            Enable automatic SLA purge
          </label>
        </div>
        {#if settingsForm.sla_purge_enabled}
          <div class="form-row">
            <label for="sla-purge-days">Purge SLA data older than (days)</label>
            <input id="sla-purge-days" type="number" min="1" max="3650" bind:value={settingsForm.sla_purge_retention_days} />
            <span class="hint">Buckets older than this will be permanently deleted.</span>
          </div>
          <div class="form-row">
            <label for="sla-purge-schedule">Purge schedule</label>
            <select id="sla-purge-schedule" bind:value={settingsForm.sla_purge_schedule}>
              <option value="first_of_month">First day of the month</option>
              <option value="daily">Daily (rolling)</option>
              <optgroup label="Specific day of month">
                {#each Array.from({ length: 28 }, (_, i) => i + 1) as day}
                  <option value={String(day)}>Day {day}</option>
                {/each}
              </optgroup>
            </select>
            <span class="hint">When the purge job runs.</span>
          </div>
        {/if}

        {#if settingsError}
          <div class="form-error">{settingsError}</div>
        {/if}
        {#if settingsMsg}
          <div class="form-success">{settingsMsg}</div>
        {/if}
        <div class="actions">
          <button class="btn btn-primary" onclick={saveSettings} disabled={settingsSaving}>
            {settingsSaving ? 'Saving...' : 'Save Settings'}
          </button>
        </div>
      </div>
      {/if}
    </section>

    <!-- Security Header Presets -->
    <section class="section">
      <button class="collapsible-header" class:open={expandedSections.presets} onclick={() => toggleSection('presets')}>
        <h2>Security Header Presets</h2>
        <span class="chevron" class:expanded={expandedSections.presets}></span>
      </button>
      {#if expandedSections.presets}
        <div class="section-body">
          <p class="section-hint">Custom presets appear alongside builtin presets (strict, moderate, none) in the route security headers dropdown.</p>

          <!-- Builtin presets (read-only) -->
          <div class="table-wrap">
            <table>
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
                    <td>-</td>
                  </tr>
                {/each}
                {#each customPresets as cp, idx}
                  <tr>
                    <td><code>{cp.name}</code></td>
                    <td class="preset-desc">{Object.keys(cp.headers).length} header{Object.keys(cp.headers).length !== 1 ? 's' : ''}</td>
                    <td><span class="badge badge-custom">custom</span></td>
                    <td class="actions-cell">
                      <button class="btn-link" onclick={() => openPresetEdit(idx)}>Edit</button>
                      <button class="btn-link danger" onclick={() => deletingPresetIdx = idx}>Delete</button>
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
          <div class="actions">
            <button class="btn btn-primary" onclick={openPresetCreate}>Add Preset</button>
          </div>
        </div>
      {/if}
    </section>

    <!-- Ban configuration note -->
    <section class="section">
      <button class="collapsible-header" class:open={expandedSections.ban_rules} onclick={() => toggleSection('ban_rules')}>
        <h2>Ban Rules</h2>
        <span class="chevron" class:expanded={expandedSections.ban_rules}></span>
      </button>
      {#if expandedSections.ban_rules}
        <div class="section-body">
          <p class="section-hint">Ban rules (slowloris protection, auto-ban threshold and duration) are configured per-route in the Routes page under Advanced Configuration > Protection.</p>
        </div>
      {/if}
    </section>

    <!-- Notification Preferences -->
    <section class="section">
      <button class="collapsible-header" class:open={expandedSections.notifications} onclick={() => toggleSection('notifications')}>
        <h2>Notification Channels</h2>
        <span class="chevron" class:expanded={expandedSections.notifications}></span>
      </button>
      {#if expandedSections.notifications}
        <div class="section-body">
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
          <div class="actions">
            <button class="btn btn-primary" onclick={openNotifCreate}>Add Channel</button>
          </div>
        </div>
      {/if}
    </section>

    <!-- Notification History -->
    <section class="section">
      <button class="collapsible-header" class:open={expandedSections.history} onclick={() => toggleSection('history')}>
        <h2>Notification History</h2>
        <span class="chevron" class:expanded={expandedSections.history}></span>
      </button>
      {#if expandedSections.history}
        <div class="section-body">
          <p class="section-hint">Recent alert events dispatched by Lorica (last 100).</p>

          {#if notifHistory.length === 0}
            <p class="empty-text">No notification events yet.</p>
          {:else}
            <div class="notif-history-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Type</th>
                    <th>Summary</th>
                  </tr>
                </thead>
                <tbody>
                  {#each notifHistory as ev}
                    <tr>
                      <td class="mono">{new Date(ev.timestamp).toLocaleString()}</td>
                      <td><span class="badge badge-{ev.alert_type === 'sla_breached' || ev.alert_type === 'backend_down' ? 'red' : ev.alert_type === 'sla_recovered' ? 'green' : ev.alert_type === 'cert_expiring' ? 'orange' : 'blue'}">{ev.alert_type}</span></td>
                      <td>{ev.summary}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}
        </div>
      {/if}
    </section>

    <!-- Preference Memory -->
    <section class="section">
      <button class="collapsible-header" class:open={expandedSections.preferences} onclick={() => toggleSection('preferences')}>
        <h2>Preference Memory</h2>
        <span class="chevron" class:expanded={expandedSections.preferences}></span>
      </button>
      {#if expandedSections.preferences}
        <div class="section-body">
          <p class="section-hint">Stored decisions for prompts and UI preferences.</p>

          <div class="pref-row">
            <div class="pref-info">
              <code>getting_started_guide</code>
              <span class="pref-hint">Show the getting started guide on the Overview page</span>
            </div>
            <label class="toggle-label">
              <span>{helperGuideVisible ? 'Visible' : 'Hidden'}</span>
              <button class="toggle" class:on={helperGuideVisible} onclick={toggleHelperGuide}>
                <span class="toggle-knob"></span>
              </button>
            </label>
          </div>

          <div class="pref-row">
            <div class="pref-info">
              <code>self_signed_cert</code>
              <span class="pref-hint">Self-signed certificate generation prompt preference</span>
            </div>
            <div class="toggle-triple">
              <button class:active={selfSignedPrefValue === 'never'} onclick={() => setSelfSignedPref('never')}>Never</button>
              <button class:active={selfSignedPrefValue === 'once' || !selfSignedPrefValue} onclick={() => setSelfSignedPref('once')}>Ask</button>
              <button class:active={selfSignedPrefValue === 'always'} onclick={() => setSelfSignedPref('always')}>Always</button>
            </div>
          </div>

          {#if preferences.length === 0}
            <p class="empty-text">No other stored preferences.</p>
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
        </div>
      {/if}
    </section>

    <!-- Export/Import -->
    <section class="section">
      <button class="collapsible-header" class:open={expandedSections.export} onclick={() => toggleSection('export')}>
        <h2>Configuration Export / Import</h2>
        <span class="chevron" class:expanded={expandedSections.export}></span>
      </button>
      {#if expandedSections.export}
        <div class="section-body">
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
        </div>
      {/if}
    </section>
  {/if}
</div>

<!-- Notification form modal -->
{#if showNotifForm}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div class="overlay" onclick={(e) => { if (e.target === e.currentTarget) showNotifForm = false; }} onkeydown={(e) => { if (e.key === 'Escape') showNotifForm = false; }} role="dialog" aria-modal="true" tabindex="-1">
    <div class="dialog" role="document">
      <h3>{notifEditing ? 'Edit' : 'Add'} Notification Channel</h3>
      <div class="form-row">
        <label for="notif-channel">Channel</label>
        <select id="notif-channel" bind:value={notifChannel}>
          <option value="email">Email (SMTP)</option>
          <option value="webhook">Webhook (HTTP)</option>
          <option value="slack">Slack</option>
        </select>
      </div>
      <div class="form-row">
        <label for="notif-enabled">
          <input id="notif-enabled" type="checkbox" bind:checked={notifEnabled} />
          Enabled
        </label>
      </div>

      {#if notifChannel === 'email'}
        <fieldset class="notif-fieldset">
          <legend>SMTP Server</legend>
          <div class="form-row">
            <label for="notif-smtp-host">SMTP Host <span class="required">*</span></label>
            <input id="notif-smtp-host" type="text" bind:value={notifSmtpHost} placeholder="smtp.example.com" required />
          </div>
          <div class="form-row">
            <label for="notif-smtp-port">SMTP Port</label>
            <input id="notif-smtp-port" type="number" bind:value={notifSmtpPort} placeholder="587" min="1" max="65535" />
            <span class="form-hint">587 (STARTTLS) or 465 (SSL)</span>
          </div>
          <div class="form-row">
            <label for="notif-smtp-user">Username</label>
            <input id="notif-smtp-user" type="text" bind:value={notifSmtpUsername} placeholder="user@example.com" />
          </div>
          <div class="form-row">
            <label for="notif-smtp-pass">Password</label>
            <input id="notif-smtp-pass" type="password" bind:value={notifSmtpPassword} placeholder={notifEditing ? 'Leave empty to keep current' : ''} />
          </div>
        </fieldset>
        <fieldset class="notif-fieldset">
          <legend>Addresses</legend>
          <div class="form-row">
            <label for="notif-from">From <span class="required">*</span></label>
            <input id="notif-from" type="email" bind:value={notifFromAddress} placeholder="noreply@example.com" required />
          </div>
          <div class="form-row">
            <label for="notif-to">To <span class="required">*</span></label>
            <input id="notif-to" type="email" bind:value={notifToAddress} placeholder="admin@example.com" required />
          </div>
        </fieldset>
      {:else}
        <div class="form-row">
          <label for="notif-url">URL <span class="required">*</span></label>
          <input id="notif-url" type="url" bind:value={notifUrl} placeholder={notifChannel === 'slack' ? 'https://hooks.slack.com/services/T.../B.../xxx' : 'https://example.com/webhook'} required />
        </div>
        {#if notifChannel === 'webhook'}
          <div class="form-row">
            <label for="notif-auth">Authorization Header</label>
            <input id="notif-auth" type="text" bind:value={notifAuthHeader} placeholder="Bearer your-token" />
            <span class="form-hint">Optional - sent as Authorization header</span>
          </div>
        {/if}
      {/if}

      <fieldset class="notif-fieldset">
        <legend>Alert Types</legend>
        <div class="alert-select-all">
          <button type="button" class="btn-link" onclick={() => { notifAlertBackendDown = notifAlertCertExpiring = notifAlertWafAlert = notifAlertConfigChanged = notifAlertSlaBreached = notifAlertIpBanned = true; }}>Select all</button>
          <span class="separator">|</span>
          <button type="button" class="btn-link" onclick={() => { notifAlertBackendDown = notifAlertCertExpiring = notifAlertWafAlert = notifAlertConfigChanged = notifAlertSlaBreached = notifAlertIpBanned = false; }}>None</button>
        </div>
        <div class="alert-checkboxes">
          <label><input type="checkbox" bind:checked={notifAlertBackendDown} /> Backend down</label>
          <label><input type="checkbox" bind:checked={notifAlertCertExpiring} /> Certificate expiring</label>
          <label><input type="checkbox" bind:checked={notifAlertWafAlert} /> WAF alert</label>
          <label><input type="checkbox" bind:checked={notifAlertConfigChanged} /> Configuration changed</label>
          <label><input type="checkbox" bind:checked={notifAlertSlaBreached} /> SLA breached</label>
          <label><input type="checkbox" bind:checked={notifAlertIpBanned} /> IP banned</label>
        </div>
      </fieldset>
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

<!-- Preset form modal -->
{#if showPresetForm}
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div class="overlay" onclick={(e) => { if (e.target === e.currentTarget) showPresetForm = false; }} onkeydown={(e) => { if (e.key === 'Escape') showPresetForm = false; }} role="dialog" aria-modal="true" tabindex="-1">
    <div class="dialog" role="document">
      <h3>{presetEditing !== null ? 'Edit' : 'Add'} Security Header Preset</h3>
      <div class="form-row">
        <label for="preset-name">Preset Name <span class="required">*</span></label>
        <input id="preset-name" type="text" bind:value={presetName} placeholder="e.g. my-api-preset" />
      </div>
      <div class="form-row">
        <label for="preset-headers">Headers (one per line, Key=Value) <span class="required">*</span></label>
        <textarea id="preset-headers" bind:value={presetHeaders} rows="6" placeholder="X-Frame-Options=DENY&#10;X-Content-Type-Options=nosniff&#10;Referrer-Policy=no-referrer"></textarea>
      </div>
      {#if presetError}
        <div class="form-error">{presetError}</div>
      {/if}
      <div class="actions">
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
  .settings-page { max-width: none; }

  .section {
    margin-bottom: 1.5rem;
  }

  .collapsible-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    width: 100%;
    padding: var(--space-3) var(--space-4);
    background: var(--color-bg-input);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    cursor: pointer;
    transition: background-color var(--transition-fast);
    font-family: inherit;
  }

  .collapsible-header:hover {
    background: var(--color-bg-hover);
  }

  .collapsible-header.open {
    border-radius: var(--radius-md) var(--radius-md) 0 0;
    border-bottom-color: transparent;
  }

  .collapsible-header h2 {
    margin: 0;
    font-size: 0.875rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 600;
    color: var(--color-text-heading);
  }

  .chevron {
    display: inline-block;
    width: 0.5rem;
    height: 0.5rem;
    border-right: 2px solid var(--color-text-muted);
    border-bottom: 2px solid var(--color-text-muted);
    transform: rotate(45deg);
    transition: transform 0.2s ease;
    flex-shrink: 0;
  }

  .chevron.expanded {
    transform: rotate(-135deg);
  }

  .section-body {
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-top: none;
    border-radius: 0 0 var(--radius-md) var(--radius-md);
    padding: var(--space-4);
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

  .notif-history-scroll {
    max-height: 400px;
    overflow-y: auto;
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

  /* Modal */
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
    animation: fadeIn var(--transition-fast);
  }

  .dialog {
    background: var(--color-bg-elevated);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-xl);
    padding: var(--space-6);
    max-width: 500px;
    width: 90%;
    box-shadow: var(--shadow-lg);
    animation: slideUp var(--transition-base);
  }

  .dialog h3 {
    margin: 0 0 var(--space-4);
  }

  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.75rem;
    margin-top: 1rem;
  }

  .section-body .btn-primary,
  .section-body .btn-secondary {
    min-width: 140px;
  }



  .required {
    color: var(--color-red);
  }

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
    max-width: 400px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .pref-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: var(--space-3) var(--space-4);
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    margin-bottom: var(--space-4);
  }

  .pref-info {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .pref-hint {
    font-size: var(--text-sm);
    color: var(--color-text-muted);
  }

  .subsection-title {
    margin: var(--space-4) 0 var(--space-2);
    font-size: var(--text-md);
    color: var(--color-text-heading);
    border-top: 1px solid var(--color-border);
    padding-top: var(--space-4);
  }

  .toggle-label {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font-size: var(--text-sm);
    color: var(--color-text-muted);
  }

  .toggle {
    position: relative;
    width: 36px;
    min-width: 36px;
    max-width: 36px;
    height: 20px;
    min-height: 20px;
    max-height: 20px;
    border-radius: var(--radius-full);
    border: none;
    background: var(--color-bg-input);
    cursor: pointer;
    transition: background-color var(--transition-fast);
    padding: 0;
    flex-shrink: 0;
  }

  .toggle.on {
    background: var(--color-green);
  }

  .toggle-knob {
    position: absolute;
    top: 2px;
    left: 2px;
    width: 16px;
    height: 16px;
    border-radius: 50%;
    background: white;
    transition: transform var(--transition-fast);
  }

  .toggle.on .toggle-knob {
    transform: translateX(16px);
  }

  .toggle-triple {
    display: inline-flex;
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    overflow: hidden;
  }

  .toggle-triple button {
    padding: 0.25rem 0.75rem;
    font-size: var(--text-xs);
    border: none;
    background: var(--color-bg-input);
    color: var(--color-text-muted);
    cursor: pointer;
    transition: background-color var(--transition-fast), color var(--transition-fast);
  }

  .toggle-triple button:not(:last-child) {
    border-right: 1px solid var(--color-border);
  }

  .toggle-triple button.active {
    background: var(--color-primary);
    color: white;
    font-weight: 600;
  }

  .toggle-triple button:hover:not(.active) {
    background: var(--color-bg-hover);
  }

  .notif-fieldset {
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    padding: var(--space-3);
    margin-bottom: var(--space-3);
  }

  .notif-fieldset legend {
    font-size: var(--text-xs);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--color-text-muted);
    padding: 0 var(--space-1);
  }

  .alert-checkboxes {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: var(--space-2);
  }

  .alert-checkboxes label {
    display: flex;
    align-items: center;
    gap: var(--space-1);
    font-size: var(--text-sm);
    cursor: pointer;
  }

  .alert-select-all {
    display: flex;
    gap: var(--space-2);
    align-items: center;
    margin-bottom: var(--space-2);
    font-size: var(--text-xs);
  }

  .separator {
    color: var(--color-text-muted);
  }

  .form-hint {
    font-size: var(--text-xs);
    color: var(--color-text-muted);
    margin-top: var(--space-1);
  }

  .form-row input[type='email'],
  .form-row input[type='url'],
  .form-row input[type='password'] {
    width: 100%;
    padding: 0.5rem 0.75rem;
    background: var(--color-bg-input);
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    color: var(--color-text);
    font-family: var(--sans);
    font-size: 0.875rem;
  }
</style>
