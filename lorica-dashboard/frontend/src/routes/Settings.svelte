<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    type GlobalSettingsResponse,
    type NotificationConfigResponse,
    type UserPreferenceResponse,
    type SecurityHeaderPreset,
    type DnsProviderResponse,
  } from '../lib/api';
  import { showToast } from '../lib/toast';
  import SettingsDnsProviders from '../components/settings/SettingsDnsProviders.svelte';
  import SettingsNotifications from '../components/settings/SettingsNotifications.svelte';
  import AppearanceTab from '../components/settings-tabs/AppearanceTab.svelte';
  import GlobalConfigTab from '../components/settings-tabs/GlobalConfigTab.svelte';
  import NetworkTab from '../components/settings-tabs/NetworkTab.svelte';
  import ObservabilityTab from '../components/settings-tabs/ObservabilityTab.svelte';
  import SecurityPresetsTab from '../components/settings-tabs/SecurityPresetsTab.svelte';
  import BanRulesTab from '../components/settings-tabs/BanRulesTab.svelte';
  import NotificationHistoryTab from '../components/settings-tabs/NotificationHistoryTab.svelte';
  import PreferencesTab from '../components/settings-tabs/PreferencesTab.svelte';
  import ExportImportTab from '../components/settings-tabs/ExportImportTab.svelte';
  import CertExportTab from '../components/settings-tabs/CertExportTab.svelte';
  import { parseOctalMode } from '../lib/validators';

  // Global settings
  let settings: GlobalSettingsResponse | null = $state(null);
  let settingsForm = $state({
    management_port: 9443,
    log_level: 'info',
    default_health_check_interval_s: 10,
    cert_warning_days: 30,
    cert_critical_days: 7,
    max_global_connections: 0,
    flood_threshold_rps: 0,
    waf_ban_threshold: 5,
    waf_ban_duration_s: 3600,
    access_log_retention: 100000,
    sla_purge_enabled: false,
    sla_purge_retention_days: 90,
    sla_purge_schedule: 'first_of_month',
    trusted_proxies: '',
    waf_whitelist_ips: '',
    connection_deny_cidrs: '',
    connection_allow_cidrs: '',
    // Observability (v1.4.0)
    otlp_endpoint: '',
    otlp_protocol: 'http-proto',
    otlp_service_name: 'lorica',
    otlp_sampling_ratio: 0.1,
    geoip_db_path: '',
    geoip_auto_update_enabled: false,
    asn_db_path: '',
    asn_auto_update_enabled: false,
    // Cert export (v1.4.1). Modes are held as user-facing octal
    // strings so the input shows "640" rather than decimal 416.
    cert_export_enabled: false,
    cert_export_dir: '',
    cert_export_owner_uid: '',
    cert_export_group_gid: '',
    cert_export_file_mode: '640',
    cert_export_dir_mode: '750',
  });
  let settingsSaving = $state(false);
  let settingsMsg = $state('');
  let settingsError = $state('');

  // Security header presets
  let customPresets: SecurityHeaderPreset[] = $state([]);

  // Notifications
  let notifications: NotificationConfigResponse[] = $state([]);

  // DNS Providers
  let dnsProviders: DnsProviderResponse[] = $state([]);

  // Preferences
  let preferences: UserPreferenceResponse[] = $state([]);

  // Notification history
  interface NotifEvent {
    alert_type: string;
    summary: string;
    timestamp: string;
    details: Record<string, string>;
  }
  let notifHistory: NotifEvent[] = $state([]);

  // Theme
  let theme = $state<'dark' | 'light'>(
    (document.documentElement.getAttribute('data-theme') as 'dark' | 'light') || 'light'
  );

  // Collapsible sections
  const SECTIONS_KEY = 'lorica_settings_sections';
  const defaultSections: Record<string, boolean> = {
    appearance: true,
    global: true,
    network: true,
    observability: true,
    dns_providers: true,
    notifications: true,
    presets: true,
    history: true,
    preferences: true,
    export: true,
    ban_rules: true,
    cert_export: true,
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
    const [settingsRes, notifRes, prefRes, histRes, dnsRes] = await Promise.all([
      api.getSettings(),
      api.listNotifications(),
      api.listPreferences(),
      api.notificationHistory(),
      api.listDnsProviders(),
    ]);
    if (settingsRes.error) {
      error = settingsRes.error.message;
    } else if (settingsRes.data) {
      settings = settingsRes.data;
      settingsForm = {
        ...settingsRes.data,
        trusted_proxies: (settingsRes.data.trusted_proxies ?? []).join('\n'),
        waf_whitelist_ips: (settingsRes.data.waf_whitelist_ips ?? []).join('\n'),
        connection_deny_cidrs: (settingsRes.data.connection_deny_cidrs ?? []).join('\n'),
        connection_allow_cidrs: (settingsRes.data.connection_allow_cidrs ?? []).join('\n'),
        otlp_endpoint: settingsRes.data.otlp_endpoint ?? '',
        otlp_protocol: settingsRes.data.otlp_protocol ?? 'http-proto',
        otlp_service_name: settingsRes.data.otlp_service_name ?? 'lorica',
        otlp_sampling_ratio: settingsRes.data.otlp_sampling_ratio ?? 0.1,
        geoip_db_path: settingsRes.data.geoip_db_path ?? '',
        geoip_auto_update_enabled:
          settingsRes.data.geoip_auto_update_enabled ?? false,
        asn_db_path: settingsRes.data.asn_db_path ?? '',
        asn_auto_update_enabled:
          settingsRes.data.asn_auto_update_enabled ?? false,
        cert_export_enabled: settingsRes.data.cert_export_enabled ?? false,
        cert_export_dir: settingsRes.data.cert_export_dir ?? '',
        cert_export_owner_uid:
          settingsRes.data.cert_export_owner_uid != null
            ? String(settingsRes.data.cert_export_owner_uid)
            : '',
        cert_export_group_gid:
          settingsRes.data.cert_export_group_gid != null
            ? String(settingsRes.data.cert_export_group_gid)
            : '',
        cert_export_file_mode:
          settingsRes.data.cert_export_file_mode != null
            ? (settingsRes.data.cert_export_file_mode as number).toString(8)
            : '640',
        cert_export_dir_mode:
          settingsRes.data.cert_export_dir_mode != null
            ? (settingsRes.data.cert_export_dir_mode as number).toString(8)
            : '750',
      };
      customPresets = settingsRes.data.custom_security_presets ?? [];
    }
    if (notifRes.data) {
      notifications = notifRes.data.notifications;
    }
    if (histRes.data) {
      notifHistory = histRes.data.events;
    }
    if (dnsRes.data) {
      dnsProviders = dnsRes.data.dns_providers;
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
    // Peel the user-facing string-typed cert_export fields off
    // `settingsForm` before spreading so the payload has backend
    // types (number / bool / string) rather than the text inputs.
    const {
      cert_export_enabled,
      cert_export_dir,
      cert_export_owner_uid,
      cert_export_group_gid,
      cert_export_file_mode,
      cert_export_dir_mode,
      ...formRest
    } = settingsForm;
    // Convert textarea fields (newline-separated) to string arrays
    const payload = {
      ...formRest,
      trusted_proxies: settingsForm.trusted_proxies
        .split('\n')
        .map((s: string) => s.trim())
        .filter((s: string) => s.length > 0),
      waf_whitelist_ips: settingsForm.waf_whitelist_ips
        .split('\n')
        .map((s: string) => s.trim())
        .filter((s: string) => s.length > 0),
      connection_deny_cidrs: settingsForm.connection_deny_cidrs
        .split('\n')
        .map((s: string) => s.trim())
        .filter((s: string) => s.length > 0),
      connection_allow_cidrs: settingsForm.connection_allow_cidrs
        .split('\n')
        .map((s: string) => s.trim())
        .filter((s: string) => s.length > 0),
      // Observability string fields: always send the trimmed value
      // (including empty string) so the backend can distinguish
      // "clear" (Some("")) from "do not touch" (field absent). A
      // plain `null` would round-trip to `None` in axum and the
      // backend would treat it as "leave unchanged", which is NOT
      // what the user wants when they wipe the field.
      otlp_endpoint: settingsForm.otlp_endpoint.trim(),
      geoip_db_path: settingsForm.geoip_db_path.trim(),
      asn_db_path: settingsForm.asn_db_path.trim(),
      // Cert export: the enable flag + directory always ride, and
      // uid / gid / modes are only sent when the operator supplied
      // a valid value (empty input => leave backend unchanged).
      cert_export_enabled,
      cert_export_dir: cert_export_dir.trim(),
      ...(cert_export_owner_uid.trim() !== ''
        ? { cert_export_owner_uid: Number(cert_export_owner_uid.trim()) }
        : {}),
      ...(cert_export_group_gid.trim() !== ''
        ? { cert_export_group_gid: Number(cert_export_group_gid.trim()) }
        : {}),
      ...(parseOctalMode(cert_export_file_mode) !== null
        ? { cert_export_file_mode: parseOctalMode(cert_export_file_mode)! }
        : {}),
      ...(parseOctalMode(cert_export_dir_mode) !== null
        ? { cert_export_dir_mode: parseOctalMode(cert_export_dir_mode)! }
        : {}),
    };
    const res = await api.updateSettings(payload);
    if (res.error) {
      settingsError = res.error.message;
      showToast(`Failed to save settings: ${res.error.message}`, 'error');
    } else if (res.data) {
      settings = res.data;
      settingsForm = {
        ...res.data,
        trusted_proxies: (res.data.trusted_proxies ?? []).join('\n'),
        waf_whitelist_ips: (res.data.waf_whitelist_ips ?? []).join('\n'),
        connection_deny_cidrs: (res.data.connection_deny_cidrs ?? []).join('\n'),
        connection_allow_cidrs: (res.data.connection_allow_cidrs ?? []).join('\n'),
        otlp_endpoint: res.data.otlp_endpoint ?? '',
        otlp_protocol: res.data.otlp_protocol ?? 'http-proto',
        otlp_service_name: res.data.otlp_service_name ?? 'lorica',
        otlp_sampling_ratio: res.data.otlp_sampling_ratio ?? 0.1,
        geoip_db_path: res.data.geoip_db_path ?? '',
        geoip_auto_update_enabled: res.data.geoip_auto_update_enabled ?? false,
        asn_db_path: res.data.asn_db_path ?? '',
        asn_auto_update_enabled: res.data.asn_auto_update_enabled ?? false,
        cert_export_enabled: res.data.cert_export_enabled ?? false,
        cert_export_dir: res.data.cert_export_dir ?? '',
        cert_export_owner_uid:
          res.data.cert_export_owner_uid != null
            ? String(res.data.cert_export_owner_uid)
            : '',
        cert_export_group_gid:
          res.data.cert_export_group_gid != null
            ? String(res.data.cert_export_group_gid)
            : '',
        cert_export_file_mode:
          res.data.cert_export_file_mode != null
            ? (res.data.cert_export_file_mode as number).toString(8)
            : '640',
        cert_export_dir_mode:
          res.data.cert_export_dir_mode != null
            ? (res.data.cert_export_dir_mode as number).toString(8)
            : '750',
      };
      showToast('Settings saved.', 'success');
    }
    settingsSaving = false;
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
    <AppearanceTab
      {theme}
      expanded={expandedSections.appearance}
      toggleSection={() => toggleSection('appearance')}
      onToggleTheme={toggleTheme}
    />

    <GlobalConfigTab
      bind:settingsForm
      expanded={expandedSections.global}
      toggleSection={() => toggleSection('global')}
      {settingsSaving}
      {settingsMsg}
      {settingsError}
      onSave={saveSettings}
    />

    <NetworkTab
      bind:settingsForm
      expanded={expandedSections.network}
      toggleSection={() => toggleSection('network')}
      {settingsSaving}
      {settingsMsg}
      {settingsError}
      onSave={saveSettings}
    />

    <ObservabilityTab
      bind:settingsForm
      expanded={expandedSections.observability}
      toggleSection={() => toggleSection('observability')}
      onSave={saveSettings}
      {settingsSaving}
      {settingsMsg}
      {settingsError}
    />

    <CertExportTab
      bind:settingsForm
      expanded={expandedSections.cert_export}
      toggleSection={() => toggleSection('cert_export')}
      onSave={saveSettings}
      {settingsSaving}
      {settingsMsg}
      {settingsError}
    />

    <SecurityPresetsTab
      bind:customPresets
      expanded={expandedSections.presets}
      toggleSection={() => toggleSection('presets')}
    />

    <BanRulesTab
      expanded={expandedSections.ban_rules}
      toggleSection={() => toggleSection('ban_rules')}
    />

    <SettingsDnsProviders bind:dnsProviders {expandedSections} {toggleSection} onReload={loadAll} />

    <SettingsNotifications bind:notifications {expandedSections} {toggleSection} onReload={loadAll} />

    <NotificationHistoryTab
      {notifHistory}
      expanded={expandedSections.history}
      toggleSection={() => toggleSection('history')}
    />

    <PreferencesTab
      {preferences}
      expanded={expandedSections.preferences}
      toggleSection={() => toggleSection('preferences')}
      onReload={loadAll}
    />

    <ExportImportTab
      expanded={expandedSections.export}
      toggleSection={() => toggleSection('export')}
      onReload={loadAll}
    />
  {/if}
</div>

<style>
  .settings-page { max-width: none; }
</style>
