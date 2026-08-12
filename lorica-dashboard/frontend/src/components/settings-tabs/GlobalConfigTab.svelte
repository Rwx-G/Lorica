<script lang="ts">
  import { isSuperAdmin } from '../../lib/auth';
  import type { SettingsSchemaResponse } from '../../lib/api';

  interface SettingsFormShape {
    management_port: number;
    log_level: string;
    default_health_check_interval_s: number;
    health_max_concurrent_probes: number;
    cert_warning_days: number;
    cert_critical_days: number;
    max_global_connections: number;
    flood_threshold_rps: number;
    waf_ban_threshold: number;
    waf_ban_duration_s: number;
    access_log_retention: number;
    waf_event_retention: number;
    sla_purge_enabled: boolean;
    sla_purge_retention_days: number;
    sla_purge_schedule: string;
    waf_whitelist_ips: string;
  }

  interface Props {
    settingsForm: SettingsFormShape;
    /**
     * Server-authoritative field bounds (Story 8.10 AC #7). Empty
     * before the schema loads, so every input falls back to its UI
     * default via `bound()`.
     */
    schema: SettingsSchemaResponse;
    expanded: boolean;
    toggleSection: () => void;
    settingsSaving: boolean;
    settingsMsg: string;
    settingsError: string;
    onSave: () => void | Promise<void>;
  }

  let {
    settingsForm = $bindable(),
    schema,
    expanded,
    toggleSection,
    settingsSaving,
    settingsMsg,
    settingsError,
    onSave,
  }: Props = $props();

  interface Bound {
    min: number;
    max: number;
  }

  // Read a field's bounds from the server schema, falling back to the
  // supplied UI defaults. The server enforces no upper bound on some
  // fields (schema omits `max`), so the fallback max is a UI-only cap.
  function bound(field: string, fallbackMin: number, fallbackMax: number): Bound {
    const f = schema[field];
    return {
      min: typeof f?.min === 'number' ? f.min : fallbackMin,
      max: typeof f?.max === 'number' ? f.max : fallbackMax,
    };
  }

  const c = $derived({
    hcInterval: bound('default_health_check_interval_s', 1, 3600),
    healthProbes: bound('health_max_concurrent_probes', 1, 512),
    certWarn: bound('cert_warning_days', 1, 365),
    certCrit: bound('cert_critical_days', 1, 365),
    maxGlobal: bound('max_global_connections', 0, 1_000_000),
    flood: bound('flood_threshold_rps', 0, 1_000_000),
    wafBanThreshold: bound('waf_ban_threshold', 0, 1000),
    wafBanDur: bound('waf_ban_duration_s', 0, 604_800),
    logRet: bound('access_log_retention', 0, 100_000_000),
    wafRet: bound('waf_event_retention', 0, 100_000_000),
    slaPurge: bound('sla_purge_retention_days', 1, 3650),
  });

  function numErr(raw: number | string, min: number, max: number): string | null {
    const str = String(raw).trim();
    if (str === '') return null;
    const n = Number(str);
    if (!Number.isInteger(n) || n < min || n > max) {
      return `value must be an integer in ${min}..${max}`;
    }
    return null;
  }
  let hcIntervalErr = $state<string | null>(null);
  let healthProbesErr = $state<string | null>(null);
  let certWarnErr = $state<string | null>(null);
  let certCritErr = $state<string | null>(null);
  let maxGlobalErr = $state<string | null>(null);
  let floodErr = $state<string | null>(null);
  let wafBanThresholdErr = $state<string | null>(null);
  let wafBanDurErr = $state<string | null>(null);
  let logRetErr = $state<string | null>(null);
  let wafRetErr = $state<string | null>(null);
  let slaPurgeErr = $state<string | null>(null);
  function checkHcInterval() { hcIntervalErr = numErr(settingsForm.default_health_check_interval_s, c.hcInterval.min, c.hcInterval.max); }
  function checkHealthProbes() { healthProbesErr = numErr(settingsForm.health_max_concurrent_probes, c.healthProbes.min, c.healthProbes.max); }
  function checkCertWarn() { certWarnErr = numErr(settingsForm.cert_warning_days, c.certWarn.min, c.certWarn.max); }
  function checkCertCrit() { certCritErr = numErr(settingsForm.cert_critical_days, c.certCrit.min, c.certCrit.max); }
  function checkMaxGlobal() { maxGlobalErr = numErr(settingsForm.max_global_connections, c.maxGlobal.min, c.maxGlobal.max); }
  function checkFlood() { floodErr = numErr(settingsForm.flood_threshold_rps, c.flood.min, c.flood.max); }
  function checkWafBanThreshold() { wafBanThresholdErr = numErr(settingsForm.waf_ban_threshold, c.wafBanThreshold.min, c.wafBanThreshold.max); }
  function checkWafBanDur() { wafBanDurErr = numErr(settingsForm.waf_ban_duration_s, c.wafBanDur.min, c.wafBanDur.max); }
  function checkLogRet() { logRetErr = numErr(settingsForm.access_log_retention, c.logRet.min, c.logRet.max); }
  function checkWafRet() { wafRetErr = numErr(settingsForm.waf_event_retention, c.wafRet.min, c.wafRet.max); }
  function checkSlaPurge() { slaPurgeErr = numErr(settingsForm.sla_purge_retention_days, c.slaPurge.min, c.slaPurge.max); }
</script>

<section class="settings-section">
  <button class="settings-collapsible-header" class:open={expanded} onclick={toggleSection}>
    <h2>Global Configuration</h2>
    <span class="settings-chevron" class:expanded></span>
  </button>
  {#if expanded}
    <div class="settings-section-body">
      <div class="settings-form-row">
        <label for="mgmt-port">Management Port</label>
        <input id="mgmt-port" type="number" bind:value={settingsForm.management_port} min="1" max="65535" disabled />
        <span class="hint">Read-only - requires restart to change</span>
      </div>
      <div class="settings-form-row">
        <label for="log-level">Log Level</label>
        <select id="log-level" bind:value={settingsForm.log_level}>
          <option value="trace">trace</option>
          <option value="debug">debug</option>
          <option value="info">info</option>
          <option value="warn">warn</option>
          <option value="error">error</option>
        </select>
      </div>
      <div class="settings-form-row">
        <label for="hc-interval">Default Health Check Interval (s)</label>
        <input id="hc-interval" type="number" bind:value={settingsForm.default_health_check_interval_s} min={c.hcInterval.min} max={c.hcInterval.max} onblur={checkHcInterval} oninput={checkHcInterval} />
        {#if hcIntervalErr}<span class="field-error" role="alert">{hcIntervalErr}</span>{/if}
      </div>
      <div class="settings-form-row">
        <label for="health-max-probes">Max Concurrent Health Probes</label>
        <input id="health-max-probes" type="number" bind:value={settingsForm.health_max_concurrent_probes} min={c.healthProbes.min} max={c.healthProbes.max} onblur={checkHealthProbes} oninput={checkHealthProbes} />
        {#if healthProbesErr}<span class="field-error" role="alert">{healthProbesErr}</span>{/if}
      </div>
      <div class="settings-form-row">
        <label for="cert-warn">Certificate Warning Threshold (days)</label>
        <input id="cert-warn" type="number" bind:value={settingsForm.cert_warning_days} min={c.certWarn.min} max={c.certWarn.max} onblur={checkCertWarn} oninput={checkCertWarn} />
        {#if certWarnErr}<span class="field-error" role="alert">{certWarnErr}</span>{/if}
      </div>
      <div class="settings-form-row">
        <label for="cert-crit">Certificate Critical Threshold (days)</label>
        <input id="cert-crit" type="number" bind:value={settingsForm.cert_critical_days} min={c.certCrit.min} max={c.certCrit.max} onblur={checkCertCrit} oninput={checkCertCrit} />
        {#if certCritErr}<span class="field-error" role="alert">{certCritErr}</span>{/if}
      </div>
      <div class="settings-form-row">
        <label for="max-global-conn">Max Global Connections</label>
        <input id="max-global-conn" type="number" bind:value={settingsForm.max_global_connections} min={c.maxGlobal.min} max={c.maxGlobal.max} onblur={checkMaxGlobal} oninput={checkMaxGlobal} />
        {#if maxGlobalErr}<span class="field-error" role="alert">{maxGlobalErr}</span>{/if}
        <span class="hint">0 = unlimited. New requests get 503 when limit is reached.</span>
      </div>
      <div class="settings-form-row">
        <label for="flood-threshold">Flood Detection Threshold (RPS)</label>
        <input id="flood-threshold" type="number" bind:value={settingsForm.flood_threshold_rps} min={c.flood.min} max={c.flood.max} onblur={checkFlood} oninput={checkFlood} />
        {#if floodErr}<span class="field-error" role="alert">{floodErr}</span>{/if}
        <span class="hint">0 = disabled. When exceeded, per-IP rate limits are halved.</span>
      </div>
      <div class="settings-form-row">
        <label for="waf-ban-threshold">WAF Auto-ban Threshold</label>
        <input id="waf-ban-threshold" type="number" bind:value={settingsForm.waf_ban_threshold} min={c.wafBanThreshold.min} max={c.wafBanThreshold.max} onblur={checkWafBanThreshold} oninput={checkWafBanThreshold} />
        {#if wafBanThresholdErr}<span class="field-error" role="alert">{wafBanThresholdErr}</span>{/if}
        <span class="hint">Ban IP after this many WAF blocks per worker (0 = disabled, default 3). With N workers, up to N x threshold requests may pass before the ban triggers.</span>
      </div>
      <div class="settings-form-row">
        <label for="waf-ban-duration">WAF Ban Duration (seconds)</label>
        <input id="waf-ban-duration" type="number" bind:value={settingsForm.waf_ban_duration_s} min={c.wafBanDur.min} max={c.wafBanDur.max} onblur={checkWafBanDur} oninput={checkWafBanDur} />
        {#if wafBanDurErr}<span class="field-error" role="alert">{wafBanDurErr}</span>{/if}
        <span class="hint">How long to ban (default 3600 = 1 hour, max 7 days).</span>
      </div>
      <div class="settings-form-row">
        <label for="waf-whitelist">WAF Whitelist IPs</label>
        <textarea id="waf-whitelist" rows="3" bind:value={settingsForm.waf_whitelist_ips} placeholder="203.0.113.50&#10;10.0.0.0/8"></textarea>
        <span class="hint">One IP or CIDR per line. These IPs bypass WAF, rate limiting, IP blocklist, and auto-ban entirely. Use for admin/operator IPs.</span>
      </div>
      <div class="settings-form-row">
        <label for="s-log-retention">Access Log Retention (entries)</label>
        <input id="s-log-retention" type="number" min={c.logRet.min} max={c.logRet.max} bind:value={settingsForm.access_log_retention} onblur={checkLogRet} oninput={checkLogRet} />
        {#if logRetErr}<span class="field-error" role="alert">{logRetErr}</span>{/if}
        <span class="hint">Maximum entries in persistent log store (0 = unlimited).</span>
      </div>
      <div class="settings-form-row">
        <label for="s-waf-retention">WAF Event Retention (entries)</label>
        <input id="s-waf-retention" type="number" min={c.wafRet.min} max={c.wafRet.max} bind:value={settingsForm.waf_event_retention} onblur={checkWafRet} oninput={checkWafRet} />
        {#if wafRetErr}<span class="field-error" role="alert">{wafRetErr}</span>{/if}
        <span class="hint">Maximum WAF events in persistent store (0 = unlimited).</span>
      </div>

      <h3 class="subsection-title">SLA Data Purge</h3>
      <div class="settings-form-row">
        <label for="sla-purge-toggle" class="toggle-label">
          <input id="sla-purge-toggle" type="checkbox" bind:checked={settingsForm.sla_purge_enabled} />
          Enable automatic SLA purge
        </label>
      </div>
      {#if settingsForm.sla_purge_enabled}
        <div class="settings-form-row">
          <label for="sla-purge-days">Purge SLA data older than (days)</label>
          <input id="sla-purge-days" type="number" min={c.slaPurge.min} max={c.slaPurge.max} bind:value={settingsForm.sla_purge_retention_days} onblur={checkSlaPurge} oninput={checkSlaPurge} />
          {#if slaPurgeErr}<span class="field-error" role="alert">{slaPurgeErr}</span>{/if}
          <span class="hint">Buckets older than this will be permanently deleted.</span>
        </div>
        <div class="settings-form-row">
          <label for="sla-purge-schedule">Purge schedule</label>
          <select id="sla-purge-schedule" bind:value={settingsForm.sla_purge_schedule}>
            <option value="first_of_month">First day of the month</option>
            <option value="daily">Daily (rolling)</option>
            <optgroup label="Specific day of month">
              {#each Array.from({ length: 28 }, (_, i) => i + 1) as day (day)}
                <option value={String(day)}>Day {day}</option>
              {/each}
            </optgroup>
          </select>
          <span class="hint">When the purge job runs.</span>
        </div>
      {/if}

      {#if settingsError}
        <div class="settings-form-error">{settingsError}</div>
      {/if}
      {#if $isSuperAdmin}
        <div class="settings-dialog-actions">
          <button class="btn btn-primary" onclick={onSave} disabled={settingsSaving}>
            {settingsSaving ? 'Saving...' : 'Save Settings'}
          </button>
        </div>
      {/if}
    </div>
  {/if}
</section>

<style>
  .hint {
    display: block;
    font-size: 0.75rem;
    color: var(--color-text-muted);
    margin-top: 0.25rem;
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
  .field-error { display: block; color: var(--color-red); font-size: var(--text-xs); margin-top: 0.25rem; }
</style>
