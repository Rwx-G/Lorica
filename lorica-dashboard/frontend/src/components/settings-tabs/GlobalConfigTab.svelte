<script lang="ts">
  import { isSuperAdmin } from '../../lib/auth';
  import type { SettingsSchemaResponse } from '../../lib/api';
  import { integerInRange, settingsBound, type SettingsBound } from '../../lib/validators';

  interface SettingsFormShape {
    management_port: number;
    log_level: string;
    default_health_check_interval_s: number;
    health_max_concurrent_probes: number;
    cert_warning_days: number;
    cert_critical_days: number;
    max_global_connections: number;
    flood_threshold_rps: number;
    flood_strict_rps: number;
    header_timeout_s: number;
    waf_ban_threshold: number;
    waf_ban_duration_s: number;
    waf_body_scan_max_inflight_bytes: number;
    access_log_retention: number;
    waf_event_retention: number;
    sla_purge_enabled: boolean;
    sla_purge_retention_days: number;
    sla_purge_schedule: string;
    waf_whitelist_ips: string;
    max_active_probes: number;
    loadtest_max_concurrency: number;
    loadtest_max_duration_s: number;
    loadtest_max_rps: number;
  }

  interface Props {
    settingsForm: SettingsFormShape;
    /**
     * Server-authoritative field bounds (Story 8.10 AC #7). Empty
     * before the schema loads, so every input falls back to its UI
     * default via `settingsBound()`.
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

  // The fallbacks are UI-only caps, used before the schema loads and
  // for fields whose validator sets no ceiling (the schema omits `max`).
  const bound = (field: string, fallbackMin: number, fallbackMax: number): SettingsBound =>
    settingsBound(schema, field, fallbackMin, fallbackMax);

  const c = $derived({
    hcInterval: bound('default_health_check_interval_s', 1, 3600),
    healthProbes: bound('health_max_concurrent_probes', 1, 512),
    certWarn: bound('cert_warning_days', 1, 365),
    certCrit: bound('cert_critical_days', 1, 365),
    maxGlobal: bound('max_global_connections', 0, 1_000_000),
    flood: bound('flood_threshold_rps', 0, 1_000_000),
    floodStrict: bound('flood_strict_rps', 0, 10_000_000),
    headerTimeout: bound('header_timeout_s', 0, 3600),
    wafBanThreshold: bound('waf_ban_threshold', 0, 1000),
    wafBanDur: bound('waf_ban_duration_s', 0, 2_592_000),
    wafScanBudget: bound('waf_body_scan_max_inflight_bytes', 1_048_576, 17_179_869_184),
    logRet: bound('access_log_retention', 0, 100_000_000),
    wafRet: bound('waf_event_retention', 0, 100_000_000),
    slaPurge: bound('sla_purge_retention_days', 1, 3650),
    activeProbes: bound('max_active_probes', 1, 10_000),
    loadConcurrency: bound('loadtest_max_concurrency', 1, 10_000),
    loadDuration: bound('loadtest_max_duration_s', 1, 86_400),
    loadRps: bound('loadtest_max_rps', 1, 1_000_000),
  });

  let hcIntervalErr = $state<string | null>(null);
  let healthProbesErr = $state<string | null>(null);
  let certWarnErr = $state<string | null>(null);
  let certCritErr = $state<string | null>(null);
  let maxGlobalErr = $state<string | null>(null);
  let floodErr = $state<string | null>(null);
  let floodStrictErr = $state<string | null>(null);
  let headerTimeoutErr = $state<string | null>(null);
  let wafBanThresholdErr = $state<string | null>(null);
  let wafBanDurErr = $state<string | null>(null);
  let wafScanBudgetErr = $state<string | null>(null);
  let logRetErr = $state<string | null>(null);
  let wafRetErr = $state<string | null>(null);
  let slaPurgeErr = $state<string | null>(null);
  let activeProbesErr = $state<string | null>(null);
  let loadConcurrencyErr = $state<string | null>(null);
  let loadDurationErr = $state<string | null>(null);
  let loadRpsErr = $state<string | null>(null);
  function checkHcInterval() { hcIntervalErr = integerInRange(settingsForm.default_health_check_interval_s, c.hcInterval); }
  function checkHealthProbes() { healthProbesErr = integerInRange(settingsForm.health_max_concurrent_probes, c.healthProbes); }
  function checkCertWarn() { certWarnErr = integerInRange(settingsForm.cert_warning_days, c.certWarn); }
  function checkCertCrit() { certCritErr = integerInRange(settingsForm.cert_critical_days, c.certCrit); }
  function checkMaxGlobal() { maxGlobalErr = integerInRange(settingsForm.max_global_connections, c.maxGlobal); }
  function checkFlood() {
    floodErr = integerInRange(settingsForm.flood_threshold_rps, c.flood);
    checkFloodStrict();
  }
  // The server refuses a strict rate at or above the threshold while
  // both are set (`GlobalSettings::validate_cross_fields`); `0` is
  // "auto", half the threshold, and exempt.
  function checkFloodStrict() {
    const outOfRange = integerInRange(settingsForm.flood_strict_rps, c.floodStrict);
    const threshold = Number(settingsForm.flood_threshold_rps);
    const strict = Number(settingsForm.flood_strict_rps);
    floodStrictErr =
      outOfRange ??
      (threshold > 0 && strict > 0 && strict >= threshold
        ? `must be below the flood detection threshold (${threshold}) while both are set; 0 = half the threshold`
        : null);
  }
  function checkHeaderTimeout() { headerTimeoutErr = integerInRange(settingsForm.header_timeout_s, c.headerTimeout); }
  function checkWafBanThreshold() { wafBanThresholdErr = integerInRange(settingsForm.waf_ban_threshold, c.wafBanThreshold); }
  function checkWafBanDur() { wafBanDurErr = integerInRange(settingsForm.waf_ban_duration_s, c.wafBanDur); }
  function checkWafScanBudget() { wafScanBudgetErr = integerInRange(settingsForm.waf_body_scan_max_inflight_bytes, c.wafScanBudget); }
  function checkLogRet() { logRetErr = integerInRange(settingsForm.access_log_retention, c.logRet); }
  function checkWafRet() { wafRetErr = integerInRange(settingsForm.waf_event_retention, c.wafRet); }
  function checkSlaPurge() { slaPurgeErr = integerInRange(settingsForm.sla_purge_retention_days, c.slaPurge); }
  function checkActiveProbes() { activeProbesErr = integerInRange(settingsForm.max_active_probes, c.activeProbes); }
  function checkLoadConcurrency() { loadConcurrencyErr = integerInRange(settingsForm.loadtest_max_concurrency, c.loadConcurrency); }
  function checkLoadDuration() { loadDurationErr = integerInRange(settingsForm.loadtest_max_duration_s, c.loadDuration); }
  function checkLoadRps() { loadRpsErr = integerInRange(settingsForm.loadtest_max_rps, c.loadRps); }
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
        <span class="hint">0 = disabled. While the proxy-wide rate is above it, every client is held to the flood strict rate below.</span>
      </div>
      <div class="settings-form-row">
        <label for="flood-strict">Flood Strict Rate (RPS per IP)</label>
        <input id="flood-strict" type="number" bind:value={settingsForm.flood_strict_rps} min={c.floodStrict.min} max={c.floodStrict.max} onblur={checkFloodStrict} oninput={checkFloodStrict} />
        {#if floodStrictErr}<span class="field-error" role="alert">{floodStrictErr}</span>{/if}
        <span class="hint">Per-IP admission rate while the proxy is in flood mode. 0 = auto (half the threshold). When set, it must be below the threshold.</span>
      </div>
      <div class="settings-form-row">
        <label for="header-timeout">Header Timeout (seconds)</label>
        <input id="header-timeout" type="number" bind:value={settingsForm.header_timeout_s} min={c.headerTimeout.min} max={c.headerTimeout.max} onblur={checkHeaderTimeout} oninput={checkHeaderTimeout} />
        {#if headerTimeoutErr}<span class="field-error" role="alert">{headerTimeoutErr}</span>{/if}
        <span class="hint">Time a client has to finish sending its request headers before it is answered 408, on every route (a slowloris floor). 0 = off; per-route thresholds still apply.</span>
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
        <span class="hint">How long to ban (default 3600 = 1 hour, max {Math.floor(c.wafBanDur.max / 86_400)} days).</span>
      </div>
      <div class="settings-form-row">
        <label for="waf-scan-budget">WAF Body Scan Budget (bytes)</label>
        <input id="waf-scan-budget" type="number" bind:value={settingsForm.waf_body_scan_max_inflight_bytes} min={c.wafScanBudget.min} max={c.wafScanBudget.max} onblur={checkWafScanBudget} oninput={checkWafScanBudget} />
        {#if wafScanBudgetErr}<span class="field-error" role="alert">{wafScanBudgetErr}</span>{/if}
        <span class="hint">Ceiling on the bytes held in WAF body-scan buffers at once (default 268435456 = 256 MiB). The budget is per process, so worker mode multiplies it by the worker count. A request that would exceed it is let through UNSCANNED rather than rejected, and raises a skipped-budget WAF event.</span>
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

      <h3 class="subsection-title">Probes and Load Tests</h3>
      <div class="settings-form-row">
        <label for="max-active-probes">Max Active Probes</label>
        <input id="max-active-probes" type="number" bind:value={settingsForm.max_active_probes} min={c.activeProbes.min} max={c.activeProbes.max} onblur={checkActiveProbes} oninput={checkActiveProbes} />
        {#if activeProbesErr}<span class="field-error" role="alert">{activeProbesErr}</span>{/if}
        <span class="hint">Synthetic probes that run at once. Enabled probes past this many do not run.</span>
      </div>
      <div class="settings-form-row">
        <label for="loadtest-max-concurrency">Load Test Concurrency Ceiling</label>
        <input id="loadtest-max-concurrency" type="number" bind:value={settingsForm.loadtest_max_concurrency} min={c.loadConcurrency.min} max={c.loadConcurrency.max} onblur={checkLoadConcurrency} oninput={checkLoadConcurrency} />
        {#if loadConcurrencyErr}<span class="field-error" role="alert">{loadConcurrencyErr}</span>{/if}
        <span class="hint">A load test with more concurrent connections than this asks for confirmation before it runs.</span>
      </div>
      <div class="settings-form-row">
        <label for="loadtest-max-duration">Load Test Duration Ceiling (seconds)</label>
        <input id="loadtest-max-duration" type="number" bind:value={settingsForm.loadtest_max_duration_s} min={c.loadDuration.min} max={c.loadDuration.max} onblur={checkLoadDuration} oninput={checkLoadDuration} />
        {#if loadDurationErr}<span class="field-error" role="alert">{loadDurationErr}</span>{/if}
        <span class="hint">A load test longer than this asks for confirmation before it runs.</span>
      </div>
      <div class="settings-form-row">
        <label for="loadtest-max-rps">Load Test Rate Ceiling (RPS)</label>
        <input id="loadtest-max-rps" type="number" bind:value={settingsForm.loadtest_max_rps} min={c.loadRps.min} max={c.loadRps.max} onblur={checkLoadRps} oninput={checkLoadRps} />
        {#if loadRpsErr}<span class="field-error" role="alert">{loadRpsErr}</span>{/if}
        <span class="hint">A load test faster than this asks for confirmation before it runs.</span>
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
