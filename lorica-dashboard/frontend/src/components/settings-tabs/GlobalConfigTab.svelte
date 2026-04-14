<script lang="ts">
  interface SettingsFormShape {
    management_port: number;
    log_level: string;
    default_health_check_interval_s: number;
    cert_warning_days: number;
    cert_critical_days: number;
    max_global_connections: number;
    flood_threshold_rps: number;
    waf_ban_threshold: number;
    waf_ban_duration_s: number;
    access_log_retention: number;
    sla_purge_enabled: boolean;
    sla_purge_retention_days: number;
    sla_purge_schedule: string;
    trusted_proxies: string;
    waf_whitelist_ips: string;
    connection_deny_cidrs: string;
    connection_allow_cidrs: string;
  }

  interface Props {
    settingsForm: SettingsFormShape;
    expanded: boolean;
    toggleSection: () => void;
    settingsSaving: boolean;
    settingsMsg: string;
    settingsError: string;
    onSave: () => void | Promise<void>;
  }

  let {
    settingsForm = $bindable(),
    expanded,
    toggleSection,
    settingsSaving,
    settingsMsg,
    settingsError,
    onSave,
  }: Props = $props();
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
        <input id="hc-interval" type="number" bind:value={settingsForm.default_health_check_interval_s} min="1" max="3600" />
      </div>
      <div class="settings-form-row">
        <label for="cert-warn">Certificate Warning Threshold (days)</label>
        <input id="cert-warn" type="number" bind:value={settingsForm.cert_warning_days} min="1" max="365" />
      </div>
      <div class="settings-form-row">
        <label for="cert-crit">Certificate Critical Threshold (days)</label>
        <input id="cert-crit" type="number" bind:value={settingsForm.cert_critical_days} min="1" max="365" />
      </div>
      <div class="settings-form-row">
        <label for="max-global-conn">Max Global Connections</label>
        <input id="max-global-conn" type="number" bind:value={settingsForm.max_global_connections} min="0" max="1000000" />
        <span class="hint">0 = unlimited. New requests get 503 when limit is reached.</span>
      </div>
      <div class="settings-form-row">
        <label for="flood-threshold">Flood Detection Threshold (RPS)</label>
        <input id="flood-threshold" type="number" bind:value={settingsForm.flood_threshold_rps} min="0" max="1000000" />
        <span class="hint">0 = disabled. When exceeded, per-IP rate limits are halved.</span>
      </div>
      <div class="settings-form-row">
        <label for="waf-ban-threshold">WAF Auto-ban Threshold</label>
        <input id="waf-ban-threshold" type="number" bind:value={settingsForm.waf_ban_threshold} min="0" max="1000" />
        <span class="hint">Ban IP after this many WAF blocks per worker (0 = disabled, default 3). With N workers, up to N x threshold requests may pass before the ban triggers.</span>
      </div>
      <div class="settings-form-row">
        <label for="waf-ban-duration">WAF Ban Duration (seconds)</label>
        <input id="waf-ban-duration" type="number" bind:value={settingsForm.waf_ban_duration_s} min="0" max="604800" />
        <span class="hint">How long to ban (default 3600 = 1 hour, max 7 days).</span>
      </div>
      <div class="settings-form-row">
        <label for="trusted-proxies">Trusted Proxies (CIDR)</label>
        <textarea id="trusted-proxies" rows="4" bind:value={settingsForm.trusted_proxies} placeholder="192.168.0.0/16&#10;10.0.0.0/8&#10;172.16.0.0/12"></textarea>
        <span class="hint">One CIDR range or IP per line. X-Forwarded-For is only trusted from these addresses. Empty = trust no XFF (direct client IP always used).</span>
      </div>
      <div class="settings-form-row">
        <label for="waf-whitelist">WAF Whitelist IPs</label>
        <textarea id="waf-whitelist" rows="3" bind:value={settingsForm.waf_whitelist_ips} placeholder="203.0.113.50&#10;10.0.0.0/8"></textarea>
        <span class="hint">One IP or CIDR per line. These IPs bypass WAF, rate limiting, IP blocklist, and auto-ban entirely. Use for admin/operator IPs.</span>
      </div>
      <div class="settings-form-row">
        <label for="conn-deny">Connection Deny CIDRs</label>
        <textarea id="conn-deny" rows="3" bind:value={settingsForm.connection_deny_cidrs} placeholder="198.51.100.0/24&#10;2001:db8::/32"></textarea>
        <span class="hint">One IP or CIDR per line. Matching connections are dropped at TCP accept, before TLS handshake. Evaluated after the allow list; deny always wins.</span>
      </div>
      <div class="settings-form-row">
        <label for="conn-allow">Connection Allow CIDRs</label>
        <textarea id="conn-allow" rows="3" bind:value={settingsForm.connection_allow_cidrs} placeholder="10.0.0.0/8&#10;192.168.0.0/16"></textarea>
        <span class="hint">One IP or CIDR per line. Leave empty for default-allow. When non-empty, switches the pre-filter to default-deny: only listed IPs are accepted.</span>
      </div>
      <div class="settings-form-row">
        <label for="s-log-retention">Access Log Retention (entries)</label>
        <input id="s-log-retention" type="number" min="0" bind:value={settingsForm.access_log_retention} />
        <span class="hint">Maximum entries in persistent log store (0 = unlimited).</span>
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
          <input id="sla-purge-days" type="number" min="1" max="3650" bind:value={settingsForm.sla_purge_retention_days} />
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
      {#if settingsMsg}
        <div class="form-success">{settingsMsg}</div>
      {/if}
      <div class="settings-dialog-actions">
        <button class="btn btn-primary" onclick={onSave} disabled={settingsSaving}>
          {settingsSaving ? 'Saving...' : 'Save Settings'}
        </button>
      </div>
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

  .form-success {
    color: var(--color-green);
    font-size: 0.8125rem;
    margin: 0.5rem 0;
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
</style>
