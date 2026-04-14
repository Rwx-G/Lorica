<script lang="ts">
  import type { RouteFormState } from '../../lib/route-form';
  import { ROUTE_DEFAULTS } from '../../lib/route-form';

  interface Props {
    form: RouteFormState;
    importedFields?: Set<string>;
  }

  let { form = $bindable(), importedFields }: Props = $props();

  function isModified(field: keyof RouteFormState): boolean {
    return ROUTE_DEFAULTS[field] !== form[field];
  }

  function isImported(field: string): boolean {
    return importedFields?.has(field) ?? false;
  }
</script>

<div class="tab-content">
  <div class="form-row">
    <div class="form-group" class:modified={isModified('max_connections')}>
      <label for="max-connections">Max connections</label>
      {#if isImported('max_connections')}<span class="imported-badge">imported</span>{/if}
      <input id="max-connections" type="number" min="1" bind:value={form.max_connections} placeholder="No limit" />
      <span class="hint">Nginx: limit_conn | HAProxy: maxconn per backend</span>
    </div>
    <div class="form-group" class:modified={isModified('slowloris_threshold_ms')}>
      <label for="slowloris-threshold">Slowloris threshold (ms)</label>
      {#if isImported('slowloris_threshold_ms')}<span class="imported-badge">imported</span>{/if}
      <input id="slowloris-threshold" type="number" min="100" bind:value={form.slowloris_threshold_ms} placeholder="5000" />
      <span class="hint">Nginx: client_header_timeout | HAProxy: timeout http-request</span>
    </div>
  </div>

  <div class="form-row">
    <div class="form-group" class:modified={isModified('auto_ban_threshold')}>
      <label for="auto-ban-threshold">Auto-ban threshold <span class="hint">(violations before ban)</span></label>
      {#if isImported('auto_ban_threshold')}<span class="imported-badge">imported</span>{/if}
      <input id="auto-ban-threshold" type="number" min="1" bind:value={form.auto_ban_threshold} placeholder="Disabled" />
      <span class="hint">Fail2ban-like behavior built into the proxy</span>
    </div>
    <div class="form-group" class:modified={isModified('auto_ban_duration_s')}>
      <label for="auto-ban-duration">Auto-ban duration (s)</label>
      {#if isImported('auto_ban_duration_s')}<span class="imported-badge">imported</span>{/if}
      <input id="auto-ban-duration" type="number" min="1" bind:value={form.auto_ban_duration_s} placeholder="3600" />
    </div>
  </div>

  <div class="section-divider">
    <h4>Rate limit <span class="hint">(token bucket, cross-worker)</span></h4>
    <p class="section-hint">
      Cross-worker under <code>--workers N</code>: every worker's local bucket is
      synced with the supervisor every 100 ms. Leave capacity empty to disable.
      See <code>docs/architecture/worker-shared-state.md</code> § 6.
    </p>
  </div>

  <div class="form-row">
    <div class="form-group" class:modified={isModified('rate_limit_capacity')}>
      <label for="rate-limit-capacity">Capacity <span class="hint">(burst tokens)</span></label>
      {#if isImported('rate_limit_capacity')}<span class="imported-badge">imported</span>{/if}
      <input id="rate-limit-capacity" type="number" min="0" max="1000000" bind:value={form.rate_limit_capacity} placeholder="Disabled" />
      <span class="hint">Burst size. 0 disables.</span>
    </div>
    <div class="form-group" class:modified={isModified('rate_limit_refill_per_sec')}>
      <label for="rate-limit-refill">Refill (tokens/s)</label>
      {#if isImported('rate_limit_refill_per_sec')}<span class="imported-badge">imported</span>{/if}
      <input id="rate-limit-refill" type="number" min="0" max="1000000" bind:value={form.rate_limit_refill_per_sec} placeholder="0 = one-shot" />
      <span class="hint">Steady-state rate. 0 = bucket drains and does not refill.</span>
    </div>
  </div>

  <div class="form-row">
    <div class="form-group" class:modified={isModified('rate_limit_scope')}>
      <label for="rate-limit-scope">Scope</label>
      {#if isImported('rate_limit_scope')}<span class="imported-badge">imported</span>{/if}
      <select id="rate-limit-scope" bind:value={form.rate_limit_scope}>
        <option value="per_ip">Per client IP (default)</option>
        <option value="per_route">Per route (shared across all clients)</option>
      </select>
      <span class="hint">
        Per-IP isolates abusive clients; per-route caps aggregate traffic to the origin.
      </span>
    </div>
  </div>

  <div class="section-divider">
    <h4>GeoIP country filter <span class="hint">(per route)</span></h4>
    <p class="section-hint">
      Resolves the client IP to an ISO 3166-1 alpha-2 country code via the
      <code>.mmdb</code> database configured in Settings. Allowlist = only listed
      countries pass; denylist = listed countries are rejected (403). Unknown
      country (reserved / private IP, DB miss) falls through without blocking;
      layer <code>ip_allowlist</code> on top for fail-close semantics. Requires
      <code>geoip_db_path</code> set globally.
    </p>
  </div>

  <div class="form-row">
    <div class="form-group" class:modified={isModified('geoip_mode')}>
      <label for="geoip-mode">Mode</label>
      {#if isImported('geoip_mode')}<span class="imported-badge">imported</span>{/if}
      <select id="geoip-mode" bind:value={form.geoip_mode}>
        <option value="denylist">Denylist (block listed countries)</option>
        <option value="allowlist">Allowlist (block everything except listed)</option>
      </select>
      <span class="hint">
        Empty country list in denylist mode = filter disabled for this route.
        Allowlist with empty list is rejected by the API (would block
        everything).
      </span>
    </div>
  </div>

  <div class="form-row">
    <div class="form-group" class:modified={isModified('geoip_countries')}>
      <label for="geoip-countries">Countries <span class="hint">(ISO 3166-1 alpha-2, comma-separated)</span></label>
      {#if isImported('geoip_countries')}<span class="imported-badge">imported</span>{/if}
      <input
        id="geoip-countries"
        type="text"
        bind:value={form.geoip_countries}
        placeholder="e.g. FR, DE, IT"
        autocomplete="off"
      />
      <span class="hint">
        Codes normalised to uppercase, duplicates collapsed. Max 300 entries.
      </span>
    </div>
  </div>
</div>

<style>
  .tab-content { display: flex; flex-direction: column; gap: 0; }

  .form-group { margin-bottom: 1rem; }
  .form-group.modified { border-left: 3px solid var(--color-primary); padding-left: 0.75rem; }

  .form-group label {
    display: block;
    font-size: 0.8125rem;
    font-weight: 500;
    color: var(--color-text-muted);
    margin-bottom: 0.375rem;
  }

  .form-group input[type="number"] {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
  }

  .form-group input:focus,
  .form-group select:focus { outline: none; border-color: var(--color-primary); }

  .form-group select {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
  }

  .section-divider {
    margin-top: 1.5rem;
    padding-top: 1rem;
    border-top: 1px solid var(--color-border);
  }
  .section-divider h4 {
    font-size: 0.875rem;
    font-weight: 600;
    color: var(--color-text);
    margin: 0 0 0.25rem 0;
  }
  .section-divider code {
    font-size: 0.75rem;
    padding: 0.0625rem 0.25rem;
    background: var(--color-bg-input);
    border-radius: 0.1875rem;
  }
  .section-hint {
    font-size: 0.75rem;
    color: var(--color-text-muted);
    margin: 0 0 1rem 0;
  }

  .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }

  .hint { font-weight: 400; color: var(--color-text-muted); font-size: 0.75rem; }

  .imported-badge {
    display: inline-block;
    padding: 0.0625rem 0.375rem;
    border-radius: 9999px;
    font-size: 0.625rem;
    font-weight: 600;
    text-transform: uppercase;
    background: rgba(59, 130, 246, 0.15);
    color: var(--color-primary);
    margin-left: 0.375rem;
    vertical-align: middle;
  }
</style>
