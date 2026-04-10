<script lang="ts">
  import type { RouteFormState } from '../../lib/route-form';
  import type { BackendResponse, CertificateResponse } from '../../lib/api';
  import { ROUTE_DEFAULTS, validateHostname } from '../../lib/route-form';
  import StatusBadge from '../StatusBadge.svelte';

  interface Props {
    form: RouteFormState;
    backends: BackendResponse[];
    certificates: CertificateResponse[];
    editing: boolean;
    importedFields?: Set<string>;
  }

  let { form = $bindable(), backends, certificates, editing, importedFields }: Props = $props();

  let hostnameError = $state('');

  const loadBalancingOptions = [
    { value: 'round_robin', label: 'Weighted Round Robin' },
    { value: 'consistent_hash', label: 'Consistent Hash' },
    { value: 'random', label: 'Random' },
    { value: 'peak_ewma', label: 'Peak EWMA' },
  ];

  function handleHostnameBlur() {
    hostnameError = validateHostname(form.hostname);
  }

  function toggleBackend(id: string) {
    if (form.backend_ids.includes(id)) {
      form.backend_ids = form.backend_ids.filter((b) => b !== id);
    } else {
      form.backend_ids = [...form.backend_ids, id];
    }
  }

  function isModified(field: keyof RouteFormState): boolean {
    const def = ROUTE_DEFAULTS[field];
    const cur = form[field];
    if (Array.isArray(def) && Array.isArray(cur)) {
      return def.length !== cur.length || def.some((v, i) => v !== cur[i]);
    }
    return def !== cur;
  }

  function isImported(field: string): boolean {
    return importedFields?.has(field) ?? false;
  }
</script>

<div class="tab-content">
  <div class="form-group" class:modified={isModified('hostname')}>
    <label for="hostname">Hostname <span class="required">*</span></label>
    {#if isImported('hostname')}<span class="imported-badge">imported</span>{/if}
    <input id="hostname" type="text" bind:value={form.hostname} placeholder="example.com" onblur={handleHostnameBlur} />
    {#if hostnameError}
      <span class="field-error">{hostnameError}</span>
    {/if}
  </div>

  <div class="form-group" class:modified={isModified('path_prefix')}>
    <label for="path">Path prefix</label>
    {#if isImported('path_prefix')}<span class="imported-badge">imported</span>{/if}
    <input id="path" type="text" bind:value={form.path_prefix} placeholder="/" />
  </div>

  <div class="form-group">
    <span class="field-label">Backends</span>
    {#if isImported('backend_ids')}<span class="imported-badge">imported</span>{/if}
    {#if backends.length === 0}
      <p class="text-muted small">No backends available</p>
    {:else}
      <div class="checkbox-list">
        {#each backends as b (b.id)}
          <label class="checkbox-item">
            <input type="checkbox" checked={form.backend_ids.includes(b.id)} onchange={() => toggleBackend(b.id)} />
            <span>{b.name ? `${b.name} (${b.address})` : b.address}</span>
            <StatusBadge status={b.health_status === 'healthy' ? 'healthy' : b.health_status === 'degraded' ? 'degraded' : b.health_status === 'down' ? 'down' : 'unknown'} />
          </label>
        {/each}
      </div>
    {/if}
  </div>

  <div class="form-group" class:modified={isModified('certificate_id')}>
    <label for="certificate">TLS Certificate</label>
    {#if isImported('certificate_id')}<span class="imported-badge">imported</span>{/if}
    <select id="certificate" bind:value={form.certificate_id} onchange={() => { if (!form.certificate_id) form.force_https = false; }}>
      <option value="">None (no TLS)</option>
      {#each certificates as c (c.id)}
        <option value={c.id}>{c.domain}</option>
      {/each}
    </select>
  </div>

  <div class="form-group" class:modified={isModified('load_balancing')}>
    <label for="lb">Load Balancing</label>
    {#if isImported('load_balancing')}<span class="imported-badge">imported</span>{/if}
    <select id="lb" bind:value={form.load_balancing}>
      {#each loadBalancingOptions as opt}
        <option value={opt.value}>{opt.label}</option>
      {/each}
    </select>
  </div>

  <div class="form-group" class:modified={isModified('waf_enabled')}>
    <label class="checkbox-item">
      <input type="checkbox" bind:checked={form.waf_enabled} />
      <span>Enable WAF</span>
    </label>
    {#if isImported('waf_enabled')}<span class="imported-badge">imported</span>{/if}
  </div>

  {#if form.waf_enabled}
    <div class="form-group" class:modified={isModified('waf_mode')}>
      <label for="waf-mode">WAF Mode</label>
      {#if isImported('waf_mode')}<span class="imported-badge">imported</span>{/if}
      <select id="waf-mode" bind:value={form.waf_mode}>
        <option value="detection">Detection (log only)</option>
        <option value="blocking">Blocking (reject 403)</option>
      </select>
    </div>
  {/if}

  {#if editing}
    <div class="form-group" class:modified={isModified('enabled')}>
      <label class="checkbox-item">
        <input type="checkbox" bind:checked={form.enabled} />
        <span>Route enabled</span>
      </label>
    </div>
  {/if}

  <div class="form-group" class:modified={isModified('force_https')}>
    <label class="checkbox-item">
      <input type="checkbox" bind:checked={form.force_https} disabled={!form.certificate_id} />
      <span>Force HTTPS redirect</span>
    </label>
    {#if !form.certificate_id}<span class="hint">Requires a certificate to be selected.</span>{/if}
    {#if isImported('force_https')}<span class="imported-badge">imported</span>{/if}
    {#if importedFields && importedFields.size > 0}<span class="hint">Nginx: return 301 https://... | Traefik: RedirectScheme middleware</span>{/if}
  </div>

  <div class="form-group" class:modified={isModified('redirect_to')}>
    <label for="redirect-to">Redirect to</label>
    {#if isImported('redirect_to')}<span class="imported-badge">imported</span>{/if}
    <input id="redirect-to" type="text" bind:value={form.redirect_to} placeholder="https://example.com" />
    <span class="hint">If set, responds with 301 redirect instead of proxying. Original path is appended.</span>
    {#if form.redirect_to}
      <span class="hint" style="color: var(--color-orange, #f59e0b);">Backends will not be used - all requests will be redirected.</span>
    {/if}
  </div>

  <div class="form-group" class:modified={isModified('return_status')}>
    <label for="return-status">Return status</label>
    {#if isImported('return_status')}<span class="imported-badge">imported</span>{/if}
    <input id="return-status" type="number" min="100" max="599" bind:value={form.return_status} placeholder="e.g. 403, 404" />
    <span class="hint">If set, responds with this HTTP status instead of proxying. Combine with Redirect to for 301/302.</span>
  </div>

  <div class="form-group" class:modified={isModified('redirect_hostname')}>
    <label for="redirect-hostname">Redirect hostname</label>
    {#if isImported('redirect_hostname')}<span class="imported-badge">imported</span>{/if}
    <input id="redirect-hostname" type="text" bind:value={form.redirect_hostname} placeholder="e.g. www.example.com" />
    {#if importedFields && importedFields.size > 0}<span class="hint">Nginx: server_name www.x.com; return 301 https://x.com... | Traefik: RedirectRegex</span>{/if}
  </div>

  <div class="form-group" class:modified={isModified('hostname_aliases')}>
    <label for="hostname-aliases">Hostname aliases <span class="hint">(comma-separated)</span></label>
    {#if isImported('hostname_aliases')}<span class="imported-badge">imported</span>{/if}
    <input id="hostname-aliases" type="text" bind:value={form.hostname_aliases} placeholder="alias1.com, alias2.com" />
    {#if importedFields && importedFields.size > 0}<span class="hint">Nginx: server_name x.com www.x.com | Traefik: Host rule with OR</span>{/if}
  </div>

  <div class="form-group" class:modified={isModified('websocket_enabled')}>
    <label class="checkbox-item">
      <input type="checkbox" bind:checked={form.websocket_enabled} />
      <span>WebSocket support</span>
    </label>
    {#if isImported('websocket_enabled')}<span class="imported-badge">imported</span>{/if}
  </div>

  <div class="form-group" class:modified={isModified('access_log_enabled')}>
    <label class="checkbox-item">
      <input type="checkbox" bind:checked={form.access_log_enabled} />
      <span>Access log enabled</span>
    </label>
    {#if isImported('access_log_enabled')}<span class="imported-badge">imported</span>{/if}
  </div>

  <div class="form-group" class:modified={isModified('compression_enabled')}>
    <label class="checkbox-item">
      <input type="checkbox" bind:checked={form.compression_enabled} />
      <span>Enable compression</span>
    </label>
    {#if isImported('compression_enabled')}<span class="imported-badge">imported</span>{/if}
  </div>

  <div class="form-group" class:modified={isModified('sticky_session')}>
    <label class="checkbox-item">
      <input type="checkbox" bind:checked={form.sticky_session} />
      <span>Sticky sessions</span>
    </label>
    <span class="hint">Routes returning clients to the same backend via a cookie (LORICA_SRV). Useful for stateful applications.</span>
  </div>
</div>

<style>
  .tab-content { display: flex; flex-direction: column; gap: 0; }

  .form-group { margin-bottom: 1rem; }
  .form-group.modified { border-left: 3px solid var(--color-primary); padding-left: 0.75rem; }

  .form-group label,
  .form-group .field-label {
    display: block;
    font-size: 0.8125rem;
    font-weight: 500;
    color: var(--color-text-muted);
    margin-bottom: 0.375rem;
  }

  .required { color: var(--color-red); }
  .field-error { display: block; color: var(--color-red); font-size: var(--text-xs); margin-top: 0.25rem; }

  .form-group input[type="text"],
  .form-group input[type="number"],
  .form-group select {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
  }

  .form-group input[type="text"]:focus,
  .form-group input[type="number"]:focus,
  .form-group select:focus {
    outline: none;
    border-color: var(--color-primary);
  }

  .checkbox-list {
    display: flex;
    flex-direction: column;
    gap: 0.375rem;
    max-height: 150px;
    overflow-y: auto;
    padding: 0.5rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
  }

  .checkbox-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8125rem;
    cursor: pointer;
  }

  .checkbox-item input[type="checkbox"] { accent-color: var(--color-primary); }

  .text-muted { color: var(--color-text-muted); }
  .small { font-size: 0.8125rem; }
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
