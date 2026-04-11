<script lang="ts">
  import type { RouteFormState } from '../../lib/route-form';
  import { ROUTE_DEFAULTS } from '../../lib/route-form';

  import type { SecurityHeaderPreset } from '../../lib/api';

  interface Props {
    form: RouteFormState;
    importedFields?: Set<string>;
    customPresets?: SecurityHeaderPreset[];
  }

  let { form = $bindable(), importedFields, customPresets = [] }: Props = $props();

  function isModified(field: keyof RouteFormState): boolean {
    return ROUTE_DEFAULTS[field] !== form[field];
  }

  function isImported(field: string): boolean {
    return importedFields?.has(field) ?? false;
  }
</script>

<div class="tab-content">
  <div class="form-group" class:modified={isModified('security_headers')}>
    <label for="security-headers">Security headers preset</label>
    {#if isImported('security_headers')}<span class="imported-badge">imported</span>{/if}
    <select id="security-headers" bind:value={form.security_headers}>
      <option value="strict">Strict</option>
      <option value="moderate">Moderate</option>
      <option value="none">None</option>
      {#each customPresets as preset}
        <option value={preset.name}>{preset.name} (custom)</option>
      {/each}
    </select>
    <span class="hint">Nginx: add_header Strict-Transport-Security... | Traefik: Headers middleware</span>
  </div>

  <div class="form-row form-row-3">
    <div class="form-group" class:modified={isModified('max_body_mb')}>
      <label for="max-body">Max body (MB)</label>
      {#if isImported('max_body_mb')}<span class="imported-badge">imported</span>{/if}
      <input id="max-body" type="number" min="0" step="1" bind:value={form.max_body_mb} placeholder="No limit" />
      <span class="hint">Nginx: client_max_body_size | Traefik: Buffering maxRequestBodyBytes</span>
    </div>
    <div class="form-group" class:modified={isModified('rate_limit_rps')}>
      <label for="rate-rps">Rate limit RPS</label>
      {#if isImported('rate_limit_rps')}<span class="imported-badge">imported</span>{/if}
      <input id="rate-rps" type="number" min="1" bind:value={form.rate_limit_rps} placeholder="No limit" />
      <span class="hint">Nginx: limit_req zone rate=Xr/s | Traefik: RateLimit middleware</span>
    </div>
    <div class="form-group" class:modified={isModified('rate_limit_burst')}>
      <label for="rate-burst">Rate limit burst</label>
      {#if isImported('rate_limit_burst')}<span class="imported-badge">imported</span>{/if}
      <input id="rate-burst" type="number" min="1" bind:value={form.rate_limit_burst} placeholder="No limit" />
    </div>
  </div>

  <div class="form-row">
    <div class="form-group" class:modified={isModified('ip_allowlist')}>
      <label for="ip-allow">IP allowlist <span class="hint">(one per line)</span></label>
      {#if isImported('ip_allowlist')}<span class="imported-badge">imported</span>{/if}
      <textarea id="ip-allow" rows="3" bind:value={form.ip_allowlist} placeholder="192.168.1.0/24&#10;10.0.0.1"></textarea>
    </div>
    <div class="form-group" class:modified={isModified('ip_denylist')}>
      <label for="ip-deny">IP denylist <span class="hint">(one per line)</span></label>
      {#if isImported('ip_denylist')}<span class="imported-badge">imported</span>{/if}
      <textarea id="ip-deny" rows="3" bind:value={form.ip_denylist} placeholder="203.0.113.0/24"></textarea>
    </div>
  </div>

  <div class="form-row">
    <div class="form-group" class:modified={isModified('basic_auth_username')}>
      <label for="basic-auth-user">Basic auth username</label>
      <input id="basic-auth-user" type="text" bind:value={form.basic_auth_username} placeholder="Leave empty to disable" />
      <span class="hint">HTTP Basic Auth for staging or internal tools. Nginx: auth_basic | Traefik: BasicAuth middleware</span>
    </div>
    <div class="form-group" class:modified={isModified('basic_auth_password')}>
      <label for="basic-auth-pass">Basic auth password</label>
      <input id="basic-auth-pass" type="password" bind:value={form.basic_auth_password} placeholder={form.basic_auth_username ? '(unchanged)' : 'Leave empty to disable'} />
      <span class="hint">Password is hashed (Argon2id) before storage. Send a new value to change it.</span>
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

  .form-group select,
  .form-group input[type="number"],
  .form-group input[type="text"],
  .form-group input[type="password"] {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
  }

  .form-group select:focus,
  .form-group input:focus { outline: none; border-color: var(--color-primary); }

  .form-group textarea {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
    font-family: var(--mono);
    resize: vertical;
  }

  .form-group textarea:focus { outline: none; border-color: var(--color-primary); }

  .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
  .form-row-3 { grid-template-columns: 1fr 1fr 1fr; }

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
