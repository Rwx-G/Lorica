<script lang="ts">
  import type { RouteFormState } from '../../lib/route-form';
  import { ROUTE_DEFAULTS } from '../../lib/route-form';

  import type { SecurityHeaderPreset, BackendResponse } from '../../lib/api';

  interface Props {
    form: RouteFormState;
    importedFields?: Set<string>;
    customPresets?: SecurityHeaderPreset[];
    backends?: BackendResponse[];
  }

  let { form = $bindable(), importedFields, customPresets = [], backends = [] }: Props = $props();

  function toggleMirrorBackend(id: string) {
    if (form.mirror_backend_ids.includes(id)) {
      form.mirror_backend_ids = form.mirror_backend_ids.filter((b) => b !== id);
    } else {
      form.mirror_backend_ids = [...form.mirror_backend_ids, id];
    }
  }

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

  <h3 class="subsection-title">Forward authentication</h3>
  <p class="subsection-hint">
    Before proxying to the upstream, issue a GET sub-request to an external
    auth service (Authelia, Authentik, Keycloak, oauth2-proxy). 2xx = allow,
    401/403/3xx = forwarded verbatim to the client (so Authelia's login
    redirect works), other = fail closed 503.
  </p>

  <div class="form-group" class:modified={form.forward_auth_address !== ''}>
    <label for="fa-address">Auth service URL</label>
    <input
      id="fa-address"
      type="text"
      bind:value={form.forward_auth_address}
      placeholder="http://authelia.internal:9091/api/verify"
    />
    <span class="hint">Empty = feature disabled. Must be an absolute http(s):// URL.</span>
  </div>

  <div class="form-row">
    <div class="form-group" class:modified={form.forward_auth_timeout_ms !== 5000}>
      <label for="fa-timeout">Timeout (ms)</label>
      <input
        id="fa-timeout"
        type="number"
        min="1"
        max="60000"
        bind:value={form.forward_auth_timeout_ms}
        disabled={!form.forward_auth_address}
      />
      <span class="hint">Per-request total timeout. 1..60000 ms. Default 5000.</span>
    </div>
    <div class="form-group" class:modified={form.forward_auth_response_headers !== ''}>
      <label for="fa-response-headers">Response headers to inject</label>
      <input
        id="fa-response-headers"
        type="text"
        bind:value={form.forward_auth_response_headers}
        placeholder="Remote-User, Remote-Groups, Remote-Email"
        disabled={!form.forward_auth_address}
      />
      <span class="hint">Comma-separated; copied from the auth response into the upstream request on 2xx only.</span>
    </div>
  </div>

  <h3 class="subsection-title">Request mirroring (shadow testing)</h3>
  <p class="subsection-hint">
    Fire-and-forget shadow copies of every request to alternate backends.
    Mirror responses are discarded. Shadow backends receive
    <code>X-Lorica-Mirror: 1</code> so they can filter this traffic out of
    their normal analytics. v1 mirrors headers + method + URL only, not
    the request body.
  </p>

  <div class="form-group" class:modified={form.mirror_backend_ids.length > 0}>
    <label>Shadow backends</label>
    {#if backends.length === 0}
      <p class="text-muted small">No backends available.</p>
    {:else}
      <div class="checkbox-list">
        {#each backends as b (b.id)}
          <label class="checkbox-item">
            <input type="checkbox" checked={form.mirror_backend_ids.includes(b.id)} onchange={() => toggleMirrorBackend(b.id)} />
            <span>{b.name ? `${b.name} (${b.address})` : b.address}</span>
          </label>
        {/each}
      </div>
    {/if}
    <span class="hint">Leave empty to disable mirroring.</span>
  </div>

  <div class="form-row">
    <div class="form-group" class:modified={form.mirror_sample_percent !== 100}>
      <label for="mirror-sample">Sample percent</label>
      <input
        id="mirror-sample"
        type="number"
        min="0"
        max="100"
        bind:value={form.mirror_sample_percent}
        disabled={form.mirror_backend_ids.length === 0}
      />
      <span class="hint">0..100. Sticky per X-Request-Id so retries of the same request stay in or out.</span>
    </div>
    <div class="form-group" class:modified={form.mirror_timeout_ms !== 5000}>
      <label for="mirror-timeout">Timeout (ms)</label>
      <input
        id="mirror-timeout"
        type="number"
        min="1"
        max="60000"
        bind:value={form.mirror_timeout_ms}
        disabled={form.mirror_backend_ids.length === 0}
      />
      <span class="hint">Slow mirrors are dropped silently; never impacts the primary request.</span>
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

  .subsection-title {
    font-size: 0.875rem;
    font-weight: 600;
    color: var(--color-text);
    margin: 1.25rem 0 0.25rem;
    padding-top: 0.75rem;
    border-top: 1px solid var(--color-border);
  }
  .subsection-hint {
    font-size: 0.75rem;
    color: var(--color-text-muted);
    margin: 0 0 0.75rem;
    line-height: 1.4;
  }
  .form-group input:disabled { opacity: 0.5; cursor: not-allowed; }

  .checkbox-list { display: flex; flex-direction: column; gap: 0.25rem; max-height: 10rem; overflow-y: auto; }
  .checkbox-item { display: flex; align-items: center; gap: 0.5rem; font-size: 0.8125rem; cursor: pointer; padding: 0.25rem 0; }
  .checkbox-item input[type="checkbox"] { accent-color: var(--color-primary); }
  .text-muted { color: var(--color-text-muted); }
  .small { font-size: 0.75rem; }
  code { font-family: ui-monospace, monospace; font-size: 0.75rem; background: var(--color-bg-input); padding: 0.05rem 0.25rem; border-radius: 0.25rem; }

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
