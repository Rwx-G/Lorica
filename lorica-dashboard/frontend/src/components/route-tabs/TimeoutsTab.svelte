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
  <h3 class="section-title">Timeouts</h3>
  <div class="form-row form-row-3">
    <div class="form-group" class:modified={isModified('connect_timeout_s')}>
      <label for="connect-timeout">Connect (s)</label>
      {#if isImported('connect_timeout_s')}<span class="imported-badge">imported</span>{/if}
      <input id="connect-timeout" type="number" min="1" max="3600" bind:value={form.connect_timeout_s} />
      <span class="hint">Nginx: proxy_connect_timeout | HAProxy: timeout connect</span>
    </div>
    <div class="form-group" class:modified={isModified('read_timeout_s')}>
      <label for="read-timeout">Read (s)</label>
      {#if isImported('read_timeout_s')}<span class="imported-badge">imported</span>{/if}
      <input id="read-timeout" type="number" min="1" max="3600" bind:value={form.read_timeout_s} />
      <span class="hint">Nginx: proxy_read_timeout | HAProxy: timeout server</span>
    </div>
    <div class="form-group" class:modified={isModified('send_timeout_s')}>
      <label for="send-timeout">Send (s)</label>
      {#if isImported('send_timeout_s')}<span class="imported-badge">imported</span>{/if}
      <input id="send-timeout" type="number" min="1" max="3600" bind:value={form.send_timeout_s} />
      <span class="hint">Nginx: proxy_send_timeout</span>
    </div>
  </div>

  <h3 class="section-title">Path Rewriting</h3>
  <div class="form-row">
    <div class="form-group" class:modified={isModified('strip_path_prefix')}>
      <label for="strip-path">Strip path prefix</label>
      {#if isImported('strip_path_prefix')}<span class="imported-badge">imported</span>{/if}
      <input id="strip-path" type="text" bind:value={form.strip_path_prefix} placeholder="/api/v1" />
      <span class="hint">Nginx: location /api/ {'{'} proxy_pass http://backend/; {'}'} | Traefik: StripPrefix middleware</span>
    </div>
    <div class="form-group" class:modified={isModified('add_path_prefix')}>
      <label for="add-path">Add path prefix</label>
      {#if isImported('add_path_prefix')}<span class="imported-badge">imported</span>{/if}
      <input id="add-path" type="text" bind:value={form.add_path_prefix} placeholder="/backend" />
      <span class="hint">Traefik: AddPrefix middleware</span>
    </div>
  </div>
  <div class="form-row">
    <div class="form-group" class:modified={isModified('path_rewrite_pattern')}>
      <label for="rewrite-pattern">Regex rewrite pattern</label>
      <input id="rewrite-pattern" type="text" bind:value={form.path_rewrite_pattern} placeholder="^/api/v1/(.*)" />
      <span class="hint">Rust regex syntax. Linear time, ReDoS-safe. Applied after strip/add prefix.</span>
    </div>
    <div class="form-group" class:modified={isModified('path_rewrite_replacement')}>
      <label for="rewrite-replacement">Regex rewrite replacement</label>
      <input id="rewrite-replacement" type="text" bind:value={form.path_rewrite_replacement} placeholder="/v2/$1" />
      <span class="hint">Use $1, $2, etc. for capture groups.</span>
    </div>
  </div>

  <h3 class="section-title">Retry</h3>
  <div class="form-group" class:modified={isModified('retry_attempts')}>
    <label for="retry-attempts">Retry attempts</label>
    {#if isImported('retry_attempts')}<span class="imported-badge">imported</span>{/if}
    <input id="retry-attempts" type="number" min="0" bind:value={form.retry_attempts} placeholder="No retry" />
  </div>

  <div class="form-group" class:modified={isModified('retry_on_methods')}>
    <label for="retry-methods">Retry on methods</label>
    <input id="retry-methods" type="text" bind:value={form.retry_on_methods} placeholder="All methods (e.g. GET, HEAD, OPTIONS)" />
    <span class="hint">Comma-separated list of HTTP methods eligible for retry. Empty = all methods.</span>
  </div>
</div>

<style>
  .tab-content { display: flex; flex-direction: column; gap: 0; }

  .section-title {
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--color-text-muted);
    margin: 1rem 0 0.75rem;
    padding-bottom: 0.375rem;
    border-bottom: 1px solid var(--color-border);
  }

  .section-title:first-child { margin-top: 0; }

  .form-group { margin-bottom: 1rem; }
  .form-group.modified { border-left: 3px solid var(--color-primary); padding-left: 0.75rem; }

  .form-group label {
    display: block;
    font-size: 0.8125rem;
    font-weight: 500;
    color: var(--color-text-muted);
    margin-bottom: 0.375rem;
  }

  .form-group input[type="text"],
  .form-group input[type="number"] {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
  }

  .form-group input:focus { outline: none; border-color: var(--color-primary); }

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
