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
  <h3 class="section-title">Proxy Headers</h3>
  <div class="form-group" class:modified={isModified('proxy_headers')}>
    <label for="proxy-headers">Custom proxy headers <span class="hint">(key=value, one per line)</span></label>
    {#if isImported('proxy_headers')}<span class="imported-badge">imported</span>{/if}
    <textarea id="proxy-headers" rows="4" bind:value={form.proxy_headers} placeholder="X-Forwarded-For=$remote_addr&#10;X-Custom=value"></textarea>
    <span class="hint">Nginx: proxy_set_header | Traefik: Headers middleware customRequestHeaders</span>
  </div>
  <div class="form-group" class:modified={isModified('proxy_headers_remove')}>
    <label for="proxy-headers-remove">Remove proxy headers <span class="hint">(comma-separated)</span></label>
    {#if isImported('proxy_headers_remove')}<span class="imported-badge">imported</span>{/if}
    <input id="proxy-headers-remove" type="text" bind:value={form.proxy_headers_remove} placeholder="X-Powered-By, Server" />
  </div>

  <h3 class="section-title">Response Headers</h3>
  <div class="form-group" class:modified={isModified('response_headers')}>
    <label for="response-headers">Custom response headers <span class="hint">(key=value, one per line)</span></label>
    {#if isImported('response_headers')}<span class="imported-badge">imported</span>{/if}
    <textarea id="response-headers" rows="4" bind:value={form.response_headers} placeholder="X-Frame-Options=DENY&#10;Cache-Control=no-store"></textarea>
    <span class="hint">Nginx: add_header | Traefik: Headers middleware customResponseHeaders</span>
  </div>
  <div class="form-group" class:modified={isModified('response_headers_remove')}>
    <label for="response-headers-remove">Remove response headers <span class="hint">(comma-separated)</span></label>
    {#if isImported('response_headers_remove')}<span class="imported-badge">imported</span>{/if}
    <input id="response-headers-remove" type="text" bind:value={form.response_headers_remove} placeholder="X-Powered-By, Server" />
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

  .form-group input[type="text"] {
    width: 100%;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    color: var(--color-text);
    font-size: 0.875rem;
  }

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
