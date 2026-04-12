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
  <div class="form-group" class:modified={isModified('cache_enabled')}>
    <label class="checkbox-item">
      <input type="checkbox" bind:checked={form.cache_enabled} />
      <span>Enable cache</span>
    </label>
    {#if isImported('cache_enabled')}<span class="imported-badge">imported</span>{/if}
    <span class="hint">Nginx: proxy_cache | Traefik: no built-in (plugin needed)</span>
  </div>

  <div class="form-row">
    <div class="form-group" class:modified={isModified('cache_ttl_s')}>
      <label for="cache-ttl">Cache TTL (s)</label>
      {#if isImported('cache_ttl_s')}<span class="imported-badge">imported</span>{/if}
      <input id="cache-ttl" type="number" min="1" bind:value={form.cache_ttl_s} placeholder="300" />
    </div>
    <div class="form-group" class:modified={isModified('cache_max_mb')}>
      <label for="cache-max-mb">Cache max size (MB)</label>
      {#if isImported('cache_max_mb')}<span class="imported-badge">imported</span>{/if}
      <input id="cache-max-mb" type="number" min="1" bind:value={form.cache_max_mb} placeholder="50" />
    </div>
  </div>

  <div class="form-row">
    <div class="form-group" class:modified={isModified('stale_while_revalidate_s')}>
      <label for="stale-revalidate">Stale-while-revalidate (s)</label>
      <input id="stale-revalidate" type="number" min="0" bind:value={form.stale_while_revalidate_s} placeholder="10" />
      <span class="hint">Serve stale cached content while refreshing in the background. 0 = disabled.</span>
    </div>
    <div class="form-group" class:modified={isModified('stale_if_error_s')}>
      <label for="stale-error">Stale-if-error (s)</label>
      <input id="stale-error" type="number" min="0" bind:value={form.stale_if_error_s} placeholder="60" />
      <span class="hint">Serve stale cached content when upstream returns an error. 0 = disabled.</span>
    </div>
  </div>

  <div class="form-group" class:modified={isModified('cache_vary_headers')}>
    <label for="cache-vary">Vary headers</label>
    <input id="cache-vary" type="text" bind:value={form.cache_vary_headers} placeholder="Accept-Encoding, Accept-Language" />
    <span class="hint">Comma-separated request header names. Each header value partitions the cache so different clients (gzip vs identity, en vs fr) get separate entries. Merged with the origin's Vary response header.</span>
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

  .form-group input[type="number"],
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

  .checkbox-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8125rem;
    cursor: pointer;
  }

  .checkbox-item input[type="checkbox"] { accent-color: var(--color-primary); }

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
