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
  <div class="form-group" class:modified={isModified('cors_allowed_origins')}>
    <label for="cors-origins">Allowed origins <span class="hint">(comma-separated)</span></label>
    {#if isImported('cors_allowed_origins')}<span class="imported-badge">imported</span>{/if}
    <input id="cors-origins" type="text" bind:value={form.cors_allowed_origins} placeholder="https://example.com, https://app.example.com" />
    <span class="hint">Nginx: add_header Access-Control-Allow-Origin | Traefik: Headers middleware accessControlAllowOriginList</span>
  </div>

  <div class="form-row">
    <div class="form-group" class:modified={isModified('cors_allowed_methods')}>
      <label for="cors-methods">Allowed methods <span class="hint">(comma-separated)</span></label>
      {#if isImported('cors_allowed_methods')}<span class="imported-badge">imported</span>{/if}
      <input id="cors-methods" type="text" bind:value={form.cors_allowed_methods} placeholder="GET, POST, PUT, DELETE" />
    </div>
    <div class="form-group" class:modified={isModified('cors_max_age_s')}>
      <label for="cors-max-age">Max age (s)</label>
      {#if isImported('cors_max_age_s')}<span class="imported-badge">imported</span>{/if}
      <input id="cors-max-age" type="number" min="0" bind:value={form.cors_max_age_s} placeholder="No limit" />
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
