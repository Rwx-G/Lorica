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
