<script lang="ts">
  import type { RouteFormState } from '../../lib/route-form';
  import type { BackendResponse } from '../../lib/api';
  import BackendCheckboxList from '../BackendCheckboxList.svelte';

  interface Props {
    form: RouteFormState;
    backends: BackendResponse[];
  }

  let { form = $bindable(), backends }: Props = $props();

  function toggleMirrorBackend(id: string) {
    if (form.mirror_backend_ids.includes(id)) {
      form.mirror_backend_ids = form.mirror_backend_ids.filter((b) => b !== id);
    } else {
      form.mirror_backend_ids = [...form.mirror_backend_ids, id];
    }
  }
</script>

<div class="mirror-panel">
  <div class="form-group" class:modified={form.mirror_backend_ids.length > 0}>
    <label id="mirror-backends-label">Shadow backends</label>
    <BackendCheckboxList
      {backends}
      selected={form.mirror_backend_ids}
      onToggle={toggleMirrorBackend}
      showHealth={false}
      ariaLabelledBy="mirror-backends-label"
    />
    <span class="hint">Leave empty to disable mirroring.</span>
    {#if form.mirror_backend_ids.length > 0}
      <div class="mirror-summary" aria-live="polite">
        <strong>{form.mirror_backend_ids.length}</strong> shadow backend{form.mirror_backend_ids.length === 1 ? '' : 's'}
        <span class="sep" aria-hidden="true">·</span>
        sampling <strong>{form.mirror_sample_percent}%</strong>
        <span class="sep" aria-hidden="true">·</span>
        {form.mirror_max_body_bytes === 0
          ? 'headers-only'
          : `max body ${(form.mirror_max_body_bytes / 1048576).toFixed(form.mirror_max_body_bytes >= 1048576 ? 0 : 2)} MiB`}
        <span class="sep" aria-hidden="true">·</span>
        {form.mirror_backend_ids.length * form.mirror_sample_percent / 100} mirror request{(form.mirror_backend_ids.length * form.mirror_sample_percent / 100) === 1 ? '' : 's'} per primary (avg)
      </div>
    {/if}
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
        title={form.mirror_backend_ids.length === 0 ? 'Select at least one shadow backend to enable this option' : ''}
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
        title={form.mirror_backend_ids.length === 0 ? 'Select at least one shadow backend to enable this option' : ''}
      />
      <span class="hint">Slow mirrors are dropped silently; never impacts the primary request.</span>
    </div>
  </div>

  <div class="form-group" class:modified={form.mirror_max_body_bytes !== 1048576}>
    <label for="mirror-max-body">Max body bytes</label>
    <input
      id="mirror-max-body"
      type="number"
      min="0"
      max="134217728"
      bind:value={form.mirror_max_body_bytes}
      disabled={form.mirror_backend_ids.length === 0}
      title={form.mirror_backend_ids.length === 0 ? 'Select at least one shadow backend to enable this option' : ''}
    />
    <span class="hint">
      Max body size buffered for mirror sub-requests. Requests with a body
      larger than this are sent to the primary normally but NOT mirrored
      (a truncated body would mislead the shadow). Default 1 MiB
      (1048576). Set to 0 for headers-only mirroring. Max 128 MiB.
    </span>
  </div>
</div>

<style>
  .mirror-panel { display: flex; flex-direction: column; gap: 0; }

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

  .form-row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
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
  .hint { display: block; font-weight: 400; color: var(--color-text-muted); font-size: 0.75rem; margin-top: 0.25rem; }

  .mirror-summary {
    margin-top: 0.5rem;
    padding: 0.375rem 0.5rem;
    border-radius: 0.25rem;
    background: rgba(59, 130, 246, 0.08);
    color: var(--color-text);
    font-size: 0.75rem;
  }

  .mirror-summary .sep {
    margin: 0 0.25rem;
    color: var(--color-text-muted);
  }
</style>
