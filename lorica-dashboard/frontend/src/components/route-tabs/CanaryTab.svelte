<script lang="ts">
  import type { RouteFormState, TrafficSplitFormState } from '../../lib/route-form';
  import type { BackendResponse } from '../../lib/api';
  import BackendCheckboxList from '../BackendCheckboxList.svelte';

  interface Props {
    form: RouteFormState;
    backends: BackendResponse[];
    importedFields?: Set<string>;
  }

  let { form = $bindable(), backends, importedFields }: Props = $props();

  let expandedIndex: number | null = $state(null);

  function newSplit(): TrafficSplitFormState {
    return { name: '', weight_percent: 0, backend_ids: [] };
  }

  function addSplit() {
    form.traffic_splits = [...form.traffic_splits, newSplit()];
    expandedIndex = form.traffic_splits.length - 1;
  }

  // Two-click inline confirm - see HeaderRulesTab for the pattern.
  let pendingRemoveIndex: number | null = $state(null);
  let pendingRemoveTimer: ReturnType<typeof setTimeout> | null = null;

  function requestRemoveSplit(index: number) {
    if (pendingRemoveIndex === index) {
      if (pendingRemoveTimer) clearTimeout(pendingRemoveTimer);
      pendingRemoveTimer = null;
      pendingRemoveIndex = null;
      form.traffic_splits = form.traffic_splits.filter((_, i) => i !== index);
      if (expandedIndex === index) expandedIndex = null;
      else if (expandedIndex != null && expandedIndex > index) expandedIndex--;
      return;
    }
    pendingRemoveIndex = index;
    if (pendingRemoveTimer) clearTimeout(pendingRemoveTimer);
    pendingRemoveTimer = setTimeout(() => {
      pendingRemoveIndex = null;
      pendingRemoveTimer = null;
    }, 3_000);
  }

  function moveUp(index: number) {
    if (index <= 0) return;
    const s = [...form.traffic_splits];
    [s[index - 1], s[index]] = [s[index], s[index - 1]];
    form.traffic_splits = s;
    if (expandedIndex === index) expandedIndex = index - 1;
    else if (expandedIndex === index - 1) expandedIndex = index;
  }

  function moveDown(index: number) {
    if (index >= form.traffic_splits.length - 1) return;
    const s = [...form.traffic_splits];
    [s[index], s[index + 1]] = [s[index + 1], s[index]];
    form.traffic_splits = s;
    if (expandedIndex === index) expandedIndex = index + 1;
    else if (expandedIndex === index + 1) expandedIndex = index;
  }

  function toggleExpand(index: number) {
    expandedIndex = expandedIndex === index ? null : index;
  }

  function toggleBackend(split: TrafficSplitFormState, id: string) {
    if (split.backend_ids.includes(id)) {
      split.backend_ids = split.backend_ids.filter((b) => b !== id);
    } else {
      split.backend_ids = [...split.backend_ids, id];
    }
    form.traffic_splits = [...form.traffic_splits];
  }

  function isImported(field: string): boolean {
    return importedFields?.has(field) ?? false;
  }

  let totalWeight = $derived(
    form.traffic_splits.reduce((sum, s) => sum + (Number(s.weight_percent) || 0), 0),
  );
  let defaultWeight = $derived(Math.max(0, 100 - totalWeight));
</script>

<div class="tab-content">
  <div class="top-bar">
    <button class="btn btn-add" onclick={addSplit}>+ Add traffic split</button>
    {#if isImported('traffic_splits')}<span class="imported-badge">imported</span>{/if}
  </div>

  <div class="intro">
    Divert a percentage of traffic to alternate backend groups. Assignment is
    sticky by client IP (per-route), so the same user stays on the same
    version across requests. Header rules always win over splits; path rules
    still override after splits. Cumulative weight must not exceed 100%.
  </div>

  {#if form.traffic_splits.length === 0}
    <div class="empty-state">
      No traffic splits configured. Add one to dedicate a bucket of users to
      a canary deployment.
    </div>
  {:else}
    <div class="weight-summary" class:over={totalWeight > 100}>
      <span>Total allocated: <strong>{totalWeight}%</strong></span>
      <span class="dot"></span>
      <span>Default backends: <strong>{defaultWeight}%</strong></span>
      {#if totalWeight > 100}
        <span class="warn">(&gt; 100% - the last splits will be clamped)</span>
      {/if}
    </div>

    {#each form.traffic_splits as split, index (index)}
      <div class="rule-card">
        <div class="rule-header">
          <div class="rule-header-left">
            <label class="sr-only" for="canary-name-{index}">Traffic split name</label>
            <input
              id="canary-name-{index}"
              type="text"
              class="name-input"
              bind:value={split.name}
              placeholder="e.g. v2-canary"
              onchange={() => { form.traffic_splits = [...form.traffic_splits]; }}
            />
            <div class="weight-field">
              <label class="sr-only" for="canary-weight-{index}">Weight percent</label>
              <input
                id="canary-weight-{index}"
                type="number"
                min="0"
                max="100"
                bind:value={split.weight_percent}
                onchange={() => { form.traffic_splits = [...form.traffic_splits]; }}
              />
              <span aria-hidden="true">%</span>
            </div>
          </div>
          <div class="rule-overrides-summary">
            {#if split.backend_ids.length > 0}
              <span class="override-pill">{split.backend_ids.length} backend{split.backend_ids.length === 1 ? '' : 's'}</span>
            {:else}
              <span class="override-pill warn">no backends</span>
            {/if}
          </div>
          <div class="rule-header-right">
            <!-- eslint-disable-next-line svelte/no-at-html-tags -->
            <button class="btn-icon" title="Move up" aria-label="Move up" disabled={index === 0} onclick={() => moveUp(index)}>{@html upIcon}</button>
            <!-- eslint-disable-next-line svelte/no-at-html-tags -->
            <button class="btn-icon" title="Move down" aria-label="Move down" disabled={index === form.traffic_splits.length - 1} onclick={() => moveDown(index)}>{@html downIcon}</button>
            <!-- eslint-disable-next-line svelte/no-at-html-tags -->
            <button class="btn-icon btn-expand" title={expandedIndex === index ? 'Collapse' : 'Expand'} aria-label={expandedIndex === index ? 'Collapse' : 'Expand'} onclick={() => toggleExpand(index)}>{@html expandedIndex === index ? collapseIcon : expandIcon}</button>
            {#if pendingRemoveIndex === index}
              <button class="btn-icon btn-delete btn-delete-confirm" title="Click again within 3 s to remove" aria-label="Confirm remove" onclick={() => requestRemoveSplit(index)}>Confirm?</button>
            {:else}
              <!-- eslint-disable-next-line svelte/no-at-html-tags -->
              <button class="btn-icon btn-delete" title="Remove" aria-label="Remove" onclick={() => requestRemoveSplit(index)}>{@html deleteIcon}</button>
            {/if}
          </div>
        </div>

        {#if expandedIndex === index}
          <div class="rule-body">
            <div class="override-section">
              <span class="override-title">Backends for this split</span>
              <BackendCheckboxList
                {backends}
                selected={split.backend_ids}
                onToggle={(id) => toggleBackend(split, id)}
                showHealth={false}
              />
            </div>
          </div>
        {/if}
      </div>
    {/each}
  {/if}
</div>

<script lang="ts" module>
  const upIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="18 15 12 9 6 15"/></svg>';
  const downIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>';
  const deleteIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
  const expandIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>';
  const collapseIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/></svg>';
</script>

<style>
  .tab-content { display: flex; flex-direction: column; gap: 0; }
  .top-bar { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem; }
  .intro { font-size: 0.8125rem; color: var(--color-text-muted); margin-bottom: 1rem; line-height: 1.4; }
  .btn-add { padding: 0.375rem 0.75rem; border: 1px solid var(--color-primary); border-radius: 0.375rem; background: transparent; color: var(--color-primary); font-size: 0.8125rem; font-weight: 500; cursor: pointer; transition: background-color 0.15s; }
  .btn-add:hover { background: rgba(59, 130, 246, 0.1); }

  .empty-state { padding: 1.5rem; text-align: center; color: var(--color-text-muted); font-size: 0.8125rem; background: var(--color-bg-input); border: 1px dashed var(--color-border); border-radius: 0.375rem; }

  .weight-summary {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    background: var(--color-bg-input);
    font-size: 0.8125rem;
    margin-bottom: 0.75rem;
  }
  .weight-summary.over { border-color: var(--color-danger); }
  .weight-summary .dot { width: 4px; height: 4px; border-radius: 50%; background: var(--color-text-muted); }
  .weight-summary .warn { color: var(--color-danger); }

  .rule-card { border: 1px solid var(--color-border); border-radius: 0.375rem; margin-bottom: 0.5rem; background: var(--color-bg-input); }
  .rule-header { display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 0.75rem; }
  .rule-header-left { display: flex; align-items: center; gap: 0.5rem; flex: 1; min-width: 0; }

  .name-input { flex: 1; min-width: 6rem; padding: 0.375rem 0.5rem; border: 1px solid var(--color-border); border-radius: 0.25rem; background: var(--color-bg); color: var(--color-text); font-size: 0.8125rem; }

  .weight-field { display: flex; align-items: center; gap: 0.25rem; }
  .weight-field input { width: 4.5rem; padding: 0.375rem 0.5rem; border: 1px solid var(--color-border); border-radius: 0.25rem; background: var(--color-bg); color: var(--color-text); font-size: 0.8125rem; }

  .rule-overrides-summary { display: flex; gap: 0.25rem; flex-wrap: wrap; min-width: 0; }
  .override-pill { padding: 0.125rem 0.375rem; border-radius: 9999px; background: rgba(59, 130, 246, 0.15); color: var(--color-primary); font-size: 0.6875rem; font-weight: 500; white-space: nowrap; }
  .override-pill.warn { background: rgba(239, 68, 68, 0.15); color: var(--color-danger); }

  .rule-header-right { display: flex; gap: 0.25rem; }
  .btn-icon { padding: 0.25rem; border: none; background: transparent; color: var(--color-text-muted); cursor: pointer; border-radius: 0.25rem; display: flex; align-items: center; justify-content: center; }
  .btn-icon:hover:not(:disabled) { background: rgba(255, 255, 255, 0.05); color: var(--color-text); }
  .btn-icon:disabled { opacity: 0.3; cursor: not-allowed; }
  .btn-icon.btn-delete:hover { color: var(--color-danger); }
  .btn-delete-confirm { width: auto; padding: 0 0.5rem; font-size: 0.6875rem; font-weight: 600; color: white; background: var(--color-danger, #dc2626); border-radius: 0.25rem; animation: pulse-arm 1s ease-in-out infinite; }
  @keyframes pulse-arm { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }

  .rule-body { padding: 0.75rem; border-top: 1px solid var(--color-border); display: flex; flex-direction: column; gap: 0.75rem; }
  .override-section { padding: 0.5rem; background: var(--color-bg); border-radius: 0.25rem; }
  .override-title { display: block; font-size: 0.75rem; font-weight: 600; color: var(--color-text-muted); margin-bottom: 0.375rem; text-transform: uppercase; letter-spacing: 0.05em; }

  .checkbox-list { display: flex; flex-direction: column; gap: 0.25rem; max-height: 12rem; overflow-y: auto; }
  .checkbox-item { display: flex; align-items: center; gap: 0.5rem; font-size: 0.8125rem; cursor: pointer; padding: 0.25rem 0; }
  .checkbox-item input[type="checkbox"] { accent-color: var(--color-primary); }

  .text-muted { color: var(--color-text-muted); }
  .small { font-size: 0.75rem; }
  .imported-badge { display: inline-block; padding: 0.0625rem 0.375rem; border-radius: 9999px; font-size: 0.625rem; font-weight: 600; text-transform: uppercase; background: rgba(59, 130, 246, 0.15); color: var(--color-primary); vertical-align: middle; }
</style>
