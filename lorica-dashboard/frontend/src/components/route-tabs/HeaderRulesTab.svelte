<script lang="ts">
  import type { RouteFormState, HeaderRuleFormState } from '../../lib/route-form';
  import type { BackendResponse } from '../../lib/api';

  interface Props {
    form: RouteFormState;
    backends: BackendResponse[];
    importedFields?: Set<string>;
  }

  let { form = $bindable(), backends, importedFields }: Props = $props();

  let expandedIndex: number | null = $state(null);

  function newRule(): HeaderRuleFormState {
    return {
      header_name: '',
      match_type: 'exact',
      value: '',
      backend_ids: [],
    };
  }

  function addRule() {
    form.header_rules = [...form.header_rules, newRule()];
    expandedIndex = form.header_rules.length - 1;
  }

  function removeRule(index: number) {
    form.header_rules = form.header_rules.filter((_, i) => i !== index);
    if (expandedIndex === index) expandedIndex = null;
    else if (expandedIndex != null && expandedIndex > index) expandedIndex--;
  }

  function moveUp(index: number) {
    if (index <= 0) return;
    const rules = [...form.header_rules];
    [rules[index - 1], rules[index]] = [rules[index], rules[index - 1]];
    form.header_rules = rules;
    if (expandedIndex === index) expandedIndex = index - 1;
    else if (expandedIndex === index - 1) expandedIndex = index;
  }

  function moveDown(index: number) {
    if (index >= form.header_rules.length - 1) return;
    const rules = [...form.header_rules];
    [rules[index], rules[index + 1]] = [rules[index + 1], rules[index]];
    form.header_rules = rules;
    if (expandedIndex === index) expandedIndex = index + 1;
    else if (expandedIndex === index + 1) expandedIndex = index;
  }

  function toggleExpand(index: number) {
    expandedIndex = expandedIndex === index ? null : index;
  }

  function toggleBackend(rule: HeaderRuleFormState, id: string) {
    if (rule.backend_ids.includes(id)) {
      rule.backend_ids = rule.backend_ids.filter((b) => b !== id);
    } else {
      rule.backend_ids = [...rule.backend_ids, id];
    }
    form.header_rules = [...form.header_rules];
  }

  function isImported(field: string): boolean {
    return importedFields?.has(field) ?? false;
  }

  function ruleSummary(rule: HeaderRuleFormState): string {
    if (!rule.header_name) return '(unnamed)';
    const op = rule.match_type === 'exact' ? '=' : rule.match_type === 'prefix' ? '^=' : '~=';
    return `${rule.header_name} ${op} ${rule.value || '""'}`;
  }
</script>

<div class="tab-content">
  <div class="top-bar">
    <button class="btn btn-add" onclick={addRule}>+ Add header rule</button>
    {#if isImported('header_rules')}<span class="imported-badge">imported</span>{/if}
  </div>

  {#if form.header_rules.length === 0}
    <div class="empty-state">
      No header rules configured. Header rules route traffic to specific backend groups
      based on a request header value (e.g. X-Version: beta for A/B testing, X-Tenant for
      multi-tenant isolation). Evaluated before path rules; first match wins.
    </div>
  {:else}
    {#each form.header_rules as rule, index (index)}
      <div class="rule-card">
        <div class="rule-header">
          <div class="rule-header-left">
            <input
              type="text"
              class="name-input"
              bind:value={rule.header_name}
              placeholder="X-Tenant"
              onchange={() => { form.header_rules = [...form.header_rules]; }}
            />
            <select
              class="match-select"
              bind:value={rule.match_type}
              onchange={() => { form.header_rules = [...form.header_rules]; }}
            >
              <option value="exact">Exact</option>
              <option value="prefix">Prefix</option>
              <option value="regex">Regex</option>
            </select>
            <input
              type="text"
              class="value-input"
              bind:value={rule.value}
              placeholder="acme"
              onchange={() => { form.header_rules = [...form.header_rules]; }}
            />
          </div>
          <div class="rule-overrides-summary">
            <span class="override-pill">{ruleSummary(rule)}</span>
            {#if rule.backend_ids.length > 0}
              <span class="override-pill">{rule.backend_ids.length} backend{rule.backend_ids.length === 1 ? '' : 's'}</span>
            {:else}
              <span class="override-pill muted">default backends</span>
            {/if}
            {#if rule.disabled}
              <span
                class="override-pill disabled-pill"
                title="The proxy skipped this rule at load time because its regex failed to compile. Re-save the rule to recompile it against the current regex engine."
              >disabled</span>
            {/if}
          </div>
          <div class="rule-header-right">
            <button class="btn-icon" title="Move up" aria-label="Move up" disabled={index === 0} onclick={() => moveUp(index)}>
              {@html upIcon}
            </button>
            <button class="btn-icon" title="Move down" aria-label="Move down" disabled={index === form.header_rules.length - 1} onclick={() => moveDown(index)}>
              {@html downIcon}
            </button>
            <button class="btn-icon btn-expand" title={expandedIndex === index ? 'Collapse' : 'Expand'} aria-label={expandedIndex === index ? 'Collapse' : 'Expand'} onclick={() => toggleExpand(index)}>
              {@html expandedIndex === index ? collapseIcon : expandIcon}
            </button>
            <button class="btn-icon btn-delete" title="Remove" aria-label="Remove" onclick={() => removeRule(index)}>
              {@html deleteIcon}
            </button>
          </div>
        </div>

        {#if expandedIndex === index}
          <div class="rule-body">
            <div class="override-section">
              <span class="override-title">Backend override</span>
              <p class="text-muted small">
                Leave unchecked to keep the route's default backends (useful for future
                extensions of this rule that don't route traffic).
              </p>
              {#if backends.length === 0}
                <p class="text-muted small">No backends available.</p>
              {:else}
                <div class="checkbox-list">
                  {#each backends as b (b.id)}
                    <label class="checkbox-item">
                      <input type="checkbox" checked={rule.backend_ids.includes(b.id)} onchange={() => toggleBackend(rule, b.id)} />
                      <span>{b.name ? `${b.name} (${b.address})` : b.address}</span>
                    </label>
                  {/each}
                </div>
              {/if}
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

  .top-bar {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 1rem;
  }

  .btn-add {
    padding: 0.375rem 0.75rem;
    border: 1px solid var(--color-primary);
    border-radius: 0.375rem;
    background: transparent;
    color: var(--color-primary);
    font-size: 0.8125rem;
    font-weight: 500;
    cursor: pointer;
    transition: background-color 0.15s;
  }

  .btn-add:hover { background: rgba(59, 130, 246, 0.1); }

  .empty-state {
    padding: 1.5rem;
    text-align: center;
    color: var(--color-text-muted);
    font-size: 0.8125rem;
    background: var(--color-bg-input);
    border: 1px dashed var(--color-border);
    border-radius: 0.375rem;
  }

  .rule-card {
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    margin-bottom: 0.5rem;
    background: var(--color-bg-input);
  }

  .rule-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem 0.75rem;
  }

  .rule-header-left {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex: 1;
    min-width: 0;
  }

  .name-input {
    flex: 1;
    min-width: 6rem;
    padding: 0.375rem 0.5rem;
    border: 1px solid var(--color-border);
    border-radius: 0.25rem;
    background: var(--color-bg);
    color: var(--color-text);
    font-size: 0.8125rem;
    font-family: ui-monospace, monospace;
  }

  .match-select {
    padding: 0.375rem 0.5rem;
    border: 1px solid var(--color-border);
    border-radius: 0.25rem;
    background: var(--color-bg);
    color: var(--color-text);
    font-size: 0.8125rem;
  }

  .value-input {
    flex: 1;
    min-width: 6rem;
    padding: 0.375rem 0.5rem;
    border: 1px solid var(--color-border);
    border-radius: 0.25rem;
    background: var(--color-bg);
    color: var(--color-text);
    font-size: 0.8125rem;
    font-family: ui-monospace, monospace;
  }

  .rule-overrides-summary {
    display: flex;
    gap: 0.25rem;
    flex-wrap: wrap;
    min-width: 0;
  }

  .override-pill {
    padding: 0.125rem 0.375rem;
    border-radius: 9999px;
    background: rgba(59, 130, 246, 0.15);
    color: var(--color-primary);
    font-size: 0.6875rem;
    font-weight: 500;
    font-family: ui-monospace, monospace;
    white-space: nowrap;
  }

  .override-pill.muted {
    background: rgba(128, 128, 128, 0.15);
    color: var(--color-text-muted);
  }

  .override-pill.disabled-pill {
    background: rgba(220, 38, 38, 0.12);
    color: #dc2626;
    border: 1px solid rgba(220, 38, 38, 0.4);
    font-weight: 600;
  }

  .rule-header-right {
    display: flex;
    gap: 0.25rem;
  }

  .btn-icon {
    padding: 0.25rem;
    border: none;
    background: transparent;
    color: var(--color-text-muted);
    cursor: pointer;
    border-radius: 0.25rem;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .btn-icon:hover:not(:disabled) {
    background: rgba(255, 255, 255, 0.05);
    color: var(--color-text);
  }

  .btn-icon:disabled { opacity: 0.3; cursor: not-allowed; }
  .btn-icon.btn-delete:hover { color: var(--color-danger); }

  .rule-body {
    padding: 0.75rem;
    border-top: 1px solid var(--color-border);
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .override-section {
    padding: 0.5rem;
    background: var(--color-bg);
    border-radius: 0.25rem;
  }

  .override-title {
    display: block;
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--color-text-muted);
    margin-bottom: 0.375rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .checkbox-list {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    max-height: 12rem;
    overflow-y: auto;
  }

  .checkbox-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8125rem;
    cursor: pointer;
    padding: 0.25rem 0;
  }

  .checkbox-item input[type="checkbox"] { accent-color: var(--color-primary); }

  .text-muted { color: var(--color-text-muted); }
  .small { font-size: 0.75rem; }

  .imported-badge {
    display: inline-block;
    padding: 0.0625rem 0.375rem;
    border-radius: 9999px;
    font-size: 0.625rem;
    font-weight: 600;
    text-transform: uppercase;
    background: rgba(59, 130, 246, 0.15);
    color: var(--color-primary);
    vertical-align: middle;
  }
</style>
