<script lang="ts">
  import type { RouteFormState, PathRuleFormState } from '../../lib/route-form';
  import type { BackendResponse } from '../../lib/api';

  interface Props {
    form: RouteFormState;
    backends: BackendResponse[];
    importedFields?: Set<string>;
  }

  let { form = $bindable(), backends, importedFields }: Props = $props();

  let expandedIndex: number | null = $state(null);

  function newRule(): PathRuleFormState {
    return {
      path: '/',
      match_type: 'prefix',
      backend_ids: [],
      cache_enabled: null,
      cache_ttl_s: null,
      response_headers: '',
      response_headers_remove: '',
      rate_limit_rps: '',
      rate_limit_burst: '',
      redirect_to: '',
      return_status: '',
    };
  }

  function addRule() {
    form.path_rules = [...form.path_rules, newRule()];
    expandedIndex = form.path_rules.length - 1;
  }

  function removeRule(index: number) {
    form.path_rules = form.path_rules.filter((_, i) => i !== index);
    if (expandedIndex === index) expandedIndex = null;
    else if (expandedIndex != null && expandedIndex > index) expandedIndex--;
  }

  function moveUp(index: number) {
    if (index <= 0) return;
    const rules = [...form.path_rules];
    [rules[index - 1], rules[index]] = [rules[index], rules[index - 1]];
    form.path_rules = rules;
    if (expandedIndex === index) expandedIndex = index - 1;
    else if (expandedIndex === index - 1) expandedIndex = index;
  }

  function moveDown(index: number) {
    if (index >= form.path_rules.length - 1) return;
    const rules = [...form.path_rules];
    [rules[index], rules[index + 1]] = [rules[index + 1], rules[index]];
    form.path_rules = rules;
    if (expandedIndex === index) expandedIndex = index + 1;
    else if (expandedIndex === index + 1) expandedIndex = index;
  }

  function toggleExpand(index: number) {
    expandedIndex = expandedIndex === index ? null : index;
  }

  function toggleBackend(rule: PathRuleFormState, id: string) {
    if (rule.backend_ids.includes(id)) {
      rule.backend_ids = rule.backend_ids.filter((b) => b !== id);
    } else {
      rule.backend_ids = [...rule.backend_ids, id];
    }
    form.path_rules = [...form.path_rules];
  }

  function isImported(field: string): boolean {
    return importedFields?.has(field) ?? false;
  }
</script>

<div class="tab-content">
  <div class="top-bar">
    <button class="btn btn-add" onclick={addRule}>+ Add path rule</button>
    {#if isImported('path_rules')}<span class="imported-badge">imported</span>{/if}
  </div>

  {#if form.path_rules.length === 0}
    <div class="empty-state">
      No path rules configured. Path rules allow different behavior for sub-paths (cache, headers, backends, blocking).
    </div>
  {:else}
    {#each form.path_rules as rule, index (index)}
      <div class="rule-card">
        <div class="rule-header">
          <div class="rule-header-left">
            <input
              type="text"
              class="path-input"
              bind:value={rule.path}
              placeholder="/api/v1"
              onchange={() => { form.path_rules = [...form.path_rules]; }}
            />
            <select
              class="match-select"
              bind:value={rule.match_type}
              onchange={() => { form.path_rules = [...form.path_rules]; }}
            >
              <option value="prefix">Prefix</option>
              <option value="exact">Exact</option>
            </select>
          </div>
          <div class="rule-header-right">
            <button class="btn-icon" title="Move up" disabled={index === 0} onclick={() => moveUp(index)}>
              {@html upIcon}
            </button>
            <button class="btn-icon" title="Move down" disabled={index === form.path_rules.length - 1} onclick={() => moveDown(index)}>
              {@html downIcon}
            </button>
            <button class="btn-icon btn-expand" title={expandedIndex === index ? 'Collapse' : 'Expand'} onclick={() => toggleExpand(index)}>
              {@html expandedIndex === index ? collapseIcon : expandIcon}
            </button>
            <button class="btn-icon btn-delete" title="Remove" onclick={() => removeRule(index)}>
              {@html deleteIcon}
            </button>
          </div>
        </div>

        {#if expandedIndex === index}
          <div class="rule-body">
            <!-- Backend override -->
            <div class="override-section">
              <span class="override-title">Backend override</span>
              {#if backends.length === 0}
                <p class="text-muted small">No backends available</p>
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

            <!-- Cache override -->
            <div class="override-section">
              <span class="override-title">Cache override</span>
              <div class="form-row">
                <label class="checkbox-item">
                  <input
                    type="checkbox"
                    checked={rule.cache_enabled === true}
                    indeterminate={rule.cache_enabled === null}
                    onchange={() => {
                      if (rule.cache_enabled === null) rule.cache_enabled = true;
                      else if (rule.cache_enabled) rule.cache_enabled = false;
                      else rule.cache_enabled = null;
                      form.path_rules = [...form.path_rules];
                    }}
                  />
                  <span>{rule.cache_enabled === null ? 'Inherit' : rule.cache_enabled ? 'Enabled' : 'Disabled'}</span>
                </label>
                <div class="inline-field">
                  <label for="pr-cache-ttl-{index}">TTL (s)</label>
                  <input
                    id="pr-cache-ttl-{index}"
                    type="number"
                    min="1"
                    bind:value={rule.cache_ttl_s}
                    placeholder="Inherit"
                    onchange={() => { form.path_rules = [...form.path_rules]; }}
                  />
                </div>
              </div>
            </div>

            <!-- Response headers -->
            <div class="override-section">
              <span class="override-title">Response headers</span>
              <textarea
                rows="3"
                bind:value={rule.response_headers}
                placeholder="X-Custom=value&#10;X-Other=value"
                onchange={() => { form.path_rules = [...form.path_rules]; }}
              ></textarea>
              <div class="inline-field" style="margin-top: 0.5rem;">
                <label for="pr-hdr-rm-{index}">Remove headers (comma-separated)</label>
                <input
                  id="pr-hdr-rm-{index}"
                  type="text"
                  bind:value={rule.response_headers_remove}
                  placeholder="X-Powered-By, Server"
                  onchange={() => { form.path_rules = [...form.path_rules]; }}
                />
              </div>
            </div>

            <!-- Rate limiting -->
            <div class="override-section">
              <span class="override-title">Rate limiting</span>
              <div class="form-row">
                <div class="inline-field">
                  <label for="pr-rps-{index}">RPS</label>
                  <input
                    id="pr-rps-{index}"
                    type="number"
                    min="1"
                    bind:value={rule.rate_limit_rps}
                    placeholder="Inherit"
                    onchange={() => { form.path_rules = [...form.path_rules]; }}
                  />
                </div>
                <div class="inline-field">
                  <label for="pr-burst-{index}">Burst</label>
                  <input
                    id="pr-burst-{index}"
                    type="number"
                    min="1"
                    bind:value={rule.rate_limit_burst}
                    placeholder="Inherit"
                    onchange={() => { form.path_rules = [...form.path_rules]; }}
                  />
                </div>
              </div>
            </div>

            <!-- Redirect -->
            <div class="override-section">
              <span class="override-title">Redirect</span>
              <input
                type="text"
                bind:value={rule.redirect_to}
                placeholder="https://example.com/new-path"
                onchange={() => { form.path_rules = [...form.path_rules]; }}
              />
            </div>

            <!-- Return status -->
            <div class="override-section">
              <span class="override-title">Return status</span>
              <input
                type="number"
                min="100"
                max="599"
                bind:value={rule.return_status}
                placeholder="e.g. 403, 404"
                onchange={() => { form.path_rules = [...form.path_rules]; }}
              />
              <span class="hint">If set, responds with this HTTP status instead of proxying.</span>
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
  const expandIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>';
  const collapseIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="18 15 12 9 6 15"/></svg>';
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

  .btn-add:hover {
    background: rgba(59, 130, 246, 0.1);
  }

  .empty-state {
    padding: 2rem 1rem;
    text-align: center;
    color: var(--color-text-muted);
    font-size: 0.875rem;
    border: 1px dashed var(--color-border);
    border-radius: 0.375rem;
  }

  .rule-card {
    border: 1px solid var(--color-border);
    border-radius: 0.375rem;
    margin-bottom: 0.75rem;
    background: var(--color-bg-input);
  }

  .rule-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.5rem 0.75rem;
    gap: 0.5rem;
  }

  .rule-header-left {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex: 1;
    min-width: 0;
  }

  .path-input {
    flex: 1;
    min-width: 100px;
    padding: 0.375rem 0.5rem;
    border: 1px solid var(--color-border);
    border-radius: 0.25rem;
    background: var(--color-bg-card);
    color: var(--color-text);
    font-size: 0.8125rem;
    font-family: var(--mono);
  }

  .path-input:focus { outline: none; border-color: var(--color-primary); }

  .match-select {
    padding: 0.375rem 0.5rem;
    border: 1px solid var(--color-border);
    border-radius: 0.25rem;
    background: var(--color-bg-card);
    color: var(--color-text);
    font-size: 0.8125rem;
  }

  .match-select:focus { outline: none; border-color: var(--color-primary); }

  .rule-header-right {
    display: flex;
    align-items: center;
    gap: 0.25rem;
    flex-shrink: 0;
  }

  .btn-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 1.75rem;
    height: 1.75rem;
    border: none;
    border-radius: 0.25rem;
    background: none;
    color: var(--color-text-muted);
    cursor: pointer;
    transition: background-color 0.15s, color 0.15s;
  }

  .btn-icon:hover:not(:disabled) {
    background: var(--color-bg-hover);
    color: var(--color-text);
  }

  .btn-icon:disabled {
    opacity: 0.3;
    cursor: not-allowed;
  }

  .btn-delete:hover:not(:disabled) {
    color: var(--color-red);
  }

  .rule-body {
    padding: 0.75rem;
    border-top: 1px solid var(--color-border);
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .override-section {
    display: flex;
    flex-direction: column;
    gap: 0.375rem;
  }

  .override-title {
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--color-text-muted);
    text-transform: uppercase;
    letter-spacing: 0.025em;
  }

  .form-row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.75rem;
  }

  .inline-field {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .inline-field label {
    font-size: 0.75rem;
    color: var(--color-text-muted);
  }

  .override-section input[type="text"],
  .override-section input[type="number"],
  .override-section select {
    width: 100%;
    padding: 0.375rem 0.5rem;
    border: 1px solid var(--color-border);
    border-radius: 0.25rem;
    background: var(--color-bg-card);
    color: var(--color-text);
    font-size: 0.8125rem;
  }

  .override-section input:focus,
  .override-section select:focus {
    outline: none;
    border-color: var(--color-primary);
  }

  .override-section textarea {
    width: 100%;
    padding: 0.375rem 0.5rem;
    border: 1px solid var(--color-border);
    border-radius: 0.25rem;
    background: var(--color-bg-card);
    color: var(--color-text);
    font-size: 0.8125rem;
    font-family: var(--mono);
    resize: vertical;
  }

  .override-section textarea:focus { outline: none; border-color: var(--color-primary); }

  .checkbox-list {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    max-height: 120px;
    overflow-y: auto;
    padding: 0.375rem;
    border: 1px solid var(--color-border);
    border-radius: 0.25rem;
    background: var(--color-bg-card);
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
