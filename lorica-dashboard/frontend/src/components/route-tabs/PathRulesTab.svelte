<script lang="ts">
  import type { RouteFormState, PathRuleFormState } from '../../lib/route-form';
  import type { BackendResponse } from '../../lib/api';
  import BackendCheckboxList from '../BackendCheckboxList.svelte';
  import {
    validateRoutePath,
    validateUrl,
    validateHeadersMapText,
    validateHttpHeaderNameList,
  } from '../../lib/validators';

  /**
   * Compute per-field errors for a given path rule. Returns `null`
   * for an OK field so template `{#if ...}` blocks collapse. Empty
   * strings are treated as "field not set yet" and never flag.
   */
  function ruleErrors(rule: PathRuleFormState) {
    return {
      path: rule.path.trim() === '' ? null : validateRoutePath(rule.path),
      redirect: validateUrl(rule.redirect_to),
      returnStatus: (() => {
        const raw = rule.return_status.trim();
        if (raw === '') return null;
        const n = Number(raw);
        if (!Number.isInteger(n) || n < 100 || n > 599) {
          return 'must be an HTTP code in 100..599';
        }
        return null;
      })(),
      respHeaders: validateHeadersMapText(rule.response_headers),
      respHeadersRemove: validateHttpHeaderNameList(rule.response_headers_remove),
      rps: (() => {
        const raw = rule.rate_limit_rps.trim();
        if (raw === '') return null;
        const n = Number(raw);
        if (!Number.isInteger(n) || n < 1) return 'must be a positive integer';
        return null;
      })(),
      burst: (() => {
        const raw = rule.rate_limit_burst.trim();
        if (raw === '') return null;
        const n = Number(raw);
        if (!Number.isInteger(n) || n < 1) return 'must be a positive integer';
        return null;
      })(),
    };
  }

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

  // Two-click confirm for delete: the first click arms the button
  // for 3 s, the second within that window commits. Matches the
  // pattern used by Canary / HeaderRules / Response rewrite so every
  // rule list in the drawer behaves the same way - no more "one
  // click silently drops a path rule that was routing 404s into the
  // void". (Resolves UXUI.md finding #6.)
  let pendingRemoveIndex: number | null = $state(null);
  let pendingRemoveTimer: ReturnType<typeof setTimeout> | null = null;

  function requestRemove(index: number) {
    if (pendingRemoveIndex === index) {
      if (pendingRemoveTimer) clearTimeout(pendingRemoveTimer);
      pendingRemoveTimer = null;
      pendingRemoveIndex = null;
      removeRule(index);
      return;
    }
    pendingRemoveIndex = index;
    if (pendingRemoveTimer) clearTimeout(pendingRemoveTimer);
    pendingRemoveTimer = setTimeout(() => {
      pendingRemoveIndex = null;
      pendingRemoveTimer = null;
    }, 3000);
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
      {@const errs = ruleErrors(rule)}
      <div class="rule-card">
        <div class="rule-header">
          <div class="rule-header-left">
            <input
              type="text"
              class="path-input"
              class:invalid={errs.path !== null}
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
          {#if errs.path}<span class="field-error" role="alert">Path: {errs.path}</span>{/if}
          <div class="rule-overrides-summary">
            {#if rule.backend_ids.length > 0}<span class="override-pill">backends</span>{/if}
            {#if rule.cache_enabled != null}<span class="override-pill">cache</span>{/if}
            {#if rule.response_headers}<span class="override-pill">headers</span>{/if}
            {#if rule.rate_limit_rps}<span class="override-pill">rate limit</span>{/if}
            {#if rule.redirect_to}<span class="override-pill">redirect</span>{/if}
            {#if rule.return_status}<span class="override-pill">return {rule.return_status}</span>{/if}
          </div>
          <div class="rule-header-right">
            <button class="btn-icon" title="Move up" aria-label="Move up" disabled={index === 0} onclick={() => moveUp(index)}>
              <!-- eslint-disable-next-line svelte/no-at-html-tags -->
              {@html upIcon}
            </button>
            <button class="btn-icon" title="Move down" aria-label="Move down" disabled={index === form.path_rules.length - 1} onclick={() => moveDown(index)}>
              <!-- eslint-disable-next-line svelte/no-at-html-tags -->
              {@html downIcon}
            </button>
            <button class="btn-icon btn-expand" title={expandedIndex === index ? 'Collapse' : 'Expand'} aria-label={expandedIndex === index ? 'Collapse' : 'Expand'} onclick={() => toggleExpand(index)}>
              <!-- eslint-disable-next-line svelte/no-at-html-tags -->
              {@html expandedIndex === index ? collapseIcon : expandIcon}
            </button>
            {#if pendingRemoveIndex === index}
              <button
                class="btn-icon btn-delete btn-delete-confirm"
                title="Click again within 3 s to remove"
                aria-label="Confirm remove"
                onclick={() => requestRemove(index)}
              >Confirm?</button>
            {:else}
              <button class="btn-icon btn-delete" title="Remove" aria-label="Remove" onclick={() => requestRemove(index)}>
                <!-- eslint-disable-next-line svelte/no-at-html-tags -->
                {@html deleteIcon}
              </button>
            {/if}
          </div>
        </div>

        {#if expandedIndex === index}
          <div class="rule-body">
            <!-- Backend override -->
            <div class="override-section">
              <span class="override-title">Backend override</span>
              <BackendCheckboxList
                {backends}
                selected={rule.backend_ids}
                onToggle={(id) => toggleBackend(rule, id)}
                showHealth={false}
              />
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
              {#if errs.respHeaders}<span class="field-error" role="alert">{errs.respHeaders}</span>{/if}
              <div class="inline-field" style="margin-top: 0.5rem;">
                <label for="pr-hdr-rm-{index}">Remove headers (comma-separated)</label>
                <input
                  id="pr-hdr-rm-{index}"
                  type="text"
                  bind:value={rule.response_headers_remove}
                  placeholder="X-Powered-By, Server"
                  onchange={() => { form.path_rules = [...form.path_rules]; }}
                />
                {#if errs.respHeadersRemove}<span class="field-error" role="alert">{errs.respHeadersRemove}</span>{/if}
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
                  {#if errs.rps}<span class="field-error" role="alert">{errs.rps}</span>{/if}
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
                  {#if errs.burst}<span class="field-error" role="alert">{errs.burst}</span>{/if}
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
              {#if errs.redirect}<span class="field-error" role="alert">{errs.redirect}</span>{/if}
              <span class="hint">
                Emitted as-is (literal 301 target). Unlike the route-level
                Redirect, the matched path is <strong>not</strong> appended.
              </span>
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
              {#if errs.returnStatus}<span class="field-error" role="alert">{errs.returnStatus}</span>{/if}
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

  .rule-overrides-summary {
    display: flex;
    align-items: center;
    gap: 0.25rem;
    flex-wrap: wrap;
  }

  .override-pill {
    display: inline-block;
    padding: 0.0625rem 0.375rem;
    border-radius: 9999px;
    font-size: 0.625rem;
    font-weight: 600;
    text-transform: uppercase;
    background: rgba(59, 130, 246, 0.15);
    color: var(--color-primary);
    white-space: nowrap;
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
  .btn-delete-confirm {
    width: auto;
    padding: 0 0.5rem;
    font-size: 0.6875rem;
    font-weight: 600;
    color: white;
    background: var(--color-danger, var(--color-red, #dc2626));
    border-radius: 0.25rem;
    animation: pulse-arm 1s ease-in-out infinite;
  }
  @keyframes pulse-arm {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.6; }
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
  .override-section input[type="number"] {
    width: 100%;
    padding: 0.375rem 0.5rem;
    border: 1px solid var(--color-border);
    border-radius: 0.25rem;
    background: var(--color-bg-card);
    color: var(--color-text);
    font-size: 0.8125rem;
  }

  .override-section input:focus {
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

  .checkbox-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8125rem;
    cursor: pointer;
  }

  .checkbox-item input[type="checkbox"] { accent-color: var(--color-primary); }

  .hint { font-weight: 400; color: var(--color-text-muted); font-size: 0.75rem; }
  .field-error { display: block; color: var(--color-red); font-size: var(--text-xs); margin-top: 0.25rem; }
  .invalid { border-color: var(--color-red) !important; }

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
