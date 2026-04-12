<script lang="ts">
  import type { RouteFormState, ResponseRewriteRuleFormState } from '../../lib/route-form';

  interface Props {
    form: RouteFormState;
    importedFields?: Set<string>;
  }

  let { form = $bindable(), importedFields }: Props = $props();

  let expandedIndex: number | null = $state(null);

  function newRule(): ResponseRewriteRuleFormState {
    return { pattern: '', replacement: '', is_regex: false, max_replacements: '' };
  }

  function addRule() {
    form.response_rewrite_rules = [...form.response_rewrite_rules, newRule()];
    expandedIndex = form.response_rewrite_rules.length - 1;
  }

  // Two-click inline confirm - see HeaderRulesTab for the pattern.
  let pendingRemoveIndex: number | null = $state(null);
  let pendingRemoveTimer: ReturnType<typeof setTimeout> | null = null;

  function requestRemove(index: number) {
    if (pendingRemoveIndex === index) {
      if (pendingRemoveTimer) clearTimeout(pendingRemoveTimer);
      pendingRemoveTimer = null;
      pendingRemoveIndex = null;
      form.response_rewrite_rules = form.response_rewrite_rules.filter((_, i) => i !== index);
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
    const r = [...form.response_rewrite_rules];
    [r[index - 1], r[index]] = [r[index], r[index - 1]];
    form.response_rewrite_rules = r;
    if (expandedIndex === index) expandedIndex = index - 1;
    else if (expandedIndex === index - 1) expandedIndex = index;
  }

  function moveDown(index: number) {
    if (index >= form.response_rewrite_rules.length - 1) return;
    const r = [...form.response_rewrite_rules];
    [r[index], r[index + 1]] = [r[index + 1], r[index]];
    form.response_rewrite_rules = r;
    if (expandedIndex === index) expandedIndex = index + 1;
    else if (expandedIndex === index + 1) expandedIndex = index;
  }

  function toggleExpand(index: number) {
    expandedIndex = expandedIndex === index ? null : index;
  }

  function isImported(field: string): boolean {
    return importedFields?.has(field) ?? false;
  }

  function ruleSummary(rule: ResponseRewriteRuleFormState): string {
    const op = rule.is_regex ? '~=' : '=';
    const pat = rule.pattern.length > 30 ? rule.pattern.slice(0, 27) + '...' : rule.pattern;
    const rep = rule.replacement.length > 30 ? rule.replacement.slice(0, 27) + '...' : rule.replacement;
    return `${pat || '(empty)'} ${op} ${rep || '""'}`;
  }
</script>

<div class="tab-content">
  <div class="top-bar">
    <button class="btn btn-add" onclick={addRule}>+ Add rewrite rule</button>
    {#if isImported('response_rewrite')}<span class="imported-badge">imported</span>{/if}
  </div>

  <div class="intro">
    Search-and-replace on the upstream response body before it reaches the
    client (Nginx <code>sub_filter</code> equivalent). Buffers the body up
    to a cap, then applies rules in declaration order. Bodies over the cap
    stream through verbatim (a half-rewritten body would be worse than
    none). Compressed responses (<code>Content-Encoding: gzip/br</code>)
    are NOT rewritten in v1.
  </div>

  {#if form.response_rewrite_rules.length === 0}
    <div class="empty-state">
      No response rewrite rules. Add one to hide backend hostnames, redact
      secrets, or patch response content in flight.
    </div>
  {:else}
    <div class="global-settings">
      <div class="form-group">
        <label for="rr-max-body">Max buffer size (bytes)</label>
        <input
          id="rr-max-body"
          type="number"
          min="1"
          max="134217728"
          bind:value={form.response_rewrite_max_body_bytes}
        />
        <span class="hint">Responses larger than this stream through unchanged. Default 1 MiB (1048576). Max 128 MiB.</span>
      </div>
      <div class="form-group">
        <label for="rr-ct">Content-Type prefixes (CSV)</label>
        <input
          id="rr-ct"
          type="text"
          bind:value={form.response_rewrite_content_type_prefixes}
          placeholder="text/, application/json"
        />
        <span class="hint">Only responses matching one of these prefixes are rewritten. Empty defaults to <code>text/</code>.</span>
      </div>
    </div>

    {#each form.response_rewrite_rules as rule, index (index)}
      <div class="rule-card">
        <div class="rule-header">
          <div class="rule-header-left">
            <span class="override-pill">#{index + 1}</span>
            <span class="summary">{ruleSummary(rule)}</span>
          </div>
          <div class="rule-header-right">
            <button class="btn-icon" title="Move up" aria-label="Move up" disabled={index === 0} onclick={() => moveUp(index)}>{@html upIcon}</button>
            <button class="btn-icon" title="Move down" aria-label="Move down" disabled={index === form.response_rewrite_rules.length - 1} onclick={() => moveDown(index)}>{@html downIcon}</button>
            <button class="btn-icon btn-expand" title={expandedIndex === index ? 'Collapse' : 'Expand'} aria-label={expandedIndex === index ? 'Collapse' : 'Expand'} onclick={() => toggleExpand(index)}>{@html expandedIndex === index ? collapseIcon : expandIcon}</button>
            {#if pendingRemoveIndex === index}
              <button class="btn-icon btn-delete btn-delete-confirm" title="Click again within 3 s to remove" aria-label="Confirm remove" onclick={() => requestRemove(index)}>Confirm?</button>
            {:else}
              <button class="btn-icon btn-delete" title="Remove" aria-label="Remove" onclick={() => requestRemove(index)}>{@html deleteIcon}</button>
            {/if}
          </div>
        </div>

        {#if expandedIndex === index}
          <div class="rule-body">
            <div class="form-group">
              <label for="rr-pattern-{index}">Pattern</label>
              <input id="rr-pattern-{index}" type="text" bind:value={rule.pattern} placeholder="internal.svc:8080" />
              <span class="hint">Literal string (default) or regex if "Interpret as regex" is on.</span>
            </div>
            <div class="form-group">
              <label for="rr-replacement-{index}">Replacement</label>
              <input id="rr-replacement-{index}" type="text" bind:value={rule.replacement} placeholder="api.example.com" />
              <span class="hint">For regex rules, $1, $2, ... reference capture groups.</span>
            </div>
            <div class="form-row">
              <label class="checkbox-item">
                <input type="checkbox" bind:checked={rule.is_regex} />
                <span>Interpret pattern as regex</span>
              </label>
              <div class="form-group inline">
                <label for="rr-max-{index}">Max replacements</label>
                <input id="rr-max-{index}" type="text" bind:value={rule.max_replacements} placeholder="(unlimited)" />
                <span class="hint">Positive integer caps the number of matches, or leave empty for unlimited.</span>
              </div>
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

  .global-settings { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin-bottom: 1rem; padding: 0.75rem; background: var(--color-bg-input); border-radius: 0.375rem; }

  .rule-card { border: 1px solid var(--color-border); border-radius: 0.375rem; margin-bottom: 0.5rem; background: var(--color-bg-input); }
  .rule-header { display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 0.75rem; }
  .rule-header-left { display: flex; align-items: center; gap: 0.5rem; flex: 1; min-width: 0; }
  .summary { font-family: ui-monospace, monospace; font-size: 0.8125rem; color: var(--color-text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .override-pill { padding: 0.125rem 0.375rem; border-radius: 9999px; background: rgba(59, 130, 246, 0.15); color: var(--color-primary); font-size: 0.6875rem; font-weight: 500; font-family: ui-monospace, monospace; white-space: nowrap; }

  .rule-header-right { display: flex; gap: 0.25rem; }
  .btn-icon { padding: 0.25rem; border: none; background: transparent; color: var(--color-text-muted); cursor: pointer; border-radius: 0.25rem; display: flex; align-items: center; justify-content: center; }
  .btn-icon:hover:not(:disabled) { background: rgba(255, 255, 255, 0.05); color: var(--color-text); }
  .btn-icon:disabled { opacity: 0.3; cursor: not-allowed; }
  .btn-icon.btn-delete:hover { color: var(--color-danger); }
  .btn-delete-confirm { width: auto; padding: 0 0.5rem; font-size: 0.6875rem; font-weight: 600; color: white; background: var(--color-danger, #dc2626); border-radius: 0.25rem; animation: pulse-arm 1s ease-in-out infinite; }
  @keyframes pulse-arm { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }

  .rule-body { padding: 0.75rem; border-top: 1px solid var(--color-border); display: flex; flex-direction: column; gap: 0.75rem; }

  .form-group { display: flex; flex-direction: column; gap: 0.25rem; }
  .form-group.inline { flex: 1; }
  .form-group label { font-size: 0.75rem; font-weight: 600; color: var(--color-text-muted); text-transform: uppercase; letter-spacing: 0.05em; }
  .form-group input[type="text"], .form-group input[type="number"] { padding: 0.375rem 0.5rem; border: 1px solid var(--color-border); border-radius: 0.25rem; background: var(--color-bg); color: var(--color-text); font-size: 0.8125rem; font-family: ui-monospace, monospace; }
  .form-group input:focus { outline: none; border-color: var(--color-primary); }
  .form-row { display: flex; gap: 1rem; align-items: flex-start; }
  .hint { font-size: 0.75rem; color: var(--color-text-muted); font-weight: 400; text-transform: none; letter-spacing: normal; }

  .checkbox-item { display: flex; align-items: center; gap: 0.5rem; font-size: 0.8125rem; cursor: pointer; padding: 0.25rem 0; }
  .checkbox-item input[type="checkbox"] { accent-color: var(--color-primary); }

  code { font-family: ui-monospace, monospace; font-size: 0.75rem; background: var(--color-bg); padding: 0.05rem 0.25rem; border-radius: 0.25rem; }

  .imported-badge { display: inline-block; padding: 0.0625rem 0.375rem; border-radius: 9999px; font-size: 0.625rem; font-weight: 600; text-transform: uppercase; background: rgba(59, 130, 246, 0.15); color: var(--color-primary); vertical-align: middle; }
</style>
