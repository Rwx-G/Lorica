<script lang="ts">
  import type { LoricaRouteImport } from '../../lib/nginx-parser';
  import { FIELD_LABELS, NGINX_DIRECTIVE_MAP } from './maps';

  interface Props {
    importRoutes: LoricaRouteImport[];
    previewTab: number;
    applying: boolean;
    onBack: () => void;
    onApply: () => void;
  }

  let {
    importRoutes,
    previewTab = $bindable(),
    applying,
    onBack,
    onApply,
  }: Props = $props();

  // Format a route field value for display.
  function formatFieldValue(route: LoricaRouteImport, field: string): string {
    const val = (route as unknown as Record<string, unknown>)[field];
    if (val === null || val === undefined) return '-';
    if (typeof val === 'boolean') return val ? 'Yes' : 'No';
    if (field === 'path_rules' && Array.isArray(val)) {
      return val.length > 0 ? `${val.length} rule(s)` : '-';
    }
    if (Array.isArray(val)) return val.length > 0 ? val.join(', ') : '-';
    if (typeof val === 'object' && val !== null) {
      if (val instanceof Set) return '-';
      const entries = Object.entries(val as Record<string, string>);
      return entries.length > 0 ? entries.map(([k, v]) => `${k}: ${v}`).join('; ') : '-';
    }
    return String(val);
  }

  // Get all displayable fields for a route.
  function getRouteFields(route: LoricaRouteImport): { field: string; imported: boolean }[] {
    const allFields = Object.keys(FIELD_LABELS);
    return allFields.map((field) => ({
      field,
      imported: route.importedFields.has(field),
    }));
  }
</script>

<div class="step-content">
  <h3>Route preview</h3>

  {#if importRoutes.length > 1}
    <div class="preview-tabs">
      {#each importRoutes as route, i}
        <button
          class="preview-tab"
          class:active={previewTab === i}
          onclick={() => { previewTab = i; }}
        >
          {route.hostname || '(no host)'}{route.path_prefix}
        </button>
      {/each}
    </div>
  {/if}

  {#if importRoutes[previewTab]}
    {@const route = importRoutes[previewTab]}
    <div class="preview-card">
      {#each getRouteFields(route) as { field, imported }}
        {@const value = formatFieldValue(route, field)}
        {#if imported || value !== '-'}
          <div class="preview-row" class:imported class:dimmed={!imported}>
            <div class="preview-nginx">
              <code>{NGINX_DIRECTIVE_MAP[field] ?? field}</code>
            </div>
            <div class="preview-lorica">
              <span class="preview-field-name">{FIELD_LABELS[field] ?? field}</span>
              <span class="preview-field-value">{value}</span>
              {#if imported}
                <span class="badge badge-imported">imported</span>
              {/if}
            </div>
          </div>
        {/if}
      {/each}
    </div>
    {#if route.path_rules && route.path_rules.length > 0}
      <div class="preview-path-rules">
        <h5>Path Rules ({route.path_rules.length})</h5>
        {#each route.path_rules as rule}
          <div class="path-rule-preview">
            <code>{rule.match_type === 'exact' ? '= ' : ''}{rule.path}</code>
            {#if rule.backend_addresses}<span class="rule-override">backends: {rule.backend_addresses.join(', ')}</span>{/if}
            {#if rule.cache_enabled}<span class="rule-override">cache: {rule.cache_ttl_s}s</span>{/if}
            {#if rule.response_headers}<span class="rule-override">headers: {Object.entries(rule.response_headers).map(([k, v]) => `${k}: ${v}`).join('; ')}</span>{/if}
            {#if rule.return_status}<span class="rule-override">return {rule.return_status}</span>{/if}
            {#if rule.redirect_to}<span class="rule-override">redirect: {rule.redirect_to}</span>{/if}
            {#if rule.rate_limit_rps}<span class="rule-override">rate limit: {rule.rate_limit_rps} rps</span>{/if}
          </div>
        {/each}
      </div>
    {/if}
    <p class="step-hint">Fields are read-only here. You can edit them in the Route Drawer after import.</p>
  {/if}

  <div class="step-actions">
    <button class="btn btn-ghost" onclick={onBack}>Back</button>
    <button class="btn btn-primary" onclick={onApply} disabled={applying}>
      {applying ? 'Applying...' : 'Apply import'}
    </button>
  </div>
</div>
