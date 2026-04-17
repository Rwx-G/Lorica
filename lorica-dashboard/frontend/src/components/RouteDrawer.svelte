<script lang="ts">
  import { untrack } from 'svelte';
  import type { RouteResponse, BackendResponse, CertificateResponse, SecurityHeaderPreset } from '../lib/api';
  import { api } from '../lib/api';
  import {
    type RouteFormState,
    ROUTE_DEFAULTS,
    TAB_FIELDS,
    routeToFormState,
    formStateToCreateRequest,
    formStateToUpdateRequest,
    getModifiedFields,
    validateRouteFormWithTab,
  } from '../lib/route-form';
  import { showToast } from '../lib/toast';
  import GeneralTab from './route-tabs/GeneralTab.svelte';
  import RoutingTab from './route-tabs/RoutingTab.svelte';
  import TransformTab from './route-tabs/TransformTab.svelte';
  import CachingTab from './route-tabs/CachingTab.svelte';
  import SecurityTab from './route-tabs/SecurityTab.svelte';
  import ProtectionTab from './route-tabs/ProtectionTab.svelte';
  import UpstreamTab from './route-tabs/UpstreamTab.svelte';
  // Absorbed tabs (no longer registered at top level):
  // - HeadersTab, CorsTab -> Transform subsections (inlined)
  // - ResponseRewriteTab -> Transform > Response body rewrite (still
  //   imported by TransformTab as an embedded panel)
  // - TimeoutsTab path rewrite -> Transform > Path rewrite (inlined)
  // - TimeoutsTab timeouts + retry -> UpstreamTab (renamed component)
  // - PathRulesTab, HeaderRulesTab, CanaryTab -> Routing subsections

  interface Props {
    open: boolean;
    editing: RouteResponse | null;
    backends: BackendResponse[];
    certificates: CertificateResponse[];
    importedFields?: Set<string>;
    onsave: () => void;
    onclose: () => void;
  }

  let { open, editing, backends, certificates, importedFields, onsave, onclose }: Props = $props();

  let form: RouteFormState = $state({ ...ROUTE_DEFAULTS });
  let formError = $state('');
  let formSubmitting = $state(false);
  let customPresets: SecurityHeaderPreset[] = $state([]);
  let activeTab = $state('general');
  let initialFormJson = $state('');

  const TABS = [
    { id: 'general', label: 'General' },
    { id: 'routing', label: 'Routing' },
    { id: 'transform', label: 'Transform' },
    { id: 'cache', label: 'Cache' },
    { id: 'security', label: 'Security' },
    { id: 'protection', label: 'Protection' },
    { id: 'upstream', label: 'Upstream' },
  ];

  // Reset form when drawer opens - untrack body so form/editing changes
  // don't re-trigger this effect (would reset activeTab on every keystroke)
  $effect(() => {
    if (open) {
      untrack(() => {
        if (editing) {
          form = routeToFormState(editing);
        } else {
          form = { ...ROUTE_DEFAULTS, backend_ids: [] };
        }
        initialFormJson = JSON.stringify(form);
        formError = '';
        formSubmitting = false;
        activeTab = 'general';
        // Fetch custom security header presets
        api.getSettings().then((res) => {
          if (res.data) {
            customPresets = res.data.custom_security_presets ?? [];
          }
        });
      });
    }
  });

  // Track unsaved changes (derived - no side effects)
  let hasUnsavedChanges = $derived(open && initialFormJson ? JSON.stringify(form) !== initialFormJson : false);

  let modifiedFields: Set<string> = $derived(getModifiedFields(form));

  /**
   * Summary chips rendered in the drawer header, right under the
   * hostname preview. Each chip is one derived fact about the route
   * so an operator can tell at a glance which features are armed
   * without clicking into the tabs. Resolves finding #14.
   *
   * Tones map to the palette used for subsection accents elsewhere
   * in the drawer (blue / cyan / purple / red / orange / slate /
   * teal / pink) so the header picks up the same colour language.
   */
  type Chip = { label: string; tone: 'blue' | 'cyan' | 'purple' | 'red' | 'orange' | 'slate' | 'teal' | 'pink' | 'green' };
  let summaryChips: Chip[] = $derived.by(() => {
    const chips: Chip[] = [];

    // TLS
    if (form.certificate_id) {
      chips.push({ label: form.force_https ? 'TLS (forced)' : 'TLS', tone: 'green' });
    }

    // Terminal responses (short-circuit proxy)
    if (form.redirect_to || form.redirect_hostname) {
      chips.push({ label: 'Redirect', tone: 'pink' });
    }
    if (form.return_status) {
      chips.push({ label: `Returns ${form.return_status}`, tone: 'pink' });
    }

    // Routing decorations
    if (form.sticky_session) {
      chips.push({ label: 'Sticky', tone: 'cyan' });
    }
    if (form.traffic_splits.length > 0) {
      const total = form.traffic_splits.reduce((s, t) => s + (t.weight_percent || 0), 0);
      chips.push({ label: `Split ${total}%`, tone: 'cyan' });
    }
    if (form.header_rules.length > 0) {
      chips.push({ label: `${form.header_rules.length} header rule${form.header_rules.length > 1 ? 's' : ''}`, tone: 'purple' });
    }
    if (form.path_rules.length > 0) {
      chips.push({ label: `${form.path_rules.length} path rule${form.path_rules.length > 1 ? 's' : ''}`, tone: 'orange' });
    }
    if (form.mirror_backend_ids.length > 0) {
      chips.push({ label: `Mirror ${form.mirror_sample_percent}%`, tone: 'slate' });
    }

    // Security
    if (form.waf_enabled) {
      chips.push({
        label: form.waf_mode === 'blocking' ? 'WAF blocking' : 'WAF detect',
        tone: 'red',
      });
    }
    if (form.basic_auth_username) {
      chips.push({ label: 'Basic auth', tone: 'cyan' });
    }
    if (form.forward_auth_address) {
      chips.push({ label: 'Forward auth', tone: 'teal' });
    }
    if (form.mtls_ca_cert_pem.trim()) {
      chips.push({
        label: form.mtls_required ? 'mTLS required' : 'mTLS optional',
        tone: 'slate',
      });
    }

    // Protection
    if (form.rate_limit_capacity && Number(form.rate_limit_capacity) > 0) {
      chips.push({
        label: `Rate ${form.rate_limit_refill_per_sec}/s`,
        tone: 'blue',
      });
    }
    if (form.geoip_mode && form.geoip_countries.trim()) {
      const countries = form.geoip_countries
        .split(/[,\s]+/)
        .filter((c) => c.length > 0);
      const preview = countries.slice(0, 2).join(',');
      const more = countries.length > 2 ? `+${countries.length - 2}` : '';
      chips.push({
        label: `GeoIP ${form.geoip_mode === 'denylist' ? 'deny' : 'allow'} ${preview}${more}`,
        tone: 'orange',
      });
    }
    if (form.bot_enabled) {
      const mode =
        form.bot_mode === 'javascript'
          ? `JS(${form.bot_pow_difficulty})`
          : form.bot_mode === 'captcha'
            ? 'Captcha'
            : 'Cookie';
      chips.push({ label: `Bot ${mode}`, tone: 'pink' });
    }

    // Cache
    if (form.cache_enabled) {
      chips.push({ label: `Cache ${form.cache_ttl_s}s`, tone: 'cyan' });
    }

    // Transform (compression is the smallest flag worth surfacing)
    if (form.compression_enabled) {
      chips.push({ label: 'gzip', tone: 'teal' });
    }

    return chips;
  });

  function tabHasModifiedFields(tabId: string): boolean {
    const fields = TAB_FIELDS[tabId];
    if (!fields) return false;
    return fields.some((f) => modifiedFields.has(f));
  }

  function handleClose() {
    if (hasUnsavedChanges) {
      const confirmed = window.confirm('You have unsaved changes. Discard them?');
      if (!confirmed) return;
    }
    onclose();
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      handleClose();
    }
  }

  async function handleSubmit() {
    const { message, tab } = validateRouteFormWithTab(form);
    if (message) {
      formError = message;
      // Auto-switch to the tab that owns the offending field so the
      // user doesn't have to hunt for it. Falls back to staying put
      // when the validator couldn't attribute the error.
      if (tab && tab !== activeTab) {
        activeTab = tab;
      }
      return;
    }
    formSubmitting = true;
    formError = '';

    if (editing) {
      const body = formStateToUpdateRequest(form);
      const res = await api.updateRoute(editing.id, body);
      if (res.error) {
        formError = res.error.message;
        formSubmitting = false;
        return;
      }
      showToast('Route updated', 'success');
    } else {
      const body = formStateToCreateRequest(form);
      const res = await api.createRoute(body);
      if (res.error) {
        formError = res.error.message;
        formSubmitting = false;
        return;
      }
      showToast('Route created', 'success');
    }

    formSubmitting = false;
    onclose();
    onsave();
  }
</script>

{#if open}
  <div
    class="drawer-overlay"
    onkeydown={handleKeydown}
    role="dialog"
    aria-modal="true"
    tabindex="-1"
  >
    <!-- Backdrop: separate DOM branch so clicks don't interfere with drawer buttons (Svelte 5 event delegation) -->
    <div class="drawer-backdrop" role="presentation" onclick={handleClose} onkeydown={(e) => { if (e.key === 'Escape') handleClose(); }}></div>
    <div class="drawer" role="document">
      <!-- Header -->
      <div class="drawer-header">
        <div class="drawer-header-left">
          <div class="drawer-title-row">
            <h2>{editing ? 'Edit Route' : 'New Route'}</h2>
            {#if form.hostname}
              <span class="hostname-preview">{form.hostname}{form.path_prefix !== '/' ? form.path_prefix : ''}</span>
            {/if}
          </div>
          {#if summaryChips.length > 0}
            <div class="summary-chips" aria-label="Effective configuration summary">
              {#each summaryChips as chip, i (i)}
                <span class="chip" data-tone={chip.tone}>{chip.label}</span>
              {/each}
            </div>
          {/if}
        </div>
        <div class="drawer-header-right">
          <button class="btn-close" onclick={handleClose} title="Close" aria-label="Close drawer">
            <!-- eslint-disable-next-line svelte/no-at-html-tags -->
            {@html closeIcon}
          </button>
        </div>
      </div>

      {#if formError}
        <div class="form-error">{formError}</div>
      {/if}

      <!-- Tab bar -->
      <div class="tab-bar">
        {#each TABS as tab (tab.id)}
          <button
            class="tab-btn"
            class:active={activeTab === tab.id}
            onclick={() => { activeTab = tab.id; }}
          >
            {tab.label}
            {#if tabHasModifiedFields(tab.id)}
              <span class="tab-dot" title="This tab has non-default values"></span>
            {/if}
          </button>
        {/each}
      </div>

      <!-- Tab content -->
      <div class="drawer-body">
        {#if activeTab === 'general'}
          <GeneralTab bind:form={form} editing={!!editing} {importedFields} />
        {:else if activeTab === 'routing'}
          <RoutingTab bind:form={form} {backends} {certificates} {importedFields} />
        {:else if activeTab === 'transform'}
          <TransformTab bind:form={form} {importedFields} />
        {:else if activeTab === 'cache'}
          <CachingTab bind:form={form} {importedFields} />
        {:else if activeTab === 'security'}
          <SecurityTab bind:form={form} {importedFields} {customPresets} {backends} initialMtlsCaCertPem={editing?.mtls?.ca_cert_pem ?? ''} />
        {:else if activeTab === 'protection'}
          <ProtectionTab bind:form={form} {importedFields} />
        {:else if activeTab === 'upstream'}
          <UpstreamTab bind:form={form} {importedFields} />
        {/if}
      </div>

      <!-- Footer -->
      <div class="drawer-footer">
        <button class="btn btn-cancel" onclick={handleClose}>Cancel</button>
        <button class="btn btn-primary" disabled={formSubmitting} onclick={handleSubmit}>
          {formSubmitting ? 'Saving...' : editing ? 'Update' : 'Create'}
        </button>
      </div>
    </div>
  </div>
{/if}

<script lang="ts" module>
  const closeIcon = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
</script>

<style>
  .drawer-overlay {
    position: fixed;
    inset: 0;
    z-index: 100;
    display: flex;
    justify-content: flex-end;
  }

  .drawer-backdrop {
    position: absolute;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
  }

  .drawer {
    position: relative;
    z-index: 1;
    /* clamp(min, preferred, max): 900px minimum on narrow screens,
       55 % of viewport for comfortable editing on full-HD and above,
       1280px hard cap so 4K screens do not drown the form in
       whitespace. */
    width: clamp(900px, 55vw, 1280px);
    max-width: 100vw;
    height: 100vh;
    background: var(--color-bg-card);
    border-left: 1px solid var(--color-border);
    display: flex;
    flex-direction: column;
    animation: slide-in 0.25s ease-out;
  }

  @keyframes slide-in {
    from { transform: translateX(100%); }
    to { transform: translateX(0); }
  }

  .drawer-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1rem 1.5rem;
    border-bottom: 1px solid var(--color-border);
    flex-shrink: 0;
  }

  .drawer-header-left {
    display: flex;
    flex-direction: column;
    gap: 0.375rem;
    min-width: 0;
    flex: 1;
  }

  .drawer-title-row {
    display: flex;
    align-items: baseline;
    gap: 1rem;
    min-width: 0;
  }

  .drawer-header-left h2 {
    margin: 0;
    white-space: nowrap;
  }

  .hostname-preview {
    font-size: 0.8125rem;
    color: var(--color-text-muted);
    font-family: var(--mono);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  /* Summary chips: a compact, colour-coded read-out of the route's
     effective configuration. Stays visible regardless of the active
     tab so an operator can tell at a glance "this route has WAF
     blocking, GeoIP deny FR, and a 301 redirect" without clicking
     through each tab. */
  .summary-chips {
    display: flex;
    flex-wrap: wrap;
    gap: 0.3125rem;
    max-width: 100%;
  }

  .chip {
    display: inline-block;
    padding: 0.125rem 0.5rem;
    border-radius: 9999px;
    font-size: 0.6875rem;
    font-weight: 600;
    line-height: 1.4;
    white-space: nowrap;
    border: 1px solid transparent;
  }

  .chip[data-tone='blue']   { color: #3b82f6; background: rgba(59,  130, 246, 0.12); border-color: rgba(59,  130, 246, 0.25); }
  .chip[data-tone='green']  { color: #10b981; background: rgba(16,  185, 129, 0.12); border-color: rgba(16,  185, 129, 0.25); }
  .chip[data-tone='purple'] { color: #8b5cf6; background: rgba(139, 92,  246, 0.12); border-color: rgba(139, 92,  246, 0.25); }
  .chip[data-tone='cyan']   { color: #06b6d4; background: rgba(6,   182, 212, 0.12); border-color: rgba(6,   182, 212, 0.25); }
  .chip[data-tone='red']    { color: #ef4444; background: rgba(239, 68,  68,  0.12); border-color: rgba(239, 68,  68,  0.25); }
  .chip[data-tone='orange'] { color: #f59e0b; background: rgba(245, 158, 11,  0.12); border-color: rgba(245, 158, 11,  0.25); }
  .chip[data-tone='slate']  { color: #64748b; background: rgba(100, 116, 139, 0.12); border-color: rgba(100, 116, 139, 0.25); }
  .chip[data-tone='teal']   { color: #14b8a6; background: rgba(20,  184, 166, 0.12); border-color: rgba(20,  184, 166, 0.25); }
  .chip[data-tone='pink']   { color: #ec4899; background: rgba(236, 72,  153, 0.12); border-color: rgba(236, 72,  153, 0.25); }

  .drawer-header-right {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    flex-shrink: 0;
  }

  .btn-close {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 2rem;
    height: 2rem;
    border: none;
    border-radius: 0.375rem;
    background: none;
    color: var(--color-text-muted);
    cursor: pointer;
    transition: background-color 0.15s, color 0.15s;
  }

  .btn-close:hover {
    background: var(--color-bg-hover);
    color: var(--color-text);
  }

  .form-error {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid var(--color-red);
    border-radius: 0.375rem;
    color: var(--color-red);
    padding: 0.5rem 0.75rem;
    font-size: 0.8125rem;
    margin: 0.75rem 1.5rem 0;
    flex-shrink: 0;
  }

  /* Horizontally scrollable tab bar with a right-edge fade to hint
     at off-screen tabs. The CSS mask keeps ~1.5rem of tab area
     faded, nudging the user to scroll right when they don't see
     the rule / canary / rewrite tabs that were added in v1.3.0. */
  .tab-bar {
    display: flex;
    gap: 0;
    padding: 0 1.5rem;
    border-bottom: 1px solid var(--color-border);
    overflow-x: auto;
    flex-shrink: 0;
    scrollbar-width: thin;
    mask-image: linear-gradient(
      to right,
      black 0,
      black calc(100% - 2rem),
      transparent 100%
    );
    -webkit-mask-image: linear-gradient(
      to right,
      black 0,
      black calc(100% - 2rem),
      transparent 100%
    );
  }

  .tab-btn {
    position: relative;
    padding: 0.75rem 1rem;
    border: none;
    background: none;
    color: var(--color-text-muted);
    font-size: 0.8125rem;
    font-weight: 500;
    cursor: pointer;
    white-space: nowrap;
    border-bottom: 2px solid transparent;
    transition: color 0.15s, border-color 0.15s;
  }

  .tab-btn:hover {
    color: var(--color-text);
  }

  .tab-btn.active {
    color: var(--color-primary);
    border-bottom-color: var(--color-primary);
  }

  .tab-dot {
    position: absolute;
    top: 0.5rem;
    right: 0.25rem;
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--color-primary);
  }

  .drawer-body {
    flex: 1;
    overflow-y: auto;
    padding: 1.5rem;
  }

  .drawer-footer {
    display: flex;
    justify-content: flex-end;
    gap: 0.75rem;
    padding: 1rem 1.5rem;
    border-top: 1px solid var(--color-border);
    flex-shrink: 0;
  }

  @media (max-width: 960px) {
    .drawer {
      width: 100vw;
    }
  }
</style>
