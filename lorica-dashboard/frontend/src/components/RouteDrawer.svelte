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
  import TimeoutsTab from './route-tabs/TimeoutsTab.svelte';
  import SecurityTab from './route-tabs/SecurityTab.svelte';
  import HeadersTab from './route-tabs/HeadersTab.svelte';
  import CorsTab from './route-tabs/CorsTab.svelte';
  import CachingTab from './route-tabs/CachingTab.svelte';
  import ProtectionTab from './route-tabs/ProtectionTab.svelte';
  import PathRulesTab from './route-tabs/PathRulesTab.svelte';
  import HeaderRulesTab from './route-tabs/HeaderRulesTab.svelte';
  import CanaryTab from './route-tabs/CanaryTab.svelte';
  import ResponseRewriteTab from './route-tabs/ResponseRewriteTab.svelte';

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
    { id: 'timeouts', label: 'Timeouts' },
    { id: 'security', label: 'Security' },
    { id: 'headers', label: 'Headers' },
    { id: 'cors', label: 'CORS' },
    { id: 'caching', label: 'Caching' },
    { id: 'protection', label: 'Protection' },
    { id: 'path_rules', label: 'Path Rules' },
    { id: 'header_rules', label: 'Header Rules' },
    { id: 'traffic_splits', label: 'Canary' },
    { id: 'response_rewrite', label: 'Rewrite' },
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
          <h2>{editing ? 'Edit Route' : 'New Route'}</h2>
          {#if form.hostname}
            <span class="hostname-preview">{form.hostname}{form.path_prefix !== '/' ? form.path_prefix : ''}</span>
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
          <GeneralTab bind:form={form} {backends} {certificates} editing={!!editing} {importedFields} />
        {:else if activeTab === 'timeouts'}
          <TimeoutsTab bind:form={form} {importedFields} />
        {:else if activeTab === 'security'}
          <SecurityTab bind:form={form} {importedFields} {customPresets} {backends} initialMtlsCaCertPem={editing?.mtls?.ca_cert_pem ?? ''} />
        {:else if activeTab === 'headers'}
          <HeadersTab bind:form={form} {importedFields} />
        {:else if activeTab === 'cors'}
          <CorsTab bind:form={form} {importedFields} />
        {:else if activeTab === 'caching'}
          <CachingTab bind:form={form} {importedFields} />
        {:else if activeTab === 'protection'}
          <ProtectionTab bind:form={form} {importedFields} />
        {:else if activeTab === 'path_rules'}
          <PathRulesTab bind:form={form} {backends} {importedFields} />
        {:else if activeTab === 'header_rules'}
          <HeaderRulesTab bind:form={form} {backends} {importedFields} />
        {:else if activeTab === 'traffic_splits'}
          <CanaryTab bind:form={form} {backends} {importedFields} />
        {:else if activeTab === 'response_rewrite'}
          <ResponseRewriteTab bind:form={form} {importedFields} />
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
    width: 900px;
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
