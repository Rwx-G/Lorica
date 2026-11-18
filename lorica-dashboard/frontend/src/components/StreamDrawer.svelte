<script lang="ts">
  import {
    api,
    type BackendResponse,
    type CertificateResponse,
    type StreamReadResponse,
    type StreamStatus,
  } from '../lib/api';
  import { canWrite } from '../lib/auth';
  import {
    STREAM_TABS,
    buildBody,
    buildCreateBody,
    draftOf,
    fieldTab,
    fieldsFor,
    newDraft,
    shapeOf,
    tabsFor,
    type StreamDraft,
    type StreamTab,
  } from '../lib/stream-form';
  import { streamBadges, streamEndpoint } from '../lib/streams';
  import { showToast } from '../lib/toast';
  import GeneralTab from './stream-tabs/GeneralTab.svelte';
  import BackendsTab from './stream-tabs/BackendsTab.svelte';
  import TlsTab from './stream-tabs/TlsTab.svelte';
  import ConnectionTab from './stream-tabs/ConnectionTab.svelte';
  import UdpTab from './stream-tabs/UdpTab.svelte';
  import ProtectionTab from './stream-tabs/ProtectionTab.svelte';

  interface Props {
    open: boolean;
    /** The stream edited, `null` for a new one. */
    editing: StreamReadResponse | null;
    /** The edited stream's status, for its badges. */
    status: StreamStatus | null;
    backends: BackendResponse[];
    certificates: CertificateResponse[];
    onsave: () => void | Promise<void>;
    onclose: () => void;
  }

  let { open, editing, status, backends, certificates, onsave, onclose }: Props = $props();

  let draft: StreamDraft = $state(newDraft());
  let activeTab: StreamTab = $state('general');
  /** The server's refusal, on the tab holding the field it names. */
  let tabError: { tab: StreamTab; message: string } | null = $state(null);
  let submitting = $state(false);

  // A fresh draft each time the drawer opens or turns to another stream.
  $effect(() => {
    if (!open) return;
    draft = editing ? draftOf(editing) : newDraft();
    activeTab = 'general';
    tabError = null;
  });

  const creating = $derived(editing === null);
  const shape = $derived(shapeOf(draft));
  const fields = $derived(fieldsFor(shape.protocol, shape.tlsMode));
  const tabs = $derived(STREAM_TABS.filter((t) => tabsFor(shape.protocol, shape.tlsMode).includes(t.id)));
  const shownTab = $derived(tabs.some((t) => t.id === activeTab) ? activeTab : 'general');
  const badges = $derived(editing ? streamBadges(editing, status) : []);

  async function save() {
    submitting = true;
    tabError = null;
    const res = editing
      ? await api.updateStream(editing.id, buildBody(draft, 'edit'))
      : await api.createStream(buildCreateBody(draft));
    submitting = false;
    if (res.error) {
      const tab = fieldTab(res.error.message);
      tabError = { tab, message: res.error.message };
      activeTab = tab;
      return;
    }
    for (const warning of res.data?.warnings ?? []) showToast(`Saved, with a warning: ${warning}`, 'success', 10_000);
    showToast(editing ? `Stream ${editing.name} updated` : 'Stream created', 'success');
    await onsave();
    onclose();
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') onclose();
  }
</script>

{#if open}
  <div class="drawer-overlay" onkeydown={handleKeydown} role="dialog" aria-modal="true" aria-labelledby="stream-drawer-title" tabindex="-1">
    <div class="drawer-backdrop" role="presentation" onclick={onclose}></div>
    <div class="drawer" role="document">
      <div class="drawer-header">
        <div class="drawer-header-left">
          <div class="drawer-title-row">
            <h2 id="stream-drawer-title">{creating ? 'New Stream' : $canWrite ? 'Edit Stream' : 'Stream'}</h2>
            {#if editing}
              <span class="endpoint-preview">{editing.name} on {streamEndpoint(editing.listen_address, editing.port_first, editing.port_last)}</span>
            {/if}
          </div>
          {#if badges.length > 0}
            <div class="drawer-badges" aria-label="Stream badges">
              {#each badges as b (b.kind)}
                <span class="badge {b.className}" title={b.help}>{b.label}</span>
              {/each}
            </div>
          {/if}
        </div>
        <button class="btn-close" onclick={onclose} title="Close" aria-label="Close drawer">
          <!-- eslint-disable-next-line svelte/no-at-html-tags -->
          {@html closeIcon}
        </button>
      </div>

      <div class="tab-bar" role="tablist">
        {#each tabs as tab (tab.id)}
          <button
            class="tab-btn"
            role="tab"
            aria-selected={shownTab === tab.id}
            class:active={shownTab === tab.id}
            class:has-error={tabError?.tab === tab.id}
            onclick={() => (activeTab = tab.id)}
          >{tab.label}</button>
        {/each}
      </div>

      <fieldset class="drawer-body" disabled={!$canWrite}>
        {#if tabError && tabError.tab === shownTab}
          <div class="form-error" role="alert">{tabError.message}</div>
        {/if}
        {#if shownTab === 'general'}
          <GeneralTab bind:draft {fields} protocol={shape.protocol} {creating} />
        {:else if shownTab === 'backends'}
          <BackendsTab bind:draft {backends} perRule={fields.has('match_rules')} />
        {:else if shownTab === 'tls'}
          <TlsTab bind:draft {fields} protocol={shape.protocol} {creating} {certificates} />
        {:else if shownTab === 'connection'}
          <ConnectionTab bind:draft {fields} protocol={shape.protocol} {creating} />
        {:else if shownTab === 'udp'}
          <UdpTab bind:draft {creating} />
        {:else if shownTab === 'protection'}
          <ProtectionTab bind:draft {fields} protocol={shape.protocol} {creating} />
        {/if}
      </fieldset>

      <div class="drawer-footer">
        <p class="hint">Empty fields take the server's default. Every cap and rate applies on each node that binds the stream.</p>
        <div class="drawer-footer-actions">
          <button class="btn btn-cancel" onclick={onclose}>{$canWrite ? 'Cancel' : 'Close'}</button>
          {#if $canWrite}
            <button class="btn btn-primary" disabled={submitting} onclick={() => void save()}>
              {submitting ? 'Saving...' : creating ? 'Create' : 'Update'}
            </button>
          {/if}
        </div>
      </div>
    </div>
  </div>
{/if}

<script lang="ts" module>
  const closeIcon = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
</script>

<style>
  .drawer-overlay { position: fixed; inset: 0; z-index: 100; display: flex; justify-content: flex-end; }
  .drawer-backdrop { position: absolute; inset: 0; background: rgba(0, 0, 0, 0.5); }
  .drawer {
    position: relative;
    z-index: 1;
    width: clamp(760px, 50vw, 1100px);
    max-width: 100vw;
    height: 100vh;
    background: var(--color-bg-card);
    border-left: 1px solid var(--color-border);
    display: flex;
    flex-direction: column;
  }
  .drawer-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1rem 1.5rem;
    border-bottom: 1px solid var(--color-border);
    flex-shrink: 0;
  }
  .drawer-header-left { display: flex; flex-direction: column; gap: 0.375rem; min-width: 0; flex: 1; }
  .drawer-title-row { display: flex; align-items: baseline; gap: 1rem; min-width: 0; }
  .drawer-title-row h2 { margin: 0; white-space: nowrap; }
  .endpoint-preview { font-size: 0.8125rem; color: var(--color-text-muted); font-family: var(--mono); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .drawer-badges { display: flex; flex-wrap: wrap; gap: 0.3125rem; }
  .drawer-badges .badge { cursor: help; font-size: var(--text-xs); }
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
  }
  .btn-close:hover { background: var(--color-bg-hover); color: var(--color-text); }
  .tab-bar { display: flex; padding: 0 1.5rem; border-bottom: 1px solid var(--color-border); overflow-x: auto; flex-shrink: 0; }
  .tab-btn {
    padding: 0.75rem 1rem;
    border: none;
    background: none;
    color: var(--color-text-muted);
    font-size: 0.8125rem;
    font-weight: 500;
    cursor: pointer;
    white-space: nowrap;
    border-bottom: 2px solid transparent;
  }
  .tab-btn:hover { color: var(--color-text); }
  .tab-btn.active { color: var(--color-primary); border-bottom-color: var(--color-primary); }
  .tab-btn.has-error { color: var(--color-red-text); }
  .drawer-body { flex: 1; overflow-y: auto; padding: 1.5rem; border: none; margin: 0; min-width: 0; }
  .form-error {
    background: var(--color-red-subtle);
    border: 1px solid var(--color-red);
    border-radius: 0.375rem;
    color: var(--color-red-text);
    padding: 0.5rem 0.75rem;
    font-size: 0.8125rem;
    margin-bottom: var(--space-4);
  }
  .drawer-footer { display: flex; flex-direction: column; gap: 0.5rem; padding: 1rem 1.5rem; border-top: 1px solid var(--color-border); flex-shrink: 0; }
  .drawer-footer .hint { margin: 0; }
  .drawer-footer-actions { display: flex; justify-content: flex-end; gap: 0.75rem; }
  @media (max-width: 800px) {
    .drawer { width: 100vw; }
  }
</style>
